//! Owns the launcher until its reap and the cgroup until confirmed quiescent.
use crate::output::{nonblocking, StreamOutput};
use hearthrun_launcher::{
    cgroup::{JobGroup, KillToken},
    image::lower_hex,
    wire,
};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fd::{AsFd, OwnedFd};
use rustix::process::{self, Pid, PidfdFlags, Signal};
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SETUP_TIMEOUT: Duration = Duration::from_secs(3);

fn invalid(detail: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

pub fn nonce() -> io::Result<[u8; 16]> {
    let mut bytes = [0; 16];
    let mut filled = 0;
    while filled != bytes.len() {
        match rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(0) => return Err(invalid("kernel random source returned no bytes")),
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(bytes)
}

pub struct LaunchInputs<'a> {
    pub binary: &'a Path,
    pub executable: &'a OwnedFd,
    pub tree: &'a OwnedFd,
    pub scratch: &'a OwnedFd,
    pub digest: &'a str,
    pub argv: &'a [String],
    pub abi: u32,
}

pub struct Native {
    pub group: JobGroup,
    child: Option<Child>,
    pidfd: Option<OwnedFd>,
    streams_safe: bool,
    control: Option<OwnedFd>,
    nonce: [u8; 16],
    uid: u32,
    abi: u32,
    deadline: Instant,
    ready_pid: Option<u32>,
    output: Option<OwnedFd>,
    released: bool,
    watchdog: Option<JoinHandle<io::Result<bool>>>,
    group_removed: bool,
    result: Option<ExitStatus>,
    launcher_result: Option<ExitStatus>,
    pub stdout: StreamOutput,
    pub stderr: StreamOutput,
}

impl Native {
    pub fn new(group: JobGroup) -> io::Result<Self> {
        Ok(Self {
            group,
            child: None,
            pidfd: None,
            streams_safe: false,
            control: None,
            nonce: nonce()?,
            uid: process::getuid().as_raw(),
            abi: 0,
            deadline: Instant::now() + SETUP_TIMEOUT,
            ready_pid: None,
            output: None,
            released: false,
            watchdog: None,
            group_removed: false,
            result: None,
            launcher_result: None,
            stdout: StreamOutput::default(),
            stderr: StreamOutput::default(),
        })
    }

    /// A partially started child/group remains owned by self on any error.
    pub fn spawn(&mut self, inputs: LaunchInputs<'_>) -> io::Result<()> {
        if self.child.is_some() || !inputs.binary.is_absolute() {
            return Err(invalid(
                "expected a fresh launcher and absolute trusted path",
            ));
        }
        self.deadline = Instant::now() + SETUP_TIMEOUT;
        self.abi = inputs.abi;
        self.group.configure()?;
        let (ours, theirs) = wire::pair()?;
        let child = Command::new(inputs.binary)
            .arg("--launch-v1")
            .arg(std::process::id().to_string())
            .arg(lower_hex(&self.nonce))
            .arg(inputs.digest)
            .args(inputs.argv)
            .env_clear()
            .stdin(Stdio::from(theirs))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        self.child = Some(child);
        self.control = Some(ours);
        let child = self.child.as_ref().expect("launcher retained");
        let pid =
            Pid::from_raw(i32::try_from(child.id()).map_err(|_| invalid("invalid launcher PID"))?)
                .ok_or_else(|| invalid("invalid launcher PID"))?;
        self.pidfd = Some(process::pidfd_open(pid, PidfdFlags::empty())?);
        nonblocking(
            child
                .stdout
                .as_ref()
                .ok_or_else(|| invalid("missing stdout pipe"))?,
        )?;
        nonblocking(
            child
                .stderr
                .as_ref()
                .ok_or_else(|| invalid("missing stderr pipe"))?,
        )?;
        self.streams_safe = true;
        self.group.place_launcher(child.id())?;
        wire::send(
            self.control.as_ref().expect("control retained"),
            &self.nonce,
            wire::PREPARE,
            0,
            &[
                inputs.executable.as_fd(),
                inputs.tree.as_fd(),
                inputs.scratch.as_fd(),
            ],
        )
    }

    pub fn ready(&self) -> bool {
        self.ready_pid.is_some() && self.output.is_some()
    }

    pub fn setup_expired(&self) -> bool {
        !self.released && Instant::now() >= self.deadline
    }

    pub fn poll_control(&mut self) -> io::Result<()> {
        let Some(socket) = self.control.as_ref() else {
            return Ok(());
        };
        for _ in 0..4 {
            let packet = match wire::receive(socket, &self.nonce, Some(self.uid)) {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && self.released => {
                    // The kernel may terminate the trusted launcher along with
                    // the guest. Classify the terminal outcome after reaping
                    // and checking the group's memory and PID counters.
                    self.control = None;
                    break;
                }
                Err(error) => return Err(error),
            };
            let sender = packet
                .sender
                .ok_or_else(|| invalid("launcher packet lacks credentials"))?;
            let pid =
                u32::try_from(sender.pid.as_raw_pid()).map_err(|_| invalid("bad sender PID"))?;
            match packet.kind {
                wire::READY
                    if self.ready_pid.is_none()
                        && !self.released
                        && packet.value == self.abi as i32 =>
                {
                    let [fd]: [OwnedFd; 1] = packet
                        .descriptors
                        .try_into()
                        .map_err(|_| invalid("output descriptor count"))?;
                    if !self.group.contains_process(pid)? {
                        return Err(invalid("policy ready sender outside owned job cgroup"));
                    }
                    wire::validate_output_descriptor(&fd, self.uid)?;
                    self.ready_pid = Some(pid);
                    self.output = Some(fd);
                }
                wire::EXIT
                    if self.released && self.ready_pid == Some(pid) && self.result.is_none() =>
                {
                    let status = ExitStatus::from_raw(packet.value);
                    if !(status.code().is_some() || status.signal().is_some()) {
                        return Err(invalid("unrecognized guest wait status"));
                    }
                    self.result = Some(status);
                }
                wire::FAULT => return Err(invalid("trusted launcher refused setup or exec")),
                _ => return Err(invalid("unexpected launcher state or credentials")),
            }
        }
        Ok(())
    }

    /// Caller serializes cancel and release. Call after journaling the release
    /// decision and immediately before changing the visible state to RUNNING.
    pub fn release(&mut self, wall: Duration) -> io::Result<Instant> {
        if !self.ready() || self.released || self.setup_expired() || self.launcher_result.is_some()
        {
            return Err(invalid("exec gate is not ready"));
        }
        self.group.verify_limits()?;
        if !self
            .group
            .contains_process(self.ready_pid.expect("ready has PID"))?
        {
            return Err(invalid("ready sender vanished before exec release"));
        }
        let socket = self
            .control
            .as_ref()
            .ok_or_else(|| invalid("missing exec control"))?;
        let pidfd = self
            .pidfd
            .as_ref()
            .ok_or_else(|| invalid("missing launcher pidfd"))?;
        let pidfd = rustix::io::fcntl_dupfd_cloexec(pidfd, 3)?;
        let kill = self.group.kill_token()?;
        // Arm before release so a stalled durable write after release cannot
        // extend the guest deadline. This thread holds no filesystem paths.
        let deadline = Instant::now() + wall;
        self.watchdog = Some(
            thread::Builder::new()
                .name("hearthrun-deadline".into())
                .stack_size(128 * 1024)
                .spawn(move || watch_wall(pidfd, kill, deadline))?,
        );
        wire::send_plain(socket, &self.nonce, wire::EXECUTE, 0)?;
        self.released = true;
        Ok(deadline)
    }

    pub fn check_deadline(&mut self) -> io::Result<bool> {
        if self
            .watchdog
            .as_ref()
            .is_none_or(|thread| !thread.is_finished())
        {
            return Ok(false);
        }
        self.watchdog
            .take()
            .expect("watchdog finished")
            .join()
            .map_err(|_| io::Error::other("wall deadline worker panicked"))?
    }

    pub fn stop(&mut self) -> io::Result<()> {
        self.control = None;
        let group = if self.group_removed {
            Ok(())
        } else {
            self.group.kill()
        };
        // A failed attach can leave the child outside this cgroup. Target the
        // held direct child/pidfd in addition to the group on all stop paths.
        if let Some(child) = self.child.as_mut() {
            if self.launcher_result.is_none() {
                if let Some(pidfd) = &self.pidfd {
                    match process::pidfd_send_signal(pidfd, Signal::KILL) {
                        Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    // No guest can run without the pidfd acquired before PREPARE.
                    match child.kill() {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        group
    }

    pub fn observe(&mut self) -> io::Result<()> {
        if let Some(child) = self.child.as_mut() {
            if self.launcher_result.is_none() {
                self.launcher_result = child.try_wait()?;
            }
            if !self.streams_safe {
                if self.launcher_result.is_some() {
                    // Failed before cgroup attachment or PREPARE. No guest
                    // ran and no descendant can hold these streams open.
                    self.stdout.eof = true;
                    self.stderr.eof = true;
                }
                return Ok(());
            }
            if let Some(pipe) = child.stdout.as_mut() {
                self.stdout.drain(pipe)?;
            }
            if let Some(pipe) = child.stderr.as_mut() {
                self.stderr.drain(pipe)?;
            }
        }
        Ok(())
    }

    pub fn launcher_reaped(&self) -> bool {
        self.child.is_none() || self.launcher_result.is_some()
    }

    pub fn guest_status(&self) -> Option<ExitStatus> {
        self.launcher_result
            .filter(ExitStatus::success)
            .and(self.result)
    }

    pub fn quiescent(&self) -> io::Result<bool> {
        Ok(self.watchdog.is_none()
            && self.launcher_reaped()
            && (self.group_removed || !self.group.populated()?)
            && (self.child.is_none() || (self.stdout.eof && self.stderr.eof)))
    }

    pub fn take_quiescent_output(&mut self) -> io::Result<Option<OwnedFd>> {
        if !self.quiescent()? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "cleanup is pending",
            ));
        }
        Ok(self.output.take())
    }

    pub fn remove_empty_group(&mut self) -> io::Result<()> {
        if !self.group_removed {
            self.group.remove_empty()?;
            self.group_removed = true;
        }
        Ok(())
    }
}

fn watch_wall(pidfd: OwnedFd, kill: KillToken, deadline: Instant) -> io::Result<bool> {
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let timeout = Timespec {
            tv_sec: remaining.as_secs() as _,
            tv_nsec: remaining.subsec_nanos().into(),
        };
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => break,
            Ok(_) if fds[0].revents().intersects(PollFlags::IN | PollFlags::HUP) => {
                if Instant::now() < deadline {
                    return Ok(false);
                }
                break;
            }
            Err(rustix::io::Errno::INTR) => continue,
            failure => {
                deadline_stop(&pidfd, kill)?;
                return Err(failure
                    .err()
                    .map_or_else(|| invalid("unexpected pidfd poll event"), io::Error::from));
            }
        }
    }
    deadline_stop(&pidfd, kill)?;
    Ok(true)
}

fn deadline_stop(pidfd: &OwnedFd, kill: KillToken) -> io::Result<()> {
    let group = kill.fire();
    let launcher = match process::pidfd_send_signal(pidfd, Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(error.into()),
    };
    group.and(launcher)
}
