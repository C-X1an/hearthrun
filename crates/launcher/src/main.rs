#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod mounts;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use hearthrun_domain::{protocol::valid_sha256, JobId};
    use hearthrun_launcher::{policy, wire};
    use rustix::fd::{AsFd, AsRawFd, OwnedFd};
    use rustix::{fs, pipe, process, thread};
    use std::ffi::{CString, OsString};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    const BARRIER: Duration = Duration::from_secs(3);

    fn invalid(detail: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, detail)
    }

    struct Arguments {
        supervisor: i32,
        nonce: [u8; 16],
        digest: String,
        argv: Vec<CString>,
    }

    impl Arguments {
        fn parse() -> io::Result<Self> {
            let mut args = std::env::args_os().skip(1);
            if args.next().as_deref().and_then(|s| s.to_str()) != Some("--launch-v1") {
                return Err(invalid("expected private launcher arguments"));
            }
            let ascii = |arg: Option<OsString>| {
                arg.and_then(|s| s.into_string().ok())
                    .ok_or_else(|| invalid("missing launch field"))
            };
            let supervisor = ascii(args.next())?
                .parse::<i32>()
                .ok()
                .filter(|pid| *pid > 1)
                .ok_or_else(|| invalid("invalid parent PID"))?;
            let hex = ascii(args.next())?;
            JobId::parse(&hex).map_err(|_| invalid("invalid launch nonce"))?;
            let mut nonce = [0; 16];
            for (i, value) in nonce.iter_mut().enumerate() {
                *value = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("validated hex");
            }
            let digest = ascii(args.next())?;
            if !valid_sha256(&digest) {
                return Err(invalid("invalid executable digest"));
            }
            let mut argv = vec![CString::from(c"/bin/task")];
            let mut bytes = 0;
            for arg in args {
                let value = arg.as_os_str().as_bytes();
                std::str::from_utf8(value).map_err(|_| invalid("arguments must be UTF-8"))?;
                bytes += value.len();
                if argv.len() > 32 || bytes > 4096 {
                    return Err(invalid("launcher arguments exceeded bounds"));
                }
                argv.push(CString::new(value).map_err(|_| invalid("NUL in argument"))?);
            }
            Ok(Self {
                supervisor,
                nonce,
                digest,
                argv,
            })
        }
    }

    fn require_parent(pid: i32) -> io::Result<()> {
        process::set_parent_process_death_signal(Some(process::Signal::KILL))?;
        if process::getppid().map(|id| id.as_raw_pid()) != Some(pid) {
            return Err(invalid("launcher parent changed"));
        }
        Ok(())
    }

    fn wait_packet(
        fd: &OwnedFd,
        nonce: &[u8; 16],
        want: u8,
        until: Instant,
    ) -> io::Result<wire::Packet> {
        while Instant::now() < until {
            if let Some(packet) = wire::receive(fd, nonce, None)? {
                if packet.kind != want || packet.value != 0 {
                    return Err(invalid("unexpected private launch message"));
                }
                return Ok(packet);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "launch control deadline",
        ))
    }

    fn wait_byte(fd: &OwnedFd, until: Instant) -> io::Result<Option<u8>> {
        let mut data = [0];
        while Instant::now() < until {
            match rustix::io::read(fd, &mut data[..]) {
                Ok(0) => return Ok(None),
                Ok(_) => return Ok(Some(data[0])),
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "launch pipe deadline",
        ))
    }

    fn fork_one() -> io::Result<i32> {
        // SAFETY: the exec-separated launcher is single-threaded at both
        // fork sites. No lock in another thread survives into the child.
        let result = unsafe { libc::fork() };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    fn exit_now(status: i32) -> ! {
        // SAFETY: _exit terminates this process without destructors. After
        // close_range the child must not drop descriptors closed by that call.
        unsafe { libc::_exit(status) }
    }

    fn drop_privileges(last_capability: u32) -> io::Result<()> {
        if !process::getgroups()?.is_empty() || last_capability > 63 {
            return Err(invalid("supplementary groups or unknown capability range"));
        }
        thread::set_no_new_privs(true)?;
        thread::clear_ambient_capability_set()?;
        // SAFETY: all prctl arguments are scalars. Bit 0 disables UID 0
        // capability inheritance on exec; bit 1 locks that setting.
        if unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 3u64, 0u64, 0u64, 0u64) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for cap in 0..=last_capability {
            // SAFETY: the validated capability ordinal and remaining arguments are scalars.
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, u64::from(cap), 0u64, 0u64, 0u64) } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let empty = thread::CapabilitySets {
            effective: thread::CapabilitySet::empty(),
            permitted: thread::CapabilitySet::empty(),
            inheritable: thread::CapabilitySet::empty(),
        };
        thread::set_capabilities(None, empty)?;
        if thread::capabilities(None)? != empty {
            return Err(invalid("capability sets remain nonempty"));
        }
        for cap in 0..=last_capability {
            // SAFETY: scalar operation reads the current bounding set.
            if unsafe { libc::prctl(libc::PR_CAPBSET_READ, u64::from(cap), 0u64, 0u64, 0u64) } != 0
            {
                return Err(invalid("capability bounding set not empty"));
            }
        }
        Ok(())
    }

    fn close_except_gates(gate: u32, report: u32) -> io::Result<()> {
        let mut start = 3;
        let mut keep = [gate, report];
        keep.sort_unstable();
        if keep[0] < start || keep[0] == keep[1] {
            return Err(invalid("launch pipes overlap standard descriptors"));
        }
        for end in [keep[0] - 1, keep[1] - 1, u32::MAX] {
            // SAFETY: only in the dedicated child. Only the two owned CLOEXEC
            // pipes and stdio survive. All branches from this point _exit/exec.
            if start <= end
                && unsafe { libc::syscall(libc::SYS_close_range, start, end, 0u32) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            start = end.saturating_add(2);
        }
        Ok(())
    }

    fn guest(
        arguments: &Arguments,
        gate: OwnedFd,
        report: OwnedFd,
        last_capability: u32,
        abi: u32,
        seccomp: &[seccompiler::sock_filter],
        until: Instant,
    ) -> ! {
        let mut argv: Vec<_> = arguments.argv.iter().map(|value| value.as_ptr()).collect();
        argv.push(std::ptr::null());
        let environment = [
            c"PATH=/bin".as_ptr(),
            c"LANG=C".as_ptr(),
            c"TZ=UTC".as_ptr(),
            std::ptr::null(),
        ];
        let setup = require_parent(1)
            .and_then(|()| drop_privileges(last_capability))
            .and_then(|()| close_except_gates(gate.as_raw_fd() as u32, report.as_raw_fd() as u32))
            .and_then(|()| policy::apply_landlock(abi))
            .and_then(|()| policy::apply_seccomp(seccomp));
        if let Err(error) = setup {
            eprintln!("trusted guest preparation: {error}");
            exit_now(125);
        }
        if rustix::io::write(&report, b"R") != Ok(1)
            || !matches!(wait_byte(&gate, until), Ok(Some(b'G')))
        {
            exit_now(125);
        }
        drop(gate);
        // SAFETY: argv/envp are null-terminated arrays of live C-string
        // pointers. The fixed pathname is the only Landlock execution grant.
        unsafe { libc::execve(c"/bin/task".as_ptr(), argv.as_ptr(), environment.as_ptr()) };
        let _ = rustix::io::write(&report, b"X");
        exit_now(127);
    }

    fn init(
        args: &Arguments,
        socket: &OwnedFd,
        output: OwnedFd,
        alive: OwnedFd,
        last_capability: u32,
        until: Instant,
    ) -> io::Result<()> {
        process::set_parent_process_death_signal(Some(process::Signal::KILL))?;
        // PID1 sees its outer parent as PID 0. Check a private pipe instead.
        // The outer parent owns the only write end after the fork.
        let mut byte = [0];
        if process::getpid().as_raw_pid() != 1
            || rustix::io::read(&alive, &mut byte[..]) != Err(rustix::io::Errno::AGAIN)
        {
            return Err(invalid(
                "PID namespace init or outer launcher liveness check failed",
            ));
        }
        drop(alive);
        let abi = policy::landlock_abi()?;
        let seccomp = policy::prepare_seccomp()?;
        let flags = pipe::PipeFlags::CLOEXEC | pipe::PipeFlags::NONBLOCK;
        let (gate, release) = pipe::pipe_with(flags)?;
        let (status, report) = pipe::pipe_with(flags)?;
        let pid = fork_one()?;
        if pid == 0 {
            drop((release, status, output));
            guest(args, gate, report, last_capability, abi, &seccomp, until);
        }
        drop((gate, report));
        if wait_byte(&status, until)? != Some(b'R') {
            return Err(invalid("guest policy or descriptor setup failed"));
        }
        wire::send(
            socket,
            &args.nonce,
            wire::READY,
            abi as i32,
            &[output.as_fd()],
        )?;
        drop(output);
        wait_packet(socket, &args.nonce, wire::EXECUTE, until)?;
        if rustix::io::write(&release, b"G")? != 1 {
            return Err(invalid("guest exec gate failed"));
        }
        drop(release);
        if wait_byte(&status, until)?.is_some() {
            return Err(invalid("approved guest exec failed"));
        }
        drop(status);
        let mut result = None;
        loop {
            match process::wait(process::WaitOptions::empty()) {
                Ok(Some((child, status))) if child.as_raw_pid() == pid => {
                    result = Some(status.as_raw())
                }
                Ok(Some(_)) | Err(rustix::io::Errno::INTR) => {}
                Err(rustix::io::Errno::CHILD) => break,
                Err(error) => return Err(error.into()),
                Ok(None) => return Err(invalid("unavailable init reap observation")),
            }
        }
        wire::send_plain(
            socket,
            &args.nonce,
            wire::EXIT,
            result.ok_or_else(|| invalid("guest was not reaped"))?,
        )
    }

    fn launch(args: &Arguments, socket: OwnedFd, until: Instant) -> io::Result<()> {
        let parent = rustix::net::sockopt::socket_peercred(&socket)?;
        if parent.pid.as_raw_pid() != args.supervisor || parent.uid != process::geteuid() {
            return Err(invalid("private socket has unexpected peer"));
        }
        require_parent(args.supervisor)?;
        fn verify_pipe(fd: &impl AsFd) -> io::Result<()> {
            let kind = fs::FileType::from_raw_mode(fs::fstat(fd)?.st_mode);
            let mode = fs::fcntl_getfl(fd)? & fs::OFlags::ACCMODE;
            if kind != fs::FileType::Fifo || mode != fs::OFlags::WRONLY {
                return Err(invalid("stdout and stderr must be write-only pipes"));
            }
            Ok(())
        }
        verify_pipe(&std::io::stdout())?;
        verify_pipe(&std::io::stderr())?;
        let null = fs::open(
            "/dev/null",
            fs::OFlags::RDONLY | fs::OFlags::CLOEXEC,
            fs::Mode::empty(),
        )?;
        rustix::stdio::dup2_stdin(&null)?;
        drop(null);
        let last_capability = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
            .trim()
            .parse::<u32>()
            .map_err(|_| invalid("invalid kernel capability range"))?;
        let packet = wait_packet(&socket, &args.nonce, wire::PREPARE, until)?;
        let [executable, input, scratch]: [OwnedFd; 3] = packet
            .descriptors
            .try_into()
            .map_err(|_| invalid("wrong launch descriptor count"))?;
        let output = match super::mounts::construct(executable, input, scratch, &args.digest) {
            Ok(output) => output,
            Err(error) => {
                let _ = wire::send_plain(&socket, &args.nonce, wire::FAULT, 1);
                return Err(error);
            }
        };
        require_parent(args.supervisor)?;
        let (alive, keepalive) =
            pipe::pipe_with(pipe::PipeFlags::CLOEXEC | pipe::PipeFlags::NONBLOCK)?;
        let pid = fork_one()?;
        if pid == 0 {
            drop(keepalive);
            match init(args, &socket, output, alive, last_capability, until) {
                Ok(()) => exit_now(0),
                Err(error) => {
                    let _ = wire::send_plain(&socket, &args.nonce, wire::FAULT, 2);
                    eprintln!("trusted init: {error}");
                    // Exiting namespace PID1 terminates remaining tasks in
                    // that namespace. The supervisor separately kills/reaps.
                    exit_now(125);
                }
            }
        }
        drop((socket, output, alive));
        let pid = process::Pid::from_raw(pid).ok_or_else(|| invalid("invalid init PID"))?;
        let result = loop {
            match process::waitpid(Some(pid), process::WaitOptions::empty()) {
                Ok(Some((_, status))) if status.exit_status() == Some(0) => break Ok(()),
                Ok(_) => break Err(invalid("namespace init failed")),
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => break Err(error.into()),
            }
        };
        drop(keepalive);
        result
    }

    pub(super) fn run() -> io::Result<()> {
        let args = Arguments::parse()?;
        let until = Instant::now() + BARRIER;
        let socket = rustix::io::fcntl_dupfd_cloexec(std::io::stdin(), 3)?;
        launch(&args, socket, until)
    }
}

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if let Err(error) = linux::run() {
        eprintln!("trusted launcher declined: {error}");
        std::process::exit(125);
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        eprintln!("HearthRun launcher requires Linux x86-64");
        std::process::exit(78);
    }
}
