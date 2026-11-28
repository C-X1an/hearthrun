//! AC-004 positive/withheld-gate subset; not the first-instruction/injection gate.
//! Derived from the real Native component smoke, without runtime/fixture changes.
#![forbid(unsafe_code)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native barrier verification requires Linux x86-64");

use hearthrun_launcher::{cgroup::JobsRoot, image, policy};
use hearthrun_supervisor::lifecycle::{nonce, LaunchInputs, Native};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use serde_json::{json, Value};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message.to_owned()))
    }
}

fn setting(name: &str) -> io::Result<PathBuf> {
    let value = std::env::var_os(name)
        .ok_or_else(|| io::Error::other(format!("set {name}; no native skip is supported")))?;
    let path = PathBuf::from(value);
    require(path.is_absolute(), "native path must be absolute")?;
    require(path.canonicalize()? == path, "native path follows a link")?;
    Ok(path)
}

fn regular(path: &Path) -> io::Result<()> {
    let info = path.symlink_metadata()?;
    require(
        info.is_file() && info.mode() & 0o022 == 0,
        "trusted binary must be a regular file without group/other write permission",
    )
}

fn bounded_parent(path: &Path) -> io::Result<()> {
    let info = path.symlink_metadata()?;
    require(
        info.is_dir()
            && info.uid() == rustix::process::geteuid().as_raw()
            && info.uid() != 0
            && info.mode() & 0o7777 == 0o700,
        "barrier parent must be a non-root owned mode0700 directory",
    )?;
    let fd = fs::open(
        path,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    require(
        fs::fstatfs(&fd)?.f_type as u64 == 0x0102_1994,
        "barrier parent must be OS-bounded tmpfs",
    )?;
    let size = fs::fstatvfs(&fd)?;
    let capacity = size
        .f_blocks
        .checked_mul(size.f_frsize)
        .ok_or_else(|| io::Error::other("tmpfs capacity overflow"))?;
    require(
        (1..=12_000_000_000).contains(&capacity),
        "barrier tmpfs exceeds the existing 12GB development allocation",
    )
}

fn tick(deadline: Instant) -> io::Result<()> {
    require(Instant::now() < deadline, "native barrier deadline expired")?;
    std::thread::sleep(Duration::from_millis(3));
    Ok(())
}

type ObjectIdentity = (u64, u64);
type PathIdentity = (u64, u64, u32);

fn identity(fd: &impl AsFd) -> io::Result<ObjectIdentity> {
    let stat = fs::fstat(fd)?;
    Ok((stat.st_dev, stat.st_ino))
}

/// Only exclusively created names are recorded. Never recursively remove a tree.
#[derive(Default)]
struct OwnedPaths {
    entries: Vec<(PathBuf, Option<PathIdentity>)>,
    kernel_pending: bool,
}

impl OwnedPaths {
    fn record(&mut self, path: &Path) -> io::Result<()> {
        self.entries.push((path.to_owned(), None));
        let info = path.symlink_metadata()?;
        self.entries.last_mut().expect("just recorded").1 =
            Some((info.dev(), info.ino(), info.mode()));
        Ok(())
    }

    fn mkdir(&mut self, path: &Path) -> io::Result<()> {
        DirBuilder::new().mode(0o700).create(path)?;
        self.record(path)
    }

    fn file(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        self.record(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn cleanup_exact(&mut self) -> io::Result<()> {
        require(
            !self.kernel_pending,
            "owned kernel cleanup is pending; runtime paths retained",
        )?;
        let mut errors = Vec::new();
        for (path, expected) in self.entries.iter().rev() {
            let result = (|| {
                let info = path.symlink_metadata()?;
                require(
                    expected.as_ref() == Some(&(info.dev(), info.ino(), info.mode()))
                        && info.uid() == rustix::process::geteuid().as_raw()
                        && !info.file_type().is_symlink(),
                    "owned runtime entry identity changed or was unavailable at creation",
                )?;
                if info.is_dir() {
                    std::fs::remove_dir(path)
                } else if info.is_file() {
                    std::fs::remove_file(path)
                } else {
                    Err(io::Error::other("unexpected owned runtime entry type"))
                }
            })();
            if let Err(error) = result {
                errors.push(format!("{}: {error}", path.display()));
            }
        }
        require(
            errors.is_empty(),
            &format!("exact runtime cleanup failures: {errors:?}"),
        )?;
        self.entries.clear();
        Ok(())
    }
}

fn read_small(directory: &impl AsFd, name: &str) -> io::Result<String> {
    let fd = fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let mut bytes = Vec::new();
    File::from(fd).take(4097).read_to_end(&mut bytes)?;
    require(
        bytes.len() <= 4096,
        "observation exceeds its fixed read bound",
    )?;
    String::from_utf8(bytes).map_err(io::Error::other)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Actor {
    pid: u32,
    start_ticks: u64,
    ppid: u32,
}

fn actor(directory: &impl AsFd, pid: u32) -> io::Result<Actor> {
    let stat = read_small(directory, "stat")?;
    let (head, tail) = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::other("malformed proc stat"))?;
    require(
        head.split_once(' ')
            .and_then(|(n, _)| n.parse::<u32>().ok())
            == Some(pid),
        "proc PID differs",
    )?;
    let fields: Vec<_> = tail.split_ascii_whitespace().collect();
    require(
        fields.len() >= 20
            && fields[0].len() == 1
            && !matches!(fields[0], "Z" | "X" | "x" | "T" | "t"),
        "launcher is dead/stopped or proc stat is malformed",
    )?;
    Ok(Actor {
        pid,
        ppid: fields[1].parse().map_err(io::Error::other)?,
        start_ticks: fields[19].parse().map_err(io::Error::other)?,
    })
}

fn open_process(pid: u32) -> io::Result<OwnedFd> {
    fs::open(
        format!("/proc/{pid}"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(Into::into)
}

fn parked_state(
    job: &mut Native,
    process: &OwnedFd,
    original: &Actor,
    named_group: &Path,
    group: &OwnedFd,
    group_identity: ObjectIdentity,
    members: &[(OwnedFd, Actor)],
) -> io::Result<()> {
    job.observe()?;
    // While unreleased, Native rejects duplicate READY, EXIT, FAULT and EOF.
    job.poll_control()?;
    require(
        job.ready()
            && !job.setup_expired()
            && !job.launcher_reaped()
            && job.guest_status().is_none(),
        "parked launcher lost READY/liveness or produced status",
    )?;
    require(
        job.stdout.bytes.is_empty()
            && job.stderr.bytes.is_empty()
            && !job.stdout.eof
            && !job.stderr.eof
            && job.stdout.discarded == 0
            && job.stderr.discarded == 0,
        "parked launcher emitted streams or EOF",
    )?;
    require(
        actor(process, original.pid)? == *original && original.ppid == std::process::id(),
        "original launcher generation/parent changed",
    )?;
    job.group.verify_limits()?;
    require(
        job.group.populated()? && job.group.contains_process(original.pid)?,
        "original live launcher lost owned group membership",
    )?;
    let named = fs::open(
        named_group,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    require(
        identity(&named)? == group_identity && identity(group)? == group_identity,
        "owned group identity changed",
    )?;
    let mut actual = read_small(group, "cgroup.procs")?
        .lines()
        .map(|row| row.parse::<u32>().map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    let mut expected: Vec<_> = members.iter().map(|(_, actor)| actor.pid).collect();
    actual.sort_unstable();
    expected.sort_unstable();
    require(
        actual == expected,
        "parked launcher/init/guest membership changed",
    )?;
    for (pinned, original_member) in members {
        require(
            actor(pinned, original_member.pid)? == *original_member
                && job.group.contains_process(original_member.pid)?,
            "parked member generation/liveness/group changed",
        )?;
    }
    Ok(())
}

fn hold_parked(
    job: &mut Native,
    named_group: &Path,
    witness: &mut Value,
) -> io::Result<ObjectIdentity> {
    *witness = json!({"status":"OBSERVING","observation_elapsed_ns":[],"requested_hold_ns":200_000_000u64,
        "scope":"same live owned launcher and empty output observed while EXEC withheld; no first-instruction proof"});
    let group = fs::open(
        named_group,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let group_identity = identity(&group)?;
    witness["group_identity"] = json!(group_identity);
    let pids = read_small(&group, "cgroup.procs")?;
    let rows: Vec<_> = pids.lines().collect();
    require(
        rows.len() == 3,
        "READY must retain the fixed outer launcher, namespace init and gated guest",
    )?;
    let mut members = Vec::new();
    for row in rows {
        let pid = row.parse::<u32>().map_err(io::Error::other)?;
        require(pid > 1, "invalid owned member PID")?;
        let process = open_process(pid)?;
        let observed = actor(&process, pid)?;
        members.push((process, observed));
    }
    let launchers: Vec<_> = members
        .iter()
        .enumerate()
        .filter(|(_, (_, observed))| observed.ppid == std::process::id())
        .map(|(index, _)| index)
        .collect();
    require(
        launchers.len() == 1,
        "owned group lacks one exact live direct launcher",
    )?;
    let (process, original) = &members[launchers[0]];
    witness["launcher"] =
        json!({"pid":original.pid,"start_ticks":original.start_ticks,"ppid":original.ppid});
    witness["parked_members"] = json!(members.iter().map(|(_, member)|
        json!({"pid":member.pid,"start_ticks":member.start_ticks,"ppid":member.ppid})).collect::<Vec<_>>());
    parked_state(
        job,
        process,
        original,
        named_group,
        &group,
        group_identity,
        &members,
    )?;
    // Native exposes its READY-owned output only after quiescence. This exact
    // pinned owned proc descriptor is the read-only live observation channel.
    // It is used only after generation + group authority above; no setns/ptrace.
    let guest_root = fs::openat(
        process,
        "root",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let output = fs::openat2(
        &guest_root,
        "out",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    let output_identity = identity(&output)?;
    witness["output_identity"] = json!(output_identity);
    parked_state(
        job,
        process,
        original,
        named_group,
        &group,
        group_identity,
        &members,
    )?;
    let started = Instant::now();
    let mut observations = Vec::new();
    loop {
        parked_state(
            job,
            process,
            original,
            named_group,
            &group,
            group_identity,
            &members,
        )?;
        // A fresh description gives every observation a new directory offset.
        let scan = fs::openat(
            &output,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        require(
            identity(&scan)? == output_identity,
            "output scan identity changed",
        )?;
        let mut entries = fs::Dir::read_from(&scan)?;
        let mut count = 0;
        while let Some(entry) = entries.read() {
            let entry = entry?;
            count += 1;
            require(
                count <= 3 && matches!(entry.file_name().to_bytes(), b"." | b".."),
                "parked output directory contains an artifact",
            )?;
        }
        require(
            identity(&output)? == output_identity,
            "parked output identity changed",
        )?;
        parked_state(
            job,
            process,
            original,
            named_group,
            &group,
            group_identity,
            &members,
        )?;
        let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).map_err(io::Error::other)?;
        require(
            elapsed_ns <= 500_000_000,
            "parked interval exceeded its fixed 500 ms observation bound",
        )?;
        require(
            observations.len() < 128,
            "parked observation count exceeds bound",
        )?;
        observations.push(elapsed_ns);
        witness["observation_elapsed_ns"] = json!(observations);
        if elapsed_ns >= 200_000_000 {
            break;
        }
        std::thread::sleep(Duration::from_millis(3));
    }
    require(
        observations.len() >= 2,
        "parking interval lacks bracketed repeated observations",
    )?;
    require(
        observations
            .last()
            .is_some_and(|elapsed| (200_000_000..=500_000_000).contains(elapsed)),
        "final stored parked observation must be within 200 to 500 ms",
    )?;
    // All observer FDs are dropped when returning, before intentional stop.
    witness["status"] = json!("LIVE_PARKED_INTERVAL_OBSERVED");
    witness["maximum_hold_ns"] = json!(500_000_000u64);
    Ok(output_identity)
}

fn cleanup(job: &mut Native) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        job.check_deadline()?;
        job.observe()?;
        if job.quiescent()? && job.try_remove_empty_group()? {
            require(job.launcher_reaped(), "cleanup lacks launcher reap")?;
            return Ok(());
        }
        tick(deadline)?;
    }
}

fn check_output(
    job: &mut Native,
    released: bool,
    live_identity: Option<ObjectIdentity>,
) -> io::Result<()> {
    let output = job
        .take_quiescent_output()?
        .ok_or_else(|| io::Error::other("authenticated READY lost its output descriptor"))?;
    if let Some(expected) = live_identity {
        require(
            identity(&output)? == expected,
            "live output observation differs from exact READY-owned descriptor",
        )?;
    }
    let summary = fs::openat2(
        &output,
        "summary.json",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    );
    if !released {
        return require(
            matches!(summary, Err(rustix::io::Errno::NOENT)) && job.guest_status().is_none(),
            "withheld EXEC produced summary bytes or guest status",
        );
    }
    require(
        job.guest_status().is_some_and(|status| status.success()),
        "released summary did not have a successful authenticated guest exit",
    )?;
    let fd = summary?;
    let info = fs::fstat(&fd)?;
    require(
        info.st_mode & 0o170000 == 0o100000 && info.st_nlink == 1,
        "summary is not a single-link regular file",
    )?;
    let mut bytes = Vec::new();
    File::from(fd).take(1025).read_to_end(&mut bytes)?;
    require(
        bytes == b"{\"count\":3,\"sum\":13}\n",
        "released summary differs from the literal independent expected bytes",
    )
}

struct Inputs {
    launcher: PathBuf,
    fixture: PathBuf,
    fixture_sha256: String,
    work: PathBuf,
    jobs: PathBuf,
}

fn recover_unstarted(root: &JobsRoot, instance: &str, id: &str) -> io::Result<()> {
    let name = format!("hr-{instance}-{id}");
    if !root.list_job_names()?.contains(&name) {
        return Ok(());
    }
    // Only after our create attempt and before spawn was ever called. An
    // unexpectedly populated object is not safe to adopt/kill on this path.
    let mut group = root.recover_owned(instance, id)?;
    require(
        !group.populated()?,
        "unstarted owned group unexpectedly populated; recovery refused",
    )?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !group.try_remove_empty()? {
        tick(deadline)?;
    }
    require(
        !root.list_job_names()?.contains(&name),
        "unstarted group remains after recovery",
    )
}

fn construct_native(
    root: &JobsRoot,
    instance: &str,
    id: &str,
    paths: &mut OwnedPaths,
) -> io::Result<Native> {
    let name = format!("hr-{instance}-{id}");
    require(
        !root.list_job_names()?.contains(&name),
        "random owned group name already exists; refuse adoption",
    )?;
    paths.kernel_pending = true;
    let created = root.create(instance, id);
    let result = match created {
        Ok(group) => Native::new(group),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // Exclusive create did not grant ownership of the existing object.
            paths.kernel_pending = false;
            eprintln!(
                "{}",
                json!({"event":"startup-exclusive-create-refusal","group":name,
                "error":error.to_string(),"foreign_object_cleanup_attempted":false})
            );
            return Err(error);
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(job) => Ok(job),
        Err(original) => {
            let recovered = recover_unstarted(root, instance, id);
            paths.kernel_pending = recovered.is_err();
            eprintln!(
                "{}",
                json!({"event":"startup-construction-failure","group":name,
                "error":original.to_string(),"owned_empty_group_recovery":format!("{recovered:?}")})
            );
            Err(io::Error::other(format!(
                "startup: {original}; empty-group recovery={recovered:?}; group={name}"
            )))
        }
    }
}

fn exercise(
    root: &JobsRoot,
    inputs: &Inputs,
    released: bool,
    paths: &mut OwnedPaths,
) -> io::Result<()> {
    let case = if released { "released" } else { "withheld" };
    let work = inputs.work.join(case);
    paths.mkdir(&work)?;
    let scratch = work.join("root");
    let input = work.join("input");
    paths.mkdir(&scratch)?;
    paths.mkdir(&input)?;
    paths.file(
        &input.join("data.ndjson"),
        b"{\"value\":8}\n{\"value\":-2}\n{\"value\":7}\n",
    )?;
    let executable = File::open(&inputs.fixture)?;
    let digest = image::sha256(&image::read_image(&executable)?);
    require(
        digest == inputs.fixture_sha256,
        "fixture bytes differ from the existing reviewed task fixture identity",
    )?;
    let executable = executable.into();
    let flags = OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let tree = fs::open(&input, flags, Mode::empty())?;
    let scratch = fs::open(&scratch, flags, Mode::empty())?;
    let instance = image::lower_hex(&nonce()?);
    let id = image::lower_hex(&nonce()?);
    let group_name = format!("hr-{instance}-{id}");
    // Retain exact cleanup identity before creating the test-owned group.
    paths.file(
        &work.join("owned-group.json"),
        format!(
            "{}\n",
            json!({"instance":instance,"job_id":id,"group":group_name})
        )
        .as_bytes(),
    )?;
    File::open(&work)?.sync_all()?;
    let abi = policy::landlock_abi()?;
    let mut job = construct_native(root, &instance, &id, paths)?;
    let mut parked_witness = Value::Null;
    let mut live_identity = None;
    let result: io::Result<()> = (|| {
        job.spawn(LaunchInputs {
            binary: &inputs.launcher,
            executable: &executable,
            tree: &tree,
            scratch: &scratch,
            digest: &digest,
            argv: &["summary".into()],
            abi,
        })?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while !job.ready() {
            job.observe()?;
            job.poll_control()?;
            require(!job.launcher_reaped(), "launcher exited before READY")?;
            tick(deadline)?;
        }
        // Native::ready follows authenticated READY + validated retained output.
        job.group.verify_limits()?;
        require(job.group.populated()?, "READY job group is not populated")?;
        require(
            job.guest_status().is_none() && job.stdout.bytes.is_empty(),
            "guest completion appeared before this test released EXEC",
        )?;
        if !released {
            let observed_output = hold_parked(
                &mut job,
                &inputs.jobs.join(&group_name),
                &mut parked_witness,
            )?;
            live_identity = Some(observed_output);
            job.stop()?;
            return Ok(());
        }
        job.release(Duration::from_secs(4))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            require(!job.check_deadline()?, "summary exceeded its wall deadline")?;
            job.observe()?;
            job.poll_control()?;
            if job.quiescent()? {
                return Ok(());
            }
            tick(deadline)?;
        }
    })();
    if let Err(original) = result {
        let stopped = job.stop();
        let cleaned = cleanup(&mut job);
        let absent = if cleaned.is_ok() {
            root.list_job_names().and_then(|names| {
                require(
                    !names.contains(&group_name),
                    "owned group remains after error cleanup",
                )
            })
        } else {
            Err(io::Error::other("cleanup did not establish removal"))
        };
        paths.kernel_pending = cleaned.is_err() || absent.is_err();
        eprintln!(
            "{}",
            json!({"event":"native-case-failure","case":case,"group":group_name,
            "error":original.to_string(),"stop":format!("{stopped:?}"),"cleanup":format!("{cleaned:?}"),
            "group_absence":format!("{absent:?}"),"runtime_paths_retained":paths.kernel_pending,"parked_witness":parked_witness})
        );
        return Err(io::Error::other(format!(
            "{case}: {original}; stop={stopped:?}; owned cleanup={cleaned:?}; group absence={absent:?}; group={group_name}"
        )));
    }
    let cleaned = cleanup(&mut job)
        .and_then(|_| root.list_job_names())
        .and_then(|names| {
            require(
                !names.contains(&group_name),
                "owned group remains after confirmed removal",
            )
        });
    if let Err(original) = cleaned {
        let stopped = job.stop();
        let recovery = cleanup(&mut job)
            .and_then(|_| root.list_job_names())
            .and_then(|names| {
                require(
                    !names.contains(&group_name),
                    "owned group remains after cleanup recovery",
                )
            });
        paths.kernel_pending = recovery.is_err();
        eprintln!(
            "{}",
            json!({"event":"native-cleanup-failure","case":case,"group":group_name,
            "error":original.to_string(),"stop":format!("{stopped:?}"),"bounded_recovery":format!("{recovery:?}"),
            "parked_witness":parked_witness,"runtime_paths_retained":paths.kernel_pending})
        );
        return Err(io::Error::other(format!(
            "cleanup: {original}; stop={stopped:?}; recovery={recovery:?}; group={group_name}"
        )));
    }
    paths.kernel_pending = false;
    let checked = check_output(&mut job, released, live_identity);
    println!(
        "{}",
        json!({"case":case,"authenticated_ready":true,"exec_released":released,"parked_witness":parked_witness,"output_check":format!("{checked:?}"),
            "expected_summary_present":released,"launcher_reaped":true,
            "owned_group_removed":true,"group":group_name,
            "scope":"AC-004 positive/withheld subset; no first-instruction or failure-injection claim"})
    );
    checked
}

#[test]
fn approved_summary_runs_after_ready_and_withheld_exec_has_no_summary() -> io::Result<()> {
    let parent = setting("HEARTHRUN_BARRIER_PARENT")?;
    bounded_parent(&parent)?;
    let launcher = setting("HEARTHRUN_LAUNCHER")?;
    let fixture = setting("HEARTHRUN_FIXTURE")?;
    let doctor = setting("HEARTHRUN_DOCTOR")?;
    for path in [&launcher, &fixture, &doctor] {
        regular(path)?;
    }
    let jobs = setting("HEARTHRUN_JOBS")?;
    let fixture_sha256 = std::env::var("HEARTHRUN_PROFILE_FIXTURE_SHA256").map_err(|error| {
        io::Error::other(format!("reviewed fixture SHA256 is required: {error}"))
    })?;
    require(
        fixture_sha256.len() == 64
            && fixture_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "fixture SHA256 must be the existing reviewed lowercase identity",
    )?;
    // This real doctor runs only when the integrated native test is invoked.
    let report = Command::new(doctor)
        .arg("--cgroup-root")
        .arg(&jobs)
        .env("TMPDIR", &parent)
        .output()?;
    let value: serde_json::Value = serde_json::from_slice(&report.stdout)?;
    require(
        report.status.success() && value["compatible"] == true,
        "current operational doctor refused native execution",
    )?;
    let work = parent.join(format!("barrier-{}", image::lower_hex(&nonce()?)));
    let mut paths = OwnedPaths::default();
    let inputs = Inputs {
        launcher,
        fixture,
        fixture_sha256,
        work,
        jobs: jobs.clone(),
    };
    let result = (|| {
        paths.mkdir(&inputs.work)?;
        let root = JobsRoot::open(&jobs, rustix::process::getuid().as_raw())?;
        exercise(&root, &inputs, true, &mut paths)?;
        exercise(&root, &inputs, false, &mut paths)
    })();
    let runtime_cleanup = paths.cleanup_exact();
    eprintln!(
        "{}",
        json!({"event":"invocation-cleanup","work":inputs.work,
        "test_result":format!("{result:?}"),"exact_runtime_cleanup":format!("{runtime_cleanup:?}"),
        "kernel_cleanup_pending":paths.kernel_pending})
    );
    match (result, runtime_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (result, cleanup) => Err(io::Error::other(format!(
            "barrier result={result:?}; exact runtime cleanup={cleanup:?}"
        ))),
    }
}
