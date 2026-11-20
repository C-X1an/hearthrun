//! Native component smoke. Run explicitly in a disposable delegated scope.
use hearthrun_launcher::{cgroup::JobsRoot, image, policy};
use hearthrun_supervisor::lifecycle::{nonce, LaunchInputs, Native};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use std::fs::{create_dir, remove_dir, File};
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, Instant};

fn issue(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn wait(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(issue("native smoke deadline"));
    }
    std::thread::sleep(Duration::from_millis(3));
    Ok(())
}

struct Fixture<'a> {
    launcher: &'a Path,
    fixture: &'a Path,
    scratch: &'a Path,
    input: &'a Path,
}

fn exercise(root: &JobsRoot, fixture: &Fixture<'_>, case: &str, args: &[String]) -> io::Result<()> {
    let executable = File::open(fixture.fixture)?;
    let digest = image::sha256(&image::read_image(&executable)?);
    let executable = executable.into();
    let flags = OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let tree = fs::open(fixture.input, flags, Mode::empty())?;
    let scratch = fs::open(fixture.scratch, flags, Mode::empty())?;
    let instance = image::lower_hex(&nonce()?);
    let id = image::lower_hex(&nonce()?);
    let abi = policy::landlock_abi()?;
    let mut job = Native::new(root.create(&instance, &id)?)?;
    let result = (|| {
        job.spawn(LaunchInputs {
            binary: fixture.launcher,
            executable: &executable,
            tree: &tree,
            scratch: &scratch,
            digest: &digest,
            argv: args,
            abi,
        })?;
        run_case(&mut job, case)?;
        check_output(&mut job, case)
    })();
    if result.is_err() {
        eprintln!(
            "trusted launch diagnostics: {}",
            String::from_utf8_lossy(&job.stderr.bytes)
        );
        job.stop()?;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !job.quiescent()? {
        job.check_deadline()?;
        job.observe()?;
        wait(deadline)?;
    }
    job.group.remove_empty()?;
    result?;
    println!("case={case} reaped=true populated=0");
    Ok(())
}

fn run_case(job: &mut Native, case: &str) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !job.ready() {
        job.observe()?;
        job.poll_control()?;
        if job.launcher_reaped() {
            return Err(issue("launcher exited before policy ready"));
        }
        wait(deadline)?;
    }
    if case == "barrier" {
        // The approved transformation would write summary.json if given
        // permission. Withhold the second gate even after policy ready.
        job.stop()?;
    } else {
        let wall = if case == "watchdog" { 500 } else { 4000 };
        job.release(Duration::from_millis(wall))?;
    }
    if case == "hold" || case == "watchdog" {
        while !job
            .stdout
            .bytes
            .windows(14)
            .any(|word| word == b"detached-ready")
        {
            job.observe()?;
            job.poll_control()?;
            if job.launcher_reaped() {
                return Err(issue("detached fixture exited before readiness"));
            }
            wait(deadline)?;
        }
        if case == "watchdog" {
            // Hold this caller past the guest deadline without ticking the
            // lifecycle loop or issuing cleanup from this thread.
            std::thread::sleep(Duration::from_millis(900));
            if !job.check_deadline()? || job.group.populated()? {
                return Err(issue(
                    "deadline worker did not empty the stopped caller's group",
                ));
            }
        }
        job.stop()?;
    }
    let cleanup = Instant::now() + Duration::from_secs(5);
    loop {
        if job.check_deadline()? {
            return Err(issue("unexpected component smoke wall expiration"));
        }
        job.observe()?;
        job.poll_control()?;
        if job.quiescent()? {
            return Ok(());
        }
        wait(cleanup)?;
    }
}

fn check_output(job: &mut Native, case: &str) -> io::Result<()> {
    let output = job
        .take_quiescent_output()?
        .ok_or_else(|| issue("output descriptor lost"))?;
    let resolve = ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV;
    let open_artifact = || {
        fs::openat2(
            &output,
            "summary.json",
            OFlags::RDONLY,
            Mode::empty(),
            resolve,
        )
    };
    if matches!(case, "barrier" | "hold" | "watchdog") {
        if !matches!(open_artifact(), Err(rustix::io::Errno::NOENT)) || job.guest_status().is_some()
        {
            return Err(issue(
                "closed gate or cancellation leaked an execution result",
            ));
        }
        return Ok(());
    }
    let status = job
        .guest_status()
        .ok_or_else(|| issue("guest exit evidence absent"))?;
    if !status.success() {
        return Err(io::Error::other(format!("fixture exit {status}")));
    }
    if case == "summary" {
        let fd = open_artifact()?;
        let mut bytes = Vec::new();
        File::from(fd).take(1024).read_to_end(&mut bytes)?;
        if bytes != b"{\"count\":3,\"sum\":13}\n" {
            return Err(issue(
                "fixture output differed from independent expected result",
            ));
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    let [_, launcher, fixture, work, jobs_root]: [_; 5] = args
        .try_into()
        .map_err(|_| issue("usage: launch-smoke LAUNCHER FIXTURE OWNED_WORK JOBS_PARENT"))?;
    let _ = rustix::process::umask(Mode::RWXG | Mode::RWXO);
    let work = Path::new(&work);
    create_dir(work)?;
    let scratch = work.join("root");
    let input = work.join("input");
    create_dir(&scratch)?;
    create_dir(&input)?;
    let data = input.join("data.ndjson");
    let canary = work.join("canary");
    std::fs::write(&data, b"{\"value\":8}\n{\"value\":-2}\n{\"value\":7}\n")?;
    std::fs::write(&canary, b"synthetic host canary")?;
    let group = JobsRoot::open(Path::new(&jobs_root), rustix::process::getuid().as_raw())?;
    let fixtures = Fixture {
        launcher: Path::new(&launcher),
        fixture: Path::new(&fixture),
        scratch: &scratch,
        input: &input,
    };
    exercise(&group, &fixtures, "summary", &["summary".into()])?;
    exercise(&group, &fixtures, "barrier", &["summary".into()])?;
    exercise(
        &group,
        &fixtures,
        "check",
        &["check".into(), canary.to_string_lossy().into_owned()],
    )?;
    exercise(&group, &fixtures, "hold", &["hold".into()])?;
    exercise(&group, &fixtures, "watchdog", &["hold".into()])?;
    if std::fs::read(&canary)? != b"synthetic host canary" {
        return Err(issue("host canary changed"));
    }
    std::fs::remove_file(data)?;
    std::fs::remove_file(canary)?;
    remove_dir(scratch)?;
    remove_dir(input)?;
    remove_dir(work)?;
    Ok(())
}
