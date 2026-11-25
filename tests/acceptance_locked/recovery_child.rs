//! DRAFT scheduler submodule: an exec-separated libtest fixture daemon.
//! Real Server authentication/framing and real Scheduler/launcher/storage.
use super::*;
use crate::server::Server;
use std::io::Write;

fn setting(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("set {name}")));
    assert!(path.is_absolute() && path.canonicalize().unwrap() == path);
    path
}

#[test]
#[ignore = "exec fixture only; recovery_acceptance invokes this exact test with --ignored"]
fn checkpoint_daemon_child() {
    assert_eq!(
        std::env::var("HEARTHRUN_RECOVERY_CHILD").as_deref(),
        Ok("v1")
    );
    crate::crash_checkpoint::selection().unwrap();
    let uid = rustix::process::geteuid().as_raw();
    assert_ne!(uid, 0);
    assert_eq!(rustix::process::getuid().as_raw(), uid);
    assert!(rustix::process::getgroups().unwrap().is_empty());
    let state = setting("HEARTHRUN_RECOVERY_STATE");
    let mut scheduler = Scheduler::open(Config {
        state: state.clone(),
        root: Some(setting("HEARTHRUN_RECOVERY_JOBS")),
        launcher: setting("HEARTHRUN_RECOVERY_LAUNCHER"),
        doctor: setting("HEARTHRUN_RECOVERY_DOCTOR"),
    })
    .unwrap();
    assert_eq!(
        scheduler.doctor["compatible"], true,
        "mandatory host controls unavailable"
    );
    let mut socket = Server::bind(&state, uid).unwrap();
    println!("HEARTHRUN_RECOVERY_CHILD_READY");
    io::stdout().flush().unwrap();
    // No private shutdown protocol, synthetic state transitions, or replacement
    // recovery implementation. The parent intentionally SIGKILLs this direct
    // child; the ordinary daemon performs restart and orderly teardown.
    let until = Instant::now() + Duration::from_secs(120);
    let result: Result<()> = (|| {
        while Instant::now() < until {
            if let Some(connection) = socket.poll_accept()? {
                let incoming = connection
                    .receive()
                    .map_err(|_| fail("recovery request refused"))?;
                if matches!(incoming.request(), Request::Stage(_)) {
                    scheduler.stages.receive(incoming)?;
                } else {
                    let valid = incoming
                        .finish()
                        .map_err(|_| fail("recovery request incomplete"))?;
                    let (request, responder) = valid.into_parts();
                    responder.respond(scheduler.request(request).resolve())?;
                }
            }
            scheduler.tick()?;
            thread::sleep(Duration::from_millis(3));
        }
        Err(fail("parent left recovery fixture daemon running").into())
    })();
    let cleanup_until = Instant::now() + Duration::from_secs(6);
    let mut cleanup_errors = Vec::new();
    while !scheduler.is_idle() && Instant::now() < cleanup_until {
        if let Err(error) = scheduler.cleanup_failed() {
            cleanup_errors.push(error.to_string());
        }
        thread::sleep(Duration::from_millis(10));
    }
    let idle = scheduler.is_idle();
    let closed = socket.close();
    assert!(
        idle && cleanup_errors.is_empty(),
        "fixture cleanup pending: {cleanup_errors:?}"
    );
    closed.unwrap();
    result.unwrap();
}
