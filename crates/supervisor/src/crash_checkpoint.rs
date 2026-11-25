//! DRAFT: compile only with cfg(all(test, feature = "native-verification")).
//! The parent kills its exact Popen child. This module never sends a signal.
use serde_json::{json, Value};
use std::io::{self, Write};
use std::time::{Duration, Instant};

pub(crate) const POINTS: &[&str] = &[
    "durable-create-intent",
    "created-before-spawn",
    "spawned-before-attach",
    "attached-before-prepare",
    "policy-ready-before-intent",
    "durable-exec-intent",
    "exec-sent-before-running",
    "running-hold-ready",
    "quiescent-export",
    "bundle-before-receipt",
];

pub(crate) fn selection() -> io::Result<Option<(String, String)>> {
    let point = std::env::var("HEARTHRUN_RECOVERY_CHECKPOINT").ok();
    let request = std::env::var("HEARTHRUN_RECOVERY_REQUEST").ok();
    match (point, request) {
        (None, None) => Ok(None),
        (Some(point), Some(request))
            if POINTS.contains(&point.as_str())
                && request.len() == 32
                && request
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Ok(Some((point, request)))
        }
        _ => Err(io::Error::other(
            "invalid fixed recovery checkpoint selection",
        )),
    }
}

pub(crate) fn hit(point: &str, job: &str, request: &str, witness: Value) -> io::Result<()> {
    let Some((selected, target)) = selection()? else {
        return Ok(());
    };
    if selected != point || target != request {
        return Ok(());
    }
    let packet = json!({"v":1,"point":point,"job_id":job,"request_id":request,
        "supervisor_pid":std::process::id(),"witness":witness});
    let bytes = serde_json::to_vec(&packet)?;
    if bytes.len() > 16 * 1024 {
        return Err(io::Error::other("checkpoint witness exceeds bound"));
    }
    let mut stdout = io::stdout().lock();
    stdout.write_all(b"HEARTHRUN_CRASH_CHECKPOINT ")?;
    stdout.write_all(&bytes)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    drop(stdout);
    // A missing parent is a real failure. The seam cannot release the gate on
    // timeout, nor pretend an intended operation completed.
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "parent did not kill checkpoint child",
    ))
}
