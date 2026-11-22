//! Runs the full real-kernel schedule oracle from the locked acceptance path.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native quiescence verification requires Linux x86-64");

use std::path::Path;
use std::process::Command;

#[test]
fn full_seeded_quiescence_campaign() {
    let public = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("cannot locate the public test source");
    let mut cmd = Command::new("python3");
    cmd.current_dir(&public).args([
        "-B",
        "tests/integration/quiescence.py",
        "--full",
        "--seed",
        "14014",
    ]);
    for (flag, variable) in [
        ("--bin-dir", "HEARTHRUN_QUIESCENCE_BIN_DIR"),
        ("--doctor", "HEARTHRUN_QUIESCENCE_DOCTOR"),
        ("--fixture", "HEARTHRUN_QUIESCENCE_FIXTURE"),
        ("--cgroup-root", "HEARTHRUN_JOBS"),
        ("--work", "HEARTHRUN_QUIESCENCE_WORK"),
    ] {
        cmd.arg(flag).arg(
            std::env::var_os(variable).unwrap_or_else(|| {
                panic!("set {variable} for the full native quiescence campaign")
            }),
        );
    }
    let exit = cmd
        .status()
        .expect("cannot start the native schedule oracle");
    assert!(exit.success(), "full native schedule oracle exited {exit}");
}
