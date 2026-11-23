//! Runs the supported-host admission refusal checks at the locked test path.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native host-refusal verification requires Linux x86-64");

use std::path::Path;
use std::process::Command;

#[test]
fn approved_submissions_are_refused_when_required_capabilities_are_missing() {
    let public = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("cannot locate the checked-out product tests");
    let mut cmd = Command::new("python3");
    cmd.current_dir(public)
        .args(["-B", "tests/integration/unsupported.py"]);
    for (flag, variable) in [
        ("--bin-dir", "HEARTHRUN_HOST_TEST_BIN_DIR"),
        ("--doctor", "HEARTHRUN_HOST_TEST_DOCTOR"),
        ("--fixture", "HEARTHRUN_HOST_TEST_FIXTURE"),
        ("--cgroup-root", "HEARTHRUN_JOBS"),
        ("--work", "HEARTHRUN_HOST_TEST_WORK"),
    ] {
        cmd.arg(flag).arg(
            std::env::var_os(variable)
                .unwrap_or_else(|| panic!("set {variable} for real host-refusal verification")),
        );
    }
    let status = cmd
        .status()
        .expect("cannot start the native host-refusal harness");
    assert!(
        status.success(),
        "native host-refusal harness exited {status}"
    );
}
