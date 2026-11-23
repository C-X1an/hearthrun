//! Runs the supported-host admission refusal checks at the locked test path.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native host-refusal verification requires Linux x86-64");

mod native_check;

#[test]
fn approved_submissions_are_refused_when_required_capabilities_are_missing() {
    native_check::run(
        "tests/integration/unsupported.py",
        &[],
        &[
            ("--bin-dir", "HEARTHRUN_HOST_TEST_BIN_DIR"),
            ("--doctor", "HEARTHRUN_HOST_TEST_DOCTOR"),
            ("--fixture", "HEARTHRUN_HOST_TEST_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_HOST_TEST_WORK"),
        ],
    );
}
