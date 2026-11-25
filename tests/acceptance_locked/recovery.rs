//! DRAFT AC-012 deterministic crash checkpoint gate. No native result claimed.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native recovery verification requires Linux x86-64");
mod native_check;

#[test]
fn real_crashes_at_fixed_startup_run_and_export_checkpoints() {
    native_check::run(
        "tests/integration/recovery.py",
        &["--checkpoint", "all"],
        &[
            ("--bin-dir", "HEARTHRUN_RECOVERY_TEST_BIN_DIR"),
            ("--doctor", "HEARTHRUN_RECOVERY_TEST_DOCTOR"),
            ("--fixture", "HEARTHRUN_RECOVERY_TEST_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--test-bin", "HEARTHRUN_RECOVERY_TEST_LIBTEST"),
            ("--work", "HEARTHRUN_RECOVERY_TEST_WORK"),
        ],
    );
}
