//! Real lost-response retry through the Unix socket and persistent ledger.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native idempotency verification requires Linux x86-64");

mod native_check;

#[test]
fn same_request_survives_a_lost_reply_and_restart() {
    native_check::run(
        "tests/integration/idempotency.py",
        &[],
        &[
            ("--bin-dir", "HEARTHRUN_RETRY_TEST_BIN_DIR"),
            ("--doctor", "HEARTHRUN_RETRY_TEST_DOCTOR"),
            ("--fixture", "HEARTHRUN_RETRY_TEST_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_RETRY_TEST_WORK"),
        ],
    );
}
