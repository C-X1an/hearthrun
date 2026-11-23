//! Runs the full real-kernel schedule oracle from the locked acceptance path.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native quiescence verification requires Linux x86-64");

mod native_check;

#[test]
fn full_seeded_quiescence_campaign() {
    native_check::run(
        "tests/integration/quiescence.py",
        &["--full", "--seed", "14014"],
        &[
            ("--bin-dir", "HEARTHRUN_QUIESCENCE_BIN_DIR"),
            ("--doctor", "HEARTHRUN_QUIESCENCE_DOCTOR"),
            ("--fixture", "HEARTHRUN_QUIESCENCE_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_QUIESCENCE_WORK"),
        ],
    );
}
