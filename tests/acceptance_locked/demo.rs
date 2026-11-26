//! AC-023 machine portion only; browser keyboard/focus remains HA-004.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native recorded-demo verification requires Linux x86-64");
mod native_check;

#[test]
fn real_demo_observations_report_links_and_text_distinctions() {
    native_check::run(
        "tests/e2e/demo.py",
        &["--check-report"],
        &[
            ("--bin-dir", "HEARTHRUN_BIN_DIR"),
            ("--doctor", "HEARTHRUN_DOCTOR"),
            ("--fixture", "HEARTHRUN_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_DEMO_WORK"),
        ],
    );
}
