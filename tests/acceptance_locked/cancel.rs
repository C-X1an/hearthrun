//! Native AC-010 owner cancellation and wall expiry of the approved detached fixture.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native scheduler acceptance requires Linux x86-64");
mod native_check;

#[test]
fn owner_cancel_and_separate_wall_expiry_clean_original_detached_processes() {
    native_check::run(
        "tests/integration/scheduler.py",
        &["--case", "cancel"],
        &[
            ("--bin-dir", "HEARTHRUN_BIN_DIR"),
            ("--doctor", "HEARTHRUN_DOCTOR"),
            ("--fixture", "HEARTHRUN_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_CANCEL_WORK"),
        ],
    );
}
