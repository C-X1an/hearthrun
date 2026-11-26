//! Native AC-002 admission, typed capacity refusal, and single-slot FIFO check.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native scheduler acceptance requires Linux x86-64");
mod native_check;

#[test]
fn four_active_sixteen_queued_reject_twenty_first_and_preserve_fifo() {
    native_check::run(
        "tests/integration/scheduler.py",
        &["--case", "admission"],
        &[
            ("--bin-dir", "HEARTHRUN_BIN_DIR"),
            ("--doctor", "HEARTHRUN_DOCTOR"),
            ("--fixture", "HEARTHRUN_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_ADMISSION_WORK"),
        ],
    );
}
