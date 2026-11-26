//! Native positive AC-009 resource limits; the pids.max negative control is separate.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native resource acceptance requires Linux x86-64");
mod native_check;

#[test]
fn memory_pids_cpu_and_stream_limits_keep_supervisor_responsive() {
    native_check::run(
        "tests/integration/resources.py",
        &[],
        &[
            ("--bin-dir", "HEARTHRUN_BIN_DIR"),
            ("--doctor", "HEARTHRUN_DOCTOR"),
            ("--fixture", "HEARTHRUN_RESOURCE_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_RESOURCE_WORK"),
        ],
    );
}
