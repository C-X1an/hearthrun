//! Scoped AC-005 positive: synthetic canary, absent proc/dev and approved input/output.
//! Full home/path/socket traversal coverage and the negative control remain open.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native filesystem policy verification requires Linux x86-64");
mod native_check;

#[test]
fn owned_canary_and_approved_io_have_no_observed_leak() {
    native_check::run(
        "tests/security/policy.py",
        &["--case", "isolation"],
        &[
            ("--bin-dir", "HEARTHRUN_BIN_DIR"),
            ("--doctor", "HEARTHRUN_DOCTOR"),
            ("--fixture", "HEARTHRUN_POLICY_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_FILESYSTEM_WORK"),
        ],
    );
}
