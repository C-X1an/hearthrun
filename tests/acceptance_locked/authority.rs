//! Scoped AC-007 positive: synthetic SECRET_CANARY and bounded guest FD enumeration.
//! A visibly injected inherited control FD and its negative control remain open.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native authority policy verification requires Linux x86-64");
mod native_check;

#[test]
fn fixed_environment_and_no_observed_extra_guest_descriptors() {
    native_check::run(
        "tests/security/policy.py",
        &["--case", "isolation"],
        &[
            ("--bin-dir", "HEARTHRUN_BIN_DIR"),
            ("--doctor", "HEARTHRUN_DOCTOR"),
            ("--fixture", "HEARTHRUN_POLICY_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_AUTHORITY_WORK"),
        ],
    );
}
