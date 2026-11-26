//! Scoped AC-008 positive: fixed invalid-operation denials and benign x32 identity query.
//! Architecture-mismatch and architecture-check omission controls remain open.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native syscall policy verification requires Linux x86-64");
mod native_check;

#[test]
fn approved_io_then_fixed_denials_and_x32_sigsys() {
    native_check::run(
        "tests/security/policy.py",
        &["--case", "seccomp"],
        &[
            ("--bin-dir", "HEARTHRUN_BIN_DIR"),
            ("--doctor", "HEARTHRUN_DOCTOR"),
            ("--fixture", "HEARTHRUN_POLICY_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_SECCOMP_WORK"),
        ],
    );
}
