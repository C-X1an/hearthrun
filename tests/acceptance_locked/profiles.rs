//! Locked AC-018 approved profile identity and typed authority refusal checks.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native profile identity verification requires Linux x86-64");
mod native_check;

#[test]
fn approved_protected_bytes_survive_owned_inert_source_replacement() {
    native_check::run(
        "tests/security/profiles.py",
        &[],
        &[
            ("--bin-dir", "HEARTHRUN_BIN_DIR"),
            ("--doctor", "HEARTHRUN_DOCTOR"),
            ("--fixture", "HEARTHRUN_FIXTURE"),
            ("--fixture-sha256", "HEARTHRUN_PROFILE_FIXTURE_SHA256"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_PROFILE_WORK"),
        ],
    );
}
