//! Scoped AC-006 positive: actual socket refusals and owned listeners.
//! Inherited-descriptor and pass/fail/pass negative controls remain open.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native network policy verification requires Linux x86-64");
mod native_check;

#[test]
fn owned_listeners_observe_controls_and_no_guest_messages() {
    native_check::run(
        "tests/security/network.py",
        &[],
        &[
            ("--bin-dir", "HEARTHRUN_BIN_DIR"),
            ("--doctor", "HEARTHRUN_DOCTOR"),
            ("--fixture", "HEARTHRUN_NETWORK_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_NETWORK_WORK"),
        ],
    );
}
