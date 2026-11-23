use std::path::Path;
use std::process::Command;

pub fn run(script: &str, switches: &[&str], bindings: &[(&str, &str)]) {
    let public = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("cannot locate the checked-out native tests");
    let mut command = Command::new("python3");
    command
        .current_dir(public)
        .args(["-B", script])
        .args(switches);
    for &(flag, variable) in bindings {
        command.arg(flag).arg(
            std::env::var_os(variable).unwrap_or_else(|| panic!("set {variable} to run {script}")),
        );
    }
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("cannot start {script}: {error}"));
    assert!(status.success(), "{script} exited {status}");
}
