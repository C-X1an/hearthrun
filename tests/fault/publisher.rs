//! Error injection at persistence sites, compiled only in the verification test build.
use super::*;
use crate::store::Store;
use serde_json::json;
use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

const BASELINE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CANDIDATE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SITES: &[(&str, &str)] = &[
    ("stage directory", "cannot create exclusive result stage"),
    (
        "artifact directory",
        "cannot create result artifact directory",
    ),
    ("artifact parent creation", "cannot create artifact parent"),
    ("artifact create", "cannot exclusively create result file"),
    ("artifact copy", "cannot copy exported artifact"),
    ("artifact fsync", "cannot sync exported artifact"),
    ("stdout create", "cannot exclusively create result file"),
    ("stdout write", "cannot write retained stream"),
    ("stdout fsync", "cannot sync retained stream"),
    ("stderr create", "cannot exclusively create result file"),
    ("stderr write", "cannot write retained stream"),
    ("stderr fsync", "cannot sync retained stream"),
    ("metadata create", "cannot exclusively create result file"),
    ("metadata write", "cannot write result metadata"),
    ("metadata fsync", "cannot sync result metadata"),
    (
        "artifact parent fsync",
        "cannot sync artifact parent directory",
    ),
    ("artifact root fsync", "cannot sync artifact root directory"),
    ("stage fsync", "cannot sync prepared result directory"),
    (
        "result rename",
        "cannot atomically publish result without replacement",
    ),
    ("result parent fsync", "cannot sync committed result parent"),
];

fn test_metadata(id: &str) -> Value {
    json!({"v":1,"job_id":id,"status":"SUCCEEDED","cleanup_confirmed":true,
           "policy_sha256":"b".repeat(64),"environment_id":"isolated-publisher-fault-test",
           "exit_code":0,"signal":null,"stdout_truncated":false,"stderr_truncated":false,
           "artifacts":[]})
}

fn private_dir(path: &Path) {
    DirBuilder::new().mode(0o700).create(path).unwrap();
}

#[test]
fn every_result_persistence_error_surfaces_without_a_receipt() {
    let root = PathBuf::from(
        std::env::var_os("HEARTHRUN_ARTIFACT_TEST_ROOT")
            .expect("set HEARTHRUN_ARTIFACT_TEST_ROOT to a dedicated capped tmpfs"),
    );
    assert!(root.is_absolute() && root.canonicalize().unwrap() == root);
    let uid = rustix::process::geteuid().as_raw();
    let parent = open_root(&root, uid).unwrap();
    let limit = fs::fstatvfs(&parent).unwrap();
    assert_eq!(fs::fstatfs(&parent).unwrap().f_type as u64, TMPFS_MAGIC);
    assert!(uid != 0 && (1..=128 * 1024 * 1024).contains(&(limit.f_blocks * limit.f_frsize)));

    let base = root.join(format!("publisher-faults-{}", random_id().unwrap()));
    private_dir(&base);
    let output = base.join("output");
    private_dir(&output);
    let child = output.join("nested");
    private_dir(&child);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(child.join("synthetic.txt"))
        .unwrap();
    file.write_all(b"synthetic artifact bytes\n").unwrap();
    file.sync_all().unwrap();
    drop(file);

    for (index, &(site, expected_message)) in SITES.iter().enumerate() {
        let state = base.join(format!("case-{index:02}"));
        private_dir(&state);
        let _store = Store::open(&state).unwrap();
        let mut publisher = Publisher::open(&state).unwrap();
        let baseline = publisher
            .commit(BASELINE, test_metadata(BASELINE), None, b"prior", b"")
            .unwrap();
        publisher.fail_at = Some(site);
        let held = fs::open(
            &output,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let attempt = publisher.commit(
            CANDIDATE,
            test_metadata(CANDIDATE),
            Some(held),
            b"output",
            b"diagnostic",
        );
        let Err(Error::Publication(error)) = attempt else {
            panic!("{site} did not reject publication");
        };
        assert_eq!(error.kind, PublicationKind::IoUncertain);
        assert_eq!(error.message, expected_message);
        assert_eq!(
            error.io_error().and_then(io::Error::raw_os_error),
            Some(libc::EIO)
        );
        assert!(publisher.is_frozen());
        let visible = state.join("results").join(CANDIDATE).exists();
        assert_eq!(visible, site == "result parent fsync");
        assert_eq!(
            publisher
                .read_stream(BASELINE, &baseline.result_digest, Stream::Stdout)
                .unwrap(),
            b"prior"
        );
        // A directory renamed before parent fsync remains an uncommitted candidate.
        // No receipt exists for a caller to journal against either outcome.
        println!("fault={site:?} receipt=false candidate_name_present={visible} prior_result_readable=true");
    }
}
