//! Error injection at persistence sites, compiled only in the verification test build.
use super::*;
use crate::scheduler::{Config, Scheduler};
use crate::server::Reply;
use crate::store::{JobRecord, ObservedExit, Store};
use hearthrun_domain::protocol::{Request, Submission};
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

#[test]
fn restart_discards_the_renamed_bundle_without_a_durable_receipt() {
    let env_path = |key: &str| {
        let path = PathBuf::from(std::env::var_os(key).unwrap_or_else(|| panic!("set {key}")));
        assert!(path.is_absolute() && path.canonicalize().unwrap() == path);
        path
    };
    let root = env_path("HEARTHRUN_ARTIFACT_TEST_ROOT");
    let uid = rustix::process::geteuid().as_raw();
    let guarded = open_root(&root, uid).unwrap();
    let space = fs::fstatvfs(&guarded).unwrap();
    assert_ne!(uid, 0);
    assert_eq!(fs::fstatfs(&guarded).unwrap().f_type as u64, TMPFS_MAGIC);
    assert!((1..=128 * 1024 * 1024).contains(&(space.f_blocks * space.f_frsize)));
    let state = root.join(format!("publisher-recovery-{}", random_id().unwrap()));
    private_dir(&state);

    let mut store = Store::open(&state).unwrap();
    let mut publisher = Publisher::open(&state).unwrap();
    let staged = |job: &str, request: &str, store: &mut Store| {
        let submission = Submission {
            request_id: request.into(),
            profile_id: "example".into(),
            stage_id: "33333333333333333333333333333333".into(),
            argv: vec!["empty".into()],
            wall_ms: 1000,
        };
        let mut record = JobRecord::intent(
            store.instance_id().into(),
            job.into(),
            &submission,
            "a".repeat(64),
            "a".repeat(64),
            "a".repeat(64),
            "b".repeat(64),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
        store.write(&record).unwrap();
        for (state, launch) in [
            ("STARTING", "CGROUP_CREATED"),
            ("CLEANUP_PENDING", "EXEC_RELEASED"),
            ("EXPORTING", "CLEANED"),
        ] {
            record.sequence += 1;
            record.state = state.into();
            record.launch_stage = launch.into();
            record.cleanup_confirmed = state == "EXPORTING";
            if record.cleanup_confirmed {
                record.observed_exit = Some(ObservedExit {
                    exit_code: Some(0),
                    signal: None,
                });
            }
            store.write(&record).unwrap();
        }
        record
    };
    let mut prior = staged(BASELINE, "11111111111111111111111111111111", &mut store);
    let committed = publisher
        .commit(BASELINE, test_metadata(BASELINE), None, b"prior", b"")
        .unwrap();
    prior.sequence += 1;
    prior.state = "SUCCEEDED".into();
    prior.result_digest = Some(committed.result_digest.clone());
    store.write(&prior).unwrap();

    let uncertain = staged(CANDIDATE, "22222222222222222222222222222222", &mut store);
    publisher.fail_at = Some("result parent fsync");
    let error = publisher
        .commit(
            CANDIDATE,
            test_metadata(CANDIDATE),
            None,
            b"uncommitted",
            b"",
        )
        .err()
        .expect("missing post-rename error");
    assert!(
        matches!(error, Error::Publication(detail) if detail.kind == PublicationKind::IoUncertain
        && detail.io_error().and_then(io::Error::raw_os_error) == Some(libc::EIO))
    );
    let renamed = state.join("results").join(CANDIDATE);
    assert_eq!(
        std::fs::read(renamed.join("stdout.bin")).unwrap(),
        b"uncommitted"
    );
    assert!(store.records().unwrap().contains(&uncertain));
    assert_eq!(uncertain.state, "EXPORTING");
    assert!(uncertain.result_digest.is_none());
    drop(publisher);
    drop(store);

    let jobs = env_path("HEARTHRUN_JOBS");
    let empty_jobs = || {
        !std::fs::read_dir(&jobs)
            .unwrap()
            .any(|entry| entry.unwrap().file_type().unwrap().is_dir())
    };
    assert!(
        empty_jobs(),
        "restart verification requires an empty delegation"
    );
    let mut scheduler = Scheduler::open(Config {
        state: state.clone(),
        root: Some(jobs.clone()),
        launcher: env_path("HEARTHRUN_FAULT_LAUNCHER"),
        doctor: env_path("HEARTHRUN_FAULT_DOCTOR"),
    })
    .unwrap();
    assert_eq!(scheduler.doctor["compatible"], true);
    let Reply::Success(interrupted) = scheduler
        .request(Request::Result(CANDIDATE.into()))
        .resolve()
    else {
        panic!("restart did not publish its own interrupted result");
    };
    assert_eq!(interrupted["metadata"]["status"], "INTERRUPTED");
    assert!(interrupted["metadata"]["artifacts"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(std::fs::read(renamed.join("stdout.bin"))
        .unwrap()
        .is_empty());
    let Reply::Success(original) = scheduler
        .request(Request::Result(BASELINE.into()))
        .resolve()
    else {
        panic!("restart lost the prior verified result");
    };
    assert_eq!(original["result_digest"], committed.result_digest);
    assert!(empty_jobs());
    drop(scheduler);
    let store = Store::open(&state).unwrap();
    let recovered = store
        .records()
        .unwrap()
        .into_iter()
        .find(|record| record.job_id == CANDIDATE)
        .unwrap();
    assert_eq!(recovered.state, "INTERRUPTED");
    assert_eq!(
        recovered.cancel_reason.as_deref(),
        Some("SUPERVISOR_RESTART")
    );
    assert_eq!(
        recovered.result_digest.as_deref(),
        interrupted["result_digest"].as_str()
    );
    println!("synthetic_checkpoint=post_rename errno=EIO receipt_before_restart=false recovered=INTERRUPTED prior_result_readable=true owned_cgroups=0");
}
