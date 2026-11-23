//! Native filesystem regression for an uncertain terminal metadata rename.
use super::*;
use crate::artifacts::{Publisher, Stream};
use serde_json::json;
use std::os::unix::fs::DirBuilderExt;

fn checkpoint(
    store: &mut Store,
    publisher: &Publisher,
    id: char,
    request: char,
    stdout: &[u8],
) -> JobRecord {
    let job_id = id.to_string().repeat(32);
    let submission = Submission {
        request_id: request.to_string().repeat(32),
        profile_id: "example".into(),
        stage_id: "33333333333333333333333333333333".into(),
        argv: vec!["empty".into()],
        wall_ms: 1000,
    };
    let mut record = JobRecord::intent(
        store.instance_id().into(),
        job_id.clone(),
        &submission,
        "a".repeat(64),
        "a".repeat(64),
        "a".repeat(64),
        "b".repeat(64),
        "2026-01-01T00:00:00Z".into(),
    )
    .unwrap();
    store.write(&record).unwrap();
    for (state, stage) in [
        ("STARTING", "CGROUP_CREATED"),
        ("CLEANUP_PENDING", "EXEC_RELEASED"),
        ("EXPORTING", "CLEANED"),
    ] {
        record.sequence += 1;
        record.state = state.into();
        record.launch_stage = stage.into();
        if state == "EXPORTING" {
            record.cleanup_confirmed = true;
            record.observed_exit = Some(ObservedExit {
                exit_code: Some(0),
                signal: None,
            });
        }
        store.write(&record).unwrap();
    }
    let metadata = json!({"status":"SUCCEEDED","cleanup_confirmed":true,"policy_sha256":"b".repeat(64),
        "environment_id":"journal-reopen-test","exit_code":0,"signal":null,"stdout_truncated":false,"stderr_truncated":false});
    let result = publisher
        .commit(&job_id, metadata, None, stdout, b"")
        .unwrap();
    record.sequence += 1;
    record.state = "SUCCEEDED".into();
    record.result_digest = Some(result.result_digest);
    record
}

#[test]
fn uncertain_terminal_rename_requires_successful_startup_sync() {
    let root = PathBuf::from(
        std::env::var_os("HEARTHRUN_ARTIFACT_TEST_ROOT")
            .expect("set HEARTHRUN_ARTIFACT_TEST_ROOT to the dedicated capped tmpfs"),
    );
    assert_eq!(root.canonicalize().unwrap(), root);
    let uid = rustix::process::geteuid().as_raw();
    let mount = open_root(&root, uid).unwrap();
    let space = fs::fstatvfs(&mount).unwrap();
    assert_ne!(uid, 0);
    assert_eq!(fs::fstatfs(&mount).unwrap().f_type as u64, 0x0102_1994);
    assert!((1..=128 * 1024 * 1024).contains(&(space.f_blocks * space.f_frsize)));
    let state = root.join(format!("journal-reopen-{}", random_id().unwrap()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    let mut store = Store::open(&state).unwrap();
    let publisher = Publisher::open(&state).unwrap();

    let prior = checkpoint(&mut store, &publisher, 'a', '1', b"prior result");
    store.write(&prior).unwrap();
    let candidate = checkpoint(&mut store, &publisher, 'b', '2', b"durable result bytes");
    let error = store
        .write_with_directory_sync(&candidate, |_| Err(rustix::io::Errno::IO))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::IoUncertain);
    assert_eq!(
        error.io_error().and_then(io::Error::raw_os_error),
        Some(libc::EIO)
    );
    assert!(store.frozen.get());
    let named = state
        .join("records")
        .join(format!("{}.json", candidate.job_id));
    assert_eq!(
        decode_record(&std::fs::read(named).unwrap()).unwrap(),
        candidate
    );
    drop(publisher);
    drop(store);

    let dir_identity = |path: &Path| {
        let stat = fs::stat(path).unwrap();
        (stat.st_dev, stat.st_ino)
    };
    let directories = [dir_identity(&state.join("records")), dir_identity(&state)];
    let diagnostics = [
        "cannot sync recovered records directory",
        "cannot sync recovered state root",
    ];
    for (fail_at, &diagnostic) in diagnostics.iter().enumerate() {
        let mut calls = 0;
        let result = Store::open_with_directory_sync(&state, |fd| {
            let stat = fs::fstat(fd).unwrap();
            assert_eq!((stat.st_dev, stat.st_ino), directories[calls]);
            calls += 1;
            if calls == fail_at + 1 {
                Err(rustix::io::Errno::IO)
            } else {
                fs::fsync(fd)
            }
        });
        let Err(error) = result else {
            panic!("startup accepted journal without required directory sync")
        };
        assert_eq!(error.kind, ErrorKind::IoUncertain);
        assert_eq!(error.message, diagnostic);
        assert_eq!(
            error.io_error().and_then(io::Error::raw_os_error),
            Some(libc::EIO)
        );
        assert_eq!(calls, fail_at + 1);
        println!("startup_refused={diagnostic:?} errno=EIO terminal_reply=false");
    }

    let store = Store::open(&state).unwrap();
    let publisher = Publisher::open(&state).unwrap();
    let records = store.records().unwrap();
    assert_eq!(records, vec![prior.clone(), candidate.clone()]);
    for (record, bytes) in [
        (prior, b"prior result".as_slice()),
        (candidate, b"durable result bytes".as_slice()),
    ] {
        assert_eq!(
            publisher
                .read_stream(
                    &record.job_id,
                    record.result_digest.as_deref().unwrap(),
                    Stream::Stdout
                )
                .unwrap(),
            bytes
        );
    }
    println!("later_startup_sync=verified existing_receipts=2 earlier_write_acknowledged=false");
}
