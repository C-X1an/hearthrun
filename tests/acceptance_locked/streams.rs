//! Locked stream retention and event-ring observations.
use super::*;
use crate::output::StreamOutput;
use std::io::Cursor;

#[path = "native_check.rs"]
mod native_check;

const RETAINED_PER_STREAM: usize = 1_048_576;
const JOB: &str = "11111111111111111111111111111111";

#[test]
fn oversized_bytes_stop_at_each_stream_cap() {
    let bytes = vec![b'x'; RETAINED_PER_STREAM + 73_219];
    for _ in 0..2 {
        let mut source = Cursor::new(&bytes);
        let mut stream = StreamOutput::default();
        for _ in 0..32 {
            stream.drain(&mut source).unwrap();
            assert!(
                stream.bytes.len() <= RETAINED_PER_STREAM,
                "retained stream exceeded exactly 1 MiB"
            );
            if stream.eof {
                break;
            }
        }
        assert!(stream.eof && stream.truncated());
        assert_eq!(stream.bytes, bytes[..RETAINED_PER_STREAM]);
        assert_eq!(stream.discarded, 73_219);
    }
    println!("{{\"case\":\"stream_buffer_bound\",\"status\":\"PASS\",\"per_stream_bytes\":1048576,\"discarded_bytes_per_stream\":73219}}");
}

fn setting(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("set {name}")));
    assert!(path.is_absolute());
    path
}

fn page(scheduler: &mut Scheduler, after_seq: u64) -> Value {
    match scheduler
        .request(Request::Events {
            job_id: JOB.into(),
            after_seq,
            limit: 100,
        })
        .resolve()
    {
        Reply::Success(data) => data,
        Reply::Error(error) => panic!("events page failed: {error:?}"),
    }
}

#[test]
fn real_stream_flood_and_finite_event_ring() {
    native_check::run(
        "tests/integration/resources.py",
        &["--streams-only"],
        &[
            ("--bin-dir", "HEARTHRUN_STREAM_TEST_BIN_DIR"),
            ("--doctor", "HEARTHRUN_STREAM_TEST_DOCTOR"),
            ("--fixture", "HEARTHRUN_STREAM_TEST_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_STREAM_TEST_WORK"),
        ],
    );

    let jobs = setting("HEARTHRUN_JOBS");
    let uid = rustix::process::geteuid().as_raw();
    assert_ne!(uid, 0);
    assert_eq!(rustix::process::getuid().as_raw(), uid);
    assert!(rustix::process::getgroups().unwrap().is_empty());
    let root = JobsRoot::open(&jobs, uid).unwrap();
    assert!(root.list_job_names().unwrap().is_empty());
    let state = setting("HEARTHRUN_STREAM_TEST_RING");
    super::terminal::bounded_work(&state);
    let mut scheduler = Scheduler::open(Config {
        state,
        root: Some(jobs),
        launcher: setting("HEARTHRUN_STREAM_TEST_BIN_DIR").join("hearthrun-launcher"),
        doctor: setting("HEARTHRUN_STREAM_TEST_DOCTOR"),
    })
    .unwrap();
    assert_eq!(scheduler.doctor["compatible"], true);

    let submission = Submission {
        request_id: "2".repeat(32),
        profile_id: "example".into(),
        stage_id: "3".repeat(32),
        argv: vec!["empty".into()],
        wall_ms: 1000,
    };
    let mut record = JobRecord::intent(
        scheduler.store.instance_id().into(),
        JOB.into(),
        &submission,
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        "2026-01-01T00:00:00Z".into(),
    )
    .unwrap();
    // The finite guest exercises real paging above. Generate synthetic events
    // in the same scheduler event path to test exact rollover beyond 1,024.
    for sequence in 1..=1027 {
        record.sequence = sequence;
        scheduler.emit(&record);
    }
    scheduler.records.insert(JOB.into(), record);
    let stale = page(&mut scheduler, 0);
    assert_eq!(stale["truncated"], true);
    assert_eq!(stale["events"][0]["sequence"], 4);
    assert_eq!(stale["next_seq"], 103);
    let mut observed = Vec::new();
    let mut after_seq = 3;
    for _ in 0..11 {
        let next = page(&mut scheduler, after_seq);
        let events = next["events"].as_array().unwrap();
        assert!((1..=100).contains(&events.len()));
        assert_eq!(next["truncated"], false);
        for event in events {
            assert_eq!(event["job_id"], JOB);
            observed.push(event["sequence"].as_u64().unwrap());
        }
        after_seq = next["next_seq"].as_u64().unwrap();
        assert_eq!(after_seq, *observed.last().unwrap());
    }
    assert_eq!(observed, (4..=1027).collect::<Vec<_>>());
    let end = page(&mut scheduler, 1027);
    assert_eq!(end, json!({"events":[],"next_seq":1027,"truncated":false}));
    assert!(root.list_job_names().unwrap().is_empty());
    println!("{{\"case\":\"event_ring_rollover\",\"status\":\"PASS\",\"synthetic_events_emitted\":1027,\"retained_events\":1024,\"stale_cursor_truncated\":true}}");
}
