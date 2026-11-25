//! Native scheduler acceptance with two bounded, test-only cleanup pauses.
use super::*;
use crate::lifecycle::CleanupPause;
use crate::server::Server;
use hearthrun_domain::MAX_HEADER_BYTES;
use rustix::{fs, process};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::{fs::DirBuilderExt, net::UnixStream};
use std::panic::{self, AssertUnwindSafe};

fn setting(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("set {name}")));
    assert!(path.is_absolute(), "expected an absolute path for {name}");
    path
}

pub(super) fn bounded_work(path: &Path) {
    let parent = path.parent().unwrap();
    assert_eq!(parent, parent.canonicalize().unwrap());
    let parent_fd = private_dir(parent).unwrap();
    assert_eq!(fs::fstatfs(&parent_fd).unwrap().f_type as u64, 0x0102_1994);
    let size = fs::fstatvfs(&parent_fd).unwrap();
    assert!((1..=12_000_000_000).contains(&(size.f_blocks * size.f_frsize)));
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let mount = mountinfo
        .lines()
        .filter_map(|line| line.split_once(" - "))
        .filter_map(|(left, right)| {
            let point = left.split_ascii_whitespace().nth(4)?;
            parent.starts_with(point).then_some((point, right))
        })
        .max_by_key(|(point, _)| point.len())
        .unwrap();
    let mut fields = mount.1.split_ascii_whitespace();
    assert_eq!(fields.next(), Some("tmpfs"));
    assert!(fields
        .nth(1)
        .unwrap()
        .split(',')
        .any(|flag| flag == "noswap"));
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

struct NativeCase {
    scheduler: Scheduler,
    socket: Server,
    state: PathBuf,
}

impl NativeCase {
    fn request(&mut self, header: Value, payload: &[u8]) -> Value {
        let mut peer = UnixStream::connect(self.state.join("control.sock")).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let bytes = serde_json::to_vec(&header).unwrap();
        peer.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
            .unwrap();
        peer.write_all(&bytes).unwrap();
        peer.write_all(payload).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let incoming = self
            .socket
            .poll_accept()
            .unwrap()
            .expect("one owned connection")
            .receive()
            .unwrap_or_else(|_| panic!("test request was not framed and authenticated"));
        if header["op"] == "stage" {
            self.scheduler.stages.receive(incoming).unwrap();
        } else {
            let (request, responder) = incoming
                .finish()
                .unwrap_or_else(|_| panic!("test request did not finish"))
                .into_parts();
            responder
                .respond(self.scheduler.request(request).resolve())
                .unwrap();
        }
        let mut length = [0; 4];
        peer.read_exact(&mut length).unwrap();
        let length = u32::from_be_bytes(length) as usize;
        assert!((1..=MAX_HEADER_BYTES).contains(&length));
        let mut response = vec![0; length];
        peer.read_exact(&mut response).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        let response = protocol::strict_json(&response).unwrap();
        assert_eq!(response["v"], 1);
        response
    }

    fn success(&mut self, header: Value, payload: &[u8]) -> Value {
        let response = self.request(header, payload);
        assert_eq!(response["ok"], true, "{response}");
        response["result"].clone()
    }

    fn tick_until(&mut self, reason: &str, ready: impl Fn(&Scheduler) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(4);
        while !ready(&self.scheduler) {
            assert!(Instant::now() < deadline, "{reason}");
            self.scheduler.tick().unwrap();
            thread::sleep(Duration::from_millis(8));
        }
    }

    fn pause(&mut self, job: &str, pause: CleanupPause) -> u32 {
        self.scheduler
            .active
            .iter_mut()
            .find(|active| active.id == job)
            .unwrap()
            .native
            .pause_cleanup(pause)
            .expect("active launcher exists")
    }

    fn check_pending(&mut self, job: &str, queued: &str, launcher: u32, populated: bool) {
        let phase = if populated { "populated" } else { "unreaped" };
        let seen = self.success(json!({"v":1,"op":"inspect","job_id":job}), &[]);
        let metrics = self.success(json!({"v":1,"op":"metrics"}), &[]);
        let next = self.success(json!({"v":1,"op":"inspect","job_id":queued}), &[]);
        let result = self.request(json!({"v":1,"op":"result","job_id":job}), &[]);
        let active = self
            .scheduler
            .active
            .iter()
            .find(|active| active.id == job)
            .unwrap();
        let group_populated = active.native.group.populated().unwrap();
        let (process_state, process_parent) = launcher_state(launcher).unwrap();
        let inventory = std::fs::read_dir(self.state.join("results"))
            .unwrap()
            .count();
        let durable = self
            .scheduler
            .store
            .records()
            .unwrap()
            .into_iter()
            .find(|record| record.job_id == job)
            .unwrap();
        println!(
            "{}",
            json!({"case":"delayed_cleanup_observation","phase":phase,"kernel_populated":group_populated,
            "launcher_state":process_state,"state":seen["state"],"journal_state":durable.state,
            "cleanup_confirmed":seen["cleanup_confirmed"],"result_error":result["error"]["code"],
            "active":metrics["active"],"queued":metrics["queued"],"result_directory_entries":inventory})
        );
        assert_eq!(group_populated, populated);
        assert_eq!(process_parent, std::process::id());
        assert_eq!(process_state == "Z", !populated);
        assert_eq!(
            seen["state"], "CLEANUP_PENDING",
            "terminal state reported before observed cleanup: {phase}"
        );
        assert_eq!(durable.state, "CLEANUP_PENDING");
        assert!(seen["outcome"].is_null() && seen["result_digest"].is_null());
        assert_eq!(seen["cleanup_confirmed"], false);
        assert!(!durable.cleanup_confirmed && durable.result_digest.is_none());
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["code"], "NOT_READY");
        assert_eq!(inventory, 0, "publication began while cleanup was pending");
        assert_eq!(metrics["active"], MAX_RUNNING);
        assert_eq!(metrics["cleanup_pending"], 1);
        assert_eq!(metrics["queued"], 1);
        assert_eq!(next["state"], "QUEUED");
        assert!(next["started_monotonic_ns"].is_null());
    }

    fn exercise(&mut self) {
        let payload = b"{\"value\":1}\n";
        let stage = self.success(
            json!({"v":1,"op":"stage","files":[{
            "path":"data.ndjson","size":payload.len(),"sha256":image::sha256(payload)}]}),
            payload,
        );
        let mut admit = |index: usize, mode: &str| {
            let result = self.success(
                json!({"v":1,"op":"submit","request_id":format!("{index:032x}"),
                "profile_id":"example","stage_id":stage["stage_id"],"wall_ms":15000,"argv":[mode]}),
                &[],
            );
            result["job_id"].as_str().unwrap().to_owned()
        };
        let running: Vec<_> = (1..=MAX_RUNNING).map(|i| admit(i, "hold")).collect();
        let queued = admit(MAX_RUNNING + 1, "empty");
        let target = &running[0];
        self.tick_until(
            "four native jobs did not reach fixture readiness",
            |scheduler| {
                scheduler.active.len() == MAX_RUNNING
                    && scheduler.active.iter().all(|active| {
                        scheduler.records[&active.id].state == "RUNNING"
                            && active.native.stdout.bytes == b"detached-ready\n"
                            && active.native.group.populated().unwrap()
                    })
            },
        );
        let launcher = self.pause(target, CleanupPause::Stop);
        let leaf = self
            .scheduler
            .active
            .iter()
            .find(|active| &active.id == target)
            .unwrap()
            .native
            .group
            .name()
            .to_owned();
        let cancel = self.success(json!({"v":1,"op":"cancel","job_id":target}), &[]);
        assert_eq!(cancel["cancel_requested"], true);
        for _ in 0..5 {
            self.scheduler.tick().unwrap();
            self.check_pending(target, &queued, launcher, true);
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(self.pause(target, CleanupPause::Reap), launcher);
        self.tick_until(
            "no kernel witness for empty cgroup with an unreaped launcher",
            |scheduler| {
                let active = scheduler
                    .active
                    .iter()
                    .find(|active| &active.id == target)
                    .unwrap();
                !active.native.group.populated().unwrap()
                    && launcher_state(launcher)
                        .is_some_and(|(state, parent)| state == "Z" && parent == std::process::id())
            },
        );
        for _ in 0..5 {
            self.scheduler.tick().unwrap();
            self.check_pending(target, &queued, launcher, false);
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(self.pause(target, CleanupPause::None), launcher);
        self.tick_until(
            "cleanup did not finish after releasing the reap",
            |scheduler| {
                scheduler.records[target].state == "CANCELLED"
                    && scheduler.records[&queued].state == "SUCCEEDED"
            },
        );
        assert!(launcher_state(launcher).is_none());
        assert!(!self
            .scheduler
            .root
            .as_ref()
            .unwrap()
            .list_job_names()
            .unwrap()
            .contains(&leaf));
        for (job, state) in [(target, "CANCELLED"), (&queued, "SUCCEEDED")] {
            let visible = self.success(json!({"v":1,"op":"inspect","job_id":job}), &[]);
            let result = self.success(json!({"v":1,"op":"result","job_id":job}), &[]);
            assert_eq!(visible["state"], state);
            assert_eq!(visible["cleanup_confirmed"], true);
            assert_eq!(result["metadata"]["status"], state);
            assert_eq!(result["metadata"]["cleanup_confirmed"], true);
            assert_eq!(result["result_digest"], visible["result_digest"]);
        }
        self.check_removal_pending(&stage["stage_id"]);
    }

    fn check_removal_pending(&mut self, stage_id: &Value) {
        let admitted = self.success(
            json!({"v":1,"op":"submit","request_id":"6".repeat(32),"profile_id":"example",
                "stage_id":stage_id,"wall_ms":15000,"argv":["summary"]}),
            &[],
        );
        let job = admitted["job_id"].as_str().unwrap();
        self.scheduler.tick().unwrap();
        let launcher = self.pause(job, CleanupPause::Remove);
        self.tick_until(
            "successful fixture did not reach the removal fence",
            |scheduler| {
                let active = scheduler
                    .active
                    .iter()
                    .find(|active| active.id == job)
                    .unwrap();
                scheduler.records[job].state == "CLEANUP_PENDING"
                    && active.native.quiescent().unwrap()
            },
        );
        let active = self
            .scheduler
            .active
            .iter()
            .find(|active| active.id == job)
            .unwrap();
        let leaf = active.native.group.name().to_owned();
        let output = active
            .native
            .output_identity()
            .unwrap()
            .expect("retained output directory");
        let published = self.state.join("results").join(job);
        for _ in 0..3 {
            self.scheduler.tick().unwrap();
            let current = self
                .scheduler
                .active
                .iter()
                .find(|active| active.id == job)
                .unwrap();
            assert!(current.native.group.empty_for_removal().unwrap());
            assert_eq!(current.native.output_identity().unwrap(), Some(output));
            assert_eq!(self.scheduler.records[job].state, "CLEANUP_PENDING");
            let visible = self.success(json!({"v":1,"op":"inspect","job_id":job}), &[]);
            assert_eq!(visible["state"], "CLEANUP_PENDING");
            assert_eq!(visible["cleanup_confirmed"], false);
            let metrics = self.success(json!({"v":1,"op":"metrics"}), &[]);
            assert!(metrics["active"].as_u64().unwrap() >= 1);
            assert_eq!(metrics["admission_open"], true);
            let refused = self.request(json!({"v":1,"op":"result","job_id":job}), &[]);
            assert_eq!(refused["error"]["code"], "NOT_READY");
            assert!(!published.exists());
        }
        assert!(launcher_state(launcher).is_none());
        assert_eq!(self.pause(job, CleanupPause::None), launcher);
        self.tick_until(
            "retained result did not publish after removal",
            |scheduler| scheduler.records[job].state == "SUCCEEDED",
        );
        assert!(!self
            .scheduler
            .root
            .as_ref()
            .unwrap()
            .list_job_names()
            .unwrap()
            .contains(&leaf));
        let verified = self.success(json!({"v":1,"op":"result","job_id":job}), &[]);
        let expected = b"{\"count\":1,\"sum\":1}\n";
        let bytes = staging::read_owned(&published.join("artifacts/summary.json"), 1024).unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(verified["metadata"]["artifacts"][0]["path"], "summary.json");
        assert_eq!(
            verified["metadata"]["artifacts"][0]["sha256"],
            image::sha256(expected)
        );
        println!("{{\"case\":\"pending_cgroup_removal\",\"status\":\"PASS\",\"pending_observations\":3,\"descriptor_identity_retained\":true,\"artifact_verified_after_removal\":true}}");
    }
}

fn launcher_state(pid: u32) -> Option<(String, u32)> {
    let raw = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => panic!("could not read owned launcher state: {error}"),
    };
    let mut fields = raw.rsplit_once(") ").unwrap().1.split_ascii_whitespace();
    Some((
        fields.next().unwrap().to_owned(),
        fields.next().unwrap().parse().unwrap(),
    ))
}

#[test]
fn delayed_cleanup_retains_slot_and_blocks_result() {
    let uid = process::geteuid().as_raw();
    assert_ne!(uid, 0);
    assert_eq!(process::getuid().as_raw(), uid);
    assert!(process::getgroups().unwrap().is_empty());
    let state = setting("HEARTHRUN_TERMINAL_TEST_WORK");
    let jobs = setting("HEARTHRUN_JOBS");
    let owned_jobs = JobsRoot::open(&jobs, uid).unwrap();
    assert!(owned_jobs.list_job_names().unwrap().is_empty());
    bounded_work(&state);
    let cfg = Config {
        state: state.clone(),
        root: Some(jobs),
        launcher: setting("HEARTHRUN_TERMINAL_TEST_LAUNCHER"),
        doctor: setting("HEARTHRUN_TERMINAL_TEST_DOCTOR"),
    };
    let scheduler = Scheduler::open(cfg).unwrap();
    assert_eq!(scheduler.doctor["compatible"], true);
    profiles::install(
        &state,
        "example",
        &setting("HEARTHRUN_TERMINAL_TEST_FIXTURE"),
    )
    .unwrap();
    let socket = Server::bind(&state, uid).unwrap();
    let mut test = NativeCase {
        scheduler,
        socket,
        state,
    };
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| test.exercise()));
    for active in &mut test.scheduler.active {
        active.native.pause_cleanup(CleanupPause::None);
    }
    let until = Instant::now() + Duration::from_secs(5);
    let mut first_error = None;
    let mut errors = 0;
    while !test.scheduler.is_idle() && Instant::now() < until {
        if let Err(error) = test.scheduler.cleanup_failed() {
            errors += 1;
            first_error.get_or_insert_with(|| error.to_string());
        }
        thread::sleep(Duration::from_millis(8));
    }
    let idle = test.scheduler.is_idle();
    let socket_error = test.socket.close().err().map(|error| error.to_string());
    let inventory = owned_jobs.list_job_names();
    let clean = idle
        && errors == 0
        && socket_error.is_none()
        && inventory.as_ref().is_ok_and(Vec::is_empty);
    if clean {
        println!("{{\"case\":\"teardown\",\"status\":\"PASS\",\"owned_cgroups_remaining\":0}}");
    } else {
        println!(
            "{}",
            json!({"case":"teardown","status":"FAIL","scheduler_idle":idle,
            "cleanup_errors":errors,"first_error":first_error,"socket_error":socket_error,
            "owned_cgroups_remaining":inventory.as_ref().ok().map(Vec::len),
            "inventory_error":inventory.err().map(|error| error.to_string())})
        );
    }
    if let Err(failure) = outcome {
        panic::resume_unwind(failure);
    }
    assert!(
        clean,
        "native case teardown could not confirm clean ownership"
    );
    println!("{{\"case\":\"delayed_cleanup\",\"status\":\"PASS\",\"populated_observations\":5,\"unreaped_observations\":5,\"queue_released_after_confirmation\":true}}");
}
