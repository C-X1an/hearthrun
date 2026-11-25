//! Single owner for admission, lifecycle, durable state, and published results.
use crate::artifacts::{self, CommittedResult, Publisher};
use crate::lifecycle::{LaunchInputs, Native};
use crate::profiles;
use crate::retention::{persistent_outcome, Retention};
use crate::server::{ErrorCode, Reply};
use crate::staging::{self, create_private_dir, private_dir, Stages};
use crate::store::{self, JobRecord, ObservedExit, Store};
use hearthrun_domain::{
    protocol::{self, Request, Submission},
    JobId, MAX_QUEUED, MAX_RUNNING,
};
use hearthrun_launcher::{cgroup::JobsRoot, image, policy};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Stop = (&'static str, &'static str);
type Outcome = (&'static str, Option<&'static str>);
const QUEUE_TIMEOUT: Duration = Duration::from_secs(30);
const EVENT_LIMIT: usize = 1024;

fn fail(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn terminal(state: &str) -> bool {
    matches!(
        state,
        "SUCCEEDED" | "FAILED" | "CANCELLED" | "TIMED_OUT" | "INTERRUPTED"
    )
}

pub struct Config {
    pub state: PathBuf,
    pub root: Option<PathBuf>,
    pub launcher: PathBuf,
    pub doctor: PathBuf,
}

struct Active {
    id: String,
    native: Native,
    deadline: Option<Instant>,
    wall: Duration,
    stop: Option<Stop>,
    publication: Option<PendingPublication>,
}

struct PendingPublication {
    stop: Option<Stop>,
    worker: JoinHandle<Result<Published>>,
}

struct Published {
    outcome: Outcome,
    result: CommittedResult,
}

pub struct ResultRead {
    id: String,
    digest: String,
    publisher: Arc<Publisher>,
    _pin: Arc<()>,
}

pub enum Response {
    Immediate(Reply),
    Read(ResultRead),
}

impl Response {
    pub fn resolve(self) -> Reply {
        match self {
            Self::Immediate(reply) => reply,
            Self::Read(read) => match read.publisher.read_result(&read.id, &read.digest) {
                Ok(result) => Reply::Success(
                    json!({"metadata":result.metadata,"result_digest":result.result_digest}),
                ),
                Err(error) => {
                    eprintln!("committed result could not be verified: {error}");
                    Reply::error(ErrorCode::IoUncertain, "result bytes could not be verified")
                }
            },
        }
    }
}

pub struct Scheduler {
    cfg: Config,
    store: Store,
    publisher: Arc<Publisher>,
    retention: Retention,
    pub stages: Arc<Stages>,
    pub doctor: Value,
    abi: u32,
    policy_digest: String,
    environment: String,
    root: Option<JobsRoot>,
    records: BTreeMap<String, JobRecord>,
    events: BTreeMap<String, VecDeque<Value>>,
    queue: VecDeque<(String, Instant)>,
    active: Vec<Active>,
    elapsed_origin: Instant,
    accepting: bool,
    uncertain: bool,
    next_prune: Instant,
}

impl Scheduler {
    pub fn open(cfg: Config) -> Result<Self> {
        let store = Store::open(&cfg.state)?;
        let scratch = cfg.state.join("scratch");
        create_private_dir(&scratch)?;
        let mut doctor = probe(&cfg, &scratch)?;
        let uid = rustix::process::geteuid().as_raw();
        let root = match cfg
            .root
            .as_ref()
            .map(|path| JobsRoot::open(path, uid))
            .transpose()
        {
            Ok(root) => root,
            Err(error) => {
                doctor["features"]["jobs_root_identity"] = json!({"passed":false,"errno":error.raw_os_error(),
                    "detail":"the supervisor could not validate the configured cgroup root"});
                eprintln!("cgroup root validation failed: {error}");
                None
            }
        };
        let abi = doctor["landlock_abi"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);
        let compatible = doctor["compatible"] == true && root.is_some() && (3..=7).contains(&abi);
        if !compatible {
            doctor["compatible"] = json!(false);
            doctor["status"] = json!("BLOCKED");
        }
        let publisher = Arc::new(Publisher::open(&cfg.state)?);
        let retention = Retention::open(&cfg.state)?;
        let stages = Arc::new(Stages::open(&cfg.state)?);
        let environment = format!(
            "linux-x86_64-{}",
            image::sha256(std::fs::read("/proc/sys/kernel/osrelease")?.as_slice())
        );
        let records = store
            .records()?
            .into_iter()
            .map(|record| (record.job_id.clone(), record))
            .collect();
        let mut scheduler = Self {
            cfg,
            store,
            publisher,
            retention,
            stages,
            doctor,
            abi,
            policy_digest: if compatible {
                policy::policy_digest(abi)
            } else {
                String::new()
            },
            environment,
            root,
            records,
            events: BTreeMap::new(),
            queue: VecDeque::new(),
            active: Vec::new(),
            elapsed_origin: Instant::now(),
            accepting: compatible,
            uncertain: false,
            next_prune: Instant::now(),
        };
        scheduler.recover()?;
        Ok(scheduler)
    }

    pub fn is_idle(&self) -> bool {
        self.active.is_empty() && self.queue.is_empty()
    }

    fn storage_certain(&self) -> bool {
        !self.uncertain && !self.publisher.is_frozen() && !self.store.is_frozen()
    }

    /// The authenticated IPC worker may write staging data before responding.
    pub fn retain_storage(&self) -> io::Result<OwnedFd> {
        self.store.retain_lock()
    }

    pub fn request(&mut self, request: Request) -> Response {
        match self.dispatch(request) {
            Ok(reply) => reply,
            Err(error) => {
                eprintln!("supervisor operation failed: {error}");
                if self.store.is_frozen() || self.publisher.is_frozen() {
                    self.uncertain = true;
                }
                Response::Immediate(Reply::error(
                    ErrorCode::IoUncertain,
                    "operation could not verify durable state",
                ))
            }
        }
    }

    fn dispatch(&mut self, request: Request) -> Result<Response> {
        let reply = match request {
            Request::Doctor => Reply::Success(self.doctor.clone()),
            Request::Metrics => {
                Reply::Success(json!({"queued":self.queue.len(),"active":self.active.len(),
                "cleanup_pending":self.records.values().filter(|record|record.state=="CLEANUP_PENDING").count(),
                "retained_requests":self.records.len(),"admission_open":self.accepting && self.storage_certain()}))
            }
            Request::Submit(submission) => return self.submit(submission).map(Response::Immediate),
            Request::Stage(_) => Reply::error(
                ErrorCode::Internal,
                "staging must complete in the connection worker",
            ),
            Request::Cancel(id) => return self.cancel(&id).map(Response::Immediate),
            Request::Inspect(id) => match self.records.get(&id) {
                Some(record) => Reply::Success(inspect(record)),
                None => Reply::error(ErrorCode::NotFound, "job ID not found"),
            },
            Request::Events {
                job_id,
                after_seq,
                limit,
            } => match self.records.get(&job_id) {
                Some(record) => {
                    let history = self.events.get(&job_id);
                    let first = history
                        .and_then(|events| events.front())
                        .and_then(|event| event["sequence"].as_u64())
                        .unwrap_or(record.sequence.saturating_add(1));
                    let events: Vec<_> = history
                        .into_iter()
                        .flatten()
                        .filter(|event| event["sequence"].as_u64().unwrap_or(0) > after_seq)
                        .take(limit as usize)
                        .cloned()
                        .collect();
                    let next = events
                        .last()
                        .and_then(|event| event["sequence"].as_u64())
                        .unwrap_or(after_seq);
                    Reply::Success(
                        json!({"events":events,"next_seq":next,"truncated":after_seq.saturating_add(1)<first}),
                    )
                }
                None => Reply::error(ErrorCode::NotFound, "job ID not found"),
            },
            Request::Result(id) => {
                let record = self.records.get(&id);
                match record.and_then(|record| record.result_digest.as_ref()) {
                    Some(digest) if !self.retention.evicted(&id, digest)? => {
                        let pin = self.retention.pin(&id)?;
                        return Ok(Response::Read(ResultRead {
                            id,
                            digest: digest.clone(),
                            publisher: Arc::clone(&self.publisher),
                            _pin: pin,
                        }));
                    }
                    Some(_) => Reply::error(ErrorCode::NotFound, "result retention expired"),
                    None if record.is_some() => {
                        Reply::error(ErrorCode::NotReady, "result is not committed")
                    }
                    None => Reply::error(ErrorCode::NotFound, "job ID not found"),
                }
            }
        };
        Ok(Response::Immediate(reply))
    }

    fn submit(&mut self, submission: Submission) -> Result<Reply> {
        match self.store.lookup_request(&submission) {
            Ok(Some(record)) => return Ok(Reply::Success(admitted(&record))),
            Ok(None) => {}
            Err(error) if error.kind == store::ErrorKind::Conflict => {
                return Ok(Reply::error(
                    ErrorCode::Conflict,
                    "request ID already names different content",
                ));
            }
            Err(error) => return Err(error.into()),
        }
        if !self.storage_certain() {
            return Ok(Reply::error(
                ErrorCode::IoUncertain,
                "admission closed for state reconciliation",
            ));
        }
        if !self.accepting {
            return Ok(Reply::error(
                ErrorCode::UnsupportedHost,
                "admission is closed; inspect doctor",
            ));
        }
        if self.queue.len() >= MAX_QUEUED {
            return Ok(Reply::error(ErrorCode::QueueFull, "waiting queue is full"));
        }
        let profile = match profiles::load(&self.cfg.state, &submission.profile_id) {
            Ok(profile) => profile,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Reply::error(
                    ErrorCode::ProfileNotFound,
                    "operator profile unavailable",
                ));
            }
            Err(_) => {
                return Ok(Reply::error(
                    ErrorCode::ProfileDigestMismatch,
                    "operator approval cannot be verified",
                ))
            }
        };
        let stage = match self.stages.open_tree(&submission.stage_id) {
            Ok(Some((_, digest))) => digest,
            Ok(None) => {
                return Ok(Reply::error(
                    ErrorCode::StageNotFound,
                    "staging ID unavailable",
                ))
            }
            Err(_) => {
                return Ok(Reply::error(
                    ErrorCode::StageDigestMismatch,
                    "staged bytes cannot be verified",
                ))
            }
        };
        let reserved = self.retention.make_room(
            &self.publisher,
            &self.records,
            self.queue.len() + self.active.len() + 1,
        );
        if let Err(error) = reserved {
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(Reply::error(
                    ErrorCode::StorageFull,
                    "retained result storage is reserved",
                ));
            }
            return Err(error.into());
        }
        let record = JobRecord::intent(
            self.store.instance_id().to_owned(),
            self.store.new_id()?,
            &submission,
            stage,
            profile.digest,
            profile.image_digest,
            self.policy_digest.clone(),
            utc(staging::now()?)?,
        )?;
        match self.store.write(&record) {
            Ok(()) => {}
            Err(error) if error.kind == store::ErrorKind::StorageFull => {
                return Ok(Reply::error(
                    ErrorCode::StorageFull,
                    "durable identity budget is full",
                ));
            }
            Err(error) => return Err(error.into()),
        }
        self.emit(&record);
        self.queue
            .push_back((record.job_id.clone(), Instant::now()));
        let reply = Reply::Success(admitted(&record));
        self.records.insert(record.job_id.clone(), record);
        Ok(reply)
    }

    fn cancel(&mut self, id: &str) -> Result<Reply> {
        let Some(record) = self.records.get(id) else {
            return Ok(Reply::error(ErrorCode::NotFound, "job ID not found"));
        };
        if terminal(&record.state) {
            return Ok(Reply::Success(
                json!({"cancel_requested":record.state=="CANCELLED","state":record.state}),
            ));
        }
        if let Some(index) = self.queue.iter().position(|(queued, _)| queued == id) {
            self.finish(
                id,
                "CANCELLED",
                Some("USER_CANCEL"),
                None,
                (&[], &[]),
                (false, false),
            )?;
            self.queue.remove(index);
        } else if let Some(index) = self.active.iter().position(|job| job.id == id) {
            let mut job = self.active.remove(index);
            let result = self.request_stop(&mut job, "CANCELLED", "USER_CANCEL");
            self.active.insert(index, job);
            result?;
        } else {
            return Ok(Reply::error(
                ErrorCode::CleanupPending,
                "job ownership needs reconciliation",
            ));
        }
        let record = &self.records[id];
        Ok(Reply::Success(
            json!({"cancel_requested":record.cancel_reason.as_deref()==Some("USER_CANCEL"),"state":record.state}),
        ))
    }

    fn start(&mut self, id: &str) -> Result<()> {
        let record = self.records[id].clone();
        let Request::Submit(submission) =
            protocol::parse_request(record.canonical_request.as_bytes())?
        else {
            return Err(fail("unrecognized submit journal").into());
        };
        self.transition(id, |next| next.state = "STARTING".into())?;
        let scratch_path = self.cfg.state.join("scratch").join(id);
        let inputs = (|| {
            let profile = profiles::load(&self.cfg.state, &record.profile_id)?;
            let (tree, digest) = self
                .stages
                .open_tree(&record.stage_id)?
                .ok_or_else(|| fail("staged input disappeared"))?;
            if profile.digest != record.profile_digest || digest != record.stage_manifest_digest {
                return Err(fail("launch inputs no longer match durable admission"));
            }
            std::fs::create_dir(&scratch_path)?;
            Ok((profile, tree, private_dir(&scratch_path)?))
        })();
        let (profile, tree, scratch) = match inputs {
            Ok(inputs) => inputs,
            Err(error) => {
                eprintln!("launch refused before cgroup creation: {error}");
                self.transition(id, |next| next.state = "CLEANUP_PENDING".into())?;
                self.exporting(id, None)?;
                self.finish(
                    id,
                    "FAILED",
                    Some("STARTUP_FAILED"),
                    None,
                    (&[], &[]),
                    (false, false),
                )?;
                self.remove_scratch(id)?;
                return Ok(());
            }
        };
        // Journal the exact cgroup name before the first possible mutation.
        self.transition(id, |next| next.launch_stage = "CGROUP_CREATED".into())?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| fail("native host not admitted"))?;
        #[cfg(all(test, feature = "native-verification"))]
        self.checkpoint("durable-create-intent", id, None)?;
        let group = root.create(self.store.instance_id(), id)?;
        let mut job = Active {
            id: id.to_owned(),
            native: Native::new(group)?,
            deadline: None,
            wall: Duration::from_millis(submission.wall_ms),
            stop: None,
            publication: None,
        };
        #[cfg(all(test, feature = "native-verification"))]
        self.checkpoint("created-before-spawn", id, Some(&job.native))?;
        let started = job.native.spawn(LaunchInputs {
            binary: &self.cfg.launcher,
            executable: &profile.image,
            tree: &tree,
            scratch: &scratch,
            digest: &record.executable_digest,
            argv: &submission.argv,
            abi: self.abi,
            #[cfg(all(test, feature = "native-verification"))]
            job_id: id,
            #[cfg(all(test, feature = "native-verification"))]
            request_id: &record.request_id,
        });
        let stage = if let Err(error) = started {
            eprintln!("native startup failed: {error}");
            self.request_stop(&mut job, "FAILED", "STARTUP_FAILED")
        } else {
            self.transition(id, |next| next.launch_stage = "CGROUP_ATTACHED".into())
        };
        // Retain the job and slice on every failure after the group exists.
        self.active.push(job);
        stage
    }

    fn request_stop(
        &mut self,
        job: &mut Active,
        outcome: &'static str,
        reason: &'static str,
    ) -> Result<()> {
        if job.stop.is_some() {
            return Ok(());
        }
        job.stop = Some((outcome, reason));
        let stopped = job.native.stop();
        let state = &self.records[&job.id].state;
        if matches!(state.as_str(), "STARTING" | "RUNNING") {
            self.transition(&job.id, |next| {
                next.state = "CANCELLING".into();
                next.cancel_reason = Some(reason.into());
            })?;
        } else if matches!(state.as_str(), "CLEANUP_PENDING" | "EXPORTING") {
            self.transition(&job.id, |next| next.cancel_reason = Some(reason.into()))?;
        }
        stopped?;
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<()> {
        self.accepting = false;
        let mut first_error = None;
        for index in 0..self.active.len() {
            let mut job = self.active.remove(index);
            let result = self.request_stop(&mut job, "CANCELLED", "SHUTDOWN");
            self.active.insert(index, job);
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        while let Some((id, _)) = self.queue.front().cloned() {
            if first_error.is_some() {
                break;
            }
            match self.finish(
                &id,
                "CANCELLED",
                Some("SHUTDOWN"),
                None,
                (&[], &[]),
                (false, false),
            ) {
                Ok(()) => {
                    self.queue.pop_front();
                }
                Err(error) => {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Preserve durable records for restart. Kernel cleanup can continue even
    /// after the store has refused all further state changes.
    pub fn cleanup_failed(&mut self) -> Result<()> {
        self.accepting = false;
        self.queue.clear();
        let mut first_error = None;
        let mut index = 0;
        while index < self.active.len() {
            let mut job = self.active.remove(index);
            if let Some(pending) = &job.publication {
                if pending.worker.is_finished() {
                    let finished = job.publication.take().expect("publisher finished");
                    if let Err(error) = finished.join() {
                        first_error.get_or_insert(error);
                    }
                    continue;
                }
                self.active.insert(index, job);
                index += 1;
                continue;
            }
            if let Err(error) = job.native.stop() {
                first_error.get_or_insert_with(|| error.into());
            }
            if let Err(error) = job.native.check_deadline() {
                first_error.get_or_insert_with(|| error.into());
            }
            let result: Result<_> = (|| {
                job.native.observe()?;
                if !job.native.quiescent()? || !job.native.try_remove_empty_group()? {
                    return Ok(false);
                }
                self.remove_scratch(&job.id)?;
                Ok(true)
            })();
            match result {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
            self.active.insert(index, job);
            index += 1;
        }
        first_error.map_or(Ok(()), Err)
    }

    pub fn tick(&mut self) -> Result<()> {
        if self.next_prune <= Instant::now() {
            let pinned: HashSet<_> = self
                .records
                .values()
                .filter(|record| !terminal(&record.state))
                .map(|record| record.stage_id.clone())
                .collect();
            self.stages.prune(&pinned)?;
            self.next_prune = Instant::now() + Duration::from_secs(5);
        }
        let mut index = 0;
        while index < self.active.len() {
            let mut job = self.active.remove(index);
            match self.advance(&mut job) {
                Ok(true) => {}
                Ok(false) => {
                    self.active.insert(index, job);
                    index += 1;
                }
                Err(error) => {
                    let stopped = job.native.stop();
                    self.active.insert(index, job);
                    self.uncertain = true;
                    if let Err(stop_error) = stopped {
                        eprintln!("cleanup still pending: {stop_error}");
                    }
                    return Err(error);
                }
            }
        }
        while let Some((id, _)) = self
            .queue
            .front()
            .filter(|(_, time)| time.elapsed() >= QUEUE_TIMEOUT)
            .cloned()
        {
            self.finish(
                &id,
                "CANCELLED",
                Some("QUEUE_TIMEOUT"),
                None,
                (&[], &[]),
                (false, false),
            )?;
            self.queue.pop_front();
        }
        while self.accepting && self.storage_certain() && self.active.len() < MAX_RUNNING {
            let Some((id, _)) = self.queue.pop_front() else {
                break;
            };
            if let Err(error) = self.start(&id) {
                self.uncertain = true;
                return Err(error);
            }
        }
        Ok(())
    }

    fn advance(&mut self, job: &mut Active) -> Result<bool> {
        if let Some(pending) = &job.publication {
            if !pending.worker.is_finished() {
                return Ok(false);
            }
            let pending = job.publication.take().expect("publisher finished");
            let before = pending.stop;
            let published = pending.join()?;
            if let Some((state, reason)) = job.stop.filter(|stop| Some(*stop) != before) {
                // Cancel can win after quiescence but before the journal makes
                // the result visible. The unpublished directory has one owner.
                self.retention
                    .discard_uncommitted(&self.publisher, &self.records[&job.id])?;
                self.begin_publication(job, (state, Some(reason)), None)?;
                return Ok(false);
            }
            #[cfg(all(test, feature = "native-verification"))]
            self.checkpoint("bundle-before-receipt", &job.id, Some(&job.native))?;
            self.record_result(published)?;
            return Ok(true);
        }
        let timed_out = job.native.check_deadline()?;
        job.native.observe()?;
        #[cfg(all(test, feature = "native-verification"))]
        if self.records[&job.id].state == "RUNNING"
            && job.native.stdout.bytes == b"detached-ready\n"
        {
            self.checkpoint("running-hold-ready", &job.id, Some(&job.native))?;
        }
        if job.stop.is_none() {
            if timed_out
                || (job
                    .deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                    && !job.native.launcher_reaped())
            {
                self.request_stop(job, "TIMED_OUT", "WALL_LIMIT")?;
            } else if let Err(error) = job.native.poll_control() {
                eprintln!("launch control refused: {error}");
                self.request_stop(job, "FAILED", "POLICY_FAILED")?;
            } else if job.native.stdout.truncated() || job.native.stderr.truncated() {
                self.request_stop(job, "FAILED", "STREAM_LIMIT")?;
            } else if job.native.setup_expired() {
                self.request_stop(job, "FAILED", "STARTUP_TIMEOUT")?;
            } else if job.native.ready() && job.deadline.is_none() && !job.native.launcher_reaped()
            {
                if !self.storage_certain() {
                    return Err(
                        fail("execution gate closed while durable storage is uncertain").into(),
                    );
                }
                #[cfg(all(test, feature = "native-verification"))]
                self.checkpoint("policy-ready-before-intent", &job.id, Some(&job.native))?;
                self.transition(&job.id, |next| next.launch_stage = "EXEC_RELEASED".into())?;
                #[cfg(all(test, feature = "native-verification"))]
                self.checkpoint("durable-exec-intent", &job.id, Some(&job.native))?;
                if !self.storage_certain() {
                    return Err(fail(
                        "execution intent committed while durable storage became uncertain",
                    )
                    .into());
                }
                job.deadline = Some(job.native.release(job.wall)?);
                #[cfg(all(test, feature = "native-verification"))]
                self.checkpoint("exec-sent-before-running", &job.id, Some(&job.native))?;
                let started = self.elapsed_origin.elapsed().as_nanos() as u64;
                self.transition(&job.id, |next| {
                    next.state = "RUNNING".into();
                    next.started_monotonic_ns = Some(started);
                })?;
            }
        }
        if job.native.launcher_reaped() || job.stop.is_some() {
            if !matches!(
                self.records[&job.id].state.as_str(),
                "CLEANUP_PENDING" | "EXPORTING"
            ) {
                self.transition(&job.id, |next| next.state = "CLEANUP_PENDING".into())?;
            }
            if !job.native.quiescent()? {
                job.native.stop()?;
                return Ok(false);
            }
            return self.finalize_active(job);
        }
        Ok(false)
    }

    fn finalize_active(&mut self, job: &mut Active) -> Result<bool> {
        let guest = job.native.guest_status();
        let exit = guest.map(|status| ObservedExit {
            exit_code: status.code(),
            signal: status.signal(),
        });
        let counters = job.native.group.counters()?;
        let limited = counters.memory_events.get("oom_kill").copied().unwrap_or(0) > 0
            || counters.pids_events.get("max").copied().unwrap_or(0) > 0;
        let (state, reason) = if let Some((state, reason)) = job.stop {
            (state, Some(reason))
        } else if limited {
            ("FAILED", Some("RESOURCE_LIMIT"))
        } else if guest.is_some_and(|status| status.success()) {
            ("SUCCEEDED", None)
        } else {
            ("FAILED", Some("EXECUTION_FAILED"))
        };
        // Keep the owned output descriptor and active slot over a transient
        // removal refusal. The kernel must remove the exact leaf first.
        if !job.native.try_remove_empty_group()? {
            return Ok(false);
        }
        let output = job.native.take_quiescent_output()?;
        let output =
            if state == "SUCCEEDED" {
                Some(output.ok_or_else(|| {
                    fail("successful execution has no retained output descriptor")
                })?)
            } else {
                drop(output);
                None
            };
        self.remove_scratch(&job.id)?;
        self.exporting(&job.id, exit)?;
        #[cfg(all(test, feature = "native-verification"))]
        self.checkpoint("quiescent-export", &job.id, Some(&job.native))?;
        self.begin_publication(job, (state, reason), output)?;
        Ok(false)
    }

    fn begin_publication(
        &self,
        job: &mut Active,
        outcome: Outcome,
        output: Option<OwnedFd>,
    ) -> Result<()> {
        let id = job.id.clone();
        let publisher = Arc::clone(&self.publisher);
        let meta = self.result_metadata(
            &id,
            outcome.0,
            (job.native.stdout.truncated(), job.native.stderr.truncated()),
        );
        let stdout = job.native.stdout.bytes.clone();
        let stderr = job.native.stderr.bytes.clone();
        let lease = self.store.retain_lock()?;
        // One worker per active slot, retained through durable publication.
        let worker = thread::Builder::new()
            .name("hearthrun-publication".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let _lease = lease;
                publish(&publisher, &id, outcome, meta, output, (&stdout, &stderr))
            })?;
        job.publication = Some(PendingPublication {
            stop: job.stop,
            worker,
        });
        Ok(())
    }

    fn recover(&mut self) -> Result<()> {
        let live: Vec<_> = self
            .records
            .values()
            .filter(|record| !terminal(&record.state))
            .cloned()
            .collect();
        if let Some(root) = &self.root {
            let expected: BTreeMap<_, _> = live
                .iter()
                .filter(|record| record.launch_stage != "INTENT")
                .map(|record| {
                    (
                        format!("hr-{}-{}", self.store.instance_id(), record.job_id),
                        record.job_id.clone(),
                    )
                })
                .collect();
            let names = root.list_job_names()?;
            if names.iter().any(|name| !expected.contains_key(name)) {
                return Err(fail("unrecognized cgroup under dedicated jobs parent").into());
            }
            let mut groups = Vec::new();
            let mut first_error: Option<Box<dyn std::error::Error + Send + Sync>> = None;
            for name in names {
                let id = &expected[&name];
                match root.recover_owned(self.store.instance_id(), id) {
                    Ok(owned) => groups.push((id.clone(), owned)),
                    Err(error) => {
                        first_error.get_or_insert(error.into());
                    }
                }
            }
            for (_, group) in &groups {
                if let Err(error) = group.kill() {
                    first_error.get_or_insert(error.into());
                }
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            for (id, mut owned) in groups {
                let result: Result<()> = (|| loop {
                    if owned.try_remove_empty()? {
                        return Ok(());
                    }
                    if Instant::now() >= deadline {
                        if self.records[&id].state != "EXPORTING" {
                            self.transition(&id, |next| next.state = "CLEANUP_PENDING".into())?;
                        }
                        return Err(fail(
                            "CLEANUP_PENDING: owned recovery cgroup remains populated",
                        )
                        .into());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                })();
                if let Err(error) = result {
                    first_error.get_or_insert(error);
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
        } else if live.iter().any(|record| record.launch_stage != "INTENT") {
            return Err(
                fail("CLEANUP_PENDING: dedicated cgroup root unavailable during recovery").into(),
            );
        }
        self.retention.reconcile(&self.publisher, &self.records)?;
        self.retention
            .make_room(&self.publisher, &self.records, live.len())?;
        for record in live {
            let id = record.job_id;
            if matches!(record.state.as_str(), "STARTING" | "RUNNING" | "CANCELLING") {
                self.transition(&id, |next| next.state = "CLEANUP_PENDING".into())?;
            }
            if self.records[&id].state == "CLEANUP_PENDING" {
                self.exporting(&id, None)?;
            }
            self.finish(
                &id,
                "INTERRUPTED",
                Some("SUPERVISOR_RESTART"),
                None,
                (&[], &[]),
                (false, false),
            )?;
            self.remove_scratch(&id)?;
        }
        Ok(())
    }

    #[cfg(all(test, feature = "native-verification"))]
    fn checkpoint(&self, point: &str, id: &str, native: Option<&Native>) -> Result<()> {
        let record = &self.records[id];
        crate::crash_checkpoint::hit(
            point,
            id,
            &record.request_id,
            json!({"journal_state":record.state,"launch_stage":record.launch_stage,
                "cleanup_confirmed":record.cleanup_confirmed,
                "native":native.map(Native::crash_witness).transpose()?}),
        )?;
        Ok(())
    }

    fn transition(&mut self, id: &str, update: impl FnOnce(&mut JobRecord)) -> Result<()> {
        let mut next = self
            .records
            .get(id)
            .ok_or_else(|| fail("unknown job transition"))?
            .clone();
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or_else(|| fail("job sequence exhausted"))?;
        update(&mut next);
        self.store.write(&next)?;
        self.emit(&next);
        self.records.insert(id.to_owned(), next);
        Ok(())
    }

    fn emit(&mut self, record: &JobRecord) {
        let events = self.events.entry(record.job_id.clone()).or_default();
        if events.len() == EVENT_LIMIT {
            events.pop_front();
        }
        events.push_back(
            json!({"v":1,"job_id":record.job_id,"sequence":record.sequence,
            "event":record.state,"monotonic_ns":self.elapsed_origin.elapsed().as_nanos() as u64,
            "reason_code":record.cancel_reason}),
        );
    }

    fn exporting(&mut self, id: &str, exit: Option<ObservedExit>) -> Result<()> {
        self.transition(id, |next| {
            next.state = "EXPORTING".into();
            next.cleanup_confirmed = true;
            next.launch_stage = "CLEANED".into();
            if exit.is_some() {
                next.observed_exit = exit;
            }
        })
    }

    fn finish(
        &mut self,
        id: &str,
        state: &'static str,
        reason: Option<&'static str>,
        output: Option<OwnedFd>,
        streams: (&[u8], &[u8]),
        truncated: (bool, bool),
    ) -> Result<()> {
        let meta = self.result_metadata(id, state, truncated);
        let published = publish(&self.publisher, id, (state, reason), meta, output, streams)?;
        self.record_result(published)
    }

    fn result_metadata(&self, id: &str, state: &str, truncated: (bool, bool)) -> Value {
        let record = &self.records[id];
        json!({"v":1,"job_id":id,"status":persistent_outcome(state),
            "cleanup_confirmed":true,"policy_sha256":record.policy_digest,"environment_id":self.environment,
            "exit_code":record.observed_exit.and_then(|exit|exit.exit_code),
            "signal":record.observed_exit.and_then(|exit|exit.signal),
            "stdout_truncated":truncated.0,"stderr_truncated":truncated.1,"artifacts":[]})
    }

    fn record_result(&mut self, published: Published) -> Result<()> {
        let Published {
            outcome: (state, reason),
            result,
        } = published;
        self.transition(&result.job_id, |next| {
            next.state = state.to_owned();
            next.cleanup_confirmed = true;
            if next.cancel_reason.is_none() {
                next.cancel_reason = reason.map(str::to_owned);
            }
            next.result_digest = Some(result.result_digest.clone());
        })?;
        self.retention.remember(&result)?;
        Ok(())
    }

    fn remove_scratch(&self, id: &str) -> Result<()> {
        JobId::parse(id).map_err(|_| fail("invalid scratch job ID"))?;
        let dir = self.cfg.state.join("scratch").join(id);
        match private_dir(&dir) {
            Ok(_) => std::fs::remove_dir(&dir)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

impl PendingPublication {
    fn join(self) -> Result<Published> {
        self.worker
            .join()
            .map_err(|_| fail("publication worker panicked"))?
    }
}

fn publish(
    publisher: &Publisher,
    id: &str,
    outcome: Outcome,
    mut meta: Value,
    output: Option<OwnedFd>,
    streams: (&[u8], &[u8]),
) -> Result<Published> {
    let mut final_outcome = outcome;
    let result = match publisher.commit(id, meta.clone(), output, streams.0, streams.1) {
        Err(artifacts::Error::Preparation(error))
            if error.kind == artifacts::PreparationKind::InvalidArtifacts =>
        {
            final_outcome = ("FAILED", Some("ARTIFACT_REJECTED"));
            meta["status"] = json!("FAILED");
            publisher.commit(id, meta, None, streams.0, streams.1)?
        }
        result => result?,
    };
    Ok(Published {
        outcome: final_outcome,
        result,
    })
}

fn admitted(record: &JobRecord) -> Value {
    json!({"job_id":record.job_id,"state":record.state,"sequence":record.sequence})
}

fn inspect(record: &JobRecord) -> Value {
    json!({"job_id":record.job_id,"state":record.state,"sequence":record.sequence,
        "outcome":terminal(&record.state).then_some(&record.state),"reason":record.cancel_reason,
        "cleanup_confirmed":record.cleanup_confirmed,"result_digest":record.result_digest,
        "policy_digest":record.policy_digest,"executable_digest":record.executable_digest,
        "started_monotonic_ns":record.started_monotonic_ns,"observed_exit":record.observed_exit})
}

fn utc(seconds: u64) -> io::Result<String> {
    let mut days = seconds / 86_400;
    let mut year = 1970;
    let leap = |n| n % 4 == 0 && (n % 100 != 0 || n % 400 == 0);
    while year <= 9999 {
        let year_days = if leap(year) { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        year += 1;
    }
    if year > 9999 {
        return Err(fail("UTC year out of range"));
    }
    let mut month = 1;
    for length in [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ] {
        if days < length {
            break;
        }
        days -= length;
        month += 1;
    }
    let (hour, minute, second) = (seconds / 3600 % 24, seconds / 60 % 60, seconds % 60);
    Ok(format!(
        "{year:04}-{month:02}-{:02}T{hour:02}:{minute:02}:{second:02}Z",
        days + 1
    ))
}

fn probe(cfg: &Config, scratch: &Path) -> Result<Value> {
    let mut cmd = Command::new(&cfg.doctor);
    cmd.env_clear().env("TMPDIR", scratch);
    if let Some(path) = &cfg.root {
        cmd.arg("--cgroup-root").arg(path);
    }
    let result = cmd.output()?;
    let mut report = protocol::strict_json(&result.stdout)?;
    if report["schema_version"] != 2 || !report["compatible"].is_boolean() {
        return Err(fail("unexpected doctor response").into());
    }
    if !result.status.success() {
        report["compatible"] = json!(false);
    }
    Ok(report)
}

#[cfg(all(test, feature = "native-verification"))]
#[path = "../../../tests/acceptance_locked/terminal.rs"]
mod terminal;

#[cfg(all(test, feature = "native-verification"))]
#[path = "../../../tests/acceptance_locked/recovery_child.rs"]
mod recovery_child;

#[cfg(all(test, feature = "native-verification"))]
#[path = "../../../tests/acceptance_locked/streams.rs"]
mod streams;
