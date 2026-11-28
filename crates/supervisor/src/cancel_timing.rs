//! Explicit test-only observer. Not compiled into feature-disabled artifacts.
//! No scheduler authority; sends are nonblocking and any loss invalidates evidence.
use hearthrun_domain::protocol::Request;
use hearthrun_launcher::cgroup::{JobGroup, KillToken};
use rustix::time::{clock_gettime, ClockId};
use serde::Serialize;
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_EVENTS: u64 = 128;
const MAX_BYTES: usize = 256 * 1024;
static STATE: OnceLock<Arc<State>> = OnceLock::new();

struct State {
    sender: mpsc::SyncSender<Event>,
    received: AtomicU64,
    lost: AtomicU64,
    stopping: AtomicBool,
    complete: AtomicBool,
}

/// Owned transport observation: never serialized into the public wire reply.
/// No Clone: one received frame has at most one owner write observation.
pub struct Receipt {
    pub(crate) job_id: String,
    ordinal: u64,
    receipt_ns: u64,
}

#[derive(Serialize)]
struct Event {
    kind: &'static str,
    job_id: String,
    ordinal: Option<u64>,
    receipt_ns: Option<u64>,
    begin_ns: Option<u64>,
    end_ns: Option<u64>,
    ok: bool,
}

fn clock() -> u64 {
    let time = clock_gettime(ClockId::Monotonic);
    // Linux monotonic time is nonnegative; overflow cannot silently wrap.
    u64::try_from(time.tv_sec)
        .expect("negative CLOCK_MONOTONIC")
        .checked_mul(1_000_000_000)
        .and_then(|secs| secs.checked_add(time.tv_nsec as u64))
        .expect("CLOCK_MONOTONIC outside evidence range")
}

/// Called only after authenticated strict parsing and the EOF receive returned.
pub(crate) fn received(request: &Request) -> Option<Receipt> {
    let Request::Cancel(job_id) = request else {
        return None;
    };
    let receipt_ns = clock();
    let state = STATE.get()?;
    let ordinal = state.received.fetch_add(1, Ordering::Relaxed) + 1;
    if ordinal > MAX_EVENTS {
        state.lost.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    Some(Receipt {
        job_id: job_id.clone(),
        ordinal,
        receipt_ns,
    })
}

fn emit(event: Event) {
    if let Some(state) = STATE.get() {
        if state.sender.try_send(event).is_err() {
            state.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub(crate) fn no_write(receipt: Receipt) {
    emit(owner_event(receipt, "owner_no_write", None, None, false));
}

fn owner_event(
    receipt: Receipt,
    kind: &'static str,
    begin_ns: Option<u64>,
    end_ns: Option<u64>,
    ok: bool,
) -> Event {
    Event {
        kind,
        job_id: receipt.job_id,
        ordinal: Some(receipt.ordinal),
        receipt_ns: Some(receipt.receipt_ns),
        begin_ns,
        end_ns,
        ok,
    }
}

pub(crate) fn owner_kill(group: &JobGroup, receipt: Receipt) -> io::Result<()> {
    // All ordinary owned-descriptor validation/opening precedes the bracket.
    let token = match group.kill_token() {
        Ok(token) => token,
        Err(error) => {
            emit(owner_event(receipt, "owner_no_write", None, None, false));
            return Err(error);
        }
    };
    let (result, begin, end) = token.fire_observed(clock);
    emit(owner_event(
        receipt,
        "owner_write",
        Some(begin),
        Some(end),
        result.is_ok(),
    ));
    result
}

pub(crate) fn deadline_kill(token: KillToken, job_id: &str) -> io::Result<()> {
    // Never attach an owner receipt to this independently executing worker.
    let (result, begin, end) = token.fire_observed(clock);
    emit(Event {
        kind: "deadline_write",
        job_id: job_id.to_owned(),
        ordinal: None,
        receipt_ns: None,
        begin_ns: Some(begin),
        end_ns: Some(end),
        ok: result.is_ok(),
    });
    result
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn bounded_text(path: &str) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?.take(129).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(invalid("clock identity exceeds bound"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("clock identity is not UTF-8"))
}

fn write_row(file: &mut File, bytes: &mut usize, value: &impl Serialize) -> io::Result<()> {
    let mut encoded = serde_json::to_vec(value)?;
    encoded.push(b'\n');
    if encoded.len() > 2048 || *bytes + encoded.len() > MAX_BYTES {
        return Err(invalid("test trace storage bound exceeded"));
    }
    file.write_all(&encoded)?;
    *bytes += encoded.len();
    Ok(())
}

/// Created before Server::bind, closed after ordinary socket/worker/job teardown.
pub struct Trace {
    state: Arc<State>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl Trace {
    pub fn start() -> io::Result<Self> {
        let run_id = std::env::var("HEARTHRUN_CANCEL_RUN_ID")
            .map_err(|_| invalid("set test run identity"))?;
        let shard = std::env::var("HEARTHRUN_CANCEL_SHARD")
            .map_err(|_| invalid("set test shard identity"))?;
        if run_id.len() != 32
            || !run_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || shard.len() != 10
            || !shard.starts_with("shard-")
            || !shard[6..].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid("invalid test trace identity"));
        }
        let path = PathBuf::from(
            std::env::var_os("HEARTHRUN_CANCEL_TRACE")
                .ok_or_else(|| invalid("set test trace path"))?,
        );
        let parent = path
            .parent()
            .ok_or_else(|| invalid("missing trace parent"))?;
        if !path.is_absolute()
            || path
                .file_name()
                .is_none_or(|name| name != "cancel-timing.jsonl")
            || parent.canonicalize()? != parent
        {
            return Err(invalid("trace path must be a new exact private leaf"));
        }
        let metadata = fs::metadata(parent)?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid("trace parent must be owner-only"));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
            return Err(invalid("trace leaf must be owner0600"));
        }
        let boot_id = bounded_text("/proc/sys/kernel/random/boot_id")?;
        let time_namespace = fs::read_link("/proc/self/ns/time")?
            .to_string_lossy()
            .into_owned();
        if time_namespace.is_empty() || time_namespace.len() > 128 {
            return Err(invalid("invalid time namespace identity"));
        }
        let mut bytes = 0;
        write_row(
            &mut file,
            &mut bytes,
            &json!({"kind":"header", "version":1,
            "run_id":run_id, "shard":shard, "pid":std::process::id(), "clock":"CLOCK_MONOTONIC",
            "boot_id":boot_id, "time_namespace":time_namespace}),
        )?;
        let (sender, receiver) = mpsc::sync_channel(MAX_EVENTS as usize);
        let state = Arc::new(State {
            sender,
            received: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
            complete: AtomicBool::new(false),
        });
        STATE
            .set(Arc::clone(&state))
            .map_err(|_| invalid("only one trace session per process"))?;
        let shared = Arc::clone(&state);
        let worker = thread::Builder::new().name("hearthrun-test-trace".into()).stack_size(128 * 1024).spawn(move || {
            let mut events = 0_u64;
            loop {
                match receiver.recv_timeout(Duration::from_millis(20)) {
                    Ok(event) => {
                        if events == MAX_EVENTS {
                            shared.lost.fetch_add(1, Ordering::Relaxed);
                        } else {
                            write_row(&mut file, &mut bytes, &event)?;
                            events += 1;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) if !shared.stopping.load(Ordering::Acquire) => continue,
                    Err(_) => break,
                }
            }
            write_row(&mut file, &mut bytes, &json!({"kind":"footer",
                "complete":shared.complete.load(Ordering::Acquire), "events":events,
                "received":shared.received.load(Ordering::Relaxed), "lost":shared.lost.load(Ordering::Relaxed)}))?;
            file.sync_all()
        })?;
        Ok(Self {
            state,
            worker: Some(worker),
        })
    }

    pub fn finish(mut self, complete: bool) -> io::Result<()> {
        self.state.complete.store(complete, Ordering::Release);
        self.state.stopping.store(true, Ordering::Release);
        self.worker
            .take()
            .expect("one trace collector")
            .join()
            .map_err(|_| io::Error::other("test trace collector panicked"))??;
        if self.state.lost.load(Ordering::Relaxed) != 0 {
            return Err(io::Error::other("test trace lost observations"));
        }
        Ok(())
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        // Early returns cannot produce a complete=true trace. No blocking work
        // or implicit runtime cleanup in Drop; the outer harness owns teardown.
        self.state.stopping.store(true, Ordering::Release);
    }
}
