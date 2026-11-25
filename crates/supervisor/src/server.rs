//! Bounded Linux local IPC; this module grants no execution or host-path authority.
//!
//! The caller holds the exclusive state lock for the entire Server lifetime,
//! including bind/close. Dropping Server closes admission but deliberately leaves
//! its socket name for the next locked recovery. Shutdown must separately stop
//! admission, drain bounded workers, and reconcile jobs; a closed peer never
//! means cancellation. Clients must half-close their write side after the one
//! request, so EOF (and therefore absence of surplus bytes) can be proved.
//!
//! A worker can stream a StagePayload into independently bounded staging storage.
//! It must verify each digest and roll back incomplete storage. Only finish()
//! produces a ValidatedRequest suitable for a bounded scheduler-owner channel.
//! No scheduler callback is invoked here and no per-connection thread is spawned.

#![cfg(target_os = "linux")]

#[cfg(all(test, feature = "native-verification"))]
#[path = "../../../tests/acceptance_locked/protocol.rs"]
mod protocol_acceptance;

use hearthrun_domain::protocol::{self, Request};
use hearthrun_domain::MAX_HEADER_BYTES;
use rustix::fd::{AsRawFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::net::{self, sockopt, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use serde_json::Value;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAX_CONNECTIONS: usize = 32;
pub const MAX_STAGE_UPLOADS: usize = 8;
const SOCKET_NAME: &str = "control.sock";
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn of(stat: &fs::Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

/// All wire error codes are drawn from the v1 API contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    BadFrame,
    BadJson,
    UnsupportedVersion,
    UnknownField,
    DuplicateKey,
    Unauthorized,
    InvalidPath,
    InvalidLimit,
    ProfileNotFound,
    ProfileDigestMismatch,
    UnsupportedExecutable,
    StageNotFound,
    StageDigestMismatch,
    QueueFull,
    StorageFull,
    Conflict,
    NotFound,
    NotReady,
    UnsupportedHost,
    StartupFailed,
    PolicyFailed,
    CleanupPending,
    CorruptState,
    IoUncertain,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadFrame => "BAD_FRAME",
            Self::BadJson => "BAD_JSON",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::DuplicateKey => "DUPLICATE_KEY",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidPath => "INVALID_PATH",
            Self::InvalidLimit => "INVALID_LIMIT",
            Self::ProfileNotFound => "PROFILE_NOT_FOUND",
            Self::ProfileDigestMismatch => "PROFILE_DIGEST_MISMATCH",
            Self::UnsupportedExecutable => "UNSUPPORTED_EXECUTABLE",
            Self::StageNotFound => "STAGE_NOT_FOUND",
            Self::StageDigestMismatch => "STAGE_DIGEST_MISMATCH",
            Self::QueueFull => "QUEUE_FULL",
            Self::StorageFull => "STORAGE_FULL",
            Self::Conflict => "CONFLICT",
            Self::NotFound => "NOT_FOUND",
            Self::NotReady => "NOT_READY",
            Self::UnsupportedHost => "UNSUPPORTED_HOST",
            Self::StartupFailed => "STARTUP_FAILED",
            Self::PolicyFailed => "POLICY_FAILED",
            Self::CleanupPending => "CLEANUP_PENDING",
            Self::CorruptState => "CORRUPT_STATE",
            Self::IoUncertain => "IO_UNCERTAIN",
            Self::Internal => "INTERNAL",
        }
    }
}

impl From<protocol::Code> for ErrorCode {
    fn from(code: protocol::Code) -> Self {
        match code {
            protocol::Code::BadFrame => Self::BadFrame,
            protocol::Code::BadJson => Self::BadJson,
            protocol::Code::UnsupportedVersion => Self::UnsupportedVersion,
            protocol::Code::UnknownField => Self::UnknownField,
            protocol::Code::DuplicateKey => Self::DuplicateKey,
            protocol::Code::InvalidPath => Self::InvalidPath,
            protocol::Code::InvalidLimit => Self::InvalidLimit,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ErrorReply {
    pub code: ErrorCode,
    message: &'static str,
}

impl ErrorReply {
    /// Static diagnostics cannot accidentally echo a request's secret contents.
    pub fn new(code: ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message: if message.len() <= 1024 {
                message
            } else {
                "error diagnostic exceeds limit"
            },
        }
    }

    pub fn message(self) -> &'static str {
        self.message
    }
}

pub enum Reply {
    Success(Value),
    Error(ErrorReply),
}

impl Reply {
    pub fn error(code: ErrorCode, message: &'static str) -> Self {
        Self::Error(ErrorReply::new(code, message))
    }
}

/// A retained directory descriptor anchors every socket-name operation. Linux
/// /proc/self/fd is required for pathname-based AF_UNIX bind; failure refuses bind.
pub struct Server {
    listener: UnixListener,
    directory: OwnedFd,
    socket_identity: Identity,
    expected_uid: u32,
    connections: Arc<AtomicUsize>,
    uploads: Arc<AtomicUsize>,
}

impl Server {
    /// The directory must already exist, be owned by expected_uid, and have exact
    /// mode 0700. The effective UID must match. The exclusive state lock is a
    /// caller-held precondition, not something proved by the pathname. Under
    /// that lock an existing owner0600 socket is stale; any other entry refuses.
    /// Isolation from a malicious same-UID host process is outside the v1 model.
    pub fn bind(private_state_dir: &Path, expected_uid: u32) -> io::Result<Self> {
        if rustix::process::geteuid().as_raw() != expected_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "configured UID differs from effective UID",
            ));
        }
        let directory = open_private_directory(private_state_dir, expected_uid)?;
        match socket_stat(&directory, expected_uid) {
            Ok(stale) => remove_same_socket(&directory, expected_uid, Identity::of(&stale))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let fd = net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        let anchor = format!("/proc/self/fd/{}/{}", directory.as_raw_fd(), SOCKET_NAME);
        let address = SocketAddrUnix::new(anchor.as_str())?;
        net::bind(&fd, &address)?;
        // The enclosing directory is 0700 before bind; no other UID can reach
        // the brief pre-chmod name. There is no process-global umask mutation.
        let created = fs::statat(&directory, SOCKET_NAME, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(created.st_mode) != FileType::Socket
            || created.st_uid != expected_uid
            || created.st_nlink != 1
        {
            return Err(invalid("new socket name failed ownership/type validation"));
        }
        // rustix's chmodat does not support SYMLINK_NOFOLLOW on Linux. The
        // retained owner0700 directory excludes other UIDs, and same-UID host
        // mutation is outside the contract. Check type/identity on both sides
        // of this operation rather than silently treating chmod failure as safe.
        fs::chmodat(
            &directory,
            SOCKET_NAME,
            Mode::RUSR | Mode::WUSR,
            AtFlags::empty(),
        )?;
        let secured = socket_stat(&directory, expected_uid)?;
        let socket_identity = Identity::of(&created);
        if Identity::of(&secured) != socket_identity {
            return Err(invalid("socket name identity changed during bind"));
        }
        net::listen(&fd, MAX_CONNECTIONS as i32)?;
        Ok(Self {
            listener: UnixListener::from(fd),
            directory,
            socket_identity,
            expected_uid,
            connections: Arc::new(AtomicUsize::new(0)),
            uploads: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Nonblocking admission. None means no socket is ready or all 32 admitted
    /// connections are held. The kernel listen backlog is independently bounded.
    /// Unauthorized peers are dropped before any header byte is read.
    pub fn poll_accept(&mut self) -> io::Result<Option<Connection>> {
        let Some(permit) = Permit::acquire(&self.connections, MAX_CONNECTIONS) else {
            return Ok(None);
        };
        let (stream, _) = match self.listener.accept() {
            Ok(pair) => pair,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let accepted = Instant::now();
        let peer = sockopt::socket_peercred(&stream)?;
        if peer.uid.as_raw() != self.expected_uid {
            reject_unauthorized(&stream);
            return Ok(None);
        }
        stream.set_nonblocking(false)?;
        Ok(Some(Connection {
            stream,
            _permit: permit,
            uploads: Arc::clone(&self.uploads),
            header_deadline: accepted + HEADER_TIMEOUT,
        }))
    }

    pub fn active_connections(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }

    /// Explicit endpoint teardown while the caller still holds the state lock.
    /// This does not claim that admitted clients or any jobs have been cleaned.
    /// A changed/replaced pathname is never unlinked. Drop alone leaves recovery
    /// work visible rather than silently swallowing an unlink error.
    pub fn close(self) -> io::Result<()> {
        drop(self.listener);
        remove_same_socket(&self.directory, self.expected_uid, self.socket_identity)
    }
}

struct Permit(Arc<AtomicUsize>);

impl Permit {
    fn acquire(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        let mut value = counter.load(Ordering::Acquire);
        while value < limit {
            match counter.compare_exchange_weak(
                value,
                value + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self(Arc::clone(counter))),
                Err(actual) => value = actual,
            }
        }
        None
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One authenticated peer, counted until its final response/drop. Moving it to a
/// bounded I/O worker is allowed; retain one scheduler owner for state mutation.
pub struct Connection {
    stream: UnixStream,
    _permit: Permit,
    uploads: Arc<AtomicUsize>,
    header_deadline: Instant,
}

impl Connection {
    /// Prefix and all partial header reads share the acceptance-time deadline.
    pub fn receive(mut self) -> Result<Incoming, ReceiveFailure> {
        let mut prefix = [0_u8; 4];
        if let Err(error) = read_exact_until(&mut self.stream, &mut prefix, self.header_deadline) {
            return Err(self.failure(
                ErrorCode::BadFrame,
                "incomplete or expired frame length",
                Some(error),
            ));
        }
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > MAX_HEADER_BYTES {
            return Err(self.failure(
                ErrorCode::BadFrame,
                "JSON header length is outside bounds",
                None,
            ));
        }
        let mut header = vec![0_u8; length];
        if let Err(error) = read_exact_until(&mut self.stream, &mut header, self.header_deadline) {
            return Err(self.failure(
                ErrorCode::BadFrame,
                "incomplete or expired JSON header",
                Some(error),
            ));
        }
        let request = match protocol::parse_request(&header) {
            Ok(request) => request,
            Err(error) => return Err(self.failure(error.code.into(), error.message, None)),
        };
        if let Err(error) = remaining(self.header_deadline) {
            return Err(self.failure(
                ErrorCode::BadFrame,
                "total header deadline expired",
                Some(error),
            ));
        }
        let (remaining, upload, deadline) = match &request {
            Request::Stage(files) => {
                let Some(total) = files
                    .iter()
                    .try_fold(0_u64, |sum, file| sum.checked_add(file.size))
                    .filter(|sum| *sum <= protocol::MAX_INPUT_BYTES)
                else {
                    return Err(self.failure(
                        ErrorCode::InvalidLimit,
                        "staging payload exceeds limit",
                        None,
                    ));
                };
                let Some(permit) = Permit::acquire(&self.uploads, MAX_STAGE_UPLOADS) else {
                    return Err(self.failure(
                        ErrorCode::QueueFull,
                        "staging upload capacity is full",
                        None,
                    ));
                };
                (total, Some(permit), Instant::now() + PAYLOAD_TIMEOUT)
            }
            _ => (0, None, self.header_deadline),
        };
        Ok(Incoming {
            request,
            payload: StagePayload {
                connection: self,
                remaining,
                deadline,
                failed: false,
                _upload: upload,
            },
        })
    }

    fn failure(
        self,
        code: ErrorCode,
        message: &'static str,
        source: Option<io::Error>,
    ) -> ReceiveFailure {
        ReceiveFailure {
            error: ErrorReply::new(code, message),
            source,
            connection: self,
        }
    }

    fn respond(mut self, reply: Reply) -> io::Result<()> {
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        let envelope = match reply {
            Reply::Success(result) => {
                // Move the handler's Value rather than cloning it through the
                // JSON macro before the capped serializer can reject its size.
                let mut fields = serde_json::Map::new();
                fields.insert("v".into(), Value::from(1));
                fields.insert("ok".into(), Value::Bool(true));
                fields.insert("result".into(), result);
                Value::Object(fields)
            }
            Reply::Error(error) => serde_json::json!({"v": 1, "ok": false, "error": {
                "code": error.code.as_str(), "message": error.message,
                "retryable": error.code == ErrorCode::QueueFull,
            }}),
        };
        // Serialize through a capped writer: no unbounded intermediate response
        // Vec, and an oversized result is rejected before any prefix is sent.
        let mut encoded = CappedBuffer(Vec::new());
        serde_json::to_writer(&mut encoded, &envelope).map_err(io::Error::other)?;
        write_all_until(
            &mut self.stream,
            &(encoded.0.len() as u32).to_be_bytes(),
            deadline,
        )?;
        write_all_until(&mut self.stream, &encoded.0, deadline)
    }
}

/// An upload reader has no filesystem/path authority. It exposes at most the
/// manifest sum and uses the same total 10s deadline across all files and reads.
/// Global durable storage/age reservations and SHA-256 verification belong to
/// the staging store; an upload permit is not a durable-storage reservation.
pub struct StagePayload {
    connection: Connection,
    remaining: u64,
    deadline: Instant,
    failed: bool,
    _upload: Option<Permit>,
}

impl StagePayload {
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}

impl Read for StagePayload {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(invalid("staging payload reader is already failed"));
        }
        if self.remaining == 0 {
            return Ok(0);
        }
        let length = buffer.len().min(self.remaining as usize);
        match read_until(
            &mut self.connection.stream,
            &mut buffer[..length],
            self.deadline,
        ) {
            Ok(0) => {
                self.failed = true;
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "staging payload ended before declared size",
                ))
            }
            Ok(count) => {
                self.remaining -= count as u64;
                Ok(count)
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
}

pub struct Incoming {
    request: Request,
    payload: StagePayload,
}

impl Incoming {
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn payload(&mut self) -> &mut StagePayload {
        &mut self.payload
    }

    /// Call only after the staging store consumed and verified each declared
    /// file. This checks exact byte count plus EOF, not its SHA-256 or durability.
    /// Normal requests also require EOF; a second frame is always surplus.
    pub fn finish(mut self) -> Result<ValidatedRequest, ReceiveFailure> {
        if self.payload.failed || self.payload.remaining != 0 {
            return Err(self.payload.connection.failure(
                ErrorCode::BadFrame,
                "staging payload was incomplete or failed",
                None,
            ));
        }
        let mut extra = [0_u8; 1];
        match read_until(
            &mut self.payload.connection.stream,
            &mut extra,
            self.payload.deadline,
        ) {
            Ok(0) => Ok(ValidatedRequest {
                request: self.request,
                connection: self.payload.connection,
            }),
            Ok(_) => Err(self.payload.connection.failure(
                ErrorCode::BadFrame,
                "surplus bytes after request",
                None,
            )),
            Err(error) => Err(self.payload.connection.failure(
                ErrorCode::BadFrame,
                "missing EOF or expired request deadline",
                Some(error),
            )),
        }
    }

    /// Rejecting an upload does not drain it or mutate scheduler state. The
    /// caller must separately clean any partially staged bytes it already wrote.
    pub fn reject(self, error: ErrorReply) -> io::Result<()> {
        self.payload.connection.respond(Reply::Error(error))
    }
}

/// This value proves framing/authentication only. It is intentionally not Clone.
/// Storage and lifecycle preconditions must still precede admission. Enqueue it
/// on a bounded channel consumed by exactly one scheduler owner; rejection or
/// response loss must never translate into automatic cancel/replay.
pub struct ValidatedRequest {
    pub request: Request,
    connection: Connection,
}

impl ValidatedRequest {
    pub fn respond(self, reply: Reply) -> io::Result<()> {
        self.connection.respond(reply)
    }

    pub fn into_parts(self) -> (Request, Responder) {
        (self.request, Responder(self.connection))
    }
}

/// Owned response authority lets the single scheduler consume Request by value
/// without duplicating it or losing the connection's capacity permit.
pub struct Responder(Connection);

impl Responder {
    pub fn respond(self, reply: Reply) -> io::Result<()> {
        self.0.respond(reply)
    }
}

pub struct ReceiveFailure {
    pub error: ErrorReply,
    source: Option<io::Error>,
    connection: Connection,
}

impl ReceiveFailure {
    pub fn io_error(&self) -> Option<&io::Error> {
        self.source.as_ref()
    }
    /// A disconnected peer may also reject the bounded error response; report
    /// that I/O error to the owner rather than turning it into request success.
    pub fn respond(self) -> io::Result<()> {
        self.connection.respond(Reply::Error(self.error))
    }
}

struct CappedBuffer(Vec<u8>);

impl Write for CappedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_HEADER_BYTES - self.0.len() {
            return Err(invalid("response exceeds JSON frame limit"));
        }
        // Fixed maximum capacity prevents Vec's geometric growth overshooting
        // the advertised frame bound. No request/body-sized buffer is retained.
        if self.0.capacity() == 0 {
            self.0.reserve_exact(MAX_HEADER_BYTES);
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// The peer has no authority to send a request or occupy a worker. A fixed,
// nonblocking transport write keeps the admission loop independent of the peer.
fn reject_unauthorized(stream: &UnixStream) {
    const HEADER: &[u8] = br#"{"v":1,"ok":false,"error":{"code":"UNAUTHORIZED","message":"Unix peer UID is unauthorized","retryable":false}}"#;
    let mut packet = [0; 4 + HEADER.len()];
    packet[..4].copy_from_slice(&(HEADER.len() as u32).to_be_bytes());
    packet[4..].copy_from_slice(HEADER);
    match net::send(
        stream,
        &packet,
        net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
    ) {
        Ok(sent) if sent == packet.len() => {}
        Ok(_) => eprintln!("Unix peer refusal could not send the complete bounded frame"),
        Err(error) => eprintln!("Unix peer refusal could not send its bounded frame: {error}"),
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "total socket deadline expired"))
}

fn read_until(stream: &mut UnixStream, bytes: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => {
                remaining(deadline)?;
                return result;
            }
        }
    }
}

fn read_exact_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let count = read_until(stream, bytes, deadline)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete socket frame",
            ));
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

fn write_all_until(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short socket response",
                ))
            }
            Ok(count) => {
                remaining(deadline)?;
                bytes = &bytes[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn open_private_directory(path: &Path, uid: u32) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(invalid("state directory must be absolute"));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut fd = fs::open("/", flags, Mode::empty())?;
    let mut count = 0;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                count += 1;
                if count > 128 {
                    return Err(invalid("state directory has too many components"));
                }
                fd = fs::openat2(
                    &fd,
                    name,
                    flags,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )?;
            }
            _ => return Err(invalid("state directory contains a non-normal component")),
        }
    }
    let stat = fs::fstat(&fd)?;
    if count == 0
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(invalid("state directory must be owned and mode 0700"));
    }
    Ok(fd)
}

fn socket_stat(directory: &OwnedFd, uid: u32) -> io::Result<fs::Stat> {
    let stat = fs::statat(directory, SOCKET_NAME, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(invalid(
            "control socket must be an owned mode0600 socket with one link",
        ));
    }
    Ok(stat)
}

fn remove_same_socket(directory: &OwnedFd, uid: u32, identity: Identity) -> io::Result<()> {
    let stat = socket_stat(directory, uid)?;
    if Identity::of(&stat) != identity {
        return Err(invalid("control socket identity changed; refusing removal"));
    }
    fs::unlinkat(directory, SOCKET_NAME, AtFlags::empty())?;
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
