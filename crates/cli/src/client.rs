use hearthrun_domain::protocol;
use hearthrun_domain::{validate_logical_path, JobId, MAX_HEADER_BYTES};
use rustix::fd::{AsRawFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::net::{self, sockopt, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::Shutdown;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_ARGUMENTS: usize = 140;
const MAX_ARGUMENT_BYTES: usize = 8192;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_OUTPUT_BYTES: u64 = 32 * 1024 * 1024;
const HELP: &str = "Usage:
  hearthrun --state ABS_DIR doctor
  hearthrun --state ABS_DIR metrics
  hearthrun --state ABS_DIR stage LOGICAL=LOCAL [LOGICAL=LOCAL ...]
  hearthrun --state ABS_DIR submit REQUEST_ID PROFILE_ID STAGE_ID [WALL_MS] [-- ARG ...]
  hearthrun --state ABS_DIR inspect JOB_ID
  hearthrun --state ABS_DIR cancel JOB_ID
  hearthrun --state ABS_DIR events JOB_ID [AFTER_SEQ [LIMIT]]
  hearthrun --state ABS_DIR result JOB_ID
  hearthrun --state ABS_DIR export JOB_ID LOGICAL ABS_DESTINATION

IDs are 32 lowercase hex characters. WALL_MS defaults to 10000 (100..60000).
Events LIMIT defaults to 100 (1..100). Local stage paths never cross the wire.
Export copies a committed artifact into an existing private directory.
One connection sends one request. There are no automatic retries or shell commands.
Use --help to print this text. Exit 0=success, 1=server rejection, 2=client error,
78=unsupported host reported by doctor/platform.";

#[derive(Debug)]
struct ClientError {
    code: &'static str,
    message: &'static str,
    source: Option<io::Error>,
}
type Result<T> = std::result::Result<T, ClientError>;

impl ClientError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            source: None,
        }
    }
    fn io(message: &'static str, source: io::Error) -> Self {
        Self {
            code: "IO_UNCERTAIN",
            message,
            source: Some(source),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
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

struct StageFile {
    logical: String,
    file: File,
    size: u64,
    sha256: String,
    identity: Identity,
}
struct Invocation {
    state: PathBuf,
    header: Vec<u8>,
    stage: Vec<StageFile>,
    operation: String,
    job_id: Option<String>,
    export: Option<ArtifactExport>,
}

struct ArtifactExport {
    logical: String,
    destination: PathBuf,
}

impl ArtifactExport {
    fn copy_from(&self, state: &Path, metadata: &Value) -> Result<()> {
        // execute() already validated the bounded result and bound the job ID
        // to our authenticated socket request. Only manifest paths are read.
        let entry = metadata["artifacts"]
            .as_array()
            .expect("validated manifest")
            .iter()
            .find(|entry| entry["path"].as_str() == Some(self.logical.as_str()))
            .ok_or_else(|| {
                ClientError::new("NOT_FOUND", "artifact is not in the committed manifest")
            })?;
        let size = entry["size_bytes"]
            .as_u64()
            .expect("validated artifact size");
        let hash = entry["sha256"].as_str().expect("validated artifact digest");
        let id = metadata["job_id"].as_str().expect("validated job ID");
        let uid = rustix::process::geteuid().as_raw();
        let state = open_state(state, uid)?;
        let path = Path::new("results")
            .join(id)
            .join("artifacts")
            .join(&self.logical);
        let artifact = operation(
            fs::openat2(
                &state,
                &path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            ),
            "cannot open committed artifact",
        )?;
        let stat = operation(fs::fstat(&artifact), "cannot verify committed artifact")?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != uid
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || stat.st_size as u64 != size
        {
            return Err(response_error("committed artifact metadata changed"));
        }
        let mut bytes = Vec::new();
        operation(
            File::from(artifact).take(size + 1).read_to_end(&mut bytes),
            "cannot read committed artifact",
        )?;
        if bytes.len() as u64 != size || lower_hex(&Sha256::digest(&bytes)) != hash {
            return Err(response_error(
                "copied bytes differ from committed artifact",
            ));
        }
        let parent = self
            .destination
            .parent()
            .expect("destination is a file path");
        let parent = open_state(parent, uid)?;
        let name = self
            .destination
            .file_name()
            .expect("destination is a file path");
        write_export(&parent, name, &bytes)
    }
}

fn write_export(parent: &OwnedFd, name: &OsStr, bytes: &[u8]) -> Result<()> {
    let mut random = [0; 16];
    let mut cursor = 0;
    while cursor < random.len() {
        match rustix::rand::getrandom(&mut random[cursor..], rustix::rand::GetRandomFlags::empty())
        {
            Ok(0) => return Err(response_error("kernel did not provide export nonce")),
            Ok(count) => cursor += count,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => {
                return Err(ClientError::io(
                    "cannot generate export nonce",
                    error.into(),
                ))
            }
        }
    }
    let temporary = format!(".hearthrun-export-{}", lower_hex(&random));
    let fd = operation(
        fs::openat(
            parent,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        ),
        "cannot create private export file",
    )?;
    let mut file = File::from(fd);
    let result = (|| {
        operation(file.write_all(bytes), "cannot write checked artifact")?;
        operation(file.sync_all(), "cannot sync checked artifact")?;
        operation(
            fs::renameat_with(parent, &temporary, parent, name, fs::RenameFlags::NOREPLACE),
            "cannot publish checked artifact at an unused destination",
        )
    })();
    if let Err(error) = result {
        operation(
            fs::unlinkat(parent, &temporary, AtFlags::empty()),
            "cannot discard private export file after failure",
        )?;
        return Err(error);
    }
    operation(fs::fsync(parent), "export exists but directory sync failed")
}

pub fn run() -> i32 {
    match execute() {
        Ok(code) => code,
        Err(error) => {
            // The error cause is retained for a bounded local diagnostic. JSON
            // encoding escapes terminal controls; no raw guest bytes are printed.
            let mut message = error.message.to_owned();
            if let Some(source) = error.source {
                let detail = source.to_string();
                let available = 1024_usize.saturating_sub(message.len() + 2);
                let mut end = detail.len().min(available);
                while !detail.is_char_boundary(end) {
                    end -= 1;
                }
                message.push_str(": ");
                message.push_str(&detail[..end]);
            }
            let envelope = serde_json::json!({"v":1,"ok":false,"error":{
                "code":error.code,"message":message,"retryable":false}});
            let status = if error.code == "UNSUPPORTED_HOST" {
                78
            } else {
                2
            };
            if let Err(output_error) = write_json(&mut io::stderr().lock(), &envelope) {
                eprintln!(
                    "IO_UNCERTAIN: cannot write the bounded client diagnostic: {output_error}"
                );
            }
            status
        }
    }
}

fn execute() -> Result<i32> {
    let mut arguments = Vec::new();
    for argument in std::env::args_os().skip(1).take(MAX_ARGUMENTS + 1) {
        if argument.as_bytes().len() > MAX_ARGUMENT_BYTES {
            return Err(usage("argument exceeds client byte bound"));
        }
        arguments.push(argument);
    }
    if arguments.len() > MAX_ARGUMENTS {
        return Err(usage("too many command-line arguments"));
    }
    if arguments.len() == 1 && matches!(arguments[0].to_str(), Some("--help" | "-h")) {
        operation(
            io::stdout().lock().write_all(HELP.as_bytes()),
            "cannot write help text",
        )?;
        operation(
            io::stdout().lock().write_all(b"\n"),
            "cannot finish help text",
        )?;
        return Ok(0);
    }
    let mut invocation = parse(&arguments)?;
    let mut socket = connect(&invocation.state)?;
    let send_outcome = send(&mut socket, &invocation.header, &mut invocation.stage);
    // EOF lets the server reject a second frame or surplus staging bytes. It is
    // not cancellation, and no failure here triggers another request.
    let close_outcome = socket.shutdown(Shutdown::Write);
    let response = read_response(&mut socket);
    let envelope = match (send_outcome, close_outcome, response) {
        (Ok(()), Ok(()), Ok(value)) => value,
        (Err(_), _, Ok(value)) if value.get("ok").and_then(Value::as_bool) == Some(false) => value,
        (Err(error), _, _) => return Err(error),
        (_, Err(error), _) => {
            return Err(ClientError::io(
                "request write shutdown failed; no request was retried",
                error,
            ))
        }
        (_, _, Err(error)) => return Err(error),
    };
    let accepted = validate_envelope(&envelope)?;
    if accepted {
        validate_success(&invocation, &envelope["result"])?;
        if let Some(export) = &invocation.export {
            export.copy_from(&invocation.state, &envelope["result"]["metadata"])?;
        }
    }
    operation(
        write_json(&mut io::stdout().lock(), &envelope),
        "cannot print response JSON",
    )?;
    if !accepted {
        return Ok(
            if envelope["error"]["code"].as_str() == Some("UNSUPPORTED_HOST") {
                78
            } else {
                1
            },
        );
    }
    if invocation.operation == "doctor" && envelope["result"]["compatible"].as_bool() == Some(false)
    {
        return Ok(78);
    }
    Ok(0)
}

fn parse(arguments: &[OsString]) -> Result<Invocation> {
    if arguments.len() < 3 || arguments[0].as_os_str() != OsStr::new("--state") {
        return Err(usage(
            "--state ABS_DIR and a command are required; use --help",
        ));
    }
    let state = PathBuf::from(&arguments[1]);
    if !state.is_absolute() || state.as_os_str().as_bytes().len() > 4096 {
        return Err(usage("state directory must be an absolute bounded path"));
    }
    let command = utf8(&arguments[2])?;
    let tail = &arguments[3..];
    let mut stage = Vec::new();
    let mut job_id = None;
    let mut export = None;
    let header_value = match command {
        "doctor" | "metrics" => {
            if !tail.is_empty() {
                return Err(usage("doctor/metrics accept no further arguments"));
            }
            serde_json::json!({"v":1,"op":command})
        }
        "stage" => {
            stage = prepare_stage(tail)?;
            let files: Vec<_> = stage
                .iter()
                .map(|file| {
                    serde_json::json!({
                "path":file.logical,"size":file.size,"sha256":file.sha256})
                })
                .collect();
            serde_json::json!({"v":1,"op":"stage","files":files})
        }
        "submit" => parse_submit(tail)?,
        "inspect" | "cancel" | "result" => {
            if tail.len() != 1 {
                return Err(usage("inspect/cancel/result require exactly one job ID"));
            }
            let id = valid_id(&tail[0])?;
            job_id = Some(id.to_owned());
            serde_json::json!({"v":1,"op":command,"job_id":id})
        }
        "export" => {
            let [id, logical, destination] = tail else {
                return Err(usage("export requires JOB_ID LOGICAL ABS_DESTINATION"));
            };
            let id = valid_id(id)?;
            let logical = utf8(logical)?;
            validate_logical_path(logical).map_err(|_| usage("invalid artifact logical path"))?;
            let destination = PathBuf::from(destination);
            if !destination.is_absolute()
                || destination.as_os_str().as_bytes().len() > 4096
                || destination.file_name().is_none()
            {
                return Err(usage(
                    "export destination must name an absolute bounded file path",
                ));
            }
            job_id = Some(id.to_owned());
            export = Some(ArtifactExport {
                logical: logical.to_owned(),
                destination,
            });
            serde_json::json!({"v":1,"op":"result","job_id":id})
        }
        "events" => {
            if !(1..=3).contains(&tail.len()) {
                return Err(usage("events requires JOB_ID and optional AFTER_SEQ/LIMIT"));
            }
            let id = valid_id(&tail[0])?;
            job_id = Some(id.to_owned());
            let after_seq = if tail.len() >= 2 {
                unsigned(&tail[1])?
            } else {
                0
            };
            let limit = if tail.len() == 3 {
                unsigned(&tail[2])?
            } else {
                100
            };
            if !(1..=100).contains(&limit) {
                return Err(usage("event limit must be1..100"));
            }
            serde_json::json!({"v":1,"op":"events","job_id":id,"after_seq":after_seq,"limit":limit})
        }
        _ => return Err(usage("unknown command; use --help")),
    };
    let header = serde_json::to_vec(&header_value).map_err(|_| usage("cannot encode command"))?;
    if header.is_empty() || header.len() > MAX_HEADER_BYTES {
        return Err(usage("request exceeds64KiB header limit"));
    }
    protocol::parse_request(&header)
        .map_err(|error| ClientError::new(error.code.as_str(), error.message))?;
    Ok(Invocation {
        state,
        header,
        stage,
        operation: command.to_owned(),
        job_id,
        export,
    })
}

fn parse_submit(arguments: &[OsString]) -> Result<Value> {
    if arguments.len() < 3 {
        return Err(usage("submit requires REQUEST_ID PROFILE_ID STAGE_ID"));
    }
    let request_id = valid_id(&arguments[0])?;
    let profile_id = utf8(&arguments[1])?;
    if !protocol::valid_profile_id(profile_id) {
        return Err(usage("invalid profile ID"));
    }
    let stage_id = valid_id(&arguments[2])?;
    let mut cursor = 3;
    let wall_ms = if arguments
        .get(cursor)
        .is_some_and(|argument| argument.as_os_str() != OsStr::new("--"))
    {
        let value = unsigned(&arguments[cursor])?;
        cursor += 1;
        value
    } else {
        10_000
    };
    if !(100..=60_000).contains(&wall_ms) {
        return Err(usage("wall time must be100..60000 milliseconds"));
    }
    if cursor < arguments.len() {
        if arguments[cursor].as_os_str() != OsStr::new("--") {
            return Err(usage("guest argument list must follow --"));
        }
        cursor += 1;
    }
    let rest = &arguments[cursor..];
    if rest.len() > 32 {
        return Err(usage("at most32 guest arguments are accepted"));
    }
    let mut argv = Vec::with_capacity(rest.len());
    let mut bytes = 0_usize;
    for argument in rest {
        let value = utf8(argument)?;
        bytes = bytes
            .checked_add(value.len())
            .filter(|size| *size <= 4096)
            .ok_or_else(|| usage("guest argument bytes exceed4096"))?;
        if value.contains('\0') {
            return Err(usage("guest argument contains NUL"));
        }
        argv.push(value);
    }
    Ok(
        serde_json::json!({"v":1,"op":"submit","request_id":request_id,"profile_id":profile_id,
        "stage_id":stage_id,"wall_ms":wall_ms,"argv":argv}),
    )
}

fn prepare_stage(arguments: &[OsString]) -> Result<Vec<StageFile>> {
    if arguments.is_empty() || arguments.len() > protocol::MAX_FILES {
        return Err(usage("stage requires1..128 LOGICAL=LOCAL files"));
    }
    let mut files = Vec::with_capacity(arguments.len());
    let mut names = BTreeSet::<String>::new();
    let mut total = 0_u64;
    for argument in arguments {
        let bytes = argument.as_bytes();
        let split = bytes
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| usage("staging arguments must be LOGICAL=LOCAL"))?;
        let logical = std::str::from_utf8(&bytes[..split])
            .map_err(|_| usage("logical staging path must be ASCII"))?;
        validate_logical_path(logical)
            .map_err(|_| ClientError::new("INVALID_PATH", "invalid logical staging path"))?;
        if names.iter().any(|other| {
            logical == other
                || logical.starts_with(&(other.clone() + "/"))
                || other.starts_with(&(logical.to_owned() + "/"))
        }) {
            return Err(ClientError::new(
                "INVALID_PATH",
                "duplicate or conflicting logical staging paths",
            ));
        }
        let local = OsStr::from_bytes(&bytes[split + 1..]);
        if local.is_empty() || local.as_bytes().len() > 4096 {
            return Err(usage("local staging path is empty or too long"));
        }
        // The operator explicitly authorizes this client-side read. Only the
        // logical name, size and digest go to the supervisor, never this path.
        let before = operation(
            fs::statat(fs::CWD, local, AtFlags::SYMLINK_NOFOLLOW),
            "cannot inspect local staging source",
        )?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile || before.st_size < 0 {
            return Err(usage(
                "local staging source must be a regular file, not a symlink or special object",
            ));
        }
        let size = before.st_size as u64;
        total = total
            .checked_add(size)
            .filter(|sum| *sum <= protocol::MAX_INPUT_BYTES)
            .ok_or_else(|| {
                ClientError::new("INVALID_LIMIT", "combined staged inputs exceed16MiB")
            })?;
        let fd = operation(
            fs::open(
                local,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            ),
            "cannot open local staging source",
        )?;
        let opened = operation(fs::fstat(&fd), "cannot inspect opened staging source")?;
        if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
            || Identity::of(&before) != Identity::of(&opened)
            || opened.st_size != before.st_size
        {
            return Err(ClientError::new(
                "IO_UNCERTAIN",
                "local staging source changed while opening",
            ));
        }
        let mut file = File::from(fd);
        let sha256 = read_exact_file(&mut file, size, Identity::of(&opened), None, None)?;
        operation(
            file.seek(SeekFrom::Start(0)),
            "cannot rewind checked staging source",
        )?;
        names.insert(logical.to_owned());
        files.push(StageFile {
            logical: logical.to_owned(),
            file,
            size,
            sha256,
            identity: Identity::of(&opened),
        });
    }
    Ok(files)
}

fn connect(state: &Path) -> Result<UnixStream> {
    let uid = rustix::process::geteuid().as_raw();
    let directory = open_state(state, uid)?;
    let before = socket_stat(&directory, uid)?;
    let fd = operation(
        net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        ),
        "cannot create local client socket",
    )?;
    let anchor = format!("/proc/self/fd/{}/control.sock", directory.as_raw_fd());
    let address = operation(
        SocketAddrUnix::new(anchor.as_str()),
        "cannot encode local socket address",
    )?;
    // Nonblocking connect prevents a full listen backlog from hanging this CLI.
    // AF_UNIX reports AGAIN for a full backlog; the client never retries it.
    match net::connect(&fd, &address) {
        Ok(()) => {}
        Err(rustix::io::Errno::AGAIN) => {
            return Err(ClientError::new(
                "QUEUE_FULL",
                "local socket backlog is full; no request was sent or retried",
            ))
        }
        Err(error) => {
            return Err(ClientError::io(
                "cannot connect to owner-only supervisor",
                error.into(),
            ))
        }
    }
    let socket = UnixStream::from(fd);
    let credentials = operation(
        sockopt::socket_peercred(&socket),
        "cannot authenticate supervisor peer credentials",
    )?;
    if credentials.uid.as_raw() != uid {
        return Err(ClientError::new(
            "UNAUTHORIZED",
            "supervisor peer UID differs from current UID",
        ));
    }
    let after = socket_stat(&directory, uid)?;
    if Identity::of(&before) != Identity::of(&after) {
        return Err(ClientError::new(
            "UNAUTHORIZED",
            "control socket name changed during connection",
        ));
    }
    operation(
        socket.set_nonblocking(false),
        "cannot configure bounded socket I/O",
    )?;
    Ok(socket)
}

fn open_state(path: &Path, uid: u32) -> Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = operation(
        fs::open("/", flags, Mode::empty()),
        "cannot open filesystem root",
    )?;
    let mut count = 0;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                count += 1;
                if count > 128 {
                    return Err(usage("state directory exceeds path depth bound"));
                }
                fd = operation(
                    fs::openat2(
                        &fd,
                        name,
                        flags,
                        Mode::empty(),
                        ResolveFlags::BENEATH
                            | ResolveFlags::NO_SYMLINKS
                            | ResolveFlags::NO_MAGICLINKS,
                    ),
                    "cannot resolve state directory safely",
                )?;
            }
            _ => return Err(usage("state directory contains non-normal components")),
        }
    }
    let stat = operation(fs::fstat(&fd), "cannot inspect state directory")?;
    if count == 0
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(ClientError::new(
            "UNAUTHORIZED",
            "state directory must be owned by current UID with mode0700",
        ));
    }
    Ok(fd)
}

fn socket_stat(directory: &OwnedFd, uid: u32) -> Result<fs::Stat> {
    let stat = operation(
        fs::statat(directory, "control.sock", AtFlags::SYMLINK_NOFOLLOW),
        "cannot inspect supervisor socket",
    )?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(ClientError::new(
            "UNAUTHORIZED",
            "control endpoint must be an owned mode0600 single-link Unix socket",
        ));
    }
    Ok(stat)
}

fn send(socket: &mut UnixStream, header: &[u8], files: &mut [StageFile]) -> Result<()> {
    let header_deadline = Instant::now() + HEADER_TIMEOUT;
    write_until(
        socket,
        &(header.len() as u32).to_be_bytes(),
        header_deadline,
    )?;
    write_until(socket, header, header_deadline)?;
    if !files.is_empty() {
        let payload_deadline = Instant::now() + PAYLOAD_TIMEOUT;
        for source in files {
            let actual = read_exact_file(
                &mut source.file,
                source.size,
                source.identity,
                Some(socket),
                Some(payload_deadline),
            )?;
            if actual != source.sha256 {
                return Err(ClientError::new(
                    "STAGE_DIGEST_MISMATCH",
                    "local source changed after manifest hashing; no request was retried",
                ));
            }
        }
    }
    Ok(())
}

fn read_exact_file(
    file: &mut File,
    size: u64,
    identity: Identity,
    mut socket: Option<&mut UnixStream>,
    deadline: Option<Instant>,
) -> Result<String> {
    let mut remaining = size;
    let mut buffer = [0_u8; 16 * 1024];
    let mut hash = Sha256::new();
    while remaining != 0 {
        if let Some(deadline) = deadline {
            time_left(deadline)?;
        }
        let length = buffer.len().min(remaining as usize);
        let count = operation(
            file.read(&mut buffer[..length]),
            "cannot read checked local staging source",
        )?;
        if count == 0 {
            return Err(ClientError::new(
                "STAGE_DIGEST_MISMATCH",
                "local staging source ended before declared size",
            ));
        }
        hash.update(&buffer[..count]);
        if let (Some(socket), Some(deadline)) = (socket.as_deref_mut(), deadline) {
            write_until(socket, &buffer[..count], deadline)?;
        }
        remaining -= count as u64;
    }
    let mut extra = [0_u8; 1];
    if operation(file.read(&mut extra), "cannot verify local staging EOF")? != 0 {
        return Err(ClientError::new(
            "STAGE_DIGEST_MISMATCH",
            "local staging source grew after size check",
        ));
    }
    let stat = operation(fs::fstat(file), "cannot recheck local staging source")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_size < 0
        || stat.st_size as u64 != size
        || Identity::of(&stat) != identity
    {
        return Err(ClientError::new(
            "STAGE_DIGEST_MISMATCH",
            "local staging source inode or size changed",
        ));
    }
    if let Some(deadline) = deadline {
        time_left(deadline)?;
    }
    Ok(lower_hex(&hash.finalize()))
}

fn read_response(socket: &mut UnixStream) -> Result<Value> {
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    let mut prefix = [0_u8; 4];
    read_exact_until(socket, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_HEADER_BYTES {
        return Err(ClientError::new(
            "BAD_FRAME",
            "response JSON header length is outside bounds",
        ));
    }
    let mut bytes = vec![0_u8; length];
    read_exact_until(socket, &mut bytes, deadline)?;
    let value = protocol::strict_json(&bytes)
        .map_err(|error| ClientError::new(error.code.as_str(), error.message))?;
    let mut surplus = [0_u8; 1];
    if read_until(socket, &mut surplus, deadline)? != 0 {
        return Err(ClientError::new(
            "BAD_FRAME",
            "surplus response bytes or second frame",
        ));
    }
    Ok(value)
}

fn validate_envelope(value: &Value) -> Result<bool> {
    let object = value
        .as_object()
        .ok_or_else(|| response_error("response must be an object"))?;
    if object.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(ClientError::new(
            "UNSUPPORTED_VERSION",
            "response protocol version1 required",
        ));
    }
    let ok = object
        .get("ok")
        .and_then(Value::as_bool)
        .ok_or_else(|| response_error("response ok flag must be boolean"))?;
    if object.len() != 3 || !object.contains_key(if ok { "result" } else { "error" }) {
        return Err(response_error(
            "response envelope fields missing or unknown",
        ));
    }
    if !ok {
        let error = object["error"]
            .as_object()
            .ok_or_else(|| response_error("typed error object required"))?;
        if error
            .keys()
            .any(|key| !["code", "message", "retryable", "details"].contains(&key.as_str()))
        {
            return Err(response_error("unknown error envelope field"));
        }
        let code = error
            .get("code")
            .and_then(Value::as_str)
            .filter(|code| known_error(code))
            .ok_or_else(|| response_error("unknown or missing error code"))?;
        if error
            .get("message")
            .and_then(Value::as_str)
            .is_none_or(|message| message.len() > 1024)
        {
            return Err(response_error("error message is missing or unbounded"));
        }
        let retryable = error
            .get("retryable")
            .and_then(Value::as_bool)
            .ok_or_else(|| response_error("error retryable flag must be boolean"))?;
        if retryable && code != "QUEUE_FULL" {
            return Err(response_error("only QUEUE_FULL may suggest retry"));
        }
        if error
            .get("details")
            .is_some_and(|details| !details.is_object())
        {
            return Err(response_error("error details must be an object"));
        }
    }
    Ok(ok)
}

fn validate_success(invocation: &Invocation, value: &Value) -> Result<()> {
    match invocation.operation.as_str() {
        "doctor" if value.get("compatible").and_then(Value::as_bool).is_none() => {
            return Err(response_error("doctor result lacks compatible boolean"))
        }
        "stage" => {
            let id = value
                .get("stage_id")
                .and_then(Value::as_str)
                .ok_or_else(|| response_error("stage result lacks stage ID"))?;
            JobId::parse(id).map_err(|_| response_error("stage result has invalid stage ID"))?;
            if value
                .get("manifest_digest")
                .and_then(Value::as_str)
                .is_none_or(|digest| !protocol::valid_sha256(digest))
            {
                return Err(response_error("stage result has invalid manifest digest"));
            }
        }
        "submit" => {
            let id = value
                .get("job_id")
                .and_then(Value::as_str)
                .ok_or_else(|| response_error("submit result lacks job ID"))?;
            JobId::parse(id).map_err(|_| response_error("submit result has invalid job ID"))?;
            if value.get("state").and_then(Value::as_str).is_none()
                || value.get("sequence").and_then(Value::as_u64).is_none()
            {
                return Err(response_error("submit result lacks state/sequence"));
            }
        }
        "result" | "export" => validate_result(
            value,
            invocation
                .job_id
                .as_deref()
                .ok_or_else(|| response_error("missing requested result identity"))?,
        )?,
        _ => {}
    }
    Ok(())
}

fn validate_result(result: &Value, job_id: &str) -> Result<()> {
    let result = result
        .as_object()
        .ok_or_else(|| response_error("result response must be an object"))?;
    if result.len() != 2
        || !result.contains_key("metadata")
        || result
            .get("result_digest")
            .and_then(Value::as_str)
            .is_none_or(|digest| !protocol::valid_sha256(digest))
    {
        return Err(response_error(
            "result response lacks exact metadata/digest fields",
        ));
    }
    let metadata = result["metadata"]
        .as_object()
        .ok_or_else(|| response_error("result metadata must be an object"))?;
    const FIELDS: &[&str] = &[
        "v",
        "job_id",
        "status",
        "cleanup_confirmed",
        "artifacts",
        "policy_sha256",
        "environment_id",
        "exit_code",
        "signal",
        "stdout_truncated",
        "stderr_truncated",
    ];
    if metadata.keys().any(|key| !FIELDS.contains(&key.as_str()))
        || metadata.get("v").and_then(Value::as_u64) != Some(1)
        || metadata.get("job_id").and_then(Value::as_str) != Some(job_id)
        || metadata.get("cleanup_confirmed").and_then(Value::as_bool) != Some(true)
    {
        return Err(response_error(
            "result metadata identity/version/cleanup is invalid",
        ));
    }
    let status = metadata
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| response_error("result status is missing"))?;
    if !matches!(status, "SUCCEEDED" | "FAILED" | "CANCELLED" | "INTERRUPTED") {
        return Err(response_error("unknown committed result status"));
    }
    if metadata
        .get("policy_sha256")
        .and_then(Value::as_str)
        .is_none_or(|digest| !protocol::valid_sha256(digest))
        || metadata
            .get("environment_id")
            .and_then(Value::as_str)
            .is_none_or(|id| id.is_empty() || id.len() > 128)
    {
        return Err(response_error(
            "result policy/environment identity is invalid",
        ));
    }
    for key in ["stdout_truncated", "stderr_truncated"] {
        if metadata.get(key).is_some_and(|value| !value.is_boolean()) {
            return Err(response_error("result truncation flag must be boolean"));
        }
    }
    let exit = optional_integer(metadata, "exit_code", 0, 255)?;
    let signal = optional_integer(metadata, "signal", 1, 64)?;
    if (exit.is_some() && signal.is_some())
        || (status == "SUCCEEDED" && (exit != Some(0) || signal.is_some()))
    {
        return Err(response_error("result status contradicts exit observation"));
    }
    let artifacts = metadata
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| response_error("artifact manifest is missing"))?;
    if artifacts.len() > 128 {
        return Err(response_error("artifact manifest count exceeds128"));
    }
    let mut names = BTreeSet::<String>::new();
    let mut total = 0_u64;
    for artifact in artifacts {
        let artifact = artifact
            .as_object()
            .ok_or_else(|| response_error("artifact manifest entry must be an object"))?;
        if artifact.len() != 3
            || !artifact.contains_key("path")
            || !artifact.contains_key("size_bytes")
            || !artifact.contains_key("sha256")
        {
            return Err(response_error(
                "artifact manifest fields missing or unknown",
            ));
        }
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| response_error("artifact path must be logical string"))?;
        validate_logical_path(path).map_err(|_| response_error("invalid artifact logical path"))?;
        if names.iter().any(|other| {
            path == other
                || path.starts_with(&(other.clone() + "/"))
                || other.starts_with(&(path.to_owned() + "/"))
        }) {
            return Err(response_error("artifact paths conflict"));
        }
        names.insert(path.to_owned());
        let size = artifact["size_bytes"]
            .as_u64()
            .ok_or_else(|| response_error("artifact size must be unsigned integer"))?;
        total = total
            .checked_add(size)
            .filter(|sum| *sum <= MAX_OUTPUT_BYTES)
            .ok_or_else(|| response_error("artifact byte sum exceeds32MiB"))?;
        if artifact["sha256"]
            .as_str()
            .is_none_or(|hash| !protocol::valid_sha256(hash))
        {
            return Err(response_error("invalid artifact digest"));
        }
    }
    Ok(())
}

fn optional_integer(
    object: &Map<String, Value>,
    key: &str,
    low: i64,
    high: i64,
) -> Result<Option<i64>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .filter(|number| (low..=high).contains(number))
            .map(Some)
            .ok_or_else(|| response_error("invalid result exit/signal integer")),
    }
}

fn known_error(code: &str) -> bool {
    matches!(
        code,
        "BAD_FRAME"
            | "BAD_JSON"
            | "UNSUPPORTED_VERSION"
            | "UNKNOWN_FIELD"
            | "DUPLICATE_KEY"
            | "UNAUTHORIZED"
            | "INVALID_PATH"
            | "INVALID_LIMIT"
            | "PROFILE_NOT_FOUND"
            | "PROFILE_DIGEST_MISMATCH"
            | "UNSUPPORTED_EXECUTABLE"
            | "STAGE_NOT_FOUND"
            | "STAGE_DIGEST_MISMATCH"
            | "QUEUE_FULL"
            | "STORAGE_FULL"
            | "CONFLICT"
            | "NOT_FOUND"
            | "NOT_READY"
            | "UNSUPPORTED_HOST"
            | "STARTUP_FAILED"
            | "POLICY_FAILED"
            | "CLEANUP_PENDING"
            | "CORRUPT_STATE"
            | "IO_UNCERTAIN"
            | "INTERNAL"
    )
}

fn time_left(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            ClientError::new(
                "IO_UNCERTAIN",
                "total socket deadline expired; no request was retried",
            )
        })
}

fn write_until(socket: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        operation(
            socket.set_write_timeout(Some(time_left(deadline)?)),
            "cannot set socket write deadline",
        )?;
        match socket.write(bytes) {
            Ok(0) => {
                return Err(ClientError::new(
                    "IO_UNCERTAIN",
                    "zero-length socket write; no request was retried",
                ))
            }
            Ok(count) => {
                time_left(deadline)?;
                bytes = &bytes[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(ClientError::io(
                    "socket write failed; no request was retried",
                    error,
                ))
            }
        }
    }
    Ok(())
}

fn read_until(socket: &mut UnixStream, bytes: &mut [u8], deadline: Instant) -> Result<usize> {
    loop {
        operation(
            socket.set_read_timeout(Some(time_left(deadline)?)),
            "cannot set response read deadline",
        )?;
        match socket.read(bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            outcome => {
                time_left(deadline)?;
                return operation(outcome, "response unavailable; no request was retried");
            }
        }
    }
}

fn read_exact_until(
    socket: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    while !bytes.is_empty() {
        let count = read_until(socket, bytes, deadline)?;
        if count == 0 {
            return Err(ClientError::new(
                "BAD_FRAME",
                "response ended before declared frame length",
            ));
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

fn utf8(value: &OsStr) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| usage("command fields and guest arguments must be UTF-8"))
}
fn valid_id(value: &OsStr) -> Result<&str> {
    let text = utf8(value)?;
    JobId::parse(text).map_err(|_| usage("ID must be32 lowercase hex characters"))?;
    Ok(text)
}
fn unsigned(value: &OsStr) -> Result<u64> {
    let text = utf8(value)?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(usage("unsigned decimal integer required"));
    }
    text.parse()
        .map_err(|_| usage("unsigned integer exceeds supported range"))
}
fn write_json(output: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *output, value).map_err(io::Error::other)?;
    output.write_all(b"\n")
}
fn usage(message: &'static str) -> ClientError {
    ClientError::new("BAD_JSON", message)
}
fn response_error(message: &'static str) -> ClientError {
    ClientError::new("BAD_JSON", message)
}
fn operation<T, E: Into<io::Error>>(
    value: std::result::Result<T, E>,
    message: &'static str,
) -> Result<T> {
    value.map_err(|error| ClientError::io(message, error.into()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 15) as usize]));
    }
    output
}
