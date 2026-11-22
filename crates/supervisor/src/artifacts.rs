//! Bounded, quiescent artifact export and durable result bundles. Linux only.
//!
//! TRUSTED CALLER CONTRACT: hold the exclusive Store state lock throughout this
//! Publisher's lifetime. An output descriptor passed to commit must come only
//! from Native::take_quiescent_output(), after launcher reaping, cgroup populated=0
//! and drained streams. An FD's type does not prove quiescence; this module never
//! creates that proof from a boolean, a saved PID, or caller JSON. None means the
//! caller deliberately discards guest artifacts under the approved profile.
//!
//! Preparation validates the whole tree before writing publication state. Once
//! staging starts, any error preserves the private stage and freezes writes for
//! reconciliation. No partial stage is returned as a result. Reservations,
//! retention, tombstones and bounded removal of abandoned stages belong to the
//! scheduler/storage owner. Successful publication still requires a separate
//! durable terminal journal commit before advertising job completion.

#![cfg(target_os = "linux")]

#[cfg(all(test, feature = "native-verification"))]
#[path = "../../../tests/fault/publisher.rs"]
mod injected_faults;

use hearthrun_domain::protocol;
use hearthrun_domain::{validate_logical_path, JobId, MAX_HEADER_BYTES};
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};

pub const MAX_ARTIFACTS: usize = 128;
pub const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_STREAM_BYTES: usize = 1024 * 1024;
const MAX_DIRECTORIES: usize = 128;
const MAX_DIRECTORY_ENTRIES: usize = 1024;
const RESULTS: &str = "results";
const ARTIFACTS: &str = "artifacts";
const METADATA: &str = "result.json";
const STDOUT: &str = "stdout.bin";
const STDERR: &str = "stderr.bin";
const TMPFS_MAGIC: u64 = 0x0102_1994;

// Inject an error before the exact persistence operation in verification builds.
// Release binaries have no fault-control field, command or environment switch.
macro_rules! persist {
    (io $publisher:expr, $point:expr, $syscall:expr, $message:expr $(,)?) => {{
        operation(persist!($publisher, $point, $syscall), $message)
    }};
    ($publisher:expr, $point:expr, $syscall:expr $(,)?) => {{
        #[cfg(all(test, feature = "native-verification"))]
        let result = match $publisher.check_persistence($point) {
            Ok(()) => ($syscall).map_err(io::Error::from),
            Err(error) => Err(error),
        };
        #[cfg(not(all(test, feature = "native-verification")))]
        let result = ($syscall).map_err(io::Error::from);
        result
    }};
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationKind {
    InvalidMetadata,
    InvalidArtifacts,
}

#[derive(Debug)]
pub struct PreparationError {
    pub kind: PreparationKind,
    pub message: &'static str,
    source: Option<io::Error>,
}

impl PreparationError {
    pub fn io_error(&self) -> Option<&io::Error> {
        self.source.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationKind {
    InvalidRoot,
    AlreadyCommitted,
    NotFound,
    CorruptResult,
    DigestMismatch,
    IoUncertain,
    Frozen,
}

#[derive(Debug)]
pub struct PublicationError {
    pub kind: PublicationKind,
    pub message: &'static str,
    source: Option<io::Error>,
}

impl PublicationError {
    pub fn io_error(&self) -> Option<&io::Error> {
        self.source.as_ref()
    }
}

#[derive(Debug)]
pub enum Error {
    Preparation(PreparationError),
    Publication(PublicationError),
}
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(error) => write!(formatter, "{:?}: {}", error.kind, error.message),
            Self::Publication(error) => write!(formatter, "{:?}: {}", error.kind, error.message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let source = match self {
            Self::Preparation(error) => &error.source,
            Self::Publication(error) => &error.source,
        };
        source
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

/// Metadata has the strict result.schema.json shape. The additional Rust fields
/// below describe internal stream files, not additional JSON schema properties.
pub struct CommittedResult {
    pub job_id: String,
    pub result_digest: String,
    pub metadata: Value,
    pub artifacts: Vec<Artifact>,
    pub stdout_size: u64,
    pub stdout_sha256: String,
    pub stderr_size: u64,
    pub stderr_sha256: String,
}

#[derive(Clone, Copy)]
pub enum Stream {
    Stdout,
    Stderr,
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

struct CheckedFile {
    path: String,
    fd: OwnedFd,
    size: u64,
    identity: Identity,
}
struct Tree {
    files: Vec<CheckedFile>,
    bytes: u64,
    directories: usize,
    entries: usize,
    names: BTreeSet<String>,
}

/// A single storage owner retains this publisher while holding Store's lock.
/// Only the scheduler issues publication work, once per reserved job ID.
pub struct Publisher {
    root: OwnedFd,
    results: OwnedFd,
    results_identity: Identity,
    uid: u32,
    frozen: AtomicBool,
    #[cfg(all(test, feature = "native-verification"))]
    fail_at: Option<&'static str>,
}

impl Publisher {
    pub fn open(root: &Path) -> Result<Self> {
        let uid = rustix::process::geteuid().as_raw();
        let root = open_root(root, uid)?;
        match fs::mkdirat(&root, RESULTS, Mode::RWXU) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io_error("cannot create results directory", error.into())),
        }
        let results = open_directory(&root, RESULTS, uid)?;
        // Also sync an existing name: this call must not rely on another caller
        // having completed a prior mkdir's parent fsync.
        operation(fs::fsync(&results), "cannot sync results directory")?;
        operation(fs::fsync(&root), "cannot sync results parent")?;
        let stat = operation(fs::fstat(&results), "cannot inspect results identity")?;
        Ok(Self {
            root,
            results,
            results_identity: Identity::of(&stat),
            uid,
            frozen: AtomicBool::new(false),
            #[cfg(all(test, feature = "native-verification"))]
            fail_at: None,
        })
    }

    #[cfg(all(test, feature = "native-verification"))]
    fn check_persistence(&self, point: &'static str) -> io::Result<()> {
        if self.fail_at == Some(point) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }

    /// Descriptor-relative retention/recovery access for the trusted owner.
    /// Validate fixed names/IDs, persist tombstones before pruning, and bound
    /// every inventory. Never forward this descriptor to a guest or client.
    pub fn result_parent(&self) -> Result<BorrowedFd<'_>> {
        if let Err(error) = self.validate_root() {
            self.frozen.store(true, Ordering::Release);
            return Err(error);
        }
        Ok(self.results.as_fd())
    }

    /// The output FD must satisfy the quiescence contract at the top of this
    /// module. A Preparation error makes no publication writes and permits a
    /// separately recorded FAILED/no-artifact attempt. A Publication error after
    /// stage creation freezes this owner; do not retry or claim a terminal job.
    pub fn commit(
        &self,
        job_id: &str,
        mut meta: Value,
        output: Option<OwnedFd>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<CommittedResult> {
        if self.is_frozen() {
            return Err(publication(
                PublicationKind::Frozen,
                "publisher is frozen after a persistence failure",
            ));
        }
        require_id(job_id)?;
        if stdout.len() > MAX_STREAM_BYTES || stderr.len() > MAX_STREAM_BYTES {
            return Err(bad_metadata("retained stream exceeds its byte limit"));
        }
        prepare_metadata(&mut meta, job_id)?;
        let mut tree = Tree::new();
        let preparation: Result<()> = (|| {
            if let Some(output) = output {
                validate_output_root(&output, self.uid)?;
                let readable = prepare_operation(
                    fs::openat2(
                        &output,
                        ".",
                        directory_flags(),
                        Mode::empty(),
                        resolve_flags(),
                    ),
                    "cannot enumerate retained output directory",
                )?;
                walk(&readable, "", self.uid, false, &mut tree)?;
            }
            Ok(())
        })();
        if let Err(error) = preparation {
            if matches!(&error, Error::Publication(_)) {
                self.frozen.store(true, Ordering::Release);
            }
            return Err(error);
        }
        tree.files.sort_by(|left, right| left.path.cmp(&right.path));
        if let Err(error) = self.validate_root() {
            self.frozen.store(true, Ordering::Release);
            return Err(error);
        }
        match fs::statat(&self.results, job_id, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                return Err(publication(
                    PublicationKind::AlreadyCommitted,
                    "a result name already exists; refusing replacement",
                ))
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                self.frozen.store(true, Ordering::Release);
                return Err(io_error("cannot check result destination", error.into()));
            }
        }
        // Generate the name before mutating publication state. Kernel entropy
        // failure never falls back to timestamps or process IDs.
        let stage_name = format!(".tmp-{job_id}-{}", random_id()?);
        let outcome = self.publish(job_id, stage_name.as_str(), meta, tree, stdout, stderr);
        if outcome.is_err() {
            self.frozen.store(true, Ordering::Release);
        }
        outcome
    }

    fn publish(
        &self,
        job_id: &str,
        stage_name: &str,
        mut meta: Value,
        tree: Tree,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<CommittedResult> {
        persist!(
            io self,
            "stage directory",
            fs::mkdirat(&self.results, stage_name, Mode::RWXU),
            "cannot create exclusive result stage",
        )?;
        let stage = open_directory(&self.results, stage_name, self.uid)?;
        persist!(
            io self,
            "artifact directory",
            fs::mkdirat(&stage, ARTIFACTS, Mode::RWXU),
            "cannot create result artifact directory",
        )?;
        let artifacts_directory = open_directory(&stage, ARTIFACTS, self.uid)?;
        let mut artifact_manifest = Vec::with_capacity(tree.files.len());
        let mut directories = BTreeSet::new();
        for source in tree.files {
            let logical_path = source.path.clone();
            let (parent, leaf) =
                artifact_parent(self, &artifacts_directory, &logical_path, &mut directories)?;
            let fd = create_file(self, &parent, leaf, "artifact create")?;
            let mut destination = File::from(fd);
            let hash = transfer_checked(source, self.uid, |bytes| {
                persist!(
                    io self,
                    "artifact copy",
                    destination.write_all(bytes),
                    "cannot copy exported artifact",
                )
            })?;
            persist!(
                io self,
                "artifact fsync",
                destination.sync_all(),
                "cannot sync exported artifact",
            )?;
            let stat = owned_file(&destination, self.uid, MAX_ARTIFACT_BYTES)?;
            match fs::statat(&parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(named) if Identity::of(&named) == Identity::of(&stat) => (),
                Ok(_) => return Err(corrupt("exported artifact name changed")),
                Err(error) => {
                    return Err(io_error(
                        "cannot inspect exported artifact name",
                        error.into(),
                    ))
                }
            }
            artifact_manifest.push(Artifact {
                path: logical_path,
                size_bytes: stat.st_size as u64,
                sha256: hash,
            });
        }
        // Filled below from exact checked descriptors; no guest path is ever
        // treated as a host absolute path or reopened without openat2 bounds.
        let stdout_sha256 = self.write_stream(&stage, STDOUT, stdout)?;
        let stderr_sha256 = self.write_stream(&stage, STDERR, stderr)?;
        let object = meta
            .as_object_mut()
            .ok_or_else(|| corrupt("prepared metadata is no longer an object"))?;
        object.insert("artifacts".into(), artifact_values(&artifact_manifest));
        let encoded = encode_metadata(&meta)?;
        let mut metadata_file = File::from(create_file(self, &stage, METADATA, "metadata create")?);
        persist!(
            io self,
            "metadata write",
            metadata_file.write_all(&encoded),
            "cannot write result metadata",
        )?;
        persist!(
            io self,
            "metadata fsync",
            metadata_file.sync_all(),
            "cannot sync result metadata",
        )?;
        for path in directories.iter().rev() {
            let directory = open_directory(&artifacts_directory, path, self.uid)?;
            persist!(
                io self,
                "artifact parent fsync",
                fs::fsync(&directory),
                "cannot sync artifact parent directory",
            )?;
        }
        persist!(
            io self,
            "artifact root fsync",
            fs::fsync(&artifacts_directory),
            "cannot sync artifact root directory",
        )?;
        persist!(
            io self,
            "stage fsync",
            fs::fsync(&stage),
            "cannot sync prepared result directory",
        )?;
        self.validate_root()?;
        persist!(
            io self,
            "result rename",
            fs::renameat_with(
                &self.results,
                stage_name,
                &self.results,
                job_id,
                RenameFlags::NOREPLACE,
            ),
            "cannot atomically publish result without replacement",
        )?;
        persist!(
            io self,
            "result parent fsync",
            fs::fsync(&self.results),
            "cannot sync committed result parent",
        )?;
        let result_digest = bundle_digest(
            &encoded,
            stdout.len() as u64,
            &stdout_sha256,
            stderr.len() as u64,
            &stderr_sha256,
        );
        Ok(CommittedResult {
            job_id: job_id.to_owned(),
            result_digest,
            metadata: meta,
            artifacts: artifact_manifest,
            stdout_size: stdout.len() as u64,
            stdout_sha256,
            stderr_size: stderr.len() as u64,
            stderr_sha256,
        })
    }

    fn write_stream(&self, directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<String> {
        let [create_site, _write_site, _sync_site] = if name == STDOUT {
            ["stdout create", "stdout write", "stdout fsync"]
        } else {
            ["stderr create", "stderr write", "stderr fsync"]
        };
        let mut file = File::from(create_file(self, directory, name, create_site)?);
        persist!(
            io self,
            _write_site,
            file.write_all(bytes),
            "cannot write retained stream",
        )?;
        persist!(
            io self,
            _sync_site,
            file.sync_all(),
            "cannot sync retained stream",
        )?;
        Ok(digest(bytes))
    }

    /// Verify metadata, stream hashes, the entire artifact inventory, and each
    /// checked file's exact bytes. expected_digest must come from the journal,
    /// not a field supplied by the result being read. NotFound may represent a
    /// scheduler-owned retention tombstone; it is not fabricated success.
    pub fn read_result(&self, job_id: &str, expected_digest: &str) -> Result<CommittedResult> {
        require_id(job_id)?;
        if !protocol::valid_sha256(expected_digest) {
            return Err(bad_metadata("invalid expected result digest"));
        }
        let outcome = self.read_verified(job_id, expected_digest);
        if matches!(&outcome, Err(Error::Publication(error)) if error.kind != PublicationKind::NotFound)
        {
            self.frozen.store(true, Ordering::Release);
        }
        outcome
    }

    fn read_verified(&self, job_id: &str, expected_digest: &str) -> Result<CommittedResult> {
        self.validate_root()?;
        let result = open_result_directory(&self.results, job_id, self.uid)?;
        validate_result_names(&result)?;
        let encoded = read_owned_bytes(&result, METADATA, MAX_HEADER_BYTES, self.uid)?;
        let metadata = protocol::strict_json(&encoded)
            .map_err(|_| corrupt("result metadata is not strict bounded JSON"))?;
        let artifacts = validate_metadata(&metadata, job_id, true)
            .map_err(|_| corrupt("committed result metadata violates v1 schema"))?;
        let artifacts_directory = open_directory(&result, ARTIFACTS, self.uid)?;
        let mut tree = Tree::new();
        walk(&artifacts_directory, "", self.uid, true, &mut tree).map_err(|error| match error {
            Error::Preparation(_) => corrupt("committed artifact tree is unsafe or unbounded"),
            Error::Publication(_) => error,
        })?;
        tree.files.sort_by(|left, right| left.path.cmp(&right.path));
        if tree.files.len() != artifacts.len() {
            return Err(corrupt(
                "artifact inventory differs from committed manifest",
            ));
        }
        for (file, manifest) in tree.files.into_iter().zip(&artifacts) {
            if file.path != manifest.path || file.size != manifest.size_bytes {
                return Err(corrupt(
                    "artifact path/size differs from committed manifest",
                ));
            }
            let hash = hash_checked(file, self.uid)?;
            if hash != manifest.sha256 {
                return Err(publication(
                    PublicationKind::DigestMismatch,
                    "committed artifact digest differs",
                ));
            }
        }
        let (stdout_size, stdout_sha256) = hash_owned_stream(&result, STDOUT, self.uid)?;
        let (stderr_size, stderr_sha256) = hash_owned_stream(&result, STDERR, self.uid)?;
        let result_digest = bundle_digest(
            &encoded,
            stdout_size,
            &stdout_sha256,
            stderr_size,
            &stderr_sha256,
        );
        if result_digest != expected_digest {
            return Err(publication(
                PublicationKind::DigestMismatch,
                "committed bundle digest differs from journal",
            ));
        }
        Ok(CommittedResult {
            job_id: job_id.to_owned(),
            result_digest,
            metadata,
            artifacts,
            stdout_size,
            stdout_sha256,
            stderr_size,
            stderr_sha256,
        })
    }

    /// Only fixed copied stream names are supported. There is no arbitrary host
    /// pathname parameter. This allocates at most one retained 1MiB stream.
    pub fn read_stream(
        &self,
        job_id: &str,
        expected_digest: &str,
        stream: Stream,
    ) -> Result<Vec<u8>> {
        let verified = self.read_result(job_id, expected_digest)?;
        let outcome = (|| {
            let result = open_result_directory(&self.results, job_id, self.uid)?;
            let (name, expected) = match stream {
                Stream::Stdout => (STDOUT, verified.stdout_sha256),
                Stream::Stderr => (STDERR, verified.stderr_sha256),
            };
            let bytes = read_owned_bytes(&result, name, MAX_STREAM_BYTES, self.uid)?;
            if digest(&bytes) != expected {
                return Err(publication(
                    PublicationKind::DigestMismatch,
                    "copied stream changed while reading",
                ));
            }
            Ok(bytes)
        })();
        if outcome.is_err() {
            self.frozen.store(true, Ordering::Release);
        }
        outcome
    }

    fn validate_root(&self) -> Result<()> {
        validate_directory(&self.root, self.uid)?;
        validate_directory(&self.results, self.uid)?;
        let named = operation(
            fs::statat(&self.root, RESULTS, AtFlags::SYMLINK_NOFOLLOW),
            "cannot inspect results name",
        )?;
        if Identity::of(&named) != self.results_identity {
            return Err(corrupt("retained results directory name changed"));
        }
        Ok(())
    }
}

impl Tree {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            bytes: 0,
            directories: 1,
            entries: 0,
            names: BTreeSet::new(),
        }
    }
}

fn walk(directory: &OwnedFd, prefix: &str, uid: u32, stored: bool, tree: &mut Tree) -> Result<()> {
    let mut entries = prepare_operation(
        Dir::read_from(directory),
        "cannot enumerate output directory",
    )?;
    while let Some(entry) = entries.read() {
        let entry = prepare_operation(entry, "cannot read output directory entry")?;
        tree.entries += 1;
        if tree.entries > MAX_DIRECTORY_ENTRIES {
            return Err(bad_artifacts("output directory entry bound exceeded"));
        }
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if name.len() > 64 || !name.is_ascii() {
            return Err(bad_artifacts(
                "artifact name violates ASCII component bounds",
            ));
        }
        let name =
            std::str::from_utf8(name).map_err(|_| bad_artifacts("artifact name is not ASCII"))?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        validate_logical_path(&path)
            .map_err(|_| bad_artifacts("artifact logical path is invalid"))?;
        if !tree.names.insert(path.clone()) {
            return Err(bad_artifacts("duplicate artifact logical path"));
        }
        let before = prepare_operation(
            fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW),
            "cannot inspect artifact entry",
        )?;
        if before.st_uid != uid {
            return Err(bad_artifacts("artifact entry has an unexpected owner"));
        }
        match FileType::from_raw_mode(before.st_mode) {
            FileType::Directory => {
                tree.directories += 1;
                if tree.directories > MAX_DIRECTORIES {
                    return Err(bad_artifacts("artifact directory bound exceeded"));
                }
                if stored && before.st_mode & 0o7777 != 0o700 {
                    return Err(bad_artifacts("stored artifact directory is not mode0700"));
                }
                let fd = prepare_operation(
                    fs::openat2(
                        directory,
                        name,
                        directory_flags(),
                        Mode::empty(),
                        resolve_flags(),
                    ),
                    "cannot resolve artifact directory safely",
                )?;
                let after =
                    prepare_operation(fs::fstat(&fd), "cannot inspect opened artifact directory")?;
                if Identity::of(&before) != Identity::of(&after)
                    || FileType::from_raw_mode(after.st_mode) != FileType::Directory
                {
                    return Err(bad_artifacts(
                        "artifact directory changed during resolution",
                    ));
                }
                walk(&fd, &path, uid, stored, tree)?;
            }
            FileType::RegularFile => {
                if tree.files.len() == MAX_ARTIFACTS || before.st_nlink != 1 || before.st_size < 0 {
                    return Err(bad_artifacts(
                        "artifact file count/type/link/size bound failed",
                    ));
                }
                let size = before.st_size as u64;
                tree.bytes = tree
                    .bytes
                    .checked_add(size)
                    .filter(|size| *size <= MAX_ARTIFACT_BYTES)
                    .ok_or_else(|| bad_artifacts("artifact byte sum exceeds32MiB"))?;
                if stored && before.st_mode & 0o7777 != 0o600 {
                    return Err(bad_artifacts("stored artifact file is not mode0600"));
                }
                let fd = prepare_operation(
                    fs::openat2(
                        directory,
                        name,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                        Mode::empty(),
                        resolve_flags(),
                    ),
                    "cannot resolve artifact file safely",
                )?;
                let after =
                    prepare_operation(fs::fstat(&fd), "cannot inspect opened artifact file")?;
                if Identity::of(&before) != Identity::of(&after)
                    || after.st_size != before.st_size
                    || after.st_uid != uid
                    || after.st_nlink != 1
                    || FileType::from_raw_mode(after.st_mode) != FileType::RegularFile
                {
                    return Err(bad_artifacts("artifact file changed during resolution"));
                }
                tree.files.push(CheckedFile {
                    path,
                    fd,
                    size,
                    identity: Identity::of(&after),
                });
            }
            _ => {
                return Err(bad_artifacts(
                    "artifact tree contains a symlink or special object",
                ))
            }
        }
    }
    Ok(())
}

fn validate_output_root(fd: &OwnedFd, uid: u32) -> Result<()> {
    let stat = prepare_operation(fs::fstat(fd), "cannot inspect retained output root")?;
    let filesystem = prepare_operation(fs::fstatfs(fd), "cannot inspect output filesystem")?;
    let flags = prepare_operation(
        fs::fcntl_getfl(fd),
        "cannot inspect output descriptor flags",
    )?;
    let descriptor_flags = prepare_operation(
        rustix::io::fcntl_getfd(fd),
        "cannot inspect output close-on-exec flag",
    )?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o700
        || filesystem.f_type as u64 != TMPFS_MAGIC
        || !flags.contains(OFlags::PATH | OFlags::DIRECTORY)
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(bad_artifacts(
            "output descriptor is not the retained private tmpfs directory",
        ));
    }
    Ok(())
}

fn prepare_metadata(metadata: &mut Value, job_id: &str) -> Result<()> {
    let object = metadata
        .as_object_mut()
        .ok_or_else(|| bad_metadata("result metadata must be an object"))?;
    if object
        .get("v")
        .is_some_and(|value| value.as_u64() != Some(1))
        || object
            .get("job_id")
            .is_some_and(|value| value.as_str() != Some(job_id))
        || object
            .get("artifacts")
            .is_some_and(|value| value.as_array().is_none_or(|array| !array.is_empty()))
    {
        return Err(bad_metadata(
            "caller supplied conflicting version/job/artifact metadata",
        ));
    }
    object.insert("v".into(), Value::from(1));
    object.insert("job_id".into(), Value::String(job_id.to_owned()));
    object.insert("artifacts".into(), Value::Array(Vec::new()));
    validate_metadata(metadata, job_id, false)?;
    Ok(())
}

fn validate_metadata(
    metadata: &Value,
    job_id: &str,
    require_sorted: bool,
) -> Result<Vec<Artifact>> {
    let object = metadata
        .as_object()
        .ok_or_else(|| bad_metadata("result metadata must be an object"))?;
    const ALLOWED: &[&str] = &[
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
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(bad_metadata("unknown result metadata field"));
    }
    if object.get("v").and_then(Value::as_u64) != Some(1)
        || object.get("job_id").and_then(Value::as_str) != Some(job_id)
        || object.get("cleanup_confirmed").and_then(Value::as_bool) != Some(true)
    {
        return Err(bad_metadata(
            "result lacks matching version/job or confirmed cleanup",
        ));
    }
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| bad_metadata("result status is missing"))?;
    if !matches!(status, "SUCCEEDED" | "FAILED" | "CANCELLED" | "INTERRUPTED") {
        return Err(bad_metadata("unknown schema result status"));
    }
    let policy = object
        .get("policy_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| bad_metadata("result policy identity is missing"))?;
    let environment = object
        .get("environment_id")
        .and_then(Value::as_str)
        .ok_or_else(|| bad_metadata("result environment identity is missing"))?;
    if !protocol::valid_sha256(policy)
        || environment.is_empty()
        || environment.len() > 128
        || environment.contains('\0')
    {
        return Err(bad_metadata("invalid bounded policy/environment identity"));
    }
    for key in ["stdout_truncated", "stderr_truncated"] {
        if object.get(key).and_then(Value::as_bool).is_none() {
            return Err(bad_metadata(
                "actual stream truncation booleans are required",
            ));
        }
    }
    let code = nullable_integer(object, "exit_code", 0, 255)?;
    let signal = nullable_integer(object, "signal", 1, 64)?;
    if (code.is_some() && signal.is_some())
        || (status == "SUCCEEDED" && (code != Some(0) || signal.is_some()))
    {
        return Err(bad_metadata("result exit/signal contradicts its status"));
    }
    let values = object
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| bad_metadata("artifact array is missing"))?;
    if values.len() > MAX_ARTIFACTS {
        return Err(bad_metadata("result artifact count exceeds128"));
    }
    let mut artifacts = Vec::with_capacity(values.len());
    let mut names = BTreeSet::<String>::new();
    let mut total = 0_u64;
    for value in values {
        let fields = value
            .as_object()
            .ok_or_else(|| bad_metadata("artifact metadata must be an object"))?;
        if fields.len() != 3
            || !fields.contains_key("path")
            || !fields.contains_key("size_bytes")
            || !fields.contains_key("sha256")
        {
            return Err(bad_metadata("artifact metadata fields missing or unknown"));
        }
        let path = fields["path"]
            .as_str()
            .ok_or_else(|| bad_metadata("artifact logical path must be a string"))?;
        validate_logical_path(path).map_err(|_| bad_metadata("invalid artifact logical path"))?;
        let size_bytes = fields["size_bytes"]
            .as_u64()
            .ok_or_else(|| bad_metadata("artifact size must be unsigned integer"))?;
        total = total
            .checked_add(size_bytes)
            .filter(|size| *size <= MAX_ARTIFACT_BYTES)
            .ok_or_else(|| bad_metadata("artifact manifest byte bound exceeded"))?;
        let sha256 = fields["sha256"]
            .as_str()
            .filter(|hash| protocol::valid_sha256(hash))
            .ok_or_else(|| bad_metadata("invalid artifact digest"))?;
        if names.iter().any(|other| {
            path == other
                || path.starts_with(&(other.clone() + "/"))
                || other.starts_with(&(path.to_owned() + "/"))
        }) {
            return Err(bad_metadata("duplicate or conflicting artifact paths"));
        }
        names.insert(path.to_owned());
        artifacts.push(Artifact {
            path: path.to_owned(),
            size_bytes,
            sha256: sha256.to_owned(),
        });
    }
    if require_sorted
        && artifacts
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(bad_metadata("artifact manifest is not strictly sorted"));
    }
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(artifacts)
}

fn nullable_integer(
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
            .ok_or_else(|| bad_metadata("exit/signal must be a bounded integer or null")),
    }
}

fn artifact_values(artifacts: &[Artifact]) -> Value {
    Value::Array(artifacts.iter().map(|artifact| serde_json::json!({
        "path": artifact.path, "size_bytes": artifact.size_bytes, "sha256": artifact.sha256,
    })).collect())
}

fn artifact_parent<'a>(
    publisher: &Publisher,
    root: &OwnedFd,
    logical_path: &'a str,
    created: &mut BTreeSet<String>,
) -> Result<(OwnedFd, &'a str)> {
    let uid = publisher.uid;
    let mut current = open_directory(root, ".", uid)?;
    let mut components = logical_path.split('/').peekable();
    let mut parent_path = String::new();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            return Ok((current, component));
        }
        if !parent_path.is_empty() {
            parent_path.push('/');
        }
        parent_path.push_str(component);
        match persist!(
            publisher,
            "artifact parent creation",
            fs::mkdirat(&current, component, Mode::RWXU)
        ) {
            Ok(()) => {
                created.insert(parent_path.clone());
            }
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
            Err(error) => return Err(io_error("cannot create artifact parent", error)),
        }
        if created.len() >= MAX_DIRECTORIES {
            return Err(corrupt("prepared artifact parent count changed"));
        }
        current = open_directory(&current, component, uid)?;
    }
    Err(corrupt("prepared artifact path has no file component"))
}

fn hash_checked(source: CheckedFile, uid: u32) -> Result<String> {
    transfer_checked(source, uid, |_| Ok(()))
}

fn transfer_checked(
    source: CheckedFile,
    uid: u32,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<String> {
    let mut file = File::from(source.fd);
    let mut remaining = source.size;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    while remaining != 0 {
        let length = buffer.len().min(remaining as usize);
        let count = operation(
            file.read(&mut buffer[..length]),
            "cannot read checked artifact",
        )?;
        if count == 0 {
            return Err(corrupt("checked artifact ended before declared size"));
        }
        consume(&buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut extra = [0_u8; 1];
    if operation(file.read(&mut extra), "cannot check artifact EOF")? != 0 {
        return Err(corrupt("checked artifact contains surplus bytes"));
    }
    let stat = operation(fs::fstat(&file), "cannot recheck artifact inode")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != uid
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as u64 != source.size
        || Identity::of(&stat) != source.identity
    {
        return Err(corrupt(
            "checked artifact changed before copy/hash completed",
        ));
    }
    Ok(hearthrun_launcher::image::lower_hex(&hash.finalize()))
}

fn hash_owned_stream(directory: &OwnedFd, name: &str, uid: u32) -> Result<(u64, String)> {
    let fd = open_owned_file(directory, name)?;
    let stat = owned_file(&fd, uid, MAX_STREAM_BYTES as u64)?;
    let size = stat.st_size as u64;
    let hash = hash_checked(
        CheckedFile {
            path: name.into(),
            fd,
            size,
            identity: Identity::of(&stat),
        },
        uid,
    )?;
    Ok((size, hash))
}

/// SHA256("HearthRun result bundle v1\\0" || metadata_len:u64be || metadata ||
/// stdout_len:u64be || stdout_sha256:64 ASCII hex || stderr_len:u64be ||
/// stderr_sha256:64 ASCII hex). Metadata binds sorted artifact paths/sizes/hashes.
fn bundle_digest(
    metadata: &[u8],
    stdout_size: u64,
    stdout_hash: &str,
    stderr_size: u64,
    stderr_hash: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"HearthRun result bundle v1\0");
    hash.update((metadata.len() as u64).to_be_bytes());
    hash.update(metadata);
    hash.update(stdout_size.to_be_bytes());
    hash.update(stdout_hash.as_bytes());
    hash.update(stderr_size.to_be_bytes());
    hash.update(stderr_hash.as_bytes());
    hearthrun_launcher::image::lower_hex(&hash.finalize())
}

fn encode_metadata(value: &Value) -> Result<Vec<u8>> {
    let mut output = BoundedBuffer(Vec::with_capacity(MAX_HEADER_BYTES));
    serde_json::to_writer(&mut output, value)
        .map_err(|_| corrupt("encoded result metadata exceeds64KiB"))?;
    Ok(output.0)
}

struct BoundedBuffer(Vec<u8>);
impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_HEADER_BYTES - self.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "metadata size bound exceeded",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_result_names(directory: &OwnedFd) -> Result<()> {
    let mut iterator = operation(
        Dir::read_from(directory),
        "cannot enumerate committed result",
    )?;
    let mut names = BTreeSet::new();
    let mut entries = 0;
    while let Some(entry) = iterator.read() {
        let entry = operation(entry, "cannot read committed result entry")?;
        entries += 1;
        if entries > 6 {
            return Err(corrupt("committed result has extra directory entries"));
        }
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name =
            std::str::from_utf8(name).map_err(|_| corrupt("committed result name is not UTF-8"))?;
        if ![ARTIFACTS, METADATA, STDOUT, STDERR].contains(&name) || !names.insert(name.to_owned())
        {
            return Err(corrupt(
                "committed result contains an unknown or duplicate name",
            ));
        }
    }
    if names.len() != 4 {
        return Err(corrupt("committed result is missing required bundle files"));
    }
    Ok(())
}

fn open_root(path: &Path, uid: u32) -> Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(publication(
            PublicationKind::InvalidRoot,
            "state root must be absolute",
        ));
    }
    let mut fd = operation(
        fs::open("/", directory_flags(), Mode::empty()),
        "cannot open filesystem root",
    )?;
    let mut count = 0;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                count += 1;
                if count > 128 {
                    return Err(publication(
                        PublicationKind::InvalidRoot,
                        "state root is too deep",
                    ));
                }
                fd = operation(
                    fs::openat2(
                        &fd,
                        name,
                        directory_flags(),
                        Mode::empty(),
                        ResolveFlags::BENEATH
                            | ResolveFlags::NO_SYMLINKS
                            | ResolveFlags::NO_MAGICLINKS,
                    ),
                    "cannot resolve state root safely",
                )?;
            }
            _ => {
                return Err(publication(
                    PublicationKind::InvalidRoot,
                    "state root contains non-normal components",
                ))
            }
        }
    }
    if count == 0 {
        return Err(publication(
            PublicationKind::InvalidRoot,
            "filesystem root cannot hold result state",
        ));
    }
    validate_directory(&fd, uid)?;
    Ok(fd)
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}
fn resolve_flags() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}

fn open_directory(parent: &OwnedFd, name: &str, uid: u32) -> Result<OwnedFd> {
    let fd = operation(
        fs::openat2(
            parent,
            name,
            directory_flags(),
            Mode::empty(),
            resolve_flags(),
        ),
        "cannot open owned result directory",
    )?;
    validate_directory(&fd, uid)?;
    Ok(fd)
}

fn open_result_directory(parent: &OwnedFd, job_id: &str, uid: u32) -> Result<OwnedFd> {
    let fd = match fs::openat2(
        parent,
        job_id,
        directory_flags(),
        Mode::empty(),
        resolve_flags(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => {
            return Err(publication(
                PublicationKind::NotFound,
                "committed result is absent",
            ))
        }
        Err(error) => {
            return Err(io_error(
                "cannot open committed result safely",
                error.into(),
            ))
        }
    };
    validate_directory(&fd, uid)?;
    Ok(fd)
}

fn validate_directory(fd: &OwnedFd, uid: u32) -> Result<()> {
    let stat = operation(fs::fstat(fd), "cannot inspect owned result directory")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(corrupt("result directory must be owned mode0700"));
    }
    Ok(())
}

fn create_file(
    publisher: &Publisher,
    directory: &OwnedFd,
    name: &str,
    _site: &'static str,
) -> Result<OwnedFd> {
    let fd = persist!(
        io publisher,
        _site,
        fs::openat2(
            directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            resolve_flags(),
        ),
        "cannot exclusively create result file",
    )?;
    owned_file(&fd, publisher.uid, 0)?;
    Ok(fd)
}

fn open_owned_file(directory: &OwnedFd, name: &str) -> Result<OwnedFd> {
    operation(
        fs::openat2(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            resolve_flags(),
        ),
        "cannot open result file safely",
    )
}

fn owned_file(fd: &impl AsFd, uid: u32, limit: u64) -> Result<fs::Stat> {
    let stat = operation(fs::fstat(fd), "cannot inspect owned result file")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as u64 > limit
    {
        return Err(corrupt(
            "result file must be a bounded owned mode0600 single-link regular file",
        ));
    }
    Ok(stat)
}

fn read_owned_bytes(directory: &OwnedFd, name: &str, limit: usize, uid: u32) -> Result<Vec<u8>> {
    let fd = open_owned_file(directory, name)?;
    let before = owned_file(&fd, uid, limit as u64)?;
    let mut file = File::from(fd);
    let mut bytes = Vec::with_capacity(limit + 1);
    let mut buffer = [0_u8; 8192];
    loop {
        let length = (limit + 1 - bytes.len()).min(buffer.len());
        if length == 0 {
            return Err(corrupt("result file grew beyond read limit"));
        }
        let count = operation(
            file.read(&mut buffer[..length]),
            "cannot read owned result bytes",
        )?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let after = owned_file(&file, uid, limit as u64)?;
    if Identity::of(&before) != Identity::of(&after)
        || before.st_size != after.st_size
        || bytes.len() as u64 != after.st_size as u64
    {
        return Err(corrupt("result file changed while reading"));
    }
    Ok(bytes)
}

fn random_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    let mut offset = 0;
    for _ in 0..32 {
        if offset == bytes.len() {
            break;
        }
        match rustix::rand::getrandom(&mut bytes[offset..], rustix::rand::GetRandomFlags::NONBLOCK)
        {
            Ok(0) => break,
            Ok(count) => offset += count,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => {
                return Err(io_error(
                    "kernel entropy unavailable for result stage",
                    error.into(),
                ))
            }
        }
    }
    if offset != bytes.len() {
        return Err(publication(
            PublicationKind::IoUncertain,
            "kernel entropy did not fill result stage ID",
        ));
    }
    let mut result = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(result)
}

fn require_id(value: &str) -> Result<()> {
    JobId::parse(value)
        .map(|_| ())
        .map_err(|_| bad_metadata("job ID must be32 lowercase hex characters"))
}
fn digest(bytes: &[u8]) -> String {
    hearthrun_launcher::image::sha256(bytes)
}
fn bad_metadata(message: &'static str) -> Error {
    Error::Preparation(PreparationError {
        kind: PreparationKind::InvalidMetadata,
        message,
        source: None,
    })
}
fn bad_artifacts(message: &'static str) -> Error {
    Error::Preparation(PreparationError {
        kind: PreparationKind::InvalidArtifacts,
        message,
        source: None,
    })
}
fn publication(kind: PublicationKind, message: &'static str) -> Error {
    Error::Publication(PublicationError {
        kind,
        message,
        source: None,
    })
}
fn corrupt(message: &'static str) -> Error {
    publication(PublicationKind::CorruptResult, message)
}
fn io_error(message: &'static str, source: io::Error) -> Error {
    Error::Publication(PublicationError {
        kind: PublicationKind::IoUncertain,
        message,
        source: Some(source),
    })
}
fn operation<T, E: Into<io::Error>>(
    value: std::result::Result<T, E>,
    message: &'static str,
) -> Result<T> {
    value.map_err(|error| io_error(message, error.into()))
}
fn prepare_operation<T, E: Into<io::Error>>(
    value: std::result::Result<T, E>,
    message: &'static str,
) -> Result<T> {
    // A source I/O failure is uncertainty, not evidence of an invalid artifact.
    // Keep it distinguishable from structural/path/link/limit rejection.
    value.map_err(|error| io_error(message, error.into()))
}
