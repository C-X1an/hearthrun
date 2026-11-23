//! Owner-only, bounded v1 intent/retry journal. Linux only; no weaker fallback.
//!
//! The configured root must already exist with mode 0700. Store owns its fixed
//! lock file for its whole lifetime; never unlink/recreate that lock. The one
//! scheduler owner performs writes. This module neither launches nor requeues
//! work, kills processes, trusts saved PIDs, exports bytes, nor verifies results.
//! Recovery classifications are instructions for reconciliation, never proof of
//! cleanup or success. Saved monotonic observations are not restart deadlines.
//!
//! Every retry identity is retained. At the count/content-byte limit admission
//! refuses instead of forgetting an old ID. Result retention is a separate
//! concern. Metadata limits below count file contents; filesystem overhead must
//! additionally fit the operator's enforced storage quota. A crash temporary is
//! preserved and refuses mutation pending explicit offline recovery.

#![cfg(target_os = "linux")]

#[cfg(all(test, feature = "native-verification"))]
#[path = "../../../tests/fault/journal_reopen.rs"]
mod journal_faults;

use hearthrun_domain::protocol::{self, Request, Submission};
use hearthrun_domain::JobId;
use rustix::fd::OwnedFd;
use rustix::fs::{
    self, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags,
};
use rustix::rand::{self, GetRandomFlags};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

pub const MAX_RECORDS: usize = 256;
pub const MAX_RECORD_BYTES: usize = 65_536;
pub const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INSTANCE_BYTES: usize = 256;
// Leave space for one atomic replacement while its previous inode still exists.
const MAX_RETAINED_BYTES: u64 =
    MAX_METADATA_BYTES - MAX_RECORD_BYTES as u64 - MAX_INSTANCE_BYTES as u64;
const LOCK_NAME: &str = "supervisor.lock";
const INSTANCE_NAME: &str = "instance.json";
const RECORDS_NAME: &str = "records";
const CATALOG_NAME: &str = "catalog.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Locked,
    InvalidRoot,
    UnsupportedVersion,
    CorruptState,
    MissingData,
    InvalidRecord,
    InvalidTransition,
    Conflict,
    StorageFull,
    IoUncertain,
    RandomUnavailable,
}

#[derive(Debug)]
pub struct StoreError {
    pub kind: ErrorKind,
    pub message: &'static str,
    source: Option<io::Error>,
}

impl StoreError {
    fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }
    fn io(message: &'static str, source: io::Error) -> Self {
        Self {
            kind: ErrorKind::IoUncertain,
            message,
            source: Some(source),
        }
    }
    pub fn io_error(&self) -> Option<&io::Error> {
        self.source.as_ref()
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExit {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

/// canonical_request is the domain Submission's exact canonical UTF-8 JSON,
/// not an arbitrary host path or reconstructed/omitted payload. Its digest and
/// repeated identity fields are checked on every read and write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    pub v: u32,
    pub instance_id: String,
    pub job_id: String,
    pub request_id: String,
    pub canonical_request_sha256: String,
    pub canonical_request: String,
    pub state: String,
    pub sequence: u64,
    pub launch_stage: String,
    pub profile_id: String,
    pub stage_id: String,
    pub stage_manifest_digest: String,
    pub profile_digest: String,
    pub executable_digest: String,
    pub policy_digest: String,
    pub submitted_at_utc: String,
    pub started_monotonic_ns: Option<u64>,
    pub observed_exit: Option<ObservedExit>,
    pub cancel_reason: Option<String>,
    pub cleanup_confirmed: bool,
    pub result_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovery {
    /// An intent that never reached a cgroup still cannot be automatically run.
    UnlaunchedInterrupted,
    /// Match the exact instance/job-owned cgroup, kill it and prove emptiness.
    ReconcileOwnedCgroup,
    /// Preserve the slot/quarantine until cleanup can actually be proved.
    CleanupPending,
    /// Compare the journal to independently verified durable result metadata.
    /// A persisted SUCCEEDED string alone is insufficient.
    VerifyCommittedResult,
}

impl JobRecord {
    pub fn recovery(&self) -> Recovery {
        if terminal(&self.state) || self.state == "EXPORTING" || self.cleanup_confirmed {
            Recovery::VerifyCommittedResult
        } else if self.state == "CLEANUP_PENDING" {
            Recovery::CleanupPending
        } else if self.launch_stage == "INTENT" {
            Recovery::UnlaunchedInterrupted
        } else {
            Recovery::ReconcileOwnedCgroup
        }
    }

    /// Construct only an unlaunched intent. The caller supplies actual approved
    /// profile/staging/policy identities and wall-clock observation, then writes
    /// the returned record durably before acknowledging or changing admission.
    #[allow(clippy::too_many_arguments)]
    pub fn intent(
        instance_id: String,
        job_id: String,
        submission: &Submission,
        stage_manifest_digest: String,
        profile_digest: String,
        executable_digest: String,
        policy_digest: String,
        submitted_at_utc: String,
    ) -> Result<Self> {
        validate_submission_fields(submission)?;
        let canonical = submission.canonical_bytes();
        let canonical_request_sha256 = digest(&canonical);
        let canonical_request = String::from_utf8(canonical)
            .map_err(|_| invalid_record("canonical request is not UTF-8"))?;
        let record = Self {
            v: 1,
            instance_id,
            job_id,
            request_id: submission.request_id.clone(),
            canonical_request_sha256,
            canonical_request,
            state: "QUEUED".into(),
            sequence: 1,
            launch_stage: "INTENT".into(),
            profile_id: submission.profile_id.clone(),
            stage_id: submission.stage_id.clone(),
            stage_manifest_digest,
            profile_digest,
            executable_digest,
            policy_digest,
            submitted_at_utc,
            started_monotonic_ns: None,
            observed_exit: None,
            cancel_reason: None,
            cleanup_confirmed: false,
            result_digest: None,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        if self.v != 1 {
            return Err(StoreError::new(
                ErrorKind::UnsupportedVersion,
                "unsupported job record version",
            ));
        }
        for id in [
            &self.instance_id,
            &self.job_id,
            &self.request_id,
            &self.stage_id,
        ] {
            if !valid_id(id) {
                return Err(invalid_record("invalid record ID"));
            }
        }
        for value in [
            &self.canonical_request_sha256,
            &self.stage_manifest_digest,
            &self.profile_digest,
            &self.executable_digest,
            &self.policy_digest,
        ] {
            if !protocol::valid_sha256(value) {
                return Err(invalid_record("invalid record digest"));
            }
        }
        if self
            .result_digest
            .as_ref()
            .is_some_and(|value| !protocol::valid_sha256(value))
        {
            return Err(invalid_record("invalid result digest"));
        }
        if !protocol::valid_profile_id(&self.profile_id)
            || self.sequence == 0
            || !valid_timestamp(&self.submitted_at_utc)
            || stage_rank(&self.launch_stage).is_none()
        {
            return Err(invalid_record(
                "invalid profile, sequence, timestamp or launch stage",
            ));
        }
        if !matches!(
            self.state.as_str(),
            "QUEUED"
                | "STARTING"
                | "RUNNING"
                | "CANCELLING"
                | "CLEANUP_PENDING"
                | "EXPORTING"
                | "SUCCEEDED"
                | "FAILED"
                | "CANCELLED"
                | "TIMED_OUT"
                | "INTERRUPTED"
        ) {
            return Err(invalid_record("unknown lifecycle state"));
        }
        if self.cancel_reason.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        }) {
            return Err(invalid_record("invalid bounded cancellation reason"));
        }
        if let Some(exit) = self.observed_exit {
            if !matches!(
                (exit.exit_code, exit.signal),
                (Some(0..=255), None) | (None, Some(1..=64))
            ) {
                return Err(invalid_record(
                    "exit observation must be one bounded code or signal",
                ));
            }
        }
        if (terminal(&self.state) || self.state == "EXPORTING") && !self.cleanup_confirmed {
            return Err(invalid_record(
                "terminal/exporting state requires recorded cleanup confirmation",
            ));
        }
        if self.cleanup_confirmed && !terminal(&self.state) && self.state != "EXPORTING" {
            return Err(invalid_record(
                "cleanup confirmation precedes exporting/terminal transition",
            ));
        }
        if self.result_digest.is_some() && !terminal(&self.state) {
            return Err(invalid_record(
                "result digest is only valid in a terminal record",
            ));
        }
        if self.state == "SUCCEEDED"
            && (self.result_digest.is_none()
                || self.observed_exit
                    != Some(ObservedExit {
                        exit_code: Some(0),
                        signal: None,
                    })
                || self.cancel_reason.is_some())
        {
            return Err(invalid_record("success lacks a clean exit/result identity"));
        }
        let stage =
            stage_rank(&self.launch_stage).ok_or_else(|| invalid_record("invalid launch stage"))?;
        if self.state == "QUEUED"
            && (stage != 0
                || self.cleanup_confirmed
                || self.started_monotonic_ns.is_some()
                || self.observed_exit.is_some())
        {
            return Err(invalid_record(
                "queued intent contains launch/cleanup observations",
            ));
        }
        if self.state == "RUNNING" && stage < 5 {
            return Err(invalid_record("running state precedes execution release"));
        }
        if stage == 6 && !self.cleanup_confirmed {
            return Err(invalid_record(
                "cleaned launch stage lacks cleanup confirmation",
            ));
        }
        if self.canonical_request.len() > protocol_header_limit() {
            return Err(invalid_record("canonical request exceeds header limit"));
        }
        let Request::Submit(submission) =
            protocol::parse_request(self.canonical_request.as_bytes())
                .map_err(|_| invalid_record("invalid canonical submit payload"))?
        else {
            return Err(invalid_record(
                "record canonical payload is not a submission",
            ));
        };
        if submission.request_id != self.request_id
            || submission.profile_id != self.profile_id
            || submission.stage_id != self.stage_id
            || submission.canonical_bytes() != self.canonical_request.as_bytes()
            || digest(self.canonical_request.as_bytes()) != self.canonical_request_sha256
        {
            return Err(invalid_record(
                "canonical payload, digest or repeated identity differs",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Instance {
    v: u32,
    instance_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    job_id: String,
    request_id: String,
    canonical_request_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    v: u32,
    instance_id: String,
    entries: Vec<CatalogEntry>,
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

struct Stored {
    record: JobRecord,
    bytes: u64,
    identity: Identity,
}
struct Inventory {
    records: Vec<Stored>,
    bytes: u64,
    catalog: Catalog,
    catalog_bytes: u64,
    catalog_identity: Identity,
}

/// Not Clone/Sync: the state lock and Cell-based failure latch belong to one
/// scheduler owner. Keep Store alive while the IPC endpoint and recovery run.
pub struct Store {
    root: PathBuf,
    directory: OwnedFd,
    records_directory: OwnedFd,
    lock: OwnedFd,
    instance_id: String,
    owner_uid: u32,
    frozen: Cell<bool>,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        Self::open_with_directory_sync(root, |dir| fs::fsync(dir))
    }

    fn open_with_directory_sync(
        root: &Path,
        mut sync: impl FnMut(&OwnedFd) -> rustix::io::Result<()>,
    ) -> Result<Self> {
        let owner_uid = rustix::process::geteuid().as_raw();
        let directory = open_root(root, owner_uid)?;
        if !exists(&directory, LOCK_NAME)? {
            // A missing lock in populated state must not create a second lock
            // inode beside an owner that could still hold the previous inode.
            require_initially_empty(&directory)?;
        }
        let lock = open_lock(&directory, owner_uid)?;
        let instance_exists = exists(&directory, INSTANCE_NAME)?;
        let records_exists = exists(&directory, RECORDS_NAME)?;
        let (instance_id, records_directory) = match (instance_exists, records_exists) {
            (false, false) => {
                require_initially_empty(&directory)?;
                let instance_id = random_id()?;
                operation(
                    fs::mkdirat(&directory, RECORDS_NAME, Mode::RWXU),
                    "cannot create records directory",
                )?;
                let records_directory = open_directory(&directory, RECORDS_NAME, owner_uid)?;
                let catalog = Catalog {
                    v: 1,
                    instance_id: instance_id.clone(),
                    entries: Vec::new(),
                };
                let catalog_bytes = encode_bounded(&catalog)?;
                atomic_write(
                    &records_directory,
                    CATALOG_NAME,
                    &catalog_bytes,
                    None,
                    owner_uid,
                )?;
                let instance = Instance {
                    v: 1,
                    instance_id: instance_id.clone(),
                };
                let bytes = serde_json::to_vec(&instance).map_err(|_| {
                    StoreError::new(ErrorKind::CorruptState, "cannot encode instance metadata")
                })?;
                atomic_write(&directory, INSTANCE_NAME, &bytes, None, owner_uid)?;
                (instance_id, records_directory)
            }
            (true, true) => {
                let (bytes, _) =
                    read_owned_file(&directory, INSTANCE_NAME, MAX_INSTANCE_BYTES, owner_uid)?;
                let value = strict_value(&bytes)?;
                require_fields(&value, &["v", "instance_id"])?;
                check_version(&value)?;
                let instance: Instance = serde_json::from_value(value)
                    .map_err(|_| corrupt("invalid instance metadata"))?;
                if !valid_id(&instance.instance_id) {
                    return Err(corrupt("invalid persistent instance ID"));
                }
                (
                    instance.instance_id,
                    open_directory(&directory, RECORDS_NAME, owner_uid)?,
                )
            }
            _ => {
                return Err(StoreError::new(
                    ErrorKind::MissingData,
                    "instance or records directory is missing; refusing reinitialization",
                ))
            }
        };
        let store = Self {
            root: root.to_path_buf(),
            directory,
            records_directory,
            lock,
            instance_id,
            owner_uid,
            frozen: Cell::new(false),
        };
        store.inventory()?;
        // A failed write may have left a validated rename visible in this OS
        // instance. Establish a fresh durability boundary under the same lock
        // before the scheduler treats any existing journal name as committed.
        operation(
            sync(&store.records_directory),
            "cannot sync recovered records directory",
        )?;
        operation(sync(&store.directory), "cannot sync recovered state root")?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Share the flock's open file description without sharing journal state.
    /// A worker may finish filesystem writes after the scheduler starts exit.
    pub(crate) fn retain_lock(&self) -> io::Result<OwnedFd> {
        rustix::io::fcntl_dupfd_cloexec(&self.lock, 3).map_err(Into::into)
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn is_frozen(&self) -> bool {
        self.frozen.get()
    }
    pub fn new_id(&self) -> Result<String> {
        random_id()
    }

    /// All retained retry identities, including terminal/interrupted records.
    /// Corruption and I/O errors latch mutation off until inspected/reopened.
    pub fn records(&self) -> Result<Vec<JobRecord>> {
        self.checked_inventory().map(|inventory| {
            inventory
                .records
                .into_iter()
                .map(|stored| stored.record)
                .collect()
        })
    }

    /// Exact retry lookup compares the full normalized payload as well as SHA-256.
    /// Some(record) is an existing identity, not authorization to execute again.
    pub fn lookup_request(&self, submission: &Submission) -> Result<Option<JobRecord>> {
        validate_submission_fields(submission)?;
        let canonical = submission.canonical_bytes();
        let Request::Submit(_) = protocol::parse_request(&canonical)
            .map_err(|_| invalid_record("invalid retry submission"))?
        else {
            return Err(invalid_record("retry payload is not a submission"));
        };
        let hash = digest(&canonical);
        let inventory = self.checked_inventory()?;
        for stored in inventory.records {
            if stored.record.request_id == submission.request_id {
                if stored.record.canonical_request_sha256 != hash
                    || stored.record.canonical_request.as_bytes() != canonical.as_slice()
                {
                    return Err(StoreError::new(
                        ErrorKind::Conflict,
                        "request ID already names another payload",
                    ));
                }
                return Ok(Some(stored.record));
            }
        }
        Ok(None)
    }

    /// A successful return follows file fsync, atomic rename, and directory
    /// fsync. A failure after mutation freezes the Store, preserves uncertainty,
    /// and must stop admission. It never retries an execution or claims success.
    pub fn write(&mut self, record: &JobRecord) -> Result<()> {
        self.write_with_directory_sync(record, |dir| fs::fsync(dir))
    }

    fn write_with_directory_sync(
        &mut self,
        record: &JobRecord,
        mut sync: impl FnMut(&OwnedFd) -> rustix::io::Result<()>,
    ) -> Result<()> {
        if self.frozen.get() {
            return Err(StoreError::new(
                ErrorKind::IoUncertain,
                "journal is frozen after an earlier persistence failure",
            ));
        }
        record.validate()?;
        if record.instance_id != self.instance_id {
            return Err(invalid_record("record belongs to another instance"));
        }
        let bytes = encode_record(record)?;
        let mut inventory = self.checked_inventory()?;
        let prior = inventory
            .records
            .iter()
            .find(|stored| stored.record.job_id == record.job_id);
        for stored in &inventory.records {
            if stored.record.request_id == record.request_id
                && stored.record.job_id != record.job_id
            {
                return Err(StoreError::new(
                    ErrorKind::Conflict,
                    "request identity already owns a different job",
                ));
            }
        }
        match prior {
            Some(stored) => validate_update(&stored.record, record)?,
            None => validate_new(record)?,
        }
        if prior.is_none() && inventory.records.len() == MAX_RECORDS {
            return Err(StoreError::new(
                ErrorKind::StorageFull,
                "retained retry record count is full",
            ));
        }
        let previous_bytes = prior.map_or(0, |stored| stored.bytes);
        let prior_identity = prior.map(|stored| stored.identity);
        let new_catalog = if prior.is_none() {
            inventory.catalog.entries.push(CatalogEntry {
                job_id: record.job_id.clone(),
                request_id: record.request_id.clone(),
                canonical_request_sha256: record.canonical_request_sha256.clone(),
            });
            inventory
                .catalog
                .entries
                .sort_by(|left, right| left.job_id.cmp(&right.job_id));
            Some(encode_bounded(&inventory.catalog)?)
        } else {
            None
        };
        let retained = inventory
            .bytes
            .checked_sub(previous_bytes)
            .and_then(|size| size.checked_add(bytes.len() as u64))
            .and_then(|size| {
                if let Some(catalog) = &new_catalog {
                    size.checked_sub(inventory.catalog_bytes)?
                        .checked_add(catalog.len() as u64)
                } else {
                    Some(size)
                }
            })
            .ok_or_else(|| corrupt("metadata accounting overflow"))?;
        if retained > MAX_RETAINED_BYTES {
            return Err(StoreError::new(
                ErrorKind::StorageFull,
                "retained metadata byte budget is full",
            ));
        }
        let name = format!("{}.json", record.job_id);
        let outcome = (|| {
            atomic_write_with_directory_sync(
                &self.records_directory,
                &name,
                &bytes,
                prior_identity,
                self.owner_uid,
                &mut sync,
            )?;
            if let Some(catalog) = new_catalog {
                // New record first, then durable catalog. A crash between them
                // leaves a detectable unindexed intent and refuses replay.
                atomic_write_with_directory_sync(
                    &self.records_directory,
                    CATALOG_NAME,
                    &catalog,
                    Some(inventory.catalog_identity),
                    self.owner_uid,
                    &mut sync,
                )?;
            }
            Ok(())
        })();
        if outcome.is_err() {
            self.frozen.set(true);
        }
        outcome
    }

    fn checked_inventory(&self) -> Result<Inventory> {
        let outcome = self.inventory();
        if outcome.is_err() {
            self.frozen.set(true);
        }
        outcome
    }

    fn inventory(&self) -> Result<Inventory> {
        validate_directory(&self.directory, self.owner_uid)?;
        validate_directory(&self.records_directory, self.owner_uid)?;
        let locked = owned_regular(&self.lock, self.owner_uid, 0)?;
        let named_lock = operation(
            fs::statat(&self.directory, LOCK_NAME, AtFlags::SYMLINK_NOFOLLOW),
            "lock name is unavailable",
        )?;
        if Identity::of(&locked) != Identity::of(&named_lock) {
            return Err(corrupt("held lock file was replaced"));
        }
        let named_records = operation(
            fs::statat(&self.directory, RECORDS_NAME, AtFlags::SYMLINK_NOFOLLOW),
            "records directory name is unavailable",
        )?;
        let opened_records = operation(
            fs::fstat(&self.records_directory),
            "cannot inspect records directory",
        )?;
        if Identity::of(&named_records) != Identity::of(&opened_records) {
            return Err(corrupt("records directory name was replaced"));
        }
        let (instance_bytes, _) = read_owned_file(
            &self.directory,
            INSTANCE_NAME,
            MAX_INSTANCE_BYTES,
            self.owner_uid,
        )?;
        let instance_value = strict_value(&instance_bytes)?;
        require_fields(&instance_value, &["v", "instance_id"])?;
        check_version(&instance_value)?;
        if instance_value["instance_id"].as_str() != Some(self.instance_id.as_str()) {
            return Err(corrupt("persistent instance identity changed"));
        }
        let (catalog_bytes, catalog_stat) = read_owned_file(
            &self.records_directory,
            CATALOG_NAME,
            MAX_RECORD_BYTES,
            self.owner_uid,
        )?;
        let catalog_value = strict_value(&catalog_bytes)?;
        require_fields(&catalog_value, &["v", "instance_id", "entries"])?;
        check_version(&catalog_value)?;
        let catalog: Catalog = serde_json::from_value(catalog_value)
            .map_err(|_| corrupt("invalid typed retry catalog"))?;
        validate_catalog(&catalog, &self.instance_id)?;
        let mut directory = operation(
            Dir::read_from(&self.records_directory),
            "cannot enumerate records directory",
        )?;
        let mut records = Vec::new();
        let mut bytes = catalog_bytes.len() as u64;
        let mut entries = 0;
        let mut jobs = BTreeSet::new();
        let mut requests = BTreeSet::new();
        while let Some(entry) = directory.read() {
            let entry = operation(entry, "cannot read record directory entry")?;
            entries += 1;
            if entries > MAX_RECORDS + 3 {
                return Err(corrupt("record directory entry count exceeds bound"));
            }
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name =
                std::str::from_utf8(name).map_err(|_| corrupt("record name is not UTF-8"))?;
            if name == CATALOG_NAME {
                continue;
            }
            if name.starts_with(".tmp-") {
                return Err(StoreError::new(
                    ErrorKind::IoUncertain,
                    "unfinished metadata temporary requires offline recovery",
                ));
            }
            let Some(job_id) = name.strip_suffix(".json").filter(|value| valid_id(value)) else {
                return Err(corrupt("unknown name in records directory"));
            };
            if records.len() == MAX_RECORDS {
                return Err(corrupt("retained record count exceeds bound"));
            }
            let (data, stat) = read_owned_file(
                &self.records_directory,
                name,
                MAX_RECORD_BYTES,
                self.owner_uid,
            )?;
            bytes = bytes
                .checked_add(data.len() as u64)
                .filter(|size| *size <= MAX_RETAINED_BYTES)
                .ok_or_else(|| corrupt("retained metadata exceeds byte bound"))?;
            let record = decode_record(&data)?;
            if record.instance_id != self.instance_id
                || record.job_id != job_id
                || !jobs.insert(record.job_id.clone())
                || !requests.insert(record.request_id.clone())
            {
                return Err(corrupt(
                    "record ownership/name or retry identity is ambiguous",
                ));
            }
            let Some(expected) = catalog
                .entries
                .iter()
                .find(|entry| entry.job_id == record.job_id)
            else {
                return Err(StoreError::new(
                    ErrorKind::IoUncertain,
                    "unindexed durable intent requires offline reconciliation",
                ));
            };
            if expected.request_id != record.request_id
                || expected.canonical_request_sha256 != record.canonical_request_sha256
            {
                return Err(corrupt("retry catalog and record identities differ"));
            }
            records.push(Stored {
                record,
                bytes: data.len() as u64,
                identity: Identity::of(&stat),
            });
        }
        if records.len() != catalog.entries.len() {
            return Err(StoreError::new(
                ErrorKind::MissingData,
                "cataloged job record is missing; refusing to forget retry identity",
            ));
        }
        records.sort_by(|left, right| left.record.job_id.cmp(&right.record.job_id));
        Ok(Inventory {
            records,
            bytes,
            catalog,
            catalog_bytes: catalog_bytes.len() as u64,
            catalog_identity: Identity::of(&catalog_stat),
        })
    }
}

fn validate_new(record: &JobRecord) -> Result<()> {
    if record.sequence != 1
        || record.state != "QUEUED"
        || record.launch_stage != "INTENT"
        || record.cleanup_confirmed
        || record.started_monotonic_ns.is_some()
        || record.observed_exit.is_some()
        || record.cancel_reason.is_some()
        || record.result_digest.is_some()
    {
        return Err(StoreError::new(
            ErrorKind::InvalidTransition,
            "new record must be an unlaunched sequence1 intent",
        ));
    }
    Ok(())
}

fn validate_update(old: &JobRecord, new: &JobRecord) -> Result<()> {
    if old.v != new.v
        || old.instance_id != new.instance_id
        || old.job_id != new.job_id
        || old.request_id != new.request_id
        || old.canonical_request_sha256 != new.canonical_request_sha256
        || old.canonical_request != new.canonical_request
        || old.profile_id != new.profile_id
        || old.stage_id != new.stage_id
        || old.stage_manifest_digest != new.stage_manifest_digest
        || old.profile_digest != new.profile_digest
        || old.executable_digest != new.executable_digest
        || old.policy_digest != new.policy_digest
        || old.submitted_at_utc != new.submitted_at_utc
    {
        return Err(StoreError::new(
            ErrorKind::Conflict,
            "immutable journal request/job identity differs",
        ));
    }
    let valid_sequence = old.sequence.checked_add(1) == Some(new.sequence);
    let stages = stage_rank(&old.launch_stage).zip(stage_rank(&new.launch_stage));
    let valid_stage = stages.is_some_and(|(before, after)| after >= before);
    if !valid_sequence
        || !valid_stage
        || terminal(&old.state)
        || !valid_state_step(&old.state, &new.state)
        || (old.cleanup_confirmed && !new.cleanup_confirmed)
        || (old.started_monotonic_ns.is_some()
            && old.started_monotonic_ns != new.started_monotonic_ns)
        || (old.observed_exit.is_some() && old.observed_exit != new.observed_exit)
        || (old.cancel_reason.is_some() && old.cancel_reason != new.cancel_reason)
        || (old.result_digest.is_some() && old.result_digest != new.result_digest)
    {
        return Err(StoreError::new(
            ErrorKind::InvalidTransition,
            "nonmonotonic or unsupported journal transition",
        ));
    }
    Ok(())
}

fn valid_state_step(old: &str, new: &str) -> bool {
    old == new
        || matches!(
            (old, new),
            ("QUEUED", "STARTING" | "CANCELLED" | "INTERRUPTED")
                | ("STARTING", "RUNNING" | "CANCELLING" | "CLEANUP_PENDING")
                | ("RUNNING", "CANCELLING" | "CLEANUP_PENDING")
                | ("CANCELLING", "CLEANUP_PENDING")
                | ("CLEANUP_PENDING", "EXPORTING" | "INTERRUPTED")
                | (
                    "EXPORTING",
                    "SUCCEEDED" | "FAILED" | "CANCELLED" | "TIMED_OUT" | "INTERRUPTED"
                )
        )
}

fn terminal(state: &str) -> bool {
    matches!(
        state,
        "SUCCEEDED" | "FAILED" | "CANCELLED" | "TIMED_OUT" | "INTERRUPTED"
    )
}

fn stage_rank(stage: &str) -> Option<u8> {
    Some(match stage {
        "INTENT" => 0,
        "CGROUP_CREATED" => 1,
        "LAUNCHER_SPAWNED" => 2,
        "CGROUP_ATTACHED" => 3,
        "SETUP_READY" => 4,
        "EXEC_RELEASED" => 5,
        "CLEANED" => 6,
        _ => return None,
    })
}

fn decode_record(bytes: &[u8]) -> Result<JobRecord> {
    let value = strict_value(bytes)?;
    require_fields(
        &value,
        &[
            "v",
            "instance_id",
            "job_id",
            "request_id",
            "canonical_request_sha256",
            "canonical_request",
            "state",
            "sequence",
            "launch_stage",
            "profile_id",
            "stage_id",
            "stage_manifest_digest",
            "profile_digest",
            "executable_digest",
            "policy_digest",
            "submitted_at_utc",
            "started_monotonic_ns",
            "observed_exit",
            "cancel_reason",
            "cleanup_confirmed",
            "result_digest",
        ],
    )?;
    check_version(&value)?;
    if !value["observed_exit"].is_null() {
        require_fields(&value["observed_exit"], &["exit_code", "signal"])?;
    }
    let record: JobRecord =
        serde_json::from_value(value).map_err(|_| corrupt("invalid typed job record"))?;
    record.validate().map_err(|error| {
        if error.kind == ErrorKind::UnsupportedVersion {
            error
        } else {
            corrupt("job record violates v1 invariants")
        }
    })?;
    Ok(record)
}

fn encode_record(record: &JobRecord) -> Result<Vec<u8>> {
    encode_bounded(record)
}

fn encode_bounded(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut buffer = BoundedBuffer(Vec::with_capacity(MAX_RECORD_BYTES));
    serde_json::to_writer(&mut buffer, value)
        .map_err(|_| invalid_record("encoded metadata exceeds byte bound"))?;
    Ok(buffer.0)
}

struct BoundedBuffer(Vec<u8>);
impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RECORD_BYTES - self.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "metadata byte bound exceeded",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn strict_value(bytes: &[u8]) -> Result<serde_json::Value> {
    protocol::strict_json(bytes)
        .map_err(|_| corrupt("invalid, duplicate-key or unbounded metadata JSON"))
}

fn require_fields(value: &serde_json::Value, fields: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| corrupt("metadata object required"))?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(corrupt("metadata fields missing or unknown"));
    }
    Ok(())
}

fn check_version(value: &serde_json::Value) -> Result<()> {
    let version = value
        .get("v")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| corrupt("metadata version must be an integer"))?;
    if version != 1 {
        return Err(StoreError::new(
            ErrorKind::UnsupportedVersion,
            "unsupported state format version",
        ));
    }
    Ok(())
}

fn open_root(path: &Path, uid: u32) -> Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(StoreError::new(
            ErrorKind::InvalidRoot,
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
                    return Err(StoreError::new(
                        ErrorKind::InvalidRoot,
                        "state root path is too deep",
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
                return Err(StoreError::new(
                    ErrorKind::InvalidRoot,
                    "state root contains a non-normal component",
                ))
            }
        }
    }
    if count == 0 {
        return Err(StoreError::new(
            ErrorKind::InvalidRoot,
            "filesystem root cannot be a state root",
        ));
    }
    validate_directory(&fd, uid).map_err(|mut error| {
        if error.kind == ErrorKind::CorruptState {
            error.kind = ErrorKind::InvalidRoot;
        }
        error
    })?;
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
        "cannot open metadata directory safely",
    )?;
    validate_directory(&fd, uid)?;
    Ok(fd)
}

fn validate_directory(fd: &OwnedFd, uid: u32) -> Result<()> {
    let stat = operation(fs::fstat(fd), "cannot inspect metadata directory")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(corrupt("metadata directory must be owned mode0700"));
    }
    Ok(())
}

fn open_lock(directory: &OwnedFd, uid: u32) -> Result<OwnedFd> {
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let (fd, created) = match fs::openat2(
        directory,
        LOCK_NAME,
        flags | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
        resolve_flags(),
    ) {
        Ok(fd) => (fd, true),
        Err(rustix::io::Errno::EXIST) => (
            operation(
                fs::openat2(directory, LOCK_NAME, flags, Mode::empty(), resolve_flags()),
                "cannot open existing state lock",
            )?,
            false,
        ),
        Err(error) => return Err(StoreError::io("cannot create state lock", error.into())),
    };
    let stat = owned_regular(&fd, uid, 0)?;
    match fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::AGAIN) => {
            return Err(StoreError::new(
                ErrorKind::Locked,
                "another owner holds the state lock",
            ))
        }
        Err(error) => {
            return Err(StoreError::io(
                "cannot acquire exclusive state lock",
                error.into(),
            ))
        }
    }
    let named = operation(
        fs::statat(directory, LOCK_NAME, AtFlags::SYMLINK_NOFOLLOW),
        "cannot inspect locked name",
    )?;
    if Identity::of(&stat) != Identity::of(&named) {
        return Err(corrupt("state lock name changed while locking"));
    }
    if created {
        operation(fs::fsync(&fd), "cannot sync state lock")?;
        operation(fs::fsync(directory), "cannot sync state lock directory")?;
    }
    Ok(fd)
}

fn exists(directory: &OwnedFd, name: &str) -> Result<bool> {
    match fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(error) => Err(StoreError::io("cannot inspect metadata name", error.into())),
    }
}

fn require_initially_empty(root: &OwnedFd) -> Result<()> {
    let mut directory = operation(
        Dir::read_from(root),
        "cannot inspect uninitialized state root",
    )?;
    let mut entries = 0;
    while let Some(entry) = directory.read() {
        let entry = operation(entry, "cannot inspect initial state entry")?;
        entries += 1;
        let name = entry.file_name().to_bytes();
        if entries > 3 || (name != b"." && name != b".." && name != LOCK_NAME.as_bytes()) {
            return Err(StoreError::new(
                ErrorKind::MissingData,
                "nonempty root lacks lock/instance metadata; refusing reinitialization",
            ));
        }
    }
    Ok(())
}

fn owned_regular(fd: &impl rustix::fd::AsFd, uid: u32, limit: usize) -> Result<fs::Stat> {
    let stat = operation(fs::fstat(fd), "cannot inspect metadata file")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as u64 > limit as u64
    {
        return Err(corrupt(
            "metadata must be a bounded owned mode0600 single-link regular file",
        ));
    }
    Ok(stat)
}

fn read_owned_file(
    directory: &OwnedFd,
    name: &str,
    limit: usize,
    uid: u32,
) -> Result<(Vec<u8>, fs::Stat)> {
    let fd = match fs::openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        resolve_flags(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => {
            return Err(StoreError::new(
                ErrorKind::MissingData,
                "inventoried metadata file is missing",
            ))
        }
        Err(error) => {
            return Err(StoreError::io(
                "cannot open metadata file safely",
                error.into(),
            ))
        }
    };
    let before = owned_regular(&fd, uid, limit)?;
    let mut file = File::from(fd);
    let mut bytes = Vec::with_capacity(limit + 1);
    let mut buffer = [0_u8; 8192];
    loop {
        let available = (limit + 1 - bytes.len()).min(buffer.len());
        if available == 0 {
            return Err(corrupt("metadata grew beyond byte bound"));
        }
        let count = operation(
            file.read(&mut buffer[..available]),
            "cannot read metadata bytes",
        )?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let after = owned_regular(&file, uid, limit)?;
    if Identity::of(&before) != Identity::of(&after)
        || before.st_size != after.st_size
        || bytes.len() as u64 != after.st_size as u64
    {
        return Err(corrupt("metadata changed while reading"));
    }
    Ok((bytes, after))
}

fn atomic_write(
    directory: &OwnedFd,
    final_name: &str,
    bytes: &[u8],
    previous: Option<Identity>,
    uid: u32,
) -> Result<()> {
    atomic_write_with_directory_sync(directory, final_name, bytes, previous, uid, |dir| {
        fs::fsync(dir)
    })
}

fn atomic_write_with_directory_sync(
    directory: &OwnedFd,
    final_name: &str,
    bytes: &[u8],
    previous: Option<Identity>,
    uid: u32,
    sync: impl FnOnce(&OwnedFd) -> rustix::io::Result<()>,
) -> Result<()> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid_record("metadata write exceeds byte bound"));
    }
    let temporary = format!(".tmp-{}.json", random_id()?);
    let fd = operation(
        fs::openat2(
            directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            resolve_flags(),
        ),
        "cannot exclusively create metadata temporary",
    )?;
    owned_regular(&fd, uid, 0)?;
    let mut file = File::from(fd);
    operation(file.write_all(bytes), "cannot write metadata temporary")?;
    operation(file.sync_all(), "cannot sync metadata temporary")?;
    owned_regular(&file, uid, MAX_RECORD_BYTES)?;
    // No destructor removes failed writes. Preserve any partial temporary or
    // uncertain rename for offline recovery rather than hiding the failure.
    if let Some(identity) = previous {
        let current = operation(
            fs::statat(directory, final_name, AtFlags::SYMLINK_NOFOLLOW),
            "cannot inspect metadata being replaced",
        )?;
        if Identity::of(&current) != identity {
            return Err(corrupt("record inode changed before replacement"));
        }
        operation(
            fs::renameat(directory, temporary.as_str(), directory, final_name),
            "cannot atomically replace metadata",
        )?;
    } else {
        operation(
            fs::renameat_with(
                directory,
                temporary.as_str(),
                directory,
                final_name,
                RenameFlags::NOREPLACE,
            ),
            "cannot publish new metadata without replacement",
        )?;
    }
    operation(sync(directory), "cannot sync published metadata directory")?;
    Ok(())
}

fn random_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    let mut offset = 0;
    for _ in 0..32 {
        if offset == bytes.len() {
            break;
        }
        match rand::getrandom(&mut bytes[offset..], GetRandomFlags::NONBLOCK) {
            Ok(0) => break,
            Ok(count) => offset += count,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => {
                return Err(StoreError {
                    kind: ErrorKind::RandomUnavailable,
                    message: "kernel random source is unavailable; refusing generated ID",
                    source: Some(error.into()),
                })
            }
        }
    }
    if offset != bytes.len() {
        return Err(StoreError::new(
            ErrorKind::RandomUnavailable,
            "kernel random source did not fill the bounded ID buffer",
        ));
    }
    let mut encoded = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(encoded)
}

fn valid_id(value: &str) -> bool {
    JobId::parse(value).is_ok()
}
fn digest(bytes: &[u8]) -> String {
    hearthrun_launcher::image::sha256(bytes)
}
fn protocol_header_limit() -> usize {
    hearthrun_domain::MAX_HEADER_BYTES
}

fn validate_catalog(catalog: &Catalog, instance_id: &str) -> Result<()> {
    if catalog.v != 1 || catalog.instance_id != instance_id || catalog.entries.len() > MAX_RECORDS {
        return Err(corrupt(
            "retry catalog version, identity or count is invalid",
        ));
    }
    let mut jobs = BTreeSet::new();
    let mut requests = BTreeSet::new();
    for entry in &catalog.entries {
        if !valid_id(&entry.job_id)
            || !valid_id(&entry.request_id)
            || !protocol::valid_sha256(&entry.canonical_request_sha256)
            || !jobs.insert(&entry.job_id)
            || !requests.insert(&entry.request_id)
        {
            return Err(corrupt(
                "retry catalog contains invalid or duplicate identities",
            ));
        }
    }
    Ok(())
}

fn validate_submission_fields(submission: &Submission) -> Result<()> {
    if !valid_id(&submission.request_id)
        || !valid_id(&submission.stage_id)
        || !protocol::valid_profile_id(&submission.profile_id)
        || !(100..=60_000).contains(&submission.wall_ms)
        || submission.argv.len() > 32
    {
        return Err(invalid_record("submission exceeds canonical field bounds"));
    }
    let mut total = 0_usize;
    for value in &submission.argv {
        total = total
            .checked_add(value.len())
            .filter(|size| *size <= 4096)
            .ok_or_else(|| invalid_record("submission argument bytes exceed bound"))?;
        if value.contains('\0') {
            return Err(invalid_record("submission argument contains NUL"));
        }
    }
    Ok(())
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len())
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes.last() != Some(&b'Z')
    {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate().take(19) {
        if !matches!(index, 4 | 7 | 10 | 13 | 16) && !byte.is_ascii_digit() {
            return false;
        }
    }
    if bytes.len() != 20
        && (bytes.len() < 22
            || bytes[19] != b'.'
            || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        bytes[start..end]
            .iter()
            .fold(0_u32, |value, digit| value * 10 + u32::from(*digit - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    year > 0
        && day > 0
        && day <= days
        && number(11, 13) < 24
        && number(14, 16) < 60
        && number(17, 19) < 60
}

fn operation<T, E: Into<io::Error>>(
    outcome: std::result::Result<T, E>,
    message: &'static str,
) -> Result<T> {
    outcome.map_err(|error| StoreError::io(message, error.into()))
}
fn invalid_record(message: &'static str) -> StoreError {
    StoreError::new(ErrorKind::InvalidRecord, message)
}
fn corrupt(message: &'static str) -> StoreError {
    StoreError::new(ErrorKind::CorruptState, message)
}
