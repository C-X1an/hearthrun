//! Descriptor-owned cgroup-v2 job leases. Linux only; there is no fallback.
//!
//! The caller holds the exclusive supervisor/state lease, persists intent before
//! `create`, and reconciles *every* listed leaf with the journal before admission.
//! Only a successful operational doctor for this boot authorizes launching. The
//! delegated jobs parent is prepared by the operator; this module never enables
//! controllers, moves the supervisor, or changes the surrounding hierarchy.
//!
//! No destructor kills or removes anything. Errors after creation/attachment keep
//! ownership in the journal and require explicit recovery. In particular, a kill
//! request is not emptiness, reaping, or terminal completion.

#![cfg(target_os = "linux")]

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags};
use rustix::process::{self, Pid, WaitId, WaitIdOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path};
use std::sync::Arc;

const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const MAX_CONTROL_BYTES: usize = 16_384;
const MAX_DIRECTORY_ENTRIES: usize = 4096;
const MAX_JOB_LEAVES: usize = 256;
const LIMITS: [(&str, &str); 5] = [
    ("memory.max", "268435456"),
    ("memory.swap.max", "0"),
    ("memory.oom.group", "1"),
    ("pids.max", "32"),
    ("cpu.max", "100000 100000"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn from_stat(stat: &fs::Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

#[derive(Debug)]
struct RootInner {
    fd: OwnedFd,
    identity: Identity,
    owner_uid: u32,
}

/// An already-delegated, process-free domain with cpu/memory/pids enabled.
#[derive(Clone, Debug)]
pub struct JobsRoot(Arc<RootInner>);

/// A single named leaf bound to its opened inode and retained parent.
///
/// Intentionally not Clone: one lifecycle owner configures, places and removes.
#[derive(Debug)]
pub struct JobGroup {
    root: Arc<RootInner>,
    fd: OwnedFd,
    identity: Identity,
    name: String,
    fresh: bool,
    configured: bool,
    placement_attempted: bool,
}

/// Single-use kill authority bound to the held kernel object.
pub struct KillToken(File);

impl KillToken {
    /// Test-only userspace bracket around the identical owned control write.
    /// This is not a kernel syscall-entry timestamp or proof of kill completion.
    #[cfg(feature = "cancellation-timing-verification")]
    pub fn fire_observed(mut self, mut clock: impl FnMut() -> u64) -> (io::Result<()>, u64, u64) {
        let begin = clock();
        let result = write_command(&mut self.0, "1");
        let end = clock();
        (result, begin, end)
    }

    pub fn fire(mut self) -> io::Result<()> {
        write_command(&mut self.0, "1")
    }
}

/// Kernel counters are observations, not a resource-limit outcome by themselves.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResourceCounters {
    pub memory_events: BTreeMap<String, u64>,
    pub pids_events: BTreeMap<String, u64>,
    pub cpu_stat: BTreeMap<String, u64>,
}

impl JobsRoot {
    /// Resolve an absolute *trusted configuration* path without following any
    /// symlink component. Mount transitions during this initial walk are needed
    /// to reach cgroupfs; all subsequent resolution additionally forbids XDEV.
    pub fn open(path: &Path, owner_uid: u32) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("jobs root must be absolute"));
        }
        let mut fd = fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let mut components = 0;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    components += 1;
                    if components > 128 {
                        return Err(invalid("jobs root has too many components"));
                    }
                    fd = fs::openat2(
                        &fd,
                        name,
                        directory_flags(),
                        Mode::empty(),
                        ResolveFlags::BENEATH
                            | ResolveFlags::NO_SYMLINKS
                            | ResolveFlags::NO_MAGICLINKS,
                    )?;
                }
                _ => return Err(invalid("jobs root has a non-normal component")),
            }
        }
        if components == 0 {
            return Err(invalid("filesystem root cannot be the jobs root"));
        }
        let stat = validate_directory(&fd, owner_uid)?;
        let root = Self(Arc::new(RootInner {
            fd,
            identity: Identity::from_stat(&stat),
            owner_uid,
        }));
        root.validate()?;
        Ok(root)
    }

    fn validate(&self) -> io::Result<()> {
        let stat = validate_directory(&self.0.fd, self.0.owner_uid)?;
        if Identity::from_stat(&stat) != self.0.identity {
            return Err(invalid("jobs root identity changed"));
        }
        require_text(&self.0.fd, "cgroup.type", "domain")?;
        require_controllers(&read_control(&self.0.fd, "cgroup.controllers")?)?;
        require_controllers(&read_control(&self.0.fd, "cgroup.subtree_control")?)?;
        if !read_control(&self.0.fd, "cgroup.procs")?.is_empty() {
            return Err(invalid("jobs parent contains processes"));
        }
        Ok(())
    }

    /// Exclusive mkdir. An existing name is always an error, never adopted.
    /// Persist the exact name before this call so a later open/configure error
    /// leaves a journal-identifiable orphan, rather than unrecorded state.
    pub fn create(&self, instance_id: &str, job_id: &str) -> io::Result<JobGroup> {
        self.validate()?;
        let name = job_name(instance_id, job_id)?;
        fs::mkdirat(&self.0.fd, name.as_str(), Mode::RWXU)?;
        self.open_leaf(name, true)
    }

    /// Open only after the caller matched this exact instance/job name to valid
    /// durable journal ownership under its exclusive state lease. The name alone
    /// is not ownership proof. Recovery may kill/remove, but never attach a PID.
    pub fn recover_owned(&self, instance_id: &str, job_id: &str) -> io::Result<JobGroup> {
        self.validate()?;
        self.open_leaf(job_name(instance_id, job_id)?, false)
    }

    fn open_leaf(&self, name: String, fresh: bool) -> io::Result<JobGroup> {
        let fd = open_relative(&self.0.fd, &name, directory_flags())?;
        let stat = validate_directory(&fd, self.0.owner_uid)?;
        if stat.st_dev != self.0.identity.device {
            return Err(invalid("job leaf crosses filesystem"));
        }
        let group = JobGroup {
            root: Arc::clone(&self.0),
            fd,
            identity: Identity::from_stat(&stat),
            name,
            fresh,
            configured: false,
            placement_attempted: false,
        };
        group.validate_leaf()?;
        Ok(group)
    }

    /// Bounded inventory. Unknown directories, symlinks and special entries
    /// refuse reconciliation without mutating any entry. Valid names from all
    /// instances are returned; the caller must reject any journal mismatch.
    pub fn list_job_names(&self) -> io::Result<Vec<String>> {
        self.validate()?;
        let mut directory = Dir::read_from(&self.0.fd)?;
        let mut names = Vec::new();
        let mut entries = 0;
        while let Some(entry) = directory.read() {
            let entry = entry?;
            entries += 1;
            if entries > MAX_DIRECTORY_ENTRIES {
                return Err(invalid("jobs root inventory exceeds bound"));
            }
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name =
                std::str::from_utf8(bytes).map_err(|_| invalid("non-UTF-8 jobs root entry"))?;
            let stat = fs::statat(&self.0.fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    if !valid_job_name(name) {
                        return Err(invalid("unrecognized directory in jobs root"));
                    }
                    if names.len() == MAX_JOB_LEAVES {
                        return Err(invalid("too many job leaves"));
                    }
                    names.push(name.to_owned());
                }
                FileType::RegularFile => {}
                _ => return Err(invalid("unexpected object in jobs root")),
            }
        }
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("ambiguous jobs root inventory"));
        }
        Ok(names)
    }
}

impl JobGroup {
    pub fn name(&self) -> &str {
        &self.name
    }

    fn validate_leaf(&self) -> io::Result<()> {
        JobsRoot(Arc::clone(&self.root)).validate()?;
        let stat = validate_directory(&self.fd, self.root.owner_uid)?;
        if Identity::from_stat(&stat) != self.identity {
            return Err(invalid("job descriptor identity changed"));
        }
        // Confirm the parent name still identifies the exact owned inode. The
        // exclusive supervisor and protected parent prevent a guest rename race;
        // hostile same-UID host mutation is outside the documented trust model.
        let named = open_relative(&self.root.fd, &self.name, directory_flags())?;
        if Identity::from_stat(&fs::fstat(named)?) != self.identity {
            return Err(invalid("job name no longer identifies owned inode"));
        }
        require_text(&self.fd, "cgroup.type", "domain")?;
        require_text(&self.fd, "cgroup.subtree_control", "")?;
        let stat = parse_counters(&read_control(&self.fd, "cgroup.stat")?)?;
        if stat.get("nr_descendants") != Some(&0) || stat.get("nr_dying_descendants") != Some(&0) {
            return Err(invalid("job is not a childless leaf"));
        }
        Ok(())
    }

    /// Configure exact product limits only on a newly created empty leaf. A
    /// failed partial configuration must never release the launcher barrier.
    /// Writing cgroup.kill while empty also probes the mandatory kill interface.
    pub fn configure(&mut self) -> io::Result<()> {
        if !self.fresh || self.placement_attempted {
            return Err(invalid("cannot configure a recovered or used leaf"));
        }
        self.configured = false;
        self.validate_leaf()?;
        self.require_empty()?;
        for (file, value) in LIMITS {
            write_control(&self.fd, file, value)?;
        }
        self.verify_limits()?;
        write_control(&self.fd, "cgroup.kill", "1")?;
        self.require_empty()?;
        let counters = self.counters()?;
        if counters.memory_events.values().any(|value| *value != 0)
            || counters.pids_events.values().any(|value| *value != 0)
        {
            return Err(invalid("fresh job already has limit events"));
        }
        self.configured = true;
        Ok(())
    }

    pub fn verify_limits(&self) -> io::Result<()> {
        self.validate_leaf()?;
        for (file, expected) in LIMITS {
            require_text(&self.fd, file, expected)?;
        }
        // Merely opening for writing does not signal or change any process.
        let _kill = control_file(&self.fd, "cgroup.kill", OFlags::WRONLY)?;
        Ok(())
    }

    /// Place only the caller's live, immediate, unreaped launcher child.
    ///
    /// Caller contract: retain its Child/pidfd; no competing reaper or SIGCHLD
    /// auto-reap; launcher is single-threaded, blocked before its first fork and
    /// cannot execute guest instructions until the later authenticated gate.
    /// waitid verifies child relationship without consuming exit status. It is
    /// not a substitute for retaining that child identity across the handshake.
    /// Any error after the write may have attached the child: kill this group,
    /// reap the child, then observe emptiness; never release the exec gate.
    pub fn place_launcher(&mut self, launcher_pid: u32) -> io::Result<()> {
        if !self.fresh || !self.configured || self.placement_attempted {
            return Err(invalid("job is not ready for first launcher placement"));
        }
        let pid = i32::try_from(launcher_pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or_else(|| invalid("invalid launcher PID"))?;
        self.verify_limits()?;
        self.require_empty()?;
        require_live_child(pid)?;
        self.placement_attempted = true;
        write_control(&self.fd, "cgroup.procs", &launcher_pid.to_string())?;
        require_live_child(pid)?;
        let procs = read_control(&self.fd, "cgroup.procs")?;
        if parse_pid_list(&procs)? != vec![launcher_pid]
            || read_decimal(&self.fd, "pids.current")? != 1
            || !self.populated()?
        {
            return Err(invalid("launcher placement or process count mismatch"));
        }
        self.verify_limits()?;
        Ok(())
    }

    /// Exact populated state from a fresh bounded read of actual cgroup.events.
    /// Unknown/duplicate keys, missing keys and invalid values refuse cleanup.
    pub fn populated(&self) -> io::Result<bool> {
        self.validate_leaf()?;
        parse_events(&read_control(&self.fd, "cgroup.events")?)
    }

    /// Check a live sender's membership before granting exec. The authenticated
    /// control socket supplies the PID and the launcher holds the sender alive.
    pub fn contains_process(&self, pid: u32) -> io::Result<bool> {
        self.validate_leaf()?;
        Ok(parse_pid_list(&read_control(&self.fd, "cgroup.procs")?)?.contains(&pid))
    }

    /// The kernel exposes these cleanup observations separately. A transition
    /// can leave one outstanding after `populated` first becomes zero.
    pub fn empty_for_removal(&self) -> io::Result<bool> {
        Ok(!self.populated()?
            && read_decimal(&self.fd, "pids.current")? == 0
            && read_control(&self.fd, "cgroup.procs")?.is_empty())
    }

    fn require_empty(&self) -> io::Result<()> {
        if !self.empty_for_removal()? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "job cgroup remains populated; cleanup pending",
            ));
        }
        Ok(())
    }

    /// Request all-descendant kill; never signal a persisted numeric PID.
    pub fn kill(&self) -> io::Result<()> {
        self.kill_token()?.fire()
    }

    pub fn kill_token(&self) -> io::Result<KillToken> {
        self.validate_leaf()?;
        Ok(KillToken(control_file(
            &self.fd,
            "cgroup.kill",
            OFlags::WRONLY,
        )?))
    }

    /// Only remove the exact owned, actually empty leaf. The caller separately
    /// proves launcher reaping and publication before claiming terminal status.
    /// Returns false while the leaf is nonempty or the kernel defers removal.
    /// Ownership and observation errors remain failures.
    pub fn try_remove_empty(&mut self) -> io::Result<bool> {
        self.validate_leaf()?;
        if !self.empty_for_removal()? {
            return Ok(false);
        }
        match fs::unlinkat(&self.root.fd, self.name.as_str(), AtFlags::REMOVEDIR) {
            Ok(()) => {}
            Err(rustix::io::Errno::BUSY) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        self.configured = false;
        self.fresh = false;
        Ok(true)
    }

    pub fn counters(&self) -> io::Result<ResourceCounters> {
        self.validate_leaf()?;
        let memory_events = parse_counters(&read_control(&self.fd, "memory.events")?)?;
        let pids_events = parse_counters(&read_control(&self.fd, "pids.events")?)?;
        let cpu_stat = parse_counters(&read_control(&self.fd, "cpu.stat")?)?;
        for required in ["low", "high", "max", "oom", "oom_kill", "oom_group_kill"] {
            if !memory_events.contains_key(required) {
                return Err(invalid("missing mandatory memory event counter"));
            }
        }
        if !pids_events.contains_key("max") || !cpu_stat.contains_key("usage_usec") {
            return Err(invalid("missing mandatory pids/cpu counter"));
        }
        Ok(ResourceCounters {
            memory_events,
            pids_events,
            cpu_stat,
        })
    }
}

fn require_live_child(pid: Pid) -> io::Result<()> {
    if process::waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )?
    .is_some()
    {
        return Err(invalid("launcher exited before placement completed"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn open_relative(fd: &impl AsFd, name: &str, flags: OFlags) -> io::Result<OwnedFd> {
    // All callers supply a single reviewed control name or a validated job name.
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(invalid("invalid descriptor-relative control name"));
    }
    Ok(fs::openat2(
        fd,
        name,
        flags | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?)
}

fn validate_directory(fd: &impl AsFd, owner_uid: u32) -> io::Result<fs::Stat> {
    let stat = fs::fstat(fd)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != owner_uid
        || stat.st_mode & 0o022 != 0
        || fs::fstatfs(fd)?.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err(invalid(
            "cgroup directory type, owner, mode or filesystem mismatch",
        ));
    }
    Ok(stat)
}

fn control_file(fd: &impl AsFd, name: &str, flags: OFlags) -> io::Result<File> {
    let opened = open_relative(fd, name, flags | OFlags::CLOEXEC)?;
    let stat = fs::fstat(&opened)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_dev != fs::fstat(fd)?.st_dev
    {
        return Err(invalid(
            "cgroup control is not a regular file on owned filesystem",
        ));
    }
    Ok(File::from(opened))
}

fn read_control(fd: &impl AsFd, name: &str) -> io::Result<String> {
    let file = control_file(fd, name, OFlags::RDONLY)?;
    let mut bytes = Vec::new();
    file.take((MAX_CONTROL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(invalid("cgroup control exceeds read bound"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("cgroup control is not UTF-8"))
}

fn write_control(fd: &impl AsFd, name: &str, value: &str) -> io::Result<()> {
    if value.is_empty() || value.len() > 128 || value.contains(['\n', '\0']) {
        return Err(invalid("invalid cgroup control write"));
    }
    write_command(&mut control_file(fd, name, OFlags::WRONLY)?, value)
}

fn write_command(file: &mut File, value: &str) -> io::Result<()> {
    // A cgroup control write is one kernel transaction. Do not retry a short
    // write as another command, and do not use truncate/create on pseudo-files.
    if file.write(value.as_bytes())? != value.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short cgroup control write",
        ));
    }
    Ok(())
}

fn require_text(fd: &impl AsFd, name: &str, expected: &str) -> io::Result<()> {
    let actual = read_control(fd, name)?;
    if actual.strip_suffix('\n').unwrap_or(&actual) != expected {
        return Err(invalid("cgroup control value mismatch"));
    }
    Ok(())
}

fn require_controllers(text: &str) -> io::Result<()> {
    let tokens: Vec<_> = text.split_ascii_whitespace().collect();
    let unique: BTreeSet<_> = tokens.iter().copied().collect();
    if tokens.len() != unique.len()
        || !["cpu", "memory", "pids"]
            .iter()
            .all(|name| unique.contains(name))
    {
        return Err(invalid(
            "mandatory cgroup controllers are unavailable or disabled",
        ));
    }
    Ok(())
}

fn read_decimal(fd: &impl AsFd, name: &str) -> io::Result<u64> {
    let text = read_control(fd, name)?;
    decimal(text.strip_suffix('\n').unwrap_or(&text))
}

fn decimal(text: &str) -> io::Result<u64> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("invalid cgroup unsigned decimal"));
    }
    text.parse().map_err(|_| invalid("cgroup counter overflow"))
}

fn parse_counters(text: &str) -> io::Result<BTreeMap<String, u64>> {
    if text.is_empty() || !text.ends_with('\n') || text.len() > MAX_CONTROL_BYTES {
        return Err(invalid("missing or unterminated cgroup counters"));
    }
    let mut counters = BTreeMap::new();
    for line in text.strip_suffix('\n').unwrap_or(text).split('\n') {
        let (key, value) = line
            .split_once(' ')
            .ok_or_else(|| invalid("malformed cgroup counter"))?;
        if key.is_empty()
            || (key != "core_sched.force_idle_usec"
                && !key
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'))
            || counters.insert(key.to_owned(), decimal(value)?).is_some()
        {
            return Err(invalid("duplicate or invalid cgroup counter key"));
        }
    }
    Ok(counters)
}

fn parse_events(text: &str) -> io::Result<bool> {
    let counters = parse_counters(text)?;
    if counters.len() != 2 || !matches!(counters.get("frozen"), Some(0 | 1)) {
        return Err(invalid("unknown or malformed cgroup events"));
    }
    match counters.get("populated") {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(invalid("missing or invalid populated event")),
    }
}

fn parse_pid_list(text: &str) -> io::Result<Vec<u32>> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if !text.ends_with('\n') {
        return Err(invalid("unterminated cgroup process list"));
    }
    let mut pids = Vec::new();
    for line in text.strip_suffix('\n').unwrap_or(text).split('\n') {
        let pid = u32::try_from(decimal(line)?).map_err(|_| invalid("invalid cgroup PID"))?;
        if pid == 0 || pids.contains(&pid) || pids.len() >= 32 {
            return Err(invalid("ambiguous or excessive cgroup process list"));
        }
        pids.push(pid);
    }
    Ok(pids)
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn job_name(instance_id: &str, job_id: &str) -> io::Result<String> {
    if !valid_id(instance_id) || !valid_id(job_id) {
        return Err(invalid(
            "instance and job IDs must be 32 lowercase hex bytes",
        ));
    }
    Ok(format!("hr-{instance_id}-{job_id}"))
}

fn valid_job_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("hr-") else {
        return false;
    };
    let Some((instance, job)) = rest.split_once('-') else {
        return false;
    };
    valid_id(instance) && valid_id(job)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_kernel_core_scheduling_counter_and_refuses_duplicates() {
        let counters = parse_counters("usage_usec 298\ncore_sched.force_idle_usec 42\n").unwrap();
        assert_eq!(counters.get("core_sched.force_idle_usec"), Some(&42));
        assert!(parse_counters(
            "usage_usec 0\ncore_sched.force_idle_usec 42\ncore_sched.force_idle_usec 43\n"
        )
        .is_err());
        assert!(parse_counters("usage_usec 0\ncore_sched.force_idle_usec +42\n").is_err());
    }

    #[test]
    fn events_refuse_ambiguous_cleanup_observations() {
        assert!(!parse_events("populated 0\nfrozen 0\n").unwrap());
        assert!(parse_events("frozen 1\npopulated 1\n").unwrap());
        for malformed in [
            "",
            "populated 0\n",
            "populated 0\nfrozen 0",
            "populated 2\nfrozen 0\n",
            "populated 0\nfrozen 0\npopulated 1\n",
            "populated 0\nfrozen 0\nfuture 0\n",
            "populated 0\nfrozen 3\n",
            "populated +0\nfrozen 0\n",
            "populated 0 \nfrozen 0\n",
            "populated 00\nfrozen 0\n",
            "populated 0\nfrozen 01\n",
        ] {
            assert!(parse_events(malformed).is_err());
        }
    }

    #[test]
    fn identities_and_counters_reject_path_and_number_ambiguity() {
        assert!(job_name(&"a".repeat(32), &"0".repeat(32)).is_ok());
        for invalid in ["../x", "", "A", "ffffffffffffffffffffffffffffffff/"] {
            assert!(job_name(invalid, &"0".repeat(32)).is_err());
        }
        assert!(parse_counters("max 1\nmax 2\n").is_err());
        assert!(parse_counters("max 18446744073709551616\n").is_err());
        assert!(parse_pid_list("4\n4\n").is_err());
        assert!(parse_pid_list("0\n").is_err());
    }
}
