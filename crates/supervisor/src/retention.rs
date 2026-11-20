//! Retained result budgets and crash-safe eviction markers.
use crate::artifacts::{CommittedResult, Publisher, MAX_ARTIFACT_BYTES, MAX_STREAM_BYTES};
use crate::staging::{create_private_dir, private_dir, read_owned, write_new};
use crate::store::JobRecord;
use hearthrun_domain::{protocol::valid_sha256, JobId};
use rustix::fd::AsFd;
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags};
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

const MAX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RESULTS: usize = 100;
const RESERVATION: u64 = MAX_ARTIFACT_BYTES + 2 * MAX_STREAM_BYTES as u64 + 65_536;
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

fn bad(detail: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

fn open_subdir(parent: &impl AsFd, name: &str) -> io::Result<rustix::fd::OwnedFd> {
    let fd = fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE,
    )?;
    let stat = fs::fstat(&fd)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o777 != 0o700 {
        return Err(bad("untrusted retention directory"));
    }
    Ok(fd)
}

fn names(parent: &impl AsFd, remaining: &mut usize) -> io::Result<Vec<String>> {
    let mut dir = Dir::read_from(parent)?;
    let mut list = Vec::new();
    while let Some(entry) = dir.read() {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| bad("non-UTF8 result path"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| bad("result directory exceeds inventory budget"))?;
        list.push(name.to_owned());
    }
    Ok(list)
}

fn remove_tree(
    parent: &impl AsFd,
    name: &str,
    depth: usize,
    remaining: &mut usize,
) -> io::Result<()> {
    if depth > 12 {
        return Err(bad("result depth exceeds bounds"));
    }
    let dir = open_subdir(parent, name)?;
    for entry in names(&dir, remaining)? {
        let stat = fs::statat(&dir, &entry, AtFlags::SYMLINK_NOFOLLOW)?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => remove_tree(&dir, &entry, depth + 1, remaining)?,
            FileType::RegularFile if stat.st_nlink == 1 => {
                fs::unlinkat(&dir, &entry, AtFlags::empty())?
            }
            _ => return Err(bad("unrecognized entry while removing owned result")),
        }
    }
    fs::unlinkat(parent, name, AtFlags::REMOVEDIR)?;
    fs::fsync(parent)?;
    Ok(())
}

struct Footprint {
    bytes: u64,
    committed: SystemTime,
    readers: Arc<()>,
}

pub struct Retention {
    root: PathBuf,
    kept: BTreeMap<String, Footprint>,
}

impl Retention {
    pub fn open(state: &Path) -> io::Result<Self> {
        let root = state.join("evicted");
        create_private_dir(&root)?;
        Ok(Self {
            root,
            kept: BTreeMap::new(),
        })
    }

    pub fn evicted(&self, id: &str, digest: &str) -> io::Result<bool> {
        JobId::parse(id).map_err(|_| bad("invalid result ID"))?;
        match read_owned(&self.root.join(id), 64) {
            Ok(bytes) if bytes == digest.as_bytes() && valid_sha256(digest) => Ok(true),
            Ok(_) => Err(bad("result eviction marker is corrupt")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn remember(&mut self, item: &CommittedResult) -> io::Result<()> {
        let bytes = item.stdout_size
            + item.stderr_size
            + item
                .artifacts
                .iter()
                .map(|artifact| artifact.size_bytes)
                .sum::<u64>()
            + serde_json::to_vec(&item.metadata)?.len() as u64;
        self.kept.insert(
            item.job_id.clone(),
            Footprint {
                bytes,
                committed: SystemTime::now(),
                readers: Arc::new(()),
            },
        );
        Ok(())
    }

    pub fn pin(&self, id: &str) -> io::Result<Arc<()>> {
        let footprint = self
            .kept
            .get(id)
            .ok_or_else(|| bad("retained result is absent from accounting"))?;
        Ok(Arc::clone(&footprint.readers))
    }

    pub fn discard_uncommitted(&self, publisher: &Publisher, job: &JobRecord) -> io::Result<()> {
        JobId::parse(&job.job_id).map_err(|_| bad("invalid unpublished result ID"))?;
        if job.state != "EXPORTING" || !job.cleanup_confirmed || job.result_digest.is_some() {
            return Err(bad("published or live result cannot be discarded"));
        }
        let parent = publisher.result_parent().map_err(io::Error::other)?;
        remove_tree(&parent, &job.job_id, 0, &mut 2048)
    }

    pub fn reconcile(
        &mut self,
        publisher: &Publisher,
        records: &BTreeMap<String, JobRecord>,
    ) -> io::Result<()> {
        let parent = publisher.result_parent().map_err(io::Error::other)?;
        let entries = names(&parent, &mut 512)?;
        let mut stale = Vec::new();
        for name in entries {
            let id = if let Some(suffix) = name.strip_prefix(".tmp-") {
                let (id, nonce) = suffix
                    .split_once('-')
                    .ok_or_else(|| bad("unrecognized result stage"))?;
                JobId::parse(nonce).map_err(|_| bad("unrecognized result stage nonce"))?;
                id
            } else {
                name.as_str()
            };
            JobId::parse(id).map_err(|_| bad("unrecognized retained result"))?;
            let record = records
                .get(id)
                .ok_or_else(|| bad("result has no journal owner"))?;
            open_subdir(&parent, &name)?;
            if id != name
                || record.result_digest.is_none()
                || self.evicted(id, record.result_digest.as_deref().unwrap_or_default())?
            {
                stale.push(name);
            }
        }
        for record in records.values() {
            if let Some(digest) = &record.result_digest {
                if !self.evicted(&record.job_id, digest)? {
                    let result = publisher
                        .read_result(&record.job_id, digest)
                        .map_err(io::Error::other)?;
                    if result.metadata["status"] != persistent_outcome(&record.state)
                        || result.metadata["policy_sha256"] != record.policy_digest
                    {
                        return Err(bad("result does not match terminal journal"));
                    }
                    self.remember(&result)?;
                    // Linux mtime orders commits across supervisor restarts.
                    let dir = File::from(open_subdir(&parent, &result.job_id)?);
                    self.kept
                        .get_mut(&result.job_id)
                        .expect("record just inserted")
                        .committed = dir.metadata()?.modified()?;
                }
            }
        }
        for name in stale {
            remove_tree(&parent, &name, 0, &mut 2048)?;
        }
        Ok(())
    }

    pub fn make_room(
        &mut self,
        publisher: &Publisher,
        records: &BTreeMap<String, JobRecord>,
        reservations: usize,
    ) -> io::Result<()> {
        let parent = publisher.result_parent().map_err(io::Error::other)?;
        while self.kept.len() + reservations > MAX_RESULTS
            || self.kept.values().map(|value| value.bytes).sum::<u64>()
                + reservations as u64 * RESERVATION
                > MAX_BYTES
        {
            let id = self
                .kept
                .iter()
                .min_by_key(|(_, value)| value.committed)
                .filter(|(_, value)| Arc::strong_count(&value.readers) == 1)
                .map(|(id, _)| id.clone())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "result storage is temporarily reserved",
                    )
                })?;
            let digest = records
                .get(&id)
                .and_then(|record| record.result_digest.as_ref())
                .ok_or_else(|| bad("result eviction has no committed journal owner"))?;
            if !self.evicted(&id, digest)? {
                write_new(&self.root.join(&id), digest.as_bytes())?;
                File::from(private_dir(&self.root)?).sync_all()?;
            }
            remove_tree(&parent, &id, 0, &mut 2048)?;
            self.kept.remove(&id);
        }
        Ok(())
    }
}

pub fn persistent_outcome(state: &str) -> &str {
    if state == "TIMED_OUT" {
        "FAILED"
    } else {
        state
    }
}
