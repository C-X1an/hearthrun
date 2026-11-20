//! Owner-only staging with bounded concurrent uploads and immutable launch inputs.
use crate::lifecycle::nonce;
use crate::server::{ErrorCode, ErrorReply, Incoming, Reply};
use hearthrun_domain::{
    protocol::{self, InputFile, Request},
    JobId,
};
use hearthrun_launcher::image::{lower_hex, sha256};
use rustix::fd::OwnedFd;
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

const STAGING_BYTES: u64 = 128 * 1024 * 1024;
const STAGING_COUNT: usize = 256;
const EXPIRY: u64 = 3600;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn now() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}

pub fn private_dir(path: &Path) -> io::Result<OwnedFd> {
    let fd = fs::openat2(
        fs::CWD,
        path,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    let stat = fs::fstat(&fd)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o777 != 0o700 {
        return Err(invalid("expected an owner-only directory"));
    }
    Ok(fd)
}

pub fn create_private_dir(path: &Path) -> io::Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => {
            File::from(private_dir(path)?).sync_all()?;
            if let Some(parent) = path.parent() {
                File::from(private_dir(parent)?).sync_all()?;
            }
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            private_dir(path)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

pub fn read_owned(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let fd = fs::openat2(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    let file = File::from(fd);
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > max
    {
        return Err(invalid("untrusted or oversized state file"));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != meta.len() {
        return Err(invalid("state file changed during read"));
    }
    Ok(bytes)
}

pub fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    v: u32,
    stage_id: String,
    created: u64,
    files: Vec<Entry>,
    manifest_digest: String,
}

impl Manifest {
    fn total(&self) -> io::Result<u64> {
        let header = serde_json::to_vec(&json!({"v":1,"op":"stage","files":self.files}))?;
        if self.v != 1
            || self.manifest_digest != sha256(&serde_json::to_vec(&self.files)?)
            || !matches!(protocol::parse_request(&header), Ok(Request::Stage(_)))
        {
            return Err(invalid("invalid staged manifest"));
        }
        Ok(self.files.iter().map(|file| file.size).sum())
    }
}

#[derive(Default)]
struct Catalog {
    uploads: usize,
    bytes: u64,
    entries: HashMap<String, Manifest>,
    uncertain: bool,
}

pub struct Stages {
    root: PathBuf,
    catalog: Mutex<Catalog>,
}

impl Stages {
    pub fn open(state: &Path) -> io::Result<Self> {
        let root = state.join("stages");
        create_private_dir(&root)?;
        let mut catalog = Catalog::default();
        for (count, entry) in std::fs::read_dir(&root)?.enumerate() {
            if count >= STAGING_COUNT + 8 {
                return Err(invalid("stage inventory exceeds bounds"));
            }
            let entry = entry?;
            let name = entry.file_name();
            let id = name
                .to_str()
                .ok_or_else(|| invalid("invalid stage directory name"))?;
            if id
                .strip_prefix(".upload-")
                .is_some_and(|id| JobId::parse(id).is_ok())
            {
                private_dir(&entry.path())?;
                std::fs::remove_dir_all(entry.path())?;
                continue;
            }
            JobId::parse(id).map_err(|_| invalid("invalid stage directory name"))?;
            private_dir(&entry.path())?;
            private_dir(&entry.path().join("tree"))?;
            let bytes = read_owned(&entry.path().join("manifest.json"), 65_536)?;
            let manifest: Manifest =
                serde_json::from_value(protocol::strict_json(&bytes).map_err(io::Error::other)?)?;
            if manifest.stage_id != id {
                return Err(invalid("stage identity mismatch"));
            }
            catalog.bytes += manifest.total()?;
            if catalog.bytes > STAGING_BYTES || catalog.entries.len() >= STAGING_COUNT {
                return Err(invalid("stage inventory exceeds budget"));
            }
            catalog.entries.insert(id.to_owned(), manifest);
        }
        File::from(private_dir(&root)?).sync_all()?;
        Ok(Self {
            root,
            catalog: Mutex::new(catalog),
        })
    }

    fn catalog(&self) -> io::Result<MutexGuard<'_, Catalog>> {
        self.catalog
            .lock()
            .map_err(|_| invalid("staging state unavailable"))
    }

    pub fn open_tree(&self, id: &str) -> io::Result<Option<(OwnedFd, String)>> {
        JobId::parse(id).map_err(|_| invalid("invalid stage ID"))?;
        let catalog = self.catalog()?;
        let Some(metadata) = catalog.entries.get(id) else {
            return Ok(None);
        };
        let dir = self.root.join(id);
        for entry in &metadata.files {
            let bytes = read_owned(&dir.join("tree").join(&entry.path), entry.size)?;
            if bytes.len() as u64 != entry.size || sha256(&bytes) != entry.sha256 {
                return Err(invalid("published staged bytes no longer match manifest"));
            }
        }
        Ok(Some((
            private_dir(&dir.join("tree"))?,
            metadata.manifest_digest.clone(),
        )))
    }

    pub fn prune(&self, pinned: &HashSet<String>) -> io::Result<()> {
        let mut catalog = self.catalog()?;
        let clock = now()?;
        let stale: Vec<_> = catalog
            .entries
            .iter()
            .filter(|(id, meta)| {
                !pinned.contains(*id) && clock.saturating_sub(meta.created) >= EXPIRY
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            std::fs::remove_dir_all(self.root.join(&id))?;
            File::from(private_dir(&self.root)?).sync_all()?;
            let entry = catalog
                .entries
                .remove(&id)
                .expect("stale stage is registered");
            catalog.bytes -= entry.total()?;
        }
        Ok(())
    }

    pub fn receive(&self, incoming: Incoming) -> io::Result<()> {
        let Request::Stage(files) = incoming.request() else {
            return Err(invalid("stage upload received the wrong operation"));
        };
        let files = files.clone();
        let bytes = files.iter().map(|f| f.size).sum::<u64>();
        let id = lower_hex(&nonce()?);
        let temp = self.root.join(format!(".upload-{id}"));
        {
            let mut catalog = self.catalog()?;
            if catalog.uncertain
                || catalog.bytes + bytes > STAGING_BYTES
                || catalog.entries.len() + catalog.uploads >= STAGING_COUNT
            {
                drop(catalog);
                return incoming.reject(ErrorReply::new(
                    ErrorCode::StorageFull,
                    "staging budget is unavailable",
                ));
            }
            std::fs::create_dir(&temp)?;
            catalog.uploads += 1;
            catalog.bytes += bytes;
        }
        let mut published = false;
        let result = self.finish_upload(incoming, files, &id, &temp, &mut published);
        let mut catalog = self.catalog()?;
        catalog.uploads -= 1;
        if !published {
            if let Err(error) = std::fs::remove_dir_all(&temp) {
                catalog.uncertain = true;
                return Err(error);
            }
            catalog.bytes -= bytes;
        } else if !catalog.entries.contains_key(&id) {
            catalog.uncertain = true;
        }
        result
    }

    fn finish_upload(
        &self,
        mut incoming: Incoming,
        files: Vec<InputFile>,
        id: &str,
        temp: &Path,
        published: &mut bool,
    ) -> io::Result<()> {
        let tree = temp.join("tree");
        std::fs::create_dir(&tree)?;
        let mut directories = BTreeSet::new();
        directories.insert(tree.clone());
        let mut manifest = Vec::with_capacity(files.len());
        for file in files {
            let target = tree.join(&file.path);
            let parent = target.parent().expect("logical path has stage parent");
            std::fs::create_dir_all(parent)?;
            for path in parent.ancestors().take_while(|path| *path != tree) {
                directories.insert(path.to_path_buf());
            }
            let mut output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&target)?;
            let mut hasher = Sha256::new();
            let mut left = file.size;
            let mut buffer = [0; 16384];
            while left != 0 {
                let count = left.min(buffer.len() as u64) as usize;
                if incoming.payload().read_exact(&mut buffer[..count]).is_err() {
                    return incoming.reject(ErrorReply::new(
                        ErrorCode::BadFrame,
                        "staging body ended before the declared size",
                    ));
                }
                hasher.update(&buffer[..count]);
                output.write_all(&buffer[..count])?;
                left -= count as u64;
            }
            if lower_hex(&hasher.finalize()) != file.sha256 {
                return incoming.reject(ErrorReply::new(
                    ErrorCode::StageDigestMismatch,
                    "staged file digest differs from declaration",
                ));
            }
            output.sync_all()?;
            manifest.push(Entry {
                path: file.path,
                size: file.size,
                sha256: file.sha256,
            });
        }
        let request = match incoming.finish() {
            Ok(request) => request,
            Err(failure) => return failure.respond(),
        };
        let result = (|| {
            let digest = sha256(&serde_json::to_vec(&manifest)?);
            let manifest = Manifest {
                v: 1,
                stage_id: id.to_owned(),
                created: now()?,
                files: manifest,
                manifest_digest: digest.clone(),
            };
            write_new(&temp.join("manifest.json"), &serde_json::to_vec(&manifest)?)?;
            for directory in directories.iter().rev() {
                File::from(private_dir(directory)?).sync_all()?;
            }
            File::from(private_dir(temp)?).sync_all()?;
            let mut catalog = self.catalog()?;
            let root = private_dir(&self.root)?;
            let name = temp.file_name().expect("upload dir has a basename");
            fs::renameat_with(&root, name, &root, id, fs::RenameFlags::NOREPLACE)?;
            *published = true;
            File::from(root).sync_all()?;
            catalog.entries.insert(id.to_owned(), manifest);
            Ok::<_, io::Error>(digest)
        })();
        match result {
            Ok(digest) => request.respond(Reply::Success(
                json!({"stage_id":id,"manifest_digest":digest}),
            )),
            Err(error) => {
                eprintln!("stage publication failed: {error}");
                request.respond(Reply::error(
                    ErrorCode::IoUncertain,
                    "staged input could not be committed",
                ))
            }
        }
    }
}
