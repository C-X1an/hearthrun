//! Local operator approval and descriptor-bound executable identity.
use crate::staging::{create_private_dir, private_dir, read_owned, write_new};
use hearthrun_domain::protocol::{self, valid_profile_id, valid_sha256};
use hearthrun_launcher::image;
use rustix::fd::OwnedFd;
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    v: u32,
    profile_id: String,
    sha256: String,
}

pub struct Profile {
    pub digest: String,
    pub image_digest: String,
    pub image: OwnedFd,
}

fn invalid(detail: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

fn open_file(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("absolute operator path required"));
    }
    let fd = fs::openat2(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    Ok(File::from(fd))
}

/// Call with the state lock held. Existing approvals are never overwritten.
pub fn install(state: &Path, id: &str, source: &Path) -> io::Result<Profile> {
    if !valid_profile_id(id) {
        return Err(invalid("invalid profile identifier"));
    }
    let bytes = image::read_image(&open_file(source)?)?;
    let parent = state.join("profiles");
    create_private_dir(&parent)?;
    let fd = private_dir(&parent)?;
    let temporary = format!(".install-{}", image::lower_hex(&crate::lifecycle::nonce()?));
    fs::mkdirat(&fd, temporary.as_str(), Mode::RWXU)?;
    let dir = parent.join(&temporary);
    let prepared = (|| {
        let bin = dir.join("task");
        write_new(&bin, &bytes)?;
        let binary = open_file(&bin)?;
        fs::fchmod(&binary, Mode::RUSR)?;
        binary.sync_all()?;
        let manifest = Manifest {
            v: 1,
            profile_id: id.to_owned(),
            sha256: image::sha256(&bytes),
        };
        write_new(&dir.join("manifest.json"), &serde_json::to_vec(&manifest)?)?;
        File::from(private_dir(&dir)?).sync_all()?;
        fs::renameat_with(&fd, temporary.as_str(), &fd, id, fs::RenameFlags::NOREPLACE)?;
        Ok::<(), io::Error>(())
    })();
    if let Err(error) = prepared {
        std::fs::remove_dir_all(dir)?;
        return Err(error);
    }
    File::from(fd).sync_all()?;
    load(state, id)
}

pub fn load(state: &Path, id: &str) -> io::Result<Profile> {
    if !valid_profile_id(id) {
        return Err(invalid("invalid profile identifier"));
    }
    let path = state.join("profiles").join(id);
    private_dir(&path)?;
    let data = read_owned(&path.join("manifest.json"), 4096)?;
    let manifest: Manifest =
        serde_json::from_value(protocol::strict_json(&data).map_err(io::Error::other)?)?;
    if manifest.v != 1 || manifest.profile_id != id || !valid_sha256(&manifest.sha256) {
        return Err(invalid("invalid profile manifest"));
    }
    let binary = open_file(&path.join("task"))?;
    let stat = fs::fstat(&binary)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o777 != 0o400 {
        return Err(invalid("approved image must be owner-only and read-only"));
    }
    let bytes = image::read_image(&binary)?;
    if image::sha256(&bytes) != manifest.sha256 {
        return Err(invalid("approved image content does not match profile"));
    }
    Ok(Profile {
        digest: image::sha256(&data),
        image_digest: manifest.sha256,
        image: binary.into(),
    })
}
