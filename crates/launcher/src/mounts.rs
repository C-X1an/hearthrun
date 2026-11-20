use hearthrun_domain::{protocol, validate_logical_path};
use hearthrun_launcher::image;
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{self, Dir, FileType, Mode, OFlags, ResolveFlags};
use rustix::mount::{self, MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::{process, thread};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const SAFE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);
const MOUNT_FLAGS: MountFlags = MountFlags::NOSUID.union(MountFlags::NODEV);

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn private_dir(fd: &impl AsFd, uid: u32) -> io::Result<()> {
    let stat = fs::fstat(fd)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o077 != 0
    {
        return Err(invalid("expected owner-only staging directory"));
    }
    Ok(())
}

fn map_namespace(uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: the separately exec'd launcher is single-threaded, so no thread
    // can share credentials, filesystem state, or namespace membership.
    unsafe { thread::unshare_unsafe(thread::UnshareFlags::NEWUSER)? };
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))?;
    if process::getuid().as_raw() != 0
        || process::getgid().as_raw() != 0
        || !process::getgroups()?.is_empty()
    {
        return Err(invalid("unexpected UID/GID mapping or supplementary group"));
    }
    // SAFETY: still single-threaded. NEWPID puts the next child in the
    // private PID namespace, leaving this trusted outer launcher outside.
    unsafe {
        thread::unshare_unsafe(
            thread::UnshareFlags::NEWNS
                | thread::UnshareFlags::NEWPID
                | thread::UnshareFlags::NEWNET
                | thread::UnshareFlags::NEWIPC
                | thread::UnshareFlags::NEWUTS,
        )?;
    }
    mount::mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )?;
    rustix::system::sethostname(b"hearthrun")?;
    Ok(())
}

#[derive(Default)]
struct InputBudget {
    entries: usize,
    files: usize,
    bytes: u64,
}

fn copy_input(
    source: &OwnedFd,
    relative: &str,
    target: &Path,
    budget: &mut InputBudget,
) -> io::Result<()> {
    let mut dir = Dir::read_from(source)?;
    while let Some(entry) = dir.read() {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| invalid("input path is not UTF-8"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        let logical = if relative.is_empty() {
            name.to_owned()
        } else {
            format!("{relative}/{name}")
        };
        validate_logical_path(&logical).map_err(|_| invalid("invalid staged input name"))?;
        budget.entries += 1;
        if budget.entries > 1024 {
            return Err(invalid("staged input contains too many entries"));
        }
        let anchor = fs::openat2(
            source,
            name,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            SAFE,
        )?;
        let stat = fs::fstat(&anchor)?;
        let path = target.join(name);
        let kind = FileType::from_raw_mode(stat.st_mode);
        let access = match kind {
            FileType::Directory => OFlags::DIRECTORY,
            FileType::RegularFile if stat.st_nlink == 1 => OFlags::NONBLOCK,
            _ => {
                return Err(invalid(
                    "input entry is not a single-link regular file or directory",
                ))
            }
        };
        let fd = fs::openat2(
            source,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | access,
            Mode::empty(),
            SAFE,
        )?;
        let opened = fs::fstat(&fd)?;
        if (stat.st_dev, stat.st_ino, stat.st_mode, stat.st_nlink)
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
            )
        {
            return Err(invalid("staged input changed during open"));
        }
        if kind == FileType::Directory {
            std::fs::create_dir(&path)?;
            copy_input(&fd, &logical, &path, budget)?;
            continue;
        }
        let size = u64::try_from(stat.st_size).map_err(|_| invalid("invalid input file size"))?;
        budget.files += 1;
        if budget.files > protocol::MAX_FILES || size > protocol::MAX_INPUT_BYTES - budget.bytes {
            return Err(invalid("staged input exceeds file or byte bound"));
        }
        let mut input = File::from(fd).take(size + 1);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)?;
        if io::copy(&mut input, &mut output)? != size {
            return Err(invalid("staged input changed during copy"));
        }
        budget.bytes += size;
    }
    Ok(())
}

fn mount_location(scratch: &OwnedFd) -> io::Result<PathBuf> {
    // The target is supplied by a trusted descriptor, never a client path.
    let path = std::fs::read_link(format!("/proc/self/fd/{}", scratch.as_raw_fd()))?;
    if !path.is_absolute() || path == Path::new("/") {
        return Err(invalid("invalid private mount location"));
    }
    let current = fs::openat2(
        fs::CWD,
        &path,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    let expected = fs::fstat(scratch)?;
    let actual = fs::fstat(current)?;
    if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino) {
        return Err(invalid(
            "mount location no longer names received scratch directory",
        ));
    }
    Ok(path)
}

pub(crate) fn construct(
    executable: OwnedFd,
    input: OwnedFd,
    scratch: OwnedFd,
    digest: &str,
) -> io::Result<OwnedFd> {
    let uid = process::getuid().as_raw();
    let gid = process::getgid().as_raw();
    if uid == 0 || !process::getgroups()?.is_empty() {
        return Err(invalid(
            "launcher requires an unprivileged UID with no supplementary groups",
        ));
    }
    private_dir(&input, uid)?;
    private_dir(&scratch, uid)?;
    let executable = File::from(executable);
    let bytes = image::read_image(&executable)?;
    if image::sha256(&bytes) != digest {
        return Err(invalid("approved native profile digest mismatch"));
    }
    let root = mount_location(&scratch)?;
    let _ = process::umask(Mode::RWXG | Mode::RWXO);
    map_namespace(uid, gid)?;
    mount::mount(
        "tmpfs",
        &root,
        "tmpfs",
        MOUNT_FLAGS,
        c"size=33554432,nr_inodes=1536,mode=0700",
    )?;
    for name in ["bin", "in", "out", "old"] {
        std::fs::create_dir(root.join(name))?;
    }
    let mut guest_exe = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(root.join("bin/task"))?;
    guest_exe.write_all(&bytes)?;
    drop(guest_exe);
    copy_input(&input, "", &root.join("in"), &mut InputBudget::default())?;
    mount::mount(
        "tmpfs",
        root.join("out"),
        "tmpfs",
        MOUNT_FLAGS | MountFlags::NOEXEC,
        c"size=33554432,nr_inodes=256,mode=0700",
    )?;
    drop((executable, input, scratch, bytes));
    std::env::set_current_dir(&root)?;
    process::pivot_root(".", "old")?;
    std::env::set_current_dir("/")?;
    mount::unmount("/old", UnmountFlags::DETACH)?;
    std::fs::remove_dir("/old")?;
    mount::mount_remount(
        "/",
        MOUNT_FLAGS | MountFlags::RDONLY,
        c"size=33554432,nr_inodes=1536,mode=0700",
    )?;
    let out = fs::open(
        "/out",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stats = fs::fstatvfs(&out)?;
    if stats.f_blocks.checked_mul(stats.f_frsize) != Some(33_554_432) || stats.f_files != 256 {
        return Err(invalid(
            "output mount limits differ from the launch contract",
        ));
    }
    Ok(out)
}
