//! Real ENOSPC control for the publication layer. Use a dedicated capped tmpfs.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Native publication verification requires Linux x86-64");

use hearthrun_supervisor::artifacts::{Error, PublicationKind, Publisher, Stream};
use hearthrun_supervisor::store::Store;
use rustix::fs::{self, FallocateFlags, Mode, OFlags};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

const FIRST: &str = "11111111111111111111111111111111";
const FULL: &str = "22222222222222222222222222222222";
const FROZEN: &str = "33333333333333333333333333333333";

fn metadata(id: &str) -> Value {
    json!({"v":1,"job_id":id,"status":"SUCCEEDED","cleanup_confirmed":true,
           "policy_sha256":"b".repeat(64),"environment_id":"isolated-publication-test",
           "exit_code":0,"signal":null,"stdout_truncated":false,"stderr_truncated":false,
           "artifacts":[]})
}

#[test]
fn nearly_full_mount_never_replaces_committed_result_or_publishes_partial() {
    let mount = PathBuf::from(
        std::env::var_os("HEARTHRUN_PUBLICATION_TEST_ROOT")
            .expect("set HEARTHRUN_PUBLICATION_TEST_ROOT to the dedicated capped tmpfs"),
    );
    assert!(mount.is_absolute() && mount.canonicalize().unwrap() == mount);
    let mount_dir = fs::open(
        &mount,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let stat = fs::fstat(&mount_dir).unwrap();
    assert!(uid != 0 && stat.st_uid == uid && stat.st_mode & 0o7777 == 0o700);
    assert_eq!(fs::fstatfs(&mount_dir).unwrap().f_type as u64, 0x0102_1994);
    let inventory = std::fs::read_dir(&mount).unwrap().count();
    assert_eq!(
        inventory, 0,
        "publication pressure test requires an empty dedicated mount"
    );
    let limit = fs::fstatvfs(&mount_dir).unwrap();
    let capacity = limit.f_blocks * limit.f_frsize;
    assert!((8 * 1024 * 1024..=128 * 1024 * 1024).contains(&capacity));
    let mount_name = mount.to_str().expect("fixture path is Unicode");
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        mountinfo.lines().any(|line| {
            let Some((left, right)) = line.split_once(" - ") else {
                return false;
            };
            left.split_ascii_whitespace().nth(4) == Some(mount_name)
                && right.split_ascii_whitespace().next() == Some("tmpfs")
                && right
                    .split_ascii_whitespace()
                    .nth(2)
                    .is_some_and(|options| options.split(',').any(|flag| flag == "noswap"))
        }),
        "expected a dedicated noswap tmpfs mount"
    );

    let state = mount.join("publication-state");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    let _store = Store::open(&state).unwrap();
    let publisher = Publisher::open(&state).unwrap();
    let saved = publisher
        .commit(FIRST, metadata(FIRST), None, b"baseline output\n", b"")
        .unwrap();
    let filler_path = mount.join("publication-pressure.bin");
    let filler = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&filler_path)
        .unwrap();
    let remaining = fs::fstatvfs(&mount_dir).unwrap();
    let remaining_bytes = remaining.f_bavail * remaining.f_frsize;
    fs::fallocate(
        &filler,
        FallocateFlags::empty(),
        0,
        remaining_bytes - 16 * 1024,
    )
    .unwrap();
    let during = fs::fstatvfs(&mount_dir).unwrap();
    let free_bytes = during.f_bavail * during.f_frsize;
    assert!(free_bytes <= 16 * 1024);

    let payload = vec![b'x'; 128 * 1024];
    let failed = publisher.commit(FULL, metadata(FULL), None, &payload, b"");
    let Err(Error::Publication(error)) = failed else {
        panic!("disk full must reject publication");
    };
    assert_eq!(error.kind, PublicationKind::IoUncertain);
    assert_eq!(
        error.io_error().and_then(std::io::Error::raw_os_error),
        Some(libc::ENOSPC)
    );
    assert!(publisher.is_frozen());
    assert!(!state.join("results").join(FULL).exists());
    let rejected = publisher.commit(FROZEN, metadata(FROZEN), None, b"", b"");
    assert!(
        matches!(rejected, Err(Error::Publication(item)) if item.kind == PublicationKind::Frozen)
    );
    assert!(!state.join("results").join(FROZEN).exists());
    let verified = publisher.read_result(FIRST, &saved.result_digest).unwrap();
    assert_eq!(verified.result_digest, saved.result_digest);
    assert_eq!(
        publisher
            .read_stream(FIRST, &saved.result_digest, Stream::Stdout)
            .unwrap(),
        b"baseline output\n"
    );
    println!("{{\"capacity_bytes\":{capacity},\"free_bytes\":{free_bytes},\"errno\":{},\"prior_result_readable\":true,\"publish_refused\":true}}", libc::ENOSPC);

    drop(filler);
    std::fs::remove_file(filler_path).unwrap();
    File::from(mount_dir).sync_all().unwrap();
    // Keep owned state for explicit recovery/inspection until the caller tears down the mount.
}
