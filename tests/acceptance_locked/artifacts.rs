//! Direct publication-boundary tests; these do not establish guest quiescence.
//!
//! Register as a Linux x86-64 supervisor integration-test target. Run with
//! HEARTHRUN_ARTIFACT_TEST_ROOT set to an absolute, owned mode0700 directory on
//! a separately OS-capped tmpfs (at most 128MiB). Missing prerequisites FAIL.
//! The device case requires an owner-owned inert node named artifact-device
//! on that nodev tmpfs. It must not be opened.
//! All objects and link targets below are synthetic and remain inside that root.

#![forbid(unsafe_code)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("artifact acceptance tests require Linux x86-64; unsupported hosts must not report a zero-test pass");

use hearthrun_supervisor::artifacts::{Error, PreparationKind, PublicationKind, Publisher, Stream};
use hearthrun_supervisor::store::Store;
use rustix::fd::OwnedFd;
use rustix::fs::{self as rfs, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::unix::fs::{symlink, DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const JOB: &str = "0123456789abcdef0123456789abcdef";
const TMPFS_MAGIC: u64 = 0x0102_1994;
const MAX_TEST_FILESYSTEM_BYTES: u64 = 128 * 1024 * 1024;
// Locked product limits are deliberately independent of implementation constants.
const ARTIFACT_LIMIT: u64 = 32 * 1024 * 1024;
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    publisher: Option<Publisher>,
    store: Option<Store>,
    base: PathBuf,
    state: PathBuf,
    output: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(std::env::var_os("HEARTHRUN_ARTIFACT_TEST_ROOT").expect(
            "HEARTHRUN_ARTIFACT_TEST_ROOT is required: supply an owned mode0700 capped tmpfs directory",
        ));
        assert!(root.is_absolute(), "test root must be absolute");
        assert_eq!(
            root.canonicalize().unwrap(),
            root,
            "test root cannot follow a link"
        );
        let root_fd = rfs::open(
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("cannot open test root without following a final symlink");
        let stat = rfs::fstat(&root_fd).expect("cannot inspect test root");
        assert_ne!(stat.st_uid, 0, "test root requires a non-root operator");
        assert_eq!(stat.st_uid, rustix::process::geteuid().as_raw());
        assert_eq!(stat.st_mode & 0o7777, 0o700, "test root must be mode0700");
        let filesystem = rfs::fstatfs(&root_fd).expect("cannot inspect test filesystem");
        assert_eq!(
            filesystem.f_type as u64, TMPFS_MAGIC,
            "test root must be tmpfs"
        );
        let capacity = filesystem
            .f_blocks
            .checked_mul(u64::try_from(filesystem.f_bsize).expect("invalid filesystem block size"))
            .expect("filesystem capacity overflow");
        assert!(
            (1..=MAX_TEST_FILESYSTEM_BYTES).contains(&capacity),
            "test filesystem must have an OS-enforced cap of at most128MiB"
        );
        let base = root.join(format!(
            "publisher-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        mkdir(&base);
        let state = base.join("state");
        let output = base.join("output");
        mkdir(&state);
        mkdir(&output);
        // Keep the production state lock for the entire Publisher lifetime.
        let store = Store::open(&state).expect("cannot acquire isolated Store lock");
        let publisher = Publisher::open(&state).expect("cannot open isolated Publisher");
        Self {
            publisher: Some(publisher),
            store: Some(store),
            base,
            state,
            output,
        }
    }

    fn publisher(&self) -> &Publisher {
        self.publisher
            .as_ref()
            .expect("fixture publisher was closed")
    }

    fn output_fd(&self) -> OwnedFd {
        rfs::open(
            &self.output,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("cannot retain synthetic output directory")
    }

    fn final_path(&self) -> PathBuf {
        self.state.join("results").join(JOB)
    }

    fn reject(&self) {
        let error = match self
            .publisher()
            .commit(JOB, metadata(), Some(self.output_fd()), b"", b"")
        {
            Ok(_) => panic!("unsafe or over-limit synthetic artifact tree was published"),
            Err(error) => error,
        };
        assert!(
            matches!(&error, Error::Preparation(detail) if detail.kind == PreparationKind::InvalidArtifacts),
            "expected explicit InvalidArtifacts, got {error}"
        );
        assert!(
            !self.publisher().is_frozen(),
            "structural refusal must precede staging"
        );
        assert!(
            fs::read_dir(self.state.join("results"))
                .expect("cannot enumerate results after refusal")
                .next()
                .is_none(),
            "refusal wrote a final result or temporary stage"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.publisher.take());
        drop(self.store.take());
        fs::remove_dir_all(&self.base).expect("cannot remove synthetic publication fixture");
    }
}

fn mkdir(path: &Path) {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .expect("cannot create owner-only synthetic directory");
}

fn file(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("cannot exclusively create synthetic regular file");
    target
        .write_all(bytes)
        .expect("cannot write synthetic regular file");
    target
        .sync_all()
        .expect("cannot sync synthetic regular file");
}

fn metadata() -> Value {
    json!({
        "status": "SUCCEEDED", "cleanup_confirmed": true,
        "policy_sha256": "0".repeat(64), "environment_id": "synthetic-publisher-test",
        "exit_code": 0, "signal": null,
        "stdout_truncated": false, "stderr_truncated": false
    })
}

fn hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Independent oracle from the documented v1 wire digest, never a publisher helper.
fn bundle_hash(metadata_bytes: &[u8], stdout: &[u8], stderr: &[u8]) -> String {
    let mut wire = b"HearthRun result bundle v1\0".to_vec();
    wire.extend_from_slice(&(metadata_bytes.len() as u64).to_be_bytes());
    wire.extend_from_slice(metadata_bytes);
    for stream in [stdout, stderr] {
        wire.extend_from_slice(&(stream.len() as u64).to_be_bytes());
        wire.extend_from_slice(hash(stream).as_bytes());
    }
    hash(&wire)
}

#[test]
fn regular_copy_binds_source_final_artifact_streams_and_bundle_hashes() {
    let fixture = Fixture::new();
    mkdir(&fixture.output.join("nested"));
    file(&fixture.output.join("nested/result.txt"), b"abc");
    file(&fixture.output.join("empty.bin"), b"");
    let stdout = b"synthetic stdout\n";
    let stderr = b"synthetic stderr\n";
    let result = fixture
        .publisher()
        .commit(JOB, metadata(), Some(fixture.output_fd()), stdout, stderr)
        .expect("regular synthetic tree must publish");
    assert_eq!(result.job_id, JOB);
    assert_eq!(result.artifacts.len(), 2);
    let expected = json!([
        {"path": "empty.bin", "size_bytes": 0, "sha256": hash(b"")},
        {"path": "nested/result.txt", "size_bytes": 3, "sha256": ABC_SHA256}
    ]);
    assert_eq!(serde_json::to_value(&result.artifacts).unwrap(), expected);
    let final_path = fixture.final_path();
    let source_bytes = fs::read(fixture.output.join("nested/result.txt")).unwrap();
    let copied_path = final_path.join("artifacts/nested/result.txt");
    let copied_bytes = fs::read(&copied_path).unwrap();
    assert_eq!(source_bytes, b"abc");
    assert_eq!(copied_bytes, source_bytes);
    assert_eq!(hash(&source_bytes), ABC_SHA256);
    assert_eq!(hash(&copied_bytes), ABC_SHA256);
    assert_eq!(fs::metadata(&copied_path).unwrap().nlink(), 1);
    assert_eq!(fs::metadata(&copied_path).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(fs::metadata(&final_path).unwrap().mode() & 0o7777, 0o700);
    assert_eq!(fs::read(final_path.join("stdout.bin")).unwrap(), stdout);
    assert_eq!(fs::read(final_path.join("stderr.bin")).unwrap(), stderr);
    assert_eq!(result.stdout_size, stdout.len() as u64);
    assert_eq!(result.stderr_size, stderr.len() as u64);
    assert_eq!(result.stdout_sha256, hash(stdout));
    assert_eq!(result.stderr_sha256, hash(stderr));
    let encoded = fs::read(final_path.join("result.json")).unwrap();
    let stored: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(stored, result.metadata);
    assert_eq!(stored["artifacts"], expected);
    assert_eq!(result.result_digest, bundle_hash(&encoded, stdout, stderr));
    let names: Vec<_> = fs::read_dir(fixture.state.join("results"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        [std::ffi::OsString::from(JOB)],
        "successful commit left a temporary result"
    );
    let reread = fixture
        .publisher()
        .read_result(JOB, &result.result_digest)
        .unwrap();
    assert_eq!(reread.artifacts, result.artifacts);
    assert_eq!(reread.result_digest, result.result_digest);
    assert_eq!(
        fixture
            .publisher()
            .read_stream(JOB, &result.result_digest, Stream::Stdout)
            .unwrap(),
        stdout
    );
    assert_eq!(
        fixture
            .publisher()
            .read_stream(JOB, &result.result_digest, Stream::Stderr)
            .unwrap(),
        stderr
    );
}

#[test]
fn result_uses_the_retained_directory_after_its_original_name_is_replaced() {
    let fixture = Fixture::new();
    file(&fixture.output.join("result.txt"), b"abc");
    let held = fixture.output_fd();
    fs::rename(&fixture.output, fixture.base.join("retained")).unwrap();
    mkdir(&fixture.output);
    file(&fixture.output.join("result.txt"), b"synthetic replacement");
    let result = fixture
        .publisher()
        .commit(JOB, metadata(), Some(held), b"", b"")
        .expect("the retained directory must still be the publication source");
    assert_eq!(result.artifacts.len(), 1);
    assert_eq!(result.artifacts[0].sha256, ABC_SHA256);
    assert_eq!(
        fs::read(fixture.final_path().join("artifacts/result.txt")).unwrap(),
        b"abc"
    );
    assert_eq!(
        fs::read(fixture.output.join("result.txt")).unwrap(),
        b"synthetic replacement"
    );
}

#[test]
fn symlink_to_local_synthetic_file_is_refused_before_staging() {
    let fixture = Fixture::new();
    file(&fixture.output.join("target.txt"), b"abc");
    symlink("target.txt", fixture.output.join("alias.txt")).unwrap();
    fixture.reject();
    assert_eq!(fs::read(fixture.output.join("target.txt")).unwrap(), b"abc");
}

#[test]
fn symlink_to_a_synthetic_sibling_outside_output_is_refused() {
    let fixture = Fixture::new();
    file(&fixture.base.join("sibling.txt"), b"abc");
    symlink("../sibling.txt", fixture.output.join("alias.txt")).unwrap();
    fixture.reject();
    assert_eq!(fs::read(fixture.base.join("sibling.txt")).unwrap(), b"abc");
}

#[test]
fn hardlinked_local_synthetic_files_are_refused_before_staging() {
    let fixture = Fixture::new();
    file(&fixture.output.join("target.txt"), b"abc");
    fs::hard_link(
        fixture.output.join("target.txt"),
        fixture.output.join("alias.txt"),
    )
    .unwrap();
    fixture.reject();
}

#[test]
fn unopened_fifo_is_refused_before_staging() {
    let fixture = Fixture::new();
    let path = fixture.output.join("fifo");
    rfs::mknodat(
        rfs::CWD,
        &path,
        rfs::FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    )
    .expect("cannot create synthetic FIFO prerequisite");
    fixture.reject();
}

#[test]
fn unopened_device_on_the_nodev_test_mount_is_refused_before_staging() {
    struct MovedDevice {
        from: PathBuf,
        original: PathBuf,
    }

    impl Drop for MovedDevice {
        fn drop(&mut self) {
            fs::rename(&self.from, &self.original)
                .expect("cannot restore the inert device fixture");
        }
    }

    let fixture = Fixture::new();
    let parent = fixture.base.parent().unwrap();
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        mountinfo.lines().any(|line| {
            let Some((metadata, fs)) = line.split_once(" - ") else {
                return false;
            };
            metadata.split_ascii_whitespace().nth(4) == parent.to_str()
                && fs.split_ascii_whitespace().next() == Some("tmpfs")
                && metadata
                    .split_ascii_whitespace()
                    .nth(5)
                    .is_some_and(|options| options.split(',').any(|flag| flag == "nodev"))
        }),
        "the device fixture needs an exact nodev tmpfs mount"
    );
    let original = parent.join("artifact-device");
    let properties =
        fs::symlink_metadata(&original).expect("missing inert artifact-device fixture");
    assert!(properties.file_type().is_char_device());
    assert_eq!(properties.nlink(), 1);
    assert_eq!(properties.uid(), rustix::process::geteuid().as_raw());
    let from = fixture.output.join("device");
    fs::rename(&original, &from).unwrap();
    let _device = MovedDevice { from, original };
    fixture.reject();
}

#[test]
fn local_inert_unix_socket_is_refused_before_staging() {
    let fixture = Fixture::new();
    // No connections, accept, reads, writes, or host socket paths are used.
    let socket = UnixListener::bind(fixture.output.join("socket"))
        .expect("cannot bind local synthetic socket prerequisite");
    fixture.reject();
    drop(socket);
}

#[test]
fn invalid_components_and_overdeep_logical_paths_are_refused_before_staging() {
    for name in ["bad name", "bad:name", "caf\u{e9}", &"a".repeat(65)] {
        let fixture = Fixture::new();
        file(&fixture.output.join(name), b"abc");
        fixture.reject();
    }
    let fixture = Fixture::new();
    let mut path = fixture.output.clone();
    for _ in 0..8 {
        path.push("dir");
        mkdir(&path);
    }
    file(&path.join("ninth.txt"), b"abc");
    fixture.reject();
}

#[test]
fn exactly128_files_publish_and129_are_refused_before_staging() {
    for count in [128, 129] {
        let fixture = Fixture::new();
        for index in 0..count {
            file(&fixture.output.join(format!("file-{index:03}")), b"");
        }
        if count == 129 {
            fixture.reject();
        } else {
            let result = fixture
                .publisher()
                .commit(JOB, metadata(), Some(fixture.output_fd()), b"", b"")
                .expect("locked128-file boundary must remain accepted");
            assert_eq!(result.artifacts.len(), 128);
        }
    }
}

#[test]
fn single_and_aggregate_excess_logical_bytes_are_refused_without_copying() {
    // Sparse files consume no32MiB payload allocation and exercise st_size limits.
    for sizes in [
        vec![ARTIFACT_LIMIT + 1],
        vec![ARTIFACT_LIMIT / 2, ARTIFACT_LIMIT / 2 + 1],
    ] {
        let fixture = Fixture::new();
        for (index, size) in sizes.into_iter().enumerate() {
            let path = fixture.output.join(format!("sparse-{index}"));
            file(&path, b"");
            OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_len(size)
                .unwrap();
        }
        fixture.reject();
    }
}

#[test]
fn final_artifact_and_stream_tampering_fail_hash_verification_and_freeze_owner() {
    for relative in ["artifacts/result.txt", "stdout.bin", "stderr.bin"] {
        let fixture = Fixture::new();
        file(&fixture.output.join("result.txt"), b"abc");
        let result = fixture
            .publisher()
            .commit(JOB, metadata(), Some(fixture.output_fd()), b"abc", b"abc")
            .expect("synthetic result must publish before tampering");
        // Same-length mutation verifies content hashing rather than size checking.
        use std::io::Write;
        File::options()
            .write(true)
            .open(fixture.final_path().join(relative))
            .unwrap()
            .write_all(b"abd")
            .unwrap();
        let error = match fixture.publisher().read_result(JOB, &result.result_digest) {
            Ok(_) => panic!("same-length committed content mutation escaped digest verification"),
            Err(error) => error,
        };
        assert!(
            matches!(&error, Error::Publication(detail) if detail.kind == PublicationKind::DigestMismatch),
            "expected DigestMismatch, got {error}"
        );
        assert!(fixture.publisher().is_frozen());
    }
}
