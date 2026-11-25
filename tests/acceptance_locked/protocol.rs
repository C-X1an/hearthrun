//! Locked AC-001 checks for the real bounded Unix socket receiver.
use super::*;
use crate::native_check;
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;

fn socket_work() -> (PathBuf, u32) {
    let work =
        PathBuf::from(std::env::var_os("HEARTHRUN_PROTOCOL_SOCKET_WORK").expect("set socket work"));
    assert!(work.is_absolute());
    let parent = work.parent().unwrap();
    assert_eq!(parent.canonicalize().unwrap(), parent);
    let uid = rustix::process::geteuid().as_raw();
    assert_ne!(uid, 0);
    assert!(rustix::process::getgroups().unwrap().is_empty());
    let scope = open_private_directory(parent, uid).unwrap();
    assert_eq!(fs::fstatfs(&scope).unwrap().f_type as u64, 0x0102_1994);
    let size = fs::fstatvfs(&scope).unwrap();
    assert!((1_000_000..=12_000_000_000).contains(&(size.f_blocks * size.f_frsize)));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&work)
        .unwrap();
    (work, uid)
}

fn socket_client(work: &Path, uid: u32) -> UnixStream {
    let path = work.join(SOCKET_NAME);
    let info = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(info.uid(), uid);
    assert_eq!(info.mode() & 0o777, 0o600);
    let stream = UnixStream::connect(path).unwrap();
    stream.set_read_timeout(Some(RESPONSE_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(RESPONSE_TIMEOUT)).unwrap();
    stream
}

fn response(client: &mut UnixStream) -> Value {
    let mut length = [0_u8; 4];
    client
        .read_exact(&mut length)
        .expect("read bounded response length");
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= MAX_HEADER_BYTES);
    let mut header = vec![0; length];
    client.read_exact(&mut header).unwrap();
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    protocol::strict_json(&header).unwrap()
}

#[test]
fn real_socket_refuses_uid_and_oversize_before_receiving_requests() {
    let (work, uid) = socket_work();
    let mut server = Server::bind(&work, uid).unwrap();
    let mut denied = socket_client(&work, uid);
    assert_eq!(std::fs::metadata(&work).unwrap().mode() & 0o777, 0o700);
    // Change only the fixture's expected policy UID after the ordinary bind.
    // Linux supplies the real connecting user's credential to poll_accept.
    server.expected_uid = uid ^ 1;
    let admission = server.poll_accept();
    server.expected_uid = uid;
    assert!(
        admission.unwrap().is_none(),
        "unexpected UID must not dispatch or fail the listener"
    );
    let refusal = response(&mut denied);
    assert_eq!(refusal["v"], 1);
    assert_eq!(refusal["ok"], false);
    assert_eq!(refusal["error"]["code"], "UNAUTHORIZED");
    assert_eq!(refusal["error"]["retryable"], false);
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);

    let mut oversized = socket_client(&work, uid);
    oversized
        .write_all(&((MAX_HEADER_BYTES + 1) as u32).to_be_bytes())
        .unwrap();
    // Keep the write half open. Neither EOF nor a missing body can produce the
    // framing error until the independent header deadline expires.
    let start = Instant::now();
    let receive = server.poll_accept().unwrap().unwrap().receive();
    let Err(error) = receive else {
        panic!("oversized header was received")
    };
    assert_eq!(error.error.code, ErrorCode::BadFrame);
    assert!(error.io_error().is_none() && start.elapsed() < HEADER_TIMEOUT / 2);
    error.respond().unwrap();
    assert_eq!(response(&mut oversized)["error"]["code"], "BAD_FRAME");

    let mut exact = socket_client(&work, uid);
    let normal = br#"{"v":1,"op":"metrics"}"#;
    let mut header = vec![b' '; MAX_HEADER_BYTES];
    header[..normal.len()].copy_from_slice(normal);
    exact
        .write_all(&(MAX_HEADER_BYTES as u32).to_be_bytes())
        .unwrap();
    exact.write_all(&header).unwrap();
    exact.shutdown(Shutdown::Write).unwrap();
    let incoming = server
        .poll_accept()
        .unwrap()
        .unwrap()
        .receive()
        .unwrap_or_else(|error| panic!("exact boundary refused: {:?}", error.error));
    assert_eq!(incoming.request(), &Request::Metrics);
    let validated = incoming
        .finish()
        .unwrap_or_else(|error| panic!("exact boundary EOF refused: {:?}", error.error));
    // A separate daemon fixture verifies the scheduler remains idle after each
    // malformed submit. This receiver-only fixture never constructs one.
    drop(validated);
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);
    server.close().unwrap();
    assert!(!work.join(SOCKET_NAME).exists());
    println!("{{\"case\":\"real_socket_rejection\",\"status\":\"PASS\",\"uid_rejection\":\"UNAUTHORIZED\",\"socket_mode\":\"0600\",\"directory_mode\":\"0700\",\"max_header_bytes\":65536}}");
}

#[test]
fn malformed_submit_never_changes_live_daemon_state() {
    native_check::run(
        "tests/integration/protocol.py",
        &[],
        &[
            ("--bin-dir", "HEARTHRUN_PROTOCOL_BIN_DIR"),
            ("--doctor", "HEARTHRUN_PROTOCOL_DOCTOR"),
            ("--fixture", "HEARTHRUN_PROTOCOL_FIXTURE"),
            ("--cgroup-root", "HEARTHRUN_JOBS"),
            ("--work", "HEARTHRUN_PROTOCOL_DAEMON_WORK"),
        ],
    );
}
