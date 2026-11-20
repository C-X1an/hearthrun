//! Bounded private seqpacket control channel between the supervisor and launcher.
//! Clients and guests never receive either endpoint.

use rustix::fs::{self, FileType, OFlags};
use rustix::net::{
    self, sockopt, AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
    ReturnFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
    UCred,
};
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsFd, OwnedFd};

const PACKET_LEN: usize = 21;
pub const PREPARE: u8 = 1;
pub const EXECUTE: u8 = 2;
pub const READY: u8 = 3;
pub const EXIT: u8 = 4;
pub const FAULT: u8 = 5;

pub struct Packet {
    pub kind: u8,
    pub value: i32,
    pub descriptors: Vec<OwnedFd>,
    pub sender: Option<UCred>,
}

pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let (parent, child) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    // Kernel-supplied per-packet credentials identify the sender at send time,
    // unlike SO_PEERCRED on a socketpair created before the launcher was spawned.
    sockopt::set_socket_passcred(&parent, true)?;
    Ok((parent, child))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn send(
    socket: &impl AsFd,
    nonce: &[u8; 16],
    kind: u8,
    value: i32,
    descriptors: &[std::os::fd::BorrowedFd<'_>],
) -> io::Result<()> {
    if count(kind) != Some(descriptors.len()) {
        return Err(invalid("wrong descriptor count for control packet"));
    }
    let mut data = [0; PACKET_LEN];
    data[0] = kind;
    data[1..17].copy_from_slice(nonce);
    data[17..].copy_from_slice(&value.to_be_bytes());
    let mut buffer = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = SendAncillaryBuffer::new(&mut buffer);
    if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(invalid("control buffer rejected descriptors"));
    }
    let n = net::sendmsg(
        socket,
        &[IoSlice::new(&data)],
        &mut ancillary,
        SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
    )?;
    if n != data.len() {
        return Err(invalid("short control packet write"));
    }
    Ok(())
}

pub fn send_plain(socket: &impl AsFd, nonce: &[u8; 16], kind: u8, value: i32) -> io::Result<()> {
    send(socket, nonce, kind, value, &[])
}

fn count(kind: u8) -> Option<usize> {
    match kind {
        PREPARE => Some(3),
        READY => Some(1),
        EXECUTE | EXIT | FAULT => Some(0),
        _ => None,
    }
}

/// None means the nonblocking socket has no packet. EOF and every malformed
/// packet are errors. Received descriptors are always owned, including on reject.
pub fn receive(
    socket: &impl AsFd,
    nonce: &[u8; 16],
    expected_uid: Option<u32>,
) -> io::Result<Option<Packet>> {
    let mut data = [0; PACKET_LEN];
    let mut control =
        [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut control);
    let msg = match net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut data)],
        &mut ancillary,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    ) {
        Ok(msg) => msg,
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if msg.bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "control peer closed",
        ));
    }
    if msg.bytes != PACKET_LEN
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || data[1..17] != nonce[..]
    {
        return Err(invalid("truncated or unauthenticated control packet"));
    }
    let mut descriptors = Vec::new();
    let mut rights_seen = false;
    let mut sender = None;
    for item in ancillary.drain() {
        match item {
            RecvAncillaryMessage::ScmRights(rights) if !rights_seen => {
                rights_seen = true;
                descriptors.extend(rights);
            }
            RecvAncillaryMessage::ScmCredentials(cred) if sender.is_none() => sender = Some(cred),
            _ => return Err(invalid("unrecognized ancillary control message")),
        }
    }
    match (expected_uid, sender.as_ref()) {
        (Some(uid), Some(cred)) if cred.uid.as_raw() == uid => {}
        (None, None) => {}
        _ => return Err(invalid("control sender credentials did not match")),
    }
    let kind = data[0];
    if count(kind) != Some(descriptors.len()) {
        return Err(invalid("invalid control packet type or descriptor count"));
    }
    let value = i32::from_be_bytes(data[17..].try_into().expect("fixed packet length"));
    Ok(Some(Packet {
        kind,
        value,
        descriptors,
        sender,
    }))
}

pub fn validate_output_descriptor(fd: &impl AsFd, expected_uid: u32) -> io::Result<()> {
    let st = fs::fstat(fd)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory
        || st.st_uid != expected_uid
        || st.st_mode & 0o777 != 0o700
        || fs::fstatfs(fd)?.f_type as u64 != 0x0102_1994
        || !fs::fcntl_getfl(fd)?.contains(OFlags::PATH | OFlags::DIRECTORY)
        || !rustix::io::fcntl_getfd(fd)?.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(invalid(
            "output descriptor is not the required private tmpfs directory",
        ));
    }
    Ok(())
}
