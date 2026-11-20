use rustix::fd::AsFd;
use rustix::fs::{self, OFlags};
use std::io::{self, Read};

pub const STREAM_LIMIT: usize = 1024 * 1024;
const DRAIN_BUDGET: usize = 128 * 1024;

#[derive(Debug, Default)]
pub struct StreamOutput {
    pub bytes: Vec<u8>,
    pub discarded: u64,
    pub eof: bool,
}

impl StreamOutput {
    pub fn truncated(&self) -> bool {
        self.discarded != 0
    }

    pub fn drain(&mut self, input: &mut impl Read) -> io::Result<()> {
        let mut buffer = [0; 8192];
        let mut remaining = DRAIN_BUDGET;
        while !self.eof && remaining != 0 {
            let count = buffer.len().min(remaining);
            match input.read(&mut buffer[..count]) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    remaining -= n;
                    let keep = n.min(STREAM_LIMIT - self.bytes.len());
                    self.bytes.extend_from_slice(&buffer[..keep]);
                    self.discarded = self.discarded.saturating_add((n - keep) as u64);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

pub fn nonblocking(fd: &impl AsFd) -> io::Result<()> {
    let flags = fs::fcntl_getfl(fd)?;
    fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK)?;
    Ok(())
}
