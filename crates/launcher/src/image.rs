//! Strict approval of immutable native profile bytes.
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};

pub const IMAGE_LIMIT: u64 = 8 * 1024 * 1024;

fn invalid(detail: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

pub fn read_image(file: &File) -> io::Result<Vec<u8>> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > IMAGE_LIMIT {
        return Err(invalid(
            "profile must be a bounded single-link regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    let mut buffer = [0; 16 * 1024];
    loop {
        let n = file.read_at(&mut buffer, bytes.len() as u64)?;
        if n == 0 {
            break;
        }
        if bytes.len() as u64 + n as u64 > IMAGE_LIMIT {
            return Err(invalid("profile exceeded executable limit"));
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    if bytes.len() as u64 != meta.len() {
        return Err(invalid("profile changed while reading"));
    }
    validate_elf(&bytes)?;
    Ok(bytes)
}

pub fn sha256(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

pub fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX[(byte >> 4) as usize]));
        text.push(char::from(HEX[(byte & 15) as usize]));
    }
    text
}

pub fn validate_elf(bytes: &[u8]) -> io::Result<()> {
    let header = bytes
        .get(..64)
        .ok_or_else(|| invalid("ELF header incomplete"))?;
    let u16_at =
        |data: &[u8], offset| u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
    let u32_at =
        |data: &[u8], offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    let u64_at =
        |data: &[u8], offset| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(header[7], 0 | 3)
        || !matches!(u16_at(header, 16), 2 | 3)
        || u16_at(header, 18) != 62
        || u32_at(header, 20) != 1
        || u16_at(header, 52) != 64
        || u16_at(header, 54) != 56
    {
        return Err(invalid("x86-64 little-endian executable ELF required"));
    }
    let table = usize::try_from(u64_at(header, 32)).map_err(|_| invalid("ELF table offset"))?;
    let count = usize::from(u16_at(header, 56));
    if !(1..=1024).contains(&count) || table < 64 {
        return Err(invalid("ELF program header count or position invalid"));
    }
    let end = table
        .checked_add(56 * count)
        .ok_or_else(|| invalid("ELF table overflow"))?;
    let table = bytes
        .get(table..end)
        .ok_or_else(|| invalid("ELF table incomplete"))?;
    let entry = u64_at(header, 24);
    let mut executable_entry = false;
    for segment in table.chunks_exact(56) {
        match u32_at(segment, 0) {
            3 | 5 => return Err(invalid("native profile must not request an interpreter")),
            1 => {
                let flags = u32_at(segment, 4);
                let offset = u64_at(segment, 8);
                let address = u64_at(segment, 16);
                let size = u64_at(segment, 32);
                let memory = u64_at(segment, 40);
                if flags & 3 == 3
                    || size > memory
                    || offset
                        .checked_add(size)
                        .is_none_or(|end| end > bytes.len() as u64)
                    || address.checked_add(memory).is_none()
                {
                    return Err(invalid("ELF load segment outside reviewed constraints"));
                }
                executable_entry |= flags & 1 != 0 && entry >= address && entry < address + size;
            }
            _ => {}
        }
    }
    if !executable_entry {
        return Err(invalid(
            "ELF entry point has no executable file-backed segment",
        ));
    }
    Ok(())
}
