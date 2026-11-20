//! Strict v1 request parsing. This module has no execution or host-path authority.
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::Read;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::{validate_logical_path, JobId, MAX_HEADER_BYTES};

pub const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_FILES: usize = 128;
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    BadFrame,
    BadJson,
    UnsupportedVersion,
    UnknownField,
    DuplicateKey,
    InvalidPath,
    InvalidLimit,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadFrame => "BAD_FRAME",
            Self::BadJson => "BAD_JSON",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::DuplicateKey => "DUPLICATE_KEY",
            Self::InvalidPath => "INVALID_PATH",
            Self::InvalidLimit => "INVALID_LIMIT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: Code,
    pub message: &'static str,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}
impl std::error::Error for ProtocolError {}

fn error(code: Code, message: &'static str) -> ProtocolError {
    ProtocolError { code, message }
}

type Result<T> = std::result::Result<T, ProtocolError>;

/// A duplicate-aware recursive seed. Parsing through Value alone would discard
/// duplicate keys, including escaped spellings of the same decoded name.
struct Strict(usize);

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON containing integers, not floating point numbers")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> std::result::Result<Value, A::Error> {
        if self.0 >= MAX_DEPTH {
            return Err(de::Error::custom("nesting limit exceeded"));
        }
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(Strict(self.0 + 1))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> std::result::Result<Value, A::Error> {
        if self.0 >= MAX_DEPTH {
            return Err(de::Error::custom("nesting limit exceeded"));
        }
        let mut values = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("HEARTHRUN_DUPLICATE_KEY"));
            }
            let value = access.next_value_seed(Strict(self.0 + 1))?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

pub fn strict_json(bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > MAX_HEADER_BYTES {
        return Err(error(
            Code::BadFrame,
            "JSON header length is outside bounds",
        ));
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Strict(0).deserialize(&mut decoder).map_err(|e| {
        if e.to_string().contains("HEARTHRUN_DUPLICATE_KEY") {
            error(Code::DuplicateKey, "duplicate decoded JSON key")
        } else {
            error(Code::BadJson, "invalid UTF-8, JSON, integer or nesting")
        }
    })?;
    decoder
        .end()
        .map_err(|_| error(Code::BadJson, "trailing JSON data"))?;
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub request_id: String,
    pub profile_id: String,
    pub stage_id: String,
    pub argv: Vec<String>,
    pub wall_ms: u64,
}

impl Submission {
    /// Sorted JSON with explicit fields; caller hashes these bytes using SHA-256.
    /// Neither whitespace nor field order can change durable request identity.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let value = serde_json::json!({"v":1,"op":"submit","request_id":self.request_id,
            "profile_id":self.profile_id,"stage_id":self.stage_id,
            "argv":self.argv,"wall_ms":self.wall_ms});
        // Serializing a finite, bounded Value containing only strings/integers is infallible.
        let fields: BTreeMap<_, _> = value
            .as_object()
            .expect("fixed object construction")
            .iter()
            .collect();
        serde_json::to_vec(&fields).expect("bounded Value serialization")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Doctor,
    Metrics,
    Stage(Vec<InputFile>),
    Submit(Submission),
    Inspect(String),
    Cancel(String),
    Result(String),
    Events {
        job_id: String,
        after_seq: u64,
        limit: u64,
    },
}

fn object(value: Value) -> Result<Map<String, Value>> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(error(Code::BadJson, "object required")),
    }
}

fn fields(map: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    if map.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(error(Code::UnknownField, "unknown request field"));
    }
    Ok(())
}

fn take(map: &mut Map<String, Value>, key: &str) -> Result<Value> {
    map.remove(key)
        .ok_or_else(|| error(Code::BadJson, "required field missing"))
}

fn string(map: &mut Map<String, Value>, key: &str) -> Result<String> {
    match take(map, key)? {
        Value::String(value) => Ok(value),
        _ => Err(error(Code::BadJson, "string field required")),
    }
}

fn unsigned(map: &mut Map<String, Value>, key: &str) -> Result<u64> {
    take(map, key)?
        .as_u64()
        .ok_or_else(|| error(Code::InvalidLimit, "unsigned integer required"))
}

fn id(map: &mut Map<String, Value>, key: &str) -> Result<String> {
    let value = string(map, key)?;
    JobId::parse(&value).map_err(|_| error(Code::BadJson, "ID must be 32 lowercase hex bytes"))?;
    Ok(value)
}

pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn valid_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn parse_request(bytes: &[u8]) -> Result<Request> {
    let mut map = object(strict_json(bytes)?)?;
    if take(&mut map, "v")?.as_u64() != Some(1) {
        return Err(error(
            Code::UnsupportedVersion,
            "protocol version 1 required",
        ));
    }
    let op = string(&mut map, "op")?;
    match op.as_str() {
        "doctor" | "metrics" => {
            fields(&map, &[])?;
            Ok(if op == "doctor" {
                Request::Doctor
            } else {
                Request::Metrics
            })
        }
        "inspect" | "cancel" | "result" => {
            fields(&map, &["job_id"])?;
            let value = id(&mut map, "job_id")?;
            Ok(match op.as_str() {
                "inspect" => Request::Inspect(value),
                "cancel" => Request::Cancel(value),
                _ => Request::Result(value),
            })
        }
        "events" => {
            fields(&map, &["job_id", "after_seq", "limit"])?;
            let job_id = id(&mut map, "job_id")?;
            let after_seq = if map.contains_key("after_seq") {
                unsigned(&mut map, "after_seq")?
            } else {
                0
            };
            let limit = if map.contains_key("limit") {
                unsigned(&mut map, "limit")?
            } else {
                100
            };
            if !(1..=100).contains(&limit) {
                return Err(error(Code::InvalidLimit, "event page limit must be 1..100"));
            }
            Ok(Request::Events {
                job_id,
                after_seq,
                limit,
            })
        }
        "stage" => {
            fields(&map, &["files"])?;
            let Value::Array(files) = take(&mut map, "files")? else {
                return Err(error(Code::BadJson, "files array required"));
            };
            if files.len() > MAX_FILES {
                return Err(error(Code::InvalidLimit, "at most 128 input files"));
            }
            let mut total = 0_u64;
            let mut seen = HashSet::<String>::new();
            let mut manifest = Vec::new();
            for file in files {
                let mut file = object(file)?;
                fields(&file, &["path", "size", "sha256"])?;
                let path = string(&mut file, "path")?;
                validate_logical_path(&path)
                    .map_err(|_| error(Code::InvalidPath, "invalid logical input path"))?;
                if seen.contains(&path)
                    || seen.iter().any(|other| {
                        path.starts_with(&(other.clone() + "/"))
                            || other.starts_with(&(path.clone() + "/"))
                    })
                {
                    return Err(error(
                        Code::InvalidPath,
                        "duplicate or conflicting input path",
                    ));
                }
                seen.insert(path.clone());
                let size = unsigned(&mut file, "size")?;
                total = total
                    .checked_add(size)
                    .filter(|sum| *sum <= MAX_INPUT_BYTES)
                    .ok_or_else(|| error(Code::InvalidLimit, "input total exceeds 16 MiB"))?;
                let sha256 = string(&mut file, "sha256")?;
                if !valid_sha256(&sha256) {
                    return Err(error(
                        Code::BadJson,
                        "SHA-256 must be 64 lowercase hex bytes",
                    ));
                }
                manifest.push(InputFile { path, size, sha256 });
            }
            Ok(Request::Stage(manifest))
        }
        "submit" => {
            fields(
                &map,
                &["request_id", "profile_id", "stage_id", "argv", "wall_ms"],
            )?;
            let request_id = id(&mut map, "request_id")?;
            let profile_id = string(&mut map, "profile_id")?;
            if !valid_profile_id(&profile_id) {
                return Err(error(Code::BadJson, "invalid operator profile identifier"));
            }
            let stage_id = id(&mut map, "stage_id")?;
            let wall_ms = unsigned(&mut map, "wall_ms")?;
            if !(100..=60_000).contains(&wall_ms) {
                return Err(error(Code::InvalidLimit, "wall_ms must be 100..60000"));
            }
            let Value::Array(values) = take(&mut map, "argv")? else {
                return Err(error(Code::BadJson, "argv array required"));
            };
            if values.len() > 32 {
                return Err(error(Code::InvalidLimit, "at most 32 arguments"));
            }
            let mut argv = Vec::new();
            let mut total = 0_usize;
            for value in values {
                let Value::String(value) = value else {
                    return Err(error(Code::BadJson, "string arguments required"));
                };
                total += value.len();
                if total > 4096 || value.contains('\0') {
                    return Err(error(Code::InvalidLimit, "argv byte or NUL limit"));
                }
                argv.push(value);
            }
            Ok(Request::Submit(Submission {
                request_id,
                profile_id,
                stage_id,
                argv,
                wall_ms,
            }))
        }
        _ => Err(error(Code::BadJson, "unknown operation")),
    }
}

/// Read only the declared header; staging payload remains in the caller's reader.
/// EOF/surplus checks and I/O deadlines belong to the actual socket receiver.
pub fn read_request(reader: &mut impl Read) -> Result<Request> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| error(Code::BadFrame, "incomplete frame length"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_HEADER_BYTES {
        return Err(error(Code::BadFrame, "frame size is outside bounds"));
    }
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| error(Code::BadFrame, "incomplete frame header"))?;
    parse_request(&bytes)
}
