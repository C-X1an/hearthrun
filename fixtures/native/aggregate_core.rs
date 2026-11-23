//! Fixed-memory B-02 aggregation core linked into the approved C entry point.
//! No allocation, I/O, std startup, pointers, borrowed foreign memory or unwind.
//! C supplies a fully initialized record and aggregate state by value. All FFI
//! fields have valid bit patterns for every value representable by C.
//!
//! Production: compile as a staticlib, edition 2021, panic=abort. The symbol
//! export requires Rust >=1.82 (the workspace minimum is 1.85). With --test the
//! same parser and arithmetic use the normal Rust test harness instead.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

const MAX_RECORD_BYTES: usize = 127;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
enum Error {
    RecordLimit = 13,
    InvalidRecord = 14,
    ValueOverflow = 15,
    SumOverflow = 16,
    CountOverflow = 17,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateState {
    pub count: u64,
    pub sum: i64,
    pub min: i64,
    pub max: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InputRecord {
    pub bytes: [u8; MAX_RECORD_BYTES],
    pub length: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateResult {
    pub state: AggregateState,
    pub error: u32,
    pub reserved: u32,
}

// Match the C11 static assertions; the fixture is linked only for Linux x86-64.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<AggregateState>() == 32 && align_of::<AggregateState>() == 8);
    assert!(offset_of!(AggregateState, sum) == 8 && offset_of!(AggregateState, min) == 16);
    assert!(offset_of!(AggregateState, max) == 24);
    assert!(size_of::<InputRecord>() == 128 && offset_of!(InputRecord, length) == 127);
    assert!(size_of::<AggregateResult>() == 40 && offset_of!(AggregateResult, error) == 32);
    assert!(offset_of!(AggregateResult, reserved) == 36);
};

fn json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn trim_json(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().copied().is_some_and(json_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().copied().is_some_and(json_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn value_from_record(record: &[u8]) -> Result<i64, Error> {
    let rest = trim_json(record)
        .strip_prefix(b"{")
        .ok_or(Error::InvalidRecord)?;
    let rest = trim_json(rest)
        .strip_prefix(b"\"value\"")
        .ok_or(Error::InvalidRecord)?;
    let rest = trim_json(rest)
        .strip_prefix(b":")
        .ok_or(Error::InvalidRecord)?;
    let number = trim_json(rest);
    let (negative, digits) = match number.strip_prefix(b"-") {
        Some(digits) => (true, digits),
        None => (false, number),
    };
    let digit_count = digits
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digit_count == 0 || (digit_count > 1 && digits[0] == b'0') {
        return Err(Error::InvalidRecord);
    }
    if trim_json(&digits[digit_count..]) != b"}" {
        return Err(Error::InvalidRecord);
    }
    let mut value = 0_i64;
    for &byte in &digits[..digit_count] {
        let digit = i64::from(byte - b'0');
        // Accumulate negatives directly; negating i64::MIN would overflow.
        value = value.checked_mul(10).ok_or(Error::ValueOverflow)?;
        value = if negative {
            value.checked_sub(digit)
        } else {
            value.checked_add(digit)
        }
        .ok_or(Error::ValueOverflow)?;
    }
    Ok(value)
}

impl AggregateState {
    fn adding(self, value: i64) -> Result<Self, Error> {
        let count = self.count.checked_add(1).ok_or(Error::CountOverflow)?;
        let sum = self.sum.checked_add(value).ok_or(Error::SumOverflow)?;
        let (min, max) = if self.count == 0 {
            (value, value)
        } else {
            (self.min.min(value), self.max.max(value))
        };
        Ok(Self {
            count,
            sum,
            min,
            max,
        })
    }
}

fn aggregate_record(state: AggregateState, record: InputRecord) -> Result<AggregateState, Error> {
    let length = usize::from(record.length);
    if length > record.bytes.len() {
        return Err(Error::RecordLimit);
    }
    state.adding(value_from_record(&record.bytes[..length])?)
}

// SAFETY: This uniquely named export has the exact repr(C), integer/array-only
// by-value ABI declared in aggregate_entry.c. There are no foreign pointers,
// lifetimes or invalid enum/bool bit patterns. No Rust unwind may cross this
// boundary: production is panic=abort with the non-unwinding handler below.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn hearthrun_aggregate_record(
    state: AggregateState,
    record: InputRecord,
) -> AggregateResult {
    match aggregate_record(state, record) {
        Ok(state) => AggregateResult {
            state,
            error: 0,
            reserved: 0,
        },
        Err(error) => AggregateResult {
            state,
            error: error as u32,
            reserved: 0,
        },
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    terminate_internal()
}

// Precompiled target objects carry a personality reference. If it is called,
// terminate before any unwind can reach the C entry point.
#[cfg(not(test))]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality(
    _version: core::ffi::c_int,
    _actions: core::ffi::c_int,
    _exception_class: u64,
    _exception: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    terminate_internal()
}

#[cfg(not(test))]
#[allow(unsafe_code)]
fn terminate_internal() -> ! {
    unsafe extern "C" {
        fn _Exit(status: core::ffi::c_int) -> !;
    }
    // SAFETY: The linked musl _Exit takes an integer and terminates the current
    // process without unwinding across the C boundary or accessing any pointer.
    unsafe { _Exit(70) }
}

#[cfg(test)]
mod tests {
    use super::{
        hearthrun_aggregate_record, value_from_record, AggregateState, Error, InputRecord,
    };

    #[test]
    fn signed_edges_and_json_whitespace() {
        assert_eq!(
            value_from_record(b" { \"value\" : -9223372036854775808 } \t\r"),
            Ok(i64::MIN)
        );
        assert_eq!(
            value_from_record(b"{\"value\":9223372036854775807}"),
            Ok(i64::MAX)
        );
        assert_eq!(value_from_record(b"{\"value\":-0}"), Ok(0));
        for bytes in [
            b"{\"value\":9223372036854775808}".as_slice(),
            b"{\"value\":-9223372036854775809}",
        ] {
            assert_eq!(value_from_record(bytes), Err(Error::ValueOverflow));
        }
    }

    #[test]
    fn rejects_other_shapes_and_non_json_bytes() {
        for bytes in [
            b"".as_slice(),
            b"{\"value\":01}",
            b"{\"value\":-01}",
            b"{\"value\":+1}",
            b"{\"value\":1.0}",
            b"{\"value\":1e2}",
            b"{\"value\":true}",
            b"{\"value\":\"1\"}",
            b"{\"value\":1,\"value\":2}",
            b"{\"value\":1,\"other\":2}",
            b"{\"other\":1}",
            b"{\"value\":1}\0",
            b"\x0b{\"value\":1}",
            b"{\"value\":1} garbage",
            b"{\"value\":-}",
        ] {
            assert_eq!(value_from_record(bytes), Err(Error::InvalidRecord));
        }
    }

    #[test]
    fn checks_sum_count_and_extrema() {
        let mut state = AggregateState::default();
        for value in [-9, 4, 12, -2] {
            state = state.adding(value).expect("small signed sum");
        }
        assert_eq!(
            state,
            AggregateState {
                count: 4,
                sum: 5,
                min: -9,
                max: 12,
            }
        );
        for value in [i64::MIN, i64::MAX] {
            let edge = AggregateState::default()
                .adding(value)
                .expect("signed edge");
            assert_eq!(
                edge.adding(if value < 0 { -1 } else { 1 }),
                Err(Error::SumOverflow)
            );
        }
        let edge = AggregateState {
            count: u64::MAX,
            ..AggregateState::default()
        };
        assert_eq!(edge.adding(0), Err(Error::CountOverflow));
    }

    #[test]
    fn boundary_rejects_bad_lengths_and_preserves_state_on_error() {
        let state = AggregateState::default();
        for length in [128, 255] {
            let result = hearthrun_aggregate_record(
                state,
                InputRecord {
                    bytes: [0; 127],
                    length,
                },
            );
            assert_eq!(result.state, state);
            assert_eq!(result.error, Error::RecordLimit as u32);
            assert_eq!(result.reserved, 0);
        }
        let mut record = InputRecord {
            bytes: [0; 127],
            length: 11,
        };
        record.bytes[..11].copy_from_slice(b"{\"value\":9}");
        let result = hearthrun_aggregate_record(state, record);
        assert_eq!(result.error, 0);
        assert_eq!(
            result.state,
            AggregateState {
                count: 1,
                sum: 9,
                min: 9,
                max: 9,
            }
        );
    }
}
