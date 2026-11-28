#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![forbid(unsafe_code)]

#[cfg(feature = "cancellation-timing-verification")]
pub mod cancel_timing;

pub mod artifacts;
pub mod lifecycle;
pub mod output;
pub mod profiles;
pub mod retention;
pub mod scheduler;
pub mod server;
pub mod staging;
pub mod store;

#[cfg(all(test, feature = "native-verification"))]
mod crash_checkpoint;

#[cfg(all(test, feature = "native-verification"))]
#[path = "../../../tests/acceptance_locked/native_check.rs"]
mod native_check;
