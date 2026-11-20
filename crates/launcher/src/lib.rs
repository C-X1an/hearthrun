//! Supervisor-side native control descriptors and Linux job groups.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod cgroup;
pub mod image;
pub mod policy;
pub mod wire;
