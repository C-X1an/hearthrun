# Limitations and status

HearthRun is experimental. Finite native runs have passed on one Linux x86-64 WSL2 host. The full locked acceptance, mutation, filesystem fault, and clean-host reproduction campaigns remain open. See the verification report for measured scope and the historical unsupported-host observation.

The domain crate models trusted observations. The native launcher and supervisor use kernel operations and authenticated control messages. The portable tests exercise the domain and strict framing independently of the kernel-bound integration tests.

The intended v1 supports a trusted operator on one Linux x86-64 host and approved static native fixtures. It does not support public multi-tenant hosting, arbitrary shell commands, arbitrary uploaded executables, dynamic package installation inside guests, network access, general OCI images, distributed scheduling or delegated external effects.

The host kernel, privileged administrator and authorized same-UID control plane are trusted. Shared-kernel exploits, malicious host root, physical attacks and side channels are outside the stated boundary. seccomp alone is not a sandbox. Kill requests do not guarantee immediate reaping of uninterruptible tasks; CLEANUP_PENDING must remain visible. Namespace and Landlock controls do not establish confidentiality against a malicious host.

The finite integration runs provide observations for their workloads. Benchmark campaigns and any performance targets have separate records. No availability, real-user, or production-scale claim has been established.

A source digest detects accidental evidence mismatch, not a maintainer who rewrites source and hashes. Evidence logs can leak data unless reviewed. The exporter has conservative file/hash/basic-key filters, not a comprehensive data-loss-prevention engine. Independent security, license, privacy and clean-host review remain required before release.
