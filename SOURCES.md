# Technical sources

Accessed2026-11-08. These sources inform the design; they are not evidence that HearthRun implements the properties. Package versions and account/pricing details must be rechecked before installation or spending.

- **T01 Seccomp BPF** - https://docs.kernel.org/userspace-api/seccomp_filter.html. Relevance: Seccomp is not a complete sandbox; ABI checks and no_new_privs.
- **T02 Landlock userspace API** - https://docs.kernel.org/userspace-api/landlock.html. Relevance: ABI-specific rights and mandatory-policy compatibility.
- **T03 Landlock6.12 documentation** - https://docs.kernel.org/6.12/userspace-api/landlock.html. Relevance: Versioned ABI baseline and enforcement semantics.
- **T04 Control Group v2** - https://docs.kernel.org/admin-guide/cgroup-v2.html. Relevance: Ownership hierarchy, controllers, delegation and cleanup observation.
- **T05 pidfd_open(2)** - https://man7.org/linux/man-pages/man2/pidfd_open.2.html. Relevance: Stable process descriptor semantics, not whole-tree ownership.
- **T06 openat2(2)** - https://man7.org/linux/man-pages/man2/openat2.2.html. Relevance: Descriptor-relative constrained pathname resolution.
- **T07 Control Group APIs and Delegation** - https://systemd.io/CGROUP_DELEGATION/. Relevance: Delegated subtree ownership and no-internal-process topology.
- **O01 NsJail** - https://github.com/google/nsjail. Relevance: Mature namespaces/resource/security alternative; comparison baseline.
- **O02 bubblewrap** - https://github.com/containers/bubblewrap. Relevance: Minimal Linux sandbox-building alternative.
- **O03 Architecture introduction** - https://gvisor.dev/docs/architecture_guide/intro/. Relevance: User-space kernel isolation alternative and different tradeoffs.
- **O04 Firecracker** - https://github.com/firecracker-microvm/firecracker. Relevance: MicroVM alternative with different host/resource burden.
- **O05 Wasmtime security** - https://docs.wasmtime.dev/security.html. Relevance: Wasm security alternative with a different execution model.
- **O06 Remote caching** - https://bazel.build/remote/caching. Relevance: Build-cache/incremental alternative and comparison design.
- **O07 Getting started** - https://rocksdb.org/docs/getting-started.html. Relevance: Storage-engine ecosystem baseline.
- **O08 BPF documentation** - https://docs.kernel.org/bpf/index.html. Relevance: Kernel observability alternative and complexity.
- **O09 Workflow execution** - https://docs.temporal.io/workflow-execution. Relevance: Durable workflow alternative; avoid another glue-only project.
- **D01 Announcing Rust1.99.1** - https://blog.rust-lang.org/2026/10/15/Rust-1.99.1/. Relevance: Selected stable patch baseline, not installed here.
- **D02 Rustup1.29.3** - https://blog.rust-lang.org/2026/11/03/Rustup-1.29.3/. Relevance: Minimal isolated toolchain-install baseline.
- **D03 rustix package manifest** - https://docs.rs/crate/rustix/latest/source/Cargo.toml.orig. Relevance: Package version/features/license baseline.
- **D04 landlock0.4.7** - https://docs.rs/crate/landlock/0.4.7. Relevance: Selected library API and enforcement caveats.
- **D05 seccompiler0.5.0** - https://docs.rs/crate/seccompiler/0.5.0. Relevance: BPF filter compiler baseline.
- **D06 rust-vmm monorepo and move issue** - https://github.com/rust-vmm/rust-vmm/issues/76. Relevance: Archived component repository not automatically abandonment.
- **D07 serde package** - https://docs.rs/crate/serde/latest. Relevance: Typed JSON library selection baseline.
- **D08 serde_json package** - https://docs.rs/crate/serde_json/latest. Relevance: JSON serialization baseline; duplicate-key policy separately required.
- **D09 tokio package** - https://docs.rs/crate/tokio/latest. Relevance: Supervisor async runtime selection.
- **D10 sha2 package** - https://docs.rs/crate/sha2/latest. Relevance: Maintained digest library selection.
- **D11 proptest package** - https://docs.rs/crate/proptest/latest. Relevance: Development-only property testing baseline.
- **D12 Cargo profiles** - https://doc.rust-lang.org/cargo/reference/profiles.html. Relevance: Debug/incremental settings for storage discipline.
- **S01 Secure use of GitHub Actions** - https://docs.github.com/en/actions/reference/security/secure-use. Relevance: Least privilege, immutable action pinning and untrusted workflow risks.
- **S02 Securely using pull_request_target** - https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target. Relevance: Avoid executing untrusted PR code with powerful credentials.
- **S03 actions/checkout v6 ref** - https://api.github.com/repos/actions/checkout/git/ref/tags/v6. Relevance: Pinned commit d23441a48e516b6c34aea4fa41551a30e30af803.
