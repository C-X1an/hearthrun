# Deployment and operations

## Two execution modes
Portable checks use Python 3.11+, Git and Make. Rust source checks use the pinned compiler. Native integration requires an owned disposable Linux x86-64 host with the kernel operations and delegation exercised by the doctor. The evidence report records the scope of each mode.

## Development storage boundary
All project-created bytes must be attributed, including Rust/Cargo/npm/browser caches, build targets, worktrees, archives, Docker/VM images and logs. Default no Docker/VM image download, no model weights, no kernel build, no Chromium bundle and no vendored dependency tree. Use one existing compatible compiler or minimal isolated Rust1.99.1. CARGO_HOME, RUSTUP_HOME, CARGO_TARGET_DIR, TMPDIR, XDG_CACHE_HOME and PIP_CACHE_DIR point into HEARTHRUN_DEV_ROOT. CARGO_INCREMENTAL=0; debug=0; build jobs<=2; only one heavy build/test process at a time across agents. Two small source worktrees maximum; shared target path only with build lock, never simultaneous conflicting builds.

A real filesystem/project quota or a fixed-capacity dedicated development volume <=12,000,000,000 bytes is the enforcement boundary. At most3,000,000,000 additional attributable external bytes are permitted within the absolute15GB total. Source, downloads, caches, state and logs should all be inside the quota root so the external margin remains unused. File-size scans provide accounting, not a hard guarantee against concurrent allocation. If quota creation requires new elevated authority or creates risk to unrelated files, record HA-002, continue tiny text/unit work, and do not start heavy downloads/builds until verified bounded placement exists. Never delete unrelated user caches, packages, files, images or volumes. Existing shared caches are not charged in full, but every project-caused increase must be recorded; easiest safe policy is isolated caches.

Planning allocation within12GB: toolchain2GB, dependencies/source1GB, compiled output3GB, tests/evidence/state2GB, worktrees1GB, controlled temp/download staging1GB, safety2GB. These are reservations, not measured package sizes. Warn at10GB; stop new heavy jobs at11GB; hard quota12GB. Absolute total tracked cap15GB. Keep logs per command<=8MiB and artifacts<=configured sizes; preserve summaries/hashes before deleting only known reproducible project outputs.

## Native launch on an already authorized systemd user host
Use a verified development boundary for the checkout, build targets and test work. The current native test harness verifies a no-swap tmpfs up to 12,000,000,000 bytes and requires an empty, dedicated cgroup v2 jobs parent already delegated to the non-root operator UID. That parent must expose `cpu`, `memory` and `pids` in `cgroup.subtree_control`. The native operator process must start with no supplementary groups. The operational doctor reports the live checks.

```sh
export HEARTHRUN_DEV_ROOT=/absolute/owned/bounded/test-work
export CARGO_TARGET_DIR=/absolute/owned/bounded/cargo-target
export HEARTHRUN_JOBS=/sys/fs/cgroup/absolute/owned/delegation/jobs
make bootstrap
make build .work/hearthrun-probe native-prerequisites
./.work/hearthrun-probe --cgroup-root "$HEARTHRUN_JOBS"
make integration-run
make demo-run
```

`native-prerequisites` defaults to `musl-gcc` for the static fixture. `NATIVE_CC` can name a trusted static x86-64 musl compiler. `integration` and `demo` also perform their build prerequisites. Use the separate run targets when the build and native commands require different host scopes. The demo creates an owned `demo-*` directory with `report.html`, summary and evidence files. Keep the directory together for report links.

An operator can create a disposable delegated systemd user service with `Delegate=cpu memory pids` or equivalent host-approved delegation. Place that service's own process in a separate host leaf before enabling the controllers on its parent. Enable the same controllers on a dedicated, empty `jobs` child and pass its absolute path to the doctor. The supervisor creates only its own verified job leaves there. Host setup changes require authorization for the specific delegation. Keep platform protections enabled and leave surrounding cgroups under their existing ownership.

## Clean-checkout reproduction

On the same compatible host and with an empty delegation, use `make clean-verify` from the root of a clean, audited public Git checkout. Set `HEARTHRUN_RUST_TOOLCHAIN_BIN` to the installed Rust 1.99.1 compiler directory containing `rustc` and `cargo`. The runner creates a shallow local clone inside `HEARTHRUN_DEV_ROOT` and fetches the lockfile's dependencies into a new Cargo home. The build and source checks then use that cache offline. Use a short work root to allow room for the native Unix socket path. To override the host and static compilers, pass `CC` and `NATIVE_CC` as Make assignments.

This target runs the implemented source checks, native integration, finite policy and resource probes, demo, and teardown. It retains a command record and raw log hashes in the fresh work directory. Full locked acceptance and the mutation campaign have separate requirements.

## CI/CD
On pull requests and pushes to main, the portable workflow validates the acceptance hash, parses source and configuration, runs Python tooling tests and compiles the C doctor. The Rust workflow runs formatting, strict Clippy, type checking and workspace tests with the pinned toolchain. Tracked-content, history and secret-pattern checks run separately with `make public-audit`. Native acceptance uses a separately triggered reviewed-commit workflow, with an operational doctor first. The workflows use read-only contents permission, SHA-pinned actions and bounded job timeouts.

Release only public-safe source/tests/docs/sanitized evidence in a fresh public-only checkout. Run exact clean-environment verification. Tag only after applicable gates; attach binaries with SHA-256 manifest and supported platform note if actually built. No fabricated tag, release URL or attestation. A public source preview may be published with explicit incomplete status; it is not a verified release. Static report hosting is optional; no live guest execution endpoint.

## Service lifecycle / runbooks
Start: validate config/path permissions, acquire state lock, probe features, reconcile orphan cgroups, then accept clients. Graceful stop: close admission, cancel queued/running jobs, wait for cleanup; preserve explicit pending status for unresolved kernel tasks. Crash: restart reconciliation, no auto replay. Disk pressure: stop admission, finish/cancel safely, prune only already-expired unreferenced results; never delete a live mount or active staging. Corrupt state: refuse mutation, preserve evidence copy, reconstruct only with explicit offline reviewed tooling; no 'best effort' success. Unknown profile/kernel: refuse, run doctor, update compatibility review only after tests.

The local retry catalog holds up to 1,024 identities and 256 KiB. The 16 MiB metadata budget includes space for temporary replacement files. Artifact eviction retains request identity. A full catalog or metadata budget returns `STORAGE_FULL` for a new job. Exact retries can still resolve records already in the catalog. The socket frame limit remains 65,536 bytes.

Rollback: stop service and clean jobs; restore previously verified binary plus matching config/policy; data format must match. Do not downgrade across incompatible state versions. Backup when service stopped, preserve complete state/profile metadata; do not copy private data into public releases. Restoration is a separately tested operation; no live consistency or secure-erasure claim.

The current reader opens existing v1 catalogs within the previous bounds. Before rolling back to a build limited to 256 identities and a 65,536-byte catalog, verify the saved state fits both limits. Preserve the complete current state separately.

Observability is local JSON logs/metrics with bounded retention. Report active/queued/cleanup_pending, rejected submissions, policy refusals, retained/discarded output, cgroup limit counters and storage bytes. Health means local supervisor can answer; readiness requires successful recovery/probes and available storage; neither means every job succeeded. No external log collector needed.

## Teardown
Cancel only jobs registered under the current instance's verified owned cgroup subtree; confirm populated=0 and reaping; close retained output FDs; remove now-empty owned cgroups and temporary mounts; stop service; archive bounded evidence. Remove only explicitly registered project temp/build paths. Print remaining attributable bytes and unresolved resources. Unrelated services and user state must remain unchanged.

## Remote alternative
Use an existing authorized SSH-accessible Linux host when local OS lacks features; transfer source and small evidence, not whole toolchain/VM images back to the device. New cloud purchase/account creation/billing consent is not authorized by this budget. HA-003 may record that optional choice. A remote host still needs the same doctor, disposable boundary, security review and no public listener.
