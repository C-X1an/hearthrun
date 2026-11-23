# Verification report

The scoped native observations were captured on Linux x86-64 WSL2, kernel `6.18.58.1-microsoft-standard-WSL2`, with Landlock ABI 7 and an owned cgroup v2 delegation. Rust source checks used the pinned 1.99.1 toolchain. The recorded source digests identify each tested snapshot. [Selected captured observations and raw digests](verification/observed-runs.json)

| Scope | Actual observation |
|---|---|
| Build, format, strict Clippy and type check | PASS on the bounded development checkout. |
| Rust, Python, property and framing | Workspace unit and contract checks passed, along with 47 Python tooling tests, 4,096 generated domain histories and 3,204 deterministic protocol mutations. |
| Operational host and launcher | 15 doctor cases passed. In seven additional cases the live supervisor refused an approved submit with a named capability absent, leaving the journal, result directory and cgroup inventory empty. The launcher integration observed the fixed environment, immutable staged input, withheld execution and detached-process cleanup. The wall deadline worker emptied a job while the lifecycle caller was paused. |
| Finite policy smoke | The approved fixture copied its declared input, checked the synthetic host canary, enumerated descriptors through its observed limit, and confirmed socket and selected syscall denials. The x32 identity query terminated with `SIGSYS`. Full locked policy coverage remains open. |
| Unix socket and durable recovery | Real CLI transformation, checked export, typed refusals, repeated request identity and crash restart without replay passed. |
| Lost replies | Two complete requests lost their replies. Across graceful and crash restarts, four exact retries kept the same job IDs, five changed requests conflicted and the prior verified result persisted. Removing the isolated test build's comparison triggered the intended failure. The restored source passed. |
| Admission and deadlines | One finite run observed 4 active, 16 waiting and `QUEUE_FULL` for the next job. Durable start observations confirmed FIFO. A 3,000 ms configured whole-group deadline reached confirmed cleanup 3,140 ms from submission in the recorded Make integration run. |
| CPU, memory, PIDs and streams | An observed 10.254-second CPU window used about 1.00036 cores under a one-core quota. Kernel memory and PID events advanced. The flood case retained 1 MiB per stream, with both truncations explicit. |
| Artifact and publication layer | 12 direct artifact tests passed, including descriptor retention after a rename and refusal of an inert device on a dedicated nodev mount. Twenty persistence errors surfaced without a receipt. The ignored-fsync control failed at the intended assertion and passed after restoration. |
| Publication recovery | Actual daemon stream-write `ENOSPC` left the job in `EXPORTING` without a result receipt or a final directory. Restart recorded `INTERRUPTED` without replay and preserved the prior result. A separate synthetic checkpoint injected EIO after the result rename. Reopening the scheduler discarded that bundle and preserved the earlier result. |
| Terminal journal restart | The journal opener verifies the inventory under the state lock and syncs both held metadata directories before serving it. An injected terminal-journal rename error followed by startup sync errors refused access. After restoring fsync, both durable bundles verified. The deliberate ignored-state-root-sync control failed at the startup refusal assertion. |
| Native cleanup schedules | All 1,000 seeded schedules passed with 500 success and 500 cancellation outcomes. The harness bracketed live cgroup and launcher observations around result queries, checked final artifact bytes and removed all ten owned test batches. The independent premature-publication control remains open. |
| Demo | Actual approved transformation, refusal, synthetic host-canary denial and detached cancellation passed. The static report's 11 links were verified. Browser and keyboard-only visual review remain pending. |
| Dependency advisories | `cargo-audit` 0.23.0 checked 38 lock entries against the recorded RustSec snapshot, yielding zero advisories and warnings in that run. |
| Benchmarks | B-01 and C transformation ran 36,750 rows with zero failures. A separate Rust B-02 run passed 3,900 rows with all four summary fields verified. The repaired B-03 run passed 3,000 cancellations with independently verified result bytes, reaping and cgroup observations. Full AC-021 remains open. |

## Failures retained

- The first native memory fixture triggered a kernel OOM kill but the supervisor recorded a policy error. After repairing outcome classification, the same suite passed with the observed memory counter and `RESOURCE_LIMIT` outcome.
- The first full benchmark campaign exhausted bounded filesystem resources before writing its summary. The revised bounded collector completed its scheduled rows and passed further analysis. [Measured campaign](BENCHMARKS.md)
- The first cleanup smoke stopped when a journal read held the old inode across an atomic replacement. Restricting the reader's retry to that owned, retired journal inode preserved strict artifact reads. The revised smoke and full campaign passed.
- Replaying the completed Rust benchmark archive over the Windows mount timed out. The analyzer passed on a checksum-verified copy of the same archive on the bounded Linux volume.
- The first cancellation smoke triggered the output cap before caller cancellation. The first full schedule later stopped on a denied descriptor observation during exec. The repaired smoke and full rerun passed from separate new work directories. [Cancellation measurements](BENCHMARKS.md#native-cancellation)

## Remaining release evidence

The locked acceptance inventory, remaining native mutations, terminal-journal fault coverage, delayed cleanup schedules, benchmark matrix and final independent acceptance review remain open. The release status records clean-candidate and GitHub results separately. [Release readiness](RELEASE_READINESS.md)
