# Verification report

The scoped native observations were captured on Linux x86-64 WSL2, kernel `6.18.58.1-microsoft-standard-WSL2`, with Landlock ABI 7 and an owned cgroup v2 delegation. Rust source checks used the pinned 1.99.1 toolchain. The recorded source digests identify each tested snapshot. [Selected captured observations and raw digests](verification/observed-runs.json)

| Scope | Actual observation |
|---|---|
| Build, format, strict Clippy and type check | PASS on the bounded development checkout. |
| Rust, Python, property and framing | Workspace unit and contract checks passed, along with 47 Python tooling tests, 4,096 generated domain histories and 3,204 deterministic protocol mutations. |
| Operational host and launcher | 15 doctor cases passed. The launcher integration observed the fixed environment, immutable staged input, withheld execution and detached-process cleanup. The wall deadline worker emptied a job while the lifecycle caller was paused. |
| Finite policy smoke | The approved fixture copied its declared input, checked the synthetic host canary, enumerated descriptors through its observed limit, and confirmed socket and selected syscall denials. The x32 identity query terminated with `SIGSYS`. Full locked policy coverage remains open. |
| Unix socket and durable recovery | Real CLI transformation, checked export, typed refusals, repeated request identity and crash restart without replay passed. |
| Admission and deadlines | One finite run observed 4 active, 16 waiting and `QUEUE_FULL` for the next job. Durable start observations confirmed FIFO. A 3,000 ms configured whole-group deadline reached confirmed cleanup 3,140 ms from submission in the recorded Make integration run. |
| CPU, memory, PIDs and streams | An observed 10.254-second CPU window used about 1.00036 cores under a one-core quota. Kernel memory and PID events advanced. The flood case retained 1 MiB per stream, with both truncations explicit. |
| Demo | Actual approved transformation, refusal, synthetic host-canary denial and detached cancellation passed. The static report's 11 links were verified. Browser and keyboard-only visual review remain pending. |
| Dependency advisories | `cargo-audit` 0.23.0 checked 38 lock entries against the recorded RustSec snapshot, yielding zero advisories and warnings in that run. |
| Benchmark smoke | 90 scheduled rows completed with zero failed samples. This run exercised only the scoped benchmark driver. |

## Failures retained

- The first native memory fixture triggered a kernel OOM kill but the supervisor recorded a policy error. After repairing outcome classification, the same suite passed with the observed memory counter and `RESOURCE_LIMIT` outcome.
- The first full benchmark campaign exhausted bounded filesystem resources before writing its summary. No full percentile claim follows from that run.

## Remaining release evidence

The locked acceptance inventory, complete native pass/fail/pass mutation campaign, full storage fault and quiescence schedules, benchmark matrix and final independent acceptance review remain open. The release status records clean-candidate and GitHub results separately. [Release readiness](RELEASE_READINESS.md)
