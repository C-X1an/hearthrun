# Benchmarks

The bounded release build completed 36,750 scheduled observations on Linux x86-64 WSL2 with zero failed rows. The run includes warmups, the direct empty-process reference and real native jobs. The analyzer verified the schedule, retained result bytes, digests and teardown. This profile measures client-observed submit-to-terminal latency. [Captured benchmark summary](verification/benchmark-observed.json)

| Empty-job setting | Timed native rows | Native p50 | Native p95 | Native p99 |
|---|---:|---:|---:|---:|
| Concurrency 1 | 5,000 | 59.36 ms | 76.22 ms | 84.23 ms |
| Concurrency 2 | 5,000 | 67.91 ms | 93.82 ms | 114.74 ms |
| Concurrency 4 | 5,000 | 71.14 ms | 124.80 ms | 161.06 ms |

The integer transformation ran five seeds across 16 KiB, 1 MiB and 8 MiB inputs at concurrency settings 1, 2 and 4. At concurrency 4, the 8 MiB workload had a p95 of 213.22 ms across 500 measured jobs. It used the approved C count/sum fixture and verified bytes against an independent Python oracle. The direct empty-process reference excludes Unix-socket admission, guest isolation and publication. [Benchmark protocol](benchmarks/protocol.md)

## Rust B-02

The Rust aggregation core with a fixed C framing and I/O entry point completed 3,900 scheduled rows with zero failed samples. The matrix included 900 warmups and 3,000 measured jobs over five seeds. Each native result matched the independent Python count, sum, min and max. The table uses client-observed submit-to-terminal latency. [Captured Rust B-02 evidence](verification/benchmark-rust-b02-observed.json)

| Input | Concurrency | Measured jobs | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| 16 KiB | 1 | 500 | 63.75 ms | 80.42 ms | 89.39 ms |
| 16 KiB | 4 | 500 | 84.61 ms | 146.80 ms | 183.33 ms |
| 1 MiB | 1 | 500 | 65.25 ms | 84.26 ms | 90.96 ms |
| 1 MiB | 4 | 500 | 89.31 ms | 150.17 ms | 189.24 ms |
| 8 MiB | 1 | 500 | 85.04 ms | 105.38 ms | 114.31 ms |
| 8 MiB | 4 | 500 | 155.86 ms | 245.57 ms | 269.64 ms |

The first full C run hit the bounded filesystem limit. The rerun compacted each successful shard after teardown and kept every raw attempt in its analysis population. Both standalone Rust binaries exited with signal 11 during native warmup. The completed Rust measurements use the linked architecture described above. Comparable execution-only clocks, per-job CPU and memory measurements, and the remaining workload matrix are open. Full AC-021 remains open. [Benchmark protocol](benchmarks/protocol.md)

## Native cancellation

The completed B-03 campaign verified 3,000 cancellations across five seeds, with 500 observations per workload and concurrency setting. The harness waited for real fixture readiness, then checked launcher reaping, cgroup emptiness, and the terminal record. Output rows also verified bytes written after readiness. [Captured B-03 evidence](verification/benchmark-cancellation-observed.json)

| Workload | Concurrency | Cancellations | Client-to-cleanup p95 | Observed cleanup-pending jobs |
|---|---:|---:|---:|---:|
| CPU spin | 1 | 500 | 12.04 ms | 258 |
| CPU spin | 4 | 500 | 47.53 ms | 59 |
| Detached descendants | 1 | 500 | 12.19 ms | 258 |
| Detached descendants | 4 | 500 | 46.54 ms | 69 |
| Output | 1 | 500 | 11.80 ms | 111 |
| Output | 4 | 500 | 46.48 ms | 58 |

These are client-observed intervals on the measured host. Exact server receipt and kill-issuance times remain open. The earlier full attempt stopped on a denied descriptor observation. Its failed and unrun rows remain in the private archive. The verified rerun counted denied observations and required a positive readiness witness within the same deadline.
