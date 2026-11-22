# Benchmarks

The bounded release build completed 36,750 scheduled observations on Linux x86-64 WSL2 with zero failed rows. The run includes warmups, the direct empty-process reference and real native jobs. The analyzer verified the schedule, retained result bytes, digests and teardown. This profile measures client-observed submit-to-terminal latency. [Captured benchmark summary](verification/benchmark-observed.json)

| Empty-job setting | Timed native rows | Native p50 | Native p95 | Native p99 |
|---|---:|---:|---:|---:|
| Concurrency 1 | 5,000 | 59.36 ms | 76.22 ms | 84.23 ms |
| Concurrency 2 | 5,000 | 67.91 ms | 93.82 ms | 114.74 ms |
| Concurrency 4 | 5,000 | 71.14 ms | 124.80 ms | 161.06 ms |

The integer transformation ran five seeds across 16 KiB, 1 MiB and 8 MiB inputs at concurrency settings 1, 2 and 4. At concurrency 4, the 8 MiB workload had a p95 of 213.22 ms across 500 measured jobs. It used the approved C count/sum fixture and verified bytes against an independent Python oracle. The direct empty-process reference excludes Unix-socket admission, guest isolation and publication. [Benchmark protocol](benchmarks/protocol.md)

The first full run hit the bounded filesystem limit. The rerun used a verified lossless compaction path after each successful shard teardown and preserved every raw attempt in the analysis population. The planned Rust min/max workload, comparable start clocks, per-job CPU and memory measurements, and the remaining workload matrix are still open. Full AC-021 remains open.
