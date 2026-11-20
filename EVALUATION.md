# Evaluation and benchmark plan

## Evidence semantics
PASS means the named command/assertion actually succeeded in the captured environment. FAIL means a real failing run. BLOCKED names an unavailable prerequisite. NOT RUN means no execution. NOT YET MEASURED applies to numerical results. A skipped native test does not make the native gate pass. Unit mocks may test failure handling; they cannot establish filesystem/network/process isolation.

Design capacity is 4 running +16 queued. Tested capacity is NOT YET MEASURED. Observed capacity is NOT YET MEASURED. Real-user/production scale is NONE ESTABLISHED. All fixture workloads are synthetic unless an explicitly licensed real workload is introduced. Seeded demo NDJSON contains generated public-safe records, not employer telemetry.

## Layers and independent oracles
Unit: state transitions, size accounting, strict framing, path grammar and request canonicalization. Contract: CLI/protocol/schema and setup nonce/FD handshake. Integration: real Unix socket, filesystem persistence and separate processes. System/acceptance: actual kernel namespaces/cgroups/policies on compatible Linux. Property: arbitrary event histories preserve terminal/quiescence and capacity invariants; artifact-path/canonicalization properties. Fuzz: protocol frames, JSON duplicate/unknown fields, artifact logical paths and persisted state parser. Security: named denied operations and external canary/listener observers. Fault injection: supervisor death, launch-step failure, storage errors, lost responses and cleanup delay. Performance: native runs, never mock timings. Clean environment: public-only checkout. Review: independent read-only findings before integration fixes.

Avoid copying implementation as oracle. Use external host canary/listeners, direct cgroup observations, standard filesystem metadata and deliberately different Python reference state model. Kernel failure injection is restricted to the owned job cgroup; never affect unrelated jobs. Compare count/sum/min/max NDJSON results against Python standard-library decimal/integer reference independently of Rust fixture code.

## Test-the-tests
Six mandatory targeted mutants: premature gate release; kill leader only; follow artifact symlink; terminal before cgroup empty; bypass missing-policy check; ignore fsync error. In an isolated disposable worktree: baseline PASS, introduce exactly one mutant, same test FAIL for the expected assertion, restore clean code, same test PASS. Record all three manifests and patch hash. Restore and verify tree hash before any merge. Do not inflate a mutation percentage using trivial code. Tooling-only mutations are not substitutes for native invariant mutations.

No deleting tests, weakening assertions, silently skipping/xfailing/quarantining, swallowing errors, fixture-specific hardcoding or changing workload until a preferred result appears. A genuine spec error needs TEST_SPEC_EXCEPTION_AC-###.md with evidence, impact and reviewer assessment; preserve the original lock. The phase/acceptance hash scripts must detect unapproved changes, not rewrite hashes.

## Benchmark matrix
|ID / claim|Workload and generator|Warmup / repetitions / concurrency|Instrument / summary|Controls / failure interpretation|
|---|---|---|---|---|
|B-01 launch overhead|Static exit0; direct process baseline versus complete HearthRun profile|30 warmups;1000 measured; concurrency1,2,4; five independent batches|monotonic_ns from submit to RUNNING and terminal; p50/p95/p99; failures separate and included in denominator|Same binary, host and cache state; random interleaving; no subtracting unexplained negative noise; slower than target is a finding|
|B-02 legitimate useful work|Seeded NDJSON16KiB/1MiB/8MiB; Rust integer aggregation, independently checked Python reference|5 seeds;30 warmups then100 repetitions/size; concurrency1,4|End-to-end and execution-only latency, throughput, CPU usage, peak memory|Record bytes, actual rows, digest, policy; exclude wrong results from performance success but retain their failed samples|
|B-03 cancellation|Spin, setsid+fork descendants, output flood|100 cancellations/type/seed;5seeds; concurrency1,4|Cancel receipt to kill request and confirmed cgroup-empty+reap; p50/p95/p99/max; cleanup_pending count|Uninterruptible states not hidden; target p95<=250ms is not a hard kill guarantee|
|B-04 resources/admission|Allocate to cap, fork to pids cap,20 admitted+one rejected|30 repetitions per profile;CPU trial>=10s|memory.events,pids.events,cpu.stat, supervisor RSS/FD count; exact admission bounds|Host reserve checked first; no unconstrained fork/allocation control outside disposable resource envelope|
|B-05 crash recovery|Kill supervisor at specified startup/run/export checkpoints|100 seeds/checkpoint plus deterministic barrier cases|Recovery duration, survivors, incorrect terminal records, leaked mounts/cgroups/FDs|SIGKILL simulation does not certify physical power-loss durability|
|B-06 lifecycle retention|1000 short jobs with rotating bounded outputs|5seeds;concurrency4|Disk bytes, orphan cgroups, open FDs, peak RSS and regression slope|Expect no unbounded growth after retention; disclose allocator/cgroup delayed reclamation|
|B-07 optional comparator|Same static binary/input and documented equivalent policy in NsJail/bubblewrap|Same schedule as B-01/02|Raw latency/resource comparison, policy-difference table|No ranking different threat boundaries as 'more secure'; gVisor/VM optional and not core gates|

Hardware record: CPU model/core count, RAM, kernel/version/boot ID, filesystem/mount options, cgroup controller files, Landlock ABI, seccomp mode, executable/config/policy digests, Rust version, optimization flags, source commit/dirty state, background load and power policy. Never dump entire environment or home paths. Keep kernel identifiers required for reproducibility; sanitize usernames/hostnames in public export.

Raw paths: verification/benchmarks/<run-id>/samples.jsonl, environment.json, summary.json and command manifests. Sample schema: run_id, workload, seed, sample_index, concurrency, bytes, submit_ns, start_ns, finish_ns, cancel_ns nullable, cleanup_ns nullable, status, exit_code nullable, max_rss_bytes nullable, cpu_usec nullable, output_digest nullable. Missing measurements stay null, never zero. Native evidence records must identify an actual runtime, not a simulator.

Summary uses nearest-rank quantiles on declared population, plus count/errors/min/max and batch medians. Report cross-batch variation. Bootstrap confidence intervals may be added with seed/repetitions disclosed; do not imply IID when samples share host state. Plot only actual raw files; axes include units and workload/config. A static HTML table and inline SVG chart suffice; no telemetry backend.

## Target table (not measured)
|Metric|Target|Release treatment|
|---|---|---|
|Empty-action p95 total overhead at concurrency1|<=100ms on reference Linux host|Investigate miss; no fabricated pass or universal promise|
|Cancellation p95 to confirmed cleanup|<=250ms on non-D-state fixtures|Report misses and cleanup_pending; correctness remains mandatory|
|Unsafe operation successes in named suite|0|Any success blocks matching isolation claim|
|Surviving descendants after confirmed cleanup|0|Any survivor is critical failure|
|Development footprint|<=15,000,000,000 bytes total attributable|Hard quota + complete accounting required for heavy setup|

An independent verifier receives canonical requirements, raw evidence, source and exact commands and tries to invalidate claims. The verifier is initially read-only, cannot fix the implementation while auditing, and must produce findings before Final Integrator patches. Same-session self-review is identified as such, not fabricated as a separate agent. Final release requires clean public-only reproduction and all applicable acceptance criteria, with human-bound optional integrations separately BLOCKED.
