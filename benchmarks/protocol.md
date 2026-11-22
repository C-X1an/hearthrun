# Bounded local benchmark protocol

The revised driver completed the native smoke and the full schedule described
below. The measured campaign and its limits are recorded in [Benchmarks](../BENCHMARKS.md).
Locked AC-021 remains unchanged. The instrumented B-01 and C transformation work
does not cover the entire `EVALUATION.md` matrix.

Use `campaign.py` only on the prepared, local compatible Linux host used by
`tests/e2e/native.py`. It performs no provisioning, compilation, downloads,
authentication, external writes or hostile-operation fixtures. Its only
transient removal is the exact owned successful-shard compaction below.
It imports the public native harness and public capture fingerprint
implementation, with no private package dependency. Standard library only.

## Prerequisites and bounded ownership

The caller is the scoped trusted UID, has no supplementary groups and supplies
existing normalized absolute paths to approved executable regular files. The
new work directory must be inside an actual OS-bounded `noswap` tmpfs of at most
12,000,000,000 bytes. Existing native preflight checks reject incompatible
storage, symlinked paths and unowned cgroup parents. The operator cgroup-v2 jobs
parent must initially have no children. Its directory descriptor and identity
are retained; recovery is restricted to exact journal-owned leaves.

The project's 15,000,000,000-byte total development budget and external overhead
must already be established by the operator. This script's tmpfs check is not
proof that source/toolchains/caches outside this mount satisfy that total.

One supervisor shard runs at a time. Timed shards use at most 128 unique native
request IDs, below Store's 256-entry limit. Each new shard gets a fresh private
state directory, profile install and staged input. Successfully stopped shard
transients are losslessly compacted after teardown. Shards are paced by
complete wave verification, teardown and compaction before
the next starts. A separate initial one-job shard exercises the approved
`hold` fixture, independent descendant readiness, cancellation and cleanup.
That control is not a cancellation performance campaign.

Each shard has a 900-second deadline, individual native wave 75 seconds,
direct wave 10 seconds, inherited 256-KiB per-process-stream capture limit and
8-MiB combined process/protocol capture budget. The campaign has a 24-hour
deadline and at most 40,000 rows. Before every new shard, actual `statvfs`
observations must report at least 268,435,456 available bytes and 16,384
available inodes, and are fsynced to `storage.jsonl`. A filesystem without a
reported inode bound refuses execution. These headroom thresholds are explicit
admission margins, not a promise that unrelated concurrent writers cannot
consume space. The hard tmpfs bound remains mandatory.

After each shard, the entire campaign tree is accounted conservatively using
max(apparent bytes, allocated blocks), with a separate retained inode count;
exceeding 2,000,000,000 bytes aborts the campaign. Directory/inode kernel
metadata is not fully represented by file block accounting, so the independent
free-inode and free-byte admission checks remain necessary. The campaign also
reserves 64 files of 65,536 bytes plus their directory for finalization, then
releases only those exact identity-checked files before final cleanup/summary.
This leaves a small byte/inode margin for salvage after a capacity failure;
it cannot guarantee finalization against arbitrary concurrent consumption.
Accounting and headroom are supplementary stops, not OS quotas.
Inputs are at most 8 MiB, reference-generation memory
is finite, and the tmpfs imposes the hard write boundary. Keep the parent
capture manifest outside the campaign work tree, on the same approved bounded
storage.

Normal teardown terminates/reaps owned subprocesses and requires no remaining
cgroup children. Any emergency journal-owned `cgroup.kill` recovery is a
teardown failure. A lost submit response is reconciled from the fresh shard's
validated catalog before cleanup. No existing state is reused. Interruptions
stop the campaign and retain evidence; do not silently resume into an old work
directory. Inspect and reconcile its owned resources before a new invocation.

## Pinned build and host record

Build once before measurement, with Rust **1.99.1** as pinned by
`rust-toolchain.toml`, `--release`, `--locked`, documented target/optimization
flags and the existing approved static fixture build procedure. Capture the
actual build with `scripts/capture.py`. The campaign never builds anything.
Supply an owner-reviewed build record JSON with these fields (placeholders
must be replaced with actual captured values):

```json
{
  "source_sha256": "<scripts.capture.source_digest(public_root)>",
  "rustc_verbose": "<complete actual rustc -vV output beginning rustc 1.99.1 >",
  "profile": "release",
  "optimization_flags": ["<actual effective flags and Cargo profile defaults>"],
  "target": "<actual target triple>",
  "build_command": ["<actual executable>", "<actual arguments>"],
  "capture_manifest_sha256": "<SHA-256 of captured build manifest>",
  "binary_sha256": {
    "hearthrun": "<actual binary SHA-256>",
    "hearthrun-supervisor": "<actual binary SHA-256>",
    "hearthrun-launcher": "<actual binary SHA-256>"
  }
}
```

The driver checks the source fingerprint and all three actual binary digests,
pinned rustc version prefix and required provenance fields. It does not itself
independently authenticate the operator's build-record assertions. Preserve
the actual referenced manifest and rustc output for independent review. Source
changes after compilation invalidate this record. Capture source/commit/dirty
state through the outer capture manifest; a missing Git commit remains null.

Supply a separate small host record JSON, containing actual observations:

```json
{
  "power_policy": "<observed governor/power mode and source>",
  "background_load_control": "<actual host-stability procedure>",
  "filesystem_mount_options": "<actual source/build/work filesystem options>",
  "landlock_abi": "<actual doctor/probe value and source>",
  "seccomp_mode": "<actual doctor/probe value and source>"
}
```

Do not dump an environment, hostname, username, home path or credential into
these files. The generated environment record records selected CPU information,
core count, RAM/proc memory counters, kernel, boot ID, cgroup controllers, work
mount options, start/end load, Python monotonic implementation, build/source
identity and fixture/doctor digests. Actual doctor output is retained in each
shard's command logs, inside its verified aggregate after successful
compaction. Review all raw records before public export.

## Exact commands

Run from the public product root. Replace every absolute placeholder with an
existing operator-owned path, except `ABS_NEW_SMOKE_WORK` and
`ABS_NEW_FULL_WORK`, which must not exist. The selected bounded filesystem must
hold both captured evidence and all shard work. No shell strings are passed
to guest workloads.

```sh
python3 scripts/capture.py --cwd . --out ABS_BOUNDED_CAPTURE_DIR --category benchmark-smoke --requirement AC-021 --timeout 3600 -- python3 -B benchmarks/campaign.py --mode smoke --bin-dir ABS_RELEASE_BIN_DIR --doctor ABS_DOCTOR --fixture ABS_APPROVED_STATIC_TASK --cgroup-root ABS_EMPTY_JOB_CGROUP_PARENT --build-record ABS_BUILD_RECORD_JSON --host-record ABS_HOST_RECORD_JSON --work ABS_NEW_SMOKE_WORK
python3 -B benchmarks/analyze.py --work ABS_NEW_SMOKE_WORK
```

Only after inspecting smoke output, result correctness, teardown and the
source/instrumentation limitations, run the full campaign:

```sh
python3 scripts/capture.py --cwd . --out ABS_BOUNDED_CAPTURE_DIR --category benchmark-full --requirement AC-021 --timeout 86500 -- python3 -B benchmarks/campaign.py --mode full --seed 21080 --bin-dir ABS_RELEASE_BIN_DIR --doctor ABS_DOCTOR --fixture ABS_APPROVED_STATIC_TASK --cgroup-root ABS_EMPTY_JOB_CGROUP_PARENT --build-record ABS_BUILD_RECORD_JSON --host-record ABS_HOST_RECORD_JSON --work ABS_NEW_FULL_WORK
python3 scripts/capture.py --cwd . --out ABS_BOUNDED_CAPTURE_DIR --category benchmark-analysis --requirement AC-021 -- python3 -B benchmarks/analyze.py --work ABS_NEW_FULL_WORK
```

Exit 78 means a missing host capability, not a benchmark pass. Other nonzero
exits mean a failure or interruption. A successful smoke is only a critical-path
smoke. A successful full invocation means its scoped assertions and scheduled
rows completed; it does not automatically pass AC-021 or unmeasured metrics.
Neither invocation changes the fail-closed `make bench` gate.

## Schedule and measurement populations

Full B-01: five batches, concurrency settings 1/2/4, each with 30 warmups then
1,000 measured empty jobs **for each** backend. The baseline directly executes
the exact same approved fixture with `empty`. Native runs the `empty` mode
through the complete configured profile and publication/cleanup path. Backend
wave order is reproducibly randomized from the declared campaign seed, group
and batch. There is no best-run selection or unexplained baseline subtraction.
30,900 total B-01 rows include 900 warmups and 30,000 measured rows.

Full B-02: five seeds 0..4, exactly 16 KiB/1 MiB/8 MiB inputs, concurrency
settings 1/2/4. Each group gets 30 warmups then 100 measured transformations.
This includes concurrency 2 to preserve locked AC-021 in addition to the
EVALUATION table's concurrency 1/4. There are 5,850 B-02 rows, including 1,350
warmups and 4,500 measured rows. Every 64-byte NDJSON row contains one seeded
integer in [-1,000,000,1,000,000] and whitespace padding before its newline.
Reference results come from independently decoding the generated bytes with
Python `json` and integer arithmetic. Input byte count, actual row count,
sum/min/max reference and SHA-256 are preserved in each shard. The native
approved C fixture's count and sum are checked exactly and its committed
artifact inventory and bundle digest are independently verified.

Smoke uses one B-01 batch and one B-02 seed, all sizes/settings, two warmups
then four measured samples per group/backend: 90 total rows. The separate hold
control is never in the B-01/B-02 populations.

Waves submit at most the selected concurrency count, poll their jobs to
terminal and verify every output before starting another wave. A final wave,
warmup boundary or shard boundary can have fewer jobs. `concurrency` is a
schedule setting; short empty jobs may complete before later wave submissions.
`running_seen_per_sweep` counts RUNNING observations in a sequential polling
sweep and **does not prove simultaneous execution**.

Native `submit_ns` is Python `monotonic_ns` just before the submit RPC;
`finish_ns` is immediately after inspect first observes a terminal state.
Only a matching durable record, successful exit, confirmed cleanup, missing
owned cgroup and independently verified result make that timed sample PASS.
All wave endpoints are observed before artifact verification or sample fsync,
which are outside those intervals. Polling, scheduling and protocol client
work remain included. `artifact_verified_ns` separately marks verification.
Direct `submit_ns` precedes `Popen`; `finish_ns` follows the first observed
reaped exit while polling all owned children. Process creation/reaping and
polling are included. The two baselines have different client/IPC costs and
different containment boundaries; the difference is not isolated kernel
launch overhead. Direct baseline policy is `DIRECT_NO_SANDBOX`.

Native `start_ns` is the journal's **supervisor-relative** Rust Instant count.
It cannot be subtracted from Python's monotonic epoch. `observed_running_ns`
is a separate optional client observation. No fabricated submit-to-RUNNING or
execution-only latency is derived. `execution_only_ms`, `cpu_usec`,
`max_rss_bytes`, `cancel_ns` and `cleanup_ns` stay null when not measured. B-02
per-job end-to-end useful throughput is input bytes divided by its successful
submit-to-terminal interval; this is not aggregate host throughput.

## Evidence, failures and analysis

`environment.json`, `schedule.json`, `attempts.jsonl`, `samples.jsonl` and
`summary.json` live under the new work directory. Per-shard `input.json`,
`stage.json`, protocol request/response JSONL, `teardown.json`, the separate
held-job control and `shard-summary.json` remain as individual essential
evidence. Native successful results additionally append their checked durable
record, exact metadata bytes, streams and artifact bytes to one fsynced
`verified-results.jsonl` per shard after wave endpoints have been observed.
Each such record is bounded to 16 KiB. This preserves those verified bytes even
when the supervisor's ordinary 100-result retention removes an older bundle
within a 128-request shard. This logging remains outside timed intervals.
`attempts.jsonl` fsyncs an intent before each
attempt; every completed attempt has a unique `run_id` in `samples.jsonl`.
The analyzer rejects duplicates, dropped identities, missing scheduled rows,
changed timing fields and nonfinite durations. A killed driver can leave
unmatched intents; these remain visible and analysis fails rather than
inventing completion times. Retain the partial run as failed evidence.

A successful shard additionally retains `transients.tar.gz`,
`transients-index.json` and `compaction.json`. Only its exact `state`, `logs`,
`tmp` and `data.ndjson` roots are eligible. Every regular-file byte, including
command stdout/stderr, staged inputs, durable records and result artifacts
still present at teardown, is stored losslessly in the aggregate. Normal
runtime result evictions are retained as their authentic tombstones, and the
verified-results aggregate preserves the earlier checked result bytes.
The index preserves paths, types, modes,
sizes and file SHA-256 values, plus the aggregate digest. An exact stale
owner-only `state/control.sock`, if present after shutdown, has only metadata
and is recorded as such rather than represented as file content. Other special
objects, symlinks, cross-device objects and foreign/writable ownership refuse
compaction. Limits are 12,000 entries, 64 MiB per file and 128 MiB total file
content per shard; the aggregate digest reader is bounded to 64 MiB.

Compaction requires successful workload completion, verified teardown, all
owned children reaped and output pipes closed. The driver fsyncs and rereads
the aggregate, checking every indexed member and content digest, then fsyncs
the index before reclaiming any original. Removal walks retained directory
descriptors without following links and checks each exact device/inode/mode
before unlink or empty-directory removal. It never recursively deletes an
unvalidated pathname. `compaction.json` is written only after removal completes.
The per-shard summary binds the ordered raw sample IDs and canonical row
digest. The analyzer verifies that binding and every archive member without
extracting files; native transformation artifact hashes remain tied to sample
observations and the retained independent count/sum reference. The analyzer
recomputes each verified result bundle digest and requires either matching
retained metadata or the exact indexed eviction marker.

Failed workloads or teardown retain their original diagnostic state/logs and
are never compacted. A compaction interruption retains the archive/index and
any originals not yet removed; it cannot produce a passing completion marker.
No attempt, sample, slow observation or failure denominator is removed by
compaction. Capacity or summary-finalization failures emit a nonzero result
with an explicit error; partial raw evidence stays available for inspection.

Failures, wrong output and slow samples are retained. Any fatal wave error
records all already-planned wave attempts, including nullable timings for work
not submitted, then stops after bounded teardown. Never rerun into the same
directory, omit failed shards or replace these raw files with a faster run.
Later complete runs are separate evidence, not erasure of earlier failures.

Summary strata include workload, warmup/measured phase, backend, input size,
concurrency and exact native policy digest; never combine distinct policies or
environments. Successful-latency quantiles use nearest rank. An additional
all-attempt observed-duration distribution includes timed failures and is
explicitly not successful performance; untimed attempts remain counted. Counts,
failure fractions, min/max and per-batch medians/cross-batch range accompany
p50/p95/p99. p99 below 1,000 successes is labelled exploratory. Warmups remain
in raw evidence and their own summary strata, not the measured population.
Samples sharing a host/cache are not assumed IID. Do not claim confidence
intervals or universal speed guarantees from this campaign.

`scripts/benchmark_summary.py` is a smaller compatible success-population
summarizer for finite-duration, single-environment/policy rows. It cannot alone
validate this campaign's schedule or preserve null untimed attempts. Use the
campaign analyzer for the complete evidence, including failure denominators.

## Remaining gates and truthful scope

The current fixture is C, not the planned Rust aggregation implementation, and
returns count/sum, not min/max. The reference records all four; only count/sum
are certified by observed native output. Execution-end, CPU and peak-memory
telemetry are unavailable. Fresh shards reset supervisor caches and introduce
cold-state effects. Record those differences with any numbers reported.
B-03/B-04/B-05/B-06/B-07, the failed/slow-sample-dropping negative control,
independent findings-before-repair review, stable-host confirmation and
public-only reproduction remain separate gates. No native results or AC-021
PASS have been claimed by this implementation task.
