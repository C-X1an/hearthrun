# HearthRun product requirements

Version 1.0; single-host experimental execution workbench; acceptance_spec_locked: true.

## Thesis and user
A developer or agent-tool integrator submits an approved native action against bounded files, then inspects exactly what ran, which authority it received, why it stopped and whether cleanup was confirmed. The trusted operator owns the host and profiles. Guest code and input/output bytes are untrusted. The local caller is an authorized same-UID user, not a hostile remote tenant.

## Jobs, stories and scope
The primary story is a deterministic static-native NDJSON summarizer consuming /in/data.ndjson and writing /out/summary.json. The same client can exercise benign adversarial probes and cancel runaway descendants. An operator can reproduce an execution, see missing host features before execution and distinguish request accepted from action successful. A reviewer can follow a two-minute demo without accounts or model keys.

Core includes operator-installed profiles, Unix-socket supervisor, launch protocol, namespace/policy setup, bounded scheduler, cancellation/recovery, artifact publication, CLI, native probes, evidence tooling and static report. Optional work after core acceptance: approved additional static tools, baseline comparison adapters, richer report, ARM64 port, dynamic-linker profile with its own threat review. Optional work must not silently become a prerequisite for core completion.

## Requirements
- **FR-001** Bounded version-1 local protocol with unknown-field rejection, stable error codes and same-UID peer admission.
- **FR-002** FIFO bounded admission: 4 running jobs and 16 waiting jobs; admission rejection has no execution side effect.
- **FR-003** Execute only operator-approved static x86-64 ELF profiles and immutable staged inputs; no arbitrary host paths or shell command strings.
- **FR-004** Expose submit, inspect, cancel, events and result export through a local CLI and owner-only Unix socket.
- **FR-005** Request identity survives restart: same ID and same canonical payload return the prior job; a different payload conflicts; uncertain work is never replayed automatically.
- **SEC-001** Refuse execution unless every mandatory kernel and delegation feature actually passes a disposable feature probe.
- **SEC-002** Untrusted code cannot run before cgroup placement, limits, namespace/root construction, no_new_privs, privilege drop, Landlock, seccomp and descriptor closure complete.
- **SEC-003** Guest has read-only approved executable/input, private bounded output, no host home/proc/cgroup/device/socket visibility and no network access.
- **SEC-004** Artifacts are exported only after all untrusted processes are gone, using descriptor-relative resolution and regular-file/link/count/byte checks.
- **SEC-005** All secrets, host environment and control descriptors are excluded from guests; logs and filenames are untrusted data, not instructions or HTML.
- **SEC-006** Dependency, CI, license, secret and public-file audits are required before release. No privileged untrusted-PR jobs.
- **REL-001** Terminal completion requires the launcher to be reaped AND the job cgroup to report populated=0 AND artifact publication outcome to be recorded.
- **REL-002** Cancellation kills the job cgroup, including setsid/double-fork descendants, rather than only its process group.
- **REL-003** Supervisor death/restart causes orphan cleanup and explicit interrupted/unknown outcomes, never assumed success or automatic resubmission.
- **REL-004** Results are atomically published after fsync; storage failure, malformed state or incomplete recovery must not produce a successful terminal record.
- **REL-005** Output streams, event retention, queue entries, inputs, artifacts and persistent storage have enforceable limits and teardown behavior.
- **PERF-001** Measure native empty-action startup, legitimate task overhead, cancellation latency, queue behavior, RSS and cleanup under declared hardware and policy; targets are not observations.
- **NFR-001** Core is Linux x86-64 with kernel >=6.6 plus feature probes; no credential, model API, database, Docker or cloud account needed on a compatible host.
- **NFR-002** A fresh checkout supports documented build, checks, local demo and teardown; unsupported environments report BLOCKED, not PASS.
- **NFR-003** Every material claim maps to actual machine-captured evidence. Negative controls demonstrate critical tests can detect defects.
- **UX-001** CLI is keyboard-native and readable without color; report is static, escaped HTML with semantic headings and text alternatives; every result shows policy and environment identity.

## Invariants and default budgets
A job never executes before the barrier succeeds. One request identity names one payload/job. A job is not complete merely because its leader exited. No artifact is published while guest descendants can write it. Failure to know the execution outcome is explicit. Mandatory policy cannot be downgraded. Guest control data cannot become a host pathname or executable command.

Design capacity (not measured): one supervisor; four active slots; sixteen queued; 256MiB memory per guest including tmpfs; 32 pids including launcher/init; CPU quota 100000/100000 per active job; swap disabled; wall time 10s default, 60s maximum; request JSON <=64KiB; input total <=16MiB, <=128 regular files; output tmpfs <=32MiB and <=256 inodes; exported <=128 regular files, <=32MiB; argv <=32 items/4096 total bytes; two retained streams <=1MiB each; events1024/job; last100 jobs or1GiB persistent results, whichever smaller. Limits include launcher overhead and must be tested at boundary values. Queue wait timeout30s; launch handshake3s; cancellation acknowledgement100ms target; cleanup250ms p95 target excluding uninterruptible kernel state. No request-rate, uptime or production-use claim exists.

The unit for device constraint is decimal bytes: total project-attributable development usage <=15,000,000,000. Use a <=12,000,000,000-byte hard-quota working area with <=3,000,000,000 reserved for external installation/metadata and safety headroom. This is a development constraint, not a guest-memory limit. A polling script is not a hard disk quota; fail heavy setup until quota/budget provenance is established.

## Reliability, privacy and portability
State format is versioned. One owning supervisor holds an exclusive state lock; unsupported format/corruption refuses mutation. Canonical request payload, ID and job intent are persisted before acknowledgement. Crash recovery preserves UNKNOWN/INTERRUPTED rather than rerunning. Results are retained locally; no telemetry leaves the host. Inputs, output and logs can contain sensitive content; default demo uses synthetic data only, owner permissions0700/0600. Retention does not imply secure erasure. Backups require stopped service and no active jobs.

Supported execution environment: Linux x86-64, kernel>=6.6 with verified features, cgroup-v2 delegation and user-namespace policy allowing the required mounts. WSL2/containers are not assumed compatible: doctor decides. Other operating systems can read reports and run portable contract/tooling checks, not claim native containment. Interface is versioned JSON with strict fields and typed errors; no internet port.

## Failure and edge cases
Full queue rejects before admission. Cancellation of a queued job removes it without launching; repeat cancel is idempotent. Cancel during startup denies release of the barrier. Cancel versus normal exit is resolved by recorded event ordering under one scheduler owner; success can win only if terminal completion was committed first. Output flood is bounded and explicit. Disk full, fsync failure, corrupt records, forged descriptors, missing controllers, fork bombs, symlink swaps, late descendants, PID reuse and supervisor death have named acceptance tests. D-state tasks can remain CLEANUP_PENDING; quarantine their slot and refuse unsafe reuse.

## Non-goals
Not a kernel-exploit boundary, public multi-tenant service, container standard, microVM hypervisor, Windows sandbox, shell-as-a-service, workflow engine, authorization-token system, network proxy, prompt-injection detector, LLM product or production availability promise. No claimed advantage over mature sandboxes without equivalent measured configurations.
