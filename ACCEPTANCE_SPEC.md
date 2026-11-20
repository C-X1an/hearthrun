# Locked acceptance specification

acceptance_spec_locked: true

Canonical machine-readable definition: spec/acceptance.json. SHA-256 baseline: spec/acceptance.sha256. Changes require an explicit versioned exception; never regenerate a baseline to conceal weakening. These are product criteria; private orchestration controls are checked separately.

## AC-001 - FR-001
**Precondition:** Socket owned by current user  
**Input:** Oversize, duplicate keys, unknown fields, wrong version, peer UID mismatch  
**Behavior:** Reject before queue or execution  
**Expected Result:** Stable typed rejection; no job created  
**Tolerance:** exact  
**Test Level:** contract  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/protocol.rs  
**Negative Control:** remove size/unknown-field guard  
**Status:** NOT RUN  

## AC-002 - FR-002
**Precondition:** Four deliberately blocked running jobs and sixteen waiting  
**Input:** Submit twenty-first request  
**Behavior:** Reject QUEUE_FULL and preserve FIFO among queued jobs  
**Expected Result:** No over-admission or starvation on finite jobs  
**Tolerance:** exact  
**Test Level:** system  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/admission.rs  
**Negative Control:** remove capacity increment  
**Status:** NOT RUN  

## AC-003 - SEC-001
**Precondition:** Each mandatory feature disabled separately in disposable host/adapter and one real unsupported host  
**Input:** Submit approved action  
**Behavior:** Refuse with named missing capability  
**Expected Result:** No guest instruction executes; simulated probes not real isolation evidence  
**Tolerance:** exact  
**Test Level:** system  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/doctor.rs  
**Negative Control:** treat unavailable as supported  
**Status:** NOT RUN  

## AC-004 - SEC-002
**Precondition:** Instrumented pre-exec barrier with gate step failure injection  
**Input:** Action writes a sentinel on first instruction  
**Behavior:** Any missing setup step prevents sentinel  
**Expected Result:** cgroup and policy ready precede exec for every accepted run  
**Tolerance:** exact  
**Test Level:** system  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/barrier.rs  
**Negative Control:** release barrier before limits  
**Status:** NOT RUN  

## AC-005 - SEC-003
**Precondition:** Owned host canary outside staged tree  
**Input:** Probe reads host home, proc, socket and traversal targets  
**Behavior:** Deny reads/opens; host canary remains unchanged  
**Expected Result:** No content/FD leakage in result or streams  
**Tolerance:** zero leaks in named suite  
**Test Level:** security  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/filesystem.rs  
**Negative Control:** bind host canary into root  
**Status:** NOT RUN  

## AC-006 - SEC-003
**Precondition:** Local controlled TCP/UDP/Unix listeners outside guest  
**Input:** Probe outbound socket, connect, DNS and inherited descriptors  
**Behavior:** No outside connection succeeds  
**Expected Result:** Controlled listeners observe zero accepted guest messages  
**Tolerance:** exact  
**Test Level:** security  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/network.rs  
**Negative Control:** permit socket and share net namespace in isolated control  
**Status:** NOT RUN  

## AC-007 - SEC-005
**Precondition:** Host environment carries synthetic SECRET_CANARY and control FD  
**Input:** Guest lists env and enumerates open FDs  
**Behavior:** Only fixed allowlisted environment and stdin/stdout/stderr remain  
**Expected Result:** No secret or supervisor/control descriptor survives exec  
**Tolerance:** exact  
**Test Level:** security  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/authority.rs  
**Negative Control:** retain synthetic control FD  
**Status:** NOT RUN  

## AC-008 - SEC-002
**Precondition:** Supported x86-64 host, pinned syscall policy  
**Input:** Static fixtures request ptrace, bpf, mount, keyctl, io_uring and x32 ABI  
**Behavior:** Deny unsupported ABI and forbidden calls; approved fixture still works  
**Expected Result:** Expected errno or controlled termination, no host side effect  
**Tolerance:** exact  
**Test Level:** security  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/seccomp.rs  
**Negative Control:** omit architecture check  
**Status:** NOT RUN  

## AC-009 - REL-005
**Precondition:** Per-job memory/pids/CPU limits configured  
**Input:** Bounded fork, allocation, CPU and output-flood fixtures  
**Behavior:** Enforce limits and keep supervisor responsive  
**Expected Result:** Counters prove limits installed; no host instability or unlimited output  
**Tolerance:** CPU 1-core quota +/-15% over >=10s when measurable  
**Test Level:** system  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/resources.rs  
**Negative Control:** omit pids.max  
**Status:** NOT RUN  

## AC-010 - REL-002
**Precondition:** Running guest creates setsid and double-fork descendants  
**Input:** Cancel job and separately expire wall deadline  
**Behavior:** Kill whole cgroup, drain streams, reap init  
**Expected Result:** No surviving job process; job reaches cancelled or explicit cleanup_pending  
**Tolerance:** p95 cancellation target <=250ms, not guarantee  
**Test Level:** fault injection  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/cancel.rs  
**Negative Control:** kill only leader  
**Status:** NOT RUN  

## AC-011 - REL-001
**Precondition:** Cancellation attempted while cleanup observation is delayed  
**Input:** Query status repeatedly  
**Behavior:** Do not report final cancelled/success while populated or unreaped  
**Expected Result:** CLEANUP_PENDING retains slot and blocks unsafe export  
**Tolerance:** exact  
**Test Level:** contract/system  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/terminal.rs  
**Negative Control:** terminal before cgroup empty  
**Status:** NOT RUN  

## AC-012 - REL-003
**Precondition:** Guest active and job metadata fsynced  
**Input:** SIGKILL supervisor at each barrier/run/export phase, restart  
**Behavior:** Owned orphan jobs killed; interrupted result; no replay  
**Expected Result:** No untrusted survivors after confirmed recovery; uncertain jobs not success  
**Tolerance:** exact; cleanup may remain pending  
**Test Level:** fault injection  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/recovery.rs  
**Negative Control:** auto-requeue interrupted job  
**Status:** NOT RUN  

## AC-013 - SEC-004
**Precondition:** Retained output directory FD and empty/reaped cgroup  
**Input:** Symlink, hardlink, FIFO, socket, device, traversal, many files, oversize output  
**Behavior:** Reject unsafe artifacts; publish only permitted regular files  
**Expected Result:** No host traversal; output total <=32MiB and <=128 files  
**Tolerance:** exact  
**Test Level:** security  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/artifacts.rs  
**Negative Control:** follow symlink  
**Status:** NOT RUN  

## AC-014 - SEC-004
**Precondition:** Guest attempts late output replacement  
**Input:** Race cancellation/completion with artifact writes  
**Behavior:** Never export while writer lives; resolve from retained mount FD afterward  
**Expected Result:** Immutable result digest matches bytes; no unchecked reopened host pathname  
**Tolerance:** exact over >=1000 seeded schedules  
**Test Level:** system/property  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/quiescence.rs  
**Negative Control:** start export before populated=0  
**Status:** NOT RUN  

## AC-015 - REL-005
**Precondition:** Guest floods stdout/stderr with hostile terminal/HTML bytes  
**Input:** Run to configured stream cap  
**Behavior:** Continue bounded draining/discarding then terminate per policy; escape rendering  
**Expected Result:** Combined retained stream <=2MiB; event ring <=1024; truncation explicit  
**Tolerance:** exact  
**Test Level:** system  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/streams.rs  
**Negative Control:** unbounded buffer growth  
**Status:** NOT RUN  

## AC-016 - REL-004
**Precondition:** Filesystem fault adapter plus disposable nearly-full filesystem  
**Input:** Fail writes/fsync/rename at all publication points  
**Behavior:** No acknowledged success for uncommitted result; clean error/unknown record  
**Expected Result:** Previously published results readable; partial files never exposed as final  
**Tolerance:** exact  
**Test Level:** fault injection  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/publication.rs  
**Negative Control:** ignore fsync error  
**Status:** NOT RUN  

## AC-017 - FR-005
**Precondition:** Request ledger persisted; response loss simulated  
**Input:** Retry same ID/content, then changed content; restart and retry  
**Behavior:** Return same job without rerun; changed content conflicts  
**Expected Result:** At most one admitted job per request ID, no exactly-once external-effects claim  
**Tolerance:** exact  
**Test Level:** integration  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/idempotency.rs  
**Negative Control:** ignore payload digest  
**Status:** NOT RUN  

## AC-018 - FR-003
**Precondition:** Operator-installed approved profile with digest  
**Input:** Mutate source path concurrently, request unauthorized profile/host mount  
**Behavior:** Bind immutable staged verified bytes; deny unauthorized options  
**Expected Result:** Executed bytes equal approved digest; no client-specified host bind path  
**Tolerance:** exact  
**Test Level:** security  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/profiles.rs  
**Negative Control:** hash then reopen mutable executable  
**Status:** NOT RUN  

## AC-019 - NFR-002
**Precondition:** Fresh isolated checkout without private handoff or caches  
**Input:** Run documented bootstrap/build/check/demo/teardown  
**Behavior:** Product works on compatible host; unsupported host states precise reason  
**Expected Result:** Public repo includes tests and fixtures needed for reproduction  
**Tolerance:** exact  
**Test Level:** clean environment  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/reproduce.py  
**Negative Control:** remove required fixture from export  
**Status:** NOT RUN  

## AC-020 - NFR-003
**Precondition:** Correct implementation plus isolated deliberate mutants  
**Input:** Run pass/fail/pass for six critical invariant mutants  
**Behavior:** Tests fail for expected reason and worktree restored  
**Expected Result:** Killed barrier, descendant, symlink, terminal, policy and publication mutants  
**Tolerance:** all six required  
**Test Level:** mutation  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** verification/mutation/protocol.md  
**Negative Control:** test itself intentionally weakened  
**Status:** NOT RUN  

## AC-021 - PERF-001
**Precondition:** Recorded hardware/kernel/config/toolchain and stable host  
**Input:** 30 warmups +1000 empty jobs, 5 seeds real transform, concurrency1/2/4  
**Behavior:** Write raw samples and p50/p95/p99 with failures included  
**Expected Result:** Valid JSONL; no fabricated percentile or selected fastest run  
**Tolerance:** no hard speed gate before baseline; regressions investigated  
**Test Level:** performance  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** benchmarks/protocol.md  
**Negative Control:** drop failed/slow samples  
**Status:** NOT RUN  

## AC-022 - SEC-006
**Precondition:** Candidate release in fresh public-only checkout  
**Input:** Audit tracked files/history/dependencies/CI/docs/evidence  
**Behavior:** No secrets/private career notes or prohibited unsafe workflow  
**Expected Result:** Release checklist and dependency/license inventory with actual commands  
**Tolerance:** exact  
**Test Level:** release  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** scripts/public_audit.py  
**Negative Control:** add synthetic forbidden private path  
**Status:** NOT RUN  

## AC-023 - UX-001
**Precondition:** Real demo evidence and keyboard-only reader  
**Input:** Run legitimate transformation, denied action, cancellation and report  
**Behavior:** Show result/policy/cleanup distinctions without color-only meaning  
**Expected Result:** Escaped HTML, valid links, no screenshot fabricated before execution  
**Tolerance:** exact  
**Test Level:** end-to-end  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** tests/acceptance_locked/demo.rs  
**Negative Control:** render unescaped guest HTML  
**Status:** NOT RUN  

## AC-024 - NFR-003
**Precondition:** Read-only independent verifier receives claims/spec/source/tests  
**Input:** Attempt to invalidate all critical claims before fixes  
**Behavior:** Findings recorded, fixes separately integrated, checks rerun  
**Expected Result:** No self-authored report mislabelled independent execution  
**Tolerance:** exact  
**Test Level:** review  
**Evidence Type:** machine-captured command output and structured assertions  
**Test Path:** verification/independent-review.md  
**Negative Control:** omit initial findings stage  
**Status:** NOT RUN
