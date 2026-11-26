# Test matrix

The locked acceptance specification defines the required paths and assertions. The evidence column records the scope actually verified. See the verification report for capture identities and portable tooling results.

| Requirement | Acceptance | Required test | Level | Negative control | Native evidence/status |
|---|---|---|---|---|---|
| FR-001 | AC-001 | `tests/acceptance_locked/protocol.rs` | contract | remove size/unknown-field guard | PARTIAL. Live daemon malformed frames and the real kernel UID comparison passed on the owned socket. The independent size/unknown-field negative control remains open. |
| FR-002 | AC-002 | `tests/acceptance_locked/admission.rs` | system | remove capacity increment | PARTIAL. The locked native test verified four live holders around the retryable rejection, an unchanged catalog and FIFO across all sixteen queued jobs. B-04 independently passed 30 admission trials. The locked negative control remains open. |
| SEC-001 | AC-003 | `tests/acceptance_locked/doctor.rs` | system | treat unavailable as supported | PARTIAL. Live admission refused seven missing-capability scenarios. A separate unsupported host and negative control remain open. |
| SEC-002 | AC-004 | `tests/acceptance_locked/barrier.rs` | system | release barrier before limits | NOT RUN |
| SEC-003 | AC-005 | `tests/acceptance_locked/filesystem.rs` | security | bind host canary into root | NOT RUN |
| SEC-003 | AC-006 | `tests/acceptance_locked/network.rs` | security | permit socket and share net namespace in isolated control | NOT RUN |
| SEC-005 | AC-007 | `tests/acceptance_locked/authority.rs` | security | retain synthetic control FD | NOT RUN |
| SEC-002 | AC-008 | `tests/acceptance_locked/seccomp.rs` | security | omit architecture check | NOT RUN |
| REL-005 | AC-009 | `tests/acceptance_locked/resources.rs` | system | omit pids.max | PARTIAL. B-04 measured actual memory, PID and CPU caps across 30 trials each. Native stream limits passed. The locked negative control remains open. |
| REL-002 | AC-010 | `tests/acceptance_locked/cancel.rs` | fault injection | kill only leader | PARTIAL. The locked native owner cancellation and separate wall expiry checks both verified detached membership, whole-group removal, launcher reaping and protected results. The locked negative control remains open. |
| REL-001 | AC-011 | `tests/acceptance_locked/terminal.rs` | contract/system | terminal before cgroup empty | PASS. Five populated and five unreaped observations retained the slot and refused results. The isolated early-terminal control failed while the kernel still reported a populated cgroup. |
| REL-003 | AC-012 | `tests/acceptance_locked/recovery.rs` | fault injection | auto-requeue interrupted job | PASS for 12 deterministic cuts using the native test supervisor and production restart. The isolated replay control produced an unexpected durable execution, and restoration passed. |
| SEC-004 | AC-013 | `tests/acceptance_locked/artifacts.rs` | security | follow symlink | PARTIAL. Twelve direct artifact checks passed. Native negative control remains open. |
| SEC-004 | AC-014 | `tests/acceptance_locked/quiescence.rs` | system/property | start export before populated=0 | PARTIAL. All 1,000 native schedules passed. Independent negative control remains open. |
| REL-005 | AC-015 | `tests/acceptance_locked/streams.rs` | system | unbounded buffer growth | PASS. Live output retained exactly 1 MiB per stream with explicit truncation and escaped excerpts. Synthetic rollover through the real scheduler retained 1,024 events. The exact buffer control failed and passed after restoration. |
| REL-004 | AC-016 | `tests/acceptance_locked/publication.rs` | fault injection | ignore fsync error | PARTIAL. Direct faults, daemon ENOSPC recovery, result and terminal-journal rename uncertainty, and both ignored-fsync controls passed. |
| FR-005 | AC-017 | `tests/acceptance_locked/idempotency.rs` | integration | ignore payload digest | PASS. Lost replies, changed requests and both restart paths verified. The isolated payload-comparison control failed at the changed-argument conflict assertion, then passed after restoration. |
| FR-003 | AC-018 | `tests/acceptance_locked/profiles.rs` | security | hash then reopen mutable executable | PARTIAL. Native verified output and profile identity survived replacement of the copied operator source. Three typed refusals left no execution state. The internal hash-to-exec negative control remains open. |
| NFR-002 | AC-019 | `tests/acceptance_locked/reproduce.py` | clean environment | remove required fixture from export | PARTIAL. Fresh-clone scoped profile and missing-fixture control passed. Full native verification remains open. |
| NFR-003 | AC-020 | `verification/mutation/protocol.md` | mutation | test itself intentionally weakened | PARTIAL. The premature-terminal and ignored-fsync controls passed. |
| PERF-001 | AC-021 | `benchmarks/protocol.md` | performance | drop failed/slow samples | PARTIAL. B-01, C count/sum, Rust B-02, client-observed cancellation, the four B-04 profiles and B-06 retention measured. The omitted-slow-row control passed. Server clocks and remaining workloads are open. |
| SEC-006 | AC-022 | `scripts/public_audit.py` | release | add synthetic forbidden private path | PASS for the audited source preview. The forbidden-path control refused the staged file, restoration passed, and 38 components had declared licenses. |
| UX-001 | AC-023 | `tests/acceptance_locked/demo.rs` | end-to-end | render unescaped guest HTML | PARTIAL. The locked native wrapper verified the worker, teardown, actual report values and eleven local links. The portable inert-markup control detected disabled escaping. A browser keyboard and focus check remains open. |
| NFR-003 | AC-024 | `verification/independent-review.md` | review | omit initial findings stage | NOT RUN |

## Additional levels

| Level | Purpose and gate |
|---|---|
|Unit|Pure state, path and framing checks passed on the pinned Rust toolchain.|
|Contract|Strict JSON duplicate keys and unknown fields; actual peer credentials and framing, not serialization round trips alone.|
|Integration|Real supervisor/launcher/Unix socket/result store, no replacement by mocks.|
|Acceptance|All 24 locked criteria, with requirement-specific assertions.|
|End-to-end|CLI submit, legitimate transformation, denial, cancellation, actual report and teardown.|
|System|Kernel controls, admission, all descendants, bounded resources on a compatible host.|
|Property|1,000 seeded lifecycle/artifact interleavings with independent invariant oracle and shrinking.|
|Fuzz|Bounded parser/path/state mutation campaigns; preserve seed, corpus and failures.|
|Mutation|Six native pass/fail/pass critical mutants; portable guard mutations are a separate result.|
|Security|Host canaries, network listeners, inherited-FD probes, syscall/ABI negative fixtures, output tricks.|
|Performance|Seven workloads, raw samples including failures, declared hardware and policy, no selected fastest run.|
|Fault injection|SIGKILL supervisor, delayed cleanup, short writes, fsync/rename/full-disk failures.|
|Clean environment|Public-only checkout on independently provisioned compatible Linux; install/build/check/demo/teardown.|

Every high-criticality requirement has a locked acceptance path above. FR-004 is exercised through AC-001/010/017/023; NFR-001 through AC-003/019. A passing test of a helper does not discharge a full-system requirement.
