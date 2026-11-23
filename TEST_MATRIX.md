# Test matrix

Research date: 2026-11-08. This table specifies required native evidence. None of the 24 full acceptance criteria has been established by the seed. Planned paths below are implementation destinations, not files claimed to exist. Portable tooling checks are tracked separately in VERIFICATION_REPORT.md.

| Requirement | Acceptance | Required test | Level | Negative control | Native evidence/status |
|---|---|---|---|---|---|
| FR-001 | AC-001 | `tests/acceptance_locked/protocol.rs` | contract | remove size/unknown-field guard | NOT RUN |
| FR-002 | AC-002 | `tests/acceptance_locked/admission.rs` | system | remove capacity increment | NOT RUN |
| SEC-001 | AC-003 | `tests/acceptance_locked/doctor.rs` | system | treat unavailable as supported | PARTIAL. Live admission refused seven missing-capability scenarios. A separate unsupported host and negative control remain open. |
| SEC-002 | AC-004 | `tests/acceptance_locked/barrier.rs` | system | release barrier before limits | NOT RUN |
| SEC-003 | AC-005 | `tests/acceptance_locked/filesystem.rs` | security | bind host canary into root | NOT RUN |
| SEC-003 | AC-006 | `tests/acceptance_locked/network.rs` | security | permit socket and share net namespace in isolated control | NOT RUN |
| SEC-005 | AC-007 | `tests/acceptance_locked/authority.rs` | security | retain synthetic control FD | NOT RUN |
| SEC-002 | AC-008 | `tests/acceptance_locked/seccomp.rs` | security | omit architecture check | NOT RUN |
| REL-005 | AC-009 | `tests/acceptance_locked/resources.rs` | system | omit pids.max | NOT RUN |
| REL-002 | AC-010 | `tests/acceptance_locked/cancel.rs` | fault injection | kill only leader | NOT RUN |
| REL-001 | AC-011 | `tests/acceptance_locked/terminal.rs` | contract/system | terminal before cgroup empty | NOT RUN |
| REL-003 | AC-012 | `tests/acceptance_locked/recovery.rs` | fault injection | auto-requeue interrupted job | NOT RUN |
| SEC-004 | AC-013 | `tests/acceptance_locked/artifacts.rs` | security | follow symlink | PARTIAL. Twelve direct artifact checks passed. Native negative control remains open. |
| SEC-004 | AC-014 | `tests/acceptance_locked/quiescence.rs` | system/property | start export before populated=0 | PARTIAL. All 1,000 native schedules passed. Independent negative control remains open. |
| REL-005 | AC-015 | `tests/acceptance_locked/streams.rs` | system | unbounded buffer growth | NOT RUN |
| REL-004 | AC-016 | `tests/acceptance_locked/publication.rs` | fault injection | ignore fsync error | PARTIAL. Direct faults, daemon ENOSPC recovery, result and terminal-journal rename uncertainty, and both ignored-fsync controls passed. |
| FR-005 | AC-017 | `tests/acceptance_locked/idempotency.rs` | integration | ignore payload digest | NOT RUN |
| FR-003 | AC-018 | `tests/acceptance_locked/profiles.rs` | security | hash then reopen mutable executable | NOT RUN |
| NFR-002 | AC-019 | `tests/acceptance_locked/reproduce.py` | clean environment | remove required fixture from export | PARTIAL. Fresh-clone scoped profile and missing-fixture control passed. Full native verification remains open. |
| NFR-003 | AC-020 | `verification/mutation/protocol.md` | mutation | test itself intentionally weakened | PARTIAL. Publisher ignored-fsync control passed. |
| PERF-001 | AC-021 | `benchmarks/protocol.md` | performance | drop failed/slow samples | PARTIAL. B-01, C count/sum and Rust B-02 measured. The omitted-slow-row control passed. Execution telemetry and remaining workloads are open. |
| SEC-006 | AC-022 | `scripts/public_audit.py` | release | add synthetic forbidden private path | NOT RUN |
| UX-001 | AC-023 | `tests/acceptance_locked/demo.rs` | end-to-end | render unescaped guest HTML | NOT RUN |
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
