# Verification contract

The authoritative behavior is `spec/acceptance.json`, its stored SHA-256 and `ACCEPTANCE_SPEC.md`. A tool cannot establish a result by editing a status table. The evidence runner captures actual commands and output; the reviewer checks that the command measured the stated property. A zero exit code alone is not a security argument.

## Run protocol

```bash
python3 scripts/capture.py --cwd . --out verification/runs --category tooling --requirement NFR-003 -- make tooling-test
python3 scripts/capture.py --cwd . --out verification/runs --category rust-unit --requirement REL-001 -- python3 scripts/require_tool.py cargo test --workspace --locked
```

Capture records run ID, actual command, relative working directory, commit when present, dirty state, source digests before/after, allowlisted OS/kernel/Python fingerprint, UTC times, monotonic duration, exit status, bounded raw output and hashes. Before a Git repository exists the commit is null; a source digest is not misrepresented as a commit. Output beyond the retention cap is explicitly truncated. Commands may not contain credentials. Logs are private until reviewed. The runner executes trusted verification commands; it is NOT an untrusted-code containment mechanism.

Evidence statuses: PASS, FAIL, BLOCKED, NOT RUN and NOT YET MEASURED. Exit78 means a missing dependency/capability, not success. A Make wrapper may translate a child exit78 to exit2; the captured child record or diagnostic supplies the reason. A denied security attack passes only when independently observed host invariants remain intact.

## Integrity rules

Do not delete failing tests, weaken assertions, silently skip/xfail/quarantine, suppress exceptions, copy implementation algorithms into an alleged independent oracle, insert fixture-specific production branches, fabricate screenshots or manually author output claimed to have been executed. New stricter tests are welcome. A genuinely erroneous locked criterion needs `TEST_SPEC_EXCEPTION_<ID>.md` with evidence, original criterion, proposed correction, impact and an independent assessment. Preserve its history; do not rewrite the lock to hide disagreement.

## Test the tests

For each native mutant: create a disposable worktree; record correct PASS; introduce exactly the intended defect; run the same test and require FAIL for the expected assertion; restore; prove a clean diff; rerun and require PASS. Required native mutants target pre-exec barrier, all-descendant cancellation, symlink export, premature terminal state, policy enforcement and ignored publication/fsync errors. Keep failed stdout/stderr and exact patch. Do not compute an inflated mutation score over trivial formatting mutations.

The six portable handoff-tool mutations are useful but cannot substitute for native AC-020. A test suite that never touches a real cgroup cannot establish descendant containment.

## Independent review and repair

Before edits, a separately executed read-only verifier receives the public specs, claims, source and exact test commands. It must record findings first. Ask: what could pass these tests while still being broken? Can guest code run before limits? Can a leaked descriptor bypass a pathname policy? Can a late writer race export? Can a supervisor crash leave children alive? Does the benchmark include failures and equivalent policies? Is clean setup missing a private file?

Classify CRITICAL/HIGH/MEDIUM/LOW/INFO. The integrator separately fixes validated material findings, adds regression tests and reruns affected and full checks. An orchestrator's self-review is not an independent review. Scoped independent work has run. The full release review remains open.

## Clean reproduction and CI

A fresh public-only checkout without private research must run bootstrap, format, lint, type analysis, unit, contract, integration, acceptance, bounded fuzz/property/security, actual demo and teardown. Dependency/advisory network outages remain BLOCKED. The portable and Rust source workflows passed on the corrected first preview. [Release readiness](RELEASE_READINESS.md)

Future native CI runs on an approved commit in a disposable compatible Linux environment. Never run hostile-code fixtures with powerful credentials or privileged persistent self-hosted runners triggered by untrusted PRs. Review workflow changes before promotion. Read-only token permissions, SHA-pinned actions, no persisted checkout credentials and bounded runtime are required. Hosted-runner capability is probed, not assumed.

## Failure recovery

Dependency failure: inspect platform/version/network, choose supported compatible dependency and preserve the locked behavior. Flake: retain all failures, reproduce repeatedly and fix the deterministic cause; retries are not a repair. API outage: mark real integration BLOCKED, use a clearly labelled contract fixture and continue. State migration failure: reproduce clean and upgrade paths; no undocumented manual database edits. CI discrepancy: compare runner/kernel/permissions/toolchain; keep evidence. Noisy benchmark: report variance and increase repetitions, never select a best run. Merge conflict: integrator owns resolution and re-verification. Weak executor output: reject structural defects and escalate model capability. Corrupt workspace: preserve useful diffs/logs and recover through a clean checkout, not a silent reset of unrelated work.

## Authored workflow lanes

`source-checks.yml` runs portable tooling and compiles the C doctor. `rust-checks.yml` installs the pinned toolchain on an ephemeral hosted runner and checks the Rust workspace. `native-acceptance.yml` is manual and requires a reviewed commit already in main history plus a compatible disposable host. The operational doctor probes actual delegated cgroup and kernel controls. Only the locked acceptance run can establish the full suite. Heavy benchmarks and mutation campaigns use explicit reviewed runs.

## Explicit extended commands

`make property` and `make fuzz` run deterministic domain and parser checks. `make public-audit` checks tracked paths, history and workflow policy. `make dependency-audit` needs the real audit tool and an existing current advisory snapshot. `make sbom` and `make license-audit` use the resolved locked graph. `make clean-verify` exercises the implemented profile in a fresh clone. The full mutation, acceptance and clean-verification gates remain open. [Operations](OPERATIONS.md) · [Benchmark protocol](benchmarks/protocol.md)

The scoped `make acceptance` command runs the actual admission, cancellation and report-aware demo checks. It reports each native outcome separately and returns a nonzero aggregate while the locked inventory remains incomplete. [Acceptance command](ACCEPTANCE_RUNNER.md)
