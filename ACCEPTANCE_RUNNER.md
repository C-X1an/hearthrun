# Acceptance command

`make acceptance` dispatches three existing native positive checks, using existing reviewed binaries. It does not build or provision the host. Every invocation still reports all 24 locked criteria as incomplete. A scoped positive PASS establishes only the assertions in its existing script; all locked negative controls, broader suites and external review/release requirements remain separate. Historical evidence is not imported.

The dispatched commands are the same scripts/options wrapped at the locked acceptance paths:

| Criterion | Existing command | Scope |
|---|---|---|
| AC-002 | `tests/integration/scheduler.py --case admission` | Live four-plus-sixteen admission, typed refusal and FIFO |
| AC-010 | `tests/integration/scheduler.py --case cancel` | Owner cancellation and separate wall expiry of detached descendants |
| AC-023 | `tests/e2e/demo.py --check-report` | Actual transformation/denial/cancellation, saved report values/links and worker/wrapper cleanup; browser focus remains open |

Set these to existing absolute operator paths, then run from the public checkout:

```bash
HEARTHRUN_BIN_DIR=ABS_EXISTING_BIN_DIR \
HEARTHRUN_DOCTOR=ABS_EXISTING_DOCTOR \
HEARTHRUN_FIXTURE=ABS_EXISTING_STATIC_TASK \
HEARTHRUN_JOBS=ABS_EMPTY_OWNED_JOBS_PARENT \
HEARTHRUN_ACCEPTANCE_WORK=ABS_NEW_WORK \
TMPDIR=ABS_EXISTING_PRIVATE_TMP \
python3 -B scripts/acceptance.py
```

The same variables apply to `make acceptance`. Explicit `--bin-dir`, `--doctor`, `--fixture`, `--cgroup-root`, `--work` and `--tmp-root` flags are also available. Missing inputs or an unsupported host return 78 and emit the full locked denominator without starting native checks. Make normally translates a child 78 to exit 2.

The existing native harness performs its actual host/binary/delegated-cgroup preflight. The runner additionally requires non-root Linux x86-64, no supplementary groups, a fresh work root outside source, and an existing private TMPDIR on the same bounded noswap tmpfs (at most 12,000,000,000 bytes and 200,000 inodes). Work, child evidence and capture output remain under the new work root. Existing binaries are streamed into bounded SHA-256/identity records before and around each dispatch; no toolchain or cache is created. Use the project's already-reviewed bounded host invocation and total storage accounting before running it.

`evidence/` contains the actual `scripts/capture.py` records and bounded raw streams. `acceptance-summary.json` binds their exact commands, exits, source digests, binary identities and observed teardown to every criterion row. A changed source/binary, truncated/incomplete output, missing completion/teardown, capture failure or nonzero child stops further dispatch. Raw evidence and work are retained. Every criterion retains its original locked test path and negative-control text plus an explicit remaining-coverage description.

The capture exit is always preserved. The exact child exit is reported only when the capture supplies it without a launch failure, timeout, retained pipe or logging error; otherwise it is null, never inferred from capture exit 74/78/124. Unknown teardown stays UNKNOWN. A capture timeout kills the trusted command group and cannot prove native descendant cleanup; inspect the retained child state/journal and exact owned cgroup identities using the existing native teardown procedure before another run. The runner never adopts unknown job IDs to signal them.

Invalid capture provenance cannot establish child teardown. An interrupted active check is recorded against its actual criterion as FAIL with its planned command/work, null exits and UNKNOWN teardown; subsequent checks remain NOT RUN. The separate outer ownership check never upgrades that interrupted child's cleanup.

Exit 1 means failed or incomplete acceptance; exit 78 means a missing prerequisite; exit 74 means summary persistence failed. This scoped implementation has no success override and cannot exit zero, including when all three positives pass. It runs no mutants, new probes, network listeners, external automation or publication.
