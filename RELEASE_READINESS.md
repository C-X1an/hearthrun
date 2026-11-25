# Release readiness

**Candidate kind.** Experimental source preview. The product acceptance gate remains open. The runtime is an owner-operated Unix-socket service for a compatible disposable Linux host.

| Check | Evidence status |
|---|---|
| Locked contract and source checks | Captured PASS on the development checkout. |
| Native functional checks | Captured finite runs for staging, execution, cleanup, recovery, output, resource limits and an actual demo. |
| Dependency advisory scan | Captured PASS for the reviewed lockfile and RustSec snapshot. |
| Independent review | Scoped findings preceded watchdog, publication, memory-outcome, demo and export repairs. Full AC-024 review remains open. |
| Locked gate and mutation campaign | Open. Direct artifact and publication faults, daemon recovery after ENOSPC, result and journal rename faults, 1,000 seeded cleanup schedules, delayed cleanup and lost replies were exercised. The 12 deterministic recovery checkpoints and their replay control passed. Native stream caps and scheduler rollover passed. The full six-mutant campaign and seeded recovery benchmark remain outstanding. |
| Performance | B-01 and C transformation completed 36,750 scheduled rows. Rust B-02 completed 3,900 rows and an independent raw replay. B-03 completed 3,000 client-observed cancellations. B-04 completed 120 resource and admission trials. B-06 completed 5,000 retention jobs with independent reconstruction. Positive late RSS slopes and the remaining benchmark matrix stay open. |
| Demo accessibility | The actual demo and 11 static links passed. Local browser keyboard and focus observations remain pending. |
| Clean candidate and remote CI | The clean source preview passed scoped local build, checks, integration, demo and teardown. The corrected portable and Rust workflows passed. |

Only source, synthetic fixtures, tests, documentation and reviewed public evidence belong in Git history. Raw local service logs and operating paths stay on the test host. The release audit checks tracked content, history and workflow permissions. The dependency report records the exact lockfile and declared licenses. [Verification](VERIFICATION_REPORT.md)
