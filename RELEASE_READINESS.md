# Release readiness

**Candidate kind.** Experimental source preview. The product acceptance gate remains open. The runtime is an owner-operated Unix-socket service for a compatible disposable Linux host.

| Check | Evidence status |
|---|---|
| Locked contract and source checks | Captured PASS on the development checkout. |
| Native functional checks | Captured finite runs for staging, execution, cleanup, recovery, output, resource limits and an actual demo. |
| Dependency advisory scan | Captured PASS for the reviewed lockfile and RustSec snapshot. |
| Independent review | Scoped findings preceded watchdog, publication, memory-outcome, demo and export repairs. Full AC-024 review remains open. |
| Locked gate and mutation campaign | Open. Direct artifact and publication faults, real disk pressure and 1,000 seeded cleanup schedules were exercised. Daemon recovery after uncertain publication, delayed cleanup and the remaining mutation controls are outstanding. |
| Performance | The revised B-01 and C transformation campaign completed 36,750 scheduled rows. Full AC-021 remains open. |
| Clean candidate and remote CI | The clean source preview passed scoped local build, checks, integration, demo and teardown. The corrected portable and Rust workflows passed. |

Only source, synthetic fixtures, tests, documentation and reviewed public evidence belong in Git history. Raw local service logs and operating paths stay on the test host. The release audit checks tracked content, history and workflow permissions. The dependency report records the exact lockfile and declared licenses. [Verification](VERIFICATION_REPORT.md)
