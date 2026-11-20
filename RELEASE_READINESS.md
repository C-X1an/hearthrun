# Release readiness

**Candidate kind.** Experimental source preview. The product acceptance gate remains open. The runtime is an owner-operated Unix-socket service for a compatible disposable Linux host.

| Check | Evidence status |
|---|---|
| Locked contract and source checks | Captured PASS on the development checkout. |
| Native functional checks | Captured finite runs for staging, execution, cleanup, recovery, output, resource limits and an actual demo. |
| Dependency advisory scan | Captured PASS for the reviewed lockfile and RustSec snapshot. |
| Independent review | Scoped findings preceded watchdog, publication, memory-outcome, demo and export repairs. Full AC-024 review remains open. |
| Locked gate and mutation campaign | Open. Full storage-fault, delayed-cleanup and quiescence schedules are outstanding. |
| Performance | Benchmark smoke passed. The first full campaign exhausted its development storage allocation. |
| Clean candidate and remote CI | Tracked separately as actual runs become available. |

Only source, synthetic fixtures, tests, documentation and reviewed public evidence belong in Git history. Raw local service logs and operating paths stay on the test host. The release audit checks tracked content, history and workflow permissions. The dependency report records the exact lockfile and declared licenses. [Verification](VERIFICATION_REPORT.md)
