# Project charter

HearthRun investigates bounded execution of operator-approved native tools on one trusted Linux host. Its defining invariant is that a terminal result cannot be published merely because the leading process exited: the launcher must be reaped, the job cgroup empty and the artifact publication outcome durable.

The intended users are developers and reviewers who need to inspect tool-run lifecycle behavior. The finishable core is a CLI, local supervisor, isolated launcher, checked artifact exporter, adversarial fixtures and reproducible evidence. AI-generated tools motivate the boundary; no AI model is needed in the product.

The project succeeds when its locked criteria have real evidence and a reviewer can reproduce the useful transformation, denied action and cancellation demos. It does not succeed by accumulating dependencies, badges or unmeasured claims. Current product status is incomplete; VERIFICATION_REPORT.md separates executed portable work from planned native behavior.
