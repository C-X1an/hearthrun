# ADR-0003-completion: Completion requires verified cleanup

Status: accepted design, implementation pending.

## Context
A leader can exit while descendants or output writers remain. Cancellation requests may not immediately reap every task.

## Decision drivers
Truthful status, no unsafe export, resource-accounting integrity.

## Options
Leader exit; process-group kill; arbitrary grace sleep; cgroup ownership with reaping observation.

## Decision
Require launcher reaped and cgroup populated=0 before export; retain CLEANUP_PENDING and its slot otherwise.

## Consequences
Admission capacity may remain quarantined rather than pretending resources are free.

## Risks
Kernel uninterruptible tasks can retain resources; there is no universal bounded kill guarantee.

## Revisit when
Revisit with additional operational recovery needs, never by reporting unobserved cleanup as success.
