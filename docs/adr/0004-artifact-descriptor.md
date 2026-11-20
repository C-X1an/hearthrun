# ADR-0004-artifact-descriptor: Retain output FD and export after quiescence

Status: accepted design, implementation pending.

## Context
The private output mount can disappear with the guest namespace, and pathname checks can race with guest writes.

## Decision drivers
No live writer during export; explicit mount lifetime; constrained path resolution.

## Options
Host bind-writable output; pathname reopen; retained directory descriptor.

## Decision
Validate and retain output-directory FD before exec; export after cleanup using descriptor-relative restrictions and strict file/byte/link checks.

## Consequences
The exporter holds a capability with intentional lifetime; ownership/closure must be tested.

## Risks
Hostile special files, descriptor confusion, exhaustion and ignored I/O failures.

## Revisit when
Revisit if streaming artifacts become a real requirement; they require a different explicitly tested contract.
