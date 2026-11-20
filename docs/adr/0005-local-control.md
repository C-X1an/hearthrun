# ADR-0005-local-control: Single owning supervisor and no database service

Status: accepted design, implementation pending.

## Context
Four-running/sixteen-queued local jobs do not justify distributed scheduling or a database deployment.

## Decision drivers
Coherent scope, durable retry identity, simple recovery, reproducibility.

## Options
PostgreSQL/queue; SQLite; explicit local intent/index/result records.

## Decision
One owning process with specified bounded durable records and fsync/atomic publication.

## Consequences
Durability implementation needs fault tests; no multi-node availability or exactly-once external-effects claim.

## Risks
Partial writes, stale indexes and unbounded retention if contracts are missed.

## Revisit when
Revisit if actual multi-process writers or operational query requirements justify a database; preserve semantics.
