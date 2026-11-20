# ADR-0006-public-private: Publish a clean, reproducible product export

Status: accepted design, implementation pending.

## Context
Development notes, credentials and operational session details may contain private material; code without tests lacks reproducible evidence.

## Decision drivers
Privacy, inspectability, clean history, no secret leakage.

## Options
Publish everything; strip tests; maintained explicit public export.

## Decision
Keep private control/research sibling to public product. Export only reviewed path/hash manifest into new history, retaining necessary tests/docs/evidence.

## Consequences
Two scopes must remain synchronized through stable contracts; public build must never require private files.

## Risks
Pattern scanning alone misses privacy or license problems.

## Revisit when
Revisit packaging convenience only if public reproduction and private exclusion remain demonstrably intact.
