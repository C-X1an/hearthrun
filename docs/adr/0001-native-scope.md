# ADR-0001-native-scope: Native Linux boundary with approved static fixtures

Status: accepted design, implementation pending.

## Context
Native tools may outlive their leading process or retain mutable output during export. This project needs a narrow boundary that makes execution ownership and completion observable.

## Decision drivers
Correct lifecycle semantics, bounded scope, inspectable failures and low setup burden.

## Options
A thin NsJail wrapper; general OCI service; microVM platform; narrow native fixture runner.

## Decision
Select a narrow native runner. Use mature systems as baselines, not competitors to be displaced.

## Consequences
Real kernel and process ownership problems become visible; dynamic arbitrary workloads are excluded.

## Risks
Shared-kernel attacks and host compatibility remain limitations.

## Revisit when
Revisit if a user requirement truly needs arbitrary workloads or stronger hostile multi-tenant isolation.
