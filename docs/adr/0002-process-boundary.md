# ADR-0002-process-boundary: Separately exec a single-threaded launcher

Status: accepted design, implementation pending.

## Context
The supervisor may use threads/asynchronous I/O, while namespace/mount/credential/policy setup has sensitive ordering.

## Decision drivers
Pre-exec correctness, small trusted surface, testable barrier, clear FD ownership.

## Options
Complex post-fork callbacks in supervisor; a general container daemon; separately exec helper.

## Decision
Fresh helper process with a controlled single-threaded setup path and explicit gate before guest exec.

## Consequences
More IPC/handshake code, but no assumption that multithreaded post-fork library calls are safe.

## Risks
Handshake confusion or leaked control descriptors can defeat the boundary.

## Revisit when
Revisit only with measured implementation constraints and equally explicit safe startup semantics.
