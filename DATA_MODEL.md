# Data model guide

The canonical data and IPC schemas are defined in API.md and schemas/. They include request identity, immutable staging, lifecycle events, result identity, stable errors, retention and publication order. The result store is single-writer local state, not a distributed database. Treat guest bytes and logical paths as untrusted. The initial seed does not implement the durable store. Changes to these interfaces must preserve the locked acceptance contract and compatibility/version checks.
