# Version 1 local API and data contracts

The local supervisor listens at `$HEARTHRUN_STATE/control.sock` in a mode 0700 state directory with a mode 0600 socket. It authenticates the current UID via `SO_PEERCRED`. Each connection carries one request with a u32 big-endian header length followed by strict UTF-8 JSON up to 65,536 bytes. Reject unknown fields, duplicate keys at any nesting, trailing JSON, invalid UTF-8, NaN/Infinity, out-of-range integers and nesting beyond 16. Responses use the same framing. The normal request timeout is 5 seconds and the staging payload timeout is 10 seconds. Connections are bounded to 32 and processing queues have separate limits. Closing a client connection does not cancel a job.

Filesystem permissions can block a caller before it connects. If an accepted peer's UID differs from the service owner, the receiver attempts a fixed nonblocking `UNAUTHORIZED` frame and closes that connection before reading a request. A transport error while sending the refusal leaves the service running.

All requests contain v:1 and op. ID fields are32 lowercase hex characters from cryptographic random128-bit IDs; not timestamps. File names use ASCII components [A-Za-z0-9._-], excluding '.' and '..', max64bytes/component, max240bytes/path, max8components, no empty/absolute/backslash paths. This conservative first profile accepts an ASCII subset of UTF-8 and avoids normalization ambiguity. JSON keys sort lexically for canonical request hashing; insignificant whitespace removed; integer fields only, no float normalization ambiguity. argv strings are UTF-8 with no NUL, <=32items and<=4096 total UTF-8 bytes. No environment, UID, mount, syscall or host-path overrides are accepted from clients.

## Operations
|op|Fields beyond v/op|Result / semantics|
|---|---|---|
|doctor|none|Named feature results and compatible boolean; native implementation probes actual operations in disposable children; passive tooling probe cannot return compatible=true|
|stage|files:[{path,size,sha256}]|After header, exactly sum(size) raw bytes in manifest order; <=128files/16MiB. Copy incrementally to owner-only staging; verify exact declared size/digest; return stage_id and manifest_digest. No client host paths. Reject surplus bytes/early EOF; clean partial uploads. No guest executes.|
|submit|request_id, profile_id, stage_id, argv:[], wall_ms:10000|Persist canonical request identity and intent, return job_id/state. Profile allowlisted by operator. wall_ms100..60000. Same request/content returns same job; changed content gives CONFLICT.|
|inspect|job_id|State, outcome nullable, sequence, reason, policy_digest, executable_digest, cleanup_confirmed, result_digest nullable. Do not fabricate missing timings.|
|cancel|job_id|cancel_requested boolean and current state. Repeated cancel is idempotent; existing committed terminal outcome is not overwritten.|
|events|job_id, after_seq:0, limit:100|Bounded page<=100, next_seq, truncated flag if caller fell behind1024-event ring; not an unbounded stream.|
|result|job_id|Committed result metadata only; NOT_READY while live/exporting/cleanup_pending. Artifact bytes read by trusted CLI through safe result handler; no arbitrary output path.|
|metrics|none|Aggregate counters without user filenames, inputs or secrets.|

The local CLI command `hearthrun --state ABS_DIR export JOB_ID LOGICAL ABS_DESTINATION` first requests verified result metadata from the authenticated supervisor. It opens only the named manifest entry through the retained result directory, checks size and SHA-256, and publishes the copy at an unused file name in an existing mode 0700 directory. The destination path stays local to the trusted CLI. Concurrent retention may cause an export to fail before the copy is published.

Staging is an explicit binary payload exception to the64KiB JSON bound, not an unbounded JSON upload. Global staging cap128MiB and8in-progress uploads; staging age<=1h when unreferenced; active jobs pin their staging. Admission reserves storage. Same-UID operator can authorize files they can already read, but the supervisor never opens a requested host path on their behalf.

## Error envelope
```json
{"v":1,"ok":false,"error":{"code":"UNSUPPORTED_HOST","message":"cgroup v2 delegation unavailable","retryable":false,"details":{"feature":"cgroup_delegation"}}}
```
Allowed codes: BAD_FRAME, BAD_JSON, UNSUPPORTED_VERSION, UNKNOWN_FIELD, DUPLICATE_KEY, UNAUTHORIZED, INVALID_PATH, INVALID_LIMIT, PROFILE_NOT_FOUND, PROFILE_DIGEST_MISMATCH, UNSUPPORTED_EXECUTABLE, STAGE_NOT_FOUND, STAGE_DIGEST_MISMATCH, QUEUE_FULL, STORAGE_FULL, CONFLICT, NOT_FOUND, NOT_READY, UNSUPPORTED_HOST, STARTUP_FAILED, POLICY_FAILED, CLEANUP_PENDING, CORRUPT_STATE, IO_UNCERTAIN, INTERNAL. Error messages are bounded<=1024bytes and never include secret file content. Only QUEUE_FULL can suggest bounded backoff; submit retries retain the same request ID. Never retry changed content with an old ID.

## Success envelope and example
```json
{"v":1,"ok":true,"result":{"job_id":"11111111111111111111111111111111","state":"QUEUED","sequence":1}}
```
Example IDs are fixtures, not live jobs. result.schema.json describes persisted committed output. An execution success requires exit0, no timeout/cancel/limit/policy error, confirmed cleanup, checked artifact publication and durable final metadata. Cancelled/failed runs may publish bounded safe diagnostic artifacts only if the operator profile permits; otherwise discard output and commit a result with no artifacts.

## State/event records
State record: version, instance_id, job_id, request_id, canonical_request_sha256, state, sequence, launch_stage, profile_id, profile_digest, executable_digest, policy_digest, stage_manifest_digest, submitted_at_utc, started_monotonic_ns nullable, observed_exit nullable, cancel_reason nullable, cleanup_confirmed, result_digest nullable. Events contain version,job_id,sequence,event,monotonic_ns,reason_code. Wall clocks aid humans; deadlines use monotonic clock and are not restored as if monotonic epochs survived reboot. Schema rejects unknown major versions.

Artifacts metadata: logical_path,size_bytes,sha256 only, never a host absolute path. Result includes environment_id, status, exit_code nullable, signal nullable, truncation booleans, artifact manifest and cleanup proof references. The64hex SHA-256 is integrity identity, not a signature or proof a malicious same-UID actor could not forge it.

Operator config/profiles are separate trusted files. Install a profile with a local administrative CLI that resolves/validates/copies the executable into protected storage. Client submit cannot create a profile. No automatic schema migration; an offline explicit future migration must preserve request identity or require new namespace. Upgrade stops admission, cleans jobs, backs up state, then switches binaries; unsupported state refuses startup.
