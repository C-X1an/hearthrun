# HearthRun command-line client

The CLI has completed finite native checks against the supervisor on Linux
x86-64. See the workspace verification report for the scope of those runs.

Build through the public workspace once its required environment is ready:

```sh
cargo build --locked -p hearthrun-cli
target/debug/hearthrun --help
```

The configured state directory must already be owned by the current UID with
mode0700, and a supervisor must listen on its owner0600 `control.sock`:

```sh
hearthrun --state /absolute/private/state doctor
hearthrun --state /absolute/private/state metrics
hearthrun --state /absolute/private/state stage data.ndjson=./data.ndjson
hearthrun --state /absolute/private/state submit REQUEST_ID PROFILE_ID STAGE_ID 10000 -- ARG
hearthrun --state /absolute/private/state inspect JOB_ID
hearthrun --state /absolute/private/state cancel JOB_ID
hearthrun --state /absolute/private/state events JOB_ID 0 100
hearthrun --state /absolute/private/state result JOB_ID
hearthrun --state /absolute/private/state export JOB_ID summary.json /absolute/private/output/summary.json
```

Replace ID placeholders with32 lowercase hexadecimal characters. Keep the same
request ID only when intentionally checking/retrying the exact same canonical
submission. The client never retries automatically. A missing response can leave
submission outcome uncertain; it does not cancel the job or authorize a new run.

`stage` accepts1..128 `LOGICAL=LOCAL` arguments and at most16MiB total bytes.
Logical names follow the v1 ASCII path grammar. The client retains checked source
file descriptors, computes their SHA-256 values, and streams exactly their declared
bytes. It sends logical names, sizes, digests and bytes; local source paths stay
in this client. The server independently verifies and owns immutable staging.

`submit` accepts an explicit request ID, approved profile ID, stage ID, optional
wall time (default10000ms, range100..60000ms) and at most32 arguments/4096 UTF-8
bytes after `--`. It sends no environment, executable host path or shell string.

Responses are JSON without color. `result` retrieves verified committed metadata
and the artifact manifest. `export` copies one manifest entry after confirming its
size and digest. Create the destination directory with mode 0700 before exporting.
The destination file name must be unused.

The client verifies directory/socket ownership and permissions, authenticates the
connected UID with `SO_PEERCRED`, caps framing at64KiB, half-closes its write side,
and uses total5s header/response and10s payload socket deadlines across partial
I/O. Kernel-blocked local filesystem operations are not a hard real-time bound.
Exit0 means an accepted operation (not necessarily a successful job),1 means a
typed server rejection,2 means a client error, and78 means an unsupported
platform/host reported by `doctor`.
