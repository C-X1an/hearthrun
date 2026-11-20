# Contributing

Start with PRD.md, ARCHITECTURE.md, API.md, SECURITY.md and the locked acceptance specification. Keep the project narrow: a change must preserve explicit execution, cleanup and publication semantics. Do not add services or frontend frameworks merely to make the repository appear larger.

Run `make tooling-test` for portable changes. For Rust changes run `make build fmt lint typecheck unit` on the pinned toolchain and capture results. Native changes additionally require the affected locked acceptance tests on a compatible host; unsupported execution is BLOCKED, not an excuse to weaken a criterion. Include a regression and, for a critical boundary, a targeted negative control.

Use owned file descriptors and explicit error propagation. Keep unsafe Rust isolated, documented with safety invariants and reviewed. Do not execute untrusted setup in a multithreaded post-fork callback. Bound every input, queue, stream and retained object. Avoid output dependence on color alone. Treat guest text as data and escape HTML.

Submit a focused change with requirement IDs, rationale, test commands, actual outcomes and limitations. Never commit credentials, private datasets, career notes or raw unreviewed evidence. Security reports follow SECURITY.md rather than a public exploit report. Preserve dependency and data licenses.
