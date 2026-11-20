# Reviewer demo and UX

[Recorded local demo](recorded.html) · [Captured observations](recorded-demo.json)

## 30 seconds
Show one sentence: 'Run an approved native action with bounded authority, then verify cleanup before trusting its output.' Run the real NDJSON summarizer. Show one compact result: input/executable digests, committed output, elapsed time from actual evidence, policy ID and cleanup_confirmed. Do not show terminal output until it exists.

## Two minutes
1. Run `make demo` on a feature-verified native host. It generates deterministic public-safe NDJSON, builds the static fixture, starts an owner-only supervisor and runs the legitimate action.
2. Show the host-canary read denial and check its unchanged bytes. The separate finite policy smoke exercises socket-creation denial.
3. Start a bounded descendant fixture, cancel it, and show cgroup-empty/reaped evidence. A kill request alone is not completion.
4. Open the generated static report. View the execution timeline, policy, artifact digests and explicit failures. Teardown confirms zero owned live jobs.

## Five-minute engineering walkthrough
Explain the pre-exec gate; inspect one actual launch trace; display output-directory FD handoff and why export waits for all descendants; inject supervisor death; restart and show interrupted rather than silently replayed work. Finish with a targeted mutant whose failure demonstrates test sensitivity. Run only approved fixtures; never a general internet-accessible shell.

## Offline / unsupported-host behavior
`make demo-offline` renders a clearly marked EXAMPLE FIXTURE report from synthetic contract data. Its banner says 'NOT A LIVE CONTAINMENT RUN'. It cannot satisfy native acceptance. When a compatible host is unavailable, `make doctor` exits78 with capabilities and exact remediation guidance; no weak fallback executes a guest. Documentation can show architecture and expected flow without inventing screenshots or terminal success.

## Thin presentation, not a frontend project
The CLI displays bounded JSON without color. Exit 0 means the operation was accepted, 1 is a typed server rejection, 2 is a client error, and 78 signals an unsupported host. Cancellation acknowledges a request. Inspect the job's terminal record for cleanup. The static report escapes guest-controlled fields and includes semantic headings, table headers, focus styles, local navigation, evidence fingerprints and actual observation times.

## Screenshots after real execution only
Capture a focused result card/timeline, not an entire crowded desktop. Include native runtime/environment label and visible cleanup state. Capture a denied action and a cancellation sequence only after they actually ran. Store public assets stripped of PII/secrets; keep raw captures private until audited. No stock/generated image may imply an execution happened.

## Hosted option
Prefer a static sanitized report or recorded real demo. Do not host anonymous native execution. A live operator-only demonstration can use SSH to an already authorized disposable compatible host; no paid service or public network endpoint is necessary for the project to be convincing.
