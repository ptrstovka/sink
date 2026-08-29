# Acceptance tests

## Focused automated gates

Normal CI builds one deterministic embedded dashboard before any Cargo command
that can compile `sink-client`:

```console
cd dashboard
npm ci
npm run verify
cd ..
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

CI installs Node 24 with its bundled npm and keys the npm cache from
`dashboard/package-lock.json` (lockfile v3). `npm run verify` is the single
frontend gate: `npm test` runs Vitest plus the production-source guard, and
`npm run build` runs typechecking, Vite build, and the production-bundle guard.
Cargo reuses the generated `dashboard/dist` and never invokes npm or downloads
assets. Fast Rust tests cover inspector retention, body states, header masking,
loopback request guards, list/detail/SSE and mutations, replay/cURL behavior,
embedded assets, and dashboard lifecycle. Formatting is also checked with the
command shown above; it does not compile `sink-client`.

The four-lane binary release workflow verifies that native `sink version` and
`sink-server version` output from each unpacked archive matches the release tag,
and runs a packaged embedded-dashboard smoke on native Linux x86_64. That smoke
starts only the copied `sink` from an empty directory with Node absent from
PATH, verifies embedded HTML, hashed JavaScript, and the transaction API, then
signals the process and proves loopback port release. Those checks run when the
release workflow is invoked; this document does not claim a release has been
published.

## Manual acceptance gates

These tests transfer multi-gigabyte data, run for an hour, and deliberately
interrupt connections and processes. Run them manually in an isolated
environment. Normal CI intentionally excludes the 1 GiB transfers, one-hour
soak, repeated disruption, and performance stress; focused automated coverage
does not replace these gates or claim they have run.

Use the guarded harness under `scripts/acceptance/`.

The harness streams file-backed uploads with curl `--upload-file` while keeping
the request method explicitly `PUT`; it never uses `--data-binary @file` for the
1 GiB payload. Each connection, ordinary request, large operation, and external
hook has a bounded timeout. Upload/download counters and SSE/WebSocket output
sizes are sampled throughout mixed and soak workloads, and a no-growth window
fails with byte-only diagnostics. Tracked children are terminated and reaped on
success, failure, or signal without printing curl/hook logs, request content,
public URLs, or credentials.

Timeouts can be tuned within enforced bounds with
`SINK_ACCEPTANCE_CONNECT_TIMEOUT_SECONDS` (default 5),
`SINK_ACCEPTANCE_REQUEST_TIMEOUT_SECONDS` (10),
`SINK_ACCEPTANCE_ORDINARY_CONCURRENCY` (25, allowed 1–100),
`SINK_ACCEPTANCE_OPERATION_TIMEOUT_SECONDS` (1800),
`SINK_ACCEPTANCE_STALL_TIMEOUT_SECONDS` (60),
`SINK_ACCEPTANCE_PROGRESS_INTERVAL_SECONDS` (5), and
`SINK_ACCEPTANCE_HOOK_TIMEOUT_SECONDS` (120). The progress interval must remain
shorter than the stall timeout. `SINK_ACCEPTANCE_SOAK_SECONDS` defaults to 3600
and allows 3600–86400 seconds. It defines the nominal workload-admission and
observation window. Work admitted before that boundary retains its bounded
request or operation timeout; an admitted upload/download pair completes
atomically with a fresh timeout for each leg. See `scripts/acceptance/README.md`
for the complete allowed ranges and maximum bounded overrun.

## Baseline setup

Create two enabled accounts and start local fixtures that can echo request
bodies, serve deterministic downloads, stream SSE indefinitely, and echo
WebSockets. Start a tunnel, record both printed URLs, then verify ordinary
methods, paths, queries, status codes, end-to-end headers, public forwarded
headers, and local virtual-host routing. Confirm an unknown host is distinct
from a known tunnel whose client/local target is unavailable.

### Required scenarios

1. Large transfer: upload a deterministic 1 GiB body and compare its SHA-256 at
   the local receiver; download a deterministic 1 GiB response and compare the
   source/received SHA-256. No truncation, corruption, whole-body memory spike,
   stalled byte counter, deadline overrun, or Sink size rejection is acceptable.
2. Long-lived traffic: keep one SSE stream and one WebSocket open for one hour.
   During that hour send periodic ordinary requests and uploads/downloads.
   Require both output byte counts to grow within every configured stall window,
   check responsiveness, and sample RSS, file descriptors, tasks, and disk use
   for progressive growth. Stop admitting new work at the nominal soak
   boundary, but let an already-admitted ordinary request or upload/download
   pair finish under its own request, operation, and stall limits. Continue
   monitoring the long-lived streams during this bounded completion window.
3. Mixed concurrency: while an upload, SSE, and WebSocket are active, issue at
   least 100 ordinary requests through the same tunnel with a bounded in-flight
   window (25 by default). Validate every response, wait for and hash-check both
   1 GiB transfers, and confirm the transfer, SSE, and WebSocket byte counters
   keep progressing. The bounded window keeps this focused on tunnel fairness,
   rather than public TLS/proxy connection admission.
4. Link disruption: interrupt the client-to-server path at least 20 times.
   Each in-flight operation must fail without replay; within 10 seconds of path
   recovery, new traffic must work at the identical public URL.
5. Server restart: restart `sink-server` at least five times while the client
   continues running. It must reconnect without configuration or URL changes.
6. Local outage: stop the local fixture without stopping the client. New public
   requests must fail quickly as service unavailable, the claim must remain,
   and new requests must recover after the fixture returns.
7. Cancellation: cancel callers during upload, download, SSE, WebSocket, and an
   ordinary slow request; then repeat with the local side closing. Resources
   must be released promptly without disrupting unrelated traffic.
8. Claims/auth: prove two clients cannot simultaneously claim one custom name;
   prove same-run reconnect reclaims it; prove a clean stop releases it. Rotate
   one account's token and disable another while tunnels are active, confirming
   immediate closure and permanent authentication failure for old credentials.
9. Shutdown: send one normal termination and observe bounded drain; send a
   second termination and observe immediate exit. Claims must release and
   interrupted application operations must not replay.
