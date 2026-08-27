# Manual acceptance tests

These workloads are release and deployment gates, not normal CI. Run them only in an
isolated environment with enough disk, bandwidth, time, and permission to
interrupt processes. Record server/client versions, OS/architecture, Traefik
version/config hash, timestamps, public hostname, and results.

Use the repository's guarded harness under `scripts/acceptance/`. The checks
below describe the required observable behavior and remain useful for
independent verification.

## Baseline setup

Create two enabled users and start local fixtures that can echo request bodies,
serve deterministic downloads, stream SSE indefinitely, and echo WebSockets.
Start a tunnel, record both printed URLs, then verify ordinary methods, paths,
queries, status codes, end-to-end headers, public forwarded headers, and local
virtual-host routing. Confirm an unknown host is distinct from a known tunnel
whose client/local target is unavailable.

## Required manual gates

1. Large transfer: upload a deterministic 1 GiB body and compare its SHA-256 at
   the local receiver; download a deterministic 1 GiB response and compare the
   source/received SHA-256. No truncation, corruption, whole-body memory spike,
   or Sink size rejection is acceptable.
2. Long-lived traffic: keep one SSE stream and one WebSocket open for one hour.
   During that hour send periodic ordinary requests and uploads/downloads.
   Check responsiveness and sample RSS, file descriptors, tasks, and disk use
   for progressive growth.
3. Mixed concurrency: while an upload, SSE, and WebSocket are active, issue at
   least 100 ordinary requests concurrently through the same tunnel. Validate
   every response and confirm long-lived operations keep progressing.
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
   one user's token and disable another while tunnels are active, confirming
   immediate closure and permanent authentication failure for old credentials.
9. Shutdown: send one normal termination and observe bounded drain; send a
   second termination and observe immediate exit. Claims must release and
   interrupted application operations must not replay.

## Pass record

Preserve command transcripts with secrets redacted, request/result counts,
hashes for both 1 GiB directions, reconnect durations, resource samples, and
relevant logs. A failure is not waived merely because a later retry passes;
capture it, determine the cause, fix or document the infrastructure boundary,
and rerun the affected gate.
