# Security model

## Trust boundaries

- Public visitors are untrusted. A public tunnel has no Sink-provided visitor
  authentication; the local application must enforce its own access control.
- Traefik is the public TLS boundary. It forwards plaintext HTTP to one
  `sink-server` listener, so that hop must stay on loopback or an equivalently
  trusted private network.
- Client control traffic authenticates with a per-account bearer token over
  TLS. The client validates the control hostname and never silently
  downgrades.
- You control the client-to-local-service hop. Explicit HTTPS validates the
  target certificate by default.
- SQLite and the server host are trusted administrative assets. Compromise of
  either can alter accounts, traffic routing, or service behavior.

## Credentials and tunnel claims

Tokens are high-entropy, shown only when created or rotated, and stored by the
server only as one-way digests. The client stores its token in a private config
file. Tokens are excluded from logs, routine errors, account listings,
forwarded headers, and local request summaries. Disable or rotation revokes
active sessions and releases their claims.

The `connect` subdomain is reserved. Other valid single-label names are
first-claim active-session leases; a conflict cannot displace the active
claimant. A transiently disconnected run may reclaim its name during a bounded
grace period, and an authenticated reconnect with the same client-run UUID may
replace its own older control link. Control-channel heartbeats bound how long a
silently lost link can remain active. Sink does not replay interrupted
application requests.

## Forwarded headers

Sink forwards the public host, scheme, and visitor address to the local
application. Traefik must replace visitor-supplied forwarding headers. If
another proxy sits in front of Traefik, trust its headers only from its known
source addresses.

## Local inspector boundary

The inspector is reachable only on an IPv4 loopback listener (`127.0.0.1`).
Every dashboard and API request must carry exactly one Host header matching the
selected loopback address. If an Origin header is supplied, exactly one is
accepted and it must equal that dashboard origin. Duplicate or mismatched
Host/Origin values and every OPTIONS/preflight request are rejected. The
service emits no CORS permission. Dashboard HTML and every API response use
`Cache-Control: no-store` and same-origin browser hardening headers.

Each inspector run generates a separate mutation token. The browser retrieves
it from the read-only session endpoint and keeps it in closure-held session
state; loading or disposing a session clears the old token and aborts protected
requests. The client prints only the loopback URL and never includes the token
in it. Reveal, pause, resume, replay, cURL generation, delete, and clear require
exactly one matching token header. Read endpoints intentionally do not require
that token. This is a local safety boundary, not authentication against other
processes owned by the same OS user: such a process can read the API, obtain the
session token, and invoke mutations.

The inspector's `x-sink-inspector-token` control header exists only on requests
to the loopback dashboard service; it is never retained or forwarded with
tunneled application traffic. The full `x-sink` / `x-sink-*` namespace is also
reserved at the capture model boundary, so captured headers in that namespace
cannot be revealed, replayed, or generated into cURL. Application headers are
classified by name. Authorization, Proxy-Authorization, Cookie, Set-Cookie,
common API-key names, and names with
token/secret/credential/password/passphrase/signature segments are masked
conservatively. Classification does not inspect values and cannot recognize
every application-specific secret name.

Reveal is a deliberate, one-value operation. The UI keeps a revealed value only
in that mounted control and clears it when hidden or unmounted; the retained
source value still exists until its transaction leaves the store. Before cURL
includes any classified sensitive values, the confirmation dialog exposes
header names only and requires explicit consent. The resulting command targets
the current local service and may put secrets into the clipboard and later the
shell's history.

Replay is also deliberate. It re-sends an eligible, fully retained request to
the current local target using the run's local TLS and Host behavior and creates
a linked replay capture. Sink excludes its reserved control headers. Replay is
rejected before any send if capture is paused, the source has gone away, or the
request is a WebSocket/SSE/streaming request, has a binary or unclassified body,
or has an incomplete or truncated body. Delete, clear, capacity eviction, and
last replay-service teardown cancel pending replay ownership; a removed entry
cannot be resurrected by a late update.

Inspector retention is bounded, process-local memory: 100 transactions and 1
MiB for each request or response body preview by default. Binary body bytes are
omitted; truncated and incomplete state and full transferred byte counts remain
visible. Delete, clear, eviction, graceful shutdown, and process exit drop the
store's ownership of retained values. They do not guarantee physical-memory
zeroization.

Residual exposure remains for URLs and query strings, request and response
bodies, unclassified headers, values disclosed by explicit Reveal or confirmed
cURL output, the clipboard and shell history, and other same-user processes.
Choose lower limits or disable inspection for workloads where those exposures
are unacceptable.

## Outside Sink's scope

Sink does not authenticate public visitors or apply per-account quotas. The
server does not retain tunneled bodies; the optional local client inspector has
the bounded retention described above. Sink is not a WAF, DDoS service, or
malware scanner. Public TLS ends at Traefik, and a random tunnel URL is not
access control.

## Leaked token

If a token leaks, rotate it immediately, confirm the affected tunnels closed,
and save the replacement in the client config. Rotation invalidates the old
token and closes its active tunnels.
