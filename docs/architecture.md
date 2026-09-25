# Architecture

Sink uses two executables and one public ingress:

```text
sink client --TLS/WebSocket--+
                             |
public TLS :443 --SNI--> Traefik --PROXY v2 + unchanged TLS--> Sink HTTPS listener
                                                                   |
                        +--------------- managed TLS termination ---+--- HTTP tunnel
                        |
                        +-- passthrough SNI dispatch -- raw tunnel ------+
                                                                         |
public HTTP :80 --Host--> Traefik --plain HTTP--> Sink HTTP listener ----+-- HTTP tunnel
                                                                         |
                                         one authenticated route session |
                                                                         v
                                         sink client --> Edge :80 / :443
```

Traefik remains the shared-public-IP multiplexer, not the TLS endpoint for the
configured Sink domain tree. On port 80 it selects the base-domain apex and
every descendant using the HTTP Host and forwards plaintext HTTP to Sink's HTTP
listener. On port 443 it selects the same tree using TLS SNI and forwards the
TCP stream unchanged after a PROXY v2 header to Sink's HTTPS listener. Sink
authenticates the immediate proxy peer before trusting that header. It then
either selects a managed certificate and terminates TLS, or routes a durable
passthrough namespace without consuming or changing the TLS bytes. For managed
TLS, the resulting HTTP Host must match the SNI. Neither layer automatically
redirects HTTP to HTTPS.

The entire configured base-domain tree reaches Sink. Traefik deliberately does
not limit the number of descendant labels or know about users, namespaces, or
tunnels. Sink's namespace and certificate policy is the authorization
boundary. The reserved `connect.<base-domain>` control route uses an
authenticated, versioned WebSocket handshake; the upgraded byte stream carries
yamux.

Each public HTTP request or upgraded connection gets an independent yamux
stream and HTTP/1.1 exchange to the client. The client proxies that exchange to
the configured local HTTP/HTTPS target. Independent streams provide
concurrency and backpressure while allowing request/response bodies, SSE, and
WebSockets to flow without whole-body buffering.

Persistent namespace claims and active tunnel route leases are different
resources. A managed namespace claim authorizes its apex and one wildcard
certificate. A passthrough claim authorizes one canonical wildcard route whose
scope is exactly the namespace apex and one direct child label. It neither
permits deeper names implicitly nor allows an exact route at the apex or a
covered direct child to override it. Only the adjacent parent owner can create
a nested claim, and configured maximum depth bounds persistent claims.
Certificate issuance happens only for managed claims while they progress
toward active state, never as a side effect of starting a tunnel. Passthrough
claims become active without Sink certificate issuance. System names such as
`connect` remain reserved.

The client represents a passthrough namespace with one `[[routes]]` entry and
one control session. Its existing HTTP `target` receives port-80 traffic for
the apex and direct children; its optional `tls_target` receives the raw
port-443 streams. `proxy_protocol = "v2"` makes the client construct a new,
minimal PROXY v2 header for the Edge connection. A normal route has neither
field by default and remains an exact HTTP/managed-TLS route.

An active tunnel route is still owned by a client-run UUID. Clean exit releases
the route, while an unexpected disconnect retains it briefly for same-run
reconnection. A newer control link from that same authenticated run atomically
replaces an older half-open link. Server-initiated WebSocket heartbeats bound
detection of silent network loss. A separately started client run cannot
acquire the route until the old run's reconnect grace expires. Requests during
that gap return service unavailable. Interrupted in-flight traffic fails and
is never automatically replayed.

SQLite stores accounts, named token digests and revisions, persistent namespace
claims, ACME account/order state, certificate material, and other durable
administrative data. Active tunnel routes remain runtime leases rather than
permanent reservations. A durable passthrough claim whose broker is absent or
disconnected is still an authorization boundary: matching HTTP fails
unavailable and matching TLS is closed rather than falling through to an exact
or managed route. A short revocation check closes active sessions after account
disable or token rotation.

With managed TLS enabled, startup reconciles durable certificate orders,
provisions or reuses the base-domain apex-plus-wildcard certificate, loads the
fail-closed SNI resolver, and refreshes managed and passthrough namespace
authorization before either listener accepts traffic. Base-certificate
unavailability fails startup. The certificate lifecycle runs immediately after
readiness and every 30 seconds; shutdown drains it together with both
listeners. Managed and passthrough namespaces therefore coexist on one HTTPS
listener without making Edge certificates available to Sink.

Forwarding preserves method, path, query, body, status, and end-to-end headers.
The local Host targets the local service; standard forwarded headers carry the
original public host/scheme and visitor address. Control credentials never
enter the forwarded HTTP exchange.

For raw TLS, the trusted address chain is deliberately rebuilt at each trust
boundary. Traefik sends public source/destination addresses in PROXY v2; Sink
accepts them only from configured canonical peer CIDRs; Sink encodes those
addresses as server-originated metadata inside the authenticated,
integrity-protected tunnel; and the client optionally creates a fresh PROXY v2
header for Edge. Inbound TLVs and untrusted visitor-supplied bytes are never
copied through as trusted metadata. Edge must accept PROXY v2 only from the
exact Sink client peer. Edge owns the certificate and performs the public TLS
handshake.

## Local traffic inspector

Inspection is a client-process side branch of the streaming proxy, not a hop in
the forwarding path. When enabled, capture writes lightweight metadata and
bounded body previews to a mutex-protected, process-local memory store. Event
publication uses a bounded non-blocking channel, so a slow dashboard cannot
backpressure tunneled traffic. The list API builds lightweight summaries; the
detail API fetches one retained request/response snapshot, and an SSE stream
announces create, update, removal, clear, pause, and resynchronization events.

The store retains at most 100 transactions and 1 MiB from each request or
response body by default. Oldest entries are evicted. Full transferred byte
counts remain available when a preview is truncated, and binary body bytes are
omitted. Delete, clear, eviction, shutdown, and process exit release ownership;
they do not promise physical-memory zeroization. A late capture update cannot
resurrect an entry after removal.

The dashboard binds only to IPv4 loopback and is supervised separately from the
tunnel connection. An automatic bind failure is reported while the tunnel can
continue; failure of an explicitly selected port fails startup. On graceful
client shutdown, the dashboard closes its SSE streams and listener and releases
its in-memory services. The production Vite output is built once before Cargo;
Cargo embeds those exact files in `sink` and never runs npm or downloads assets.
At runtime the binary serves only embedded bytes and needs no Node.js,
dashboard filesystem, or CDN.
