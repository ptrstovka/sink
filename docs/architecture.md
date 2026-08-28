# Architecture

Sink uses two executables and one public ingress:

```text
                         connect.example.com
sink client ===== TLS/WebSocket via Traefik =====+
      |                                           |
      | HTTP or HTTPS                       one plaintext
      v                                       listener
local application <--- multiplexed streams ---> sink-server
                                                  ^
public visitor -------- HTTP/S via Traefik --------+
                         *.example.com
```

Traefik terminates TLS and forwards `connect.<base-domain>`, the base-domain
status host, and valid single-label wildcard hosts to the same server service.
The server selects control or public behavior from the preserved Host. The
reserved control route uses an authenticated, versioned WebSocket handshake;
the upgraded byte stream carries yamux.

Each public HTTP request or upgraded connection gets an independent yamux
stream and HTTP/1.1 exchange to the client. The client proxies that exchange to
the configured local HTTP/HTTPS target. Independent streams provide
concurrency and backpressure while allowing request/response bodies, SSE, and
WebSockets to flow without whole-body buffering.

The server holds active subdomain claims. A client-run UUID owns the claim;
clean exit releases it, while an unexpected disconnect retains it briefly for
same-run reconnection. A newer control link from that same authenticated run
atomically replaces an older half-open link. Server-initiated WebSocket
heartbeats bound detection of silent network loss. A separately started client
run cannot acquire the name until the old run's reconnect grace expires.
Requests during that gap return service unavailable. Interrupted in-flight
traffic fails and is never automatically replayed.

SQLite stores accounts, enabled state, token digest/generation, and other
durable administrative data. Public claims are runtime leases rather than
permanent reservations. A short revocation check closes active sessions after
account disable or token rotation.

Forwarding preserves method, path, query, body, status, and end-to-end headers.
The local Host targets the local service; standard forwarded headers carry the
original public host/scheme and visitor address. Control credentials never
enter the forwarded HTTP exchange.

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
