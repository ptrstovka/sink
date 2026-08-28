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
