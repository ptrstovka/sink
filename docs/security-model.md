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

## Outside Sink's scope

Sink does not authenticate public visitors, inspect or retain HTTP bodies, or
apply per-account quotas. It is not a WAF, DDoS service, or malware scanner.
Public TLS ends at Traefik, and a random tunnel URL is not access control.

## Leaked token

If a token leaks, rotate it immediately, confirm the affected tunnels closed,
and save the replacement in the client config. Rotation invalidates the old
token and closes its active tunnels.
