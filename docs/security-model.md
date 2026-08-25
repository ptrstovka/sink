# Security model

## Trust boundaries

- Public visitors are untrusted. A public tunnel has no Sink-provided visitor
  authentication; the local application must enforce its own access control.
- Traefik is the public TLS boundary. It forwards plaintext HTTP to one
  `sink-server` listener, so that hop must stay on loopback or an equivalently
  trusted private network.
- Client control traffic authenticates with a per-user bearer token over TLS.
  The client validates the control hostname and never silently downgrades.
- The client-to-local-service hop is controlled by the user. Explicit HTTPS
  validates the target certificate by default.
- SQLite and the server host are trusted administrative assets. Compromise of
  either can alter users, traffic routing, or service behavior.

## Product controls

Tokens are high-entropy, shown only when created or rotated, and stored by the
server only as one-way digests. The client stores its token in a user-private
file. Tokens are excluded from logs, routine errors, user listings, forwarded
headers, and local request summaries. Disable or rotation revokes active
sessions and releases their claims.

The `connect` subdomain is reserved. Other valid single-label names are
first-claim active-session leases; a conflict cannot displace the owner. A
transiently disconnected run may reclaim its name during a bounded grace
period. Sink does not replay interrupted application requests.

End-to-end HTTP semantics are preserved, including forwarded public host,
scheme, and visitor address. Traefik must sanitize client-supplied forwarded
headers and trust such headers from an upstream load balancer only by explicit
source range.

## Not provided by the MVP

Sink is not a WAF, DDoS service, malware scanner, content inspector, tenant
quota system, public visitor identity layer, or end-to-end TLS tunnel through
Traefik. It does not protect a vulnerable local application merely by placing
it behind a random URL. Request/response bodies are not captured for audit or
replay.

Operators remain responsible for host hardening, timely upgrades, DNS and
certificate control, firewalling, backups, log retention, abuse handling,
capacity limits, and securely issuing tokens. See
[deployment boundaries](deployment-boundaries.md).

## Incident actions

For a suspected token leak, rotate the user's token immediately, confirm their
active tunnels closed, issue the replacement through a secret channel, and
review authentication/tunnel lifecycle logs. For host or database compromise,
take the service out of rotation, preserve evidence, rotate all user tokens and
TLS material as appropriate, restore from a known-good system, and validate
with the acceptance checklist before returning traffic.
