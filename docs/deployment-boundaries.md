# Deployment boundaries

The shipped examples deliberately target a narrow, supportable MVP topology:

- One `sink-server` process, one SQLite database, and Traefik v3 on the same
  Linux host. There is no clustering, leader election, shared claim registry,
  or active/active server support.
- Traefik terminates TLS; its backend hop is plaintext. Loopback binding is the
  safe default. A container or separate ingress host requires a private,
  authenticated/encrypted network design and firewall changes not supplied
  here.
- DNS needs `connect.<base-domain>` and `*.<base-domain>` records. The apex is a
  separate record. A wildcard certificate covers `connect` and tunnel hosts,
  but not the apex unless it is also listed.
- Only a single DNS label is a tunnel name. `connect` is reserved. Raw TCP,
  UDP, Windows, permanent name reservations, and a server configuration file
  are outside MVP scope.
- SQLite is local persistent state. Filesystem snapshots must account for WAL,
  and network filesystems are not an assumed/supported database substrate.
- Sink imposes no application body-size or deliberately low tunnel-concurrency
  limit. Finite memory, disk, sockets, bandwidth, Traefik settings, upstream
  proxies, and the local application still impose practical limits.
- Unlimited streaming timeouts increase slow-client resource exposure. Apply
  host/edge connection and abuse controls with care; body buffering, fixed
  request lifetimes, or low size caps violate Sink's large/streaming contract.
- The MVP has operational logs but no dashboard, rich metrics, per-user quota,
  public visitor authentication, body capture, or replay.
- Public URLs are reachable by anyone who knows them. The tunneled application
  owns authorization, CSRF behavior, secure cookies, and content security.
- Proxies in front of Traefik are not assumed. If one is added, configure
  trusted forwarded-header source ranges; never globally trust arbitrary
  visitor-supplied forwarding headers.

The systemd unit uses broadly available hardening directives but should be
checked with `systemd-analyze verify` on the target distribution. If a needed
operation is denied, investigate and narrow the relevant directive instead of
disabling the entire sandbox.
