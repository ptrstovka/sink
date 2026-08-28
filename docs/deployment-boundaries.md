# Deployment boundaries

## Supported deployment

The supplied systemd, container, and Traefik files assume one `sink-server`
process, one SQLite database, and Traefik v3 on the same Linux host. Sink does
not support clustering, shared tunnel claims, or active/active replicas.

- Traefik terminates TLS and sends plaintext HTTP to `sink-server`. Keep that
  hop on loopback. Running ingress and Sink on separate hosts requires a
  private, authenticated network and firewall rules not supplied here.
- DNS needs `connect.<base-domain>` and `*.<base-domain>` records. The apex is a
  separate record. A wildcard certificate covers `connect` and tunnel hosts,
  but not the apex unless it is also listed.
- Keep SQLite on local disk. Backups and filesystem snapshots must account for
  WAL files; network filesystems are unsupported.

## Product and traffic limits

- Only a single DNS label is a tunnel name. `connect` is reserved. Raw TCP,
  UDP, Windows, permanent name reservations, and a server configuration file
  are not supported.
- Sink adds no application body-size cap or low deployment-level concurrency
  cap. Available memory, sockets, bandwidth, protocol limits, Traefik,
  upstream proxies, and the local application still set practical limits.
- Long-lived streams keep connections and other resources open. Apply
  connection and abuse controls at the host or edge without buffering bodies,
  imposing low size caps, or cutting off expected streams.
- `sink-server` writes operational logs but has no dashboard, metrics endpoint,
  per-account quota, public visitor authentication, body capture, or replay.
  The separate `sink` client can expose its bounded traffic inspector only on
  the same machine's IPv4 loopback interface; it does not add a public or
  server-side dashboard.

## Public exposure and proxies

- Public URLs are reachable by anyone who knows them. The tunneled application
  must handle authorization, CSRF, secure cookies, and content security.
- If you place another proxy in front of Traefik, configure explicit trusted
  source ranges for forwarded headers. Never trust forwarding headers from
  arbitrary visitors.

Run `systemd-analyze verify` against the supplied service unit on the target
distribution. If a hardening directive blocks a required operation, narrow
that directive instead of disabling the whole sandbox.
