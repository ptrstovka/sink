# Deployment boundaries

## Supported deployment

The supplied systemd, container, and Traefik files assume one `sink-server`
process, one SQLite database, and Traefik v3. Sink does not support clustering,
shared tunnel claims, or active/active replicas.

- Public port 80 remains plain HTTP. Traefik selects the configured base-domain
  apex and every descendant by HTTP `Host` and forwards the request to Sink's
  HTTP listener. It must not add an HTTP-to-HTTPS redirect.
- Public port 443 uses a Traefik TCP router. Traefik selects the configured
  base-domain apex and every descendant by TLS SNI, enables TLS passthrough,
  prepends PROXY v2, and forwards the TLS byte stream unchanged to Sink's HTTPS
  listener. Sink terminates and manages certificates for managed namespaces;
  it forwards passthrough namespace TLS unchanged to the client-side Edge,
  which owns that namespace's certificates.
- The HTTP and HTTPS listeners are distinct. Keep both upstream hops on
  loopback when Traefik and Sink share a host. Running them on separate hosts
  requires a private, authenticated network and firewall rules not supplied
  here; never expose either listener to an untrusted network.
- The whole configured base-domain tree belongs to Sink. Traefik deliberately
  matches arbitrary descendant depth and does not encode Sink's namespace or
  certificate authorization policy. Sink rejects unauthorized Host/SNI values.
  A passthrough claim covers exactly its apex and direct children. Covered
  exact routes cannot override it and deeper names are not implicitly covered.
- DNS must make the base-domain apex and every intended descendant reach the
  public Traefik address. DNS wildcard behavior is separate from TLS wildcard
  coverage. Sink provisions the base apex plus its wildcard and provisions a
  managed claimed namespace apex plus its wildcard when that namespace is
  authorized. Passthrough claims provision no Sink certificate.
- Keep SQLite on local disk. Backups and filesystem snapshots must account for
  WAL files; network filesystems are unsupported.

## Listener and readiness contract

- `SINK_SERVER_HTTP_LISTEN_ADDRESS` selects the plain HTTP listener. The legacy
  `SINK_SERVER_LISTEN_ADDRESS` remains an alias for it, but deployments should
  use the explicit name.
- `SINK_SERVER_HTTPS_LISTEN_ADDRESS` selects the TLS listener and is required
  when `SINK_SERVER_CERTIFICATE_BACKEND_ENABLED=true`. It must differ from the
  HTTP address. Configuring an HTTPS address while the certificate backend is
  disabled is rejected.
- `SINK_SERVER_HTTPS_PROXY_PROTOCOL=required-v2` makes every connection to the
  HTTPS listener begin with PROXY v2. The companion
  `SINK_SERVER_HTTPS_PROXY_TRUSTED_PEER_CIDRS` must contain only canonical CIDRs
  for immediate Traefik peers. Do not put visitor, CDN, or general private
  network ranges in this list. The compatibility default is `disabled`.
- Managed TLS requires the Cloudflare zone ID and API token, an ACME contact,
  explicit ACME terms agreement, and an HTTPS ACME directory URL. The code
  default is Let's Encrypt staging; production deployments must explicitly set
  `https://acme-v02.api.letsencrypt.org/directory`.
- Before either listener accepts traffic, Sink reconciles durable certificate
  state, provisions or reuses a valid base-domain certificate, loads the
  fail-closed SNI resolver, and refreshes managed and passthrough namespace
  authorization boundaries. Startup fails when the base certificate is
  unavailable. The log message `sink server ready` is the service readiness
  signal; a started process or a bound socket alone is not readiness. The
  container image's HTTP health check proves the plain listener is serving the
  configured base Host, but an external TLS probe through Traefik is still
  required to validate PROXY v2 and SNI dispatch.
- Once ready, the certificate lifecycle runs immediately and every 30 seconds.
  Graceful shutdown drains the HTTP listener, HTTPS listener, and lifecycle.
  For HTTPS requests, the HTTP Host must match the TLS SNI.

## Product and traffic limits

- Persistent namespace claims are bounded by
  `SINK_SERVER_MAX_NAMESPACE_DEPTH`; the supplied examples use depth 2.
  Traefik routing is intentionally not bounded to that depth because a tunnel
  label can sit below a claimed namespace. `connect` and other system names are
  reserved by Sink. Raw forwarding is limited to TLS selected by SNI under an
  explicit passthrough claim; generic raw TCP, UDP, Windows, and a server
  configuration file are not supported.
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
- The Cloudflare API token is an environment-only secret. Give it only the DNS
  permissions required for the configured zone, keep the environment file or
  container secret private, and never pass it on the command line.
- If you place another proxy in front of Traefik, configure explicit trusted
  source ranges for forwarded headers. Never trust forwarding headers from
  arbitrary visitors.

## Edge passthrough trust and failure boundary

The supported source-IP chain is:

```text
outer proxy -> Sink trusted PROXY v2 -> authenticated tunnel metadata
            -> Sink client fresh PROXY v2 -> Edge trusted client peer
```

Each arrow is a separate trust decision. Sink never treats arbitrary bytes or
inbound TLVs as trusted tunnel metadata, and the client never copies an inbound
header verbatim. Edge must enable PROXY v2 only for connections from the exact
Sink client peer. If the route omits `proxy_protocol = "v2"`, Edge must expect
ordinary TLS from that peer instead.

The durable passthrough claim and the live route have different lifetimes. A
server restart reloads the claim from SQLite; a client restart must re-establish
the one namespace route. While no matching broker is connected, HTTP returns
unavailable and TLS closes. Sink does not fall back to managed TLS, a parent
certificate, or an exact route. Preserve the SQLite volume/file across server
restarts, run both processes under restart supervision, and alert on sustained
unavailability rather than attempting an automatic mode change.

Enabling or disabling ingress PROXY v2 is a coordinated maintenance change:
the Traefik sender and Sink requirement must agree for all managed and
passthrough TLS on the shared listener. Changing only one side interrupts every
TLS route. Validate the new pair through Traefik before claiming a passthrough
namespace. Rollback likewise changes both sides together. Releasing a
passthrough namespace first requires its live route and child claims to be
gone; only then can an operator claim the same name in managed mode and wait
for certificate readiness. No step adds an HTTP-to-HTTPS redirect.

Run `systemd-analyze verify` against the supplied service unit on the target
distribution. If a hardening directive blocks a required operation, narrow
that directive instead of disabling the whole sandbox.
