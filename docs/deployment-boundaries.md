# Deployment boundaries

## Supported deployment

Sink supports one `sink-server` process with one local SQLite database. It does
not support clustering, shared route leases, or active/active replicas.

- The HTTP and HTTPS listeners are separate. They may bind directly to public
  ports 80 and 443.
- DNS must send the configured base domain and intended descendants to the
  server. Sink validates HTTP Host and TLS SNI against its route and namespace
  policy.
- Sink terminates TLS for managed namespaces. Raw TLS passthrough is limited to
  explicit passthrough claims; generic raw TCP and UDP forwarding are not
  supported.
- Keep SQLite on local disk. Backups and filesystem snapshots must account for
  WAL files; network filesystems are unsupported.

## Listener and readiness contract

- `SINK_SERVER_HTTP_LISTEN_ADDRESS` selects the HTTP listener. The legacy
  `SINK_SERVER_LISTEN_ADDRESS` remains an alias.
- `SINK_SERVER_HTTPS_LISTEN_ADDRESS` selects the TLS listener and is required
  when managed TLS is enabled. It must differ from the HTTP address.
- HTTPS PROXY protocol support defaults to `disabled`. `required-v2` is only for
  deployments with a trusted TCP proxy and requires exact canonical peer CIDRs.
- Managed TLS requires a Cloudflare zone ID and API token, an ACME contact,
  explicit agreement to the ACME terms, and an HTTPS ACME directory URL. The
  default directory is Let's Encrypt staging.
- Before accepting traffic, Sink reconciles certificate state, obtains or
  loads a valid base certificate, and loads namespace authorization. The log
  message `sink server ready` is the readiness signal.
- Sink does not add an HTTP-to-HTTPS redirect. HTTP and HTTPS routes remain
  independently reachable.

## Product and traffic limits

- Persistent namespace depth is bounded by
  `SINK_SERVER_MAX_NAMESPACE_DEPTH`. The `connect` name and other system names
  are reserved.
- Sink adds no application body-size limit. Available memory, sockets,
  bandwidth, operating-system limits, and the local application set practical
  limits.
- Long-lived uploads, downloads, SSE, and WebSockets keep resources open. Avoid
  infrastructure settings that buffer entire bodies or impose short connection
  lifetimes.
- `sink-server` has no dashboard, metrics endpoint, per-account quota, visitor
  authentication, body capture, or replay. The client inspector is available
  only on the client machine's IPv4 loopback interface.
- Public tunnel URLs are reachable by anyone who knows them. The local
  application remains responsible for authorization, CSRF protection, secure
  cookies, and content security.

## Optional proxies

A reverse proxy is not required. When one is present, it must preserve HTTP Host
values, pass TLS through without termination, and support streaming traffic.
Do not trust visitor-supplied forwarding or PROXY protocol metadata.

When HTTPS PROXY v2 is enabled, the sender and Sink configuration must change
together. Sink rejects connections without a valid header and rejects headers
from peers outside `SINK_SERVER_HTTPS_PROXY_TRUSTED_PEER_CIDRS`.

## Passthrough TLS

A passthrough namespace claim and its live client route have different
lifetimes. The claim persists in SQLite; the route exists only while its client
is connected. When the route is unavailable, matching HTTP returns unavailable
and matching TLS closes rather than falling back to another route.

If outgoing PROXY v2 is enabled for the local TLS target, that service must
trust headers only from the Sink client peer. The client constructs a fresh
header from authenticated tunnel metadata and does not copy inbound TLVs.

Run `systemd-analyze verify` against the supplied unit on the target
distribution. If a hardening directive blocks a required operation, narrow that
directive instead of disabling the entire sandbox.
