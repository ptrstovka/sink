# Server deployment reference

This reference assumes you run one Linux host with `sink-server` behind an
existing Traefik v3 instance. Start with [Get Sink running](getting-started.md)
for the complete server-and-client setup. Multiple server replicas are not
supported; see [deployment boundaries](deployment-boundaries.md).

## 1. Prepare DNS and TLS ownership

Point `example.com` and every intended descendant at Traefik. The apex needs
its own DNS record; arrange wildcard, delegated, or explicit records so deeper
names also reach the same public address. The whole configured tree belongs to
Sink even though Traefik continues sharing that address with unrelated domains.

Do not provision Sink-tree certificates in Traefik. Sink uses Cloudflare DNS-01
and ACME to provision the base-domain apex plus one wildcard, and each accepted
managed namespace claim provisions its apex plus one wildcard. A passthrough
claim provisions no Sink certificate: its Edge owns and presents certificates
for the claim apex and intended direct children. Use a zone-scoped Cloudflare
API token, preserve the SQLite certificate/order state, and set the production
ACME directory explicitly because the server default is staging:

```text
https://acme-v02.api.letsencrypt.org/directory
```

The `connect` label and other configured system names are reserved. Persistent
namespace depth is configurable and defaults to 2. Only the adjacent parent
owner may create a nested namespace, and tunnel creation never starts a
certificate order.

## 2. Install the release

Verify the selected archive with the release's `SHA256SUMS`. Install both
binaries as root-owned, non-writable executables:

```console
install -o root -g root -m 0755 sink /usr/local/bin/sink
install -o root -g root -m 0755 sink-server /usr/local/bin/sink-server
```

Create a non-login service identity and configuration directory using your
distribution's system tools. The service example expects a `sink` user/group,
`/etc/sink/sink-server.env` owned by `root:sink` with mode `0640`, and
systemd-managed `/var/lib/sink` state.

Copy `deploy/systemd/sink-server.service` to `/etc/systemd/system/` and the
environment example to `/etc/sink/`. Replace `example.com`, review the listen
addresses, Cloudflare values, ACME contact, SQLite path, and log filter. The
essential production settings are:

```dotenv
SINK_SERVER_HTTP_LISTEN_ADDRESS=127.0.0.1:8080
SINK_SERVER_HTTPS_LISTEN_ADDRESS=127.0.0.1:8443
SINK_SERVER_HTTPS_PROXY_PROTOCOL=required-v2
SINK_SERVER_HTTPS_PROXY_TRUSTED_PEER_CIDRS=127.0.0.1/32
SINK_SERVER_PUBLIC_BASE_DOMAIN=example.com
SINK_SERVER_MAX_NAMESPACE_DEPTH=2
SINK_SERVER_CERTIFICATE_PROVIDER=cloudflare
SINK_SERVER_CERTIFICATE_BACKEND_ENABLED=true
SINK_SERVER_ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
SINK_SERVER_ACME_CONTACT=mailto:admin@example.com
SINK_SERVER_ACME_TERMS_AGREED=true
SINK_SERVER_CLOUDFLARE_ZONE_ID=0123456789abcdef0123456789abcdef
SINK_SERVER_CLOUDFLARE_API_TOKEN=replace-with-zone-scoped-token
SINK_SERVER_SQLITE_PATH=/var/lib/sink/sink.sqlite3
```

Keep the environment file `root:sink` mode `0640`; the Cloudflare token is
environment-only and must not be placed on the command line. The trusted CIDR
above is correct only while Traefik connects from IPv4 loopback as in the
supplied dynamic example. Use the exact canonical `/32` or `/128` Sink observes
if that topology changes; never substitute a visitor or broad private range.
Then run:

```console
systemd-analyze verify /etc/systemd/system/sink-server.service
systemctl daemon-reload
systemctl enable --now sink-server
systemctl status sink-server
```

The server should bind HTTP on `127.0.0.1:8080` and managed/passthrough HTTPS on
`127.0.0.1:8443`; do not expose either upstream listener to an untrusted
network. Sink terminates only managed TLS on the latter. `--listen-address` /
`SINK_SERVER_LISTEN_ADDRESS` remains a legacy alias for the HTTP address, but
new deployments should use the explicit HTTP and HTTPS settings shown above.

The supplied unit uses `Type=simple`, so `systemctl is-active` proves process
liveness rather than application readiness. Wait for `sink server ready` after
base-certificate provisioning/reuse, durable-order reconciliation, resolver
loading, and namespace-boundary refresh. If no valid base certificate is
available, startup fails before either listener accepts traffic.

### Container alternative

Each published release builds `ghcr.io/ptrstovka/sink-server` for Linux amd64
and arm64. The image runs as UID/GID `10001`, listens on container ports 8080
for HTTP and 8443 for HTTPS, and stores SQLite state under `/data`. Create the
managed-TLS `.env` described in [Get Sink running](getting-started.md), then:

```console
cd deploy/docker
docker compose up -d
docker compose exec sink-server sink-server user create me
```

The example binds `127.0.0.1:42424` to container HTTP port 8080 and
`127.0.0.1:42425` to container HTTPS port 8443 for same-host Traefik. Keep the
named volume for upgrades. When replacing it with a bind mount, make the host
directory writable by UID/GID `10001`. Set
`SINK_HTTPS_PROXY_TRUSTED_PEER_CIDRS` in `.env` to the canonical peer address
seen inside the container. A host process reaching a Docker-published port may
appear as the bridge gateway rather than `127.0.0.1`; trust that exact `/32` or
`/128`, not the whole bridge network.

## 3. Configure Traefik

Copy `deploy/traefik/sink-dynamic.yml` into the existing file-provider
directory, replace every `example.com`, and merge the static fragment's
timeouts/provider settings into the existing Traefik install configuration.
Do not attach a buffering middleware or request-size limit to Sink routers.

The HTTP router on public port 80 matches the apex plus every descendant by
Host, preserves the original Host, and forwards to Sink's plain HTTP listener.
It performs no redirect. The TCP router on public port 443 matches the same
unbounded tree by SNI and forwards TLS unchanged to Sink's HTTPS listener with

```yaml
tls:
  passthrough: true
```

The service also prepends PROXY v2:

```yaml
loadBalancer:
  proxyProtocol:
    version: 2
```

Sink must require that header and trust only this immediate Traefik peer. In
`required-v2` mode it rejects untrusted peers plus missing, malformed,
oversized, unsupported, or `LOCAL` headers before reading the ClientHello. Do
not attach a Traefik certificate resolver to the Sink TCP router. Traefik must
not encode namespace depth or individual tunnel names; Sink's fail-closed SNI
and namespace policy decides which names are authorized. Unrelated domains on
the shared entry points continue to use their existing routers.

Validate the merged configuration with your existing Traefik validation and
reload process. Check the Traefik log for all Sink routers and file-provider
errors before changing DNS. Enabling the sender and Sink's `required-v2`
parser is a coordinated maintenance event: either one without the other breaks
all managed and passthrough TLS on this listener. After both are active, verify
a managed hostname through public port 443 before creating a passthrough claim.

## 4. Manage accounts

The systemd service runs as the `sink` OS service account. Sink accounts live
inside SQLite and are unrelated to that OS identity. Run account commands with
the same service identity and database path. For the supplied unit:

```console
sudo -u sink env \
  SINK_SERVER_SQLITE_PATH=/var/lib/sink/sink.sqlite3 \
  sink-server user create me
```

Run `list`, `rotate-token`, `disable`, and `enable` the same way. `create` and
`rotate-token` print the token once. Save it directly in the client config, or
use a secure channel when moving it to another machine. Listings never contain
reusable tokens. Rotation and disable immediately close existing tunnels; a
lost token must be rotated, not retrieved.

Persistent namespace operations use the authenticated client configuration:

```console
sink namespace claim team.example.com
sink namespace claim edge.example.com --passthrough
sink namespace list
sink namespace status team.example.com
sink namespace release team.example.com
```

Managed claim waits up to 300 seconds by default for certificate-backed active
state; `--no-wait` returns after acceptance and `--timeout` accepts 1 to 3600
seconds. Omitting `--passthrough` is managed mode. A passthrough claim becomes
active without Sink certificate issuance and reserves its apex plus one
direct-child scope for one wildcard route. Exact routes cannot override it and
deeper names are not implicitly covered. Release is rejected while child
claims or active routes remain.

## 5. Activate and operate an Edge passthrough route

Prepare and validate each trust boundary before creating the durable claim:

1. Back up SQLite and the active Sink/Traefik configuration, and retain the old
   binaries. Make Edge healthy on its internal HTTP port 80 and TLS port 443.
   Edge must own the public certificate and, if visitor addresses are required,
   accept PROXY v2 only from the exact Sink client peer.
2. Coordinate Traefik's HTTPS-service PROXY v2 sender with Sink's
   `required-v2` parser and peer CIDR. Wait for `sink server ready`, the HTTP
   health check, and a successful managed HTTPS probe through Traefik.
3. Store the client token with private file permissions and prepare the
   one-entry route file shown in the client reference. Keep credentials out of
   the route file and process command line; `sink connect` validates the whole
   file before starting any route.
4. Claim the namespace with `--passthrough`, then start the supervised
   `sink connect --config FILE` process. Verify HTTP reaches Edge port 80, TLS
   presents Edge's certificate from port 443 without byte changes, and Edge
   sees the expected source address.

The namespace claim persists in server SQLite across restarts. Its live HTTP
and raw-TLS broker does not: the client must reconnect. Run both server and
client under restart supervision. Prefer graceful client restarts so the old
route releases before the new process acquires it; after an abrupt exit a new
process may wait for the old run's reconnect grace. Health monitoring should
check the server's readiness log/HTTP health, one managed HTTPS name through
Traefik, and both HTTP and TLS on an Edge child. A listening process alone does
not prove the complete chain.

When the client, Edge, or broker is unavailable, durable passthrough ownership
fails closed: matching HTTP is unavailable and matching TLS closes. Sink does
not fall back to a managed certificate, parent certificate, or exact route.
This is expected during restart and must be monitored rather than bypassed.

To roll back one namespace, stop its client gracefully, remove child claims,
and release the passthrough claim after the route is gone. Only then claim the
same name in managed mode, wait for certificate-backed active state, and start
the replacement exact route. To roll back ingress PROXY v2, change the Traefik
sender and Sink requirement together; a one-sided rollback interrupts every
TLS route on the shared listener. Restoring the old server binary may also
require restoring a compatible SQLite backup; review migration notes first.
No rollback step introduces an HTTP-to-HTTPS redirect.

## 6. Back up, monitor, and upgrade

- Read logs with `journalctl -u sink-server`. They include authentication
  failures, tunnel and namespace lifecycle, certificate errors, conflicts, and
  forwarding errors, but not tokens, the Cloudflare credential, or HTTP bodies.
- Sink does not expose a metrics endpoint. Monitor disk space, file
  descriptors, memory, connection count, certificate expiry, and Traefik
  errors with your existing host and ingress tools.
- Back up SQLite with its online backup mechanism, or stop the service before
  copying the database. Copying only the main file while WAL writes are active
  can produce an inconsistent backup. Test restoration.
- Before upgrade, back up SQLite, verify the new release checksum, stage the
  old binary for rollback, replace the executable atomically, and restart the
  service. Review release notes for database migration or protocol changes.
- Use Traefik/host controls for rate limits and resource protection, but exempt
  intended streaming traffic from body buffering and fixed lifetime limits.
