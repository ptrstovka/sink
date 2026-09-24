# Server deployment reference

This reference assumes you run one Linux host with `sink-server` behind an
existing Traefik v3 instance. Start with [Get Sink running](getting-started.md)
for the complete server-and-client setup. Multiple server replicas are not
supported; see [deployment boundaries](deployment-boundaries.md).

## 1. Prepare DNS and managed TLS

Point `example.com` and every intended descendant at Traefik. The apex needs
its own DNS record; arrange wildcard, delegated, or explicit records so deeper
names also reach the same public address. The whole configured tree belongs to
Sink even though Traefik continues sharing that address with unrelated domains.

Do not provision the Sink certificate in Traefik. Sink uses Cloudflare DNS-01
and ACME to provision the base-domain apex plus one wildcard, and each accepted
namespace claim provisions its apex plus one wildcard. Use a zone-scoped
Cloudflare API token, preserve the SQLite certificate/order state, and set the
production ACME directory explicitly because the server default is staging:

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
environment-only and must not be placed on the command line. Then run:

```console
systemd-analyze verify /etc/systemd/system/sink-server.service
systemctl daemon-reload
systemctl enable --now sink-server
systemctl status sink-server
```

The server should bind HTTP on `127.0.0.1:8080` and Sink-terminated HTTPS on
`127.0.0.1:8443`; do not expose either upstream listener to an untrusted
network. `--listen-address` / `SINK_SERVER_LISTEN_ADDRESS` remains a legacy
alias for the HTTP address, but new deployments should use the explicit HTTP
and HTTPS settings shown above.

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
directory writable by UID/GID `10001`.

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

Do not attach a Traefik certificate resolver to the Sink TCP router. Traefik
must not encode namespace depth or individual tunnel names; Sink's fail-closed
SNI and namespace policy decides which names are authorized. Unrelated domains
on the shared entry points continue to use their existing routers.

Validate the merged configuration with your existing Traefik validation and
reload process. Check the Traefik log for all Sink routers and file-provider
errors before changing DNS.

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
sink namespace list
sink namespace status team.example.com
sink namespace release team.example.com
```

Claim waits up to 300 seconds by default for certificate-backed active state;
`--no-wait` returns after acceptance and `--timeout` accepts 1 to 3600 seconds.
Release is rejected while child claims or active routes remain.

## 5. Back up, monitor, and upgrade

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
