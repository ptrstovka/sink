# Server deployment reference

This reference covers a single `sink-server` process with one SQLite database.
The server can listen directly on a public IP. Clustering, shared tunnel claims,
and active/active replicas are not supported.

Start with [Get Sink running](getting-started.md) for the shortest setup.

## DNS and certificates

Point the base domain and every intended tunnel hostname at the server's public
IP. A base-domain apex record plus a wildcard record is sufficient for common
setups; add explicit or delegated records where necessary.

Sink obtains and serves certificates through ACME DNS-01. The current
certificate provider is Cloudflare, so managed TLS requires a zone-scoped API
token, the zone ID, an ACME contact, and explicit agreement to the ACME terms.
The built-in ACME directory default is Let's Encrypt staging. Production
deployments must explicitly select:

```text
https://acme-v02.api.letsencrypt.org/directory
```

The base domain receives an apex-plus-wildcard certificate. Each managed
namespace claim receives its own apex-plus-wildcard certificate. Preserve the
SQLite database because it contains certificate and ACME account state.

## Install the binaries

Verify the selected release archive against `SHA256SUMS`, then install the
binaries as root-owned, non-writable executables:

```console
install -o root -g root -m 0755 sink /usr/local/bin/sink
install -o root -g root -m 0755 sink-server /usr/local/bin/sink-server
```

The supplied systemd unit expects a `sink` service account,
`/etc/sink/sink-server.env`, and a systemd-managed `/var/lib/sink` directory.
Copy the files from `deploy/systemd/`, then configure the environment:

```dotenv
SINK_SERVER_HTTP_LISTEN_ADDRESS=0.0.0.0:80
SINK_SERVER_HTTPS_LISTEN_ADDRESS=0.0.0.0:443
SINK_SERVER_HTTPS_PROXY_PROTOCOL=disabled
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

Keep the environment file owned by `root:sink` with mode `0640`. The API token
is accepted only through the environment and must not be placed on the command
line. The supplied unit grants only `CAP_NET_BIND_SERVICE` so the unprivileged
service can bind ports 80 and 443.

Allow inbound TCP ports 80 and 443 in the host firewall, then start the service:

```console
systemd-analyze verify /etc/systemd/system/sink-server.service
systemctl daemon-reload
systemctl enable --now sink-server
journalctl -u sink-server -f
```

Wait for `sink server ready`. The process does not accept traffic until it has
reconciled certificate state, obtained or loaded a valid base certificate, and
loaded its namespace routing state.

### Container deployment

The server image runs as UID/GID `10001`, listens on container ports 8080 and
8443, and stores state under `/data`. The supplied Compose file maps public host
ports 80 and 443 to those listeners:

```console
cd deploy/docker
docker compose pull
docker compose up -d
docker compose logs -f sink-server
```

Keep the `sink-data` volume across upgrades. If you replace it with a bind
mount, make the directory writable by UID/GID `10001`. Change
`SINK_HTTP_HOST_PORT` or `SINK_HTTPS_HOST_PORT` only when another layer is
responsible for exposing the standard public ports.

## Manage accounts

Sink accounts live in SQLite and are separate from the operating-system service
account. With the supplied systemd unit, run administration commands as:

```console
sudo -u sink env \
  SINK_SERVER_SQLITE_PATH=/var/lib/sink/sink.sqlite3 \
  sink-server user create me
```

The other account commands are `list`, `rotate-token`, `disable`, and `enable`.
Creation and rotation print the token once. Rotation and disable close active
tunnels immediately.

With Compose, use:

```console
docker compose exec sink-server sink-server user create me
```

## Manage namespaces

Persistent namespace operations use the authenticated client configuration:

```console
sink namespace claim team.example.com
sink namespace list
sink namespace status team.example.com
sink namespace release team.example.com
```

A managed claim reserves its apex and one wildcard level and waits for
certificate provisioning by default. Use `--no-wait` to return after the claim
is accepted, or `--timeout` to change the wait limit. A claim cannot be released
while it has child claims or active routes.

Raw TLS passthrough is an advanced namespace mode. Its route configuration and
trust requirements are documented in the [client reference](client-reference.md)
and [security model](security-model.md).

## Backups, monitoring, and upgrades

- Read service logs with `journalctl -u sink-server` or
  `docker compose logs sink-server`.
- Monitor disk space, file descriptors, memory, connection count, certificate
  expiry, and public HTTP/HTTPS reachability.
- Back up SQLite with its online backup mechanism, or stop the server before
  copying it. Copying only the main file while WAL writes are active can produce
  an inconsistent backup.
- Before an upgrade, back up SQLite, verify the new release checksum, keep the
  previous binary or image available for rollback, and review the release notes
  for database or protocol changes.
- Preserve streaming behavior when applying host-level rate limits or resource
  controls. Avoid request buffering, small body limits, and short connection
  lifetimes for routes that use uploads, downloads, SSE, or WebSockets.

## Optional reverse proxy

A reverse proxy is not required. If one is used, it must preserve the original
HTTP Host, pass TLS through unchanged so Sink can select and terminate managed
certificates, and allow long-lived streaming connections.

The HTTPS listener's PROXY protocol mode is disabled by default. Enable
`required-v2` only when the immediate TCP proxy sends PROXY v2, and restrict
`SINK_SERVER_HTTPS_PROXY_TRUSTED_PEER_CIDRS` to that proxy's exact canonical
address range. A mismatch between sender and receiver prevents HTTPS traffic
from reaching Sink.
