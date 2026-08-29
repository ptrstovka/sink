# Server deployment reference

This reference assumes you run one Linux host with `sink-server` behind an
existing Traefik v3 instance. Start with [Get Sink running](getting-started.md)
for the complete server-and-client setup. Multiple server replicas are not
supported; see [deployment boundaries](deployment-boundaries.md).

## 1. Prepare DNS and TLS

Point `connect.example.com` and `*.example.com` at Traefik. Add a separate
`example.com` record if the minimal apex response is wanted; wildcard DNS does
not cover the apex. Provision a certificate covering `*.example.com`. Include
`example.com` as a SAN if the HTTPS apex router is retained.

The `connect` label is reserved for authenticated control traffic and must
never be assigned as a public tunnel.

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
address, SQLite path, and log filter, then run:

```console
systemd-analyze verify /etc/systemd/system/sink-server.service
systemctl daemon-reload
systemctl enable --now sink-server
systemctl status sink-server
```

The server should bind `127.0.0.1:8080`; do not expose its plaintext listener
to an untrusted network.

### Container alternative

Each published release builds `ghcr.io/ptrstovka/sink-server` for Linux amd64
and arm64. The image runs as UID/GID `10001`, listens on container port `8080`,
and stores SQLite state under `/data`. For the supplied Compose deployment:

```console
cd deploy/docker
SINK_PUBLIC_BASE_DOMAIN=example.com SINK_VERSION=0.2.0 docker compose up -d
docker compose exec sink-server sink-server user create me
```

The example binds only `127.0.0.1:42424` on the host for a same-host Traefik
service. Keep the named volume for upgrades. When replacing it with a bind
mount, make the host directory writable by UID/GID `10001`.

## 3. Configure Traefik

Copy `deploy/traefik/sink-dynamic.yml` into the existing file-provider
directory, replace every `example.com`, and merge the static fragment's
timeouts/provider settings into the existing Traefik install configuration.
Do not attach a buffering middleware or request-size limit to Sink routers.

The connect and wildcard routers keep public HTTP available, terminate
public/control HTTPS, redirect plaintext control requests to HTTPS, preserve
the original Host, and send everything to the same plaintext backend. Two
optional apex routers expose the minimal base-domain response. The higher
explicit priority prevents the wildcard router from taking `connect`.

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

## 5. Back up, monitor, and upgrade

- Read logs with `journalctl -u sink-server`. They include authentication
  failures, tunnel lifecycle, conflicts, and forwarding errors, but not tokens
  or HTTP bodies.
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
