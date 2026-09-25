# Get Sink running

One Sink installation has two programs:

- `sink-server` accepts public traffic on an internet-facing server.
- `sink` runs beside a local web service and opens an outbound tunnel to the
  server.

You need a domain, a Linux server with public ports 80 and 443 available, and a
Cloudflare API token that can manage DNS records for the domain.

## 1. Prepare DNS

Point your base domain and its wildcard at the server's public IP. For example,
if the Sink domain is `example.com`, create records for `example.com` and
`*.example.com`. Add explicit or delegated records for any deeper names that
your DNS setup does not cover.

Sink uses the base domain for generated tunnel addresses and reserves
`connect.example.com` for client connections.

## 2. Start the server

The supplied Compose file publishes Sink directly on host ports 80 and 443.
Create `deploy/docker/.env`:

```dotenv
SINK_PUBLIC_BASE_DOMAIN=example.com
SINK_VERSION=RELEASE_VERSION
SINK_MAX_NAMESPACE_DEPTH=2
SINK_ACME_CONTACT=mailto:admin@example.com
SINK_CLOUDFLARE_ZONE_ID=0123456789abcdef0123456789abcdef
SINK_CLOUDFLARE_API_TOKEN=replace-with-zone-scoped-token
```

Keep this file private, then start the server:

```console
cd deploy/docker
docker compose pull
docker compose up -d
docker compose logs -f sink-server
```

The container runs without root privileges. Its SQLite database and certificate
state live in the `sink-data` volume, so keep that volume across upgrades.

Startup is complete when the logs contain `sink server ready`. On first start,
Sink must create its ACME account and obtain the base-domain certificate before
it accepts traffic. Verify that both of these URLs reach the server:

```text
http://example.com
https://example.com
```

Sink serves HTTP and HTTPS independently and does not add an HTTP-to-HTTPS
redirect.

## 3. Create an account

Create an account for the client:

```console
docker compose exec sink-server sink-server user create me
```

Copy the token when it appears. Sink shows it only once. If it is lost, replace
it with `sink-server user rotate-token me`.

## 4. Configure the client

Install `sink` from the same release, then save the server address and token:

```console
sink config add-server-addr https://connect.example.com
sink config add-authtoken YOUR_TOKEN
```

The token is stored in the client's private configuration file.

## 5. Open a tunnel

If the local application is available at `http://localhost:3000`, run:

```console
sink http 3000
```

Sink prints the public HTTP and HTTPS URLs. Keep the command running while the
tunnel is in use. To choose a hostname:

```console
sink http 3000 --url https://demo.example.com
```

Targets may also be a `host:port`, an `http://` URL, or an `https://` URL.

## 6. Optionally reserve a namespace

Generated and chosen tunnel names are runtime leases. To reserve a persistent
managed namespace for an account, run:

```console
sink namespace claim team.example.com
sink namespace list
```

The claim covers its apex and one wildcard level. After it becomes active, the
account can open tunnels such as `https://demo.team.example.com`.

For configuration options, upgrades, backups, and advanced TLS passthrough,
continue with the [server deployment reference](server-reference.md) and
[client reference](client-reference.md).
