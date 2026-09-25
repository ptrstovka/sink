# Get Sink running

One Sink installation has two programs:

- `sink-server` runs on your internet-facing server, behind Traefik.
- `sink` runs on your computer and connects one of your local apps to that
  server.

You normally manage both. Start with one server, one account, and one token;
you can add more accounts later.

## 1. Start your server

The supplied Compose file expects Traefik on the same machine and publishes the
Sink HTTP and HTTPS listeners only on host loopback. Create a `.env` file beside
it:

```dotenv
SINK_PUBLIC_BASE_DOMAIN=example.com
SINK_VERSION=VERSION_WITH_MANAGED_TLS
SINK_HTTP_HOST_PORT=42424
SINK_HTTPS_HOST_PORT=42425
# Set this to the canonical /32 or /128 that sink-server observes for Traefik.
# With a host Traefik and a published Docker port, it may be the bridge gateway.
SINK_HTTPS_PROXY_TRUSTED_PEER_CIDRS=192.0.2.10/32
SINK_MAX_NAMESPACE_DEPTH=2
SINK_ACME_CONTACT=mailto:admin@example.com
SINK_CLOUDFLARE_ZONE_ID=0123456789abcdef0123456789abcdef
SINK_CLOUDFLARE_API_TOKEN=replace-with-zone-scoped-token
```

Use a release containing managed TLS, replace the example zone values, and
keep the `.env` file private. The Compose configuration enables the Cloudflare
certificate backend, agrees to the configured ACME terms, and explicitly uses
the Let's Encrypt production directory
`https://acme-v02.api.letsencrypt.org/directory`; the server's code default is
staging. It also requires PROXY v2 on the HTTPS listener. Replace the
documentation-only peer CIDR with the exact address Sink observes for Traefik;
do not trust the example range or a broad Docker/private subnet.

Then start Sink:

```console
cd deploy/docker
docker compose pull
docker compose up -d
docker compose logs -f sink-server
```

The container runs without root privileges. Its SQLite database lives in the
named `sink-data` volume, so recreating or upgrading the container does not
remove account, token, namespace, ACME, or certificate state. The process binds
container ports 8080 for HTTP and 8443 for managed or passthrough HTTPS;
Compose maps them to `127.0.0.1:42424` and `127.0.0.1:42425` by default. Sink
terminates only managed TLS.

Initial managed-TLS startup is ready only after durable certificate state is
reconciled, the base apex-plus-wildcard certificate is provisioned or reused,
and the managed/passthrough namespace indexes are loaded. Wait for
`sink server ready` in the logs. A running container or bound socket alone is
not readiness; the built-in HTTP health check cannot pass until Sink starts
accepting traffic. After Traefik is configured, also probe one managed HTTPS
name through public port 443 to verify that Traefik's PROXY v2 sender and Sink's
required parser agree.

Replace `example.com` with your own domain. Sink has no built-in domain and the
server refuses to start until `SINK_SERVER_PUBLIC_BASE_DOMAIN` or
`--public-base-domain` is set. DNS must send the apex and every intended
descendant to Traefik. Sink, not Traefik, obtains and serves certificates for
the base domain and managed namespaces; each passthrough Edge owns its own
certificates.

## 2. Create your token

Create one account for yourself. The name is just a label stored in your own
database; `me` is fine:

```console
docker compose exec sink-server sink-server user create me
```

Copy the token when it appears. Sink shows it only once. If you lose it, create
a replacement with `sink-server user rotate-token me`.

## 3. Configure the client on your computer

Install the `sink` binary from the same GitHub release, then save your server
address and token:

```console
sink config add-server-addr https://connect.example.com
sink config add-authtoken YOUR_TOKEN
```

The token is stored in your private local config file. You do not need to put it
in your project or pass it on every command.

## 4. Connect Traefik

Adapt the supplied files under `deploy/traefik/` and replace `example.com` with
your domain. On public port 80, Traefik uses HTTP Host routing for the apex and
every descendant and sends plain HTTP to `http://127.0.0.1:42424`. On public
port 443, its TCP router uses SNI for the same unbounded tree and passes TLS
unchanged, after a PROXY v2 header, to `127.0.0.1:42425`. Sink terminates
managed TLS, but forwards passthrough TLS unchanged to Edge. Do not configure a
redirect or a Traefik certificate resolver for the Sink tree.

Coordinate enabling Traefik's PROXY v2 sender with Sink's `required-v2`
setting: a one-sided change breaks every TLS route on the shared listener.
Validate the Compose and Traefik configurations, wait for `sink server ready`
and a healthy container, then verify a managed HTTPS name through Traefik.
Complete this trust-chain activation before creating a passthrough claim.

## 5. Optionally claim a namespace

The base domain is owned by Sink, and system names such as `connect` are
reserved. To reserve a persistent managed namespace for your account, run:

```console
sink namespace claim team.example.com
sink namespace list
```

Managed claim waits for certificate provisioning by default and prints the
active state when ready. Use `--no-wait` to return after acceptance or
`--timeout` with 1 to 3600 seconds to change the default 300-second wait. The
claim covers its apex plus one wildcard. Only the parent owner may create the
next nested claim, and the server's configured maximum namespace depth still
applies. Starting a tunnel never triggers certificate issuance.

To let an Edge service own the certificate and TLS handshake instead, first
make Edge healthy on its internal ports 80 and 443, then make the mode explicit:

```console
sink namespace claim edge.example.com --passthrough
sink namespace status edge.example.com
```

Omitting `--passthrough` remains managed mode. A passthrough claim needs no
Sink certificate and covers exactly its apex plus one direct child. Exact
routes cannot override that scope, and deeper hostnames are not implicitly
covered. The durable claim fails closed while its client or Edge is
unavailable.

## 6. Open a tunnel

If your local app is available at `http://localhost:3000`, run:

```console
sink http 3000
```

Sink prints both public URLs. Keep the command running while you use the
tunnel. To choose a memorable hostname in the root pool:

```console
sink http 3000 --url https://demo.example.com
```

An active managed namespace also permits tunnel hosts immediately below it,
for example `https://demo.team.example.com` after `team.example.com` is active.
Every registered route is available over both HTTP and HTTPS; Sink performs no
automatic redirect.

Targets such as `http://laravel-demo.test` and local HTTPS URLs also work:

```console
sink http http://laravel-demo.test
sink http https://localhost:8443
```

For the passthrough Edge claim, create `edge-routes.toml` beside the client
service configuration:

```toml
[[routes]]
name = "edge"
url = "https://edge.example.com"
target = "http://edge.internal:80"
tls_target = "tcp://edge.internal:443"
proxy_protocol = "v2"
inspect = false
```

Run `sink connect --config edge-routes.toml` under a process manager. One entry
and one session pair ordinary HTTP with raw TLS for the namespace apex and
direct children. `proxy_protocol = "v2"` makes the client build a fresh header
for Edge; omit it if Edge does not need the visitor socket address. Edge must
trust PROXY v2 only from this Sink client peer and must present the correct
certificate on port 443. Keep the bearer token in the private Sink client
config, not in the route file or service command line. The example disables
HTTP preview retention; raw TLS is never inspected. Verify an HTTP response,
the Edge certificate on TLS, and the source address Edge sees.

For rollback, stop the client gracefully, release the passthrough namespace
after its live route and any child claims are gone, and only then create a
managed claim if desired. Wait for that certificate-backed claim to become
active before starting an exact managed route. If rolling back ingress PROXY
v2 itself, change Traefik and Sink together. Preserve the SQLite volume and the
old binaries/configuration throughout the rollback window.

Use the [server deployment reference](server-reference.md) for DNS, TLS,
backups, upgrades, and hardening. The [client reference](client-reference.md)
covers target formats, reconnect behavior, and TLS options.
