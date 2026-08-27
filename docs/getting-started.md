# Get Sink running

One Sink installation has two programs:

- `sink-server` runs on your internet-facing server, behind Traefik.
- `sink` runs on your computer and connects one of your local apps to that
  server.

You normally manage both. Start with one server, one account, and one token;
you can add more accounts later.

## 1. Start your server

The supplied Compose file expects Traefik on the same machine and publishes the
Sink listener only on `127.0.0.1:42424`. Create a `.env` file beside it:

```dotenv
SINK_PUBLIC_BASE_DOMAIN=example.com
SINK_VERSION=0.0.1
SINK_HOST_PORT=42424
```

Then start Sink:

```console
cd deploy/docker
docker compose pull
docker compose up -d
docker compose logs -f sink-server
```

The container runs without root privileges. Its SQLite database lives in the
named `sink-data` volume, so recreating or upgrading the container does not
remove your account or token state. `docker compose ps` shows whether the
server's built-in HTTP health check is passing.

Replace `example.com` with your own domain. Sink has no built-in domain and the
server refuses to start until `SINK_SERVER_PUBLIC_BASE_DOMAIN` or
`--public-base-domain` is set.

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

## 4. Open your first tunnel

If your local app is available at `http://localhost:3000`, run:

```console
sink http 3000
```

Sink prints both public URLs. Keep the command running while you use the
tunnel. To choose a memorable one-label hostname:

```console
sink http 3000 --url https://demo.example.com
```

Targets such as `http://laravel-demo.test` and local HTTPS URLs also work:

```console
sink http http://laravel-demo.test
sink http https://localhost:8443
```

## 5. Connect Traefik

Traefik should send the apex host, `connect.<your-domain>`, and wildcard tunnel
hosts to `http://127.0.0.1:42424`. Adapt the supplied files under
`deploy/traefik/` and replace `example.com` with your domain. Keep HTTP enabled
for public tunnel hosts; only plaintext control traffic is redirected to HTTPS.

Use the [server deployment reference](server-reference.md) for DNS, TLS,
backups, upgrades, and hardening. The [client reference](client-reference.md)
covers target formats, reconnect behavior, and TLS options.
