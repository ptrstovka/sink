# sink

Sink is a self-hosted reverse tunnel for HTTP and HTTPS. Run the `sink` client
beside a local web service, and `sink-server` makes it available at a generated
or chosen subdomain of your own domain.

Sink streams request and response bodies without buffering them in full. It
supports large transfers, SSE, WebSockets, concurrent requests, reconnecting
with the same public address, and bearer-token accounts. The client also has a
loopback traffic inspector for viewing and deliberately replaying bounded
request/response previews while a tunnel is running.

## How it fits together

```text
public visitor --HTTP/S--> Traefik --plaintext HTTP--> sink-server
                                                       ^
sink client --authenticated TLS control WebSocket------+---> local HTTP/S app
```

Traefik owns public TLS. Both `connect.<base-domain>` and public tunnel hosts
route to one loopback-bound `sink-server` listener. See
[architecture](docs/architecture.md) and [security model](docs/security-model.md).

## Install

GitHub Releases contain archives for macOS arm64/x86_64 and Linux
arm64/x86_64. Linux archives use musl targets. Each archive contains `sink` and
`sink-server` plus the MIT license; verify it against the release's
`SHA256SUMS` before installing. Published releases also produce a multi-platform
server image at `ghcr.io/ptrstovka/sink-server`. The macOS executables are
Developer ID signed and notarized by Apple.

After installing the client, `sink update` immediately installs the matching
client from the latest stable GitHub Release once its exact platform archive
and `SHA256SUMS` are attached. The command does not ask for a second
confirmation and never updates `sink-server`. It supports the same four
standalone macOS/Linux architectures and verifies the GitHub asset digest,
`SHA256SUMS`, and staged client version before replacement.

[Get Sink running](docs/getting-started.md) installs both programs and opens the
first tunnel. Use the [server deployment reference](docs/server-reference.md)
and [client reference](docs/client-reference.md) for the remaining options.

## Quick client use

```console
sink config add-server-addr https://connect.example.com
sink config add-authtoken TOKEN
sink http 3000
sink http 3000 --url https://demo.example.com
```

Targets may also be `host:port`, `http://...`, or `https://...`. The control
connection and local HTTPS targets validate certificates by default.

An interactive `sink http` start checks for a stable client update in the
background at most once per 24 hours. A cached available version is shown on
every interactive start. Service and other noninteractive runs do not check;
`SINK_NO_UPDATE_CHECK=1` disables only this startup check and notice, not the
explicit `sink update` command.

The inspector is enabled by default. `sink` prints a URL such as
`http://127.0.0.1:4040`; the URL contains no mutation token. Its HTML,
JavaScript, and styles are embedded in the `sink` executable, so an installed
binary needs no Node.js, dashboard directory, or CDN. Use `--inspect=false` to
disable it or `--dashboard-port PORT` to choose its loopback port. See the
[client reference](docs/client-reference.md) for inspector behavior and the
[security model](docs/security-model.md) before revealing or exporting secrets.

## Quick server use

```console
sink-server serve --public-base-domain example.com
sink-server user create me
sink-server user list
sink-server user rotate-token me
sink-server user disable me
sink-server user enable me
```

The [CLI reference](docs/cli-reference.md) summarizes the available commands
and settings.

## Tests and releases

CI installs Node 24 with its bundled npm, runs `npm ci` and `npm run verify` in
`dashboard`, then reuses that production `dashboard/dist` for formatting,
locked Clippy-with-warnings-denied, and locked bounded workspace tests. The npm
commands already include the frontend tests, typecheck, production build, and
source and bundle guards. Run the 1 GiB transfers, one-hour soak, and
disruption/performance workloads manually. See
[acceptance tests](docs/acceptance-tests.md).

Published releases build all four supported binary targets from a full checkout
and the server container. Publishing a Cargo source package is not part of that
contract because the ignored prebuilt dashboard output is not contained in a
workspace source archive. The [release guide](docs/releasing.md) documents the
Apple credentials required for macOS signing and notarization and the packaged
inspector smoke.

## Limits and license

See [deployment boundaries](docs/deployment-boundaries.md) before changing the
documented topology. Sink is available under the [MIT](LICENSE-MIT) license.
