# sink

Sink is a self-hosted reverse tunnel for HTTP and HTTPS. Run the `sink` client
beside a local web service, and `sink-server` makes it available at a generated
or chosen subdomain of your own domain.

Sink streams request and response bodies without buffering them in full. It
supports large transfers, SSE, WebSockets, concurrent requests, reconnecting
with the same public address, and bearer-token accounts.

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
`sink-server` plus both license texts; verify it against the release's
`SHA256SUMS` before installing. Published releases also produce a multi-platform
server image at `ghcr.io/ptrstovka/sink-server`. The macOS executables are
Developer ID signed and notarized by Apple.

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

## Tests

CI runs formatting, Clippy with warnings denied, and bounded workspace tests.
Run the 1 GiB transfers, one-hour soak, and disruption/performance workloads
manually. See [manual acceptance tests](docs/acceptance-tests.md).

## Releasing

Published releases build all supported binaries and the server container. The
[release guide](docs/releasing.md) documents the Apple credentials required for
macOS signing and notarization.

## Limits and license

See [deployment boundaries](docs/deployment-boundaries.md) before changing the
documented topology. Sink is available under the [MIT](LICENSE-MIT) license.
