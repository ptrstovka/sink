# sink

Sink is a minimal self-hosted HTTP/HTTPS reverse tunnel. A developer runs the
`sink` client beside a local web service; `sink-server` makes that service
available at a generated or chosen subdomain of the operator's domain.

The MVP is implemented as a Rust workspace. Its contract includes streaming
bodies, large transfers, SSE, WebSockets,
concurrent requests, reconnect with the same public address, and multi-user
bearer-token authentication.

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
`SHA256SUMS` before installing.

Operators should start with the [operator guide](docs/operator-guide.md) and
the examples under `deploy/`. Users should start with the
[client guide](docs/client-guide.md).

## Quick client use

```console
sink config add-server-addr https://connect.example.com
sink config add-authtoken TOKEN
sink http 3000
sink http 3000 --url https://demo.example.com
```

Targets may also be `host:port`, `http://...`, or `https://...`. The control
connection and local HTTPS targets validate certificates by default.

## Quick operator use

```console
sink-server serve
sink-server user create alice
sink-server user list
sink-server user rotate-token alice
sink-server user disable alice
sink-server user enable alice
```

The command families above are part of the MVP contract; all current options
are summarized in the [CLI reference](docs/cli-reference.md). Check each
installed binary's `--help` before automating across versions.

## Verification policy

Normal CI runs formatting, Clippy with warnings denied, and bounded workspace
tests. The 1 GiB transfer checks, one-hour soak, and disruption/performance
stress workloads are deliberately manual and opt-in. See
[manual acceptance tests](docs/acceptance-tests.md).

## Scope and license

Known infrastructure and product limits are recorded in
[deployment boundaries](docs/deployment-boundaries.md). Sink is dual-licensed
under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
