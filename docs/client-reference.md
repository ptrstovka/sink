# Client reference

## Install and configure

Download the archive matching the machine from GitHub Releases, then verify the
download before extracting it:

```console
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf sink-VERSION-PLATFORM.tar.gz
install -m 0755 sink ~/.local/bin/sink
```

On macOS, use `shasum -a 256 -c SHA256SUMS` if `sha256sum` is unavailable.
Store the token you created on your server and its control address:

```console
sink config add-server-addr https://connect.example.com
sink config add-authtoken TOKEN
```

The config file is readable only by your account. Keep it out of repositories
and images. One-run overrides are available with `--authtoken` and
`--server-addr`, but command-line secrets may be visible in process listings.

## Open a tunnel

```console
sink http 3000
sink http host.local:3000
sink http https://localhost:8443
sink http 3000 --url https://demo.example.com
```

A number means HTTP on localhost. A target without a scheme defaults to HTTP;
an explicit `https://` uses TLS to the local service. With no `--url`, the
server allocates a subdomain. A chosen URL must be one valid DNS label below
your server's base domain, and `connect` is reserved.

The client prints its local target, public HTTP and HTTPS URLs, connection
state, and completed-request summaries. Keep it running. After a transient
network or server interruption it reconnects and reclaims the same address.
The interrupted in-flight operation fails and is never replayed; new traffic
works after reconnection.

## TLS behavior

Authenticated control traffic requires TLS and hostname validation in normal
use. `--allow-plaintext-control` permits an explicitly configured `http://`
control origin for local development only. Local HTTPS certificates are also
validated by default; `--local-tls-insecure` applies only to an explicit
`https://` local target, never to control transport.

## Common failures

- Authentication rejected: the client will not retry invalid credentials.
  Check whether the account is disabled or its token was rotated, then save the
  current token.
- Address conflict: choose another name or wait until the active claimant exits.
- Public `503`: the client is disconnected or its local target is unavailable;
  start the target and retry a new request.
- Local HTTPS certificate error: fix the certificate trust/hostname. Use the
  development opt-out only for a target you control.
- Missing configuration: save the token and server address, or pass
  `--authtoken` and `--server-addr` for that run. Sink has no built-in server
  address.
