# Client reference

## Install and configure

Download the archive matching the machine from GitHub Releases, then verify the
download before extracting it:

```console
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf sink-VERSION-PLATFORM.tar.gz
install -m 0755 sink ~/.local/bin/sink
```

On macOS, use `shasum -a 256 -c SHA256SUMS --ignore-missing` if `sha256sum` is
unavailable.

The standalone client can update itself after installation:

```console
sink update
```

This explicit command is consent to install immediately and does not ask for a
second confirmation. It selects the matching client archive from the latest
stable GitHub Release, extracts only `sink`, and never updates `sink-server`.
The supported release assets are:

| System | Architecture | Asset |
| --- | --- | --- |
| macOS | arm64 | `sink-v<version>-macos-arm64.tar.gz` |
| macOS | x86_64 | `sink-v<version>-macos-x86_64.tar.gz` |
| Linux | arm64 | `sink-v<version>-linux-arm64.tar.gz` |
| Linux | x86_64 | `sink-v<version>-linux-x86_64.tar.gz` |

Before replacing the running client, Sink verifies the GitHub asset digest,
the archive checksum in the release's `SHA256SUMS`, and that the staged
client's `sink version` matches the selected release. A release is eligible
only when both the exact platform archive and `SHA256SUMS` exist. There is no
prerelease, channel, pinned-version, or downgrade support.

The installed client's path must be writable. If it is not, the update fails
without invoking `sudo` or replacing the binary. Have the administrator update
the system installation, explicitly run the command with the privilege
appropriate for that path, or reinstall `sink` in a user-writable directory.

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

## Raw TLS passthrough

Claim the namespace with the explicit passthrough mode. Omitting the flag
continues to create a managed-TLS namespace:

```console
sink namespace claim tls.example.com --passthrough
sink namespace status tls.example.com
```

A passthrough claim becomes active without requesting a certificate from
Sink's ACME provider. Its route covers exactly `tls.example.com` and one direct
child such as `app.tls.example.com`. It does not cover
`deep.app.tls.example.com`, and neither the apex nor a covered direct child can
be shadowed by an exact route. Use a separate authorized namespace for deeper
names.

Run the namespace with one `[[routes]]` entry and one control session. For
example, save this as `passthrough-routes.toml`:

```toml
[[routes]]
name = "passthrough"
url = "https://tls.example.com"
target = "http://service.internal:80"
tls_target = "tcp://service.internal:443"
proxy_protocol = "v2"
inspect = false
```

The route `url` is the claimed namespace apex. Its normal `target` receives
HTTP for the apex and direct children through the HTTP tunnel. `tls_target`
must be a `tcp://host:port` address and receives the original TLS bytes for the
same scope. The local TLS service presents and manages the certificate on port
443; Sink never terminates the passthrough handshake. There is no implicit
HTTP-to-HTTPS redirect. The example explicitly disables the HTTP inspector;
raw TLS is never inspected regardless of this setting.

`proxy_protocol = "v2"` is optional. When present, the client creates a fresh
PROXY v2 header from the source/destination metadata authenticated by
`sink-server` and writes it before the untouched TLS bytes. Configure the local
TLS service to accept PROXY v2 only from the exact Sink client peer. When the
field is omitted, the client sends no PROXY header. `proxy_protocol` is invalid
without `tls_target`; the only accepted outgoing version is `v2`.

The command validates the entire file before it starts any route:

```console
sink connect --config passthrough-routes.toml
```

Authentication and the control server remain in the private saved client
configuration or the command's global overrides; they are not route-file
fields. Keep the route file private if internal hostnames are sensitive. A
generic `[[routes]]` entry with only `name`, `url`, and `target` remains an exact
HTTP/managed-TLS route: raw TLS and outgoing PROXY v2 are off by default.

Use a process manager for production. Restart gracefully so the old route is
released before the replacement starts. An unexpected exit retains the lease
briefly for same-run reconnect; a new process has a new run identity and may
need to wait for that grace period. The durable namespace persists in server
SQLite, but the HTTP and raw-TLS broker exists only while `sink connect` is
connected. During client or local-service downtime the namespace fails closed.

## Cross-origin assets and requests

CORS is opt-in per tunnel and applies to all its HTTP paths for the current run.
Configure the tunnel serving the assets, naming the origin of the page loading
them:

```console
sink http 3000 --url https://assets.example.com --cors-allow-origin https://app.example.com
sink http 3000 --url https://assets.example.com --cors-allow-origin '*'
sink http 3000 --url https://assets.example.com --cors-allow-origin https://app.example.com --cors-allow-credentials
```

For the reverse direction, configure the `app` tunnel to allow
`https://assets.example.com`. Repeat `--cors-allow-origin` to allow multiple origins.
Origins include the scheme and optional port; paths, query strings, fragments,
URL credentials, bare hostnames, `null`, and patterns such as `*.example.com` are
not accepted. Quote `'*'` so the shell does not expand it into filenames.
Wildcard cannot be combined with other origins or `--cors-allow-credentials`.

With CORS enabled, Sink replaces upstream `Access-Control-*` response headers
with its policy. Enabled policies add `Vary: Origin` while retaining existing
`Vary` values. Requests from unmatched origins still reach the application, but
the response carries no CORS permission. Without these options, all existing
upstream CORS behavior is preserved.

Sink handles CORS preflight (`OPTIONS` with `Origin` and
`Access-Control-Request-Method`) locally: allowed requests receive `204` with
the requested method and headers, including `Authorization`; denied origins
receive `403`, and malformed preflights receive `400`. These responses use
`Cache-Control: no-store` and appear in the inspector. Ordinary `OPTIONS`
requests continue to the application. The policy applies to streamed responses
and client-generated proxy errors, but not WebSocket upgrades, direct local
replays, or the loopback inspector itself. Errors generated by the public
server before reaching a connected client cannot receive this client policy.

CORS lets browsers read cross-origin responses; it does not authenticate users
or change browser cookie rules. Credentialed fetches still need the caller's
`credentials: "include"` and appropriate application cookie settings. The
wildcard mode is intended for public resources without credentialed fetches.
Enabling the policy permits requested methods and headers for allowed origins;
it is not an asset-path filter or an application authorization mechanism.

Only the client needs an update. Restart each relevant tunnel with the new
flags; no server update or configuration migration is required.

## Local traffic inspector

Inspection is enabled by default for `sink http`. The client prints only the
local dashboard URL, for example `inspector dashboard:
http://127.0.0.1:4040`; it never places the per-run mutation token in that URL.
Open it from the same machine. The release binary contains the complete
dashboard and does not need Node.js or files from the source checkout.

By default the dashboard tries `127.0.0.1:4040` and scans upward until it finds
an available port. `--dashboard-port PORT` requests exactly one non-zero
loopback port; startup fails if it is unavailable. An unexpected error while
using automatic selection disables the dashboard but leaves the tunnel
running. Use `--inspect=false` to disable capture and the dashboard. The
retention flags and defaults are listed in the [CLI reference](cli-reference.md).

The transaction list is newest first and contains summaries only. Selecting an
entry loads its request and response details. Live changes arrive over SSE; the
UI refreshes the list when the stream first connects or reports missed events.
Pause stops retaining new original traffic without stopping or pausing the
tunnel, and keeps existing entries. Resume permits new capture. Delete removes
one entry; Clear requires explicit confirmation and removes all retained
entries. Capacity eviction removes the oldest entry. Removal cancels any
pending replay work owned by that entry, and later proxy updates cannot restore
it.

Sensitive header values are masked by default. Reveal is an explicit action for
one value; hiding or leaving that rendered value clears the UI copy, but the
underlying retained transaction remains until removal. cURL generation targets
the current local service. If eligible headers have sensitive values, the UI
first shows names only and requires confirmation before those values enter the
generated command and clipboard. Treat the clipboard and any shell history as
secret-bearing after confirmation.

Replay is explicit and sends the retained method, public path/query, eligible
headers, and fully retained request body directly to the current local target,
using the run's local TLS and Host-rewrite behavior. It creates a new linked
transaction. Replay is rejected before sending while capture is paused or when
the source is gone, and is unavailable for WebSockets, SSE, streaming request
bodies, binary or unclassified request bodies, and incomplete or truncated
request bodies. Replay never sends Sink control headers.

The default store retains 100 transactions and up to 1,048,576 bytes separately
for each request and response preview. The UI reports full byte counts even
when text is truncated; binary body bytes are omitted. These are inspection
limits, not forwarding limits: the proxy continues streaming the full traffic.
For fully retained bodies, the dashboard decodes bounded `gzip`, `deflate`, and
`br` preview copies before displaying structured text such as JSON. Forwarded
bytes and headers remain unchanged. Unsupported, incomplete, or truncated
encoded bodies are shown as metadata-only instead of rendering compressed bytes
as text.

## Client update notices

At each interactive `sink http` start (with standard error attached to a
terminal), Sink shows a cached newer stable version when one is available. If a
check is due, it checks GitHub in the background; network checks happen at most
once per 24 hours. Between checks, the cached version is shown on every
interactive start without another network request.

Service and noninteractive runs do not perform the startup check. Set
`SINK_NO_UPDATE_CHECK=1` to disable only the startup check and notice. It does
not disable `sink update`, and startup never installs an update automatically.

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
- Passthrough TLS closes before the local handshake: confirm the durable claim
  is passthrough and active, `sink connect` is running its apex route, and the
  service is reachable on `tls_target`. If ingress PROXY v2 is enabled, confirm
  its sender and Sink use matching settings.
- The local TLS service logs the Sink client address instead of the visitor
  address: set `proxy_protocol = "v2"` and make the service trust PROXY v2 only
  from that client peer.
- Local HTTPS certificate error: fix the certificate trust/hostname. Use the
  development opt-out only for a target you control.
- Missing configuration: save the token and server address, or pass
  `--authtoken` and `--server-addr` for that run. Sink has no built-in server
  address.
- Explicit dashboard port unavailable: stop the listener using that loopback
  port or select another `--dashboard-port`.
