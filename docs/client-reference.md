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
- Explicit dashboard port unavailable: stop the listener using that loopback
  port or select another `--dashboard-port`.
