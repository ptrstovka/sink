# CLI reference

## Client

```text
sink http <target> [OPTIONS]
sink connect [OPTIONS] --config <file>
sink namespace claim <hostname> [OPTIONS]
sink namespace list [OPTIONS]
sink namespace status <hostname> [OPTIONS]
sink namespace release <hostname> [OPTIONS]
sink config add-authtoken TOKEN
sink config add-server-addr SERVER
sink update
sink version
```

`sink http <target>` accepts a local port, `host:port`, or an `http://` or
`https://` URL. Its options are:

| Option | Default and behavior |
| --- | --- |
| `--url HTTPS_URL` | Ask for one public hostname; otherwise the server allocates one. |
| `--authtoken TOKEN` | Override the saved token for this run. |
| `--server-addr SERVER` | Override the saved control origin; there is no built-in default. |
| `--cors-allow-origin ORIGIN` | Opt in to CORS for this tunnel; repeat for exact HTTP(S) origins, or use quoted `'*'` for any origin. Disabled by default. |
| `--cors-allow-credentials` | Allow credentialed CORS requests; requires concrete allowed origins and rejects `'*'`. |
| `--local-tls-insecure` | Disable certificate verification only for an explicit HTTPS local target. |
| `--preserve-host` | Forward the public `Host` header to the local target. By default, `Host` is rewritten to the target authority while `X-Forwarded-Host` retains the public host. |
| `--allow-plaintext-control` | Permit an explicitly configured `http://` control origin for local development. |
| `--inspect=<BOOL>` | Enable local capture and dashboard; defaults to `true`. Use the equals form, including `--inspect=false`. |
| `--dashboard-port PORT` | Bind exactly `127.0.0.1:PORT`; must be non-zero. When omitted, scan from port 4040 upward. |
| `--inspect-request-limit COUNT` | Maximum retained transactions; defaults to 100 and must be non-zero. |
| `--inspect-body-limit BYTES` | Maximum retained bytes for each request or response body preview; defaults to 1,048,576 and must be non-zero. |

Automatic dashboard selection prefers port 4040. If an unexpected automatic
bind error occurs, Sink reports it and continues the tunnel without the
dashboard. An unavailable explicit port is a startup error. When inspection is
enabled, stdout contains `inspector dashboard: http://127.0.0.1:PORT`; this URL
has no query token or fragment. The dashboard obtains its per-run mutation token
through its loopback session API.

### Multi-route configuration

`sink connect` runs every route in a TOML file in one foreground process. Each
`[[routes]]` table is one named route with its own control session, reconnect
loop, and optional HTTP inspector. Even a file with just one route is valid.

```text
sink connect [OPTIONS] --config <FILE>
```

| Option | Default and behavior |
| --- | --- |
| `--config FILE` | Required path to the route TOML file. Relative paths are resolved from the current working directory. There is no default route-file path. |
| `--authtoken TOKEN` | Override the saved authentication token for all routes in this run without saving it. |
| `--server-addr SERVER` | Override the saved control-server origin for all routes in this run without saving it. Accepts an HTTP(S) origin with an optional non-zero port, without URL credentials, a path other than `/`, a query, or a fragment. There is no built-in server address. |
| `--allow-plaintext-control` | Defaults to off. Permit an explicitly configured `http://` control origin for this run; intended for local development. HTTPS certificate validation remains enabled. |
| `-h`, `--help` | Print command help and exit. |

Authentication and `server_addr` come from the
[saved client configuration](client-reference.md#saved-client-configuration)
unless overridden above. Both must be available, and all routes use the same
token and server. `--config` selects only the route file; it does not select or
replace the saved client configuration. HTTP target, CORS, TLS, and inspector
options belong in each route table; `connect` does not accept the corresponding
`sink http` flags.

For example, save this as `routes.toml`, configure the client, and start it:

```toml
[[routes]]
name = "app"
url = "https://app.example.com"
target = "3000"

[[routes]]
name = "api"
url = "https://api.example.com"
target = "api.internal:8080"
```

```console
sink config add-server-addr https://connect.example.com
sink config add-authtoken TOKEN
sink connect --config routes.toml
sink connect --help
```

#### Route-file keys

The only top-level key is `routes`, normally written as repeated `[[routes]]`
array tables. At least one route is required. All supported route keys are
listed below; omitted optional keys use their own defaults for each route.
There is no global defaults table or per-route token/server setting.

| Key | TOML type | Required or default | Behavior and validation |
| --- | --- | --- | --- |
| `name` | String | Required | Route label used in output. Must be 1–64 ASCII letters, digits, hyphens, or underscores; case-sensitive and unique in the file. |
| `url` | String | Required | Requested public HTTPS hostname, for example `"https://api.example.com"`. Must use a DNS hostname, without an explicit port (even `:443`), URL credentials, a path other than `/`, a query, or a fragment. Wildcards and IP addresses are invalid; `connect` is reserved. Normalized hostnames must be unique in the file. |
| `target` | String | Required | Local HTTP(S) service: a port string such as `"3000"`, `"host:port"`, or an explicit `"http://…"` / `"https://…"` URL. Required even with `tls_target`. See target rules below. |
| `local_tls_insecure` | Boolean | `false` | Disable certificate verification for the local HTTP target only. May be `true` only with an explicit HTTPS `target`; does not affect control TLS or raw TLS. |
| `preserve_host` | Boolean | `false` | With `false`, rewrite HTTP `Host` to the local target authority. With `true`, forward the public `Host`, useful for a name-based reverse proxy. `X-Forwarded-Host` retains the public host in either mode. |
| `cors_allow_origin` | Array of strings | `[]` | Opt in to CORS for this route's HTTP paths. Accept exact HTTP(S) origins with optional ports, or `["*"]` for any origin. Wildcard must be the only entry. |
| `cors_allow_credentials` | Boolean | `false` | Permit credentialed CORS requests. Requires a non-empty list of concrete origins and rejects `"*"`. |
| `inspect` | Boolean | `true` | Capture HTTP transactions and enable this route's loopback dashboard. Raw TLS contents are never inspected. |
| `dashboard_port` | Integer | Omitted: automatic | Fixed dashboard port from 1 through 65535 on `127.0.0.1`. Requires `inspect = true`; explicitly assigned ports must be unique across routes. |
| `inspect_request_limit` | Integer | `100` | Maximum retained HTTP transactions for this route. Must be positive and fit the platform's `usize`, even when inspection is disabled. |
| `inspect_body_limit` | Integer | `1048576` | Maximum retained bytes separately for each request and response body preview. Must be positive and fit the platform's `usize`, even when inspection is disabled. Does not limit forwarded body size. |
| `tls_target` | String | Omitted: disabled | Raw TLS destination, strictly `"tcp://host:port"` with an explicit port from 1 through 65535. Requires an active passthrough namespace on the server; `url` must be its apex. |
| `proxy_protocol` | String | Omitted: disabled | Only `"v2"` is accepted, and it requires `tls_target`. Prepend a PROXY v2 header to outgoing raw TLS; does not change HTTP forwarding. |

Strings, including a numeric `target`, must be quoted. Booleans and integers
must use TOML values such as `inspect = false` and `dashboard_port = 4042`, not
quoted strings. Unknown keys at the top level or in a route, duplicate keys,
missing required keys, and incorrect value types are rejected. In particular,
`authtoken`, `server_addr`, and `allow_plaintext_control` are not route-file keys.

#### HTTP targets, public addresses, and CORS

A numeric `target` selects HTTP on localhost. A target without a scheme must
include a port and defaults to HTTP; an explicit HTTP(S) URL may omit the port
to use 80 or 443. IPv6 addresses use brackets, for example `"[::1]:3000"`.
Targets reject whitespace, URL credentials, port zero, query strings, and
fragments. A base path is allowed: with
`target = "https://localhost:8443/base"`, an incoming `/users?id=1` is forwarded
to `/base/users?id=1`. Local HTTPS validates certificates and the target
hostname by default.

Every route needs an explicit public `url`; `connect` does not allocate a random
hostname. The server checks the hostname against its base domain, namespace
ownership, active certificate state, and route conflicts. An ordinary entry
without `tls_target` creates an exact HTTP/managed-TLS route. Deeper names need
an authorized active namespace. Starting `connect` does not claim a persistent
namespace or issue certificates. Managed routes serve both HTTP and HTTPS
without an automatic redirect, even though `url` uses `https://`.

CORS origins reject bare hostnames, `null`, wildcard patterns such as
`*.example.com`, URL credentials, paths other than `/`, queries, and fragments.
An empty list leaves upstream CORS behavior unchanged. Enabled CORS replaces
upstream `Access-Control-*` headers and handles preflight locally. It applies
to HTTP traffic, not raw TLS, WebSocket upgrades, local replays, or the
inspector. See [CORS behavior](client-reference.md#cross-origin-assets-and-requests).

This ordinary HTTPS target example sets every HTTP route option explicitly:

```toml
[[routes]]
name = "api"
url = "https://api.example.com"
target = "https://localhost:8443/base"
local_tls_insecure = true # development service with an untrusted certificate
preserve_host = true
cors_allow_origin = ["https://app.example.com", "http://localhost:5173"]
cors_allow_credentials = true
inspect = true
dashboard_port = 4042
inspect_request_limit = 250
inspect_body_limit = 2097152
```

#### Raw TLS route options

For a namespace already claimed with
`sink namespace claim tls.example.com --passthrough`, use its apex as `url`
and add the raw target to the same route table:

```toml
[[routes]]
name = "passthrough"
url = "https://tls.example.com"
target = "http://service.internal:80"
preserve_host = true
tls_target = "tcp://service.internal:443"
proxy_protocol = "v2"
inspect = false
```

A passthrough entry still owns only one session: its HTTP target handles the
claim apex and direct children, and its TLS target handles raw TLS for the same
scope. The local TLS service presents and manages its own certificate. Sink
forwards the TLS bytes without terminating or inspecting them.

`tls_target` accepts DNS names, IPv4, and bracketed IPv6, for example
`"tcp://[::1]:443"`. It rejects URL credentials, whitespace, paths other than
an optional `/`, queries, and fragments. With `proxy_protocol = "v2"`, the
local TLS listener must accept PROXY v2 from the Sink client peer before its TLS
handshake. See the [passthrough guide](client-reference.md#raw-tls-passthrough)
for namespace scope and metadata trust requirements.

#### Startup, inspection, retries, and shutdown

The entire route file is read and validated before credentials are resolved,
dashboards are bound, or any control connection starts. Invalid routes, missing
credentials, an invalid saved client file, or failure to bind an explicit
dashboard port fail startup for the whole command.

Explicit dashboard ports are reserved before automatic allocation. Automatic
dashboards scan upward from 4040 and use separate ports and stores per route.
An unexpected automatic bind error is reported and the affected route
continues without its dashboard. `inspect = false` disables both capture and
the dashboard; omit `dashboard_port` in that case. Inspector limits are per
route and do not limit tunnel throughput or body size. See the
[inspector guide](client-reference.md#local-traffic-inspector).

Output is prefixed with `[name]` and includes local targets, dashboard URLs,
public HTTP/HTTPS URLs after connection, state changes, and completed HTTP
request summaries. Each route retries independently with exponential backoff
and jitter, starting at 50–100 ms and capped at 2 seconds. Route-specific
failures, including a hostname conflict, keep retrying while other routes
continue. Invalid authentication, a disabled user, or a control HTTP 401/403
stops all routes and makes the command fail. Interrupted in-flight traffic is
never replayed; reconnection keeps the same route identity and public address.

Ctrl-C or SIGTERM gracefully shuts down all routes and releases their leases,
allowing in-flight traffic up to 10 seconds to drain. A second termination
signal forces immediate exit. An unexpected exit may retain the old leases
briefly; a fresh process may need to wait for the reconnect grace period.

The file is loaded once; restart the command to apply changes. There is no
file watching, environment-variable interpolation, route-selection flag, or
validation-only mode. Keep sensitive internal addresses private and use a
process manager when running the command as a service.

### Client updates

`sink update` immediately installs the matching `sink` client from the latest
stable GitHub Release without another confirmation. The exact platform archive
and `SHA256SUMS` must both be attached. It supports the four standalone
macOS/Linux architectures, verifies the GitHub asset digest, `SHA256SUMS`, and
staged client version before replacement, and never updates `sink-server`. The
install path must be writable; Sink fails without invoking `sudo` otherwise.
Use the appropriate privilege for a system-owned install or reinstall the
client in a user-writable directory. Prereleases, channels, pinned versions,
and downgrades are not supported.

Interactive `sink http` starts, with standard error attached to a terminal,
check GitHub in the background at most once per 24 hours and show a cached
available version on every interactive start. Service and noninteractive runs
do not check. `SINK_NO_UPDATE_CHECK=1` disables only the startup check and
notice; it does not disable `sink update`.

### Persistent namespaces

`sink namespace` uses the saved server address and token unless the command's
`--server-addr` or `--authtoken` override is supplied. The subcommands are:

- `claim HOSTNAME` creates a persistent managed-TLS namespace by default and
  waits for active certificate-backed state for up to 300 seconds.
  `--passthrough` instead creates an immediately active raw-TLS namespace that
  never enters Sink's certificate lifecycle. `--no-wait` returns after server
  acceptance; `--timeout SECONDS` accepts 1 through 3600 and conflicts with
  `--no-wait`.
- `list` shows every namespace owned by the authenticated user.
- `status HOSTNAME` shows one owned namespace and its current state.
- `release HOSTNAME` begins release and is rejected while child claims or
  active tunnel routes remain.

A managed namespace certificate covers the claim apex plus one wildcard. A
passthrough namespace route covers that same apex-and-one-direct-child scope,
but carries raw TLS and owns no Sink certificate. It cannot be overridden by an
exact route and does not cover deeper names implicitly. Only the adjacent
parent owner may create a nested claim, system names are reserved, and the
configured server maximum bounds persistent namespace depth. Starting
`sink http` or `sink connect` never triggers certificate issuance. Once a
namespace is active, its scope is available over both plain HTTP and HTTPS
without an automatic redirect.

## Server and release executables

Release archives contain `sink` and `sink-server`. Server commands are
`sink-server serve`, `sink-server version`, and the `sink-server user create`,
`list`, `rotate-token`, `disable`, and `enable` families. Usernames are
positional for every command except `list`.

Server runtime settings use flags over environment values:

- `--http-listen-address` / `SINK_SERVER_HTTP_LISTEN_ADDRESS`
- `--https-listen-address` / `SINK_SERVER_HTTPS_LISTEN_ADDRESS`
- `--https-proxy-protocol` / `SINK_SERVER_HTTPS_PROXY_PROTOCOL`
- `--https-proxy-trusted-peer-cidrs` /
  `SINK_SERVER_HTTPS_PROXY_TRUSTED_PEER_CIDRS`
- `--public-base-domain` / `SINK_SERVER_PUBLIC_BASE_DOMAIN`
- `--max-namespace-depth` / `SINK_SERVER_MAX_NAMESPACE_DEPTH`
- `--certificate-provider` / `SINK_SERVER_CERTIFICATE_PROVIDER`
- `--certificate-backend-enabled` /
  `SINK_SERVER_CERTIFICATE_BACKEND_ENABLED`
- `--acme-directory-url` / `SINK_SERVER_ACME_DIRECTORY_URL`
- `--acme-contact` / `SINK_SERVER_ACME_CONTACT`
- `--acme-terms-agreed` / `SINK_SERVER_ACME_TERMS_AGREED`
- `--cloudflare-zone-id` / `SINK_SERVER_CLOUDFLARE_ZONE_ID`
- `--sqlite-path` / `SINK_SERVER_SQLITE_PATH`
- `--log-level` / `SINK_SERVER_LOG_LEVEL`

`--listen-address` / `SINK_SERVER_LISTEN_ADDRESS` remains a compatibility alias
for the HTTP listener. If both legacy and explicit HTTP values are supplied,
they must agree. New deployments should configure the explicit HTTP and HTTPS
settings.

The HTTP listener defaults to `127.0.0.1:8080`. An HTTPS listener has no
default: it is required when the certificate backend is enabled, rejected when
the backend is disabled, and must differ from the HTTP address. The certificate
backend is disabled by default. Its current provider default is `cloudflare`,
the maximum namespace depth defaults to 2, and the safe ACME directory default
is Let's Encrypt staging. Production must explicitly set
`https://acme-v02.api.letsencrypt.org/directory`.

The HTTPS ingress PROXY policy defaults to `disabled`. Set it to `required-v2`
only with a non-empty comma-separated list of canonical IPv4/IPv6 CIDRs for
the immediate L4 proxy peers. Trusted CIDRs are invalid while the policy is
disabled, and PROXY mode requires the certificate backend/HTTPS listener.
Required mode rejects an untrusted connection before parsing metadata and
rejects a missing, malformed, oversized, unsupported, or `LOCAL` header before
managed/passthrough TLS dispatch. The accepted CLI flags and their environment
counterparts both use the explicit `https-proxy` / `HTTPS_PROXY` prefix.

`SINK_SERVER_CLOUDFLARE_API_TOKEN` is required in the environment when managed
TLS is enabled and intentionally has no CLI flag, preventing exposure in the
process list. Enabled managed TLS also requires a valid zone ID, a
`mailto:` ACME contact, and explicit terms agreement.

The public base domain and client server address have no defaults; configure
both explicitly. With managed TLS enabled, `sink server ready` is emitted only
after durable certificate reconciliation, a valid base certificate, dynamic
SNI resolver loading, and namespace-boundary refresh. Neither listener accepts
traffic before that readiness point, and no HTTP-to-HTTPS redirect is applied.
