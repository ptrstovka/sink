# CLI reference

## Client

```text
sink http <target> [OPTIONS]
sink connect --config <file>
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

- `claim HOSTNAME` creates a persistent namespace claim and waits for active
  certificate-backed state for up to 300 seconds by default. `--no-wait`
  returns after server acceptance; `--timeout SECONDS` accepts 1 through 3600
  and conflicts with `--no-wait`.
- `list` shows every namespace owned by the authenticated user.
- `status HOSTNAME` shows one owned namespace and its current state.
- `release HOSTNAME` begins release and is rejected while child claims or
  active tunnel routes remain.

A namespace certificate covers the claim apex plus one wildcard. Only the
adjacent parent owner may create a nested claim, system names are reserved, and
the configured server maximum bounds persistent namespace depth. Starting
`sink http` or `sink connect` never triggers certificate issuance. Once a
namespace is active, tunnel hosts directly below it are available over both
plain HTTP and HTTPS without an automatic redirect.

## Server and release executables

Release archives contain `sink` and `sink-server`. Server commands are
`sink-server serve`, `sink-server version`, and the `sink-server user create`,
`list`, `rotate-token`, `disable`, and `enable` families. Usernames are
positional for every command except `list`.

Server runtime settings use flags over environment values:

- `--http-listen-address` / `SINK_SERVER_HTTP_LISTEN_ADDRESS`
- `--https-listen-address` / `SINK_SERVER_HTTPS_LISTEN_ADDRESS`
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

`SINK_SERVER_CLOUDFLARE_API_TOKEN` is required in the environment when managed
TLS is enabled and intentionally has no CLI flag, preventing exposure in the
process list. Enabled managed TLS also requires a valid zone ID, a
`mailto:` ACME contact, and explicit terms agreement.

The public base domain and client server address have no defaults; configure
both explicitly. With managed TLS enabled, `sink server ready` is emitted only
after durable certificate reconciliation, a valid base certificate, dynamic
SNI resolver loading, and namespace-boundary refresh. Neither listener accepts
traffic before that readiness point, and no HTTP-to-HTTPS redirect is applied.
