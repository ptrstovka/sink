# CLI reference

## Client

`sink http <target>` accepts a local port, `host:port`, or an `http://` or
`https://` URL. Its options are:

| Option | Default and behavior |
| --- | --- |
| `--url HTTPS_URL` | Ask for one public hostname; otherwise the server allocates one. |
| `--authtoken TOKEN` | Override the saved token for this run. |
| `--server-addr SERVER` | Override the saved control origin; there is no built-in default. |
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

Other client commands are `sink config add-authtoken TOKEN`, `sink config
add-server-addr SERVER`, and `sink version`.

## Server and release executables

Release archives contain `sink` and `sink-server`. Server commands are
`sink-server serve`, `sink-server version`, and the `sink-server user create`,
`list`, `rotate-token`, `disable`, and `enable` families. Usernames are
positional for every command except `list`.

Server runtime settings use flags over environment values:

- `--listen-address` / `SINK_SERVER_LISTEN_ADDRESS`
- `--public-base-domain` / `SINK_SERVER_PUBLIC_BASE_DOMAIN`
- `--sqlite-path` / `SINK_SERVER_SQLITE_PATH`
- `--log-level` / `SINK_SERVER_LOG_LEVEL`

The public base domain and client server address have no defaults; configure
both explicitly.
