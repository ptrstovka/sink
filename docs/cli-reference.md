# CLI reference

These names are implemented by the client and server command models. Check the
installed release's `--help` when automating across versions.

- Client: `sink http <target>`, `sink config add-authtoken TOKEN`, and `sink
  config add-server-addr SERVER`.
- Client tunnel options: `--url`, `--authtoken`, and `--server-addr`.
- Client development options: `--local-tls-insecure` disables verification
  only for an HTTPS local target; `--allow-plaintext-control` permits an
  explicitly configured `http://` control origin for that run.
- Release executables: `sink` and `sink-server`.
- Server: `sink-server serve`; user command families `create`, `list`,
  `rotate-token`, `disable`, and `enable`. Usernames are positional for every
  command except `list`.
- Server runtime settings (flags win): `--listen-address` /
  `SINK_SERVER_LISTEN_ADDRESS`, `--public-base-domain` /
  `SINK_SERVER_PUBLIC_BASE_DOMAIN`, `--sqlite-path` /
  `SINK_SERVER_SQLITE_PATH`, and `--log-level` /
  `SINK_SERVER_LOG_LEVEL`.

The deployment examples use these exact server settings. Never compensate for
a version mismatch by weakening TLS defaults.
