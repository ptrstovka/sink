# CLI reference

- Client: `sink http <target>`, `sink config add-authtoken TOKEN`, `sink config
  add-server-addr SERVER`, and `sink version`.
- Client tunnel options: `--url`, `--authtoken`, and `--server-addr`.
- Client development options: `--local-tls-insecure` disables verification
  only for an HTTPS local target; `--allow-plaintext-control` permits an
  explicitly configured `http://` control origin for that run.
- Release executables: `sink` and `sink-server`.
- Server: `sink-server serve`, `sink-server version`; user command families
  `create`, `list`, `rotate-token`, `disable`, and `enable`. Usernames are
  positional for every command except `list`.
- Server runtime settings (flags win): `--listen-address` /
  `SINK_SERVER_LISTEN_ADDRESS`, `--public-base-domain` /
  `SINK_SERVER_PUBLIC_BASE_DOMAIN`, `--sqlite-path` /
  `SINK_SERVER_SQLITE_PATH`, and `--log-level` /
  `SINK_SERVER_LOG_LEVEL`.

The public base domain and client server address have no defaults; configure
both explicitly.
