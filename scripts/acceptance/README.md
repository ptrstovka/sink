# Manual acceptance harness

These helpers are intentionally excluded from `cargo test` and normal CI. They
can generate and transfer multi-gigabyte data, run for an hour, interrupt live
links, restart a server, rotate credentials, and terminate processes. Run them
only against an isolated acceptance deployment.

Every command requires:

```sh
export SINK_ACCEPTANCE_CONFIRM=I_UNDERSTAND
```

The runner never prints a Sink token and does not enable shell tracing. Keep
tokens out of hook output and process logs. Hooks are absolute executable paths,
receive no token arguments from the runner, and should read credentials from a
restricted owner-controlled source.

## Fixture and tunnel setup

After the workspace lockfile has been reconciled by the integration owner,
build the manual fixture:

```sh
cargo build --locked --release -p sink-e2e --bin acceptance-fixture
mkdir -p /tmp/sink-acceptance-work
export SINK_ACCEPTANCE_WORK_DIR=/tmp/sink-acceptance-work
scripts/acceptance/run.sh prepare-payload
export SINK_ACCEPTANCE_PAYLOAD_FILE=/tmp/sink-acceptance-work/sink-acceptance-1g.bin
export SINK_ACCEPTANCE_DOWNLOAD_FILE="$SINK_ACCEPTANCE_PAYLOAD_FILE"
export SINK_ACCEPTANCE_FIXTURE_LISTEN=127.0.0.1:3000
target/release/acceptance-fixture
```

In separate terminals, start an isolated `sink-server`, create a dedicated
user, and run `sink http 127.0.0.1:3000` with a chosen acceptance hostname.
Use the explicit plaintext-control override only when the control listener is a
loopback `http://127.0.0.1:<port>` address. Then set:

```sh
export SINK_ACCEPTANCE_PUBLIC_URL=http://chosen-host.example.test
export SINK_ACCEPTANCE_FIXTURE_URL=http://127.0.0.1:3000
```

The fixture contract is `/health`, `/ordinary/<id>`, `PUT /upload`,
`GET /download`, `/sse`, `/ws`, `POST /side-effect`, and `/stats`.

## Data, mixed traffic, soak, and cancellation

```sh
scripts/acceptance/run.sh large-transfer
SINK_ACCEPTANCE_REQUEST_COUNT=120 scripts/acceptance/run.sh mixed-traffic
SINK_ACCEPTANCE_SOAK_SECONDS=3600 scripts/acceptance/run.sh soak
scripts/acceptance/run.sh cancellation
```

`large-transfer` verifies SHA-256 for both the 1 GiB upload and download.
`mixed-traffic` keeps an upload, download, SSE, and WebSocket active while at
least 100 ordinary requests run. `soak` refuses a duration shorter than one
hour. `cancellation` checks the fixture counters to ensure the abandoned local
operation closes and its side effect occurs exactly once. `websocat` is needed
for WebSocket workloads.

## Interruptions and server restarts

Set each hook to a narrow, executable script that performs exactly one action.
The link hook should cut only the client-to-server control link and restore it;
the restart hook should restart only the isolated acceptance server. The runner
does 20 cuts and 5 restarts and requires the unchanged public URL to recover
within 10 seconds after each event.

```sh
export SINK_ACCEPTANCE_LINK_INTERRUPT_HOOK=/absolute/path/cut-and-restore-link
export SINK_ACCEPTANCE_SERVER_RESTART_HOOK=/absolute/path/restart-acceptance-server
scripts/acceptance/run.sh interruptions
```

## Conflict, reclaim, revocation, and shutdown

The coordination commands use hooks so the runner never embeds a token or
assumes a process manager. Each check hook must exit zero only when the expected
state is observed. Configure the following executable paths:

```sh
# claims: this hook is the raw conflicting start and must itself exit nonzero
export SINK_ACCEPTANCE_CONFLICT_HOOK=/absolute/path/start-conflicting-client
export SINK_ACCEPTANCE_LINK_INTERRUPT_HOOK=/absolute/path/cut-and-restore-link
export SINK_ACCEPTANCE_PRIMARY_STOP_HOOK=/absolute/path/stop-primary-client
export SINK_ACCEPTANCE_REPLACEMENT_START_HOOK=/absolute/path/start-replacement-client
scripts/acceptance/run.sh claims

# revocation: rotate, prove old client stopped permanently, start new, disable, prove stop
export SINK_ACCEPTANCE_ROTATE_HOOK=/absolute/path/rotate-dedicated-user-token
export SINK_ACCEPTANCE_OLD_CREDENTIAL_CHECK_HOOK=/absolute/path/assert-old-client-stopped
export SINK_ACCEPTANCE_NEW_CLIENT_START_HOOK=/absolute/path/start-new-token-client
export SINK_ACCEPTANCE_DISABLE_HOOK=/absolute/path/disable-dedicated-user
export SINK_ACCEPTANCE_DISABLED_CLIENT_CHECK_HOOK=/absolute/path/assert-disabled-client-stopped
scripts/acceptance/run.sh revocation

# shutdown: signal once/check bounded drain, then independently exercise a repeated signal
export SINK_ACCEPTANCE_CLIENT_SHUTDOWN_HOOK=/absolute/path/signal-client-once
export SINK_ACCEPTANCE_CLIENT_EXIT_CHECK_HOOK=/absolute/path/assert-client-exited
export SINK_ACCEPTANCE_CLIENT_REPEAT_SIGNAL_HOOK=/absolute/path/test-client-repeated-signal
export SINK_ACCEPTANCE_SERVER_SHUTDOWN_HOOK=/absolute/path/signal-server-once
export SINK_ACCEPTANCE_SERVER_EXIT_CHECK_HOOK=/absolute/path/assert-server-exited
export SINK_ACCEPTANCE_SERVER_REPEAT_SIGNAL_HOOK=/absolute/path/test-server-repeated-signal
scripts/acceptance/run.sh shutdown
```

Hook scripts should refuse broad or production targets, avoid `eval`, avoid
printing commands containing credentials, and record the exact process IDs or
service names they intend to affect before mutating anything. Remove the
dedicated acceptance user and payload directory manually after review.
