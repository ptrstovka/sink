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
tokens out of hook output and process logs. Hooks are absolute executable
paths, receive no token arguments from the runner, and should read credentials
from a restricted file or secret store. Public URLs containing user
information, queries, or fragments are rejected so curl failures and harness
diagnostics cannot accidentally expose credentials. Curl and hook error output
stays in the mode-0700 temporary run directory and is removed during cleanup;
diagnostics report only safe status and byte counters.

## Fixture and tunnel setup

Build the manual fixture from a clean checkout with the committed lockfile:

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
account, and run `sink http 127.0.0.1:3000` with a chosen acceptance hostname.
Use the explicit plaintext-control override only when the control listener is a
loopback `http://127.0.0.1:<port>` address. Then set:

```sh
export SINK_ACCEPTANCE_PUBLIC_URL=http://chosen-host.example.test
export SINK_ACCEPTANCE_FIXTURE_URL=http://127.0.0.1:3000
```

The fixture exposes `/health`, `/ordinary/<id>`, `PUT /upload`,
`GET /download`, `/sse`, `/ws`, `POST /side-effect`, and `/stats`.

Run the mock-backed harness regression without a live tunnel:

```sh
scripts/acceptance/test.sh
```

## Data, mixed traffic, soak, and cancellation

```sh
scripts/acceptance/run.sh large-transfer
SINK_ACCEPTANCE_REQUEST_COUNT=120 \
  SINK_ACCEPTANCE_ORDINARY_CONCURRENCY=25 \
  scripts/acceptance/run.sh mixed-traffic
SINK_ACCEPTANCE_SOAK_SECONDS=3600 scripts/acceptance/run.sh soak
scripts/acceptance/run.sh cancellation
```

`large-transfer` verifies SHA-256 for both the 1 GiB upload and download.
Uploads use curl's file-backed `--upload-file` streaming path with an explicit
`PUT`; the runner does not use `--data-binary @file`, which can cause macOS curl
to try to allocate the complete 1 GiB body. `mixed-traffic` waits for and
hash-checks both 1 GiB transfers while 100–1000 ordinary requests run through a
bounded in-flight window (25 by default), and it requires the SSE and WebSocket
output files to keep growing. Bounding the window avoids turning the check into
a public TLS/proxy connection-admission stress test. `soak` refuses a
duration shorter than one hour and checks transfer byte progress plus SSE and
WebSocket growth throughout the run. The duration is the workload-admission
and observation window: work is no longer admitted after it expires, while an
ordinary request or upload/download pair admitted before the boundary keeps
its bounded request or operation timeout. `cancellation` checks the fixture
counters to ensure the abandoned local operation closes and its side effect
occurs exactly once.
`websocat` is needed for WebSocket workloads.

## Deadlines and progress controls

The safe defaults should work for the isolated acceptance environment. Override
them only when the expected network or process-manager latency is understood:

| Variable | Default | Allowed | Purpose |
| --- | ---: | ---: | --- |
| `SINK_ACCEPTANCE_CONNECT_TIMEOUT_SECONDS` | 5 | 1–60 | DNS/TCP/TLS connection limit for curl |
| `SINK_ACCEPTANCE_REQUEST_TIMEOUT_SECONDS` | 10 | 2–300 | Total limit for an ordinary or probe request |
| `SINK_ACCEPTANCE_ORDINARY_CONCURRENCY` | 25 | 1–100 | Maximum in-flight ordinary requests during mixed traffic |
| `SINK_ACCEPTANCE_OPERATION_TIMEOUT_SECONDS` | 1800 | 30–7200 | Total limit for each 1 GiB transfer or cancellation caller |
| `SINK_ACCEPTANCE_STALL_TIMEOUT_SECONDS` | 60 | 10–600 | Maximum time without newly reported transfer/SSE/WebSocket bytes |
| `SINK_ACCEPTANCE_PROGRESS_INTERVAL_SECONDS` | 5 | 1–60 | Progress sampling interval; it must be shorter than the stall timeout |
| `SINK_ACCEPTANCE_HOOK_TIMEOUT_SECONDS` | 120 | 5–900 | Total limit for each interruption/auth/shutdown hook |
| `SINK_ACCEPTANCE_SOAK_SECONDS` | 3600 | 3600–86400 | Nominal workload-admission and observation duration |

Every curl transfer also has a low-speed abort. An external monitor polls the
actual upload/download counters and terminates a child that crosses its own
request or operation deadline, so the soak loop is not relying on curl alone.
The nominal soak boundary stops new admission. An ordinary request already
admitted receives its full request timeout, and an admitted upload/download
pair completes atomically with a fresh operation timeout for each leg while
SSE/WebSocket progress remains monitored. The command can therefore finish
after the nominal duration, but the extension remains bounded by the greater
of one request timeout and two operation timeouts, plus small monitoring and
termination overhead. The pass line reports both configured and actual elapsed
seconds.

On exit or interruption, the runner terminates and reaps its tracked curl,
SSE, WebSocket, feeder, and hook children before removing its narrowly matched
temporary directory. Finished children are untracked immediately to avoid PID
reuse during a long soak.

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
# Claims
export SINK_ACCEPTANCE_CONFLICT_HOOK=/absolute/path/start-conflicting-client
export SINK_ACCEPTANCE_LINK_INTERRUPT_HOOK=/absolute/path/cut-and-restore-link
export SINK_ACCEPTANCE_PRIMARY_STOP_HOOK=/absolute/path/stop-primary-client
export SINK_ACCEPTANCE_REPLACEMENT_START_HOOK=/absolute/path/start-replacement-client
scripts/acceptance/run.sh claims

# Revocation
export SINK_ACCEPTANCE_ROTATE_HOOK=/absolute/path/rotate-dedicated-user-token
export SINK_ACCEPTANCE_OLD_CREDENTIAL_CHECK_HOOK=/absolute/path/assert-old-client-stopped
export SINK_ACCEPTANCE_NEW_CLIENT_START_HOOK=/absolute/path/start-new-token-client
export SINK_ACCEPTANCE_DISABLE_HOOK=/absolute/path/disable-dedicated-user
export SINK_ACCEPTANCE_DISABLED_CLIENT_CHECK_HOOK=/absolute/path/assert-disabled-client-stopped
scripts/acceptance/run.sh revocation

# Shutdown
export SINK_ACCEPTANCE_CLIENT_SHUTDOWN_HOOK=/absolute/path/signal-client-once
export SINK_ACCEPTANCE_CLIENT_EXIT_CHECK_HOOK=/absolute/path/assert-client-exited
export SINK_ACCEPTANCE_CLIENT_REPEAT_SIGNAL_HOOK=/absolute/path/test-client-repeated-signal
export SINK_ACCEPTANCE_SERVER_SHUTDOWN_HOOK=/absolute/path/signal-server-once
export SINK_ACCEPTANCE_SERVER_EXIT_CHECK_HOOK=/absolute/path/assert-server-exited
export SINK_ACCEPTANCE_SERVER_REPEAT_SIGNAL_HOOK=/absolute/path/test-server-repeated-signal
scripts/acceptance/run.sh shutdown
```

Scope hooks to the isolated test processes. Resolve exact process IDs or
service names before changing their state, do not use `eval`, and do not print
credentials. Remove the acceptance account and payload directory when
finished.
