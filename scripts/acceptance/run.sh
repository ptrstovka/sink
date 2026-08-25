#!/usr/bin/env bash

set -euo pipefail
umask 077

CONFIRM_VALUE=I_UNDERSTAND
ONE_GIB=1073741824
BACKGROUND_PIDS=()

die() {
  printf 'acceptance error: %s\n' "$*" >&2
  exit 1
}

require_confirmation() {
  [[ "${SINK_ACCEPTANCE_CONFIRM:-}" == "$CONFIRM_VALUE" ]] ||
    die "set SINK_ACCEPTANCE_CONFIRM=$CONFIRM_VALUE to run manual acceptance"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_env() {
  local name=$1
  [[ -n "${!name:-}" ]] || die "required environment variable is unset: $name"
}

require_public_url() {
  require_env SINK_ACCEPTANCE_PUBLIC_URL
  case "$SINK_ACCEPTANCE_PUBLIC_URL" in
    http://*|https://*) ;;
    *) die "SINK_ACCEPTANCE_PUBLIC_URL must use http:// or https://" ;;
  esac
  [[ "$SINK_ACCEPTANCE_PUBLIC_URL" != *'?'* ]] || die "public URL must not contain a query"
  PUBLIC_URL=${SINK_ACCEPTANCE_PUBLIC_URL%/}
  case "$PUBLIC_URL" in
    https://*) WEBSOCKET_URL="wss://${PUBLIC_URL#https://}" ;;
    http://*) WEBSOCKET_URL="ws://${PUBLIC_URL#http://}" ;;
  esac
}

make_run_dir() {
  local temp_base=${TMPDIR:-/tmp}
  RUN_DIR=$(mktemp -d "$temp_base/sink-acceptance.XXXXXX")
}

cleanup() {
  local pid
  for pid in "${BACKGROUND_PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${BACKGROUND_PIDS[@]:-}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
  if [[ -n "${RUN_DIR:-}" ]]; then
    case "$RUN_DIR" in
      */sink-acceptance.*) rm -rf -- "$RUN_DIR" ;;
      *) printf 'refusing to remove unexpected path: %s\n' "$RUN_DIR" >&2 ;;
    esac
  fi
}

trap cleanup EXIT INT TERM

sha256_file() {
  local path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

require_payload() {
  require_env SINK_ACCEPTANCE_PAYLOAD_FILE
  [[ -f "$SINK_ACCEPTANCE_PAYLOAD_FILE" ]] || die "payload file does not exist"
  local size
  size=$(wc -c < "$SINK_ACCEPTANCE_PAYLOAD_FILE" | tr -d '[:space:]')
  [[ "$size" == "$ONE_GIB" ]] || die "payload must be exactly 1 GiB; found $size bytes"
}

prepare_payload() {
  require_confirmation
  require_command dd
  require_env SINK_ACCEPTANCE_WORK_DIR
  [[ -d "$SINK_ACCEPTANCE_WORK_DIR" ]] || die "SINK_ACCEPTANCE_WORK_DIR must already exist"
  local output="$SINK_ACCEPTANCE_WORK_DIR/sink-acceptance-1g.bin"
  [[ ! -e "$output" ]] || die "refusing to overwrite existing payload: $output"
  printf 'Generating a 1 GiB random payload at %s\n' "$output"
  dd if=/dev/urandom of="$output" bs=1048576 count=1024
  printf 'sha256=%s\n' "$(sha256_file "$output")"
  printf 'Set SINK_ACCEPTANCE_PAYLOAD_FILE to this path for later commands.\n'
}

large_transfer() {
  require_confirmation
  require_public_url
  require_payload
  require_command curl
  make_run_dir

  local expected upload_reply received download_file download_hash
  expected=$(sha256_file "$SINK_ACCEPTANCE_PAYLOAD_FILE")
  upload_reply="$RUN_DIR/upload.txt"
  download_file="$RUN_DIR/download.bin"

  curl --fail --silent --show-error --http1.1 \
    --request PUT --data-binary "@$SINK_ACCEPTANCE_PAYLOAD_FILE" \
    "$PUBLIC_URL/upload" > "$upload_reply"
  received=$(awk -F= '$1 == "sha256" {print $2}' "$upload_reply")
  [[ "$received" == "$expected" ]] || die "1 GiB upload SHA-256 mismatch"

  curl --fail --silent --show-error --http1.1 \
    "$PUBLIC_URL/download" --output "$download_file"
  download_hash=$(sha256_file "$download_file")
  [[ "$download_hash" == "$expected" ]] || die "1 GiB download SHA-256 mismatch"
  printf '1 GiB upload and download SHA-256 checks passed.\n'
}

start_sse_and_websocket() {
  require_command websocat
  curl --fail --silent --show-error --no-buffer \
    "$PUBLIC_URL/sse" > "$RUN_DIR/sse.log" &
  BACKGROUND_PIDS+=("$!")
  (
    local sequence=0
    while :; do
      printf 'soak-%s\n' "$sequence"
      sequence=$((sequence + 1))
      sleep 1
    done
  ) | websocat "$WEBSOCKET_URL/ws" > "$RUN_DIR/websocket.log" &
  BACKGROUND_PIDS+=("$!")
}

mixed_traffic() {
  require_confirmation
  require_public_url
  require_payload
  require_command curl
  make_run_dir
  start_sse_and_websocket

  curl --fail --silent --show-error --http1.1 \
    --request PUT --data-binary "@$SINK_ACCEPTANCE_PAYLOAD_FILE" \
    "$PUBLIC_URL/upload" > "$RUN_DIR/mixed-upload.txt" &
  BACKGROUND_PIDS+=("$!")
  curl --fail --silent --show-error --http1.1 \
    "$PUBLIC_URL/download" --output "$RUN_DIR/mixed-download.bin" &
  BACKGROUND_PIDS+=("$!")

  local count=${SINK_ACCEPTANCE_REQUEST_COUNT:-120}
  [[ "$count" =~ ^[0-9]+$ ]] || die "SINK_ACCEPTANCE_REQUEST_COUNT must be an integer"
  (( count >= 100 )) || die "mixed traffic requires at least 100 ordinary requests"
  local id pid
  local ordinary_pids=()
  for ((id = 0; id < count; id += 1)); do
    curl --fail --silent --show-error --http1.1 \
      "$PUBLIC_URL/ordinary/$id" > "$RUN_DIR/ordinary-$id.txt" &
    pid=$!
    ordinary_pids+=("$pid")
    BACKGROUND_PIDS+=("$pid")
  done
  for pid in "${ordinary_pids[@]}"; do
    wait "$pid"
  done
  printf '%s mixed ordinary requests completed while upload, download, SSE, and WebSocket were active.\n' "$count"
}

soak() {
  require_confirmation
  require_public_url
  require_payload
  require_command curl
  make_run_dir
  local duration=${SINK_ACCEPTANCE_SOAK_SECONDS:-3600}
  [[ "$duration" =~ ^[0-9]+$ ]] || die "SINK_ACCEPTANCE_SOAK_SECONDS must be an integer"
  (( duration >= 3600 )) || die "the acceptance soak must run for at least 3600 seconds"
  start_sse_and_websocket

  local started=$SECONDS
  local iteration=0
  while (( SECONDS - started < duration )); do
    curl --fail --silent --show-error --http1.1 \
      "$PUBLIC_URL/ordinary/$iteration" > /dev/null
    if (( iteration % 10 == 0 )); then
      curl --fail --silent --show-error --http1.1 \
        --request PUT --data-binary "@$SINK_ACCEPTANCE_PAYLOAD_FILE" \
        "$PUBLIC_URL/upload" > /dev/null
      curl --fail --silent --show-error --http1.1 \
        "$PUBLIC_URL/download" --output /dev/null
    fi
    iteration=$((iteration + 1))
    sleep 60
  done
  [[ -s "$RUN_DIR/sse.log" ]] || die "SSE produced no progress"
  [[ -s "$RUN_DIR/websocket.log" ]] || die "WebSocket produced no echoes"
  printf 'One-hour SSE/WebSocket and mixed-transfer soak passed.\n'
}

run_hook() {
  local variable=$1
  require_env "$variable"
  local hook=${!variable}
  [[ "$hook" == /* ]] || die "$variable must be an absolute executable path"
  [[ -x "$hook" ]] || die "$variable is not executable"
  "$hook" > "$RUN_DIR/hook.log" 2>&1 || die "$variable failed; output retained only until cleanup"
}

run_expected_failure_hook() {
  local variable=$1
  require_env "$variable"
  local hook=${!variable}
  [[ "$hook" == /* ]] || die "$variable must be an absolute executable path"
  [[ -x "$hook" ]] || die "$variable is not executable"
  if "$hook" > "$RUN_DIR/hook.log" 2>&1; then
    die "$variable unexpectedly succeeded"
  fi
}

probe_success_within_ten_seconds() {
  local attempt
  for ((attempt = 0; attempt < 40; attempt += 1)); do
    if curl --fail --silent --show-error --max-time 2 \
      "$PUBLIC_URL/health" > /dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

interruptions() {
  require_confirmation
  require_public_url
  require_command curl
  make_run_dir
  local iteration
  for ((iteration = 1; iteration <= 20; iteration += 1)); do
    run_hook SINK_ACCEPTANCE_LINK_INTERRUPT_HOOK
    probe_success_within_ten_seconds || die "link cut $iteration did not recover within 10 seconds"
  done
  for ((iteration = 1; iteration <= 5; iteration += 1)); do
    run_hook SINK_ACCEPTANCE_SERVER_RESTART_HOOK
    probe_success_within_ten_seconds || die "server restart $iteration did not recover within 10 seconds"
  done
  printf '20 link interruptions and 5 server restarts reclaimed the same configured public URL.\n'
}

cancellation() {
  require_confirmation
  require_public_url
  require_command curl
  require_env SINK_ACCEPTANCE_FIXTURE_URL
  make_run_dir
  curl --silent --show-error --http1.1 --request POST \
    "$PUBLIC_URL/side-effect" > "$RUN_DIR/cancelled.txt" &
  local caller=$!
  BACKGROUND_PIDS+=("$caller")
  sleep 1
  kill "$caller"
  wait "$caller" >/dev/null 2>&1 || true
  local attempt stats
  for ((attempt = 0; attempt < 40; attempt += 1)); do
    stats=$(curl --fail --silent --show-error "$SINK_ACCEPTANCE_FIXTURE_URL/stats")
    if [[ "$stats" == *'active_streams=0'* && "$stats" == *'side_effects=1'* ]]; then
      curl --fail --silent --show-error "$PUBLIC_URL/health" > /dev/null
      printf 'Cancellation propagated and the side effect was not replayed.\n'
      return
    fi
    sleep 0.25
  done
  die "cancelled local stream remained active or the side effect was replayed"
}

claims() {
  require_confirmation
  require_public_url
  require_command curl
  make_run_dir
  run_expected_failure_hook SINK_ACCEPTANCE_CONFLICT_HOOK
  run_hook SINK_ACCEPTANCE_LINK_INTERRUPT_HOOK
  probe_success_within_ten_seconds || die "the original run did not reclaim its custom name"
  run_hook SINK_ACCEPTANCE_PRIMARY_STOP_HOOK
  run_hook SINK_ACCEPTANCE_REPLACEMENT_START_HOOK
  probe_success_within_ten_seconds || die "the replacement client did not acquire the cleanly released name"
  printf 'Conflict, same-run reclaim, clean release, and replacement claim passed.\n'
}

revocation() {
  require_confirmation
  require_public_url
  require_command curl
  make_run_dir
  run_hook SINK_ACCEPTANCE_ROTATE_HOOK
  run_hook SINK_ACCEPTANCE_OLD_CREDENTIAL_CHECK_HOOK
  run_hook SINK_ACCEPTANCE_NEW_CLIENT_START_HOOK
  probe_success_within_ten_seconds || die "the rotated credential did not establish a new tunnel"
  run_hook SINK_ACCEPTANCE_DISABLE_HOOK
  run_hook SINK_ACCEPTANCE_DISABLED_CLIENT_CHECK_HOOK
  printf 'Rotation and disable closed active tunnels; stale/disabled credentials failed permanently.\n'
}

shutdown_check() {
  require_confirmation
  require_public_url
  require_command curl
  make_run_dir
  run_hook SINK_ACCEPTANCE_CLIENT_SHUTDOWN_HOOK
  run_hook SINK_ACCEPTANCE_CLIENT_EXIT_CHECK_HOOK
  run_hook SINK_ACCEPTANCE_CLIENT_REPEAT_SIGNAL_HOOK
  run_hook SINK_ACCEPTANCE_SERVER_SHUTDOWN_HOOK
  run_hook SINK_ACCEPTANCE_SERVER_EXIT_CHECK_HOOK
  run_hook SINK_ACCEPTANCE_SERVER_REPEAT_SIGNAL_HOOK
  printf 'Client/server graceful drains and repeated-signal forced exits completed cleanly.\n'
}

usage() {
  printf '%s\n' \
    'usage: scripts/acceptance/run.sh <command>' \
    'commands: prepare-payload, large-transfer, mixed-traffic, soak,' \
    '          interruptions, cancellation, claims, revocation, shutdown'
}

case "${1:-}" in
  prepare-payload) prepare_payload ;;
  large-transfer) large_transfer ;;
  mixed-traffic) mixed_traffic ;;
  soak) soak ;;
  interruptions) interruptions ;;
  cancellation) cancellation ;;
  claims) claims ;;
  revocation) revocation ;;
  shutdown) shutdown_check ;;
  *) usage; exit 2 ;;
esac
