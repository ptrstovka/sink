#!/usr/bin/env bash

set -euo pipefail
umask 077

CONFIRM_VALUE=I_UNDERSTAND
ONE_GIB=1073741824
BACKGROUND_PIDS=()
CLEANING_UP=0
RUN_STARTED_SECONDS=$SECONDS
TRANSFER_KIND=none
TRANSFER_PROGRESS_FILE=
TRANSFER_PID=
UPLOAD_PROGRESS_FILE=
DOWNLOAD_PROGRESS_FILE=
SSE_PID=
WEBSOCKET_PID=
WEBSOCKET_FEED_PID=
SSE_LAST_BYTES=0
SSE_LAST_PROGRESS_SECONDS=$SECONDS
WEBSOCKET_LAST_BYTES=0
WEBSOCKET_LAST_PROGRESS_SECONDS=$SECONDS
SOAK_LAST_SECONDS=

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
  [[ "$SINK_ACCEPTANCE_PUBLIC_URL" != *'#'* ]] || die "public URL must not contain a fragment"
  case "${SINK_ACCEPTANCE_PUBLIC_URL#*://}" in
    *@*) die "public URL must not contain user information" ;;
  esac
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

track_pid() {
  BACKGROUND_PIDS+=("$1")
}

untrack_pid() {
  local target=$1
  local pid
  local remaining=()
  for pid in "${BACKGROUND_PIDS[@]:-}"; do
    [[ -n "$pid" ]] || continue
    [[ "$pid" == "$target" ]] || remaining+=("$pid")
  done
  BACKGROUND_PIDS=()
  for pid in "${remaining[@]:-}"; do
    [[ -n "$pid" ]] || continue
    BACKGROUND_PIDS+=("$pid")
  done
}

pid_running() {
  kill -0 "$1" >/dev/null 2>&1
}

terminate_pid() {
  local pid=$1
  local attempt
  if pid_running "$pid"; then
    kill "$pid" >/dev/null 2>&1 || true
    for ((attempt = 0; attempt < 20; attempt += 1)); do
      pid_running "$pid" || break
      sleep 0.1
    done
    if pid_running "$pid"; then
      kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
  fi
  wait "$pid" >/dev/null 2>&1 || true
  untrack_pid "$pid"
}

cleanup() {
  local pid attempt any_running
  if (( CLEANING_UP != 0 )); then
    return 0
  fi
  CLEANING_UP=1
  for pid in "${BACKGROUND_PIDS[@]:-}"; do
    [[ -n "$pid" ]] || continue
    kill "$pid" >/dev/null 2>&1 || true
  done
  for ((attempt = 0; attempt < 20; attempt += 1)); do
    any_running=0
    for pid in "${BACKGROUND_PIDS[@]:-}"; do
      [[ -n "$pid" ]] || continue
      if pid_running "$pid"; then
        any_running=1
        break
      fi
    done
    (( any_running == 1 )) || break
    sleep 0.1
  done
  for pid in "${BACKGROUND_PIDS[@]:-}"; do
    [[ -n "$pid" ]] || continue
    if pid_running "$pid"; then
      kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
  done
  for pid in "${BACKGROUND_PIDS[@]:-}"; do
    [[ -n "$pid" ]] || continue
    wait "$pid" >/dev/null 2>&1 || true
  done
  BACKGROUND_PIDS=()
  if [[ -n "${RUN_DIR:-}" ]]; then
    case "$RUN_DIR" in
      */sink-acceptance.*) rm -rf -- "$RUN_DIR" ;;
      *) printf 'refusing to remove unexpected path: %s\n' "$RUN_DIR" >&2 ;;
    esac
  fi
}

handle_signal() {
  local status=$1
  trap - EXIT INT TERM
  cleanup
  exit "$status"
}

trap cleanup EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

read_bounded_integer() {
  local variable=$1
  local default=$2
  local minimum=$3
  local maximum=$4
  local output=$5
  local value=${!variable:-$default}
  [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] || die "$variable must be an integer"
  (( value >= minimum && value <= maximum )) ||
    die "$variable must be between $minimum and $maximum seconds"
  printf -v "$output" '%s' "$value"
}

configure_limits() {
  read_bounded_integer SINK_ACCEPTANCE_CONNECT_TIMEOUT_SECONDS 5 1 60 CONNECT_TIMEOUT_SECONDS
  read_bounded_integer SINK_ACCEPTANCE_REQUEST_TIMEOUT_SECONDS 10 2 300 REQUEST_TIMEOUT_SECONDS
  read_bounded_integer SINK_ACCEPTANCE_OPERATION_TIMEOUT_SECONDS 1800 30 7200 OPERATION_TIMEOUT_SECONDS
  read_bounded_integer SINK_ACCEPTANCE_STALL_TIMEOUT_SECONDS 60 10 600 STALL_TIMEOUT_SECONDS
  read_bounded_integer SINK_ACCEPTANCE_PROGRESS_INTERVAL_SECONDS 5 1 60 PROGRESS_INTERVAL_SECONDS
  read_bounded_integer SINK_ACCEPTANCE_HOOK_TIMEOUT_SECONDS 120 5 900 HOOK_TIMEOUT_SECONDS
  (( PROGRESS_INTERVAL_SECONDS < STALL_TIMEOUT_SECONDS )) ||
    die "SINK_ACCEPTANCE_PROGRESS_INTERVAL_SECONDS must be shorter than SINK_ACCEPTANCE_STALL_TIMEOUT_SECONDS"
}

file_bytes() {
  local path=$1
  if [[ -f "$path" ]]; then
    wc -c < "$path" | tr -d '[:space:]'
  else
    printf '0\n'
  fi
}

curl_progress_bytes() {
  local path=$1
  local field=$2
  if [[ ! -s "$path" ]]; then
    printf '0\n'
    return
  fi
  tr '\r' '\n' < "$path" | awk -v field="$field" '
    /^[[:space:]]*[0-9]+[[:space:]]/ { value = $field }
    END {
      if (value == "") {
        print 0
        exit
      }
      suffix = substr(value, length(value), 1)
      multiplier = 1
      if (suffix == "k") multiplier = 1024
      else if (suffix == "M") multiplier = 1024 * 1024
      else if (suffix == "G") multiplier = 1024 * 1024 * 1024
      else if (suffix == "T") multiplier = 1024 * 1024 * 1024 * 1024
      if (multiplier != 1) value = substr(value, 1, length(value) - 1)
      printf "%.0f\n", value * multiplier
    }
  '
}

transfer_progress_bytes() {
  case "$TRANSFER_KIND" in
    upload) curl_progress_bytes "$TRANSFER_PROGRESS_FILE" 6 ;;
    download) curl_progress_bytes "$TRANSFER_PROGRESS_FILE" 4 ;;
    *) printf '0\n' ;;
  esac
}

diagnostic_snapshot() {
  local reason=$1
  local transfer_bytes=0
  local upload_bytes=0
  local download_bytes=0
  local sse_bytes=0
  local websocket_bytes=0
  [[ -z "$TRANSFER_PROGRESS_FILE" ]] || transfer_bytes=$(transfer_progress_bytes)
  [[ -z "$UPLOAD_PROGRESS_FILE" ]] || upload_bytes=$(curl_progress_bytes "$UPLOAD_PROGRESS_FILE" 6)
  [[ -z "$DOWNLOAD_PROGRESS_FILE" ]] || download_bytes=$(curl_progress_bytes "$DOWNLOAD_PROGRESS_FILE" 4)
  [[ -z "${RUN_DIR:-}" ]] || sse_bytes=$(file_bytes "$RUN_DIR/sse.log")
  [[ -z "${RUN_DIR:-}" ]] || websocket_bytes=$(file_bytes "$RUN_DIR/websocket.log")
  printf 'acceptance diagnostic: reason=%s elapsed_seconds=%s transfer=%s transfer_bytes=%s upload_bytes=%s download_bytes=%s sse_bytes=%s websocket_bytes=%s\n' \
    "$reason" "$((SECONDS - RUN_STARTED_SECONDS))" "$TRANSFER_KIND" "$transfer_bytes" \
    "$upload_bytes" "$download_bytes" "$sse_bytes" "$websocket_bytes" >&2
}

fail_with_diagnostics() {
  diagnostic_snapshot "$1"
  die "$2"
}

seconds_until() {
  local deadline=$1
  local remaining=$((deadline - SECONDS))
  (( remaining > 0 )) || remaining=1
  printf '%s\n' "$remaining"
}

minimum() {
  if (( $1 < $2 )); then
    printf '%s\n' "$1"
  else
    printf '%s\n' "$2"
  fi
}

validate_soak_clock_configuration() {
  local clock_file=${SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE:-}
  [[ -n "$clock_file" ]] || return 0
  [[ "${SINK_ACCEPTANCE_TEST_SOAK_CLOCK_GUARD:-}" == acceptance.invalid &&
    "${PUBLIC_URL:-}" == https://acceptance.invalid ]] ||
    die "SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE is restricted to the guarded acceptance.invalid mock test"
}

read_soak_seconds() {
  local output=$1
  local clock_file=${SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE:-}
  local value=$SECONDS
  if [[ -n "$clock_file" ]]; then
    [[ -f "$clock_file" ]] || die "SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE must name a file"
    value=$(< "$clock_file")
    [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] ||
      die "SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE must contain an integer"
  fi
  if [[ -n "$SOAK_LAST_SECONDS" ]] && (( value < SOAK_LAST_SECONDS )); then
    die "soak clock decreased from $SOAK_LAST_SECONDS to $value"
  fi
  SOAK_LAST_SECONDS=$value
  printf -v "$output" '%s' "$value"
}

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

collect_pid_status() {
  local pid=$1
  local output=$2
  local exit_status
  if wait "$pid"; then
    exit_status=0
  else
    exit_status=$?
  fi
  untrack_pid "$pid"
  printf -v "$output" '%s' "$exit_status"
}

check_stream_progress() {
  local now=$SECONDS
  local current
  [[ -n "$SSE_PID" ]] || fail_with_diagnostics stream_not_started "SSE monitor was not started"
  [[ -n "$WEBSOCKET_PID" ]] || fail_with_diagnostics stream_not_started "WebSocket monitor was not started"
  pid_running "$SSE_PID" || fail_with_diagnostics sse_exited "SSE stream exited before the workload completed"
  pid_running "$WEBSOCKET_PID" || fail_with_diagnostics websocket_exited "WebSocket stream exited before the workload completed"
  pid_running "$WEBSOCKET_FEED_PID" || fail_with_diagnostics websocket_feeder_exited "WebSocket input feeder exited before the workload completed"

  current=$(file_bytes "$RUN_DIR/sse.log")
  if (( current > SSE_LAST_BYTES )); then
    SSE_LAST_BYTES=$current
    SSE_LAST_PROGRESS_SECONDS=$now
  elif (( now - SSE_LAST_PROGRESS_SECONDS >= STALL_TIMEOUT_SECONDS )); then
    fail_with_diagnostics sse_stalled "SSE output did not grow for $STALL_TIMEOUT_SECONDS seconds"
  fi

  current=$(file_bytes "$RUN_DIR/websocket.log")
  if (( current > WEBSOCKET_LAST_BYTES )); then
    WEBSOCKET_LAST_BYTES=$current
    WEBSOCKET_LAST_PROGRESS_SECONDS=$now
  elif (( now - WEBSOCKET_LAST_PROGRESS_SECONDS >= STALL_TIMEOUT_SECONDS )); then
    fail_with_diagnostics websocket_stalled "WebSocket output did not grow for $STALL_TIMEOUT_SECONDS seconds"
  fi
}

start_sse_and_websocket() {
  local lifetime=$1
  local fifo="$RUN_DIR/websocket.in"
  require_command websocat
  require_command mkfifo
  mkfifo "$fifo"

  curl --fail --silent --show-error --no-buffer --http1.1 \
    --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
    --max-time "$lifetime" \
    --speed-limit 1 --speed-time "$STALL_TIMEOUT_SECONDS" \
    --stderr "$RUN_DIR/sse.err" \
    "$PUBLIC_URL/sse" > "$RUN_DIR/sse.log" &
  SSE_PID=$!
  track_pid "$SSE_PID"

  (
    local sequence=0
    while :; do
      printf 'soak-%s\n' "$sequence"
      sequence=$((sequence + 1))
      sleep 1
    done
  ) > "$fifo" &
  WEBSOCKET_FEED_PID=$!
  track_pid "$WEBSOCKET_FEED_PID"

  websocat "$WEBSOCKET_URL/ws" < "$fifo" \
    > "$RUN_DIR/websocket.log" 2> "$RUN_DIR/websocket.err" &
  WEBSOCKET_PID=$!
  track_pid "$WEBSOCKET_PID"

  SSE_LAST_BYTES=0
  SSE_LAST_PROGRESS_SECONDS=$SECONDS
  WEBSOCKET_LAST_BYTES=0
  WEBSOCKET_LAST_PROGRESS_SECONDS=$SECONDS
}

stop_sse_and_websocket() {
  if [[ -n "$WEBSOCKET_FEED_PID" ]]; then
    terminate_pid "$WEBSOCKET_FEED_PID"
    WEBSOCKET_FEED_PID=
  fi
  if [[ -n "$WEBSOCKET_PID" ]]; then
    terminate_pid "$WEBSOCKET_PID"
    WEBSOCKET_PID=
  fi
  if [[ -n "$SSE_PID" ]]; then
    terminate_pid "$SSE_PID"
    SSE_PID=
  fi
}

monitor_pause_until() {
  local deadline=$1
  local delay
  while (( SECONDS < deadline )); do
    check_stream_progress
    delay=$(minimum "$PROGRESS_INTERVAL_SECONDS" "$(seconds_until "$deadline")")
    sleep "$delay"
  done
  check_stream_progress
}

wait_for_pid_until() {
  local pid=$1
  local deadline=$2
  local label=$3
  local watch_streams=${4:-0}
  local delay status
  while pid_running "$pid"; do
    if (( SECONDS >= deadline )); then
      terminate_pid "$pid"
      fail_with_diagnostics "${label}_deadline" "$label exceeded its deadline"
    fi
    (( watch_streams == 0 )) || check_stream_progress
    delay=$(minimum 1 "$(seconds_until "$deadline")")
    sleep "$delay"
  done
  collect_pid_status "$pid" status
  return "$status"
}

start_upload() {
  local prefix=$1
  local max_time=$2
  TRANSFER_KIND=upload
  TRANSFER_PROGRESS_FILE="$prefix.progress"
  UPLOAD_PROGRESS_FILE=$TRANSFER_PROGRESS_FILE
  : > "$TRANSFER_PROGRESS_FILE"
  curl --fail --show-error --http1.1 \
    --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
    --max-time "$max_time" \
    --speed-limit 1 --speed-time "$STALL_TIMEOUT_SECONDS" \
    --request PUT --upload-file "$SINK_ACCEPTANCE_PAYLOAD_FILE" \
    --output "$prefix.reply" \
    --write-out '%{size_upload}\n' \
    --stderr "$TRANSFER_PROGRESS_FILE" \
    "$PUBLIC_URL/upload" > "$prefix.metrics" &
  TRANSFER_PID=$!
  track_pid "$TRANSFER_PID"
}

start_download() {
  local prefix=$1
  local output=$2
  local max_time=$3
  TRANSFER_KIND=download
  TRANSFER_PROGRESS_FILE="$prefix.progress"
  DOWNLOAD_PROGRESS_FILE=$TRANSFER_PROGRESS_FILE
  : > "$TRANSFER_PROGRESS_FILE"
  curl --fail --show-error --http1.1 \
    --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
    --max-time "$max_time" \
    --speed-limit 1 --speed-time "$STALL_TIMEOUT_SECONDS" \
    --output "$output" \
    --write-out '%{size_download}\n' \
    --stderr "$TRANSFER_PROGRESS_FILE" \
    "$PUBLIC_URL/download" > "$prefix.metrics" &
  TRANSFER_PID=$!
  track_pid "$TRANSFER_PID"
}

verify_transfer_size() {
  local metrics=$1
  local label=$2
  local size
  size=$(tr -d '[:space:]' < "$metrics")
  [[ "$size" =~ ^[0-9]+$ ]] || fail_with_diagnostics "${label}_missing_size" "$label did not report a final byte count"
  [[ "$size" == "$ONE_GIB" ]] || fail_with_diagnostics "${label}_wrong_size" "$label transferred $size bytes instead of 1 GiB"
}

wait_for_transfer() {
  local deadline=$1
  local watch_streams=${2:-0}
  local last_bytes=0
  local last_progress=$SECONDS
  local current delay status pid
  pid=$TRANSFER_PID
  while pid_running "$pid"; do
    if (( SECONDS >= deadline )); then
      terminate_pid "$pid"
      TRANSFER_PID=
      fail_with_diagnostics operation_deadline "$TRANSFER_KIND exceeded its operation deadline"
    fi
    current=$(transfer_progress_bytes)
    if (( current > last_bytes )); then
      last_bytes=$current
      last_progress=$SECONDS
    elif (( SECONDS - last_progress >= STALL_TIMEOUT_SECONDS )); then
      terminate_pid "$pid"
      TRANSFER_PID=
      fail_with_diagnostics transfer_stalled "$TRANSFER_KIND byte count did not grow for $STALL_TIMEOUT_SECONDS seconds"
    fi
    (( watch_streams == 0 )) || check_stream_progress
    delay=$(minimum "$PROGRESS_INTERVAL_SECONDS" "$(seconds_until "$deadline")")
    sleep "$delay"
  done
  collect_pid_status "$pid" status
  TRANSFER_PID=
  (( status == 0 )) || fail_with_diagnostics transfer_failed "$TRANSFER_KIND failed with curl status $status"
}

verify_upload_reply() {
  local reply=$1
  local expected=$2
  local received bytes
  received=$(awk -F= '$1 == "sha256" {print $2}' "$reply")
  bytes=$(awk -F= '$1 == "bytes" {print $2}' "$reply")
  [[ "$bytes" == "$ONE_GIB" ]] || fail_with_diagnostics upload_receiver_size_mismatch "upload receiver reported an unexpected byte count"
  [[ "$received" == "$expected" ]] || fail_with_diagnostics upload_hash_mismatch "1 GiB upload SHA-256 mismatch"
}

large_transfer() {
  require_confirmation
  require_public_url
  require_payload
  require_command curl
  configure_limits
  make_run_dir

  local expected deadline max_time download_hash
  expected=$(sha256_file "$SINK_ACCEPTANCE_PAYLOAD_FILE")

  deadline=$((SECONDS + OPERATION_TIMEOUT_SECONDS))
  max_time=$(seconds_until "$deadline")
  start_upload "$RUN_DIR/upload" "$max_time"
  wait_for_transfer "$deadline"
  verify_transfer_size "$RUN_DIR/upload.metrics" upload
  verify_upload_reply "$RUN_DIR/upload.reply" "$expected"

  deadline=$((SECONDS + OPERATION_TIMEOUT_SECONDS))
  max_time=$(seconds_until "$deadline")
  start_download "$RUN_DIR/download" "$RUN_DIR/download.bin" "$max_time"
  wait_for_transfer "$deadline"
  verify_transfer_size "$RUN_DIR/download.metrics" download
  download_hash=$(sha256_file "$RUN_DIR/download.bin")
  [[ "$download_hash" == "$expected" ]] || fail_with_diagnostics download_hash_mismatch "1 GiB download SHA-256 mismatch"
  TRANSFER_KIND=none
  TRANSFER_PROGRESS_FILE=
  printf '1 GiB upload and download SHA-256 checks passed.\n'
}

mixed_traffic() {
  require_confirmation
  require_public_url
  require_payload
  require_command curl
  configure_limits
  make_run_dir

  local count=${SINK_ACCEPTANCE_REQUEST_COUNT:-120}
  local ordinary_concurrency=${SINK_ACCEPTANCE_ORDINARY_CONCURRENCY:-25}
  [[ "$count" =~ ^(0|[1-9][0-9]*)$ ]] || die "SINK_ACCEPTANCE_REQUEST_COUNT must be an integer"
  (( count >= 100 && count <= 1000 )) || die "mixed traffic requires between 100 and 1000 ordinary requests"
  [[ "$ordinary_concurrency" =~ ^(0|[1-9][0-9]*)$ ]] ||
    die "SINK_ACCEPTANCE_ORDINARY_CONCURRENCY must be an integer"
  (( ordinary_concurrency >= 1 && ordinary_concurrency <= 100 )) ||
    die "SINK_ACCEPTANCE_ORDINARY_CONCURRENCY must be between 1 and 100"

  local expected started deadline request_deadline request_waves max_time
  local upload_pid upload_progress download_pid download_progress
  local upload_last=0 upload_last_progress=$SECONDS upload_done=0 upload_status=0
  local download_last=0 download_last_progress=$SECONDS download_done=0 download_status=0
  local ordinary_started=0 ordinary_done=0 ordinary_failures=0
  local current delay id pid index status expected_body pause_deadline
  local ordinary_pids=()
  local ordinary_collected=()

  expected=$(sha256_file "$SINK_ACCEPTANCE_PAYLOAD_FILE")
  started=$SECONDS
  deadline=$((started + OPERATION_TIMEOUT_SECONDS))
  start_sse_and_websocket "$((OPERATION_TIMEOUT_SECONDS + PROGRESS_INTERVAL_SECONDS))"

  max_time=$(seconds_until "$deadline")
  start_upload "$RUN_DIR/mixed-upload" "$max_time"
  upload_pid=$TRANSFER_PID
  upload_progress=$TRANSFER_PROGRESS_FILE
  start_download "$RUN_DIR/mixed-download" "$RUN_DIR/mixed-download.bin" "$max_time"
  download_pid=$TRANSFER_PID
  download_progress=$TRANSFER_PROGRESS_FILE
  upload_last_progress=$SECONDS
  download_last_progress=$SECONDS
  TRANSFER_KIND=mixed
  TRANSFER_PROGRESS_FILE=

  for ((id = 0; id < ordinary_concurrency && id < count; id += 1)); do
    curl --fail --silent --show-error --http1.1 \
      --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
      --max-time "$REQUEST_TIMEOUT_SECONDS" \
      --stderr "$RUN_DIR/ordinary-$id.err" \
      --output "$RUN_DIR/ordinary-$id.txt" \
      "$PUBLIC_URL/ordinary/$id" &
    pid=$!
    ordinary_pids[id]=$pid
    ordinary_collected[id]=0
    track_pid "$pid"
    ordinary_started=$((ordinary_started + 1))
  done
  request_waves=$(((count + ordinary_concurrency - 1) / ordinary_concurrency))
  request_deadline=$((SECONDS + request_waves * (REQUEST_TIMEOUT_SECONDS + 1)))
  (( request_deadline <= deadline )) || request_deadline=$deadline

  while (( upload_done == 0 || download_done == 0 || ordinary_done < count )); do
    check_stream_progress

    if (( upload_done == 0 )); then
      if pid_running "$upload_pid"; then
        current=$(curl_progress_bytes "$upload_progress" 6)
        if (( current > upload_last )); then
          upload_last=$current
          upload_last_progress=$SECONDS
        elif (( SECONDS - upload_last_progress >= STALL_TIMEOUT_SECONDS )); then
          fail_with_diagnostics mixed_upload_stalled "mixed upload byte count did not grow for $STALL_TIMEOUT_SECONDS seconds"
        fi
      else
        collect_pid_status "$upload_pid" upload_status
        upload_done=1
        (( upload_status == 0 )) || fail_with_diagnostics mixed_upload_failed "mixed upload failed with curl status $upload_status"
        verify_transfer_size "$RUN_DIR/mixed-upload.metrics" mixed_upload
      fi
    fi

    if (( download_done == 0 )); then
      if pid_running "$download_pid"; then
        current=$(curl_progress_bytes "$download_progress" 4)
        if (( current > download_last )); then
          download_last=$current
          download_last_progress=$SECONDS
        elif (( SECONDS - download_last_progress >= STALL_TIMEOUT_SECONDS )); then
          fail_with_diagnostics mixed_download_stalled "mixed download byte count did not grow for $STALL_TIMEOUT_SECONDS seconds"
        fi
      else
        collect_pid_status "$download_pid" download_status
        download_done=1
        (( download_status == 0 )) || fail_with_diagnostics mixed_download_failed "mixed download failed with curl status $download_status"
        verify_transfer_size "$RUN_DIR/mixed-download.metrics" mixed_download
      fi
    fi

    for ((index = 0; index < ordinary_started; index += 1)); do
      if (( ordinary_collected[index] == 0 )) && ! pid_running "${ordinary_pids[index]}"; then
        collect_pid_status "${ordinary_pids[index]}" status
        ordinary_collected[index]=1
        ordinary_done=$((ordinary_done + 1))
        if (( status != 0 )); then
          ordinary_failures=$((ordinary_failures + 1))
        else
          expected_body="ordinary-$index"
          [[ "$(< "$RUN_DIR/ordinary-$index.txt")" == "$expected_body" ]] ||
            ordinary_failures=$((ordinary_failures + 1))
        fi
        if (( ordinary_started < count )); then
          id=$ordinary_started
          curl --fail --silent --show-error --http1.1 \
            --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
            --max-time "$REQUEST_TIMEOUT_SECONDS" \
            --stderr "$RUN_DIR/ordinary-$id.err" \
            --output "$RUN_DIR/ordinary-$id.txt" \
            "$PUBLIC_URL/ordinary/$id" &
          pid=$!
          ordinary_pids[id]=$pid
          ordinary_collected[id]=0
          track_pid "$pid"
          ordinary_started=$((ordinary_started + 1))
        fi
      fi
    done
    (( ordinary_failures == 0 )) || fail_with_diagnostics mixed_ordinary_failed "$ordinary_failures mixed ordinary requests failed or returned an unexpected body"

    if (( ordinary_done < count && SECONDS >= request_deadline )); then
      fail_with_diagnostics mixed_ordinary_deadline "mixed ordinary requests exceeded the request deadline"
    fi
    if (( SECONDS >= deadline )); then
      fail_with_diagnostics mixed_overall_deadline "mixed workload exceeded the operation deadline"
    fi

    if (( upload_done == 0 || download_done == 0 || ordinary_done < count )); then
      delay=$(minimum "$PROGRESS_INTERVAL_SECONDS" "$(seconds_until "$deadline")")
      if (( ordinary_done < count )); then
        delay=$(minimum "$delay" "$(seconds_until "$request_deadline")")
        delay=$(minimum "$delay" 1)
      fi
      sleep "$delay"
    fi
  done

  if (( SSE_LAST_BYTES == 0 || WEBSOCKET_LAST_BYTES == 0 )); then
    pause_deadline=$((SECONDS + PROGRESS_INTERVAL_SECONDS))
    (( pause_deadline <= deadline )) || pause_deadline=$deadline
    monitor_pause_until "$pause_deadline"
  fi
  (( SSE_LAST_BYTES > 0 )) || fail_with_diagnostics sse_no_progress "SSE produced no progress during the mixed workload"
  (( WEBSOCKET_LAST_BYTES > 0 )) || fail_with_diagnostics websocket_no_progress "WebSocket produced no echoes during the mixed workload"
  stop_sse_and_websocket
  verify_upload_reply "$RUN_DIR/mixed-upload.reply" "$expected"
  [[ "$(sha256_file "$RUN_DIR/mixed-download.bin")" == "$expected" ]] ||
    fail_with_diagnostics mixed_download_hash_mismatch "mixed download SHA-256 mismatch"
  TRANSFER_KIND=none
  TRANSFER_PROGRESS_FILE=
  printf '%s mixed ordinary requests and 1 GiB transfers completed with continuous SSE/WebSocket progress.\n' "$count"
}

soak() {
  require_confirmation
  require_public_url
  require_payload
  require_command curl
  configure_limits
  make_run_dir

  local duration
  read_bounded_integer SINK_ACCEPTANCE_SOAK_SECONDS 3600 3600 86400 duration
  local started deadline finished elapsed completion_budget
  local iteration=0
  local now remaining operation_deadline request_deadline max_time status pause_deadline expected pid transfer_prefix
  validate_soak_clock_configuration
  expected=$(sha256_file "$SINK_ACCEPTANCE_PAYLOAD_FILE")
  completion_budget=$((2 * OPERATION_TIMEOUT_SECONDS))
  if (( REQUEST_TIMEOUT_SECONDS > completion_budget )); then
    completion_budget=$REQUEST_TIMEOUT_SECONDS
  fi
  start_sse_and_websocket "$((duration + completion_budget + PROGRESS_INTERVAL_SECONDS))"
  SOAK_LAST_SECONDS=
  read_soak_seconds started
  deadline=$((started + duration))

  while :; do
    read_soak_seconds now
    (( now < deadline )) || break
    max_time=$REQUEST_TIMEOUT_SECONDS
    curl --fail --silent --show-error --http1.1 \
      --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
      --max-time "$max_time" \
      --stderr "$RUN_DIR/soak-ordinary.err" \
      --output /dev/null \
      "$PUBLIC_URL/ordinary/$iteration" &
    pid=$!
    track_pid "$pid"
    request_deadline=$((SECONDS + REQUEST_TIMEOUT_SECONDS))
    if wait_for_pid_until "$pid" "$request_deadline" soak_ordinary 1; then
      status=0
    else
      status=$?
    fi
    (( status == 0 )) || fail_with_diagnostics soak_ordinary_failed "soak ordinary request failed with curl status $status"

    read_soak_seconds now
    # The soak deadline gates pair admission; each admitted half keeps its operation deadline.
    if (( iteration % 10 == 0 && now < deadline )); then
      max_time=$OPERATION_TIMEOUT_SECONDS
      transfer_prefix="$RUN_DIR/soak-upload-$iteration"
      start_upload "$transfer_prefix" "$max_time"
      operation_deadline=$((SECONDS + OPERATION_TIMEOUT_SECONDS))
      wait_for_transfer "$operation_deadline" 1
      verify_transfer_size "$transfer_prefix.metrics" soak_upload
      verify_upload_reply "$transfer_prefix.reply" "$expected"

      max_time=$OPERATION_TIMEOUT_SECONDS
      transfer_prefix="$RUN_DIR/soak-download-$iteration"
      start_download "$transfer_prefix" /dev/null "$max_time"
      operation_deadline=$((SECONDS + OPERATION_TIMEOUT_SECONDS))
      wait_for_transfer "$operation_deadline" 1
      verify_transfer_size "$transfer_prefix.metrics" soak_download
    fi

    iteration=$((iteration + 1))
    read_soak_seconds now
    if (( now < deadline )); then
      remaining=$((deadline - now))
      pause_deadline=$((SECONDS + $(minimum 60 "$remaining")))
      monitor_pause_until "$pause_deadline"
    fi
  done
  check_stream_progress
  (( SSE_LAST_BYTES > 0 )) || fail_with_diagnostics sse_no_progress "SSE produced no progress during the soak"
  (( WEBSOCKET_LAST_BYTES > 0 )) || fail_with_diagnostics websocket_no_progress "WebSocket produced no echoes during the soak"
  read_soak_seconds finished
  elapsed=$((finished - started))
  stop_sse_and_websocket
  TRANSFER_KIND=none
  TRANSFER_PROGRESS_FILE=
  printf 'Bounded SSE/WebSocket and mixed-transfer soak passed: configured_duration_seconds=%s elapsed_seconds=%s\n' \
    "$duration" "$elapsed"
}

run_hook() {
  local variable=$1
  require_env "$variable"
  local hook=${!variable}
  local deadline status pid
  [[ "$hook" == /* ]] || die "$variable must be an absolute executable path"
  [[ -x "$hook" ]] || die "$variable is not executable"
  "$hook" > "$RUN_DIR/hook.log" 2>&1 &
  pid=$!
  track_pid "$pid"
  deadline=$((SECONDS + HOOK_TIMEOUT_SECONDS))
  if wait_for_pid_until "$pid" "$deadline" "$variable"; then
    status=0
  else
    status=$?
  fi
  (( status == 0 )) || die "$variable failed with status $status; output retained only until cleanup"
}

run_expected_failure_hook() {
  local variable=$1
  require_env "$variable"
  local hook=${!variable}
  local deadline status pid
  [[ "$hook" == /* ]] || die "$variable must be an absolute executable path"
  [[ -x "$hook" ]] || die "$variable is not executable"
  "$hook" > "$RUN_DIR/hook.log" 2>&1 &
  pid=$!
  track_pid "$pid"
  deadline=$((SECONDS + HOOK_TIMEOUT_SECONDS))
  if wait_for_pid_until "$pid" "$deadline" "$variable"; then
    status=0
  else
    status=$?
  fi
  if (( status == 0 )); then
    die "$variable unexpectedly succeeded"
  fi
}

probe_success_within_ten_seconds() {
  local attempt
  for ((attempt = 0; attempt < 40; attempt += 1)); do
    if curl --fail --silent --show-error --http1.1 \
      --connect-timeout "$CONNECT_TIMEOUT_SECONDS" --max-time 2 \
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
  configure_limits
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
  configure_limits
  make_run_dir
  curl --silent --show-error --http1.1 --request POST \
    --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
    --max-time "$OPERATION_TIMEOUT_SECONDS" \
    --stderr "$RUN_DIR/cancellation.err" \
    "$PUBLIC_URL/side-effect" > "$RUN_DIR/cancelled.txt" &
  local caller=$!
  track_pid "$caller"
  sleep 1
  terminate_pid "$caller"
  local attempt stats
  for ((attempt = 0; attempt < 40; attempt += 1)); do
    stats=$(curl --fail --silent --show-error --http1.1 \
      --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
      --max-time "$REQUEST_TIMEOUT_SECONDS" \
      --stderr "$RUN_DIR/cancellation-stats.err" \
      "$SINK_ACCEPTANCE_FIXTURE_URL/stats")
    if [[ "$stats" == *'active_streams=0'* && "$stats" == *'side_effects=1'* ]]; then
      curl --fail --silent --show-error --http1.1 \
        --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
        --max-time "$REQUEST_TIMEOUT_SECONDS" \
        --stderr "$RUN_DIR/cancellation-health.err" \
        "$PUBLIC_URL/health" > /dev/null
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
  configure_limits
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
  configure_limits
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
  configure_limits
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
