#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/sink-acceptance-test.XXXXXX")
trap 'rm -rf -- "$TEST_ROOT"' EXIT

mkdir -p "$TEST_ROOT/bin" "$TEST_ROOT/state"
printf '0\n' > "$TEST_ROOT/state/active"
printf '0\n' > "$TEST_ROOT/state/max"

cat > "$TEST_ROOT/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

output=
stderr_file=
max_time=
soak_scenario=${SINK_ACCEPTANCE_TEST_SOAK_SCENARIO:-}
url=
while (( $# > 0 )); do
  case "$1" in
    --output|--stderr|--connect-timeout|--max-time|--speed-limit|--speed-time|--request|--upload-file|--write-out)
      case "$1" in
        --output) output=$2 ;;
        --stderr) stderr_file=$2 ;;
        --max-time) max_time=$2 ;;
      esac
      shift 2
      ;;
    --*) shift ;;
    http://*|https://*) url=$1; shift ;;
    *) shift ;;
  esac
done

if [[ -n "$stderr_file" ]]; then
  if [[ "${SINK_ACCEPTANCE_TEST_DELAY_STDERR_OPEN:-0}" == 1 && "$url" == */upload ]]; then
    /bin/sleep 2
    if [[ -s "$stderr_file" ]]; then
      : > "$SINK_ACCEPTANCE_TEST_STATE/stale-progress-observed"
    fi
  fi
  : > "$stderr_file"
fi
case "$url" in
  */sse)
    while :; do
      printf 'data: progress\n\n'
      /bin/sleep 0.2
    done
    ;;
  */upload)
    if [[ "$soak_scenario" == pair ]]; then
      printf 'upload %s\n' "$max_time" >> "$SINK_ACCEPTANCE_TEST_STATE/soak-calls"
      printf '3605\n' > "$SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE"
    fi
    if [[ "${SINK_ACCEPTANCE_TEST_DELAY_STDERR_OPEN:-0}" == 1 ]]; then
      for ((progress = 1; progress <= 9; progress += 1)); do
        printf '0 0 0 0 0 %sM\r' "$progress" >> "$stderr_file"
        /bin/sleep 1
      done
    elif [[ "$soak_scenario" == pair ]]; then
      /bin/sleep 1
    else
      /bin/sleep 7
    fi
    printf 'bytes=1073741824\nsha256=testhash\n' > "$output"
    printf '1073741824\n'
    ;;
  */download)
    if [[ "$soak_scenario" == pair ]]; then
      printf 'download %s\n' "$max_time" >> "$SINK_ACCEPTANCE_TEST_STATE/soak-calls"
      (( max_time == 30 )) || exit 28
      printf '3610\n' > "$SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE"
    fi
    if [[ "${SINK_ACCEPTANCE_TEST_DELAY_STDERR_OPEN:-0}" != 1 ]]; then
      if [[ "$soak_scenario" == pair ]]; then
        /bin/sleep 1
      else
        /bin/sleep 7
      fi
    fi
    : > "$output"
    printf '1073741824\n'
    ;;
  */ordinary/*)
    case "$soak_scenario" in
      pair)
        printf 'ordinary %s\n' "$max_time" >> "$SINK_ACCEPTANCE_TEST_STATE/soak-calls"
        printf '3560\n' > "$SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE"
        exit 0
        ;;
      ordinary-boundary)
        printf 'ordinary %s\n' "$max_time" >> "$SINK_ACCEPTANCE_TEST_STATE/soak-calls"
        printf '3600\n' > "$SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE"
        /bin/sleep 1
        exit 0
        ;;
      default-clock)
        printf 'ordinary %s\n' "$max_time" >> "$SINK_ACCEPTANCE_TEST_STATE/soak-calls"
        exit 22
        ;;
      decreasing-clock)
        printf '9\n' > "$SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE"
        /bin/sleep 1
        exit 0
        ;;
    esac
    lock="$SINK_ACCEPTANCE_TEST_STATE/lock"
    while ! mkdir "$lock" 2>/dev/null; do /bin/sleep 0.01; done
    active=$(< "$SINK_ACCEPTANCE_TEST_STATE/active")
    active=$((active + 1))
    printf '%s\n' "$active" > "$SINK_ACCEPTANCE_TEST_STATE/active"
    maximum=$(< "$SINK_ACCEPTANCE_TEST_STATE/max")
    if (( active > maximum )); then
      printf '%s\n' "$active" > "$SINK_ACCEPTANCE_TEST_STATE/max"
    fi
    printf '%s\n' "$url" >> "$SINK_ACCEPTANCE_TEST_STATE/requests"
    rmdir "$lock"

    decrement_active() {
      while ! mkdir "$lock" 2>/dev/null; do /bin/sleep 0.01; done
      active=$(< "$SINK_ACCEPTANCE_TEST_STATE/active")
      printf '%s\n' "$((active - 1))" > "$SINK_ACCEPTANCE_TEST_STATE/active"
      rmdir "$lock"
    }
    trap decrement_active EXIT
    /bin/sleep 1
    id=${url##*/}
    printf 'ordinary-%s\n' "$id" > "$output"
    ;;
  *) exit 22 ;;
esac
EOF

cat > "$TEST_ROOT/bin/mktemp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${SINK_ACCEPTANCE_TEST_RUN_DIR:-}" ]]; then
  [[ "${1:-}" == -d ]] || exit 64
  mkdir -p "$SINK_ACCEPTANCE_TEST_RUN_DIR"
  printf '%s\n' "$SINK_ACCEPTANCE_TEST_RUN_DIR"
else
  exec /usr/bin/mktemp "$@"
fi
EOF

cat > "$TEST_ROOT/bin/websocat" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r line; do
  printf '%s\n' "$line"
done
EOF

cat > "$TEST_ROOT/bin/sha256sum" <<'EOF'
#!/usr/bin/env bash
printf 'testhash  %s\n' "$1"
EOF

chmod +x "$TEST_ROOT/bin/curl" "$TEST_ROOT/bin/mktemp" "$TEST_ROOT/bin/websocat" "$TEST_ROOT/bin/sha256sum"
dd if=/dev/zero of="$TEST_ROOT/payload.bin" bs=1 count=0 seek=1073741824 2>/dev/null

run_test_soak() {
  local public_url=$1
  shift
  env -u SINK_ACCEPTANCE_TEST_SOAK_SCENARIO \
    -u SINK_ACCEPTANCE_TEST_SOAK_CLOCK_GUARD \
    -u SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE \
    PATH="$TEST_ROOT/bin:$PATH" \
    SINK_ACCEPTANCE_TEST_STATE="$TEST_ROOT/state" \
    SINK_ACCEPTANCE_CONFIRM=I_UNDERSTAND \
    SINK_ACCEPTANCE_PUBLIC_URL="$public_url" \
    SINK_ACCEPTANCE_PAYLOAD_FILE="$TEST_ROOT/payload.bin" \
    SINK_ACCEPTANCE_CONNECT_TIMEOUT_SECONDS=1 \
    SINK_ACCEPTANCE_REQUEST_TIMEOUT_SECONDS=2 \
    SINK_ACCEPTANCE_OPERATION_TIMEOUT_SECONDS=30 \
    SINK_ACCEPTANCE_STALL_TIMEOUT_SECONDS=10 \
    SINK_ACCEPTANCE_PROGRESS_INTERVAL_SECONDS=1 \
    "$@" \
    "$ROOT/scripts/acceptance/run.sh" soak
}

env \
  PATH="$TEST_ROOT/bin:$PATH" \
  SINK_ACCEPTANCE_TEST_STATE="$TEST_ROOT/state" \
  SINK_ACCEPTANCE_CONFIRM=I_UNDERSTAND \
  SINK_ACCEPTANCE_PUBLIC_URL=https://acceptance.invalid \
  SINK_ACCEPTANCE_PAYLOAD_FILE="$TEST_ROOT/payload.bin" \
  SINK_ACCEPTANCE_REQUEST_COUNT=100 \
  SINK_ACCEPTANCE_ORDINARY_CONCURRENCY=25 \
  SINK_ACCEPTANCE_CONNECT_TIMEOUT_SECONDS=1 \
  SINK_ACCEPTANCE_REQUEST_TIMEOUT_SECONDS=2 \
  SINK_ACCEPTANCE_OPERATION_TIMEOUT_SECONDS=30 \
  SINK_ACCEPTANCE_STALL_TIMEOUT_SECONDS=10 \
  SINK_ACCEPTANCE_PROGRESS_INTERVAL_SECONDS=1 \
  "$ROOT/scripts/acceptance/run.sh" mixed-traffic > "$TEST_ROOT/run.out"

[[ "$(< "$TEST_ROOT/state/max")" == 25 ]] || {
  printf 'expected max ordinary concurrency 25, got %s\n' "$(< "$TEST_ROOT/state/max")" >&2
  exit 1
}
[[ "$(wc -l < "$TEST_ROOT/state/requests" | tr -d '[:space:]')" == 100 ]] || {
  printf 'expected exactly 100 ordinary requests\n' >&2
  exit 1
}
grep -q '100 mixed ordinary requests' "$TEST_ROOT/run.out"

if env \
  PATH="$TEST_ROOT/bin:$PATH" \
  SINK_ACCEPTANCE_CONFIRM=I_UNDERSTAND \
  SINK_ACCEPTANCE_PUBLIC_URL=https://acceptance.invalid \
  SINK_ACCEPTANCE_PAYLOAD_FILE="$TEST_ROOT/payload.bin" \
  SINK_ACCEPTANCE_ORDINARY_CONCURRENCY=0 \
  "$ROOT/scripts/acceptance/run.sh" mixed-traffic > /dev/null 2> "$TEST_ROOT/invalid.err"; then
  printf 'zero ordinary concurrency unexpectedly succeeded\n' >&2
  exit 1
fi
grep -q 'SINK_ACCEPTANCE_ORDINARY_CONCURRENCY must be between 1 and 100' "$TEST_ROOT/invalid.err"

RACE_RUN_DIR="$TEST_ROOT/sink-acceptance.progress-race"
mkdir -p "$RACE_RUN_DIR"
printf '0 0 0 0 0 1024M\r' > "$RACE_RUN_DIR/upload.progress"
env \
  PATH="$TEST_ROOT/bin:$PATH" \
  SINK_ACCEPTANCE_TEST_STATE="$TEST_ROOT/state" \
  SINK_ACCEPTANCE_TEST_RUN_DIR="$RACE_RUN_DIR" \
  SINK_ACCEPTANCE_TEST_DELAY_STDERR_OPEN=1 \
  SINK_ACCEPTANCE_CONFIRM=I_UNDERSTAND \
  SINK_ACCEPTANCE_PUBLIC_URL=https://acceptance.invalid \
  SINK_ACCEPTANCE_PAYLOAD_FILE="$TEST_ROOT/payload.bin" \
  SINK_ACCEPTANCE_CONNECT_TIMEOUT_SECONDS=1 \
  SINK_ACCEPTANCE_REQUEST_TIMEOUT_SECONDS=2 \
  SINK_ACCEPTANCE_OPERATION_TIMEOUT_SECONDS=30 \
  SINK_ACCEPTANCE_STALL_TIMEOUT_SECONDS=10 \
  SINK_ACCEPTANCE_PROGRESS_INTERVAL_SECONDS=1 \
  "$ROOT/scripts/acceptance/run.sh" large-transfer > "$TEST_ROOT/progress-race.out"

[[ ! -e "$TEST_ROOT/state/stale-progress-observed" ]] || {
  printf 'mock curl inherited stale upload progress before opening stderr\n' >&2
  exit 1
}
grep -q '1 GiB upload and download SHA-256 checks passed' "$TEST_ROOT/progress-race.out"

: > "$TEST_ROOT/state/soak-calls"
if run_test_soak https://acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_SCENARIO=default-clock \
  > /dev/null 2> "$TEST_ROOT/soak-default-clock.err"; then
  printf 'default-clock soak unexpectedly succeeded past the expected mock request failure\n' >&2
  exit 1
fi
[[ "$(< "$TEST_ROOT/state/soak-calls")" == 'ordinary 2' ]] || {
  printf 'default-clock soak did not reach its first ordinary request; got:\n' >&2
  cat "$TEST_ROOT/state/soak-calls" >&2
  exit 1
}
grep -q 'reason=soak_ordinary_failed' "$TEST_ROOT/soak-default-clock.err"
grep -q 'soak ordinary request failed with curl status 22' "$TEST_ROOT/soak-default-clock.err"

printf '0\n' > "$TEST_ROOT/state/soak-clock"
: > "$TEST_ROOT/state/soak-calls"
run_test_soak https://acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_SCENARIO=pair \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_GUARD=acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE="$TEST_ROOT/state/soak-clock" \
  > "$TEST_ROOT/soak-boundary.out"

ordinary_timeout=$(awk '$1 == "ordinary" { print $2 }' "$TEST_ROOT/state/soak-calls")
upload_timeout=$(awk '$1 == "upload" { print $2 }' "$TEST_ROOT/state/soak-calls")
download_timeout=$(awk '$1 == "download" { print $2 }' "$TEST_ROOT/state/soak-calls")
if (( ordinary_timeout != 2 || upload_timeout != 30 || download_timeout != 30 )); then
  printf 'expected an atomic upload/download pair with full operation deadlines; got:\n' >&2
  cat "$TEST_ROOT/state/soak-calls" >&2
  exit 1
fi
grep -q 'configured_duration_seconds=3600 elapsed_seconds=3610' "$TEST_ROOT/soak-boundary.out"

printf '0\n' > "$TEST_ROOT/state/soak-clock"
: > "$TEST_ROOT/state/soak-calls"
run_test_soak https://acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_SCENARIO=ordinary-boundary \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_GUARD=acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE="$TEST_ROOT/state/soak-clock" \
  > "$TEST_ROOT/soak-ordinary-boundary.out"

[[ "$(< "$TEST_ROOT/state/soak-calls")" == 'ordinary 2' ]] || {
  printf 'expected one full-timeout ordinary request and no boundary pair; got:\n' >&2
  cat "$TEST_ROOT/state/soak-calls" >&2
  exit 1
}
grep -q 'configured_duration_seconds=3600 elapsed_seconds=3600' "$TEST_ROOT/soak-ordinary-boundary.out"

printf '0\n' > "$TEST_ROOT/state/soak-clock"
if run_test_soak https://acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE="$TEST_ROOT/state/soak-clock" \
  > /dev/null 2> "$TEST_ROOT/soak-clock-unguarded.err"; then
  printf 'unguarded test soak clock unexpectedly succeeded\n' >&2
  exit 1
fi
grep -q 'restricted to the guarded acceptance.invalid mock test' "$TEST_ROOT/soak-clock-unguarded.err"

if run_test_soak https://other.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_GUARD=acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE="$TEST_ROOT/state/soak-clock" \
  > /dev/null 2> "$TEST_ROOT/soak-clock-non-mock.err"; then
  printf 'test soak clock unexpectedly affected a non-mock URL\n' >&2
  exit 1
fi
grep -q 'restricted to the guarded acceptance.invalid mock test' "$TEST_ROOT/soak-clock-non-mock.err"

printf 'malformed\n' > "$TEST_ROOT/state/soak-clock"
if run_test_soak https://acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_GUARD=acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE="$TEST_ROOT/state/soak-clock" \
  > /dev/null 2> "$TEST_ROOT/soak-clock-malformed.err"; then
  printf 'malformed test soak clock unexpectedly succeeded\n' >&2
  exit 1
fi
grep -q 'must contain an integer' "$TEST_ROOT/soak-clock-malformed.err"

printf '10\n' > "$TEST_ROOT/state/soak-clock"
if run_test_soak https://acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_SCENARIO=decreasing-clock \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_GUARD=acceptance.invalid \
  SINK_ACCEPTANCE_TEST_SOAK_CLOCK_FILE="$TEST_ROOT/state/soak-clock" \
  > /dev/null 2> "$TEST_ROOT/soak-clock-decreasing.err"; then
  printf 'decreasing test soak clock unexpectedly succeeded\n' >&2
  exit 1
fi
grep -q 'soak clock decreased from 10 to 9' "$TEST_ROOT/soak-clock-decreasing.err"

printf 'acceptance harness rolling-concurrency, stale-progress, default-clock, soak-boundary, and clock-safety regressions passed\n'
