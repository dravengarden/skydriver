#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=tests/lib/live-metrics.sh
source "$root/tests/lib/live-metrics.sh"

if [[ ${CARRACK_R2_SMALL_SYNC_LIVE_TEST:-} != 1 ]]; then
  echo "set CARRACK_R2_SMALL_SYNC_LIVE_TEST=1 to authorize real dev R2 writes" >&2
  exit 2
fi
: "${CARRACK_VFS_TOKEN:?CARRACK_VFS_TOKEN is required}"

control_url=${CARRACK_CONTROL_URL:-https://dev.carrack.stormbird.xyz}
driver_id=${CARRACK_R2_DRIVER_ID:-r2-default}
parent=${CARRACK_R2_SMALL_SYNC_PARENT:-/}
file_count=${CARRACK_R2_SMALL_SYNC_FILES:-64}
file_bytes=${CARRACK_R2_SMALL_SYNC_BYTES:-1048576}
upload_concurrency=${CARRACK_R2_SMALL_SYNC_UPLOAD_CONCURRENCY:-8}
sync_concurrency=${CARRACK_R2_SMALL_SYNC_CONCURRENCY:-16}
carrack_bin=${CARRACK_BIN:-target/release/carrack}
operation_timeout_seconds=${CARRACK_LIVE_OPERATION_TIMEOUT_SECONDS:-300}

if [[ $control_url != https://dev.carrack.stormbird.xyz ]]; then
  echo "small-file sync acceptance is restricted to the Carrack development environment" >&2
  exit 2
fi
if [[ $driver_id != r2-default ]]; then
  echo "CARRACK_R2_DRIVER_ID must be r2-default" >&2
  exit 2
fi
if [[ $parent != /* || $parent == *..* || $parent == *//* ]]; then
  echo "CARRACK_R2_SMALL_SYNC_PARENT must be a canonical absolute VFS path" >&2
  exit 2
fi
carrack_require_integer_range CARRACK_R2_SMALL_SYNC_FILES "$file_count" 8 1000
carrack_require_integer_range CARRACK_R2_SMALL_SYNC_BYTES "$file_bytes" 1 16777216
carrack_require_integer_range CARRACK_R2_SMALL_SYNC_UPLOAD_CONCURRENCY "$upload_concurrency" 1 32
carrack_require_integer_range CARRACK_R2_SMALL_SYNC_CONCURRENCY "$sync_concurrency" 1 64
carrack_require_integer_range CARRACK_LIVE_OPERATION_TIMEOUT_SECONDS "$operation_timeout_seconds" 1 3600
if [[ ! -x $carrack_bin ]]; then
  echo "Carrack binary is not executable: $carrack_bin" >&2
  exit 2
fi

state=$(mktemp -d)
chmod 0700 "$state"
identifier=$(openssl rand -hex 8)
run_id=$identifier
name="carrack-r2-small-sync-$identifier"
if [[ $parent == / ]]; then
  directory="/$name"
else
  directory="${parent%/}/$name"
fi
source_file="$state/source.bin"
committed="$state/committed"
mkdir -m 0700 "$committed"
directory_created=false

carrack_command() {
  local stage=$1
  shift
  local status
  timeout --signal=INT --kill-after=15s "${operation_timeout_seconds}s" \
    "$carrack_bin" "$@" || {
    status=$?
    echo "small-file live acceptance failed during $stage (status $status)" >&2
    return "$status"
  }
}

cleanup() {
  local marker ordinal path
  shopt -s nullglob
  for marker in "$committed"/*; do
    ordinal=${marker##*/}
    path="$directory/file-$ordinal.bin"
    carrack_command "cleanup file $ordinal" remove "$path" \
      --control-url "$control_url" \
      --idempotency-key "r2-small-sync-remove-$identifier-$ordinal" \
      --format json >/dev/null 2>&1 || \
      echo "warning: live object cleanup must be retried for $path" >&2
  done
  if [[ $directory_created == true ]]; then
    carrack_command "cleanup directory" remove "$directory" \
      --control-url "$control_url" \
      --idempotency-key "r2-small-sync-rmdir-$identifier" \
      --format json >/dev/null 2>&1 || \
      echo "warning: live directory cleanup must be retried for $directory" >&2
  fi
  rm -rf "$state"
}
trap cleanup EXIT

head -c "$file_bytes" /dev/urandom >"$source_file"
source_sha=$(sha256sum "$source_file" | cut -d' ' -f1)
expected_bytes=$((file_count * file_bytes))

carrack_command compatibility compatibility --control-url "$control_url" --format json |
  jq -e '.protocol_epoch == 2 and .enforcement == "required"' >/dev/null
carrack_command mkdir mkdir "$directory" \
  --control-url "$control_url" \
  --idempotency-key "r2-small-sync-mkdir-$identifier" \
  --format json | jq -e '.schema == "carrack.fs-mkdir.v1"' >/dev/null
directory_created=true

put_one() {
  local ordinal=$1
  local result
  result=$(carrack_command "upload $ordinal" put \
    "$source_file" "$directory/file-$ordinal.bin" \
    --control-url "$control_url" \
    --preferred-driver-id "$driver_id" \
    --idempotency-key "r2-small-sync-put-$identifier-$ordinal" \
    --staging-directory "$state/upload-$ordinal" \
    --format json)
  jq -e --arg driver "$driver_id" '
    .schema == "carrack.fs-put.v1" and
    .receipt.state == "committed" and
    .receipt.driver_id == $driver
  ' <<<"$result" >/dev/null
  : >"$committed/$ordinal"
}

upload_started_ns=$(carrack_now_ns)
upload_started_at=$(carrack_now_utc)
active=0
upload_failed=0
for ((ordinal = 0; ordinal < file_count; ordinal++)); do
  put_one "$ordinal" &
  active=$((active + 1))
  if ((active >= upload_concurrency)); then
    wait -n || upload_failed=1
    active=$((active - 1))
  fi
done
while ((active > 0)); do
  wait -n || upload_failed=1
  active=$((active - 1))
done
if ((upload_failed != 0)); then
  echo "one or more small-file uploads failed" >&2
  exit 1
fi
upload_finished_ns=$(carrack_now_ns)
upload_finished_at=$(carrack_now_utc)

cold_started_ns=$(carrack_now_ns)
cold_started_at=$(carrack_now_utc)
cold_result=$(carrack_command "cold sync" sync "$directory" "$state/download" \
  --control-url "$control_url" \
  --state-directory "$state/sync-state" \
  --maximum-concurrency "$sync_concurrency" \
  --maximum-file-concurrency 1 \
  --format json)
cold_finished_ns=$(carrack_now_ns)
cold_finished_at=$(carrack_now_utc)
jq -e --argjson files "$file_count" --argjson bytes "$expected_bytes" '
  .schema == "carrack.fs-sync.v1" and
  .files == $files and
  .downloaded_files == $files and
  .reused_files == 0 and
  .downloaded_bytes == $bytes
' <<<"$cold_result" >/dev/null

for ((ordinal = 0; ordinal < file_count; ordinal++)); do
  [[ $(sha256sum "$state/download/file-$ordinal.bin" | cut -d' ' -f1) == "$source_sha" ]]
done

warm_started_ns=$(carrack_now_ns)
warm_started_at=$(carrack_now_utc)
warm_result=$(carrack_command "warm sync" sync "$directory" "$state/download" \
  --control-url "$control_url" \
  --state-directory "$state/sync-state" \
  --maximum-concurrency "$sync_concurrency" \
  --maximum-file-concurrency 1 \
  --format json)
warm_finished_ns=$(carrack_now_ns)
warm_finished_at=$(carrack_now_utc)
jq -e --argjson files "$file_count" '
  .schema == "carrack.fs-sync.v1" and
  .files == $files and
  .downloaded_files == 0 and
  .reused_files == $files and
  .downloaded_bytes == 0
' <<<"$warm_result" >/dev/null

upload_elapsed_ms=$(carrack_elapsed_ms "$upload_started_ns" "$upload_finished_ns")
cold_elapsed_ms=$(carrack_elapsed_ms "$cold_started_ns" "$cold_finished_ns")
warm_elapsed_ms=$(carrack_elapsed_ms "$warm_started_ns" "$warm_finished_ns")

jq -n \
  --arg schema carrack.r2-small-sync-live-acceptance.v1 \
  --arg driver_id "$driver_id" \
  --arg run_id "$run_id" \
  --arg directory "$directory" \
  --arg source_sha256 "$source_sha" \
  --arg upload_started_at "$upload_started_at" \
  --arg upload_finished_at "$upload_finished_at" \
  --arg cold_started_at "$cold_started_at" \
  --arg cold_finished_at "$cold_finished_at" \
  --arg warm_started_at "$warm_started_at" \
  --arg warm_finished_at "$warm_finished_at" \
  --argjson files "$file_count" \
  --argjson bytes_per_file "$file_bytes" \
  --argjson total_bytes "$expected_bytes" \
  --argjson upload_concurrency "$upload_concurrency" \
  --argjson sync_concurrency "$sync_concurrency" \
  --argjson upload_elapsed_ms "$upload_elapsed_ms" \
  --argjson cold_elapsed_ms "$cold_elapsed_ms" \
  --argjson warm_elapsed_ms "$warm_elapsed_ms" \
  '{
    schema: $schema,
    driver_id: $driver_id,
    run_id: $run_id,
    temporary_directory: $directory,
    shape: {
      files: $files,
      bytes_per_file: $bytes_per_file,
      total_bytes: $total_bytes,
      source_sha256: $source_sha256
    },
    pipeline: {
      upload_concurrency: $upload_concurrency,
      sync_concurrency: $sync_concurrency,
      ranges_per_file: 1
    },
    setup: {
      started_at: $upload_started_at,
      finished_at: $upload_finished_at,
      elapsed_ms: $upload_elapsed_ms
    },
    cold_sync: {
      started_at: $cold_started_at,
      finished_at: $cold_finished_at,
      elapsed_ms: $cold_elapsed_ms,
      verified_files: $files,
      verified_bytes: $total_bytes
    },
    warm_sync: {
      started_at: $warm_started_at,
      finished_at: $warm_finished_at,
      elapsed_ms: $warm_elapsed_ms,
      reused_files: $files,
      provider_bytes: 0
    },
    cleanup: "logical remove on exit; physical deletion remains server-owned"
  }'
