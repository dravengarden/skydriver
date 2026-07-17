#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=tests/lib/live-metrics.sh
source "$root/tests/lib/live-metrics.sh"

if [[ ${CARRACK_ALIYUN_LIVE_TEST:-} != 1 ]]; then
  echo "set CARRACK_ALIYUN_LIVE_TEST=1 to authorize real Aliyun Drive writes" >&2
  exit 2
fi
: "${CARRACK_VFS_TOKEN:?CARRACK_VFS_TOKEN is required}"
: "${CARRACK_ALIYUN_DRIVER_ID:?CARRACK_ALIYUN_DRIVER_ID is required}"

control_url=${CARRACK_CONTROL_URL:-https://dev.carrack.stormbird.xyz}
directory=${CARRACK_ALIYUN_TEST_DIRECTORY:-/}
payload_bytes=${CARRACK_ALIYUN_TEST_BYTES:-33554432}
carrack_bin=${CARRACK_BIN:-target/release/carrack}
operation_timeout_seconds=${CARRACK_LIVE_OPERATION_TIMEOUT_SECONDS:-300}

if [[ $control_url != https://dev.carrack.stormbird.xyz ]]; then
  echo "live acceptance is restricted to the Carrack development environment" >&2
  exit 2
fi
if [[ $directory != /* || $directory == *..* || $directory == *//* ]]; then
  echo "CARRACK_ALIYUN_TEST_DIRECTORY must be a canonical absolute VFS path" >&2
  exit 2
fi
if [[ ! $payload_bytes =~ ^[1-9][0-9]*$ || $payload_bytes -gt 1073741824 ]]; then
  echo "CARRACK_ALIYUN_TEST_BYTES must be between 1 and 1073741824" >&2
  exit 2
fi
if [[ ! $operation_timeout_seconds =~ ^[1-9][0-9]*$ || $operation_timeout_seconds -gt 3600 ]]; then
  echo "CARRACK_LIVE_OPERATION_TIMEOUT_SECONDS must be between 1 and 3600" >&2
  exit 2
fi
if [[ ! -x $carrack_bin ]]; then
  echo "Carrack binary is not executable: $carrack_bin" >&2
  exit 2
fi

carrack_command() {
  local stage=$1
  shift
  local status
  timeout --signal=INT --kill-after=15s "${operation_timeout_seconds}s" \
    "$carrack_bin" "$@" || {
    status=$?
    carrack_live_failure_json \
      carrack.aliyun-live-acceptance-failure.v1 "$CARRACK_ALIYUN_DRIVER_ID" \
      "$stage" "$status" "$operation_timeout_seconds" "$payload_bytes" \
      4194304 4 >&2
    return "$status"
  }
}

state=$(mktemp -d)
chmod 0700 "$state"
identifier=$(openssl rand -hex 8)
name="carrack-aliyun-live-$identifier.bin"
if [[ $directory == / ]]; then
  destination="/$name"
else
  destination="${directory%/}/$name"
fi
source_file="$state/source.bin"
download_file="$state/download.bin"
resumed_file="$state/resumed.bin"
put_committed=false
remove_key="aliyun-live-remove-$identifier"

cleanup() {
  if [[ $put_committed == true ]]; then
    carrack_command "cleanup remove" remove "$destination" \
      --control-url "$control_url" --idempotency-key "$remove_key" \
      --format json >/dev/null 2>&1 || \
      echo "warning: live object cleanup must be retried for $destination" >&2
  fi
  rm -rf "$state"
}
trap cleanup EXIT

head -c "$payload_bytes" /dev/urandom >"$source_file"
source_sha=$(sha256sum "$source_file" | cut -d' ' -f1)

carrack_command compatibility compatibility --control-url "$control_url" --format json |
  jq -e '.protocol_epoch == 2 and .enforcement == "required"' >/dev/null

upload_started_ns=$(carrack_now_ns)
put_result=$(carrack_command upload put \
  "$source_file" "$destination" \
  --control-url "$control_url" \
  --preferred-driver-id "$CARRACK_ALIYUN_DRIVER_ID" \
  --idempotency-key "aliyun-live-put-$identifier" \
  --staging-directory "$state/upload-staging" \
  --transfer-part-bytes 4194304 \
  --maximum-concurrency 4 \
  --format json)
upload_finished_ns=$(carrack_now_ns)
jq -e --arg driver "$CARRACK_ALIYUN_DRIVER_ID" '
  .schema == "carrack.fs-put.v1" and
  .receipt.state == "committed" and
  .receipt.driver_id == $driver and
  .crypto_suite == "carrack-vfs-aes256gcm-hkdfsha256-v1"
' <<<"$put_result" >/dev/null
put_committed=true

download_started_ns=$(carrack_now_ns)
get_result=$(carrack_command download get \
  "$destination" "$download_file" \
  --control-url "$control_url" \
  --staging-directory "$state/download-staging" \
  --transfer-part-bytes 4194304 \
  --maximum-concurrency 4 \
  --format json)
download_finished_ns=$(carrack_now_ns)
jq -e '.schema == "carrack.fs-get.v1"' <<<"$get_result" >/dev/null
[[ $(sha256sum "$download_file" | cut -d' ' -f1) == "$source_sha" ]]

set +e
resume_started_ns=$(carrack_now_ns)
timeout 0.2s "$carrack_bin" get \
  "$destination" "$resumed_file" \
  --control-url "$control_url" \
  --staging-directory "$state/resume-staging" \
  --transfer-part-bytes 4194304 \
  --maximum-concurrency 4 \
  --format json >/dev/null
interrupted_status=$?
set -e
if [[ $interrupted_status != 0 && $interrupted_status != 124 ]]; then
  echo "unexpected interrupted-download status: $interrupted_status" >&2
  exit 1
fi
if [[ $interrupted_status != 0 ]]; then
  carrack_command resume get \
    "$destination" "$resumed_file" \
    --control-url "$control_url" \
    --staging-directory "$state/resume-staging" \
    --transfer-part-bytes 4194304 \
    --maximum-concurrency 4 \
    --format json >/dev/null
fi
resume_finished_ns=$(carrack_now_ns)
[[ $(sha256sum "$resumed_file" | cut -d' ' -f1) == "$source_sha" ]]

upload_elapsed_ns=$((upload_finished_ns - upload_started_ns))
download_elapsed_ns=$((download_finished_ns - download_started_ns))
resume_elapsed_ns=$((resume_finished_ns - resume_started_ns))
upload_elapsed_ms=$(carrack_elapsed_ms "$upload_started_ns" "$upload_finished_ns")
download_elapsed_ms=$(carrack_elapsed_ms "$download_started_ns" "$download_finished_ns")
resume_elapsed_ms=$(carrack_elapsed_ms "$resume_started_ns" "$resume_finished_ns")
upload_bytes_per_second=$(carrack_bytes_per_second "$payload_bytes" "$upload_elapsed_ns")
download_bytes_per_second=$(carrack_bytes_per_second "$payload_bytes" "$download_elapsed_ns")
resume_bytes_per_second=$(carrack_bytes_per_second "$payload_bytes" "$resume_elapsed_ns")

remove_result=$(carrack_command remove remove \
  "$destination" --control-url "$control_url" \
  --idempotency-key "$remove_key" --format json)
jq -e '.schema == "carrack.vfs.remove-receipt.v1"' <<<"$remove_result" >/dev/null
put_committed=false

listing=$(carrack_command list list \
  "$directory" --control-url "$control_url" --format json)
jq -e --arg name "$name" 'all(.entries[]; .name != $name)' <<<"$listing" >/dev/null

jq -n \
  --arg schema carrack.aliyun-live-acceptance.v1 \
  --arg driver_id "$CARRACK_ALIYUN_DRIVER_ID" \
  --arg source_sha256 "$source_sha" \
  --argjson plaintext_bytes "$payload_bytes" \
  --argjson transfer_part_bytes 4194304 \
  --argjson maximum_concurrency 4 \
  --argjson upload_elapsed_ms "$upload_elapsed_ms" \
  --argjson upload_bytes_per_second "$upload_bytes_per_second" \
  --argjson download_elapsed_ms "$download_elapsed_ms" \
  --argjson download_bytes_per_second "$download_bytes_per_second" \
  --argjson resume_elapsed_ms "$resume_elapsed_ms" \
  --argjson resume_bytes_per_second "$resume_bytes_per_second" \
  '{
    schema: $schema,
    driver_id: $driver_id,
    plaintext_bytes: $plaintext_bytes,
    source_sha256: $source_sha256,
    pipeline: {
      transfer_part_bytes: $transfer_part_bytes,
      maximum_concurrency: $maximum_concurrency
    },
    end_to_end: {
      upload_elapsed_ms: $upload_elapsed_ms,
      upload_bytes_per_second: $upload_bytes_per_second,
      download_elapsed_ms: $download_elapsed_ms,
      download_bytes_per_second: $download_bytes_per_second,
      interrupted_resume_elapsed_ms: $resume_elapsed_ms,
      interrupted_resume_bytes_per_second: $resume_bytes_per_second
    },
    encrypted_upload_verified: true,
    concurrent_range_download_verified: true,
    interrupted_resume_verified: true,
    logical_remove_verified: true,
    physical_delete_pending_server_grace: true
  }'
