#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=tests/lib/live-metrics.sh
source "$root/tests/lib/live-metrics.sh"

if [[ ${CARRACK_R2_LIVE_TEST:-} != 1 ]]; then
  echo "set CARRACK_R2_LIVE_TEST=1 to authorize real Cloudflare R2 writes" >&2
  exit 2
fi
: "${CARRACK_VFS_TOKEN:?CARRACK_VFS_TOKEN is required}"

control_url=${CARRACK_CONTROL_URL:-https://dev.carrack.stormbird.xyz}
driver_id=${CARRACK_R2_DRIVER_ID:-r2-default}
directory=${CARRACK_R2_TEST_DIRECTORY:-/}
payload_bytes=${CARRACK_R2_TEST_BYTES:-134217728}
transfer_part_bytes=${CARRACK_R2_TEST_PART_BYTES:-8388608}
maximum_concurrency=${CARRACK_R2_TEST_CONCURRENCY:-8}
carrack_bin=${CARRACK_BIN:-target/release/carrack}
operation_timeout_seconds=${CARRACK_LIVE_OPERATION_TIMEOUT_SECONDS:-300}

if [[ $control_url != https://dev.carrack.stormbird.xyz ]]; then
  echo "live acceptance is restricted to the Carrack development environment" >&2
  exit 2
fi
if [[ $driver_id != r2-default ]]; then
  echo "CARRACK_R2_DRIVER_ID must be r2-default for the managed-bucket acceptance" >&2
  exit 2
fi
if [[ $directory != /* || $directory == *..* || $directory == *//* ]]; then
  echo "CARRACK_R2_TEST_DIRECTORY must be a canonical absolute VFS path" >&2
  exit 2
fi
if ! carrack_require_integer_range CARRACK_R2_TEST_BYTES "$payload_bytes" 104857600 1073741824; then
  exit 2
fi
if ! carrack_require_integer_range CARRACK_R2_TEST_PART_BYTES "$transfer_part_bytes" 5242880 268435456; then
  exit 2
fi
if [[ $transfer_part_bytes -ge $payload_bytes ]]; then
  echo "CARRACK_R2_TEST_PART_BYTES must leave at least two payload parts" >&2
  exit 2
fi
if ! carrack_require_integer_range CARRACK_R2_TEST_CONCURRENCY "$maximum_concurrency" 2 64; then
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
      carrack.r2-live-acceptance-failure.v1 "$driver_id" "$stage" "$status" \
      "$operation_timeout_seconds" "$payload_bytes" "$transfer_part_bytes" \
      "$maximum_concurrency" >&2
    return "$status"
  }
}

state=$(mktemp -d)
chmod 0700 "$state"
identifier=$(openssl rand -hex 8)
name="carrack-r2-live-$identifier.bin"
if [[ $directory == / ]]; then
  destination="/$name"
else
  destination="${directory%/}/$name"
fi
source_file="$state/source.bin"
download_file="$state/download.bin"
resumed_file="$state/resumed.bin"
put_committed=false
remove_key="r2-live-remove-$identifier"

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
  --preferred-driver-id "$driver_id" \
  --idempotency-key "r2-live-put-$identifier" \
  --staging-directory "$state/upload-staging" \
  --transfer-part-bytes "$transfer_part_bytes" \
  --maximum-concurrency "$maximum_concurrency" \
  --format json)
upload_finished_ns=$(carrack_now_ns)
jq -e --arg driver "$driver_id" '
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
  --transfer-part-bytes "$transfer_part_bytes" \
  --maximum-concurrency "$maximum_concurrency" \
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
  --transfer-part-bytes "$transfer_part_bytes" \
  --maximum-concurrency "$maximum_concurrency" \
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
    --transfer-part-bytes "$transfer_part_bytes" \
    --maximum-concurrency "$maximum_concurrency" \
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
  --arg schema carrack.r2-live-acceptance.v1 \
  --arg driver_id "$driver_id" \
  --arg source_sha256 "$source_sha" \
  --argjson plaintext_bytes "$payload_bytes" \
  --argjson transfer_part_bytes "$transfer_part_bytes" \
  --argjson maximum_concurrency "$maximum_concurrency" \
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
    encrypted_multipart_upload_verified: true,
    concurrent_range_download_verified: true,
    interrupted_resume_verified: true,
    logical_remove_verified: true,
    physical_delete_pending_server_grace: true
  }'
