#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=tests/lib/live-metrics.sh
source "$root/tests/lib/live-metrics.sh"

[[ $(carrack_elapsed_ms 1000000000 2000000000) == 1000 ]]
[[ $(carrack_elapsed_ms 1000000000 1000000001) == 1 ]]
[[ $(carrack_bytes_per_second 1048576 1000000000) == 1048576 ]]
carrack_require_integer_range TEST_VALUE 8 2 64

if carrack_elapsed_ms 2 1 >/dev/null 2>&1; then
  echo "elapsed metrics accepted reversed timestamps" >&2
  exit 1
fi
if carrack_bytes_per_second 1 0 >/dev/null 2>&1; then
  echo "throughput metrics accepted zero elapsed time" >&2
  exit 1
fi
if carrack_require_integer_range TEST_VALUE 1 2 64 >/dev/null 2>&1; then
  echo "integer range accepted a value below its bound" >&2
  exit 1
fi
if carrack_require_integer_range TEST_VALUE invalid 2 64 >/dev/null 2>&1; then
  echo "integer range accepted a non-integer" >&2
  exit 1
fi

failure=$(carrack_live_failure_json \
  carrack.r2-live-acceptance-failure.v2 r2-default 0123456789abcdef \
  resume 124 300 134217728 8388608 8 \
  2026-07-17T12:00:00Z 2026-07-17T12:05:00Z 300000)
jq -e '
  .schema == "carrack.r2-live-acceptance-failure.v2" and
  .driver_id == "r2-default" and
  .run_id == "0123456789abcdef" and
  .stage == "resume" and
  .stage_timing.started_at == "2026-07-17T12:00:00Z" and
  .stage_timing.finished_at == "2026-07-17T12:05:00Z" and
  .stage_timing.elapsed_ms == 300000 and
  .exit_status == 124 and
  .timeout_seconds == 300 and
  .plaintext_bytes == 134217728 and
  .pipeline.transfer_part_bytes == 8388608 and
  .pipeline.maximum_concurrency == 8
' <<<"$failure" >/dev/null
if carrack_live_failure_json failure driver 0123456789abcdef stage 0 300 1 1 1 \
  2026-07-17T12:00:00Z 2026-07-17T12:00:01Z 1000 >/dev/null 2>&1; then
  echo "live failure accepted a successful exit status" >&2
  exit 1
fi
if carrack_live_failure_json failure driver not-opaque stage 1 300 1 1 1 \
  2026-07-17T12:00:00Z 2026-07-17T12:00:01Z 1000 >/dev/null 2>&1; then
  echo "live failure accepted a noncanonical run identifier" >&2
  exit 1
fi

r2_acceptance="$root/tests/r2-live.sh"
if env CARRACK_R2_LIVE_TEST=1 CARRACK_VFS_TOKEN=redacted \
  CARRACK_R2_TEST_BYTES=33554432 CARRACK_BIN=/bin/true \
  "$r2_acceptance" >/dev/null 2>&1; then
  echo "R2 acceptance claimed multipart coverage below its threshold" >&2
  exit 1
fi
if env CARRACK_R2_LIVE_TEST=1 CARRACK_VFS_TOKEN=redacted \
  CARRACK_R2_TEST_BYTES=134217728 CARRACK_R2_TEST_PART_BYTES=134217728 \
  CARRACK_BIN=/bin/true "$r2_acceptance" >/dev/null 2>&1; then
  echo "R2 acceptance claimed concurrent ranges with only one part" >&2
  exit 1
fi
if env CARRACK_R2_LIVE_TEST=1 CARRACK_VFS_TOKEN=redacted \
  CARRACK_R2_TEST_CONCURRENCY=1 CARRACK_BIN=/bin/true \
  "$r2_acceptance" >/dev/null 2>&1; then
  echo "R2 acceptance claimed concurrent ranges at concurrency one" >&2
  exit 1
fi
if rg -q 'env CARRACK_VFS_TOKEN' "$root/tests/r2-live.sh" "$root/tests/aliyun-live.sh"; then
  echo "live acceptance exposed a VFS token through command arguments" >&2
  exit 1
fi
