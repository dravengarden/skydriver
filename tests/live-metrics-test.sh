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
