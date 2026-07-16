#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=tests/lib/live-metrics.sh
source "$root/tests/lib/live-metrics.sh"

[[ $(carrack_elapsed_ms 1000000000 2000000000) == 1000 ]]
[[ $(carrack_elapsed_ms 1000000000 1000000001) == 1 ]]
[[ $(carrack_bytes_per_second 1048576 1000000000) == 1048576 ]]

if carrack_elapsed_ms 2 1 >/dev/null 2>&1; then
  echo "elapsed metrics accepted reversed timestamps" >&2
  exit 1
fi
if carrack_bytes_per_second 1 0 >/dev/null 2>&1; then
  echo "throughput metrics accepted zero elapsed time" >&2
  exit 1
fi
