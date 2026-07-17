#!/usr/bin/env bash

# Low-overhead wall-clock helpers for live transfer acceptance. These metrics
# are advisory end-to-end observations, never integrity or billing evidence.

carrack_now_ns() {
  date +%s%N
}

carrack_elapsed_ms() {
  local started_ns=$1
  local finished_ns=$2
  if [[ ! $started_ns =~ ^[0-9]+$ || ! $finished_ns =~ ^[0-9]+$ || $finished_ns -lt $started_ns ]]; then
    echo "invalid live metric timestamps" >&2
    return 1
  fi
  printf '%s\n' "$(((finished_ns - started_ns + 999999) / 1000000))"
}

carrack_bytes_per_second() {
  local bytes=$1
  local elapsed_ns=$2
  if [[ ! $bytes =~ ^[0-9]+$ || ! $elapsed_ns =~ ^[1-9][0-9]*$ ]]; then
    echo "invalid live throughput sample" >&2
    return 1
  fi
  printf '%s\n' "$((bytes * 1000000000 / elapsed_ns))"
}

carrack_require_integer_range() {
  local name=$1
  local value=$2
  local minimum=$3
  local maximum=$4
  if [[ ! $value =~ ^[0-9]+$ || $value -lt $minimum || $value -gt $maximum ]]; then
    echo "$name must be between $minimum and $maximum" >&2
    return 1
  fi
}

carrack_live_failure_json() {
  local schema=$1
  local driver_id=$2
  local stage=$3
  local exit_status=$4
  local timeout_seconds=$5
  local plaintext_bytes=$6
  local transfer_part_bytes=$7
  local maximum_concurrency=$8
  carrack_require_integer_range exit_status "$exit_status" 1 255 >/dev/null || return 1
  carrack_require_integer_range timeout_seconds "$timeout_seconds" 1 3600 >/dev/null || return 1
  carrack_require_integer_range plaintext_bytes "$plaintext_bytes" 1 1073741824 >/dev/null || return 1
  carrack_require_integer_range transfer_part_bytes "$transfer_part_bytes" 1 268435456 >/dev/null || return 1
  carrack_require_integer_range maximum_concurrency "$maximum_concurrency" 1 64 >/dev/null || return 1
  jq -cn \
    --arg schema "$schema" \
    --arg driver_id "$driver_id" \
    --arg stage "$stage" \
    --argjson exit_status "$exit_status" \
    --argjson timeout_seconds "$timeout_seconds" \
    --argjson plaintext_bytes "$plaintext_bytes" \
    --argjson transfer_part_bytes "$transfer_part_bytes" \
    --argjson maximum_concurrency "$maximum_concurrency" \
    '{
      schema: $schema,
      driver_id: $driver_id,
      stage: $stage,
      exit_status: $exit_status,
      timeout_seconds: $timeout_seconds,
      plaintext_bytes: $plaintext_bytes,
      pipeline: {
        transfer_part_bytes: $transfer_part_bytes,
        maximum_concurrency: $maximum_concurrency
      }
    }'
}
