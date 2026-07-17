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
