#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state_directory=$(mktemp -d)
server_log="$state_directory/wrangler.log"
port=${CARRACK_TEST_PORT:-8791}
server_pid=

cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$state_directory"
}
trap cleanup EXIT

wrangler=(
  pnpm exec wrangler
  --config "$repository_root/control-plane/wrangler.jsonc"
)

"${wrangler[@]}" d1 migrations apply CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" >/dev/null

raw_token=0123456789abcdef0123456789abcdef
token=$(printf '%s' "$raw_token" | base64 -w0 | tr '+/' '-_' | tr -d '=')
verifier=$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)
restore_content=$(jq -cn '{
  schema_version: "carrack.manifest.v1",
  namespace_id: "202122232425262728292a2b2c2d2e2f",
  object_id: "restore-object",
  generation: 1,
  plaintext_size: 2,
  plaintext_sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  layout: {
    physical_block_bytes: 2,
    crypto_frame_bytes: 2,
    logical_pack_bytes: 2
  },
  crypto: {
    suite: "carrack-aes128gcm-hkdfsha256-v1",
    root_version: 1,
    key_epoch: 7
  },
  packs: [{
    ordinal: 0,
    pack_id: "404142434445464748494a4b4c4d4e4f",
    plaintext_offset: 0,
    plaintext_size: 2,
    ciphertext_size: 18,
    ciphertext_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
    extents: [{
      ordinal: 0,
      first_frame: 0,
      frame_count: 1,
      ciphertext_offset: 0,
      ciphertext_size: 18,
      ciphertext_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
    }]
  }]
}')
restore_manifest_sha=$(printf '%s' "$restore_content" | sha256sum | cut -d' ' -f1)
restore_recovery=$(jq -cn \
  --arg manifest_sha "$restore_manifest_sha" \
  --argjson manifest "$restore_content" \
  '{
    schema_version: "carrack.recovery.v1",
    manifest_sha256: $manifest_sha,
    manifest: $manifest,
    locations: [{
      extent_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
      driver_id: "restore-driver",
      storage_key: "restore/payload",
      offset: 0,
      length: 18
    }]
  }')
restore_recovery_bytes=${#restore_recovery}
printf '%s' "$restore_recovery" >"$state_directory/restore-manifest.json"

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "
    INSERT INTO namespaces (
      id, name, crypto_suite, root_key_version, active_key_epoch,
      replica_policy_json, retention_policy_json, created_at, updated_at
    ) VALUES (
      '202122232425262728292a2b2c2d2e2f', 'worker-e2e',
      'carrack-aes128gcm-hkdfsha256-v1', 1, 1, '{}', '{}', unixepoch(), unixepoch()
    );
    INSERT INTO clients (
      id, name, sdk_version, capabilities_json, labels_json, state, created_at, updated_at
    ) VALUES (
      '303132333435363738393a3b3c3d3e3f', 'worker-e2e', 'test', '[]', '{}',
      'online', unixepoch(), unixepoch()
    );
    INSERT INTO client_token_verifiers (
      id, client_id, verifier_algorithm, verifier_sha256, created_at
    ) VALUES (
      '404142434445464748494a4b4c4d4e4f',
      '303132333435363738393a3b3c3d3e3f', 'sha256/v1', '$verifier', unixepoch()
    );
    INSERT INTO client_namespace_permissions (client_id, namespace_id, role, created_at)
    VALUES (
      '303132333435363738393a3b3c3d3e3f',
      '202122232425262728292a2b2c2d2e2f', 'importer', unixepoch()
    );
    INSERT INTO client_namespace_permissions (client_id, namespace_id, role, created_at)
    VALUES (
      '303132333435363738393a3b3c3d3e3f',
      '202122232425262728292a2b2c2d2e2f', 'restorer', unixepoch()
    );
    INSERT INTO credential_envelopes (
      id, envelope_algorithm, key_version, nonce, ciphertext, created_at, rotated_at
    ) VALUES ('restore-credential', 'test/v1', '1', X'01', X'02', unixepoch(), unixepoch());
    INSERT INTO driver_instances (
      id, kind, config_json, credential_ref, created_at, updated_at
    ) VALUES ('restore-driver', 'test/v1', '{}', 'restore-credential', unixepoch(), unixepoch());
    INSERT INTO objects (id, namespace_id, logical_name, created_at, updated_at)
    VALUES (
      'restore-object', '202122232425262728292a2b2c2d2e2f', 'restore/empty',
      unixepoch(), unixepoch()
    );
    INSERT INTO object_versions (
      id, object_id, generation, manifest_sha256, plaintext_sha256,
      plaintext_bytes, chunk_count, pack_count, state, created_at
    ) VALUES (
      'restore-version', 'restore-object', 1,
      '$restore_manifest_sha',
      'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
      2, 1, 1, 'staging', unixepoch()
    );
    INSERT INTO packs (
      id, namespace_id, crypto_suite, root_key_version, key_epoch,
      ciphertext_sha256, plaintext_bytes, ciphertext_bytes, frame_bytes, created_at
    ) VALUES (
      '404142434445464748494a4b4c4d4e4f',
      '202122232425262728292a2b2c2d2e2f',
      'carrack-aes128gcm-hkdfsha256-v1', 1, 7,
      '1111111111111111111111111111111111111111111111111111111111111111',
      2, 18, 2, unixepoch()
    );
    INSERT INTO extents (
      id, pack_id, ordinal, first_frame, frame_count, ciphertext_offset,
      ciphertext_bytes, ciphertext_sha256, created_at
    ) VALUES (
      'restore-extent', '404142434445464748494a4b4c4d4e4f', 0, 0, 1, 0, 18,
      '2222222222222222222222222222222222222222222222222222222222222222',
      unixepoch()
    );
    INSERT INTO version_packs (version_id, ordinal, pack_id, plaintext_offset)
    VALUES ('restore-version', 0, '404142434445464748494a4b4c4d4e4f', 0);
    INSERT INTO locations (
      id, extent_id, driver_id, storage_key, storage_offset, storage_length,
      ciphertext_sha256, ciphertext_bytes, state, created_at, updated_at
    ) VALUES (
      'restore-location', 'restore-extent', 'restore-driver', 'restore/payload', 0, 18,
      '2222222222222222222222222222222222222222222222222222222222222222',
      18, 'staging', unixepoch(), unixepoch()
    );
    UPDATE locations SET state = 'verified', verified_at = unixepoch(), updated_at = unixepoch()
    WHERE id = 'restore-location';
    INSERT INTO recovery_manifests (
      manifest_sha256, version_id, schema_version, r2_storage_key,
      sidecar_driver_id, sidecar_storage_key, state, ciphertext_bytes,
      verified_at, created_at, updated_at
    ) VALUES (
      '$restore_manifest_sha',
      'restore-version', 'carrack.recovery.v1', 'restore/manifest.json',
      'restore-driver', 'restore/sidecar.json', 'durable', $restore_recovery_bytes,
      unixepoch(), unixepoch(), unixepoch()
    );
    UPDATE object_versions SET state = 'published', published_at = unixepoch()
    WHERE id = 'restore-version';
    UPDATE objects SET current_generation = 1, updated_at = unixepoch()
    WHERE id = 'restore-object';
  " >/dev/null

"${wrangler[@]}" r2 object put carrack-manifests-preview/restore/manifest.json \
  --local \
  --persist-to "$state_directory" \
  --file "$state_directory/restore-manifest.json" >/dev/null

"${wrangler[@]}" dev \
  --local \
  --persist-to "$state_directory" \
  --port "$port" \
  --inspector-port 0 \
  --var CARRACK_ROOT_KEY_V1:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA \
  --show-interactive-dev-session=false >"$server_log" 2>&1 &
server_pid=$!

for _ in $(seq 1 60); do
  if curl --silent --fail "http://127.0.0.1:$port/api/health" >/dev/null; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$server_log" >&2
    exit 1
  fi
  sleep 0.25
done

if ! curl --silent --fail "http://127.0.0.1:$port/api/health" >/dev/null; then
  cat "$server_log" >&2
  echo "local Worker did not become healthy" >&2
  exit 1
fi

base_url="http://127.0.0.1:$port"
authorization="Authorization: Bearer $token"
json='Content-Type: application/json'

restore=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn --arg manifest_sha "$restore_manifest_sha" '{
    namespace_id: "202122232425262728292a2b2c2d2e2f",
    manifest_sha256: $manifest_sha,
    idempotency_key: "worker-e2e-restore-1"
  }')" \
  "$base_url/api/v1/restores")
restore_id=$(jq -r .id <<<"$restore")
jq -e --arg manifest_sha "$restore_manifest_sha" '
  .kind == "restore" and .state == "planned" and
  .version_id == "restore-version" and .object_id == "restore-object" and
  .generation == 1 and
  .manifest_sha256 == $manifest_sha
' <<<"$restore" >/dev/null

read_lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/restores/$restore_id/claim")
read_fence=$(jq -r .fencing_token <<<"$read_lease")
jq -e --arg restore_id "$restore_id" --arg manifest_sha "$restore_manifest_sha" '
  .operation_id == $restore_id and .operation_state == "running" and
  .version_id == "restore-version" and
  .manifest_sha256 == $manifest_sha
' <<<"$read_lease" >/dev/null

fetched_manifest=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$(jq -r .lease_id <<<"$read_lease")" \
    --arg incarnation "$(jq -r .incarnation <<<"$read_lease")" \
    --argjson fence "$read_fence" \
    '{lease_id: $lease_id, incarnation: $incarnation, fencing_token: $fence}')" \
  "$base_url/api/v1/restores/$restore_id/manifest")
[[ "$fetched_manifest" == "$restore_recovery" ]]

key_grant=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$(jq -r .lease_id <<<"$read_lease")" \
    --arg incarnation "$(jq -r .incarnation <<<"$read_lease")" \
    --arg manifest_sha "$restore_manifest_sha" \
    --argjson fence "$read_fence" \
    '{
      lease_id: $lease_id,
      incarnation: $incarnation,
      fencing_token: $fence,
      manifest_sha256: $manifest_sha,
      root_version: 1,
      key_epoch: 7
    }')" \
  "$base_url/api/v1/restores/$restore_id/key")
jq -e '
  .root_version == 1 and .key_epoch == 7 and
  .epoch_key == "gFJYocreVdq4o7taC21pJ1P8jLoqaibruBF6HNpPbbA"
' <<<"$key_grant" >/dev/null

renewed_read_lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/restores/$restore_id/claim")
jq -e --argjson fence "$read_fence" '.fencing_token == $fence' \
  <<<"$renewed_read_lease" >/dev/null

restore_progress=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$(jq -r .lease_id <<<"$read_lease")" \
    --arg incarnation "$(jq -r .incarnation <<<"$read_lease")" \
    --argjson fence "$read_fence" \
    '{
      lease_id: $lease_id,
      incarnation: $incarnation,
      fencing_token: $fence,
      attempt: $fence,
      sequence: 1,
      wire_bytes_read: 18,
      wire_bytes_written: 0,
      useful_bytes_verified: 2,
      active_nanoseconds: 1,
      retry_count: 0,
      throttle_count: 0
    }')" \
  "$base_url/api/v1/operations/$restore_id/progress")
jq -e --arg component_id "$restore_id/restore" '
  .component_id == $component_id and .sequence == 1 and .disposition == "current"
' <<<"$restore_progress" >/dev/null

completed_restore=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$(jq -r .lease_id <<<"$read_lease")" \
    --arg incarnation "$(jq -r .incarnation <<<"$read_lease")" \
    --arg manifest_sha "$restore_manifest_sha" \
    --argjson fence "$read_fence" \
    '{
      lease_id: $lease_id,
      incarnation: $incarnation,
      fencing_token: $fence,
      manifest_sha256: $manifest_sha,
      plaintext_sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      plaintext_bytes: 2
    }')" \
  "$base_url/api/v1/restores/$restore_id/complete")
jq -e --arg restore_id "$restore_id" --arg manifest_sha "$restore_manifest_sha" '
  .operation_id == $restore_id and .state == "succeeded" and
  .manifest_sha256 == $manifest_sha
' <<<"$completed_restore" >/dev/null

failed_restore=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn --arg manifest_sha "$restore_manifest_sha" '{
    namespace_id: "202122232425262728292a2b2c2d2e2f",
    manifest_sha256: $manifest_sha,
    idempotency_key: "worker-e2e-restore-failure"
  }')" \
  "$base_url/api/v1/restores")
failed_restore_id=$(jq -r .id <<<"$failed_restore")
failed_lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/restores/$failed_restore_id/claim")
failed_result=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$(jq -r .lease_id <<<"$failed_lease")" \
    --arg incarnation "$(jq -r .incarnation <<<"$failed_lease")" \
    --arg manifest_sha "$restore_manifest_sha" \
    --argjson fence "$(jq -r .fencing_token <<<"$failed_lease")" \
    '{
      lease_id: $lease_id,
      incarnation: $incarnation,
      fencing_token: $fence,
      manifest_sha256: $manifest_sha,
      error_code: "plaintext_integrity"
    }')" \
  "$base_url/api/v1/restores/$failed_restore_id/fail")
jq -e --arg restore_id "$failed_restore_id" '
  .operation_id == $restore_id and .state == "failed"
' <<<"$failed_result" >/dev/null

operation=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{
    "namespace_id":"202122232425262728292a2b2c2d2e2f",
    "idempotency_key":"worker-e2e-source-v1",
    "useful_bytes_total":1024
  }' \
  "$base_url/api/v1/operations")
operation_id=$(jq -r .id <<<"$operation")
incarnation=$(jq -r .incarnation <<<"$operation")

lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/operations/$operation_id/claim")
lease_id=$(jq -r .lease_id <<<"$lease")
fence=$(jq -r .fencing_token <<<"$lease")

progress_body() {
  local sequence=$1
  local wire_read=$2
  local wire_written=$3
  local useful=$4
  local active=$5
  local supplied_fence=${6:-$fence}

  jq -cn \
    --arg lease_id "$lease_id" \
    --arg incarnation "$incarnation" \
    --argjson fence "$supplied_fence" \
    --argjson sequence "$sequence" \
    --argjson wire_read "$wire_read" \
    --argjson wire_written "$wire_written" \
    --argjson useful "$useful" \
    --argjson active "$active" \
    '{
      lease_id: $lease_id,
      incarnation: $incarnation,
      fencing_token: $fence,
      attempt: $fence,
      sequence: $sequence,
      wire_bytes_read: $wire_read,
      wire_bytes_written: $wire_written,
      useful_bytes_verified: $useful,
      active_nanoseconds: $active,
      retry_count: 1,
      throttle_count: 0
    }'
}

report() {
  curl --silent --show-error --fail-with-body \
    -H "$authorization" -H "$json" \
    --data "$1" \
    "$base_url/api/v1/operations/$operation_id/progress"
}

first_body=$(progress_body 1 2048 1100 1024 1000000000)
first=$(report "$first_body")
duplicate=$(report "$first_body")
second=$(report "$(progress_body 2 4096 2200 2048 2000000000)")
concurrent_body=$(progress_body 3 5000 3000 2500 3000000000)
concurrent_pids=()
for index in $(seq 1 8); do
  report "$concurrent_body" >"$state_directory/concurrent-$index.json" &
  concurrent_pids+=("$!")
done
for pid in "${concurrent_pids[@]}"; do
  wait "$pid"
done
old=$(report "$first_body")

jq -e '.sequence == 1 and .disposition == "current"' <<<"$first" >/dev/null
jq -e '.sequence == 1 and .disposition == "current"' <<<"$duplicate" >/dev/null
jq -e '.sequence == 2 and .disposition == "current"' <<<"$second" >/dev/null
for index in $(seq 1 8); do
  jq -e '.sequence == 3 and .disposition == "current"' \
    "$state_directory/concurrent-$index.json" >/dev/null
done
jq -e '.sequence == 3 and .disposition == "superseded"' <<<"$old" >/dev/null

regression_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$(progress_body 4 1 1 1 1)" \
  "$base_url/api/v1/operations/$operation_id/progress")
stale_fence=$((fence + 1))
stale_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$(progress_body 4 6000 4000 3500 4000000000 "$stale_fence")" \
  "$base_url/api/v1/operations/$operation_id/progress")

[[ "$regression_status" == 409 ]]
[[ "$stale_status" == 409 ]]
