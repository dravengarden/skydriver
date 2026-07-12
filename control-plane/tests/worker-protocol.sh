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

report_error() {
  if [[ -f "$server_log" ]]; then
    cat "$server_log" >&2
  fi
}
trap report_error ERR

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
restore_recovery_sha=$(printf '%s' "$restore_recovery" | sha256sum | cut -d' ' -f1)
import_content=$(jq -cn '{
  schema_version: "carrack.manifest.v1",
  namespace_id: "202122232425262728292a2b2c2d2e2f",
  object_id: "import-object",
  generation: 1,
  plaintext_size: 1024,
  plaintext_sha256: "7777777777777777777777777777777777777777777777777777777777777777",
  layout: {
    physical_block_bytes: 1024,
    crypto_frame_bytes: 1024,
    logical_pack_bytes: 1024
  },
  crypto: {
    suite: "carrack-aes128gcm-hkdfsha256-v1",
    root_version: 1,
    key_epoch: 1
  },
  packs: [{
    ordinal: 0,
    pack_id: "505152535455565758595a5b5c5d5e5f",
    plaintext_offset: 0,
    plaintext_size: 1024,
    ciphertext_size: 1040,
    ciphertext_sha256: "5555555555555555555555555555555555555555555555555555555555555555",
    extents: [{
      ordinal: 0,
      first_frame: 0,
      frame_count: 1,
      ciphertext_offset: 0,
      ciphertext_size: 1040,
      ciphertext_sha256: "6666666666666666666666666666666666666666666666666666666666666666"
    }]
  }]
}')
import_manifest_sha=$(printf '%s' "$import_content" | sha256sum | cut -d' ' -f1)
import_recovery=$(jq -cn \
  --arg manifest_sha "$import_manifest_sha" \
  --argjson manifest "$import_content" '
  {
    schema_version: "carrack.recovery.v1",
    manifest_sha256: $manifest_sha,
    manifest: $manifest,
    locations: [{
      extent_sha256: "6666666666666666666666666666666666666666666666666666666666666666",
      driver_id: "restore-driver",
      storage_key: "import/payload",
      provider_version: "import-v1",
      offset: 0,
      length: 1040
    }]
  }')
wrong_import_content=$(jq -cn --argjson manifest "$import_content" '$manifest | .crypto.key_epoch = 2')
wrong_import_manifest_sha=$(printf '%s' "$wrong_import_content" | sha256sum | cut -d' ' -f1)
wrong_import_recovery=$(jq -cn \
  --arg manifest_sha "$wrong_import_manifest_sha" \
  --argjson recovery "$import_recovery" \
  --argjson manifest "$wrong_import_content" '
  $recovery | .manifest_sha256 = $manifest_sha | .manifest = $manifest')
copy_recovery=$(jq -cn \
  --argjson recovery "$restore_recovery" \
  '$recovery | .locations += [{
    extent_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
    driver_id: "copy-driver",
    storage_key: "copy/payload",
    provider_version: "copy-v1",
    offset: 0,
    length: 18
  }]')
copy_without_source=$(jq -cn \
  --argjson recovery "$copy_recovery" \
  '$recovery | .locations = [.locations[-1]]')
move_recovery=$(jq -cn \
  --argjson recovery "$copy_recovery" \
  '$recovery | .locations += [{
    extent_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
    driver_id: "move-driver",
    storage_key: "move/payload",
    provider_version: "move-v1",
    offset: 0,
    length: 18
  }]')
move_final_recovery=$(jq -cn \
  --argjson recovery "$move_recovery" \
  '$recovery | .locations = [.locations[] | select(.driver_id != "restore-driver")]')
move_underreplicated_recovery=$(jq -cn \
  --argjson recovery "$move_recovery" \
  '$recovery | .locations = [.locations[] | select(.driver_id == "move-driver")]')
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
      'carrack-aes128gcm-hkdfsha256-v1', 1, 1,
      '{\"minimum_available_replicas\":2}', '{\"move_grace_seconds\":120}',
      unixepoch(), unixepoch()
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
    INSERT INTO client_namespace_permissions (client_id, namespace_id, role, created_at)
    VALUES (
      '303132333435363738393a3b3c3d3e3f',
      '202122232425262728292a2b2c2d2e2f', 'relay', unixepoch()
    );
    INSERT INTO client_namespace_permissions (client_id, namespace_id, role, created_at)
    VALUES (
      '303132333435363738393a3b3c3d3e3f',
      '202122232425262728292a2b2c2d2e2f', 'janitor', unixepoch()
    );
    INSERT INTO credential_envelopes (
      id, envelope_algorithm, key_version, nonce, ciphertext, created_at, rotated_at
    ) VALUES ('restore-credential', 'test/v1', '1', X'01', X'02', unixepoch(), unixepoch());
    INSERT INTO driver_instances (
      id, kind, config_json, credential_ref, created_at, updated_at
    ) VALUES ('restore-driver', 'test/v1', '{}', 'restore-credential', unixepoch(), unixepoch());
    INSERT INTO driver_instances (
      id, kind, config_json, created_at, updated_at
    ) VALUES ('copy-driver', 'test/v1', '{}', unixepoch(), unixepoch());
    INSERT INTO driver_instances (
      id, kind, config_json, created_at, updated_at
    ) VALUES ('move-driver', 'test/v1', '{}', unixepoch(), unixepoch());
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
    UPDATE locations SET state = 'available', revision = revision + 1, updated_at = unixepoch()
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

copy_operation=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn --arg manifest_sha "$restore_manifest_sha" '{
    namespace_id: "202122232425262728292a2b2c2d2e2f",
    manifest_sha256: $manifest_sha,
    destination_driver_id: "copy-driver",
    idempotency_key: "worker-e2e-copy-1"
  }')" \
  "$base_url/api/v1/copies")
copy_id=$(jq -r .id <<<"$copy_operation")
copy_incarnation=$(jq -r .incarnation <<<"$copy_operation")
jq -e \
  --arg manifest_sha "$restore_manifest_sha" \
  --arg recovery_sha "$restore_recovery_sha" '
  .kind == "copy" and .state == "planned" and
  .manifest_sha256 == $manifest_sha and
  .source_recovery_sha256 == $recovery_sha and
  .source_recovery_revision == 1 and
  .destination_driver_id == "copy-driver"
' <<<"$copy_operation" >/dev/null

copy_lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/operations/$copy_id/claim")
copy_lease_id=$(jq -r .lease_id <<<"$copy_lease")
copy_fence=$(jq -r .fencing_token <<<"$copy_lease")

copy_source=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$copy_lease_id" \
    --arg incarnation "$copy_incarnation" \
    --argjson fence "$copy_fence" \
    '{lease_id: $lease_id, incarnation: $incarnation, fencing_token: $fence}')" \
  "$base_url/api/v1/copies/$copy_id/manifest")
[[ "$copy_source" == "$restore_recovery" ]]

losing_copy_operation=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn --arg manifest_sha "$restore_manifest_sha" '{
    namespace_id: "202122232425262728292a2b2c2d2e2f",
    manifest_sha256: $manifest_sha,
    destination_driver_id: "copy-driver",
    idempotency_key: "worker-e2e-copy-loser"
  }')" \
  "$base_url/api/v1/copies")
losing_copy_id=$(jq -r .id <<<"$losing_copy_operation")
losing_copy_incarnation=$(jq -r .incarnation <<<"$losing_copy_operation")
losing_copy_lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/operations/$losing_copy_id/claim")

invalid_staged_copy=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data-binary "$copy_without_source" \
  "$base_url/api/v1/recovery-manifests/stage")
invalid_copy_publication=$(jq -cn \
  --arg operation_id "$copy_id" \
  --arg lease_id "$copy_lease_id" \
  --arg incarnation "$copy_incarnation" \
  --arg manifest_sha "$restore_manifest_sha" \
  --arg recovery_sha "$(jq -r .recovery_sha256 <<<"$invalid_staged_copy")" \
  --arg r2_key "$(jq -r .r2_key <<<"$invalid_staged_copy")" \
  --arg r2_version "$(jq -r .r2_version <<<"$invalid_staged_copy")" \
  --argjson fence "$copy_fence" '
  {
    operation_id: $operation_id,
    lease_id: $lease_id,
    incarnation: $incarnation,
    fencing_token: $fence,
    manifest_sha256: $manifest_sha,
    recovery_sha256: $recovery_sha,
    r2_key: $r2_key,
    r2_version: $r2_version,
    sidecar_driver_id: "copy-driver",
    sidecar_storage_key: "copy/invalid-recovery.json"
  }')
removed_source_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$invalid_copy_publication" \
  "$base_url/api/v1/copies/publish")
[[ "$removed_source_status" == 400 ]]

staged_copy=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data-binary "$copy_recovery" \
  "$base_url/api/v1/recovery-manifests/stage")
copy_recovery_sha=$(jq -r .recovery_sha256 <<<"$staged_copy")
restaged_copy=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data-binary "$copy_recovery" \
  "$base_url/api/v1/recovery-manifests/stage")
jq -e \
  --arg recovery_sha "$copy_recovery_sha" \
  --arg r2_version "$(jq -r .r2_version <<<"$staged_copy")" '
  .recovery_sha256 == $recovery_sha and .r2_version == $r2_version
' <<<"$restaged_copy" >/dev/null

copy_publication=$(jq -cn \
  --arg operation_id "$copy_id" \
  --arg lease_id "$copy_lease_id" \
  --arg incarnation "$copy_incarnation" \
  --arg manifest_sha "$restore_manifest_sha" \
  --arg recovery_sha "$copy_recovery_sha" \
  --arg r2_key "$(jq -r .r2_key <<<"$staged_copy")" \
  --arg r2_version "$(jq -r .r2_version <<<"$staged_copy")" \
  --argjson fence "$copy_fence" '
  {
    operation_id: $operation_id,
    lease_id: $lease_id,
    incarnation: $incarnation,
    fencing_token: $fence,
    manifest_sha256: $manifest_sha,
    recovery_sha256: $recovery_sha,
    r2_key: $r2_key,
    r2_version: $r2_version,
    sidecar_driver_id: "copy-driver",
    sidecar_storage_key: "copy/recovery.json"
  }')

stale_copy_publication=$(jq ".fencing_token = $((copy_fence + 1))" <<<"$copy_publication")
stale_copy_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$stale_copy_publication" \
  "$base_url/api/v1/copies/publish")
[[ "$stale_copy_status" == 409 ]]

published_copy=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$copy_publication" \
  "$base_url/api/v1/copies/publish")
jq -e \
  --arg copy_id "$copy_id" \
  --arg manifest_sha "$restore_manifest_sha" \
  --arg recovery_sha "$copy_recovery_sha" '
  .operation_id == $copy_id and .manifest_sha256 == $manifest_sha and
  .recovery_sha256 == $recovery_sha and .destination_driver_id == "copy-driver" and
  .locations_added == 1 and .recovery_revision == 2 and .state == "published"
' <<<"$published_copy" >/dev/null

losing_publication=$(jq \
  --arg operation_id "$losing_copy_id" \
  --arg lease_id "$(jq -r .lease_id <<<"$losing_copy_lease")" \
  --arg incarnation "$losing_copy_incarnation" \
  --argjson fence "$(jq -r .fencing_token <<<"$losing_copy_lease")" '
  .operation_id = $operation_id |
  .lease_id = $lease_id |
  .incarnation = $incarnation |
  .fencing_token = $fence
' <<<"$copy_publication")
losing_copy_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$losing_publication" \
  "$base_url/api/v1/copies/publish")
[[ "$losing_copy_status" == 409 ]]

replayed_copy=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$copy_publication" \
  "$base_url/api/v1/copies/publish")
[[ "$replayed_copy" == "$published_copy" ]]

copied_restore=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn --arg manifest_sha "$restore_manifest_sha" '{
    namespace_id: "202122232425262728292a2b2c2d2e2f",
    manifest_sha256: $manifest_sha,
    idempotency_key: "worker-e2e-restored-copy"
  }')" \
  "$base_url/api/v1/restores")
copied_restore_id=$(jq -r .id <<<"$copied_restore")
copied_restore_lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/restores/$copied_restore_id/claim")
copied_recovery=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$(jq -r .lease_id <<<"$copied_restore_lease")" \
    --arg incarnation "$(jq -r .incarnation <<<"$copied_restore_lease")" \
    --argjson fence "$(jq -r .fencing_token <<<"$copied_restore_lease")" \
    '{lease_id: $lease_id, incarnation: $incarnation, fencing_token: $fence}')" \
  "$base_url/api/v1/restores/$copied_restore_id/manifest")
[[ "$copied_recovery" == "$copy_recovery" ]]

move_operation=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn --arg manifest_sha "$restore_manifest_sha" '{
    namespace_id: "202122232425262728292a2b2c2d2e2f",
    manifest_sha256: $manifest_sha,
    source_driver_id: "restore-driver",
    destination_driver_id: "move-driver",
    idempotency_key: "worker-e2e-move-1"
  }')" \
  "$base_url/api/v1/moves")
move_id=$(jq -r .id <<<"$move_operation")
move_incarnation=$(jq -r .incarnation <<<"$move_operation")
jq -e \
  --arg manifest_sha "$restore_manifest_sha" \
  --arg recovery_sha "$copy_recovery_sha" '
  .kind == "move" and .state == "planned" and .move_state == "copying" and
  .manifest_sha256 == $manifest_sha and .source_recovery_sha256 == $recovery_sha and
  .source_recovery_revision == 2 and .source_driver_id == "restore-driver" and
  .destination_driver_id == "move-driver" and .source_location_count == 1 and
  .minimum_available_replicas == 2 and .grace_seconds == 120
' <<<"$move_operation" >/dev/null

move_lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/operations/$move_id/claim")
move_lease_id=$(jq -r .lease_id <<<"$move_lease")
move_fence=$(jq -r .fencing_token <<<"$move_lease")

move_source=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$move_lease_id" \
    --arg incarnation "$move_incarnation" \
    --argjson fence "$move_fence" \
    '{lease_id: $lease_id, incarnation: $incarnation, fencing_token: $fence}')" \
  "$base_url/api/v1/moves/$move_id/manifest")
[[ "$move_source" == "$copy_recovery" ]]

staged_move=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data-binary "$move_recovery" \
  "$base_url/api/v1/recovery-manifests/stage")
move_recovery_sha=$(jq -r .recovery_sha256 <<<"$staged_move")
move_publication=$(jq -cn \
  --arg operation_id "$move_id" \
  --arg lease_id "$move_lease_id" \
  --arg incarnation "$move_incarnation" \
  --arg manifest_sha "$restore_manifest_sha" \
  --arg recovery_sha "$move_recovery_sha" \
  --arg r2_key "$(jq -r .r2_key <<<"$staged_move")" \
  --arg r2_version "$(jq -r .r2_version <<<"$staged_move")" \
  --argjson fence "$move_fence" '
  {
    operation_id: $operation_id,
    lease_id: $lease_id,
    incarnation: $incarnation,
    fencing_token: $fence,
    manifest_sha256: $manifest_sha,
    recovery_sha256: $recovery_sha,
    r2_key: $r2_key,
    r2_version: $r2_version,
    sidecar_driver_id: "move-driver",
    sidecar_storage_key: "move/recovery-with-source.json"
  }')

published_move=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$move_publication" \
  "$base_url/api/v1/moves/publish-destination")
jq -e \
  --arg move_id "$move_id" \
  --arg recovery_sha "$move_recovery_sha" '
  .operation_id == $move_id and .recovery_sha256 == $recovery_sha and
  .destination_driver_id == "move-driver" and .locations_added == 1 and
  .recovery_revision == 3 and .state == "destination_published"
' <<<"$published_move" >/dev/null

published_move_restore=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn --arg manifest_sha "$restore_manifest_sha" '{
    namespace_id: "202122232425262728292a2b2c2d2e2f",
    manifest_sha256: $manifest_sha,
    idempotency_key: "worker-e2e-restored-move-destination"
  }')" \
  "$base_url/api/v1/restores")
published_move_restore_id=$(jq -r .id <<<"$published_move_restore")
published_move_restore_lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/restores/$published_move_restore_id/claim")
published_move_recovery=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$(jq -r .lease_id <<<"$published_move_restore_lease")" \
    --arg incarnation "$(jq -r .incarnation <<<"$published_move_restore_lease")" \
    --argjson fence "$(jq -r .fencing_token <<<"$published_move_restore_lease")" \
    '{lease_id: $lease_id, incarnation: $incarnation, fencing_token: $fence}')" \
  "$base_url/api/v1/restores/$published_move_restore_id/manifest")
[[ "$published_move_recovery" == "$move_recovery" ]]

staged_move_final=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data-binary "$move_final_recovery" \
  "$base_url/api/v1/recovery-manifests/stage")
move_final_sha=$(jq -r .recovery_sha256 <<<"$staged_move_final")
move_tombstone=$(jq -cn \
  --arg operation_id "$move_id" \
  --arg lease_id "$move_lease_id" \
  --arg incarnation "$move_incarnation" \
  --arg manifest_sha "$restore_manifest_sha" \
  --arg recovery_sha "$move_final_sha" \
  --arg r2_key "$(jq -r .r2_key <<<"$staged_move_final")" \
  --arg r2_version "$(jq -r .r2_version <<<"$staged_move_final")" \
  --argjson fence "$move_fence" '
  {
    operation_id: $operation_id,
    lease_id: $lease_id,
    incarnation: $incarnation,
    fencing_token: $fence,
    manifest_sha256: $manifest_sha,
    recovery_sha256: $recovery_sha,
    r2_key: $r2_key,
    r2_version: $r2_version,
    sidecar_driver_id: "move-driver",
    sidecar_storage_key: "move/recovery-final.json"
  }')
staged_move_underreplicated=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data-binary "$move_underreplicated_recovery" \
  "$base_url/api/v1/recovery-manifests/stage")
underreplicated_move_tombstone=$(jq \
  --arg recovery_sha "$(jq -r .recovery_sha256 <<<"$staged_move_underreplicated")" \
  --arg r2_key "$(jq -r .r2_key <<<"$staged_move_underreplicated")" \
  --arg r2_version "$(jq -r .r2_version <<<"$staged_move_underreplicated")" '
  .recovery_sha256 = $recovery_sha | .r2_key = $r2_key | .r2_version = $r2_version
' <<<"$move_tombstone")
underreplicated_move_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$underreplicated_move_tombstone" \
  "$base_url/api/v1/moves/tombstone-source")
[[ "$underreplicated_move_status" == 400 ]]

stale_move_tombstone=$(jq ".fencing_token = $((move_fence + 1))" <<<"$move_tombstone")
stale_move_tombstone_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$stale_move_tombstone" \
  "$base_url/api/v1/moves/tombstone-source")
[[ "$stale_move_tombstone_status" == 409 ]]

tombstoned_move=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$move_tombstone" \
  "$base_url/api/v1/moves/tombstone-source")
jq -e \
  --arg move_id "$move_id" \
  --arg recovery_sha "$move_final_sha" '
  .operation_id == $move_id and .recovery_sha256 == $recovery_sha and
  .source_driver_id == "restore-driver" and .source_locations_tombstoned == 1 and
  .recovery_revision == 4 and .grace_until > 0 and .state == "source_delete_pending"
' <<<"$tombstoned_move" >/dev/null

replayed_move_tombstone=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$move_tombstone" \
  "$base_url/api/v1/moves/tombstone-source")
[[ "$replayed_move_tombstone" == "$tombstoned_move" ]]

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "UPDATE move_sources SET grace_until = unixepoch() - 1 WHERE operation_id = '$move_id'" \
  >/dev/null

active_read_delete_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/moves/$move_id/deletes/claim")
[[ "$active_read_delete_status" == 409 ]]

for active_restore in copied published_move; do
  if [[ "$active_restore" == copied ]]; then
    active_restore_id=$copied_restore_id
    active_restore_lease=$copied_restore_lease
  else
    active_restore_id=$published_move_restore_id
    active_restore_lease=$published_move_restore_lease
  fi

  curl --silent --show-error --fail-with-body \
    -H "$authorization" -H "$json" \
    --data "$(jq -cn \
      --arg lease_id "$(jq -r .lease_id <<<"$active_restore_lease")" \
      --arg incarnation "$(jq -r .incarnation <<<"$active_restore_lease")" \
      --arg manifest_sha "$restore_manifest_sha" \
      --argjson fence "$(jq -r .fencing_token <<<"$active_restore_lease")" '
      {
        lease_id: $lease_id,
        incarnation: $incarnation,
        fencing_token: $fence,
        manifest_sha256: $manifest_sha,
        plaintext_sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        plaintext_bytes: 2
      }')" \
    "$base_url/api/v1/restores/$active_restore_id/complete" >/dev/null
done

delete_claim=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/moves/$move_id/deletes/claim")
delete_task_id=$(jq -r .task.task_id <<<"$delete_claim")
delete_incarnation=$(jq -r .task.incarnation <<<"$delete_claim")
delete_fence=$(jq -r .task.fencing_token <<<"$delete_claim")
jq -e --arg move_id "$move_id" '
  .state == "claimed" and .task.operation_id == $move_id and
  .task.driver_id == "restore-driver" and .task.storage_key == "restore/payload" and
  .task.expected_location_count == 1 and .task.fencing_token > 0
' <<<"$delete_claim" >/dev/null

failed_delete=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg task_id "$delete_task_id" \
    --arg incarnation "$delete_incarnation" \
    --argjson fence "$delete_fence" '
    {
      task_id: $task_id,
      incarnation: $incarnation,
      fencing_token: $fence,
      error_code: "provider_delete_failed"
    }')" \
  "$base_url/api/v1/moves/deletes/fail")
jq -e '.state == "failed"' <<<"$failed_delete" >/dev/null

delete_claim=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/moves/$move_id/deletes/claim")
delete_task_id=$(jq -r .task.task_id <<<"$delete_claim")
delete_incarnation=$(jq -r .task.incarnation <<<"$delete_claim")
delete_fence=$(jq -r .task.fencing_token <<<"$delete_claim")
jq -e '.task.attempt_count == 2 and .task.state == "claimed"' <<<"$delete_claim" >/dev/null

stale_delete_revalidation=$(jq -cn \
  --arg task_id "$delete_task_id" \
  --arg incarnation "$delete_incarnation" \
  --argjson fence "$((delete_fence + 1))" '
  {task_id: $task_id, incarnation: $incarnation, fencing_token: $fence, lease_seconds: 60}
')
stale_delete_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$stale_delete_revalidation" \
  "$base_url/api/v1/moves/deletes/revalidate")
[[ "$stale_delete_status" == 409 ]]

delete_revalidation=$(jq -cn \
  --arg task_id "$delete_task_id" \
  --arg incarnation "$delete_incarnation" \
  --argjson fence "$delete_fence" '
  {task_id: $task_id, incarnation: $incarnation, fencing_token: $fence, lease_seconds: 60}
')
revalidated_delete=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$delete_revalidation" \
  "$base_url/api/v1/moves/deletes/revalidate")
revalidated_fence=$(jq -r .fencing_token <<<"$revalidated_delete")
[[ "$revalidated_fence" == "$((delete_fence + 1))" ]]

stale_delete_completion_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$delete_revalidation" \
  "$base_url/api/v1/moves/deletes/complete")
[[ "$stale_delete_completion_status" == 409 ]]

delete_completion=$(jq -cn \
  --arg task_id "$delete_task_id" \
  --arg incarnation "$delete_incarnation" \
  --argjson fence "$revalidated_fence" '
  {task_id: $task_id, incarnation: $incarnation, fencing_token: $fence}
')
completed_delete_response=$(curl --silent --show-error --write-out $'\n%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$delete_completion" \
  "$base_url/api/v1/moves/deletes/complete")
completed_delete_status=$(tail -n 1 <<<"$completed_delete_response")
completed_delete=$(sed '$d' <<<"$completed_delete_response")
if [[ "$completed_delete_status" != 200 ]]; then
  echo "$completed_delete" >&2
  exit 1
fi
jq -e --arg move_id "$move_id" '
  .operation_id == $move_id and .locations_deleted == 1 and
  .task_state == "deleted" and .move_state == "succeeded"
' <<<"$completed_delete" >/dev/null

replayed_delete=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$delete_completion" \
  "$base_url/api/v1/moves/deletes/complete")
[[ "$replayed_delete" == "$completed_delete" ]]

finished_delete_claim=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/moves/$move_id/deletes/claim")
jq -e '.state == "succeeded" and .task == null' <<<"$finished_delete_claim" >/dev/null

final_move_restore=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn --arg manifest_sha "$restore_manifest_sha" '{
    namespace_id: "202122232425262728292a2b2c2d2e2f",
    manifest_sha256: $manifest_sha,
    idempotency_key: "worker-e2e-restored-move-final"
  }')" \
  "$base_url/api/v1/restores")
final_move_restore_id=$(jq -r .id <<<"$final_move_restore")
final_move_restore_lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/restores/$final_move_restore_id/claim")
final_move_recovery=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$(jq -cn \
    --arg lease_id "$(jq -r .lease_id <<<"$final_move_restore_lease")" \
    --arg incarnation "$(jq -r .incarnation <<<"$final_move_restore_lease")" \
    --argjson fence "$(jq -r .fencing_token <<<"$final_move_restore_lease")" \
    '{lease_id: $lease_id, incarnation: $incarnation, fencing_token: $fence}')" \
  "$base_url/api/v1/restores/$final_move_restore_id/manifest")
[[ "$final_move_recovery" == "$move_final_recovery" ]]

operation_request='{
  "namespace_id":"202122232425262728292a2b2c2d2e2f",
  "idempotency_key":"worker-e2e-source-v1",
  "useful_bytes_total":1024
}'
operation=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$operation_request" \
  "$base_url/api/v1/operations")
operation_id=$(jq -r .id <<<"$operation")
incarnation=$(jq -r .incarnation <<<"$operation")
jq -e '.root_version == 1 and .key_epoch == 1' <<<"$operation" >/dev/null

lease=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data '{"lease_seconds":60}' \
  "$base_url/api/v1/operations/$operation_id/claim")
lease_id=$(jq -r .lease_id <<<"$lease")
fence=$(jq -r .fencing_token <<<"$lease")

import_key_grant_body=$(jq -cn \
  --arg lease_id "$lease_id" \
  --arg incarnation "$incarnation" \
  --argjson fence "$fence" '
  {
    lease_id: $lease_id,
    incarnation: $incarnation,
    fencing_token: $fence,
    root_version: 1,
    key_epoch: 1
  }')
import_key_grant=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$import_key_grant_body" \
  "$base_url/api/v1/imports/$operation_id/key")
jq -e --arg operation_id "$operation_id" '
  .operation_id == $operation_id and .root_version == 1 and .key_epoch == 1 and
  (.epoch_key | type == "string" and length == 43)
' <<<"$import_key_grant" >/dev/null

wrong_import_key_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$(jq '.key_epoch = 2' <<<"$import_key_grant_body")" \
  "$base_url/api/v1/imports/$operation_id/key")
[[ "$wrong_import_key_status" == 409 ]]

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

staged_wrong_import=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data-binary "$wrong_import_recovery" \
  "$base_url/api/v1/recovery-manifests/stage")
wrong_import_publication=$(jq -cn \
  --arg operation_id "$operation_id" \
  --arg lease_id "$lease_id" \
  --arg incarnation "$incarnation" \
  --arg manifest_sha "$wrong_import_manifest_sha" \
  --arg recovery_sha "$(jq -r .recovery_sha256 <<<"$staged_wrong_import")" \
  --arg r2_key "$(jq -r .r2_key <<<"$staged_wrong_import")" \
  --arg r2_version "$(jq -r .r2_version <<<"$staged_wrong_import")" \
  --argjson fence "$fence" '
  {
    operation_id: $operation_id,
    lease_id: $lease_id,
    incarnation: $incarnation,
    fencing_token: $fence,
    manifest_sha256: $manifest_sha,
    recovery_sha256: $recovery_sha,
    r2_key: $r2_key,
    r2_version: $r2_version,
    sidecar_driver_id: "restore-driver",
    sidecar_storage_key: "import/wrong-sidecar.json",
    expected_object_revision: 1
  }')
wrong_import_publication_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization" -H "$json" \
  --data "$wrong_import_publication" \
  "$base_url/api/v1/imports/publish")
[[ "$wrong_import_publication_status" == 409 ]]

staged_import=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data-binary "$import_recovery" \
  "$base_url/api/v1/recovery-manifests/stage")
import_publication=$(jq -cn \
  --arg operation_id "$operation_id" \
  --arg lease_id "$lease_id" \
  --arg incarnation "$incarnation" \
  --arg manifest_sha "$import_manifest_sha" \
  --arg recovery_sha "$(jq -r .recovery_sha256 <<<"$staged_import")" \
  --arg r2_key "$(jq -r .r2_key <<<"$staged_import")" \
  --arg r2_version "$(jq -r .r2_version <<<"$staged_import")" \
  --argjson fence "$fence" '
  {
    operation_id: $operation_id,
    lease_id: $lease_id,
    incarnation: $incarnation,
    fencing_token: $fence,
    manifest_sha256: $manifest_sha,
    recovery_sha256: $recovery_sha,
    r2_key: $r2_key,
    r2_version: $r2_version,
    sidecar_driver_id: "restore-driver",
    sidecar_storage_key: "import/sidecar.json",
    expected_object_revision: 1
  }')
published_import=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$import_publication" \
  "$base_url/api/v1/imports/publish")
jq -e \
  --arg operation_id "$operation_id" \
  --arg manifest_sha "$import_manifest_sha" '
  .operation_id == $operation_id and .object_id == "import-object" and
  .generation == 1 and .manifest_sha256 == $manifest_sha and .state == "published"
' <<<"$published_import" >/dev/null

replayed_import=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$import_publication" \
  "$base_url/api/v1/imports/publish")
[[ "$replayed_import" == "$published_import" ]]

completed_import_operation=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" \
  --data "$operation_request" \
  "$base_url/api/v1/operations")
jq -e \
  --arg operation_id "$operation_id" \
  --arg manifest_sha "$import_manifest_sha" '
  .id == $operation_id and .state == "succeeded" and
  .published_object_id == "import-object" and .published_generation == 1 and
  .published_manifest_sha256 == $manifest_sha and
  .published_destination_driver_id == "restore-driver" and
  .published_sidecar_storage_key == "import/sidecar.json"
' <<<"$completed_import_operation" >/dev/null
