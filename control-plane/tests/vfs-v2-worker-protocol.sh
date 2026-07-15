#!/usr/bin/env bash
set -euo pipefail

curl() {
  command curl \
    --header "Carrack-Protocol-Epoch: 2" \
    --header "Carrack-SDK-Version: 0.3.4" \
    "$@"
}

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state_directory=$(mktemp -d)
server_log="$state_directory/wrangler.log"
port=${CARRACK_VFS_TEST_PORT:-8792}
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

raw_token_1=0123456789abcdef0123456789abcdef
raw_token_2=fedcba9876543210fedcba9876543210
token_1=$(printf '%s' "$raw_token_1" | base64 -w0 | tr '+/' '-_' | tr -d '=')
token_2=$(printf '%s' "$raw_token_2" | base64 -w0 | tr '+/' '-_' | tr -d '=')
verifier_1=$(printf '%s' "$token_1" | sha256sum | cut -d' ' -f1)
verifier_2=$(printf '%s' "$token_2" | sha256sum | cut -d' ' -f1)

filesystem=12000000000000000000000000000001
principal=22000000000000000000000000000001
root=32000000000000000000000000000001
directory=32000000000000000000000000000002
token_id_1=42000000000000000000000000000001
token_id_2=42000000000000000000000000000002
empty_directory_root=9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254
root_before=b5a22ea56c8f95ef505f5f0473a5bb1ca98f1267f438ac8a220b459a15b24d8e
file_root=d60042cf44d28c3a12f278cffde67620f94f1a3e4c82208102da97b96cd5b4d9
metadata_root=7f8375a6dbb0bbb8aa2a4c5893444ec014588c02e59841088b1064646663bfc7
manifest_hex=6361727261636b2e7666732e626c6f636b2d6d616e69666573742e76310000000000000000030000000000000004000000000000000162bedb441eb622eb0eeeefe5b0f69fbe3650d5f441d9341e5d52699f4d05b6c8d60042cf44d28c3a12f278cffde67620f94f1a3e4c82208102da97b96cd5b4d9
manifest_sha=ed1c547d98c2889e33ce3bc6effc09f93db562dbb3e4faaed3b7df50fb967f34
manifest_bytes=$((${#manifest_hex} / 2))
printf '%s' "$manifest_hex" | xxd -r -p >"$state_directory/block-manifest.bin"

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "
    INSERT INTO credential_envelopes (
      id, envelope_algorithm, key_version, nonce, ciphertext, created_at, rotated_at
    ) VALUES ('vfs-worker-credential', 'test/v1', '1', X'01', X'02', 1, 1);
    INSERT INTO driver_instances (
      id, kind, config_json, credential_ref, created_at, updated_at
    ) VALUES (
      'vfs-worker-driver', 'localfs/v2', '{}', 'vfs-worker-credential', 1, 1
    );
    INSERT INTO vfs_filesystems (id, name, created_at, updated_at)
    VALUES ('$filesystem', 'VFS Worker protocol', 1, 1);
    INSERT INTO vfs_principals (
      id, kind, display_name, state, created_at, updated_at
    ) VALUES ('$principal', 'service', 'VFS Worker client', 'active', 1, 1);
    INSERT INTO vfs_directories (
      id, filesystem_id, parent_id, name, data_root, crypto_suite,
      active_key_epoch, acl_inherits, created_at, updated_at
    ) VALUES
      (
        '$root', '$filesystem', NULL, '', '$root_before', 'plaintext/v1',
        1, 0, 1, 1
      ),
      (
        '$directory', '$filesystem', '$root', 'uploads', '$empty_directory_root',
        'plaintext/v1', 1, 1, 1, 1
      );
    INSERT INTO vfs_directory_entries (
      directory_id, name, kind, child_directory_id, size_bytes,
      data_root, created_at, updated_at
    ) VALUES (
      '$root', 'uploads', 'directory', '$directory', 0,
      '$empty_directory_root', 1, 1
    );
    INSERT INTO vfs_directory_drivers (
      directory_id, driver_id, write_priority, created_by, created_at, updated_at
    ) VALUES ('$directory', 'vfs-worker-driver', 0, '$principal', 1, 1);
    INSERT INTO vfs_acl_grants (
      id, directory_id, principal_id, action, source_role, created_by, created_at
    ) VALUES
      (
        '92000000000000000000000000000001', '$root', '$principal',
        'content.write', 'editor', '$principal', unixepoch()
      ),
      (
        '92000000000000000000000000000002', '$root', '$principal',
        'driver.use', 'storage_operator', '$principal', unixepoch()
      ),
      (
        '92000000000000000000000000000003', '$root', '$principal',
        'gc.run', 'storage_operator', '$principal', unixepoch()
      );
    INSERT INTO vfs_token_verifiers (
      id, principal_id, root_directory_id, verifier_sha256, expires_at,
      issued_by, created_at
    ) VALUES
      (
        '$token_id_1', '$principal', '$directory', '$verifier_1',
        unixepoch() + 3600, '$principal', unixepoch()
      ),
      (
        '$token_id_2', '$principal', '$directory', '$verifier_2',
        unixepoch() + 3600, '$principal', unixepoch()
      );
    INSERT INTO vfs_token_actions (token_id, action) VALUES
      ('$token_id_1', 'content.write'),
      ('$token_id_1', 'driver.use'),
      ('$token_id_2', 'content.write'),
      ('$token_id_2', 'driver.use'),
      ('$token_id_2', 'gc.run');
    INSERT INTO vfs_token_drivers (token_id, driver_id) VALUES
      ('$token_id_1', 'vfs-worker-driver'),
      ('$token_id_2', 'vfs-worker-driver');
    UPDATE vfs_token_verifiers SET sealed_at = unixepoch()
    WHERE id IN ('$token_id_1', '$token_id_2');
  " >/dev/null

"${wrangler[@]}" dev \
  --local \
  --persist-to "$state_directory" \
  --port "$port" \
  --inspector-port 0 \
  --var CARRACK_ADMIN_TOKEN:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA \
  --show-interactive-dev-session=false >"$server_log" 2>&1 &
server_pid=$!

for _ in $(seq 1 240); do
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
  echo "local VFS Worker did not become healthy" >&2
  exit 1
fi

wasm_sdk_proof=$(command curl --silent --show-error --fail-with-body \
  "http://127.0.0.1:$port/api/acceptance/wasm-sdk")
[[ "$(jq -r '.schema' <<<"$wasm_sdk_proof")" == carrack.sdk.wasm-acceptance.v1 ]]
[[ "$(jq -r '.sdk_version' <<<"$wasm_sdk_proof")" == 0.3.4 ]]
[[ "$(jq -r '.plaintext_merkle_root' <<<"$wasm_sdk_proof")" == \
  d60042cf44d28c3a12f278cffde67620f94f1a3e4c82208102da97b96cd5b4d9 ]]
[[ "$(jq -r '.decoded_sha256' <<<"$wasm_sdk_proof")" == \
  ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ]]
[[ "$(jq -r '.round_trip_verified' <<<"$wasm_sdk_proof")" == true ]]

base_url="http://127.0.0.1:$port"
authorization_1="Authorization: Bearer $token_1"
authorization_2="Authorization: Bearer $token_2"
json='Content-Type: application/json'

compatibility=$(command curl --silent --show-error --fail-with-body \
  "$base_url/api/compatibility")
[[ "$(jq -r '.schema' <<<"$compatibility")" == carrack.protocol-compatibility.v1 ]]
[[ "$(jq -r '.protocol_epoch' <<<"$compatibility")" == 2 ]]
[[ "$(jq -r '.minimum_sdk_version' <<<"$compatibility")" == 0.3.0 ]]

missing_compatibility=$(command curl --silent --show-error \
  --output "$state_directory/upgrade-required.json" --write-out '%{http_code}' \
  --request POST "$base_url/api/v2/puts/prepare")
[[ "$missing_compatibility" == 426 ]]
jq -e '
  .schema == "carrack.protocol-error.v1" and
  .code == "sdk_upgrade_required" and
  .protocol_epoch == 2 and
  .minimum_sdk_version == "0.3.0"
' "$state_directory/upgrade-required.json" >/dev/null

wrong_epoch=$(command curl --silent --output /dev/null --write-out '%{http_code}' \
  --header 'Carrack-Protocol-Epoch: 1' --header 'Carrack-SDK-Version: 99.0.0' \
  --request POST "$base_url/api/v2/puts/prepare")
[[ "$wrong_epoch" == 426 ]]

old_sdk=$(command curl --silent --output /dev/null --write-out '%{http_code}' \
  --header 'Carrack-Protocol-Epoch: 2' --header 'Carrack-SDK-Version: 0.2.0' \
  --request POST "$base_url/api/v2/puts/prepare")
[[ "$old_sdk" == 426 ]]

prepare_request=$(jq -cn \
  --arg directory_id "$directory" \
  --arg file_root "$file_root" \
  --arg metadata_root "$metadata_root" \
  --arg manifest_sha "$manifest_sha" \
  --argjson manifest_bytes "$manifest_bytes" \
  '{
    directory_id: $directory_id,
    entry_name: "asset.bin",
    expected_entry_revision: 0,
    plaintext_bytes: 3,
    verification_block_bytes: 4,
    verification_block_count: 1,
    file_root: $file_root,
    metadata_root: $metadata_root,
    block_manifest_sha256: $manifest_sha,
    block_manifest_bytes: $manifest_bytes,
    encryption_frame_bytes: 4,
    preferred_driver_id: "vfs-worker-driver",
    idempotency_key: "worker-put-asset-v1"
  }')

unauthenticated_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$json" --data "$prepare_request" "$base_url/api/v2/puts/prepare")
[[ "$unauthenticated_status" == 401 ]]

prepared=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_1" -H "$json" --data "$prepare_request" \
  "$base_url/api/v2/puts/prepare")
[[ "$(jq -r '.schema' <<<"$prepared")" == carrack.vfs.put-preparation.v1 ]]
[[ "$(jq -r '.state' <<<"$prepared")" == prepared ]]
[[ "$(jq -r '.driver_id' <<<"$prepared")" == vfs-worker-driver ]]
[[ "$(jq -r '.storage_key' <<<"$prepared")" != *asset* ]]
intent_id=$(jq -r '.intent_id' <<<"$prepared")
file_id=$(jq -r '.file_id' <<<"$prepared")
version_id=$(jq -r '.version_id' <<<"$prepared")
location_id=$(jq -r '.location_id' <<<"$prepared")
[[ "$intent_id" =~ ^[0-9a-f]{32}$ ]]
[[ "$file_id" =~ ^[0-9a-f]{32}$ ]]
[[ "$version_id" =~ ^[0-9a-f]{32}$ ]]
[[ "$location_id" =~ ^[0-9a-f]{32}$ ]]

replayed_prepare=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_1" -H "$json" --data "$prepare_request" \
  "$base_url/api/v2/puts/prepare")
[[ "$replayed_prepare" == "$prepared" ]]

changed_prepare_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization_1" -H "$json" \
  --data "$(jq '.entry_name = "other.bin"' <<<"$prepare_request")" \
  "$base_url/api/v2/puts/prepare")
[[ "$changed_prepare_status" == 409 ]]

staged=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_1" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$state_directory/block-manifest.bin" \
  "$base_url/api/v2/puts/$intent_id/block-manifest")
[[ "$(jq -r '.schema' <<<"$staged")" == carrack.vfs.block-manifest-stage.v1 ]]
[[ "$(jq -r '.sha256' <<<"$staged")" == "$manifest_sha" ]]
r2_version=$(jq -r '.r2_version' <<<"$staged")

commit_request=$(jq -cn \
  --arg r2_version "$r2_version" \
  '{
    block_manifest_r2_version: $r2_version,
    encoded_bytes: 3,
    encoded_sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    verification_method: "complete_readback",
    native_id: "native-asset-1",
    provider_version: "provider-asset-1",
    etag: "etag-asset-1"
  }')

committed=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$commit_request" \
  "$base_url/api/v2/puts/$intent_id/commit")
[[ "$(jq -r '.schema' <<<"$committed")" == carrack.vfs.put-receipt.v1 ]]
[[ "$(jq -r '.state' <<<"$committed")" == committed ]]
[[ "$(jq -r '.file_id' <<<"$committed")" == "$file_id" ]]
[[ "$(jq -r '.version_id' <<<"$committed")" == "$version_id" ]]
[[ "$(jq -r '.location_id' <<<"$committed")" == "$location_id" ]]
[[ "$(jq -r '.entry_revision' <<<"$committed")" == 1 ]]

replayed_commit=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$commit_request" \
  "$base_url/api/v2/puts/$intent_id/commit")
[[ "$replayed_commit" == "$committed" ]]

changed_commit_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization_2" -H "$json" \
  --data "$(jq '.provider_version = "provider-asset-2"' <<<"$commit_request")" \
  "$base_url/api/v2/puts/$intent_id/commit")
[[ "$changed_commit_status" == 409 ]]

overwrite_prepare_request=$(jq \
  '.expected_entry_revision = 1 | .idempotency_key = "worker-put-asset-v2"' \
  <<<"$prepare_request")
overwrite_prepared=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$overwrite_prepare_request" \
  "$base_url/api/v2/puts/prepare")
overwrite_intent=$(jq -r '.intent_id' <<<"$overwrite_prepared")
overwrite_file=$(jq -r '.file_id' <<<"$overwrite_prepared")
overwrite_version=$(jq -r '.version_id' <<<"$overwrite_prepared")
[[ "$overwrite_file" == "$file_id" ]]
[[ "$overwrite_version" != "$version_id" ]]
overwrite_staged=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$state_directory/block-manifest.bin" \
  "$base_url/api/v2/puts/$overwrite_intent/block-manifest")
overwrite_r2_version=$(jq -r '.r2_version' <<<"$overwrite_staged")
overwrite_commit_request=$(jq \
  --arg version "$overwrite_r2_version" \
  '.block_manifest_r2_version = $version
   | .native_id = "native-asset-2"
   | .provider_version = "provider-asset-2"
   | .etag = "etag-asset-2"' <<<"$commit_request")
overwrite_committed=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$overwrite_commit_request" \
  "$base_url/api/v2/puts/$overwrite_intent/commit")
[[ "$(jq -r '.file_id' <<<"$overwrite_committed")" == "$file_id" ]]
[[ "$(jq -r '.version_id' <<<"$overwrite_committed")" == "$overwrite_version" ]]
[[ "$(jq -r '.entry_revision' <<<"$overwrite_committed")" == 2 ]]
[[ "$(jq -r '.catalog_revision_id' <<<"$overwrite_committed")" -gt \
  "$(jq -r '.catalog_revision_id' <<<"$committed")" ]]

second_prepare_request=$(jq \
  '.entry_name = "revoked.bin" | .idempotency_key = "worker-put-revoked-v1"' \
  <<<"$prepare_request")
second_prepared=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$second_prepare_request" \
  "$base_url/api/v2/puts/prepare")
second_intent=$(jq -r '.intent_id' <<<"$second_prepared")
second_staged=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$state_directory/block-manifest.bin" \
  "$base_url/api/v2/puts/$second_intent/block-manifest")
second_r2_version=$(jq -r '.r2_version' <<<"$second_staged")

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "DELETE FROM vfs_acl_grants
             WHERE directory_id = '$root' AND action = 'content.write';" >/dev/null

revoked_commit_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization_2" -H "$json" \
  --data "$(jq --arg version "$second_r2_version" '.block_manifest_r2_version = $version' \
    <<<"$commit_request")" \
  "$base_url/api/v2/puts/$second_intent/commit")
[[ "$revoked_commit_status" == 403 ]]

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "
    CREATE TABLE vfs_worker_assertions (
      accepted INTEGER NOT NULL CHECK (accepted = 1)
    ) STRICT;
    INSERT INTO vfs_worker_assertions
    SELECT intent.state = 'committed'
           AND receipt.token_id = '$token_id_2'
           AND evidence.token_id = '$token_id_2'
           AND evidence.commit_sha256 = receipt.commit_sha256
           AND receipt.entry_revision = 1
           AND version.state = 'published'
           AND location.state = 'available'
           AND outbox.state = 'pending'
    FROM vfs_put_intents AS intent
    JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = intent.id
    JOIN vfs_put_receipts AS receipt ON receipt.intent_id = intent.id
    JOIN vfs_file_versions AS version ON version.id = intent.version_id
    JOIN vfs_locations AS location ON location.id = intent.location_id
    JOIN vfs_catalog_outbox AS outbox
      ON outbox.revision_id = receipt.catalog_revision_id
    WHERE intent.id = '$intent_id';
    INSERT INTO vfs_worker_assertions
    SELECT intent.state = 'committed'
           AND receipt.entry_revision = 2
           AND evidence.commit_sha256 = receipt.commit_sha256
           AND file.id = '$file_id'
           AND file.current_version_id = '$overwrite_version'
           AND file.revision = 2
           AND entry.version_id = '$overwrite_version'
           AND entry.revision = 2
           AND catalog.parent_revision_id = previous.catalog_revision_id
           AND head.revision_id = catalog.id
           AND head.revision = 2
    FROM vfs_put_intents AS intent
    JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = intent.id
    JOIN vfs_put_receipts AS receipt ON receipt.intent_id = intent.id
    JOIN vfs_files AS file ON file.id = intent.file_id
    JOIN vfs_directory_entries AS entry
      ON entry.directory_id = intent.directory_id AND entry.name = intent.entry_name
    JOIN vfs_catalog_revisions AS catalog ON catalog.id = receipt.catalog_revision_id
    JOIN vfs_catalog_mutation_heads AS head ON head.filesystem_id = intent.filesystem_id
    JOIN vfs_put_receipts AS previous ON previous.intent_id = '$intent_id'
    WHERE intent.id = '$overwrite_intent';
    INSERT INTO vfs_worker_assertions
    SELECT state = 'prepared' FROM vfs_put_intents WHERE id = '$second_intent';
    INSERT INTO vfs_worker_assertions
    SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);
  " >/dev/null

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "INSERT INTO vfs_acl_grants (
               id, directory_id, principal_id, action, source_role, created_by, created_at
             ) VALUES (
               '92000000000000000000000000000009', '$root', '$principal',
               'content.write', 'editor', '$principal', unixepoch()
             );" >/dev/null

race_request_a=$(jq \
  '.entry_name = "race.bin" | .idempotency_key = "worker-put-race-a"' \
  <<<"$prepare_request")
race_request_b=$(jq \
  '.entry_name = "race.bin" | .idempotency_key = "worker-put-race-b"' \
  <<<"$prepare_request")
race_prepared_a=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$race_request_a" \
  "$base_url/api/v2/puts/prepare")
race_prepared_b=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$race_request_b" \
  "$base_url/api/v2/puts/prepare")
race_intent_a=$(jq -r '.intent_id' <<<"$race_prepared_a")
race_intent_b=$(jq -r '.intent_id' <<<"$race_prepared_b")
race_staged_a=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$state_directory/block-manifest.bin" \
  "$base_url/api/v2/puts/$race_intent_a/block-manifest")
race_staged_b=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$state_directory/block-manifest.bin" \
  "$base_url/api/v2/puts/$race_intent_b/block-manifest")
race_commit_a=$(jq \
  --arg version "$(jq -r '.r2_version' <<<"$race_staged_a")" \
  '.block_manifest_r2_version = $version
   | .native_id = "native-race-a"
   | .provider_version = "provider-race-a"
   | .etag = "etag-race-a"' <<<"$commit_request")
race_commit_b=$(jq \
  --arg version "$(jq -r '.r2_version' <<<"$race_staged_b")" \
  '.block_manifest_r2_version = $version
   | .native_id = "native-race-b"
   | .provider_version = "provider-race-b"
   | .etag = "etag-race-b"' <<<"$commit_request")
curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$race_commit_a" \
  "$base_url/api/v2/puts/$race_intent_a/commit" >/dev/null
race_conflict_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization_2" -H "$json" --data "$race_commit_b" \
  "$base_url/api/v2/puts/$race_intent_b/commit")
[[ "$race_conflict_status" == 409 ]]

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "INSERT INTO vfs_worker_assertions
             SELECT intent.state = 'prepared'
                    AND evidence.native_id = 'native-race-b'
                    AND evidence.provider_version = 'provider-race-b'
                    AND evidence.etag = 'etag-race-b'
                    AND NOT EXISTS (
                      SELECT 1 FROM vfs_put_receipts WHERE intent_id = intent.id
                    )
             FROM vfs_put_intents AS intent
             JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = intent.id
             WHERE intent.id = '$race_intent_b';" >/dev/null

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "
    UPDATE driver_instances SET credential_ref = NULL
    WHERE id = 'vfs-worker-driver';
    UPDATE vfs_put_intents
    SET state = 'expired', revision = revision + 1
    WHERE id = '$race_intent_b';
    INSERT INTO vfs_put_delete_tasks (
      id, driver_revision, evidence_sha256, delete_after, created_at, updated_at
    )
    SELECT intent.id, driver.revision, evidence.commit_sha256,
           unixepoch() - 1, unixepoch(), unixepoch()
    FROM vfs_put_intents AS intent
    JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = intent.id
    JOIN driver_instances AS driver ON driver.id = intent.driver_id
    WHERE intent.id = '$race_intent_b';
  " >/dev/null

unauthorized_claim=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_1" -H "$json" --data '{"lease_seconds":60}' \
  "$base_url/api/v2/put-deletes/claim")
[[ "$(jq -r '.state' <<<"$unauthorized_claim")" == idle ]]

claimed=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data '{"lease_seconds":60}' \
  "$base_url/api/v2/put-deletes/claim")
[[ "$(jq -r '.state' <<<"$claimed")" == claimed ]]
[[ "$(jq -r '.task.task_id' <<<"$claimed")" == "$race_intent_b" ]]
[[ "$(jq -r '.task.schema' <<<"$claimed")" == carrack.vfs.put-delete-task.v1 ]]
claim_incarnation=$(jq -r '.task.incarnation' <<<"$claimed")
claim_fence=$(jq -r '.task.fencing_token' <<<"$claimed")

driver_grant=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data '{}' \
  "$base_url/api/v2/put-deletes/$race_intent_b/driver-grant")
[[ "$(jq -r '.schema' <<<"$driver_grant")" == carrack.vfs.put-delete-driver-grant.v1 ]]
[[ "$(jq -r '.task_id' <<<"$driver_grant")" == "$race_intent_b" ]]
[[ "$(jq -r '.driver_revision' <<<"$driver_grant")" == 1 ]]

fail_request=$(jq -cn --arg incarnation "$claim_incarnation" --argjson fence "$claim_fence" \
  '{incarnation:$incarnation,fencing_token:$fence,error_code:"test_retry"}')
failed=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$fail_request" \
  "$base_url/api/v2/put-deletes/$race_intent_b/fail")
[[ "$(jq -r '.state' <<<"$failed")" == failed ]]

reclaimed=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data '{"lease_seconds":60}' \
  "$base_url/api/v2/put-deletes/claim")
reclaim_incarnation=$(jq -r '.task.incarnation' <<<"$reclaimed")
reclaim_fence=$(jq -r '.task.fencing_token' <<<"$reclaimed")
[[ "$reclaim_fence" -gt "$claim_fence" ]]

premature_completion=$(jq -cn \
  --arg incarnation "$reclaim_incarnation" --argjson fence "$reclaim_fence" \
  '{incarnation:$incarnation,fencing_token:$fence,outcome:"deleted"}')
premature_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization_2" -H "$json" --data "$premature_completion" \
  "$base_url/api/v2/put-deletes/$race_intent_b/complete")
[[ "$premature_status" == 409 ]]

revalidate_request=$(jq -cn \
  --arg incarnation "$reclaim_incarnation" --argjson fence "$reclaim_fence" \
  '{incarnation:$incarnation,fencing_token:$fence,lease_seconds:60}')
revalidated=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$revalidate_request" \
  "$base_url/api/v2/put-deletes/$race_intent_b/revalidate")
revalidated_fence=$(jq -r '.fencing_token' <<<"$revalidated")
[[ "$revalidated_fence" -eq $((reclaim_fence + 1)) ]]

stale_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$authorization_2" -H "$json" --data "$premature_completion" \
  "$base_url/api/v2/put-deletes/$race_intent_b/complete")
[[ "$stale_status" == 409 ]]

completion_request=$(jq -cn \
  --arg incarnation "$reclaim_incarnation" --argjson fence "$revalidated_fence" \
  '{incarnation:$incarnation,fencing_token:$fence,outcome:"deleted"}')
completed=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$completion_request" \
  "$base_url/api/v2/put-deletes/$race_intent_b/complete")
[[ "$(jq -r '.state' <<<"$completed")" == deleted ]]
[[ "$(jq -r '.completion_outcome' <<<"$completed")" == deleted ]]

replayed_completion=$(curl --silent --show-error --fail-with-body \
  -H "$authorization_2" -H "$json" --data "$completion_request" \
  "$base_url/api/v2/put-deletes/$race_intent_b/complete")
[[ "$replayed_completion" == "$completed" ]]
