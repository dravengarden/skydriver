#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state_directory=$(mktemp -d)
server_log="$state_directory/wrangler.log"
cookie_jar="$state_directory/cookies.txt"
local_root="$state_directory/provider"
port=${CARRACK_VFS_BOOTSTRAP_TEST_PORT:-8793}
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
    sleep 1
    cat "$server_log" >&2
  fi
}
trap report_error ERR

mkdir -p "$local_root"

wrangler=(
  pnpm exec wrangler
  --config "$repository_root/control-plane/wrangler.jsonc"
)

"${wrangler[@]}" d1 migrations apply CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" >/dev/null

admin_token=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA

"${wrangler[@]}" dev \
  --local \
  --persist-to "$state_directory" \
  --port "$port" \
  --inspector-port 0 \
  --var CARRACK_ROOT_KEY_V1:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA \
  --var CARRACK_VFS_MASTER_KEY_V1:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA \
  --var CARRACK_ADMIN_TOKEN:"$admin_token" \
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
  echo "local VFS bootstrap Worker did not become healthy" >&2
  exit 1
fi

base_url="http://127.0.0.1:$port"
json='Content-Type: application/json'
bootstrap_request=$(jq -cn \
  --arg local_root "$local_root" \
  '{
    filesystem_name: "Carrack VFS",
    principal_display_name: "VFS operator",
    local_driver_id: "local-main",
    local_root: $local_root,
    idempotency_key: "bootstrap-worker-v1"
  }')

unauthenticated_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$json" --data "$bootstrap_request" "$base_url/api/v2/bootstrap")
[[ "$unauthenticated_status" == 401 ]]

curl --silent --show-error --fail-with-body \
  -c "$cookie_jar" -H "$json" \
  --data "$(jq -cn --arg password "$admin_token" '{password: $password}')" \
  "$base_url/api/auth/login" >/dev/null

bootstrap_headers="$state_directory/bootstrap-headers.txt"
bootstrapped=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -D "$bootstrap_headers" -H "$json" \
  --data "$bootstrap_request" "$base_url/api/v2/bootstrap")
grep -iq '^cache-control: no-store, max-age=0' "$bootstrap_headers"
[[ "$(jq -r '.schema' <<<"$bootstrapped")" == carrack.vfs.bootstrap-receipt.v1 ]]
[[ "$(jq -r '.driver_id' <<<"$bootstrapped")" == local-main ]]
[[ "$(jq -r '.crypto_suite' <<<"$bootstrapped")" == carrack-vfs-aes256gcm-hkdfsha256-v1 ]]
[[ "$(jq -r '.key_epoch' <<<"$bootstrapped")" == 1 ]]

filesystem_id=$(jq -r '.filesystem_id' <<<"$bootstrapped")
principal_id=$(jq -r '.principal_id' <<<"$bootstrapped")
root_directory_id=$(jq -r '.root_directory_id' <<<"$bootstrapped")
token_id=$(jq -r '.token_id' <<<"$bootstrapped")
token=$(jq -r '.token' <<<"$bootstrapped")
[[ "$filesystem_id" =~ ^[0-9a-f]{32}$ ]]
[[ "$principal_id" =~ ^[0-9a-f]{32}$ ]]
[[ "$root_directory_id" =~ ^[0-9a-f]{32}$ ]]
[[ "$token_id" =~ ^[0-9a-f]{32}$ ]]
[[ "$token" =~ ^[A-Za-z0-9_-]{43}$ ]]

management_snapshot=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/snapshot")
management_cursor=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/events/cursor")
jq -e '.schema == "carrack.management.event-cursor.v1" and (.event_cursor | type == "number")' \
  <<<"$management_cursor" >/dev/null
jq -e --argjson cursor "$(jq '.event_cursor' <<<"$management_snapshot")" \
  '.event_cursor == $cursor' <<<"$management_cursor" >/dev/null
[[ "$(jq -r '.schema' <<<"$management_snapshot")" == carrack.management.snapshot.v1 ]]
[[ "$(jq -r '.drivers | length' <<<"$management_snapshot")" == 1 ]]
[[ "$(jq -r '.drivers[0].id' <<<"$management_snapshot")" == local-main ]]
[[ "$(jq -r '.drivers[0].config.root' <<<"$management_snapshot")" == "$local_root" ]]
[[ "$(jq -r '.filesystems[0].root_directory_id' <<<"$management_snapshot")" == "$root_directory_id" ]]
[[ "$(jq -r '.tokens[0].id' <<<"$management_snapshot")" == "$token_id" ]]
[[ "$(jq -r '.tokens[0] | has("token")' <<<"$management_snapshot")" == false ]]

cli_management_snapshot=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
  go run ./cmd/carrack admin snapshot --control-url "$base_url" --format json)
[[ "$(jq -r '.schema' <<<"$cli_management_snapshot")" == carrack.management.snapshot.v1 ]]
[[ "$(jq -r '.drivers[0].id' <<<"$cli_management_snapshot")" == local-main ]]

management_directory=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/directories/$root_directory_id")
[[ "$(jq -r '.schema' <<<"$management_directory")" == carrack.management.directory.v1 ]]
[[ "$(jq -r '.directory.id' <<<"$management_directory")" == "$root_directory_id" ]]
[[ "$(jq -r '.placements[0]' <<<"$management_directory")" == local-main ]]

cli_management_directory=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
  go run ./cmd/carrack admin directory "$root_directory_id" \
    --control-url "$base_url" --format json)
[[ "$(jq -r '.directory.id' <<<"$cli_management_directory")" == "$root_directory_id" ]]

configuration_status=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/auth/configuration")
[[ "$(jq -r '.enabled' <<<"$configuration_status")" == false ]]
wrong_configuration_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" -H "$json" \
  --data '{"password":"wrong"}' "$base_url/api/auth/configuration/enable")
[[ "$wrong_configuration_status" == 401 ]]
configuration_enabled=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -c "$cookie_jar" -H "$json" \
  --data "$(jq -cn --arg password "$admin_token" '{password: $password}')" \
  "$base_url/api/auth/configuration/enable")
[[ "$(jq -r '.enabled' <<<"$configuration_enabled")" == true ]]
[[ "$(jq -r '.expires_at > 0' <<<"$configuration_enabled")" == true ]]

annotation_validation=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" \
  --data '{"label":"Release agent","note":"Publishes verified releases.","expected_revision":1}' \
  "$base_url/api/admin/tokens/$token_id/annotation/validate")
[[ "$(jq -r '.schema' <<<"$annotation_validation")" == carrack.management.token-annotation-validation.v1 ]]
[[ "$(jq -r '.label' <<<"$annotation_validation")" == 'Release agent' ]]
validation_expires_at=$(jq -r '.validation_expires_at' <<<"$annotation_validation")
validation_digest=$(jq -r '.validation_digest' <<<"$annotation_validation")
annotation_apply=$(jq -cn \
  --arg digest "$validation_digest" \
  --argjson expires_at "$validation_expires_at" \
  '{
    label: "Release agent",
    note: "Publishes verified releases.",
    expected_revision: 1,
    validation_expires_at: $expires_at,
    validation_digest: $digest,
    idempotency_key: "annotate-release-agent-v1"
  }')
annotation_receipt=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$annotation_apply" \
  "$base_url/api/admin/tokens/$token_id/annotation/apply")
[[ "$(jq -r '.schema' <<<"$annotation_receipt")" == carrack.management.token-annotation-receipt.v1 ]]
[[ "$(jq -r '.final_revision' <<<"$annotation_receipt")" == 2 ]]
annotation_replay=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$annotation_apply" \
  "$base_url/api/admin/tokens/$token_id/annotation/apply")
[[ "$annotation_replay" == "$annotation_receipt" ]]
annotated_snapshot=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/snapshot")
[[ "$(jq -r '.tokens[0].label' <<<"$annotated_snapshot")" == 'Release agent' ]]
[[ "$(jq -r '.tokens[0].note' <<<"$annotated_snapshot")" == 'Publishes verified releases.' ]]
[[ "$(jq -r '.tokens[0].metadata_revision' <<<"$annotated_snapshot")" == 2 ]]
[[ "$(jq -r '.event_cursor' <<<"$annotated_snapshot")" -gt "$(jq -r '.event_cursor' <<<"$management_snapshot")" ]]

cli_annotation_check=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
  go run ./cmd/carrack admin token annotate "$token_id" \
    --control-url "$base_url" \
    --label 'Release automation' \
    --note 'Used by the verified release pipeline.' \
    --expected-revision 2 \
    --check \
    --format json)
[[ "$(jq -r '.schema' <<<"$cli_annotation_check")" == carrack.management.token-annotation-validation.v1 ]]
cli_annotation_receipt=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
  go run ./cmd/carrack admin token annotate "$token_id" \
    --control-url "$base_url" \
    --label 'Release automation' \
    --note 'Used by the verified release pipeline.' \
    --expected-revision 2 \
    --idempotency-key annotate-release-agent-v2 \
    --format json)
[[ "$(jq -r '.schema' <<<"$cli_annotation_receipt")" == carrack.management.token-annotation-receipt.v1 ]]
[[ "$(jq -r '.final_revision' <<<"$cli_annotation_receipt")" == 3 ]]

configuration_disabled=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -c "$cookie_jar" -X POST "$base_url/api/auth/configuration/disable")
[[ "$(jq -r '.enabled' <<<"$configuration_disabled")" == false ]]
disabled_apply_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" -H "$json" --data "$annotation_apply" \
  "$base_url/api/admin/tokens/$token_id/annotation/apply")
[[ "$disabled_apply_status" == 403 ]]

replayed_bootstrap=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$bootstrap_request" \
  "$base_url/api/v2/bootstrap")
[[ "$replayed_bootstrap" == "$bootstrapped" ]]

changed_bootstrap_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" -H "$json" \
  --data "$(jq '.filesystem_name = "Other VFS"' <<<"$bootstrap_request")" \
  "$base_url/api/v2/bootstrap")
[[ "$changed_bootstrap_status" == 409 ]]

authorization="Authorization: Bearer $token"
file_root=d60042cf44d28c3a12f278cffde67620f94f1a3e4c82208102da97b96cd5b4d9
metadata_root=7f8375a6dbb0bbb8aa2a4c5893444ec014588c02e59841088b1064646663bfc7
manifest_sha=ed1c547d98c2889e33ce3bc6effc09f93db562dbb3e4faaed3b7df50fb967f34
manifest_bytes=118
prepare_request=$(jq -cn \
  --arg directory_id "$root_directory_id" \
  --arg file_root "$file_root" \
  --arg metadata_root "$metadata_root" \
  --arg manifest_sha "$manifest_sha" \
  --argjson manifest_bytes "$manifest_bytes" \
  '{
    directory_id: $directory_id,
    entry_name: "bootstrap.bin",
    expected_entry_revision: 0,
    plaintext_bytes: 3,
    verification_block_bytes: 4,
    verification_block_count: 1,
    file_root: $file_root,
    metadata_root: $metadata_root,
    block_manifest_sha256: $manifest_sha,
    block_manifest_bytes: $manifest_bytes,
    encryption_frame_bytes: 4,
    preferred_driver_id: "local-main",
    idempotency_key: "bootstrap-put-v1"
  }')

prepared=$(curl --silent --show-error --fail-with-body \
  -H "$authorization" -H "$json" --data "$prepare_request" \
  "$base_url/api/v2/puts/prepare")
intent_id=$(jq -r '.intent_id' <<<"$prepared")
version_id=$(jq -r '.version_id' <<<"$prepared")
[[ "$(jq -r '.requires_encryption_key' <<<"$prepared")" == true ]]

key_headers="$state_directory/key-headers.txt"
key_grant=$(curl --silent --show-error --fail-with-body \
  -X POST -D "$key_headers" -H "$authorization" \
  "$base_url/api/v2/puts/$intent_id/key-grant")
grep -iq '^cache-control: no-store, max-age=0' "$key_headers"
[[ "$(jq -r '.schema' <<<"$key_grant")" == carrack.vfs.directory-key-grant.v1 ]]
[[ "$(jq -r '.intent_id' <<<"$key_grant")" == "$intent_id" ]]
[[ "$(jq -r '.directory_id' <<<"$key_grant")" == "$root_directory_id" ]]
[[ "$(jq -r '.version_id' <<<"$key_grant")" == "$version_id" ]]
directory_key=$(jq -r '.directory_key' <<<"$key_grant")
[[ "$directory_key" =~ ^[A-Za-z0-9_-]{43}$ ]]

replayed_key_grant=$(curl --silent --show-error --fail-with-body \
  -X POST -H "$authorization" "$base_url/api/v2/puts/$intent_id/key-grant")
[[ "$replayed_key_grant" == "$key_grant" ]]

driver_headers="$state_directory/driver-headers.txt"
driver_grant=$(curl --silent --show-error --fail-with-body \
  -X POST -D "$driver_headers" -H "$authorization" \
  "$base_url/api/v2/puts/$intent_id/driver-grant")
grep -iq '^cache-control: no-store, max-age=0' "$driver_headers"
[[ "$(jq -r '.schema' <<<"$driver_grant")" == carrack.vfs.driver-grant.v1 ]]
[[ "$(jq -r '.driver_id' <<<"$driver_grant")" == local-main ]]
[[ "$(jq -r '.driver_kind' <<<"$driver_grant")" == local-filesystem/v2 ]]
[[ "$(jq -r '.config.root' <<<"$driver_grant")" == "$local_root" ]]
[[ "$(jq -r '.credential' <<<"$driver_grant")" == null ]]

cli_binary="$state_directory/carrack"
cli_source="$state_directory/cli-source.bin"
cli_journals="$state_directory/cli-journals"
cli_staging="$state_directory/cli-staging"
printf '%s' 'Carrack CLI encrypted complete-object payload' >"$cli_source"
go -C "$repository_root" build -o "$cli_binary" ./cmd/carrack

vfs_put=(
  env CARRACK_VFS_TOKEN="$token"
  "$cli_binary" vfs put "$cli_source" cli-release.bin
  --control-url "$base_url"
  --directory-id "$root_directory_id"
  --preferred-driver-id local-main
  --idempotency-key bootstrap-cli-put-v1
  --journal-directory "$cli_journals"
  --staging-directory "$cli_staging"
  --verification-block-bytes 16
  --encryption-frame-bytes 8
  --part-bytes 11
  --format json
)

cli_put=$("${vfs_put[@]}")
[[ "$(jq -r '.schema' <<<"$cli_put")" == carrack.sdk.vfs-put-result.v1 ]]
[[ "$(jq -r '.receipt.state' <<<"$cli_put")" == committed ]]
[[ "$(jq -r '.receipt.driver_id' <<<"$cli_put")" == local-main ]]
[[ "$(jq -r '.crypto_suite' <<<"$cli_put")" == carrack-vfs-aes256gcm-hkdfsha256-v1 ]]
[[ "$(jq -r '.warnings | length' <<<"$cli_put")" == 0 ]]
[[ -z "$(find "$cli_staging" -mindepth 1 -print -quit)" ]]

replayed_cli_put=$("${vfs_put[@]}")
[[ "$(jq -c '.receipt' <<<"$replayed_cli_put")" == "$(jq -c '.receipt' <<<"$cli_put")" ]]
[[ "$(jq -r '.journal_id' <<<"$replayed_cli_put")" != "$(jq -r '.journal_id' <<<"$cli_put")" ]]

cli_version_id=$(jq -r '.receipt.version_id' <<<"$cli_put")
cli_location_id=$(jq -r '.receipt.location_id' <<<"$cli_put")
cli_storage_key=$(jq -r '.receipt.storage_key' <<<"$cli_put")
cli_encoded_bytes=$(jq -r '.receipt.encoded_bytes' <<<"$cli_put")
cli_plaintext_bytes=$(stat --format '%s' "$cli_source")
cli_expected_encoded_bytes=$((cli_plaintext_bytes + ((cli_plaintext_bytes + 7) / 8) * 16))
[[ "$cli_encoded_bytes" == "$cli_expected_encoded_bytes" ]]
[[ -f "$local_root/$cli_storage_key" ]]
[[ "$(stat --format '%s' "$local_root/$cli_storage_key")" == "$cli_encoded_bytes" ]]
if grep --text --fixed-strings --quiet 'Carrack CLI encrypted complete-object payload' \
  "$local_root/$cli_storage_key"; then
  echo "encrypted provider object exposed CLI plaintext" >&2
  exit 1
fi
[[ "$(find "$local_root" -path "$local_root/.carrack" -prune -o -type f -print | wc -l)" == 1 ]]

verifier=$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)
"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "
    CREATE TABLE vfs_bootstrap_assertions (
      accepted INTEGER NOT NULL CHECK (accepted = 1)
    ) STRICT;
    INSERT INTO vfs_bootstrap_assertions
    SELECT filesystem.id = '$filesystem_id'
           AND principal.id = '$principal_id'
           AND directory.id = '$root_directory_id'
           AND directory.crypto_suite = 'carrack-vfs-aes256gcm-hkdfsha256-v1'
           AND key_epoch.envelope_algorithm = 'aes-256-gcm/v1'
           AND key_epoch.master_key_version = 'v1'
           AND length(key_epoch.nonce) = 12
           AND length(key_epoch.ciphertext) = 48
           AND token.id = '$token_id'
           AND token.verifier_sha256 = '$verifier'
           AND token.sealed_at IS NOT NULL
           AND driver.kind = 'local-filesystem/v2'
           AND json_extract(driver.config_json, '$.root') = '$local_root'
           AND placement.directory_id = directory.id
           AND (SELECT COUNT(*) FROM vfs_token_actions WHERE token_id = token.id) = 12
           AND (SELECT COUNT(*) FROM vfs_acl_grants
                WHERE directory_id = directory.id AND principal_id = principal.id) = 12
           AND (SELECT COUNT(*) FROM vfs_bootstrap_receipts) = 1
           AND (SELECT COUNT(*) FROM vfs_audit_events
                WHERE event_kind = 'filesystem_bootstrapped') = 1
           AND (SELECT COUNT(*) FROM vfs_audit_events
                WHERE event_kind = 'directory_key_granted') = 4
           AND (SELECT COUNT(*) FROM vfs_audit_events
                WHERE event_kind = 'driver_granted') = 3
           AND (SELECT COUNT(*) FROM vfs_put_receipts AS receipt
                JOIN vfs_put_intents AS intent ON intent.id = receipt.intent_id
                WHERE intent.version_id = '$cli_version_id') = 1
           AND (SELECT COUNT(*) FROM vfs_file_versions
                WHERE id = '$cli_version_id' AND state = 'published') = 1
           AND (SELECT COUNT(*) FROM vfs_locations
                WHERE id = '$cli_location_id' AND state = 'available'
                  AND storage_key = '$cli_storage_key') = 1
           AND (SELECT COUNT(*) FROM vfs_directory_entries
                WHERE directory_id = directory.id AND name = 'cli-release.bin'
                  AND version_id = '$cli_version_id') = 1
    FROM vfs_filesystems AS filesystem
    JOIN vfs_principals AS principal ON principal.id = '$principal_id'
    JOIN vfs_directories AS directory ON directory.filesystem_id = filesystem.id
    JOIN vfs_directory_key_epochs AS key_epoch ON key_epoch.directory_id = directory.id
    JOIN vfs_token_verifiers AS token ON token.principal_id = principal.id
    JOIN driver_instances AS driver ON driver.id = 'local-main'
    JOIN vfs_directory_drivers AS placement ON placement.driver_id = driver.id
    WHERE filesystem.id = '$filesystem_id';
    INSERT INTO vfs_bootstrap_assertions
    SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);
  " >/dev/null

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "DELETE FROM vfs_acl_grants
             WHERE directory_id = '$root_directory_id' AND action = 'content.write';" >/dev/null

revoked_grant_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -X POST -H "$authorization" "$base_url/api/v2/puts/$intent_id/key-grant")
[[ "$revoked_grant_status" == 403 ]]
