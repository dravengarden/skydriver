#!/usr/bin/env bash
set -euo pipefail

curl() {
  command curl \
    --header "Carrack-Protocol-Epoch: 2" \
    --header "Carrack-SDK-Version: 0.3.3" \
    "$@"
}

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
  --test-scheduled \
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
rust_target="$state_directory/rust-target"
CARGO_TARGET_DIR="$rust_target" cargo build --quiet --manifest-path "$repository_root/Cargo.toml" \
  --package carrack-cli --bin carrackctl --bin carrack
rust_carrackctl="$rust_target/debug/carrackctl"
rust_carrack="$rust_target/debug/carrack"
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
[[ "$(jq -r '.schema' <<<"$management_snapshot")" == carrack.management.snapshot.v2 ]]
[[ "$(jq -r '.drivers | length' <<<"$management_snapshot")" == 1 ]]
[[ "$(jq -r '.drivers[0].id' <<<"$management_snapshot")" == local-main ]]
[[ "$(jq -r '.drivers[0].config.root' <<<"$management_snapshot")" == "$local_root" ]]
[[ "$(jq -r '.filesystems[0].root_directory_id' <<<"$management_snapshot")" == "$root_directory_id" ]]
[[ "$(jq -r '.tokens[0].id' <<<"$management_snapshot")" == "$token_id" ]]
[[ "$(jq -r '.tokens[0] | has("token")' <<<"$management_snapshot")" == false ]]

cli_acl=$(CARRACK_VFS_TOKEN="$token" "$rust_carrackctl" vfs acl show / \
  --control-url "$base_url" --format json)
[[ "$(jq -r '.schema' <<<"$cli_acl")" == carrack.vfs.acl.v1 ]]
[[ "$(jq -r '.directory_id' <<<"$cli_acl")" == "$root_directory_id" ]]
cli_placements=$(CARRACK_VFS_TOKEN="$token" "$rust_carrackctl" vfs placement show / \
  --control-url "$base_url" --format json)
[[ "$(jq -r '.schema' <<<"$cli_placements")" == carrack.vfs.placements.v1 ]]
[[ "$(jq -r '.placements[0].driver_id' <<<"$cli_placements")" == local-main ]]
child_expiry=$(( $(date +%s) + 3600 ))
issued_child=$(CARRACK_VFS_TOKEN="$token" "$rust_carrackctl" vfs token issue / \
  --control-url "$base_url" --action directory.list,content.read \
  --expires-at "$child_expiry" --idempotency-key bootstrap-child-token-v1 --format json)
child_token_id=$(jq -r '.token_id' <<<"$issued_child")
[[ "$(jq -r '.schema' <<<"$issued_child")" == carrack.vfs.token-issue-receipt.v1 ]]
[[ "$(jq -r '.token | length' <<<"$issued_child")" == 43 ]]
revoked_child=$(CARRACK_VFS_TOKEN="$token" "$rust_carrackctl" vfs token revoke "$child_token_id" \
  --control-url "$base_url" --idempotency-key bootstrap-child-token-revoke-v1 --format json)
[[ "$(jq -r '.schema' <<<"$revoked_child")" == carrack.vfs.token-revoke-receipt.v1 ]]
[[ "$(jq -r '.state' <<<"$revoked_child")" == revoked ]]

cli_management_snapshot=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
	  "$rust_carrackctl" snapshot --control-url "$base_url" --format json)
[[ "$(jq -r '.schema' <<<"$cli_management_snapshot")" == carrack.management.snapshot.v2 ]]
[[ "$(jq -r '.drivers[0].id' <<<"$cli_management_snapshot")" == local-main ]]

management_directory=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/directories/$root_directory_id")
[[ "$(jq -r '.schema' <<<"$management_directory")" == carrack.management.directory.v1 ]]
[[ "$(jq -r '.directory.id' <<<"$management_directory")" == "$root_directory_id" ]]
[[ "$(jq -r '.placements[0]' <<<"$management_directory")" == local-main ]]

cli_management_directory=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
	  "$rust_carrackctl" directory "$root_directory_id" \
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
[[ "$(jq -r --arg token_id "$token_id" \
  '.tokens[] | select(.id == $token_id) | .label' <<<"$annotated_snapshot")" == 'Release agent' ]]
[[ "$(jq -r --arg token_id "$token_id" \
  '.tokens[] | select(.id == $token_id) | .note' <<<"$annotated_snapshot")" == 'Publishes verified releases.' ]]
[[ "$(jq -r --arg token_id "$token_id" \
  '.tokens[] | select(.id == $token_id) | .metadata_revision' <<<"$annotated_snapshot")" == 2 ]]
[[ "$(jq -r '.event_cursor' <<<"$annotated_snapshot")" -gt "$(jq -r '.event_cursor' <<<"$management_snapshot")" ]]

cli_annotation_check=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
	  "$rust_carrackctl" token annotate "$token_id" \
    --control-url "$base_url" \
    --label 'Release automation' \
    --note 'Used by the verified release pipeline.' \
    --expected-revision 2 \
    --check \
    --format json)
[[ "$(jq -r '.schema' <<<"$cli_annotation_check")" == carrack.management.token-annotation-validation.v1 ]]
cli_annotation_receipt=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
	  "$rust_carrackctl" token annotate "$token_id" \
    --control-url "$base_url" \
    --label 'Release automation' \
    --note 'Used by the verified release pipeline.' \
    --expected-revision 2 \
    --idempotency-key annotate-release-agent-v2 \
    --format json)
[[ "$(jq -r '.schema' <<<"$cli_annotation_receipt")" == carrack.management.token-annotation-receipt.v1 ]]
[[ "$(jq -r '.final_revision' <<<"$cli_annotation_receipt")" == 3 ]]

driver_validation=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" \
  --data '{"enabled":false,"expected_revision":1}' \
  "$base_url/api/admin/drivers/local-main/state/validate")
[[ "$(jq -r '.schema' <<<"$driver_validation")" == carrack.management.driver-state-validation.v1 ]]
[[ "$(jq -r '.current_enabled' <<<"$driver_validation")" == true ]]
[[ "$(jq -r '.enabled' <<<"$driver_validation")" == false ]]
[[ "$(jq -r '.placement_count' <<<"$driver_validation")" == 1 ]]
[[ "$(jq -r '.warnings | length > 0' <<<"$driver_validation")" == true ]]
driver_validation_expires_at=$(jq -r '.validation_expires_at' <<<"$driver_validation")
driver_validation_digest=$(jq -r '.validation_digest' <<<"$driver_validation")
driver_apply=$(jq -cn \
  --arg digest "$driver_validation_digest" \
  --argjson expires_at "$driver_validation_expires_at" \
  '{
    enabled: false,
    expected_revision: 1,
    validation_expires_at: $expires_at,
    validation_digest: $digest,
    idempotency_key: "disable-local-main-v1"
  }')
driver_receipt=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$driver_apply" \
  "$base_url/api/admin/drivers/local-main/state/apply")
[[ "$(jq -r '.schema' <<<"$driver_receipt")" == carrack.management.driver-state-receipt.v1 ]]
[[ "$(jq -r '.enabled' <<<"$driver_receipt")" == false ]]
[[ "$(jq -r '.final_revision' <<<"$driver_receipt")" == 2 ]]
driver_replay=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$driver_apply" \
  "$base_url/api/admin/drivers/local-main/state/apply")
[[ "$driver_replay" == "$driver_receipt" ]]
disabled_driver_snapshot=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/snapshot")
[[ "$(jq -r '.drivers[0].enabled' <<<"$disabled_driver_snapshot")" == false ]]
[[ "$(jq -r '.drivers[0].revision' <<<"$disabled_driver_snapshot")" == 2 ]]

cli_driver_check=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
	  "$rust_carrackctl" driver enable local-main \
    --control-url "$base_url" \
    --expected-revision 2 \
    --check \
    --format json)
[[ "$(jq -r '.schema' <<<"$cli_driver_check")" == carrack.management.driver-state-validation.v1 ]]
[[ "$(jq -r '.enabled' <<<"$cli_driver_check")" == true ]]
cli_driver_receipt=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
	  "$rust_carrackctl" driver enable local-main \
    --control-url "$base_url" \
    --expected-revision 2 \
    --idempotency-key enable-local-main-v2 \
    --format json)
[[ "$(jq -r '.schema' <<<"$cli_driver_receipt")" == carrack.management.driver-state-receipt.v1 ]]
[[ "$(jq -r '.enabled' <<<"$cli_driver_receipt")" == true ]]
[[ "$(jq -r '.final_revision' <<<"$cli_driver_receipt")" == 3 ]]
enabled_driver_snapshot=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/snapshot")
[[ "$(jq -r '.drivers[0].enabled' <<<"$enabled_driver_snapshot")" == true ]]
[[ "$(jq -r '.drivers[0].revision' <<<"$enabled_driver_snapshot")" == 3 ]]

aliyun_config="$state_directory/aliyun-driver.json"
jq -cn '{}' >"$aliyun_config"
cli_registration_check=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
	  "$rust_carrackctl" driver register aliyun-main \
    --control-url "$base_url" \
    --kind aliyundrive-open/v2 \
    --config-file "$aliyun_config" \
    --check \
    --format json)
[[ "$(jq -r '.schema' <<<"$cli_registration_check")" == carrack.management.driver-registration-validation.v1 ]]
[[ "$(jq -r '.enabled' <<<"$cli_registration_check")" == false ]]
[[ "$(jq -r '.requires_credential' <<<"$cli_registration_check")" == true ]]
[[ "$(jq -r '.config.drive_type' <<<"$cli_registration_check")" == resource ]]
[[ "$(jq -r '.warnings | length >= 2' <<<"$cli_registration_check")" == true ]]
cli_registration_receipt=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
	  "$rust_carrackctl" driver register aliyun-main \
    --control-url "$base_url" \
    --kind aliyundrive-open/v2 \
    --config-file "$aliyun_config" \
    --idempotency-key register-aliyun-main-v1 \
    --format json)
[[ "$(jq -r '.schema' <<<"$cli_registration_receipt")" == carrack.management.driver-registration-receipt.v1 ]]
[[ "$(jq -r '.enabled' <<<"$cli_registration_receipt")" == false ]]
[[ "$(jq -r '.final_revision' <<<"$cli_registration_receipt")" == 1 ]]
registered_driver_snapshot=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/snapshot")
[[ "$(jq -r '.drivers[] | select(.id == "aliyun-main") | .kind' <<<"$registered_driver_snapshot")" == aliyundrive-open/v2 ]]
[[ "$(jq -r '.drivers[] | select(.id == "aliyun-main") | .enabled' <<<"$registered_driver_snapshot")" == false ]]
[[ "$(jq -r '.drivers[] | select(.id == "aliyun-main") | .credential_present' <<<"$registered_driver_snapshot")" == false ]]

aliyun_credential="$state_directory/aliyun-credential.json"
refresh_token_expires_at=$(( $(date +%s) + 3600 ))
credential_payload=$(printf '{"sub":"test-account","aud":"test-client","exp":%s}' "$refresh_token_expires_at" | base64 -w0 | tr '+/' '-_' | tr -d '=')
protocol_refresh_token="e30.${credential_payload}.cmVmcmVzaA"
jq -cn \
  --arg refresh_token "$protocol_refresh_token" \
  '{refresh_token: $refresh_token,
    refresh_issuer: "openlist-online/v1"}' >"$aliyun_credential"
chmod 600 "$aliyun_credential"
cli_credential_check=$(CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
	  "$rust_carrackctl" driver credential set aliyun-main \
    --control-url "$base_url" \
    --credential-file "$aliyun_credential" \
    --expected-revision 1 \
    --check \
    --format json)
[[ "$(jq -r '.schema' <<<"$cli_credential_check")" == carrack.management.driver-credential-validation.v1 ]]
[[ "$(jq -r '.credential_revision' <<<"$cli_credential_check")" == 1 ]]
[[ "$(jq -r '.refresh_token_expires_at' <<<"$cli_credential_check")" == "$refresh_token_expires_at" ]]
[[ "$cli_credential_check" != *"$protocol_refresh_token"* ]]

registration_replay_validation=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" \
  --data '{"driver_id":"aliyun-replay","kind":"aliyundrive-open/v2","config":{}}' \
  "$base_url/api/admin/drivers/registration/validate")
registration_replay_apply=$(jq -c \
  '{
    driver_id,
    kind,
    config,
    validation_expires_at,
    validation_digest,
    idempotency_key: "register-aliyun-replay-v1"
  }' <<<"$registration_replay_validation")
registration_replay_receipt=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$registration_replay_apply" \
  "$base_url/api/admin/drivers/registration/apply")
registration_replayed=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$registration_replay_apply" \
  "$base_url/api/admin/drivers/registration/apply")
[[ "$registration_replayed" == "$registration_replay_receipt" ]]

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

cli_source="$state_directory/cli-source.bin"
cli_staging="$state_directory/cli-staging"
printf '%s' 'Carrack CLI encrypted complete-object payload' >"$cli_source"

vfs_put=(
  env CARRACK_VFS_TOKEN="$token"
  "$rust_carrack" put "$cli_source" /cli-release.bin
  --control-url "$base_url"
  --preferred-driver-id local-main
  --idempotency-key bootstrap-cli-put-v1
  --staging-directory "$cli_staging"
  --verification-block-bytes 16
  --encryption-frame-bytes 8
  --transfer-part-bytes 7
  --maximum-concurrency 4
  --format json
)

cli_put=$("${vfs_put[@]}")
[[ "$(jq -r '.schema' <<<"$cli_put")" == carrack.fs-put.v1 ]]
[[ "$(jq -r '.receipt.state' <<<"$cli_put")" == committed ]]
[[ "$(jq -r '.receipt.driver_id' <<<"$cli_put")" == local-main ]]
[[ "$(jq -r '.crypto_suite' <<<"$cli_put")" == carrack-vfs-aes256gcm-hkdfsha256-v1 ]]
[[ "$(jq -r '.warnings | length' <<<"$cli_put")" == 0 ]]
[[ -z "$(find "$cli_staging" -mindepth 1 -print -quit)" ]]
[[ -z "$(find "$local_root/.carrack/uploads" -type f -print -quit)" ]]

replayed_cli_put=$("${vfs_put[@]}")
[[ "$(jq -c '.receipt' <<<"$replayed_cli_put")" == "$(jq -c '.receipt' <<<"$cli_put")" ]]

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

cli_download="$state_directory/cli-download.bin"
cli_download_staging="$state_directory/cli-download-staging"
mkdir -p "$cli_download_staging/parts/$cli_version_id"
dd if="$local_root/$cli_storage_key" \
  of="$cli_download_staging/parts/$cli_version_id/0000000000000000.part" \
  bs=5 count=1 status=none
chmod 0444 "$cli_download_staging/parts/$cli_version_id/0000000000000000.part"
cli_get=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" get /cli-release.bin "$cli_download" \
  --control-url "$base_url" \
  --staging-directory "$cli_download_staging" \
  --transfer-part-bytes 5 \
  --maximum-concurrency 4 \
  --format json)
[[ "$(jq -r '.schema' <<<"$cli_get")" == carrack.fs-get.v1 ]]
[[ "$(jq -r '.version_id' <<<"$cli_get")" == "$cli_version_id" ]]
cmp --silent "$cli_source" "$cli_download"
[[ -z "$(find "$cli_download_staging" -mindepth 1 -print -quit)" ]]

sync_destination="$state_directory/synchronized"
sync_state="$state_directory/sync-state"
first_sync=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" sync / "$sync_destination" \
  --control-url "$base_url" --state-directory "$sync_state" \
  --transfer-part-bytes 5 --maximum-concurrency 3 --maximum-file-concurrency 4 \
  --format json)
[[ "$(jq -r '.schema' <<<"$first_sync")" == carrack.fs-sync.v1 ]]
[[ "$(jq -r '.downloaded_files' <<<"$first_sync")" == 1 ]]
cmp --silent "$cli_source" "$sync_destination/cli-release.bin"
second_sync=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" sync / "$sync_destination" \
  --control-url "$base_url" --state-directory "$sync_state" --format json)
[[ "$(jq -r '.reused_files' <<<"$second_sync")" == 1 ]]
[[ "$(jq -r '.downloaded_files' <<<"$second_sync")" == 0 ]]
printf 'corrupt' >"$sync_destination/cli-release.bin"
repaired_sync=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" sync / "$sync_destination" \
  --control-url "$base_url" --state-directory "$sync_state" --format json)
[[ "$(jq -r '.downloaded_files' <<<"$repaired_sync")" == 1 ]]
cmp --silent "$cli_source" "$sync_destination/cli-release.bin"

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
           AND (SELECT COUNT(*) FROM vfs_read_leases
                WHERE version_id = '$cli_version_id' AND completed_at IS NOT NULL) >= 1
           AND (SELECT COUNT(*) FROM vfs_read_leases
                WHERE version_id = '$cli_version_id' AND completed_at IS NULL
                  AND expires_at > unixepoch()) = 0
           AND (SELECT COUNT(*) FROM vfs_directory_entries
                WHERE directory_id = directory.id AND name = 'cli-release.bin'
                  AND version_id = '$cli_version_id') = 1
    FROM vfs_filesystems AS filesystem
    JOIN vfs_principals AS principal ON principal.id = '$principal_id'
    JOIN vfs_directories AS directory ON directory.filesystem_id = filesystem.id
    JOIN vfs_directory_key_epochs AS key_epoch ON key_epoch.directory_id = directory.id
    JOIN vfs_token_verifiers AS token ON token.id = '$token_id'
      AND token.principal_id = principal.id
    JOIN driver_instances AS driver ON driver.id = 'local-main'
    JOIN vfs_directory_drivers AS placement ON placement.driver_id = driver.id
    WHERE filesystem.id = '$filesystem_id';
    INSERT INTO vfs_bootstrap_assertions
    SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);
  " >/dev/null

cli_mkdir=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" mkdir /archive \
  --control-url "$base_url" \
  --idempotency-key bootstrap-cli-mkdir-archive-v1 \
  --format json)
[[ "$(jq -r '.schema' <<<"$cli_mkdir")" == carrack.fs-mkdir.v1 ]]
archive_directory_id=$(jq -r '.directory_id' <<<"$cli_mkdir")

cli_rename=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" rename \
  /cli-release.bin /archive/release.bin \
  --control-url "$base_url" \
  --idempotency-key bootstrap-cli-rename-v1 \
  --format json)
[[ "$(jq -r '.schema' <<<"$cli_rename")" == carrack.vfs.rename-receipt.v1 ]]
[[ "$(jq -r '.destination_directory_id' <<<"$cli_rename")" == "$archive_directory_id" ]]
[[ "$(jq -r '.subject_id' <<<"$cli_rename")" == "$(jq -r '.receipt.file_id' <<<"$cli_put")" ]]
replayed_cli_rename=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" rename \
  /cli-release.bin /archive/release.bin \
  --control-url "$base_url" \
  --idempotency-key bootstrap-cli-rename-v1 \
  --format json)
[[ "$replayed_cli_rename" == "$cli_rename" ]]

moved_download="$state_directory/moved-download.bin"
CARRACK_VFS_TOKEN="$token" "$rust_carrack" get /archive/release.bin "$moved_download" \
  --control-url "$base_url" \
  --staging-directory "$state_directory/moved-download-staging" \
  --format json >/dev/null
cmp --silent "$cli_source" "$moved_download"

same_directory_rename=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" rename \
  /archive/release.bin /archive/final.bin \
  --control-url "$base_url" \
  --idempotency-key bootstrap-cli-rename-v2 \
  --format json)
[[ "$(jq -r '.destination_name' <<<"$same_directory_rename")" == final.bin ]]

CARRACK_VFS_TOKEN="$token" "$rust_carrack" mkdir /archive/nested \
  --control-url "$base_url" \
  --idempotency-key bootstrap-cli-mkdir-nested-v1 \
  --format json >/dev/null
cycle_status=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" rename \
  /archive /archive/nested/cycle \
  --control-url "$base_url" \
  --idempotency-key bootstrap-cli-rename-cycle-v1 \
  --format json >/dev/null 2>&1 && echo 0 || echo 1)
[[ "$cycle_status" == 1 ]]

directory_rename=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" rename /archive /releases \
  --control-url "$base_url" \
  --idempotency-key bootstrap-cli-rename-directory-v1 \
  --format json)
[[ "$(jq -r '.kind' <<<"$directory_rename")" == directory ]]
[[ "$(jq -r '.subject_id' <<<"$directory_rename")" == "$archive_directory_id" ]]

cli_remove=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" remove /releases/final.bin \
  --control-url "$base_url" \
  --idempotency-key bootstrap-cli-remove-v1 \
  --format json)
[[ "$(jq -r '.schema' <<<"$cli_remove")" == carrack.vfs.remove-receipt.v1 ]]
[[ "$(jq -r '.kind' <<<"$cli_remove")" == file ]]
[[ "$(jq -r '.delete_after > .committed_at' <<<"$cli_remove")" == true ]]
replayed_cli_remove=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" remove /releases/final.bin \
  --control-url "$base_url" \
  --idempotency-key bootstrap-cli-remove-v1 \
  --format json)
[[ "$replayed_cli_remove" == "$cli_remove" ]]
[[ -f "$local_root/$cli_storage_key" ]]
removed_list=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" list /releases --control-url "$base_url")
[[ "$(jq '[.entries[] | select(.name == "final.bin")] | length' <<<"$removed_list")" == 0 ]]

CARRACK_VFS_TOKEN="$token" "$rust_carrack" remove /releases/nested \
  --control-url "$base_url" --idempotency-key bootstrap-cli-remove-nested-v1 >/dev/null
CARRACK_VFS_TOKEN="$token" "$rust_carrack" remove /releases \
  --control-url "$base_url" --idempotency-key bootstrap-cli-remove-releases-v1 >/dev/null

# Keep one authorized subtree and one sibling alive in the materialized head.
# A subtree token must receive only its complete Merkle closure, never the
# sibling or the filesystem-root navigation metadata.
projected_directory=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" mkdir /projected \
  --control-url "$base_url" --idempotency-key bootstrap-projected-root-v1 --format json)
projected_directory_id=$(jq -r '.directory_id' <<<"$projected_directory")
projected_nested=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" mkdir /projected/nested \
  --control-url "$base_url" --idempotency-key bootstrap-projected-nested-v1 --format json)
projected_nested_id=$(jq -r '.directory_id' <<<"$projected_nested")
hidden_directory=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" mkdir /hidden \
  --control-url "$base_url" --idempotency-key bootstrap-hidden-sibling-v1 --format json)
hidden_directory_id=$(jq -r '.directory_id' <<<"$hidden_directory")
projected_token_expiry=$(( $(date +%s) + 3600 ))
projected_token_receipt=$(CARRACK_VFS_TOKEN="$token" "$rust_carrackctl" vfs token issue /projected \
  --control-url "$base_url" --action directory.list,content.read \
  --expires-at "$projected_token_expiry" \
  --idempotency-key bootstrap-projected-token-v1 --format json)
projected_token=$(jq -r '.token' <<<"$projected_token_receipt")
[[ "$projected_token" =~ ^[A-Za-z0-9_-]{43}$ ]]
projected_authorization="Authorization: Bearer $projected_token"

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local --persist-to "$state_directory" \
  --command "CREATE TABLE vfs_remove_assertions (
      accepted INTEGER NOT NULL CHECK (accepted = 1)
    ) STRICT;
    INSERT INTO vfs_remove_assertions
    SELECT CASE WHEN
      (SELECT state FROM vfs_files WHERE id = '$(jq -r '.receipt.file_id' <<<"$cli_put")') = 'tombstoned'
      AND (SELECT state FROM vfs_file_versions WHERE id = '$cli_version_id') = 'tombstoned'
      AND (SELECT state FROM vfs_locations WHERE id = '$cli_location_id') = 'tombstoned'
      AND (SELECT delete_after FROM vfs_locations WHERE id = '$cli_location_id') > unixepoch()
    THEN 1 ELSE 0 END;
    DROP TABLE vfs_remove_assertions;" >/dev/null

# Server-owned lifecycle must claim the tombstone itself. An agent-local
# provider cannot be reached by Cloudflare, so the safe outcome is a durable
# blocked task and a retained tombstoned location, never false deletion.
"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local --persist-to "$state_directory" \
  --command "UPDATE vfs_locations
             SET delete_after = unixepoch() - 1, revision = revision + 1,
                 updated_at = unixepoch()
             WHERE id = '$cli_location_id' AND state = 'tombstoned';" >/dev/null
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local --persist-to "$state_directory" \
  --command "CREATE TABLE vfs_catalog_checkpoint_assertions (
      accepted INTEGER NOT NULL CHECK (accepted = 1)
    ) STRICT;
    INSERT INTO vfs_catalog_checkpoint_assertions
    SELECT CASE WHEN
      (SELECT revision_id FROM vfs_catalog_heads
       WHERE filesystem_id = '$filesystem_id') =
      (SELECT revision_id FROM vfs_catalog_mutation_heads
       WHERE filesystem_id = '$filesystem_id')
      AND EXISTS (
        SELECT 1
        FROM vfs_catalog_heads AS head
        JOIN vfs_catalog_revisions AS revision ON revision.id = head.revision_id
        JOIN vfs_catalog_outbox AS outbox ON outbox.revision_id = revision.id
        JOIN vfs_catalog_checkpoint_artifacts AS artifact
          ON artifact.revision_id = revision.id
        WHERE head.filesystem_id = '$filesystem_id'
          AND head.root_data_root = revision.root_data_root
          AND revision.state = 'published'
          AND revision.checkpoint_r2_key = artifact.r2_key
          AND revision.checkpoint_sha256 = artifact.sha256
          AND revision.checkpoint_r2_version = artifact.r2_version
          AND revision.checkpoint_bytes = artifact.bytes
          AND revision.checkpoint_bytes > 0
          AND outbox.state = 'done'
          AND artifact.state = 'published'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM vfs_catalog_outbox AS outbox
        JOIN vfs_catalog_revisions AS revision ON revision.id = outbox.revision_id
        WHERE revision.filesystem_id = '$filesystem_id' AND outbox.state != 'done'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM vfs_catalog_revisions AS revision
        JOIN vfs_catalog_heads AS head ON head.filesystem_id = revision.filesystem_id
        WHERE revision.filesystem_id = '$filesystem_id'
          AND revision.id < head.revision_id
          AND revision.state = 'pending'
          AND NOT EXISTS (
            SELECT 1 FROM vfs_catalog_revision_collapses AS collapse
            WHERE collapse.revision_id = revision.id
              AND collapse.superseded_by_revision_id = head.revision_id
          )
      )
    THEN 1 ELSE 0 END;
    DROP TABLE vfs_catalog_checkpoint_assertions;" >/dev/null

checkpoint_headers="$state_directory/catalog-checkpoint-headers.txt"
checkpoint_body="$state_directory/catalog-checkpoint.json"
curl --silent --show-error --fail-with-body \
  -D "$checkpoint_headers" -H "$authorization" \
  "$base_url/api/v2/catalog/checkpoint" >"$checkpoint_body"
checkpoint_sha256=$(awk '
  tolower($1) == "carrack-catalog-sha256:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$checkpoint_headers")
checkpoint_revision=$(awk '
  tolower($1) == "carrack-catalog-revision:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$checkpoint_headers")
checkpoint_root=$(awk '
  tolower($1) == "carrack-catalog-root:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$checkpoint_headers")
checkpoint_etag=$(awk '
  tolower($1) == "etag:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$checkpoint_headers")
[[ -n "$checkpoint_sha256" ]]
[[ "$checkpoint_etag" == "\"sha256:$checkpoint_sha256\"" ]]
[[ "$(sha256sum "$checkpoint_body" | cut -d' ' -f1)" == "$checkpoint_sha256" ]]
jq --exit-status \
  --arg filesystem_id "$filesystem_id" \
  --arg root_directory_id "$root_directory_id" \
  --arg hidden_directory_id "$hidden_directory_id" \
  --arg revision "$checkpoint_revision" \
  --arg root "$checkpoint_root" \
  '.schema == "carrack.vfs.catalog-checkpoint.v1"
   and .filesystem_id == $filesystem_id
   and .root_directory_id == $root_directory_id
   and (.revision_id | tostring) == $revision
   and .root_data_root == $root
   and ([.directories[].directory_id] | length) > 0
   and any(.directories[]; .directory_id == $hidden_directory_id)' \
  "$checkpoint_body" >/dev/null

unchanged_checkpoint="$state_directory/unchanged-catalog-checkpoint"
unchanged_status=$(curl --silent --show-error \
  --output "$unchanged_checkpoint" --write-out '%{http_code}' \
  -H "$authorization" -H "If-None-Match: $checkpoint_etag" \
  "$base_url/api/v2/catalog/checkpoint")
[[ "$unchanged_status" == 304 ]]
[[ ! -s "$unchanged_checkpoint" ]]

# Seed the native client's authenticated base closure, then mutate one small
# branch. The next server head should publish a strictly smaller hash-linked
# delta and the client must apply it without weakening full-tree verification.
delta_sync_destination="$state_directory/delta-sync"
delta_sync_state="$state_directory/delta-sync-state"
initial_delta_sync=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" sync / \
  "$delta_sync_destination" --control-url "$base_url" \
  --state-directory "$delta_sync_state" --format json)
[[ "$(jq -r '.directories' <<<"$initial_delta_sync")" == 4 ]]
delta_directory=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" mkdir /delta \
  --control-url "$base_url" --idempotency-key bootstrap-delta-directory-v1 --format json)
delta_directory_id=$(jq -r '.directory_id' <<<"$delta_directory")
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local --persist-to "$state_directory" \
  --command "CREATE TABLE vfs_catalog_delta_assertions (
      accepted INTEGER NOT NULL CHECK (accepted = 1)
    ) STRICT;
    INSERT INTO vfs_catalog_delta_assertions
    SELECT CASE WHEN
      EXISTS (
        SELECT 1
        FROM vfs_catalog_heads AS head
        JOIN vfs_catalog_delta_artifacts AS delta
          ON delta.target_revision_id = head.revision_id
        JOIN vfs_catalog_checkpoint_artifacts AS target
          ON target.revision_id = head.revision_id
        WHERE head.filesystem_id = '$filesystem_id'
          AND delta.base_revision_id = $checkpoint_revision
          AND delta.base_root_data_root = '$checkpoint_root'
          AND delta.base_checkpoint_sha256 = '$checkpoint_sha256'
          AND delta.checkpoint_sha256 = target.sha256
          AND delta.bytes < target.bytes
          AND delta.state = 'published'
          AND target.state = 'published'
      )
      AND (SELECT state FROM vfs_catalog_checkpoint_artifacts
           WHERE revision_id = $checkpoint_revision) = 'orphaned'
    THEN 1 ELSE 0 END;
    DROP TABLE vfs_catalog_delta_assertions;" >/dev/null

delta_headers="$state_directory/catalog-delta-headers.txt"
delta_body="$state_directory/catalog-delta.json"
curl --silent --show-error --fail-with-body \
  -D "$delta_headers" -H "$authorization" \
  -H "If-None-Match: $checkpoint_etag" \
  -H 'Carrack-Catalog-Accept-Delta: v1' \
  -H "Carrack-Catalog-Base-Revision: $checkpoint_revision" \
  -H "Carrack-Catalog-Base-Root: $checkpoint_root" \
  -H "Carrack-Catalog-Base-SHA256: $checkpoint_sha256" \
  "$base_url/api/v2/catalog/checkpoint" >"$delta_body"
grep -iq '^content-type: application/vnd.carrack.catalog-delta+json' "$delta_headers"
delta_sha256=$(awk '
  tolower($1) == "carrack-catalog-delta-sha256:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$delta_headers")
delta_checkpoint_sha256=$(awk '
  tolower($1) == "carrack-catalog-sha256:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$delta_headers")
delta_revision=$(awk '
  tolower($1) == "carrack-catalog-revision:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$delta_headers")
delta_root=$(awk '
  tolower($1) == "carrack-catalog-root:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$delta_headers")
delta_etag=$(awk '
  tolower($1) == "etag:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$delta_headers")
[[ "$(sha256sum "$delta_body" | cut -d' ' -f1)" == "$delta_sha256" ]]
[[ "$delta_etag" == "\"sha256:$delta_checkpoint_sha256\"" ]]
jq --exit-status \
  --arg filesystem_id "$filesystem_id" \
  --arg root_directory_id "$root_directory_id" \
  --arg delta_directory_id "$delta_directory_id" \
  --arg base_revision "$checkpoint_revision" \
  --arg base_root "$checkpoint_root" \
  --arg base_sha256 "$checkpoint_sha256" \
  --arg revision "$delta_revision" \
  --arg root "$delta_root" \
  --arg checkpoint_sha256 "$delta_checkpoint_sha256" \
  '.schema == "carrack.vfs.catalog-delta.v1"
   and .filesystem_id == $filesystem_id
   and (.base_revision_id | tostring) == $base_revision
   and .base_root_directory_id == $root_directory_id
   and .base_root_data_root == $base_root
   and .base_checkpoint_sha256 == $base_sha256
   and (.revision_id | tostring) == $revision
   and .root_directory_id == $root_directory_id
   and .root_data_root == $root
   and .checkpoint_sha256 == $checkpoint_sha256
   and (.directories | length) == 2
   and any(.directories[]; .directory_id == $root_directory_id)
   and any(.directories[]; .directory_id == $delta_directory_id)' \
  "$delta_body" >/dev/null

legacy_delta_headers="$state_directory/legacy-delta-headers.txt"
legacy_delta_body="$state_directory/legacy-delta-checkpoint.json"
command curl --silent --show-error --fail-with-body \
  --header "Carrack-Protocol-Epoch: 2" \
  --header "Carrack-SDK-Version: 0.3.1" \
  -D "$legacy_delta_headers" -H "$authorization" \
  -H "If-None-Match: $checkpoint_etag" \
  -H 'Carrack-Catalog-Accept-Delta: v1' \
  -H "Carrack-Catalog-Base-Revision: $checkpoint_revision" \
  -H "Carrack-Catalog-Base-Root: $checkpoint_root" \
  -H "Carrack-Catalog-Base-SHA256: $checkpoint_sha256" \
  "$base_url/api/v2/catalog/checkpoint" >"$legacy_delta_body"
grep -iq '^content-type: application/json' "$legacy_delta_headers"
! grep -iq '^carrack-catalog-delta-sha256:' "$legacy_delta_headers"
legacy_delta_checkpoint_sha256=$(awk '
  tolower($1) == "carrack-catalog-sha256:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$legacy_delta_headers")
[[ "$legacy_delta_checkpoint_sha256" == "$delta_checkpoint_sha256" ]]
[[ "$(sha256sum "$legacy_delta_body" | cut -d' ' -f1)" == "$delta_checkpoint_sha256" ]]

updated_delta_sync=$(CARRACK_VFS_TOKEN="$token" "$rust_carrack" sync / \
  "$delta_sync_destination" --control-url "$base_url" \
  --state-directory "$delta_sync_state" --format json)
[[ "$(jq -r '.directories' <<<"$updated_delta_sync")" == 5 ]]
[[ -d "$delta_sync_destination/delta" ]]

projected_headers="$state_directory/projected-checkpoint-headers.txt"
projected_body="$state_directory/projected-checkpoint.json"
curl --silent --show-error --fail-with-body \
  -D "$projected_headers" -H "$projected_authorization" \
  "$base_url/api/v2/catalog/checkpoint" >"$projected_body"
projected_sha256=$(awk '
  tolower($1) == "carrack-catalog-sha256:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$projected_headers")
projected_revision=$(awk '
  tolower($1) == "carrack-catalog-revision:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$projected_headers")
projected_root=$(awk '
  tolower($1) == "carrack-catalog-root:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$projected_headers")
projected_etag=$(awk '
  tolower($1) == "etag:" {
    gsub("\\r", "", $2);
    print $2
  }
' "$projected_headers")
[[ "$projected_etag" =~ ^\"sha256:[0-9a-f]{64}\"$ ]]
[[ "$projected_etag" != "\"sha256:$projected_sha256\"" ]]
[[ "$(sha256sum "$projected_body" | cut -d' ' -f1)" == "$projected_sha256" ]]
jq --exit-status \
  --arg filesystem_id "$filesystem_id" \
  --arg root_directory_id "$projected_directory_id" \
  --arg nested_directory_id "$projected_nested_id" \
  --arg forbidden_root "$root_directory_id" \
  --arg forbidden_sibling "$hidden_directory_id" \
  --arg revision "$projected_revision" \
  --arg root "$projected_root" \
  '.schema == "carrack.vfs.catalog-checkpoint.v1"
   and .filesystem_id == $filesystem_id
   and .root_directory_id == $root_directory_id
   and (.revision_id | tostring) == $revision
   and .root_data_root == $root
   and (.directories | length) == 2
   and any(.directories[];
     .directory_id == $root_directory_id
     and .parent_directory_id == null
     and .name == "")
   and any(.directories[];
     .directory_id == $nested_directory_id
     and .parent_directory_id == $root_directory_id
     and .name == "nested")
   and all(.directories[];
     .directory_id != $forbidden_root
     and .directory_id != $forbidden_sibling)' \
  "$projected_body" >/dev/null

unchanged_projected="$state_directory/unchanged-projected-checkpoint"
unchanged_projected_status=$(curl --silent --show-error \
  --output "$unchanged_projected" --write-out '%{http_code}' \
  -H "$projected_authorization" -H "If-None-Match: $projected_etag" \
  "$base_url/api/v2/catalog/checkpoint")
[[ "$unchanged_projected_status" == 304 ]]
[[ ! -s "$unchanged_projected" ]]

projected_sync_destination="$state_directory/projected-sync"
projected_sync_state="$state_directory/projected-sync-state"
projected_sync=$(CARRACK_VFS_TOKEN="$projected_token" "$rust_carrack" sync / \
  "$projected_sync_destination" --control-url "$base_url" \
  --state-directory "$projected_sync_state" --format json)
[[ "$(jq -r '.directories' <<<"$projected_sync")" == 2 ]]
[[ "$(jq -r '.files' <<<"$projected_sync")" == 0 ]]

legacy_projected_body="$state_directory/legacy-projected-checkpoint"
legacy_projected_status=$(command curl --silent --show-error \
  --output "$legacy_projected_body" --write-out '%{http_code}' \
  --header "Carrack-Protocol-Epoch: 2" \
  --header "Carrack-SDK-Version: 0.3.0" \
  -H "$projected_authorization" "$base_url/api/v2/catalog/checkpoint")
[[ "$legacy_projected_status" == 204 ]]
[[ ! -s "$legacy_projected_body" ]]

# A newly introduced ACL boundary immediately disables bulk projection. The
# client must use individually authorized revision-pinned directory pages.
"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local --persist-to "$state_directory" \
  --command "UPDATE vfs_directories
             SET acl_inherits = 0, revision = revision + 1,
                 updated_at = MAX(updated_at, unixepoch())
             WHERE id = '$projected_nested_id' AND state = 'active';" >/dev/null
boundary_body="$state_directory/boundary-checkpoint"
boundary_status=$(curl --silent --show-error \
  --output "$boundary_body" --write-out '%{http_code}' \
  -H "$projected_authorization" "$base_url/api/v2/catalog/checkpoint")
[[ "$boundary_status" == 204 ]]
[[ ! -s "$boundary_body" ]]
boundary_sync_status=$(CARRACK_VFS_TOKEN="$projected_token" "$rust_carrack" sync / \
  "$projected_sync_destination" --control-url "$base_url" \
  --state-directory "$projected_sync_state" --format json >/dev/null 2>&1 && echo 0 || echo 1)
[[ "$boundary_sync_status" == 1 ]]

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local --persist-to "$state_directory" \
  --command "CREATE TABLE vfs_server_gc_assertions (
      accepted INTEGER NOT NULL CHECK (accepted = 1)
    ) STRICT;
    INSERT INTO vfs_server_gc_assertions
    SELECT CASE WHEN
      (SELECT state FROM vfs_locations WHERE id = '$cli_location_id') = 'tombstoned'
      AND (SELECT state FROM vfs_location_delete_tasks WHERE id = '$cli_location_id') = 'blocked'
      AND (SELECT last_error_code FROM vfs_location_delete_tasks
           WHERE id = '$cli_location_id') = 'server_cannot_reach_local_driver'
    THEN 1 ELSE 0 END;
    DROP TABLE vfs_server_gc_assertions;" >/dev/null

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "DELETE FROM vfs_acl_grants
             WHERE directory_id = '$root_directory_id' AND action = 'content.write';" >/dev/null

revoked_grant_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -X POST -H "$authorization" "$base_url/api/v2/puts/$intent_id/key-grant")
[[ "$revoked_grant_status" == 403 ]]
