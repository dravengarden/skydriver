#!/usr/bin/env bash
set -euo pipefail

curl() {
  command curl \
    --header "Carrack-Protocol-Epoch: 2" \
    --header "Carrack-SDK-Version: 0.3.0" \
    "$@"
}

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state_directory=$(mktemp -d)
server_log="$state_directory/wrangler.log"
cookie_jar="$state_directory/cookies.txt"
local_root="$state_directory/provider"
port=${CARRACK_VFS_MANAGEMENT_TEST_PORT:-8794}
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

base_url="http://127.0.0.1:$port"
json='Content-Type: application/json'

old_admin_sdk=$(command curl --silent --output /dev/null --write-out '%{http_code}' \
  --header 'Carrack-Protocol-Epoch: 2' --header 'Carrack-SDK-Version: 0.1.0' \
  "$base_url/api/admin/snapshot")
[[ "$old_admin_sdk" == 426 ]]

curl --silent --show-error --fail-with-body \
  -c "$cookie_jar" -H "$json" \
  --data "$(jq -cn --arg password "$admin_token" '{password: $password}')" \
  "$base_url/api/auth/login" >/dev/null

bootstrap_request=$(jq -cn \
  --arg local_root "$local_root" \
  '{
    filesystem_name: "Carrack management test",
    principal_display_name: "VFS management operator",
    local_driver_id: "local-main",
    local_root: $local_root,
    idempotency_key: "management-bootstrap-v1"
  }')
bootstrapped=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$bootstrap_request" \
  "$base_url/api/v2/bootstrap")

filesystem_id=$(jq -r '.filesystem_id' <<<"$bootstrapped")
principal_id=$(jq -r '.principal_id' <<<"$bootstrapped")
root_directory_id=$(jq -r '.root_directory_id' <<<"$bootstrapped")
root_token=$(jq -r '.token' <<<"$bootstrapped")
root_authorization="Authorization: Bearer $root_token"

vfs_session=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" "$base_url/api/v2/session")
[[ "$(jq -r '.schema' <<<"$vfs_session")" == carrack.vfs.session.v1 ]]
[[ "$(jq -r '.root_directory_id' <<<"$vfs_session")" == "$root_directory_id" ]]
expires_at=$(($(date +%s) + 3600))

unauthenticated_list_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "$base_url/api/v2/directories/$root_directory_id/entries")
[[ "$unauthenticated_list_status" == 401 ]]

directory_headers="$state_directory/directory-headers.txt"
directory_page=$(curl --silent --show-error --fail-with-body \
  -D "$directory_headers" -H "$root_authorization" \
  "$base_url/api/v2/directories/$root_directory_id/entries?limit=1")
grep -iq '^cache-control: no-store, max-age=0' "$directory_headers"
[[ "$(jq -r '.schema' <<<"$directory_page")" == carrack.vfs.directory-list.v1 ]]
[[ "$(jq -r '.directory.id' <<<"$directory_page")" == "$root_directory_id" ]]
[[ "$(jq -r '.directory.filesystem_id' <<<"$directory_page")" == "$filesystem_id" ]]
[[ "$(jq -r '.entries | length' <<<"$directory_page")" == 0 ]]
initial_root=$(jq -r '.directory.data_root' <<<"$directory_page")

mkdir_request='{
  "name":"releases",
  "idempotency_key":"mkdir-releases-v1"
}'
mkdir_headers="$state_directory/mkdir-headers.txt"
created_directory=$(curl --silent --show-error --fail-with-body \
  -D "$mkdir_headers" -H "$root_authorization" -H "$json" \
  --data "$mkdir_request" \
  "$base_url/api/v2/directories/$root_directory_id/children")
grep -iq '^cache-control: no-store, max-age=0' "$mkdir_headers"
[[ "$(jq -r '.schema' <<<"$created_directory")" == carrack.vfs.directory-create-receipt.v1 ]]
[[ "$(jq -r '.parent_directory_id' <<<"$created_directory")" == "$root_directory_id" ]]
[[ "$(jq -r '.name' <<<"$created_directory")" == releases ]]
[[ "$(jq -r '.crypto_suite' <<<"$created_directory")" == carrack-vfs-aes256gcm-hkdfsha256-v1 ]]
created_directory_id=$(jq -r '.directory_id' <<<"$created_directory")
created_directory_root=$(jq -r '.data_root' <<<"$created_directory")

replayed_mkdir=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$mkdir_request" \
  "$base_url/api/v2/directories/$root_directory_id/children")
[[ "$replayed_mkdir" == "$created_directory" ]]

changed_mkdir_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$root_authorization" -H "$json" \
  --data '{"name":"other","idempotency_key":"mkdir-releases-v1"}' \
  "$base_url/api/v2/directories/$root_directory_id/children")
[[ "$changed_mkdir_status" == 409 ]]

duplicate_mkdir_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$root_authorization" -H "$json" \
  --data '{"name":"releases","idempotency_key":"mkdir-releases-duplicate-v1"}' \
  "$base_url/api/v2/directories/$root_directory_id/children")
[[ "$duplicate_mkdir_status" == 409 ]]

root_after_mkdir=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" \
  "$base_url/api/v2/directories/$root_directory_id/entries")
[[ "$(jq -r '.entries | length' <<<"$root_after_mkdir")" == 1 ]]
[[ "$(jq -r '.entries[0].name' <<<"$root_after_mkdir")" == releases ]]
[[ "$(jq -r '.entries[0].child_directory_id' <<<"$root_after_mkdir")" == "$created_directory_id" ]]
[[ "$(jq -r '.entries[0].data_root' <<<"$root_after_mkdir")" == "$created_directory_root" ]]
[[ "$(jq -r '.directory.data_root' <<<"$root_after_mkdir")" != "$initial_root" ]]

acl=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" \
  "$base_url/api/v2/directories/$created_directory_id/acl")
[[ "$(jq -r '.schema' <<<"$acl")" == carrack.vfs.acl.v1 ]]
acl_revision=$(jq -r '.acl_revision' <<<"$acl")
acl_replace_request=$(jq -cn \
  --arg principal_id "$principal_id" \
  --argjson expected "$acl_revision" \
  '{
    principal_id: $principal_id,
    role: "viewer",
    expected_acl_revision: $expected,
    idempotency_key: "acl-viewer-v1"
  }')
acl_replaced=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$acl_replace_request" \
  "$base_url/api/v2/directories/$created_directory_id/acl/replace")
[[ "$(jq -r '.kind' <<<"$acl_replaced")" == acl.replace ]]
[[ "$(jq -c '.policy.actions' <<<"$acl_replaced")" == '["content.read","directory.list"]' ]]
replayed_acl=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$acl_replace_request" \
  "$base_url/api/v2/directories/$created_directory_id/acl/replace")
[[ "$replayed_acl" == "$acl_replaced" ]]

acl_after=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" \
  "$base_url/api/v2/directories/$created_directory_id/acl")
[[ "$(jq -r '.grants | length' <<<"$acl_after")" == 2 ]]
[[ "$(jq -r '.grants | all(.source_role == "viewer")' <<<"$acl_after")" == true ]]

placements=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" \
  "$base_url/api/v2/directories/$created_directory_id/placements")
[[ "$(jq -r '.schema' <<<"$placements")" == carrack.vfs.placements.v1 ]]
placement_revision=$(jq -r '.placement_revision' <<<"$placements")
placement_replace_request=$(jq -cn \
  --argjson expected "$placement_revision" \
  '{
    placements: [{driver_id: "local-main", write_priority: 0}],
    expected_placement_revision: $expected,
    idempotency_key: "placement-local-v1"
  }')
placement_replaced=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$placement_replace_request" \
  "$base_url/api/v2/directories/$created_directory_id/placements/replace")
[[ "$(jq -r '.kind' <<<"$placement_replaced")" == placement.replace ]]
replayed_placement=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$placement_replace_request" \
  "$base_url/api/v2/directories/$created_directory_id/placements/replace")
[[ "$replayed_placement" == "$placement_replaced" ]]

stale_placement_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$root_authorization" -H "$json" \
  --data "$(jq '.idempotency_key = "placement-stale-v1"' <<<"$placement_replace_request")" \
  "$base_url/api/v2/directories/$created_directory_id/placements/replace")
[[ "$stale_placement_status" == 409 ]]

issue_request=$(jq -cn \
  --arg root "$created_directory_id" \
  --argjson expires_at "$expires_at" \
  '{
    root_directory_id: $root,
    actions: ["directory.list", "content.read", "directory.list"],
    driver_ids: ["local-main"],
    expires_at: $expires_at,
    idempotency_key: "reader-child-v1"
  }')
issue_headers="$state_directory/issue-headers.txt"
issued=$(curl --silent --show-error --fail-with-body \
  -D "$issue_headers" -H "$root_authorization" -H "$json" \
  --data "$issue_request" "$base_url/api/v2/tokens")
grep -iq '^cache-control: no-store, max-age=0' "$issue_headers"
[[ "$(jq -r '.schema' <<<"$issued")" == carrack.vfs.token-issue-receipt.v1 ]]
[[ "$(jq -c '.actions' <<<"$issued")" == '["content.read","directory.list"]' ]]
[[ "$(jq -c '.driver_ids' <<<"$issued")" == '["local-main"]' ]]
child_token_id=$(jq -r '.token_id' <<<"$issued")
child_token=$(jq -r '.token' <<<"$issued")
[[ "$child_token_id" =~ ^[0-9a-f]{32}$ ]]
[[ "$child_token" =~ ^[A-Za-z0-9_-]{43}$ ]]
[[ "$child_token" != "$root_token" ]]

replayed_issue=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$issue_request" \
  "$base_url/api/v2/tokens")
[[ "$replayed_issue" == "$issued" ]]

changed_issue_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$root_authorization" -H "$json" \
  --data "$(jq '.actions = ["directory.list"]' <<<"$issue_request")" \
  "$base_url/api/v2/tokens")
[[ "$changed_issue_status" == 409 ]]

child_authorization="Authorization: Bearer $child_token"
curl --silent --show-error --fail-with-body \
  -H "$child_authorization" \
  "$base_url/api/v2/directories/$created_directory_id/entries" >/dev/null

child_parent_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$child_authorization" \
  "$base_url/api/v2/directories/$root_directory_id/entries")
[[ "$child_parent_status" == 403 ]]

child_issue_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$child_authorization" -H "$json" --data "$issue_request" \
  "$base_url/api/v2/tokens")
[[ "$child_issue_status" == 403 ]]

delegate_request=$(jq -cn \
  --arg root "$root_directory_id" \
  --argjson expires_at "$expires_at" \
  '{
    root_directory_id: $root,
    actions: ["directory.list", "token.issue"],
    driver_ids: ["local-main"],
    expires_at: $expires_at,
    idempotency_key: "delegating-child-v1"
  }')
delegate=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$delegate_request" \
  "$base_url/api/v2/tokens")
delegate_token_id=$(jq -r '.token_id' <<<"$delegate")
delegate_token=$(jq -r '.token' <<<"$delegate")
delegate_authorization="Authorization: Bearer $delegate_token"

widened_driver_request=$(jq -cn \
  --arg root "$root_directory_id" \
  --argjson expires_at "$expires_at" \
  '{
    root_directory_id: $root,
    actions: ["directory.list"],
    expires_at: $expires_at,
    idempotency_key: "widen-driver-v1"
  }')
widened_driver_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$delegate_authorization" -H "$json" --data "$widened_driver_request" \
  "$base_url/api/v2/tokens")
[[ "$widened_driver_status" == 400 ]]

grandchild_request=$(jq -cn \
  --arg root "$root_directory_id" \
  --argjson expires_at "$expires_at" \
  '{
    root_directory_id: $root,
    actions: ["directory.list"],
    driver_ids: ["local-main"],
    expires_at: $expires_at,
    idempotency_key: "grandchild-v1"
  }')
grandchild=$(curl --silent --show-error --fail-with-body \
  -H "$delegate_authorization" -H "$json" --data "$grandchild_request" \
  "$base_url/api/v2/tokens")
grandchild_token=$(jq -r '.token' <<<"$grandchild")

rust_target="$state_directory/rust-target"
cargo build --quiet --manifest-path "$repository_root/Cargo.toml" \
  --target-dir "$rust_target" -p carrack-cli --bin carrack --bin carrackctl
cli_binary="$rust_target/debug/carrack"
control_binary="$rust_target/debug/carrackctl"
cli_mkdir=$(env CARRACK_VFS_TOKEN="$root_token" \
  "$cli_binary" mkdir /releases/artifacts \
  --control-url "$base_url" \
  --idempotency-key cli-mkdir-artifacts-v1 \
  --format json)
[[ "$(jq -r '.schema' <<<"$cli_mkdir")" == carrack.fs-mkdir.v1 ]]
cli_directory_id=$(jq -r '.directory_id' <<<"$cli_mkdir")

rust_list=$(env CARRACK_VFS_TOKEN="$root_token" CARRACK_CONTROL_URL="$base_url" \
  "$cli_binary" list /)
[[ "$(jq -r '.schema' <<<"$rust_list")" == carrack.fs-list.v1 ]]
[[ "$(jq -r '.entries | length' <<<"$rust_list")" == 1 ]]
rust_mkdir=$(env CARRACK_VFS_TOKEN="$root_token" CARRACK_CONTROL_URL="$base_url" \
  "$cli_binary" mkdir /rust-native --idempotency-key rust-native-mkdir-v1)
[[ "$(jq -r '.schema' <<<"$rust_mkdir")" == carrack.fs-mkdir.v1 ]]
[[ "$(jq -r '.state' <<<"$rust_mkdir")" == committed ]]
rust_stat=$(env CARRACK_VFS_TOKEN="$root_token" CARRACK_CONTROL_URL="$base_url" \
  "$cli_binary" stat /rust-native)
[[ "$(jq -r '.kind' <<<"$rust_stat")" == directory ]]

cli_acl=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs acl show /releases/artifacts \
  --control-url "$base_url" --format json)
[[ "$(jq -r '.schema' <<<"$cli_acl")" == carrack.vfs.acl.v1 ]]
cli_acl_revision=$(jq -r '.acl_revision' <<<"$cli_acl")
cli_acl_replaced=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs acl replace /releases/artifacts \
  --control-url "$base_url" \
  --principal-id "$principal_id" \
  --action directory.list,content.read \
  --expected-revision "$cli_acl_revision" \
  --idempotency-key cli-acl-viewer-v1 \
  --format json)
[[ "$(jq -r '.kind' <<<"$cli_acl_replaced")" == acl.replace ]]
[[ "$(jq -c '.policy.actions' <<<"$cli_acl_replaced")" == '["content.read","directory.list"]' ]]

cli_placements=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs placement show /releases/artifacts \
  --control-url "$base_url" --format json)
[[ "$(jq -r '.schema' <<<"$cli_placements")" == carrack.vfs.placements.v1 ]]
cli_placement_revision=$(jq -r '.placement_revision' <<<"$cli_placements")
cli_placement_replaced=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs placement replace /releases/artifacts \
  --control-url "$base_url" \
  --placement local-main:0 \
  --expected-revision "$cli_placement_revision" \
  --idempotency-key cli-placement-local-v1 \
  --format json)
[[ "$(jq -r '.kind' <<<"$cli_placement_replaced")" == placement.replace ]]
[[ "$(jq -r '.policy.placements[0].driver_id' <<<"$cli_placement_replaced")" == local-main ]]

cli_issue=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs token issue / \
  --control-url "$base_url" \
  --action directory.list \
  --driver-id local-main \
  --expires-at "$expires_at" \
  --idempotency-key cli-reader-v1 \
  --format json)
[[ "$(jq -r '.schema' <<<"$cli_issue")" == carrack.vfs.token-issue-receipt.v1 ]]
cli_token_id=$(jq -r '.token_id' <<<"$cli_issue")
cli_token=$(jq -r '.token' <<<"$cli_issue")

cli_page=$(env CARRACK_VFS_TOKEN="$cli_token" \
  "$cli_binary" list / --control-url "$base_url" --format json)
[[ "$(jq -r '.schema' <<<"$cli_page")" == carrack.fs-list.v1 ]]

cli_revoked=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs token revoke "$cli_token_id" \
  --control-url "$base_url" \
  --idempotency-key cli-reader-revoke-v1 \
  --format json)
[[ "$(jq -r '.state' <<<"$cli_revoked")" == revoked ]]

revoke_request='{"idempotency_key":"delegating-child-revoke-v1"}'
revoked_delegate=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$revoke_request" \
  "$base_url/api/v2/tokens/$delegate_token_id/revoke")
[[ "$(jq -r '.state' <<<"$revoked_delegate")" == revoked ]]

delegate_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$delegate_authorization" \
  "$base_url/api/v2/directories/$root_directory_id/entries")
[[ "$delegate_status" == 401 ]]
grandchild_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer $grandchild_token" \
  "$base_url/api/v2/directories/$root_directory_id/entries")
[[ "$grandchild_status" == 401 ]]

child_revoke_request='{"idempotency_key":"reader-child-revoke-v1"}'
revoked_child=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$child_revoke_request" \
  "$base_url/api/v2/tokens/$child_token_id/revoke")
replayed_revoke=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$child_revoke_request" \
  "$base_url/api/v2/tokens/$child_token_id/revoke")
[[ "$replayed_revoke" == "$revoked_child" ]]

revoked_child_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$child_authorization" \
  "$base_url/api/v2/directories/$created_directory_id/entries")
[[ "$revoked_child_status" == 401 ]]

self_revoke_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$root_authorization" -H "$json" \
  --data '{"idempotency_key":"reject-self-revoke-v1"}' \
  "$base_url/api/v2/tokens/$(jq -r '.token_id' <<<"$bootstrapped")/revoke")
[[ "$self_revoke_status" == 400 ]]

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "
    DELETE FROM vfs_acl_grants
    WHERE directory_id = '$root_directory_id'
      AND principal_id = '$principal_id'
      AND action = 'token.issue';
  " >/dev/null

acl_denied_request=$(jq -cn \
  --arg root "$root_directory_id" \
  --argjson expires_at "$expires_at" \
  '{
    root_directory_id: $root,
    actions: ["directory.list"],
    driver_ids: ["local-main"],
    expires_at: $expires_at,
    idempotency_key: "denied-after-acl-v1"
  }')
acl_denied_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$root_authorization" -H "$json" --data "$acl_denied_request" \
  "$base_url/api/v2/tokens")
[[ "$acl_denied_status" == 403 ]]

child_verifier=$(printf '%s' "$child_token" | sha256sum | cut -d' ' -f1)
"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "
    CREATE TABLE vfs_management_assertions (
      accepted INTEGER NOT NULL CHECK (accepted = 1)
    ) STRICT;
    INSERT INTO vfs_management_assertions
    SELECT (SELECT COUNT(*) FROM vfs_token_issue_receipts) = 4
       AND (SELECT COUNT(*) FROM vfs_token_revoke_receipts) = 3
       AND (SELECT COUNT(*) FROM vfs_audit_events WHERE event_kind = 'token_issued') = 4
       AND (SELECT COUNT(*) FROM vfs_audit_events WHERE event_kind = 'token_revoked') = 3
       AND (SELECT COUNT(*) FROM vfs_directory_create_receipts) = 3
       AND (SELECT COUNT(*) FROM vfs_audit_events WHERE event_kind = 'directory_created') = 3
       AND (SELECT COUNT(*) FROM vfs_policy_mutation_receipts) = 4
       AND (SELECT COUNT(*) FROM vfs_audit_events WHERE event_kind = 'acl.replace') = 2
       AND (SELECT COUNT(*) FROM vfs_audit_events WHERE event_kind = 'placement.replace') = 2
       AND EXISTS (
         SELECT 1
         FROM vfs_directories AS child
         JOIN vfs_directory_entries AS entry
           ON entry.child_directory_id = child.id
         JOIN vfs_directory_key_epochs AS key_epoch
           ON key_epoch.directory_id = child.id
          AND key_epoch.key_epoch = child.active_key_epoch
         WHERE child.id = '$created_directory_id'
           AND child.parent_id = '$root_directory_id'
           AND entry.directory_id = '$root_directory_id'
           AND entry.data_root = child.data_root
           AND key_epoch.ciphertext IS NOT NULL
       )
       AND (SELECT COUNT(*) FROM vfs_token_verifiers
            WHERE id = '$child_token_id' AND verifier_sha256 = '$child_verifier') = 1
       AND (SELECT COUNT(*) FROM vfs_token_issue_receipts
            WHERE idempotency_key = 'denied-after-acl-v1') = 0
       AND NOT EXISTS (
         SELECT 1 FROM vfs_token_issue_receipts
         WHERE instr(actions_json, '$child_token') != 0
            OR instr(COALESCE(driver_ids_json, ''), '$child_token') != 0
       )
       AND NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);
  " >/dev/null
