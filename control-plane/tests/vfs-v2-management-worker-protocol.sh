#!/usr/bin/env bash
set -euo pipefail

curl() {
  command curl \
    --header "Carrack-Protocol-Epoch: 2" \
    --header "Carrack-SDK-Version: 0.3.6" \
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
  if [[ -n "$server_pid" ]]; then
    kill -- "-$server_pid" 2>/dev/null || kill "$server_pid" 2>/dev/null || true
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
"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "INSERT INTO vfs_transfer_hourly_analytics (
    bucket, driver_id, token_id, directory_id, direction,
    weighted_transfers, weighted_bytes, weighted_provider_ms,
    weighted_total_ms, weighted_retries, weighted_phase_transfers,
    weighted_plan_ms, weighted_queue_ms, weighted_phase_provider_ms,
    weighted_post_provider_ms, speed_b1, updated_at
  ) VALUES (
    3600, 'driver-phase-test', 'token-phase-test', 'directory-phase-test', 'download',
    10, 10485760, 10000, 20000, 0, 10, 2000, 3000, 10000, 4000, 10, 3600
  )" >/dev/null
"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "INSERT INTO driver_instances (
    id, kind, config_json, enabled, revision, created_at, updated_at
  ) VALUES (
    'local-secondary', 'local-filesystem/v2',
    json_object('root', '$state_directory/provider-secondary'), 1, 1, 1, 1
  )" >/dev/null

admin_token=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA
operator_account=draven
export CARRACK_OPERATOR_ACCOUNT="$operator_account"

setsid "${wrangler[@]}" dev \
  --local \
  --persist-to "$state_directory" \
  --port "$port" \
  --inspector-port 0 \
  --var CARRACK_VFS_MASTER_KEY_V1:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA \
  --var CARRACK_OPERATOR_ACCOUNT:"$operator_account" \
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

unauthenticated_activity=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "$base_url/api/admin/activity")
[[ "$unauthenticated_activity" == 401 ]]
unauthenticated_events=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "$base_url/api/admin/events?after=0&limit=1")
[[ "$unauthenticated_events" == 401 ]]
unauthenticated_recent_events=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "$base_url/api/admin/events/recent?before=0&limit=1")
[[ "$unauthenticated_recent_events" == 401 ]]
unauthenticated_token_options=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "$base_url/api/admin/options/tokens?q=&limit=1")
[[ "$unauthenticated_token_options" == 401 ]]
unauthenticated_metrics=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "$base_url/api/admin/metrics/global/all")
[[ "$unauthenticated_metrics" == 401 ]]
unauthenticated_analytics=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "$base_url/api/admin/analytics/transfers")
[[ "$unauthenticated_analytics" == 401 ]]
unauthenticated_directory_entries=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "$base_url/api/admin/directories/0123456789abcdef0123456789abcdef/entries?revision=1")
[[ "$unauthenticated_directory_entries" == 401 ]]

for retired_get_route in \
  /api/client/session \
  /api/summary \
  /api/components/live \
  /api/integrity/findings; do
  retired_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    "$base_url$retired_get_route")
  [[ "$retired_status" == 404 ]]
done
for retired_post_route in \
  /api/clients \
  /api/v1/operations \
  /api/recovery/begin; do
  retired_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    -X POST "$base_url$retired_post_route")
  [[ "$retired_status" == 404 ]]
done

curl --silent --show-error --fail-with-body \
  -c "$cookie_jar" -H "$json" \
  --data "$(jq -cn --arg account "$operator_account" --arg password "$admin_token" \
    '{account: $account, password: $password}')" \
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

global_metrics=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/metrics/global/all")
[[ "$(jq -r '.schema' <<<"$global_metrics")" == carrack.management.transfer-metrics.v1 ]]
[[ "$(jq -r '.scope_kind' <<<"$global_metrics")" == global ]]
[[ "$(jq -r '.scope_id' <<<"$global_metrics")" == all ]]
[[ "$(jq -r '.retention_days' <<<"$global_metrics")" == 400 ]]
[[ "$(jq -r '.window_days' <<<"$global_metrics")" == 30 ]]
[[ "$(jq -r '.rows | length' <<<"$global_metrics")" == 0 ]]
oversized_metrics_window=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" "$base_url/api/admin/metrics/global/all?days=401")
[[ "$oversized_metrics_window" == 400 ]]
transfer_analytics=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" \
  "$base_url/api/admin/analytics/transfers?from=1&to=86401&interval=hour&group_by=driver&direction=both")
[[ "$(jq -r '.schema' <<<"$transfer_analytics")" == carrack.management.transfer-analytics.v2 ]]
[[ "$(jq -r '.interval' <<<"$transfer_analytics")" == hour ]]
[[ "$(jq -r '.group_by' <<<"$transfer_analytics")" == driver ]]
[[ "$(jq -r '.approximate' <<<"$transfer_analytics")" == true ]]
[[ "$(jq -r '.rows | length' <<<"$transfer_analytics")" == 1 ]]
[[ "$(jq -r '.rows[0].group_id' <<<"$transfer_analytics")" == driver-phase-test ]]
[[ "$(jq -r '.rows[0].weighted_phase_transfers' <<<"$transfer_analytics")" == 10 ]]
[[ "$(jq -r '.rows[0].weighted_plan_ms' <<<"$transfer_analytics")" == 2000 ]]
[[ "$(jq -r '.rows[0].weighted_queue_ms' <<<"$transfer_analytics")" == 3000 ]]
[[ "$(jq -r '.rows[0].weighted_phase_provider_ms' <<<"$transfer_analytics")" == 10000 ]]
[[ "$(jq -r '.rows[0].weighted_post_provider_ms' <<<"$transfer_analytics")" == 4000 ]]
invalid_descendant_analytics=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" \
  "$base_url/api/admin/analytics/transfers?include_descendants=true")
[[ "$invalid_descendant_analytics" == 400 ]]

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

for name in archive-a archive-b archive-c; do
  curl --silent --show-error --fail-with-body \
    -H "$root_authorization" -H "$json" \
    --data "$(jq -cn --arg name "$name" '{
      name: $name,
      idempotency_key: ("management-page-" + $name + "-v1")
    }')" \
    "$base_url/api/v2/directories/$root_directory_id/children" >/dev/null
done
management_directory=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" \
  "$base_url/api/admin/directories/$root_directory_id?entries=false")
[[ "$(jq -r '.schema' <<<"$management_directory")" == carrack.management.directory.v1 ]]
[[ "$(jq -r '.entries | length' <<<"$management_directory")" == 0 ]]
[[ "$(jq -r '.mount.relationship' <<<"$management_directory")" == default ]]
[[ "$(jq -r '.mount.effective_driver_id' <<<"$management_directory")" == local-main ]]
management_revision=$(jq -r '.directory.revision' <<<"$management_directory")
management_page_one=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" \
  "$base_url/api/admin/directories/$root_directory_id/entries?revision=$management_revision&prefix=archive-&after_kind=&after_name=&limit=2")
[[ "$(jq -r '.schema' <<<"$management_page_one")" == carrack.management.directory-entry-page.v1 ]]
[[ "$(jq -c '[.entries[].name]' <<<"$management_page_one")" == '["archive-a","archive-b"]' ]]
[[ "$(jq -r '.has_more' <<<"$management_page_one")" == true ]]
next_kind=$(jq -r '.next_after_kind' <<<"$management_page_one")
next_name=$(jq -r '.next_after_name' <<<"$management_page_one")
management_page_two=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" \
  --get \
  --data-urlencode "revision=$management_revision" \
  --data-urlencode 'prefix=archive-' \
  --data-urlencode "after_kind=$next_kind" \
  --data-urlencode "after_name=$next_name" \
  --data-urlencode 'limit=2' \
  "$base_url/api/admin/directories/$root_directory_id/entries")
[[ "$(jq -c '[.entries[].name]' <<<"$management_page_two")" == '["archive-c"]' ]]
[[ "$(jq -r '.has_more' <<<"$management_page_two")" == false ]]

curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" \
  --data '{"name":"archive-d","idempotency_key":"management-page-archive-d-v1"}' \
  "$base_url/api/v2/directories/$root_directory_id/children" >/dev/null
stale_management_page=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" \
  "$base_url/api/admin/directories/$root_directory_id/entries?revision=$management_revision&limit=2")
[[ "$stale_management_page" == 409 ]]

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
[[ "$(jq -r '.placements | length' <<<"$placements")" == 1 ]]
[[ "$(jq -r '.placements[0].driver_id' <<<"$placements")" == local-main ]]
[[ "$(jq -r '.placements[0].mount_kind' <<<"$placements")" == inherited ]]
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

mount_directory=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" \
  --data '{"name":"secondary","idempotency_key":"mkdir-secondary-mount-v1"}' \
  "$base_url/api/v2/directories/$root_directory_id/children")
mount_directory_id=$(jq -r '.directory_id' <<<"$mount_directory")
mount_before=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" \
  "$base_url/api/v2/directories/$mount_directory_id/placements")
mount_revision=$(jq -r '.placement_revision' <<<"$mount_before")
mount_request=$(jq -cn --argjson expected "$mount_revision" '{
  placements: [{driver_id: "local-secondary", write_priority: 0}],
  expected_placement_revision: $expected,
  idempotency_key: "mount-secondary-v1"
}')
curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" --data "$mount_request" \
  "$base_url/api/v2/directories/$mount_directory_id/placements/replace" >/dev/null
mount_after=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" \
  "$base_url/api/v2/directories/$mount_directory_id/placements")
[[ "$(jq -r '.placements[0].driver_id' <<<"$mount_after")" == local-secondary ]]
[[ "$(jq -r '.placements[0].mount_kind' <<<"$mount_after")" == mount ]]

nested_directory=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" \
  --data '{"name":"nested","idempotency_key":"mkdir-secondary-nested-v1"}' \
  "$base_url/api/v2/directories/$mount_directory_id/children")
nested_directory_id=$(jq -r '.directory_id' <<<"$nested_directory")
nested_policy=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" \
  "$base_url/api/v2/directories/$nested_directory_id/placements")
[[ "$(jq -r '.placements[0].driver_id' <<<"$nested_policy")" == local-secondary ]]
[[ "$(jq -r '.placements[0].mount_kind' <<<"$nested_policy")" == inherited ]]
nested_mount_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$root_authorization" -H "$json" \
  --data "$(jq -cn --argjson expected "$(jq -r '.placement_revision' <<<"$nested_policy")" '{
    placements: [{driver_id: "local-main", write_priority: 0}],
    expected_placement_revision: $expected,
    idempotency_key: "reject-nested-mount-v1"
  }')" \
  "$base_url/api/v2/directories/$nested_directory_id/placements/replace")
[[ "$nested_mount_status" == 409 ]]

nonempty_unmount_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$root_authorization" -H "$json" \
  --data "$(jq -cn --argjson expected "$(jq -r '.placement_revision' <<<"$mount_after")" '{
    placements: [{driver_id: "local-main", write_priority: 0}],
    expected_placement_revision: $expected,
    idempotency_key: "reject-nonempty-unmount-v1"
  }')" \
  "$base_url/api/v2/directories/$mount_directory_id/placements/replace")
[[ "$nonempty_unmount_status" == 409 ]]

cross_driver_source=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" -H "$json" \
  --data '{"name":"cross-source","idempotency_key":"mkdir-cross-source-v1"}' \
  "$base_url/api/v2/directories/$root_directory_id/children")
cross_driver_source_id=$(jq -r '.directory_id' <<<"$cross_driver_source")
cross_driver_source_revision=$(curl --silent --show-error --fail-with-body \
  -H "$root_authorization" \
  "$base_url/api/v2/directories/$root_directory_id/entries" | \
  jq -r '.entries[] | select(.name == "cross-source").revision')
cross_driver_rename_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "$root_authorization" -H "$json" \
  --data "$(jq -cn --argjson revision "$cross_driver_source_revision" --arg destination "$mount_directory_id" '{
    source_name: "cross-source",
    expected_source_revision: $revision,
    destination_directory_id: $destination,
    destination_name: "cross-source",
    idempotency_key: "reject-cross-driver-rename-v1"
  }')" \
  "$base_url/api/v2/directories/$root_directory_id/rename")
[[ "$cross_driver_rename_status" == 409 ]]

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
[[ "$(jq -r '.entries | length' <<<"$rust_list")" == 7 ]]
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
	  "$control_binary" vfs mount show /releases/artifacts \
  --control-url "$base_url" --format json)
[[ "$(jq -r '.schema' <<<"$cli_placements")" == carrack.vfs.placements.v1 ]]
cli_placement_revision=$(jq -r '.placement_revision' <<<"$cli_placements")
cli_placement_replaced=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs mount set /releases/artifacts \
  --control-url "$base_url" \
  --driver local-secondary \
  --expected-revision "$cli_placement_revision" \
  --idempotency-key cli-mount-secondary-v1 \
  --format json)
[[ "$(jq -r '.kind' <<<"$cli_placement_replaced")" == placement.replace ]]
[[ "$(jq -r '.policy.placements[0].driver_id' <<<"$cli_placement_replaced")" == local-secondary ]]
cli_mounted=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs mount show /releases/artifacts \
  --control-url "$base_url" --format json)
[[ "$(jq -r '.placements[0].mount_kind' <<<"$cli_mounted")" == mount ]]
cli_inherited=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs mount inherit /releases/artifacts \
  --control-url "$base_url" \
  --expected-revision "$(jq -r '.placement_revision' <<<"$cli_mounted")" \
  --idempotency-key cli-mount-inherit-v1 \
  --format json)
[[ "$(jq -r '.kind' <<<"$cli_inherited")" == placement.replace ]]
cli_inherited_policy=$(env CARRACK_VFS_TOKEN="$root_token" \
	  "$control_binary" vfs mount show /releases/artifacts \
  --control-url "$base_url" --format json)
[[ "$(jq -r '.placements[0].driver_id' <<<"$cli_inherited_policy")" == local-main ]]
[[ "$(jq -r '.placements[0].mount_kind' <<<"$cli_inherited_policy")" == inherited ]]

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

now=$(date +%s)
"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "
    INSERT INTO vfs_audit_events (
      event_kind, subject_kind, subject_id, details_json, created_at
    ) VALUES (
      'management.events.redaction_test', 'test', 'event-page',
      '{\"credential\":\"must-not-render\",\"safe\":\"visible\"}', $now
    );
  " >/dev/null

for invalid_event_query in \
  'after=01' \
  'after=0&after=1' \
  'limit=0' \
  'limit=251' \
  'unknown=1'; do
  invalid_event_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    -b "$cookie_jar" "$base_url/api/admin/events?$invalid_event_query")
  [[ "$invalid_event_status" == 400 ]]
done

event_headers="$state_directory/event-headers.txt"
event_page_1=$(curl --silent --show-error --fail-with-body \
  -D "$event_headers" -b "$cookie_jar" "$base_url/api/admin/events?after=0&limit=2")
grep -iq '^cache-control: no-store, max-age=0' "$event_headers"
jq -e '
  .schema == "carrack.management.events.v1" and
  .after == 0 and
  .has_more == true and
  (.events | length) == 2 and
  .next_after == .events[-1].id and
  .events[0].id < .events[1].id and
  .next_after < .event_cursor
' <<<"$event_page_1" >/dev/null

event_page_1_cursor=$(jq -r '.event_cursor' <<<"$event_page_1")
event_page_1_next=$(jq -r '.next_after' <<<"$event_page_1")
event_page_2=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" \
  "$base_url/api/admin/events?after=$event_page_1_next&limit=250")
jq -e --argjson cursor "$event_page_1_cursor" --argjson after "$event_page_1_next" '
  .schema == "carrack.management.events.v1" and
  .after == $after and
  .event_cursor == $cursor and
  .has_more == false and
  .next_after == .event_cursor and
  ([.events[].id] | all(. > $after and . <= $cursor)) and
  ([.events[].event_kind] | index("management.events.redaction_test") != null) and
  ([.events[] | select(.event_kind == "management.events.redaction_test")][0].details ==
    {"credential":"[redacted]","safe":"visible"})
' <<<"$event_page_2" >/dev/null

ahead_event_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" \
  "$base_url/api/admin/events?after=$((event_page_1_cursor + 1))&limit=1")
[[ "$ahead_event_status" == 409 ]]

recent_events=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/events/recent?before=0&limit=2")
jq -e '
  .schema == "carrack.management.recent-events.v1" and
  .before == 0 and
  .has_more == true and
  (.events | length) == 2 and
  .events[0].id > .events[1].id and
  .next_before == .events[-1].id
' <<<"$recent_events" >/dev/null

cli_event_page=$(env CARRACK_OPERATOR_CREDENTIAL="$admin_token" \
  "$control_binary" watch --after 0 --limit 2 \
  --control-url "$base_url" --format json)
jq -e '
  .schema == "carrack.management.events.v1" and
  .after == 0 and
  (.events | length) == 2 and
  .next_after == .events[-1].id
' <<<"$cli_event_page" >/dev/null

activity_headers="$state_directory/activity-headers.txt"
activity=$(curl --silent --show-error --fail-with-body \
  -D "$activity_headers" -b "$cookie_jar" \
  "$base_url/api/admin/activity?attention=all&offset=0&limit=25")
grep -iq '^cache-control: no-store, max-age=0' "$activity_headers"
jq -e '
  .schema == "carrack.management.activity.v2" and
  .offset == 0 and .limit == 25 and
  (.has_more | type) == "boolean" and
  (.active_items | type) == "array"
' <<<"$activity" >/dev/null

token_options=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/options/tokens?q=&limit=1")
jq -e '
  .schema == "carrack.management.token-options.v1" and
  (.tokens | length) == 1 and
  .has_more == true and
  .next_after_label == .tokens[0].label and
  .next_after_id == .tokens[0].id
' <<<"$token_options" >/dev/null

exact_token_option=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/options/tokens?q=$child_token_id&limit=25")
jq -e --arg token "$child_token_id" '
  (.tokens | length) == 1 and .tokens[0].id == $token
' <<<"$exact_token_option" >/dev/null

directory_options=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/options/directories?q=&limit=25")
jq -e --arg directory "$created_directory_id" '
  .schema == "carrack.management.directory-options.v1" and
  ([.directories[] | select(.id == $directory)][0].path | startswith("/"))
' <<<"$directory_options" >/dev/null

exact_directory_option=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/options/directories?q=$created_directory_id&limit=25")
jq -e --arg directory "$created_directory_id" '
  (.directories | length) == 1 and .directories[0].id == $directory
' <<<"$exact_directory_option" >/dev/null

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
       AND (SELECT COUNT(*) FROM vfs_directory_create_receipts) = 10
       AND (SELECT COUNT(*) FROM vfs_audit_events WHERE event_kind = 'directory_created') = 10
       AND (SELECT COUNT(*) FROM vfs_policy_mutation_receipts) = 6
       AND (SELECT COUNT(*) FROM vfs_audit_events WHERE event_kind = 'acl.replace') = 2
       AND (SELECT COUNT(*) FROM vfs_audit_events WHERE event_kind = 'placement.replace') = 4
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
