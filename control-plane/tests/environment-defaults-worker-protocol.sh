#!/usr/bin/env bash
set -euo pipefail

curl() {
  command curl \
    --header "Skydriver-Protocol-Epoch: 2" \
    --header "Skydriver-SDK-Version: 0.3.6" \
    "$@"
}

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state_directory=$(mktemp -d)
server_log="$state_directory/wrangler.log"
cookie_jar="$state_directory/cookies.txt"
port=${SKYDRIVER_ENVIRONMENT_DEFAULTS_TEST_PORT:-8795}
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

wrangler=(
  pnpm exec wrangler
  --config "$repository_root/control-plane/wrangler.jsonc"
)

"${wrangler[@]}" d1 migrations apply SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" >/dev/null

"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "INSERT INTO driver_instances (
       id, kind, config_json, credential_ref, enabled, revision,
       created_at, updated_at, lifecycle_owner
   ) VALUES (
       'legacy-empty', 'local-filesystem/v2', '{\"root\":\"/tmp/legacy-empty\"}',
       NULL, 0, 1, unixepoch(), unixepoch(), 'legacy-bootstrap'
   );" >/dev/null

admin_token=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA
operator_account=draven
r2_endpoint=https://0123456789abcdef.r2.cloudflarestorage.com

setsid "${wrangler[@]}" dev \
  --local \
  --persist-to "$state_directory" \
  --port "$port" \
  --inspector-port 0 \
  --test-scheduled \
  --var SKYDRIVER_ENVIRONMENT:dev \
  --var SKYDRIVER_OPERATOR_ACCOUNT:"$operator_account" \
  --var SKYDRIVER_DEFAULT_R2_MAX_PHYSICAL_BYTES:107374182400 \
  --var SKYDRIVER_R2_ENDPOINT:"$r2_endpoint" \
  --var SKYDRIVER_VFS_MASTER_KEY_V1:"$admin_token" \
  --var SKYDRIVER_ADMIN_TOKEN:"$admin_token" \
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
curl --silent --show-error --fail-with-body \
  -c "$cookie_jar" -H "$json" \
  --data "$(jq -cn --arg account "$operator_account" --arg password "$admin_token" \
    '{account: $account, password: $password}')" \
  "$base_url/api/auth/login" >/dev/null

snapshot=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/snapshot")
jq -e --arg endpoint "$r2_endpoint" '
  .drivers == [{
    id: "r2-default",
    kind: "r2/v1",
    lifecycle_owner: "environment",
    config: {
      endpoint: $endpoint,
      bucket: "carrack-payload-dev",
      prefix: "",
      managed: true
    },
    enabled: false,
    revision: 1,
    credential_present: false,
    credential_rotated_at: null,
    credential_expires_at: null,
    credential_refresh_state: null,
    credential_refresh_after: null,
    credential_refresh_last_succeeded_at: null,
    credential_refresh_last_error_code: null,
    credential_refresh_token_expires_at: null,
    placement_count: 0,
    location_count: 0,
    available_location_count: 0,
    encoded_bytes: 0,
    file_count: 0,
    quota_revision: 2,
    max_physical_bytes: 107374182400,
    max_object_count: null,
    reserved_physical_bytes: 0,
    reserved_object_count: 0,
    updated_at: .drivers[0].updated_at
  }]
' <<<"$snapshot" >/dev/null

retired_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" -H "$json" \
  --data '{"enabled":true,"expected_revision":2}' \
  "$base_url/api/admin/drivers/legacy-empty/state/validate")
[[ "$retired_status" == 404 ]]

enable_without_credential=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" -H "$json" \
  --data '{"enabled":true,"expected_revision":1}' \
  "$base_url/api/admin/drivers/r2-default/state/validate")
[[ "$enable_without_credential" == 400 ]]

managed_registration=$(jq -cn --arg endpoint "$r2_endpoint" '{
  driver_id: "r2-extra",
  kind: "r2/v1",
  config: {
    endpoint: $endpoint,
    bucket: "carrack-payload-dev",
    prefix: "",
    managed: true
  }
}')
managed_registration_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -b "$cookie_jar" -H "$json" --data "$managed_registration" \
  "$base_url/api/admin/drivers/registration/validate")
[[ "$managed_registration_status" == 400 ]]

bootstrap_request='{
  "filesystem_name":"Skydriver VFS",
  "principal_display_name":"VFS operator",
  "idempotency_key":"environment-bootstrap-v2"
}'
bootstrapped=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$bootstrap_request" \
  "$base_url/api/v2/bootstrap")
[[ "$(jq -r '.driver_id' <<<"$bootstrapped")" == r2-default ]]
replayed=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" -H "$json" --data "$bootstrap_request" \
  "$base_url/api/v2/bootstrap")
[[ "$replayed" == "$bootstrapped" ]]

root_directory_id=$(jq -r '.root_directory_id' <<<"$bootstrapped")
directory=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/directories/$root_directory_id")
[[ "$(jq -c '.placements' <<<"$directory")" == '["r2-default"]' ]]
[[ "$(jq -r '.mount.relationship' <<<"$directory")" == default ]]

# Hosted inventory is conservative under provider drift: an object that has no
# D1 identity becomes quarantine evidence and remains physically present.
unknown_source="$state_directory/unknown-provider-object"
unknown_readback="$state_directory/unknown-provider-readback"
printf 'unowned-provider-object\n' >"$unknown_source"
"${wrangler[@]}" r2 object put \
  carrack-payload-local/inventory-fault-injection/unknown \
  --local --persist-to "$state_directory" --file "$unknown_source" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "UPDATE driver_instances SET enabled = 1, revision = revision + 1,
       updated_at = unixepoch() WHERE id = 'r2-default';" >/dev/null
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
inventory=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/provider-inventory")
if ! jq -e '
  .drivers[] | select(.driver_id == "r2-default") |
  .state == "complete" and .scanned_objects == 1 and
  .unknown_objects == 1 and .quarantined_objects == 1 and
  .quarantined_bytes == 24 and .last_error_code == null and
  .attempt_count == 0 and .next_scan_at > .last_completed_at
' <<<"$inventory" >/dev/null; then
  jq . <<<"$inventory" >&2
  exit 1
fi
scheduled_inventory=$(curl --silent --show-error --fail-with-body \
  -X POST -b "$cookie_jar" \
  "$base_url/api/admin/provider-inventory/r2-default/refresh")
jq -e '
  .observed_at as $observed_at |
  .drivers[] | select(.driver_id == "r2-default") |
  .state == "idle" and .attempt_count == 0 and
  .last_error_code == null and .next_scan_at <= $observed_at
' <<<"$scheduled_inventory" >/dev/null
"${wrangler[@]}" r2 object get \
  carrack-payload-local/inventory-fault-injection/unknown \
  --local --persist-to "$state_directory" --file "$unknown_readback" >/dev/null
cmp "$unknown_source" "$unknown_readback"

# Hosted physical GC must fail closed when its immutable driver-revision fence
# changes, while deleting an independently fenced object once every identity
# and reachability check still matches.
filesystem_id=$(jq -r '.filesystem_id' <<<"$bootstrapped")
principal_id=$(jq -r '.principal_id' <<<"$bootstrapped")
token_id=$(jq -r '.token_id' <<<"$bootstrapped")
blocked_source="$state_directory/lifecycle-blocked-object"
blocked_readback="$state_directory/lifecycle-blocked-readback"
deleted_source="$state_directory/lifecycle-deleted-object"
printf 'revision-fenced-object\n' >"$blocked_source"
printf 'safe-to-delete-object\n' >"$deleted_source"
blocked_bytes=$(wc -c <"$blocked_source" | tr -d ' ')
deleted_bytes=$(wc -c <"$deleted_source" | tr -d ' ')
blocked_sha=$(sha256sum "$blocked_source" | cut -d ' ' -f 1)
deleted_sha=$(sha256sum "$deleted_source" | cut -d ' ' -f 1)
deleted_etag=$(md5sum "$deleted_source" | cut -d ' ' -f 1)
"${wrangler[@]}" r2 object put \
  carrack-payload-local/lifecycle-fault-injection/blocked \
  --local --persist-to "$state_directory" --file "$blocked_source" >/dev/null
"${wrangler[@]}" r2 object put \
  carrack-payload-local/lifecycle-fault-injection/deleted \
  --local --persist-to "$state_directory" --file "$deleted_source" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "INSERT INTO vfs_files (id, filesystem_id, created_at, updated_at)
   VALUES ('a1111111111111111111111111111111', '$filesystem_id', unixepoch(), unixepoch());
   INSERT INTO vfs_file_versions (
     id, file_id, plaintext_bytes, verification_block_bytes,
     verification_block_count, file_root, block_manifest_sha256,
     block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
     crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes,
     encoded_sha256, created_at
   ) VALUES (
     'b1111111111111111111111111111111', 'a1111111111111111111111111111111',
     $blocked_bytes, 4096, 1,
     '1111111111111111111111111111111111111111111111111111111111111111',
     '2111111111111111111111111111111111111111111111111111111111111111',
     1, 'fault/manifests/blocked', 'fault-manifest-blocked', 'plaintext/v1',
     1, 4096, $blocked_bytes, '$blocked_sha', unixepoch()
   );
   INSERT INTO vfs_locations (
     id, version_id, driver_id, storage_key, size_bytes, object_sha256,
     created_at, updated_at
   ) VALUES (
     'c1111111111111111111111111111111', 'b1111111111111111111111111111111',
     'r2-default', 'lifecycle-fault-injection/blocked', $blocked_bytes,
     '$blocked_sha', unixepoch(), unixepoch()
   );
   UPDATE vfs_locations
   SET state = 'verified', verified_at = unixepoch(), revision = revision + 1,
       updated_at = unixepoch()
   WHERE id = 'c1111111111111111111111111111111';
   UPDATE vfs_locations
   SET state = 'tombstoned', delete_after = unixepoch() - 1,
       revision = revision + 1, updated_at = unixepoch()
   WHERE id = 'c1111111111111111111111111111111';
   INSERT INTO vfs_location_delete_tasks (
     id, expected_location_revision, driver_id, driver_revision, storage_key,
     native_id, provider_version, etag, size_bytes, delete_after,
     created_at, updated_at
   )
   SELECT location.id, location.revision, location.driver_id, driver.revision,
          location.storage_key, location.native_id, location.provider_version,
          location.etag, location.size_bytes, location.delete_after,
          unixepoch(), unixepoch()
   FROM vfs_locations AS location
   JOIN driver_instances AS driver ON driver.id = location.driver_id
   WHERE location.id = 'c1111111111111111111111111111111';
   UPDATE driver_instances
   SET revision = revision + 1, updated_at = unixepoch()
   WHERE id = 'r2-default';
   INSERT INTO vfs_files (id, filesystem_id, created_at, updated_at)
   VALUES ('a2222222222222222222222222222222', '$filesystem_id', unixepoch(), unixepoch());
   INSERT INTO vfs_file_versions (
     id, file_id, plaintext_bytes, verification_block_bytes,
     verification_block_count, file_root, block_manifest_sha256,
     block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
     crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes,
     encoded_sha256, created_at
   ) VALUES (
     'b2222222222222222222222222222222', 'a2222222222222222222222222222222',
     $deleted_bytes, 4096, 1,
     '1222222222222222222222222222222222222222222222222222222222222222',
     '2222222222222222222222222222222222222222222222222222222222222222',
     1, 'fault/manifests/deleted', 'fault-manifest-deleted', 'plaintext/v1',
     1, 4096, $deleted_bytes, '$deleted_sha', unixepoch()
   );
   INSERT INTO vfs_locations (
     id, version_id, driver_id, storage_key, etag, size_bytes, object_sha256,
     created_at, updated_at
   ) VALUES (
     'c2222222222222222222222222222222', 'b2222222222222222222222222222222',
     'r2-default', 'lifecycle-fault-injection/deleted', '$deleted_etag', $deleted_bytes,
     '$deleted_sha', unixepoch(), unixepoch()
   );
   UPDATE vfs_locations
   SET state = 'verified', verified_at = unixepoch(), revision = revision + 1,
       updated_at = unixepoch()
   WHERE id = 'c2222222222222222222222222222222';
   UPDATE vfs_locations
   SET state = 'tombstoned', delete_after = unixepoch() - 1,
       revision = revision + 1, updated_at = unixepoch()
   WHERE id = 'c2222222222222222222222222222222';" >/dev/null

curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT CASE WHEN state = 'blocked' AND last_error_code = 'revalidation_failed'
     THEN 1 ELSE 0 END AS accepted
   FROM vfs_location_delete_tasks
   WHERE id = 'c1111111111111111111111111111111';" --json |
  jq -e '.[0].results == [{"accepted":1}]' >/dev/null
"${wrangler[@]}" r2 object get \
  carrack-payload-local/lifecycle-fault-injection/blocked \
  --local --persist-to "$state_directory" --file "$blocked_readback" >/dev/null
cmp "$blocked_source" "$blocked_readback"

curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT CASE WHEN location.state = 'deleted' AND task.state = 'deleted'
     THEN 1 ELSE 0 END AS accepted
   FROM vfs_locations AS location
   JOIN vfs_location_delete_tasks AS task ON task.id = location.id
   WHERE location.id = 'c2222222222222222222222222222222';" --json |
  jq -e '.[0].results == [{"accepted":1}]' >/dev/null
if "${wrangler[@]}" r2 object get \
  carrack-payload-local/lifecycle-fault-injection/deleted \
  --local --persist-to "$state_directory" \
  --file "$state_directory/unexpected-deleted-readback" >/dev/null 2>&1; then
  echo "fenced lifecycle object remained in R2 after committed deletion" >&2
  exit 1
fi

# A direct provider read remains protected by its durable D1 lease. Cron may
# block the stale task, but it must leave both the location and provider bytes
# intact until a later lifecycle decision creates a newly fenced task.
token_id=$(jq -r '.token_id' <<<"$bootstrapped")
leased_source="$state_directory/lifecycle-leased-object"
leased_readback="$state_directory/lifecycle-leased-readback"
printf 'actively-downloaded-object\n' >"$leased_source"
leased_bytes=$(wc -c <"$leased_source" | tr -d ' ')
leased_sha=$(sha256sum "$leased_source" | cut -d ' ' -f 1)
"${wrangler[@]}" r2 object put \
  carrack-payload-local/lifecycle-fault-injection/leased \
  --local --persist-to "$state_directory" --file "$leased_source" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "INSERT INTO vfs_files (id, filesystem_id, created_at, updated_at)
   VALUES ('a3333333333333333333333333333333', '$filesystem_id', unixepoch(), unixepoch());
   INSERT INTO vfs_file_versions (
     id, file_id, plaintext_bytes, verification_block_bytes,
     verification_block_count, file_root, block_manifest_sha256,
     block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
     crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes,
     encoded_sha256, created_at
   ) VALUES (
     'b3333333333333333333333333333333', 'a3333333333333333333333333333333',
     $leased_bytes, 4096, 1,
     '1333333333333333333333333333333333333333333333333333333333333333',
     '2333333333333333333333333333333333333333333333333333333333333333',
     1, 'fault/manifests/leased', 'fault-manifest-leased', 'plaintext/v1',
     1, 4096, $leased_bytes, '$leased_sha', unixepoch()
   );
   INSERT INTO vfs_locations (
     id, version_id, driver_id, storage_key, size_bytes, object_sha256,
     created_at, updated_at
   ) VALUES (
     'c3333333333333333333333333333333', 'b3333333333333333333333333333333',
     'r2-default', 'lifecycle-fault-injection/leased', $leased_bytes,
     '$leased_sha', unixepoch(), unixepoch()
   );
   UPDATE vfs_locations
   SET state = 'verified', verified_at = unixepoch(), revision = revision + 1,
       updated_at = unixepoch()
   WHERE id = 'c3333333333333333333333333333333';
   UPDATE vfs_locations
   SET state = 'tombstoned', delete_after = unixepoch() - 1,
       revision = revision + 1, updated_at = unixepoch()
   WHERE id = 'c3333333333333333333333333333333';
   INSERT INTO vfs_read_leases (
     id, version_id, location_id, token_id, expires_at, created_at
   ) VALUES (
     'd3333333333333333333333333333333', 'b3333333333333333333333333333333',
     'c3333333333333333333333333333333', '$token_id',
     unixepoch() + 3600, unixepoch()
   );" >/dev/null
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
leased_fence=$("${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT CASE WHEN location.state = 'tombstoned'
                       AND task.state = 'blocked'
                       AND task.last_error_code = 'revalidation_failed'
                       AND lease.completed_at IS NULL
                       AND lease.expires_at > unixepoch()
     THEN 1 ELSE 0 END AS accepted
   FROM vfs_locations AS location
   JOIN vfs_location_delete_tasks AS task ON task.id = location.id
   JOIN vfs_read_leases AS lease ON lease.location_id = location.id
   WHERE location.id = 'c3333333333333333333333333333333';" --json)
if ! jq -e '.[0].results == [{"accepted":1}]' <<<"$leased_fence" >/dev/null; then
  jq . <<<"$leased_fence" >&2
  "${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
    --local --persist-to "$state_directory" --command \
    "SELECT location.state AS location_state, task.state AS task_state,
            task.last_error_code, task.delete_after, unixepoch() AS now,
            lease.expires_at, lease.completed_at
     FROM vfs_locations AS location
     LEFT JOIN vfs_location_delete_tasks AS task ON task.id = location.id
     LEFT JOIN vfs_read_leases AS lease ON lease.location_id = location.id
     WHERE location.id = 'c3333333333333333333333333333333';" --json >&2
  exit 1
fi
"${wrangler[@]}" r2 object get \
  carrack-payload-local/lifecycle-fault-injection/leased \
  --local --persist-to "$state_directory" --file "$leased_readback" >/dev/null
cmp "$leased_source" "$leased_readback"

# A provider may have committed Delete while its response was lost. Replaying
# the exact fenced R2 delete against an already-missing object is idempotent and
# must still commit the D1 location and task state.
missing_bytes=29
missing_sha=4444444444444444444444444444444444444444444444444444444444444444
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "INSERT INTO vfs_files (id, filesystem_id, created_at, updated_at)
   VALUES ('a4444444444444444444444444444444', '$filesystem_id', unixepoch(), unixepoch());
   INSERT INTO vfs_file_versions (
     id, file_id, plaintext_bytes, verification_block_bytes,
     verification_block_count, file_root, block_manifest_sha256,
     block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
     crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes,
     encoded_sha256, created_at
   ) VALUES (
     'b4444444444444444444444444444444', 'a4444444444444444444444444444444',
     $missing_bytes, 4096, 1,
     '1444444444444444444444444444444444444444444444444444444444444444',
     '2444444444444444444444444444444444444444444444444444444444444444',
     1, 'fault/manifests/missing', 'fault-manifest-missing', 'plaintext/v1',
     1, 4096, $missing_bytes, '$missing_sha', unixepoch()
   );
   INSERT INTO vfs_locations (
     id, version_id, driver_id, storage_key, size_bytes, object_sha256,
     created_at, updated_at
   ) VALUES (
     'c4444444444444444444444444444444', 'b4444444444444444444444444444444',
     'r2-default', 'lifecycle-fault-injection/already-missing', $missing_bytes,
     '$missing_sha', unixepoch(), unixepoch()
   );
   UPDATE vfs_locations
   SET state = 'verified', verified_at = unixepoch(), revision = revision + 1,
       updated_at = unixepoch()
   WHERE id = 'c4444444444444444444444444444444';
   UPDATE vfs_locations
   SET state = 'tombstoned', delete_after = unixepoch() - 1,
       revision = revision + 1, updated_at = unixepoch()
   WHERE id = 'c4444444444444444444444444444444';" >/dev/null
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT CASE WHEN location.state = 'deleted' AND task.state = 'deleted'
                       AND task.attempt_count = 1
                       AND task.last_error_code IS NULL
     THEN 1 ELSE 0 END AS accepted
   FROM vfs_locations AS location
   JOIN vfs_location_delete_tasks AS task ON task.id = location.id
   WHERE location.id = 'c4444444444444444444444444444444';" --json |
  jq -e '.[0].results == [{"accepted":1}]' >/dev/null

# An exact Stat mismatch permanently blocks deletion and retains provider bytes.
# The provider object may have been replaced outside Skydriver; guessing from its
# key or treating ETag as a content hash would violate complete-object identity.
retry_source="$state_directory/lifecycle-identity-mismatch"
retry_readback="$state_directory/lifecycle-identity-mismatch-readback"
printf 'provider-identity-mismatch!!\n' >"$retry_source"
retry_bytes=$(wc -c <"$retry_source" | tr -d ' ')
retry_sha=$(sha256sum "$retry_source" | cut -d ' ' -f 1)
"${wrangler[@]}" r2 object put \
  carrack-payload-local/lifecycle-fault-injection/identity-mismatch \
  --local --persist-to "$state_directory" --file "$retry_source" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "INSERT INTO vfs_files (id, filesystem_id, created_at, updated_at)
   VALUES ('a5555555555555555555555555555555', '$filesystem_id', unixepoch(), unixepoch());
   INSERT INTO vfs_file_versions (
     id, file_id, plaintext_bytes, verification_block_bytes,
     verification_block_count, file_root, block_manifest_sha256,
     block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
     crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes,
     encoded_sha256, created_at
   ) VALUES (
     'b5555555555555555555555555555555', 'a5555555555555555555555555555555',
     $retry_bytes, 4096, 1,
     '1555555555555555555555555555555555555555555555555555555555555555',
     '2555555555555555555555555555555555555555555555555555555555555555',
     1, 'fault/manifests/retry', 'fault-manifest-retry', 'plaintext/v1',
     1, 4096, $retry_bytes, '$retry_sha', unixepoch()
   );
   INSERT INTO vfs_locations (
     id, version_id, driver_id, storage_key, etag, size_bytes, object_sha256,
     created_at, updated_at
   ) VALUES (
     'c5555555555555555555555555555555', 'b5555555555555555555555555555555',
     'r2-default', 'lifecycle-fault-injection/identity-mismatch', 'wrong-etag', $retry_bytes,
     '$retry_sha', unixepoch(), unixepoch()
   );
   UPDATE vfs_locations
   SET state = 'verified', verified_at = unixepoch(), revision = revision + 1,
       updated_at = unixepoch()
   WHERE id = 'c5555555555555555555555555555555';
   UPDATE vfs_locations
   SET state = 'tombstoned', delete_after = unixepoch() - 1,
       revision = revision + 1, updated_at = unixepoch()
   WHERE id = 'c5555555555555555555555555555555';" >/dev/null
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
retry_state=$("${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT state, attempt_count, last_error_code, retry_at, updated_at
   FROM vfs_location_delete_tasks
   WHERE id = 'c5555555555555555555555555555555';" --json)
jq -e '
  .[0].results[0] |
  .state == "blocked" and .attempt_count == 1 and
  .last_error_code == "provider_identity_mismatch" and .retry_at == null
' <<<"$retry_state" >/dev/null
activity=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/activity")
jq -e '
  .active_items[] | select(.id == "c5555555555555555555555555555555") |
  .state == "blocked" and .deadline_at != null and
  .attention_required == true
' <<<"$activity" >/dev/null
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT CASE WHEN state = 'blocked' AND attempt_count = 1
                       AND last_error_code = 'provider_identity_mismatch'
     THEN 1 ELSE 0 END AS accepted
   FROM vfs_location_delete_tasks
   WHERE id = 'c5555555555555555555555555555555';" --json |
  jq -e '.[0].results == [{"accepted":1}]' >/dev/null
"${wrangler[@]}" r2 object get \
  carrack-payload-local/lifecycle-fault-injection/identity-mismatch \
  --local --persist-to "$state_directory" --file "$retry_readback" >/dev/null
cmp "$retry_source" "$retry_readback"

# Abandoned complete uploads and unfinished R2 multipart uploads share the
# hosted lifecycle but retain independent fences. A complete object without
# usable identity is blocked, while an exact multipart abort remains retryable.
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "INSERT INTO driver_instances (
       id, kind, config_json, enabled, revision, created_at, updated_at
   ) VALUES (
       'r2-cleanup-fault', 'r2/v1',
       '{\"endpoint\":\"https://fault.r2.cloudflarestorage.com\",\"bucket\":\"fault\",\"prefix\":\"\",\"managed\":false}',
       1, 1, unixepoch(), unixepoch()
   );
   DELETE FROM vfs_directory_mounts
   WHERE directory_id = '$root_directory_id';
   DELETE FROM vfs_directory_drivers
   WHERE directory_id = '$root_directory_id';
   INSERT INTO vfs_directory_drivers (
       directory_id, driver_id, write_priority, created_by, created_at, updated_at
   ) VALUES (
       '$root_directory_id', 'r2-cleanup-fault', 0, '$principal_id',
       unixepoch(), unixepoch()
   );
   INSERT INTO vfs_directory_mounts (
       directory_id, driver_id, kind, created_by, created_at
   ) VALUES (
       '$root_directory_id', 'r2-cleanup-fault', 'default', '$principal_id', unixepoch()
   );
   INSERT INTO vfs_put_intents (
       id, filesystem_id, principal_id, token_id, directory_id, entry_name,
       expected_entry_revision, expected_file_revision, file_id, version_id,
       location_id, driver_id, storage_key, plaintext_bytes,
       verification_block_bytes, verification_block_count, file_root,
       metadata_root, block_manifest_sha256, block_manifest_bytes,
       block_manifest_r2_key, crypto_suite, key_epoch, encryption_frame_bytes,
       request_sha256, idempotency_key, expires_at, created_at
   ) VALUES (
       'd6666666666666666666666666666666', '$filesystem_id', '$principal_id',
       '$token_id', '$root_directory_id', 'cleanup-fault.bin', 0, 0,
       'a6666666666666666666666666666666',
       'b6666666666666666666666666666666',
       'c6666666666666666666666666666666', 'r2-cleanup-fault',
       'objects/v2/de/dededededededededededededededededededededededede',
       1, 4096, 1,
       '1666666666666666666666666666666666666666666666666666666666666666',
       '2666666666666666666666666666666666666666666666666666666666666666',
       '3666666666666666666666666666666666666666666666666666666666666666',
       1, 'fault/manifests/cleanup',
       'carrack-vfs-aes256gcm-hkdfsha256-v1', 1, 4096,
       '4666666666666666666666666666666666666666666666666666666666666666',
       'cleanup-fault', unixepoch() + 3600, unixepoch()
   );
   INSERT INTO vfs_r2_upload_cleanup_tasks (
       intent_id, driver_revision, created_at, updated_at
   ) VALUES ('d6666666666666666666666666666666', 1, unixepoch(), unixepoch());
   INSERT INTO vfs_put_upload_evidence (
       intent_id, token_id, commit_sha256, block_manifest_r2_version,
       encoded_bytes, encoded_sha256, verification_method, verified_at
   ) VALUES (
       'd6666666666666666666666666666666', '$token_id',
       '5666666666666666666666666666666666666666666666666666666666666666',
       'fault-manifest-version', 1,
       '6666666666666666666666666666666666666666666666666666666666666666',
       'complete_readback', unixepoch()
   );
   UPDATE vfs_put_intents
   SET state = 'expired', revision = revision + 1
   WHERE id = 'd6666666666666666666666666666666';
   INSERT INTO vfs_put_delete_tasks (
       id, driver_revision, evidence_sha256, delete_after, created_at, updated_at
   ) VALUES (
       'd6666666666666666666666666666666', 1,
       '5666666666666666666666666666666666666666666666666666666666666666',
       unixepoch() - 1, unixepoch(), unixepoch()
   );" >/dev/null
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
cleanup_retry_state=$("${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT 'put' AS kind, state, attempt_count, last_error_code, retry_at,
          server_blocked_at, updated_at
   FROM vfs_put_delete_tasks WHERE id = 'd6666666666666666666666666666666'
   UNION ALL
   SELECT 'r2', state, attempt_count, last_error_code, retry_at, NULL, updated_at
   FROM vfs_r2_upload_cleanup_tasks
   WHERE intent_id = 'd6666666666666666666666666666666'
   ORDER BY kind;" --json)
jq -e '
  .[0].results | length == 2 and
  (map(select(.kind == "put"))[0] |
    .state == "failed" and .attempt_count == 1 and
    .last_error_code == "credential_incomplete" and
    .retry_at == null and .server_blocked_at >= .updated_at) and
  (map(select(.kind == "r2"))[0] |
    .state == "failed" and .attempt_count == 1 and
    .last_error_code == "provider_cleanup_failed" and
    .retry_at > .updated_at)
' <<<"$cleanup_retry_state" >/dev/null
r2_retry_at=$(jq -r '.[0].results[] | select(.kind == "r2") | .retry_at' \
  <<<"$cleanup_retry_state")
cleanup_activity=$(curl --silent --show-error --fail-with-body \
  -b "$cookie_jar" "$base_url/api/admin/activity")
jq -e --argjson r2_retry_at "$r2_retry_at" '
  any(.active_items[];
    .kind == "put_cleanup" and
    .id == "d6666666666666666666666666666666" and
    .deadline_at != null and .attention_required == true
  ) and
  any(.active_items[];
    .kind == "r2_upload_cleanup" and
    .id == "d6666666666666666666666666666666" and
    .deadline_at == $r2_retry_at and .attention_required == true
  )
' <<<"$cleanup_activity" >/dev/null
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT CASE WHEN
       (SELECT attempt_count = 1 AND retry_at IS NULL
               AND server_blocked_at IS NOT NULL
        FROM vfs_put_delete_tasks
        WHERE id = 'd6666666666666666666666666666666')
       AND
       (SELECT attempt_count = 1 AND retry_at = $r2_retry_at
        FROM vfs_r2_upload_cleanup_tasks
        WHERE intent_id = 'd6666666666666666666666666666666')
     THEN 1 ELSE 0 END AS accepted;" --json |
  jq -e '.[0].results == [{"accepted":1}]' >/dev/null

# Provider listing failures retain a visible error and a future retry instead
# of spending one Aliyun request on every Cron pass.
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "INSERT INTO driver_instances (
       id, kind, config_json, enabled, revision, created_at, updated_at
   ) VALUES (
       'aliyun-inventory-fault', 'aliyundrive-open/v2',
       '{\"api_base_url\":\"https://openapi.alipan.com\",\"drive_type\":\"resource\",\"root_folder_id\":\"root\",\"upload_part_bytes\":4194304}',
       1, 1, unixepoch(), unixepoch()
   );
   INSERT INTO operator_auth_rate_limits (
       scope, subject, window_started_at, attempts, blocked_until, updated_at
   ) VALUES (
       'login_ip',
       'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
       1, 1, 1, 1
   );" >/dev/null
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
inventory_retry_state=$("${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT state, attempt_count, last_error_code, next_scan_at, updated_at
   FROM vfs_provider_inventory_state
   WHERE driver_id = 'aliyun-inventory-fault';" --json)
jq -e '
  .[0].results[0] |
  .state == "error" and .attempt_count == 1 and
  .last_error_code == "provider_list_failed" and .next_scan_at > .updated_at
' <<<"$inventory_retry_state" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT CASE WHEN NOT EXISTS (
       SELECT 1 FROM operator_auth_rate_limits
       WHERE subject = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
     ) THEN 1 ELSE 0 END AS accepted;" --json |
  jq -e '.[0].results == [{"accepted":1}]' >/dev/null
inventory_retry_at=$(jq -r '.[0].results[0].next_scan_at' \
  <<<"$inventory_retry_state")
curl --silent --show-error --fail-with-body \
  "$base_url/cdn-cgi/handler/scheduled?cron=*+*+*+*+*" >/dev/null
"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "SELECT CASE WHEN state = 'error' AND attempt_count = 1
                       AND next_scan_at = $inventory_retry_at
     THEN 1 ELSE 0 END AS accepted
   FROM vfs_provider_inventory_state
   WHERE driver_id = 'aliyun-inventory-fault';" --json |
  jq -e '.[0].results == [{"accepted":1}]' >/dev/null

"${wrangler[@]}" d1 execute SKYDRIVER_INDEX \
  --local --persist-to "$state_directory" --command \
  "CREATE TABLE environment_default_assertions (
       accepted INTEGER NOT NULL CHECK (accepted = 1)
   ) STRICT;
   INSERT INTO environment_default_assertions
   SELECT CASE WHEN
     (SELECT retired_at IS NOT NULL FROM driver_instances WHERE id = 'legacy-empty')
     AND (SELECT lifecycle_owner = 'environment' FROM driver_instances
          WHERE id = 'r2-default')
     AND (SELECT COUNT(*) FROM driver_quota_policies
          WHERE driver_id = 'r2-default'
            AND revision = 2
            AND max_physical_bytes = 107374182400) = 1
     AND (SELECT COUNT(*) FROM vfs_audit_events
          WHERE event_kind = 'environment.driver.materialized'
            AND subject_id = 'r2-default') = 1
     AND (SELECT COUNT(*) FROM vfs_audit_events
          WHERE event_kind = 'driver.retired'
            AND subject_id = 'legacy-empty') = 1
     AND NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check)
   THEN 1 ELSE 0 END;
   DROP TABLE environment_default_assertions;" >/dev/null
