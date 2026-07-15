#!/usr/bin/env bash
set -euo pipefail

curl() {
  command curl \
    --header "Carrack-Protocol-Epoch: 2" \
    --header "Carrack-SDK-Version: 0.3.1" \
    "$@"
}

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state_directory=$(mktemp -d)
server_log="$state_directory/wrangler.log"
cookie_jar="$state_directory/cookies.txt"
port=${CARRACK_ENVIRONMENT_DEFAULTS_TEST_PORT:-8795}
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

wrangler=(
  pnpm exec wrangler
  --config "$repository_root/control-plane/wrangler.jsonc"
)

"${wrangler[@]}" d1 migrations apply CARRACK_INDEX \
  --local --persist-to "$state_directory" >/dev/null

"${wrangler[@]}" d1 execute CARRACK_INDEX \
  --local --persist-to "$state_directory" --command \
  "INSERT INTO driver_instances (
       id, kind, config_json, credential_ref, enabled, revision,
       created_at, updated_at, lifecycle_owner
   ) VALUES (
       'legacy-empty', 'local-filesystem/v2', '{\"root\":\"/tmp/legacy-empty\"}',
       NULL, 0, 1, unixepoch(), unixepoch(), 'legacy-bootstrap'
   );" >/dev/null

admin_token=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA
r2_endpoint=https://0123456789abcdef.r2.cloudflarestorage.com

"${wrangler[@]}" dev \
  --local \
  --persist-to "$state_directory" \
  --port "$port" \
  --inspector-port 0 \
  --var CARRACK_ENVIRONMENT:dev \
  --var CARRACK_DEFAULT_R2_MAX_PHYSICAL_BYTES:107374182400 \
  --var CARRACK_R2_ENDPOINT:"$r2_endpoint" \
  --var CARRACK_ROOT_KEY_V1:"$admin_token" \
  --var CARRACK_VFS_MASTER_KEY_V1:"$admin_token" \
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
curl --silent --show-error --fail-with-body \
  -c "$cookie_jar" -H "$json" \
  --data "$(jq -cn --arg password "$admin_token" '{password: $password}')" \
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
  "filesystem_name":"Carrack VFS",
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
[[ "$(jq -r '.placements | length' <<<"$directory")" == 0 ]]

"${wrangler[@]}" d1 execute CARRACK_INDEX \
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
