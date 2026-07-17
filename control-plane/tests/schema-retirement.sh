#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state_directory=$(mktemp -d)

cleanup() {
  rm -rf "$state_directory"
}
trap cleanup EXIT

wrangler=(
  pnpm exec wrangler d1
  --config "$repository_root/control-plane/wrangler.jsonc"
)
retirement_migration="$repository_root/control-plane/migrations/0055_retire_archive_schema.sql"

# Let Miniflare create the exact local D1 database layout, then prepare the
# pre-retirement schema directly so this test can fault-inject migration 0055.
"${wrangler[@]}" execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --command "SELECT 1" >/dev/null

database_path=$(find "$state_directory" -type f -name '*.sqlite' ! -name metadata.sqlite -print -quit)
if [[ -z "$database_path" ]]; then
  echo "local D1 database was not created" >&2
  exit 1
fi

for migration in "$repository_root"/control-plane/migrations/*.sql; do
  if [[ "$migration" == "$retirement_migration" ]]; then
    continue
  fi
  sqlite3 -bail "$database_path" <"$migration"
done

sqlite3 -bail "$database_path" <<'SQL'
INSERT INTO transfer_jobs (
  id, source_uri, destination_uri, transfer_mode, state, created_at, updated_at
) VALUES (
  'retirement-must-stop', 'file:///source', 'file:///destination',
  'direct', 'pending', 1, 1
);
SQL

failure_output="$state_directory/expected-failure.log"
if "${wrangler[@]}" execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --file "$retirement_migration" >"$failure_output" 2>&1; then
  echo "schema retirement unexpectedly accepted a non-empty archive table" >&2
  exit 1
fi
if ! rg -q "CHECK constraint failed: row_count = 0" "$failure_output"; then
  cat "$failure_output" >&2
  echo "schema retirement failed for an unexpected reason" >&2
  exit 1
fi

failure_state=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT
     (SELECT COUNT(*) FROM transfer_jobs),
     EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'clients'),
     EXISTS(
       SELECT 1 FROM sqlite_schema
       WHERE type = 'table' AND name = 'legacy_archive_retirement_assertions'
     );")
if [[ "$failure_state" != "1|1|0" ]]; then
  echo "failed retirement was not atomic: $failure_state" >&2
  exit 1
fi

sqlite3 -bail "$database_path" "DELETE FROM transfer_jobs;"
"${wrangler[@]}" execute CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" \
  --file "$retirement_migration" >/dev/null

legacy_tables=(
  audit_events
  blocks
  chunks
  client_namespace_permissions
  client_token_verifiers
  clients
  compact_intents
  copy_intents
  copy_publication_intents
  copy_publication_locations
  extents
  gc_candidates
  gc_delete_tasks
  gc_epochs
  gc_intents
  gc_version_references
  import_intents
  integrity_findings
  integrity_observations
  inventory_completions
  inventory_intents
  inventory_report_objects
  inventory_report_pages
  leases
  locations
  logical_objects
  move_delete_tasks
  move_intents
  move_sources
  move_tombstone_intents
  namespaces
  object_blocks
  object_versions
  objects
  operation_attempts
  operation_components
  operations
  pack_entries
  packs
  publication_intents
  quarantine_action_completions
  quarantine_action_intents
  quarantine_delete_tasks
  quarantined_provider_objects
  reconcile_completions
  reconcile_intents
  reconcile_observations
  recovery_manifests
  repair_completion_objects
  repair_completions
  repair_intents
  repair_objects
  repair_targets
  replicas
  restore_intents
  telemetry_minute_buckets
  telemetry_rollups
  transfer_jobs
  verify_completions
  verify_intents
  version_chunks
  version_packs
  vfs_principal_clients
)
legacy_views=(
  gc_active_version_leases
  gc_markable_locations
  gc_protected_locations
  inventory_missing_subjects
  inventory_report_attempts
  inventory_report_counts
  safe_gc_delete_tasks
  safe_move_delete_tasks
  safe_quarantine_delete_tasks
)
required_schema=(
  admin_configuration_sessions
  admin_sessions
  control_plane_state
  credential_envelopes
  driver_authorization_claims
  driver_credential_refreshes
  driver_instances
  driver_quota_policies
  management_mutation_receipts
  safe_unreachable_vfs_locations
  vfs_catalog_delta_artifacts
  vfs_catalog_revisions
  vfs_directories
  vfs_directory_mounts
  vfs_files
  vfs_filesystems
  vfs_file_versions
  vfs_location_delete_tasks
  vfs_locations
  vfs_principals
)

sql_names() {
  local names=()
  local name
  for name in "$@"; do
    names+=("'$name'")
  done
  local joined
  local IFS=,
  joined="${names[*]}"
  printf '%s' "$joined"
}

legacy_table_names=$(sql_names "${legacy_tables[@]}")
legacy_object_names=$(sql_names "${legacy_tables[@]}" "${legacy_views[@]}")
required_names=$(sql_names "${required_schema[@]}")

remaining_legacy=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM sqlite_schema
    WHERE name IN ($legacy_object_names) OR tbl_name IN ($legacy_table_names);")
if [[ "$remaining_legacy" != "0" ]]; then
  echo "$remaining_legacy legacy schema objects remain after retirement" >&2
  exit 1
fi

required_count=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ($required_names);")
if [[ "$required_count" != "${#required_schema[@]}" ]]; then
  echo "schema retirement removed required VFS schema" >&2
  exit 1
fi

foreign_key_errors=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM pragma_foreign_key_check;")
if [[ "$foreign_key_errors" != "0" ]]; then
  echo "$foreign_key_errors foreign-key errors remain after schema retirement" >&2
  exit 1
fi
