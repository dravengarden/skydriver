#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state_directory=$(mktemp -d)

cleanup() {
  rm -rf "$state_directory"
}
trap cleanup EXIT

database_path="$state_directory/query-plans.sqlite"
for migration in "$repository_root"/control-plane/migrations/*.sql; do
  sqlite3 -bail "$database_path" <"$migration"
done

assert_uses_index() {
  local label=$1
  local index=$2
  local query=$3
  local plan
  plan=$(sqlite3 -batch -noheader "$database_path" "EXPLAIN QUERY PLAN $query")
  if [[ $plan != *"$index"* ]]; then
    printf '%s\n' "$plan" >&2
    echo "$label does not use $index" >&2
    exit 1
  fi
}

# Operator Activity must not scan retained terminal history.
assert_uses_index activity-upload idx_vfs_put_intents_expiry \
  "SELECT id FROM vfs_put_intents
   WHERE state = 'prepared' AND expires_at > 1
   ORDER BY created_at DESC, id LIMIT 100"

assert_uses_index activity-download idx_vfs_read_leases_expiry \
  "SELECT lease.id FROM vfs_read_leases AS lease
   JOIN vfs_locations AS location ON location.id = lease.location_id
   WHERE lease.completed_at IS NULL AND lease.expires_at > 1
   ORDER BY lease.created_at DESC, lease.id LIMIT 100"

assert_uses_index activity-location-delete idx_vfs_location_delete_tasks_claim \
  "SELECT id FROM vfs_location_delete_tasks
   WHERE state IN ('pending', 'claimed', 'retry', 'blocked')
   ORDER BY updated_at DESC, id LIMIT 100"

assert_uses_index activity-put-cleanup idx_vfs_put_delete_tasks_claimable \
  "SELECT task.id FROM vfs_put_delete_tasks AS task
   JOIN vfs_put_intents AS intent ON intent.id = task.id
   WHERE task.state IN ('pending', 'claimed', 'failed')
   ORDER BY task.updated_at DESC, task.id LIMIT 100"

assert_uses_index activity-r2-cleanup idx_vfs_r2_cleanup_activity \
  "SELECT task.intent_id FROM vfs_r2_upload_cleanup_tasks AS task
   CROSS JOIN vfs_put_intents AS intent ON intent.id = task.intent_id
   WHERE task.state IN ('active', 'cleaning', 'failed')
     AND (task.state IN ('cleaning', 'failed')
          OR intent.state IN ('expired', 'abandoned'))
   ORDER BY task.updated_at DESC, task.intent_id LIMIT 100"

assert_uses_index activity-credential-refresh idx_driver_credential_refreshes_activity \
  "SELECT credential_id FROM driver_credential_refreshes
   WHERE state IN ('claimed', 'retry', 'reauth_required')
   ORDER BY updated_at DESC, credential_id LIMIT 100"

assert_uses_index management-event-page "USING INTEGER PRIMARY KEY" \
  "SELECT id, event_kind FROM vfs_audit_events
   WHERE id > 1 AND id <= 1000
   ORDER BY id LIMIT 101"

# Cron retention and claim loops are bounded only when their deadline indexes
# remain usable by the exact production predicates.
assert_uses_index read-lease-retirement idx_vfs_read_leases_retirement \
  "SELECT id FROM vfs_read_leases
   WHERE COALESCE(completed_at, expires_at) <= 1
   ORDER BY COALESCE(completed_at, expires_at), id LIMIT 1000"

assert_uses_index r2-cleanup-retirement idx_vfs_r2_cleanup_evidence_retirement \
  "SELECT intent_id FROM vfs_r2_upload_cleanup_tasks
   WHERE state IN ('cleaned', 'superseded') AND completed_at <= 1
   ORDER BY completed_at, intent_id LIMIT 250"

assert_uses_index credential-refresh-claim idx_driver_credential_refreshes_claimable \
  "SELECT driver_id FROM driver_credential_refreshes
   WHERE state IN ('ready', 'retry', 'claimed')
     AND (NULL IS NULL OR driver_id = NULL)
     AND ((state = 'ready' AND refresh_after <= 1)
       OR (state = 'retry' AND retry_at <= 1)
       OR (state = 'claimed' AND lease_expires_at <= 1))
   ORDER BY COALESCE(retry_at, refresh_after), driver_id LIMIT 1"

assert_uses_index catalog-outbox-claim idx_vfs_catalog_outbox_claimable \
  "SELECT outbox.revision_id FROM vfs_catalog_outbox AS outbox
   JOIN vfs_catalog_revisions AS revision ON revision.id = outbox.revision_id
   JOIN vfs_catalog_mutation_heads AS head
     ON head.filesystem_id = revision.filesystem_id
    AND head.revision_id = revision.id
   WHERE revision.state = 'pending'
     AND outbox.state != 'done'
     AND outbox.state IN ('pending', 'claimed')
     AND NOT EXISTS (
       SELECT 1 FROM vfs_catalog_revision_collapses AS collapse
       WHERE collapse.revision_id = revision.id
     )
     AND (outbox.state = 'pending'
       OR (outbox.state = 'claimed' AND outbox.lease_expires_at <= 1))
   ORDER BY outbox.updated_at, outbox.revision_id LIMIT 1"

assert_uses_index location-tombstone-queue idx_vfs_locations_tombstone_deadline \
  "SELECT location.id FROM vfs_locations AS location
   JOIN driver_instances AS driver ON driver.id = location.driver_id
   WHERE location.state = 'tombstoned' AND location.delete_after IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM vfs_location_delete_tasks AS task
       WHERE task.id = location.id
     )
   ORDER BY location.delete_after, location.id LIMIT 100"

assert_uses_index location-delete-claim idx_vfs_location_delete_tasks_claim \
  "SELECT id FROM vfs_location_delete_tasks
   WHERE delete_after <= 1
     AND (state IN ('pending', 'retry')
       OR (state = 'claimed' AND lease_expires_at <= 1))
   ORDER BY delete_after, id LIMIT 1"

assert_uses_index unreachable-version-mark idx_vfs_versions_published_at \
  "SELECT id FROM safe_unreachable_vfs_locations
   WHERE published_at <= 1
   ORDER BY published_at, id LIMIT 100"
