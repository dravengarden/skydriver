PRAGMA foreign_keys = ON;

-- Backfill only the untouched unlimited policy created for an existing
-- environment-owned R2 driver. Any operator quota mutation advances the
-- revision and is therefore preserved exactly.
UPDATE driver_quota_policies
SET max_physical_bytes = 107374182400,
    revision = revision + 1,
    updated_at = MAX(updated_at, unixepoch())
WHERE driver_id = 'r2-default'
  AND revision = 1
  AND max_physical_bytes IS NULL
  AND max_object_count IS NULL
  AND EXISTS (
      SELECT 1
      FROM driver_instances AS driver
      WHERE driver.id = driver_quota_policies.driver_id
        AND driver.kind = 'r2/v1'
        AND driver.lifecycle_owner = 'environment'
        AND driver.retired_at IS NULL
  );

INSERT INTO vfs_audit_events (
    filesystem_id, principal_id, token_id, event_kind,
    subject_kind, subject_id, details_json, created_at
)
SELECT NULL, NULL, NULL, 'environment.driver.quota_initialized',
       'driver', 'r2-default',
       json_object(
           'max_physical_bytes', 107374182400,
           'source', 'migration'
       ), unixepoch()
WHERE changes() = 1;
