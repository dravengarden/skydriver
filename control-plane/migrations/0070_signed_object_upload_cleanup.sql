PRAGMA foreign_keys = ON;

-- The original table name is retained for migration compatibility, but the
-- durable cleanup protocol now covers every compiled signed-object multipart
-- driver with the same pinned intent and revision fences.
DROP TRIGGER validate_vfs_r2_cleanup_insert;
DROP VIEW safe_vfs_r2_upload_cleanup_tasks;

CREATE TRIGGER validate_vfs_r2_cleanup_insert
BEFORE INSERT ON vfs_r2_upload_cleanup_tasks
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_put_intents AS intent
        JOIN driver_instances AS driver ON driver.id = intent.driver_id
        WHERE intent.id = NEW.intent_id
          AND intent.state = 'prepared'
          AND intent.expires_at > unixepoch()
          AND driver.kind IN ('r2/v1', 'aws-s3/v1')
          AND driver.enabled = 1
          AND driver.revision = NEW.driver_revision
    ) THEN RAISE(ABORT, 'signed-object cleanup task requires a live pinned Put') END;
END;

CREATE VIEW safe_vfs_r2_upload_cleanup_tasks AS
SELECT task.intent_id
FROM vfs_r2_upload_cleanup_tasks AS task
JOIN vfs_put_intents AS intent ON intent.id = task.intent_id
JOIN driver_instances AS driver ON driver.id = intent.driver_id
WHERE task.state IN ('active', 'cleaning', 'failed')
  AND intent.state IN ('expired', 'abandoned')
  AND driver.kind IN ('r2/v1', 'aws-s3/v1')
  AND driver.enabled = 1
  AND driver.revision = task.driver_revision
  AND NOT EXISTS (SELECT 1 FROM vfs_put_receipts WHERE intent_id = intent.id)
  AND NOT EXISTS (
      SELECT 1 FROM vfs_locations AS location
      WHERE location.driver_id = intent.driver_id
        AND location.storage_key = intent.storage_key
        AND location.state != 'deleted'
  );
