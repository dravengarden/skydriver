PRAGMA foreign_keys = ON;

-- Server-owned cleanup identity for every R2 Put grant. This covers clients
-- that disappear after a single PUT, after multipart initiation, or after
-- multipart completion but before publishing provider evidence.
CREATE TABLE vfs_r2_upload_cleanup_tasks (
    intent_id TEXT PRIMARY KEY REFERENCES vfs_put_intents(id) ON DELETE CASCADE,
    driver_revision INTEGER NOT NULL CHECK (driver_revision > 0),
    upload_id TEXT CHECK (
        upload_id IS NULL OR length(CAST(upload_id AS BLOB)) BETWEEN 1 AND 1024
    ),
    state TEXT NOT NULL DEFAULT 'active' CHECK (
        state IN ('active', 'cleaning', 'failed', 'cleaned', 'superseded')
    ),
    fencing_token INTEGER NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    lease_expires_at INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_code TEXT,
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    completed_at INTEGER,
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    CHECK ((state = 'cleaning') = (lease_expires_at IS NOT NULL)),
    CHECK ((state IN ('cleaned', 'superseded')) = (completed_at IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX idx_vfs_r2_cleanup_upload
ON vfs_r2_upload_cleanup_tasks(upload_id)
WHERE upload_id IS NOT NULL;

CREATE INDEX idx_vfs_r2_cleanup_claim
ON vfs_r2_upload_cleanup_tasks(state, lease_expires_at, intent_id)
WHERE state IN ('active', 'cleaning', 'failed');

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
          AND driver.kind = 'r2/v1'
          AND driver.enabled = 1
          AND driver.revision = NEW.driver_revision
    ) THEN RAISE(ABORT, 'R2 cleanup task requires a live pinned Put') END;
END;

CREATE TRIGGER protect_vfs_r2_cleanup_identity
BEFORE UPDATE OF intent_id, driver_revision, created_at
ON vfs_r2_upload_cleanup_tasks
BEGIN
    SELECT RAISE(ABORT, 'R2 cleanup task identity is immutable');
END;

CREATE TRIGGER supersede_vfs_r2_cleanup_on_receipt
AFTER INSERT ON vfs_put_receipts
BEGIN
    UPDATE vfs_r2_upload_cleanup_tasks
    SET state = 'superseded', lease_expires_at = NULL,
        completed_at = unixepoch(), updated_at = unixepoch()
    WHERE intent_id = NEW.intent_id AND state IN ('active', 'cleaning', 'failed');
END;

CREATE VIEW safe_vfs_r2_upload_cleanup_tasks AS
SELECT task.intent_id
FROM vfs_r2_upload_cleanup_tasks AS task
JOIN vfs_put_intents AS intent ON intent.id = task.intent_id
JOIN driver_instances AS driver ON driver.id = intent.driver_id
WHERE task.state IN ('active', 'cleaning', 'failed')
  AND intent.state IN ('expired', 'abandoned')
  AND driver.kind = 'r2/v1'
  AND driver.enabled = 1
  AND driver.revision = task.driver_revision
  AND NOT EXISTS (SELECT 1 FROM vfs_put_receipts WHERE intent_id = intent.id)
  AND NOT EXISTS (
      SELECT 1 FROM vfs_locations AS location
      WHERE location.driver_id = intent.driver_id
        AND location.storage_key = intent.storage_key
        AND location.state != 'deleted'
  );
