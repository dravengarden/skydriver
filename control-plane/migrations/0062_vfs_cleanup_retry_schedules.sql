PRAGMA foreign_keys = ON;

-- Abandoned Put deletion and R2 upload cleanup both perform provider I/O.
-- Persist their next eligible attempt so transient provider failures cannot
-- hot-loop on every Cron invocation.
ALTER TABLE vfs_put_delete_tasks ADD COLUMN retry_at INTEGER;

UPDATE vfs_put_delete_tasks
SET retry_at = updated_at
WHERE state = 'failed' AND server_blocked_at IS NULL;

DROP INDEX idx_vfs_put_delete_tasks_claimable;
DROP INDEX idx_vfs_put_delete_tasks_server_claim;

CREATE INDEX idx_vfs_put_delete_tasks_claimable
ON vfs_put_delete_tasks(state, updated_at DESC, id)
WHERE state IN ('pending', 'claimed', 'failed');

CREATE INDEX idx_vfs_put_delete_tasks_server_claim
ON vfs_put_delete_tasks(
    state, retry_at, delete_after, lease_expires_at, id
)
WHERE state IN ('pending', 'claimed', 'failed') AND server_blocked_at IS NULL;

CREATE TRIGGER validate_vfs_put_delete_task_retry_insert
BEFORE INSERT ON vfs_put_delete_tasks
WHEN (NEW.state = 'failed' AND NEW.server_blocked_at IS NULL AND NEW.retry_at IS NULL)
  OR ((NEW.state != 'failed' OR NEW.server_blocked_at IS NOT NULL)
      AND NEW.retry_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'VFS put delete retry schedule must match state');
END;

CREATE TRIGGER validate_vfs_put_delete_task_retry_update
BEFORE UPDATE OF state, server_blocked_at, retry_at ON vfs_put_delete_tasks
WHEN (NEW.state = 'failed' AND NEW.server_blocked_at IS NULL AND NEW.retry_at IS NULL)
  OR ((NEW.state != 'failed' OR NEW.server_blocked_at IS NOT NULL)
      AND NEW.retry_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'VFS put delete retry schedule must match state');
END;

DROP TRIGGER supersede_vfs_put_delete_task_on_location_insert;
CREATE TRIGGER supersede_vfs_put_delete_task_on_location_insert
AFTER INSERT ON vfs_locations
WHEN NEW.state != 'deleted'
BEGIN
    UPDATE vfs_put_delete_tasks
    SET state = 'superseded', owner_token_id = NULL, incarnation = NULL,
        lease_expires_at = NULL, retry_at = NULL, last_error_code = NULL,
        updated_at = unixepoch()
    WHERE id IN (
        SELECT task.id
        FROM vfs_put_delete_tasks AS task
        JOIN vfs_put_intents AS intent ON intent.id = task.id
        WHERE intent.driver_id = NEW.driver_id
          AND intent.storage_key = NEW.storage_key
          AND task.state IN ('pending', 'claimed', 'failed')
    );
END;

DROP TRIGGER supersede_vfs_put_delete_task_on_location_update;
CREATE TRIGGER supersede_vfs_put_delete_task_on_location_update
AFTER UPDATE OF state ON vfs_locations
WHEN NEW.state != 'deleted'
BEGIN
    UPDATE vfs_put_delete_tasks
    SET state = 'superseded', owner_token_id = NULL, incarnation = NULL,
        lease_expires_at = NULL, retry_at = NULL, last_error_code = NULL,
        updated_at = unixepoch()
    WHERE id IN (
        SELECT task.id
        FROM vfs_put_delete_tasks AS task
        JOIN vfs_put_intents AS intent ON intent.id = task.id
        WHERE intent.driver_id = NEW.driver_id
          AND intent.storage_key = NEW.storage_key
          AND task.state IN ('pending', 'claimed', 'failed')
    );
END;

ALTER TABLE vfs_r2_upload_cleanup_tasks ADD COLUMN retry_at INTEGER;

UPDATE vfs_r2_upload_cleanup_tasks
SET retry_at = updated_at
WHERE state = 'failed';

DROP INDEX idx_vfs_r2_cleanup_claim;

CREATE INDEX idx_vfs_r2_cleanup_claim
ON vfs_r2_upload_cleanup_tasks(
    state, retry_at, lease_expires_at, intent_id
)
WHERE state IN ('active', 'cleaning', 'failed');

CREATE TRIGGER validate_vfs_r2_cleanup_retry_insert
BEFORE INSERT ON vfs_r2_upload_cleanup_tasks
WHEN (NEW.state = 'failed' AND NEW.retry_at IS NULL)
  OR (NEW.state != 'failed' AND NEW.retry_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'VFS R2 cleanup retry schedule must match state');
END;

CREATE TRIGGER validate_vfs_r2_cleanup_retry_update
BEFORE UPDATE OF state, retry_at ON vfs_r2_upload_cleanup_tasks
WHEN (NEW.state = 'failed' AND NEW.retry_at IS NULL)
  OR (NEW.state != 'failed' AND NEW.retry_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'VFS R2 cleanup retry schedule must match state');
END;

DROP TRIGGER supersede_vfs_r2_cleanup_on_receipt;
CREATE TRIGGER supersede_vfs_r2_cleanup_on_receipt
AFTER INSERT ON vfs_put_receipts
BEGIN
    UPDATE vfs_r2_upload_cleanup_tasks
    SET state = 'superseded', lease_expires_at = NULL, retry_at = NULL,
        completed_at = unixepoch(), updated_at = unixepoch()
    WHERE intent_id = NEW.intent_id AND state IN ('active', 'cleaning', 'failed');
END;
