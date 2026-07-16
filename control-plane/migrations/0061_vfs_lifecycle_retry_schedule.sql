PRAGMA foreign_keys = ON;

-- Provider deletion failures are retryable, but they must not hot-loop on
-- every Cron pass. The exact provider identity remains immutable while this
-- timestamp schedules bounded exponential retry.
ALTER TABLE vfs_location_delete_tasks ADD COLUMN retry_at INTEGER;

UPDATE vfs_location_delete_tasks
SET retry_at = updated_at
WHERE state = 'retry';

DROP INDEX idx_vfs_location_delete_tasks_claim;

CREATE INDEX idx_vfs_location_delete_tasks_claim
ON vfs_location_delete_tasks(
    state, retry_at, delete_after, lease_expires_at, id
);

CREATE TRIGGER validate_vfs_location_delete_task_retry_insert
BEFORE INSERT ON vfs_location_delete_tasks
WHEN (NEW.state = 'retry' AND NEW.retry_at IS NULL)
  OR (NEW.state != 'retry' AND NEW.retry_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'VFS location delete retry schedule must match state');
END;

CREATE TRIGGER validate_vfs_location_delete_task_retry_update
BEFORE UPDATE OF state, retry_at ON vfs_location_delete_tasks
WHEN (NEW.state = 'retry' AND NEW.retry_at IS NULL)
  OR (NEW.state != 'retry' AND NEW.retry_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'VFS location delete retry schedule must match state');
END;
