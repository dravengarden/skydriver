PRAGMA foreign_keys = ON;

DROP TRIGGER protect_vfs_location_delete_task_identity;

CREATE TRIGGER protect_vfs_location_delete_task_identity
BEFORE UPDATE OF
    id, expected_location_revision, driver_id, driver_revision, storage_key,
    native_id, provider_version, etag, size_bytes, delete_after, created_at
ON vfs_location_delete_tasks
BEGIN
    SELECT RAISE(ABORT, 'VFS location delete task identity is immutable');
END;

CREATE TRIGGER validate_vfs_location_delete_task_transition
BEFORE UPDATE OF state ON vfs_location_delete_tasks
BEGIN
    SELECT CASE WHEN NOT (
        (
            OLD.state IN ('pending', 'retry')
            AND NEW.state = 'claimed'
            AND NEW.fencing_token = OLD.fencing_token + 1
        )
        OR (
            OLD.state = 'claimed'
            AND NEW.state = 'claimed'
            AND OLD.lease_expires_at <= NEW.updated_at
            AND NEW.fencing_token = OLD.fencing_token + 1
        )
        OR (
            OLD.state = 'claimed'
            AND NEW.state IN ('retry', 'blocked', 'deleted')
            AND NEW.fencing_token = OLD.fencing_token
        )
    ) THEN RAISE(ABORT, 'invalid VFS location delete task transition') END;
END;

CREATE TRIGGER validate_completed_vfs_location_delete_task
BEFORE UPDATE OF state ON vfs_location_delete_tasks
WHEN NEW.state = 'deleted'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_locations AS location
        WHERE location.id = NEW.id
          AND location.state = 'deleted'
          AND location.revision = NEW.expected_location_revision + 1
    ) THEN RAISE(ABORT, 'VFS location delete completion requires deleted location') END;
END;
