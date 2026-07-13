PRAGMA foreign_keys = ON;

-- Completion is accepted only after a distinct final revalidation rotates the
-- fence immediately before provider deletion.
ALTER TABLE vfs_put_delete_tasks
ADD COLUMN revalidated_at INTEGER;

CREATE TRIGGER validate_vfs_put_delete_revalidation
BEFORE UPDATE OF revalidated_at ON vfs_put_delete_tasks
WHEN NEW.revalidated_at IS NOT NULL AND NEW.state != 'claimed'
BEGIN
    SELECT RAISE(ABORT, 'only claimed VFS put delete tasks may be revalidated');
END;
