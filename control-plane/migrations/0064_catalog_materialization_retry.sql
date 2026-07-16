PRAGMA foreign_keys = ON;

-- Manifest R2 and catalog assembly failures may be transient. Keep the
-- immutable revision pending, but make its next eligible claim explicit so a
-- broken head cannot consume every Cron pass.
ALTER TABLE vfs_catalog_outbox ADD COLUMN retry_at INTEGER;

UPDATE vfs_catalog_outbox
SET retry_at = updated_at
WHERE state = 'pending' AND last_error_code IS NOT NULL;

DROP INDEX idx_vfs_catalog_outbox_claimable;
CREATE INDEX idx_vfs_catalog_outbox_claimable
ON vfs_catalog_outbox(state, retry_at, lease_expires_at, updated_at, revision_id)
WHERE state IN ('pending', 'claimed');

CREATE TRIGGER validate_vfs_catalog_outbox_retry_insert
BEFORE INSERT ON vfs_catalog_outbox
WHEN NEW.state != 'pending' AND NEW.retry_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'catalog outbox retry schedule requires pending state');
END;

CREATE TRIGGER validate_vfs_catalog_outbox_retry_update
BEFORE UPDATE OF state, retry_at ON vfs_catalog_outbox
WHEN NEW.state != 'pending' AND NEW.retry_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'catalog outbox retry schedule requires pending state');
END;
