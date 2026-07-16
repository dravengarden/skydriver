PRAGMA foreign_keys = ON;

-- Inventory is provider API work, not metadata hygiene. Persist a due time so
-- completed scans run daily and transient provider failures back off instead
-- of consuming one listing request on every Cron invocation.
ALTER TABLE vfs_provider_inventory_state ADD COLUMN next_scan_at INTEGER;
ALTER TABLE vfs_provider_inventory_state
ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0);

UPDATE vfs_provider_inventory_state
SET next_scan_at = CASE WHEN state = 'unsupported' THEN NULL ELSE updated_at END;

DROP INDEX vfs_provider_inventory_due;
CREATE INDEX vfs_provider_inventory_due
ON vfs_provider_inventory_state(next_scan_at, driver_id)
WHERE next_scan_at IS NOT NULL;

CREATE TRIGGER validate_vfs_provider_inventory_schedule_insert
BEFORE INSERT ON vfs_provider_inventory_state
WHEN (NEW.state = 'unsupported' AND NEW.next_scan_at IS NOT NULL)
  OR (NEW.state != 'unsupported' AND NEW.next_scan_at IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'provider inventory schedule must match state');
END;

CREATE TRIGGER validate_vfs_provider_inventory_schedule_update
BEFORE UPDATE OF state, next_scan_at ON vfs_provider_inventory_state
WHEN (NEW.state = 'unsupported' AND NEW.next_scan_at IS NOT NULL)
  OR (NEW.state != 'unsupported' AND NEW.next_scan_at IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'provider inventory schedule must match state');
END;
