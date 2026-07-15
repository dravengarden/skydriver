PRAGMA foreign_keys = ON;

-- Drivers created from an environment binding have an immutable identity.
-- Legacy bootstrap drivers remain as durable receipt targets after retirement,
-- but disappear from active management and can never be re-enabled.
ALTER TABLE driver_instances ADD COLUMN lifecycle_owner TEXT NOT NULL DEFAULT 'operator'
CHECK (lifecycle_owner IN ('operator', 'legacy-bootstrap', 'environment'));

ALTER TABLE driver_instances ADD COLUMN retired_at INTEGER
CHECK (retired_at IS NULL OR retired_at > 0);

UPDATE driver_instances
SET lifecycle_owner = 'legacy-bootstrap'
WHERE kind = 'local-filesystem/v2'
  AND id IN (SELECT driver_id FROM vfs_bootstrap_receipts);

CREATE INDEX idx_driver_instances_active
ON driver_instances(id)
WHERE retired_at IS NULL;

CREATE UNIQUE INDEX idx_vfs_audit_environment_driver_lifecycle
ON vfs_audit_events(event_kind, subject_kind, subject_id)
WHERE event_kind IN ('environment.driver.materialized', 'driver.retired');

CREATE TRIGGER protect_driver_lifecycle_owner
BEFORE UPDATE OF lifecycle_owner ON driver_instances
WHEN NEW.lifecycle_owner != OLD.lifecycle_owner
BEGIN
    SELECT RAISE(ABORT, 'driver lifecycle owner is immutable');
END;

CREATE TRIGGER protect_environment_driver_identity
BEFORE UPDATE OF id, kind, config_json ON driver_instances
WHEN OLD.lifecycle_owner = 'environment'
BEGIN
    SELECT RAISE(ABORT, 'environment driver identity is immutable');
END;

CREATE TRIGGER validate_driver_retirement
BEFORE UPDATE OF retired_at ON driver_instances
WHEN OLD.retired_at IS NULL AND NEW.retired_at IS NOT NULL
BEGIN
    SELECT CASE WHEN OLD.lifecycle_owner != 'legacy-bootstrap'
        THEN RAISE(ABORT, 'only a legacy bootstrap driver may retire') END;
    SELECT CASE WHEN NEW.enabled != 0
        THEN RAISE(ABORT, 'enabled driver cannot retire') END;
    SELECT CASE WHEN NEW.revision != OLD.revision + 1 OR NEW.updated_at < OLD.updated_at
        THEN RAISE(ABORT, 'driver retirement requires the next revision') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM vfs_directory_drivers WHERE driver_id = OLD.id
    ) THEN RAISE(ABORT, 'placed driver cannot retire') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM vfs_locations WHERE driver_id = OLD.id
    ) THEN RAISE(ABORT, 'driver with locations cannot retire') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM vfs_put_intents WHERE driver_id = OLD.id
    ) THEN RAISE(ABORT, 'driver with Put history cannot retire') END;
END;

CREATE TRIGGER protect_retired_driver
BEFORE UPDATE ON driver_instances
WHEN OLD.retired_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'retired driver is immutable');
END;

CREATE TRIGGER reserve_environment_default_r2_identity
BEFORE INSERT ON driver_instances
WHEN NEW.id = 'r2-default' AND NEW.lifecycle_owner != 'environment'
BEGIN
    SELECT RAISE(ABORT, 'r2-default is reserved for the environment');
END;

CREATE TRIGGER validate_environment_driver_identity
BEFORE INSERT ON driver_instances
WHEN NEW.lifecycle_owner = 'environment'
 AND (NEW.id != 'r2-default' OR NEW.kind != 'r2/v1')
BEGIN
    SELECT RAISE(ABORT, 'invalid environment driver identity');
END;

CREATE TRIGGER protect_managed_driver_delete
BEFORE DELETE ON driver_instances
WHEN OLD.lifecycle_owner IN ('legacy-bootstrap', 'environment')
BEGIN
    SELECT RAISE(ABORT, 'managed driver identity cannot be deleted');
END;
