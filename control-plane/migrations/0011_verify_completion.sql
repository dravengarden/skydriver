PRAGMA foreign_keys = ON;

ALTER TABLE integrity_observations ADD COLUMN lease_id TEXT;
ALTER TABLE integrity_observations ADD COLUMN incarnation TEXT;
ALTER TABLE integrity_observations ADD COLUMN fencing_token INTEGER;

CREATE TABLE verify_completions (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    report_sha256 TEXT NOT NULL UNIQUE CHECK (length(report_sha256) = 64),
    verified_count INTEGER NOT NULL CHECK (verified_count >= 0),
    missing_count INTEGER NOT NULL CHECK (missing_count >= 0),
    corrupt_count INTEGER NOT NULL CHECK (corrupt_count >= 0),
    unavailable_count INTEGER NOT NULL CHECK (unavailable_count >= 0),
    state TEXT NOT NULL DEFAULT 'staging' CHECK (state IN ('staging', 'committed')),
    completed_at INTEGER NOT NULL,
    committed_at INTEGER
) STRICT;

CREATE TRIGGER verify_completion_commit_requires_closed_operation
BEFORE UPDATE OF state ON verify_completions
WHEN NEW.state = 'committed' AND OLD.state = 'staging'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM operations AS operation
        JOIN operation_components AS component
          ON component.id = operation.id || '/verify'
        JOIN leases AS lease ON lease.operation_id = operation.id
        WHERE operation.id = NEW.operation_id
          AND operation.kind = 'verify'
          AND operation.state = 'succeeded'
          AND component.state = 'succeeded'
          AND lease.lease_kind = 'write'
          AND lease.released_at IS NOT NULL
    ) THEN RAISE(ABORT, 'verify completion requires closed operation and lease') END;
END;

DROP TRIGGER integrity_observation_requires_live_verify_fence;

CREATE TRIGGER integrity_observation_requires_live_verify_fence
BEFORE INSERT ON integrity_observations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM verify_intents AS intent
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN locations AS location ON location.id = NEW.location_id
        JOIN extents AS extent ON extent.id = location.extent_id
        JOIN version_packs AS version_pack ON version_pack.pack_id = extent.pack_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE intent.operation_id = NEW.operation_id
          AND operation.kind = 'verify'
          AND operation.state = 'running'
          AND version_pack.version_id = intent.version_id
          AND location.driver_id = intent.driver_id
          AND location.state = 'available'
          AND lease.owner_client_id = operation.requested_by
          AND lease.id = NEW.lease_id
          AND lease.lease_kind = 'write'
          AND lease.incarnation = NEW.incarnation
          AND lease.fencing_token = NEW.fencing_token
          AND lease.incarnation = control.incarnation
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
          AND control.mode = 'active'
    ) THEN RAISE(ABORT, 'integrity observation requires live verify fence') END;
END;
