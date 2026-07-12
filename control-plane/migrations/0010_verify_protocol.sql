PRAGMA foreign_keys = ON;

CREATE TABLE verify_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES object_versions(id),
    manifest_sha256 TEXT NOT NULL,
    recovery_revision INTEGER NOT NULL CHECK (recovery_revision > 0),
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    created_at INTEGER NOT NULL,
    UNIQUE (operation_id, version_id, manifest_sha256, recovery_revision, driver_id)
) STRICT;

CREATE TABLE integrity_observations (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    location_id TEXT NOT NULL REFERENCES locations(id),
    condition TEXT NOT NULL CHECK (
        condition IN ('verified', 'missing', 'corrupt', 'driver_unavailable')
    ),
    evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (operation_id, location_id)
) STRICT;

CREATE INDEX idx_verify_intents_driver_version
ON verify_intents(driver_id, version_id);

CREATE INDEX idx_integrity_observations_location_time
ON integrity_observations(location_id, observed_at);

CREATE TRIGGER verify_intent_requires_published_recovery
BEFORE INSERT ON verify_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM object_versions AS version
        JOIN recovery_manifests AS recovery ON recovery.version_id = version.id
        JOIN locations AS location ON location.extent_id IN (
            SELECT extent.id
            FROM version_packs AS version_pack
            JOIN packs AS pack ON pack.id = version_pack.pack_id
            JOIN extents AS extent ON extent.pack_id = pack.id
            WHERE version_pack.version_id = version.id
        )
        WHERE version.id = NEW.version_id
          AND version.state = 'published'
          AND version.manifest_sha256 = NEW.manifest_sha256
          AND recovery.manifest_sha256 = NEW.manifest_sha256
          AND recovery.revision = NEW.recovery_revision
          AND recovery.state = 'durable'
          AND recovery.verified_at IS NOT NULL
          AND location.driver_id = NEW.driver_id
          AND location.state = 'available'
    ) THEN RAISE(ABORT, 'verify intent requires published durable recovery and available driver locations') END;
END;

CREATE TRIGGER integrity_observation_requires_live_verify_fence
BEFORE INSERT ON integrity_observations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM verify_intents AS intent
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN locations AS location ON location.id = NEW.location_id
        JOIN extents AS extent ON extent.id = location.extent_id
        JOIN packs AS pack ON pack.id = extent.pack_id
        JOIN version_packs AS version_pack ON version_pack.pack_id = pack.id
        WHERE intent.operation_id = NEW.operation_id
          AND operation.kind = 'verify'
          AND operation.state = 'running'
          AND version_pack.version_id = intent.version_id
          AND location.driver_id = intent.driver_id
          AND location.state = 'available'
    ) THEN RAISE(ABORT, 'integrity observation is outside verify intent') END;
END;
