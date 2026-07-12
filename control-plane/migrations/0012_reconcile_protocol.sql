PRAGMA foreign_keys = ON;

CREATE TABLE reconcile_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES object_versions(id),
    manifest_sha256 TEXT NOT NULL,
    recovery_revision INTEGER NOT NULL CHECK (recovery_revision > 0),
    minimum_available_replicas INTEGER NOT NULL CHECK (
        minimum_available_replicas BETWEEN 1 AND 64
    ),
    created_at INTEGER NOT NULL,
    UNIQUE (operation_id, version_id, manifest_sha256, recovery_revision)
) STRICT;

CREATE INDEX idx_reconcile_intents_version
ON reconcile_intents(version_id, recovery_revision);

CREATE TRIGGER reconcile_intent_requires_published_recovery
BEFORE INSERT ON reconcile_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM object_versions AS version
        JOIN recovery_manifests AS recovery ON recovery.version_id = version.id
        WHERE version.id = NEW.version_id
          AND version.state = 'published'
          AND version.manifest_sha256 = NEW.manifest_sha256
          AND recovery.manifest_sha256 = NEW.manifest_sha256
          AND recovery.revision = NEW.recovery_revision
          AND recovery.state = 'durable'
          AND recovery.verified_at IS NOT NULL
    ) THEN RAISE(ABORT, 'reconcile intent requires published durable recovery') END;
END;
