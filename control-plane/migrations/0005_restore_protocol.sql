CREATE TABLE restore_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES object_versions(id),
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64),
    created_at INTEGER NOT NULL,
    UNIQUE (operation_id, version_id),
    UNIQUE (operation_id, manifest_sha256)
) STRICT;

CREATE INDEX idx_restore_intents_version
ON restore_intents(version_id);
