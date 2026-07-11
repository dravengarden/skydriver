PRAGMA foreign_keys = ON;

ALTER TABLE object_versions
ADD COLUMN pack_count INTEGER NOT NULL DEFAULT 0 CHECK (pack_count >= 0);

UPDATE object_versions
SET pack_count = (
    SELECT COUNT(*)
    FROM version_packs
    WHERE version_id = object_versions.id
);

CREATE TABLE publication_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES clients(id),
    namespace_id TEXT NOT NULL REFERENCES namespaces(id),
    object_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    manifest_sha256 TEXT NOT NULL UNIQUE CHECK (length(manifest_sha256) = 64),
    recovery_sha256 TEXT NOT NULL UNIQUE CHECK (length(recovery_sha256) = 64),
    r2_storage_key TEXT NOT NULL UNIQUE CHECK (length(r2_storage_key) BETWEEN 1 AND 4096),
    r2_version TEXT NOT NULL CHECK (length(r2_version) BETWEEN 1 AND 1024),
    sidecar_driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    sidecar_storage_key TEXT NOT NULL CHECK (
        length(sidecar_storage_key) BETWEEN 1 AND 4096
    ),
    expected_object_revision INTEGER NOT NULL CHECK (expected_object_revision > 0),
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    lease_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    state TEXT NOT NULL CHECK (state IN ('staging', 'committed')),
    created_at INTEGER NOT NULL,
    committed_at INTEGER,
    updated_at INTEGER NOT NULL,
    UNIQUE (namespace_id, object_id, generation),
    UNIQUE (sidecar_driver_id, sidecar_storage_key)
) STRICT;

CREATE INDEX idx_publication_intents_state_time
ON publication_intents(state, updated_at);

CREATE TRIGGER committed_publication_requires_current_version
BEFORE UPDATE OF state ON publication_intents
WHEN NEW.state = 'committed' AND OLD.state != 'committed'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM control_plane_state AS state
        JOIN leases AS lease
          ON lease.id = NEW.lease_id
         AND lease.operation_id = NEW.operation_id
         AND lease.owner_client_id = NEW.client_id
         AND lease.incarnation = state.incarnation
         AND lease.fencing_token = NEW.fencing_token
         AND lease.released_at IS NULL
         AND lease.expires_at > unixepoch()
        WHERE state.singleton = 1
          AND state.mode = 'active'
          AND state.incarnation = NEW.incarnation
    ) THEN RAISE(ABORT, 'publication commit requires the current live fence') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM objects AS object
        JOIN object_versions AS version
          ON version.object_id = object.id
         AND version.generation = object.current_generation
        WHERE object.id = NEW.object_id
          AND object.namespace_id = NEW.namespace_id
          AND object.current_generation = NEW.generation
          AND version.manifest_sha256 = NEW.manifest_sha256
          AND version.state = 'published'
    ) THEN RAISE(ABORT, 'publication commit requires the current published version') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM recovery_manifests
        WHERE manifest_sha256 = NEW.manifest_sha256
          AND state = 'durable'
          AND r2_storage_key = NEW.r2_storage_key
          AND sidecar_driver_id = NEW.sidecar_driver_id
          AND sidecar_storage_key = NEW.sidecar_storage_key
    ) THEN RAISE(ABORT, 'publication commit requires both recovery copies') END;
END;

CREATE TRIGGER published_version_requires_complete_manifest_shape
BEFORE UPDATE OF state ON object_versions
WHEN NEW.state = 'published' AND OLD.state != 'published'
BEGIN
    SELECT CASE WHEN (
        SELECT COUNT(*) FROM version_packs WHERE version_id = NEW.id
    ) != NEW.pack_count
    THEN RAISE(ABORT, 'published version pack count is incomplete') END;

    SELECT CASE WHEN (
        SELECT COUNT(*)
        FROM version_packs AS version_pack
        JOIN extents AS extent ON extent.pack_id = version_pack.pack_id
        WHERE version_pack.version_id = NEW.id
    ) != NEW.chunk_count
    THEN RAISE(ABORT, 'published version extent count is incomplete') END;
END;

CREATE TRIGGER immutable_published_version_shape
BEFORE UPDATE OF pack_count ON object_versions
WHEN OLD.state IN ('published', 'retired', 'tombstoned')
BEGIN
    SELECT RAISE(ABORT, 'published object version shape is immutable');
END;

CREATE TRIGGER location_storage_range_must_cover_extent
BEFORE INSERT ON locations
WHEN NEW.storage_length != NEW.ciphertext_bytes
BEGIN
    SELECT RAISE(ABORT, 'location storage range must cover its extent');
END;
