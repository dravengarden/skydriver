PRAGMA foreign_keys = ON;

ALTER TABLE recovery_manifests
ADD COLUMN recovery_sha256 TEXT CHECK (
    recovery_sha256 IS NULL OR (
        length(recovery_sha256) = 64
        AND recovery_sha256 NOT GLOB '*[^0-9a-f]*'
    )
);

ALTER TABLE recovery_manifests
ADD COLUMN r2_version TEXT CHECK (
    r2_version IS NULL OR length(r2_version) BETWEEN 1 AND 1024
);

ALTER TABLE recovery_manifests
ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0);

CREATE UNIQUE INDEX idx_recovery_manifests_recovery_sha256
ON recovery_manifests(recovery_sha256)
WHERE recovery_sha256 IS NOT NULL;

CREATE TABLE copy_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES object_versions(id),
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256) = 64
        AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_recovery_sha256 TEXT NOT NULL CHECK (
        length(source_recovery_sha256) = 64
        AND source_recovery_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_recovery_revision INTEGER NOT NULL CHECK (source_recovery_revision > 0),
    source_r2_storage_key TEXT NOT NULL CHECK (
        length(source_r2_storage_key) BETWEEN 1 AND 4096
    ),
    source_r2_version TEXT NOT NULL CHECK (length(source_r2_version) BETWEEN 1 AND 1024),
    source_recovery_bytes INTEGER NOT NULL CHECK (source_recovery_bytes > 0),
    destination_driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    created_at INTEGER NOT NULL,
    UNIQUE (operation_id, version_id),
    UNIQUE (operation_id, manifest_sha256)
) STRICT;

CREATE TABLE copy_publication_intents (
    operation_id TEXT PRIMARY KEY REFERENCES copy_intents(operation_id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES clients(id),
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256) = 64
        AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_sha256 TEXT NOT NULL CHECK (
        length(recovery_sha256) = 64
        AND recovery_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    r2_storage_key TEXT NOT NULL CHECK (length(r2_storage_key) BETWEEN 1 AND 4096),
    r2_version TEXT NOT NULL CHECK (length(r2_version) BETWEEN 1 AND 1024),
    sidecar_driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    sidecar_storage_key TEXT NOT NULL CHECK (
        length(sidecar_storage_key) BETWEEN 1 AND 4096
    ),
    expected_location_count INTEGER NOT NULL CHECK (expected_location_count >= 0),
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    lease_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    state TEXT NOT NULL CHECK (state IN ('staging', 'committed')),
    created_at INTEGER NOT NULL,
    committed_at INTEGER,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE copy_publication_locations (
    operation_id TEXT NOT NULL REFERENCES copy_publication_intents(operation_id) ON DELETE CASCADE,
    location_id TEXT NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
    PRIMARY KEY (operation_id, location_id)
) STRICT;

CREATE INDEX idx_copy_intents_manifest
ON copy_intents(manifest_sha256, destination_driver_id);

CREATE INDEX idx_copy_publication_intents_state_time
ON copy_publication_intents(state, updated_at);

CREATE TRIGGER recovery_manifest_backfill_preserves_head
BEFORE UPDATE OF recovery_sha256, r2_storage_key, r2_version,
                 sidecar_driver_id, sidecar_storage_key, ciphertext_bytes, revision
ON recovery_manifests
WHEN OLD.recovery_sha256 IS NULL
  AND (
      NEW.r2_storage_key != OLD.r2_storage_key
      OR NEW.sidecar_driver_id != OLD.sidecar_driver_id
      OR NEW.sidecar_storage_key != OLD.sidecar_storage_key
      OR NEW.ciphertext_bytes != OLD.ciphertext_bytes
      OR NEW.revision != OLD.revision
  )
BEGIN
    SELECT RAISE(ABORT, 'recovery identity backfill cannot replace the published head');
END;

CREATE TRIGGER recovery_manifest_head_update_requires_copy_fence
BEFORE UPDATE OF recovery_sha256, r2_storage_key, r2_version,
                 sidecar_driver_id, sidecar_storage_key, ciphertext_bytes, revision
ON recovery_manifests
WHEN OLD.recovery_sha256 IS NOT NULL
  AND (
      NEW.recovery_sha256 IS NOT OLD.recovery_sha256
      OR NEW.r2_storage_key IS NOT OLD.r2_storage_key
      OR NEW.r2_version IS NOT OLD.r2_version
      OR NEW.sidecar_driver_id IS NOT OLD.sidecar_driver_id
      OR NEW.sidecar_storage_key IS NOT OLD.sidecar_storage_key
      OR NEW.ciphertext_bytes != OLD.ciphertext_bytes
      OR NEW.revision != OLD.revision
  )
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM copy_intents AS copy
        JOIN copy_publication_intents AS publication
          ON publication.operation_id = copy.operation_id
        JOIN operations AS operation
          ON operation.id = copy.operation_id
        JOIN leases AS lease
          ON lease.id = publication.lease_id
         AND lease.operation_id = copy.operation_id
        JOIN control_plane_state AS state ON state.singleton = 1
        WHERE copy.manifest_sha256 = OLD.manifest_sha256
          AND copy.source_recovery_sha256 = OLD.recovery_sha256
          AND copy.source_recovery_revision = OLD.revision
          AND publication.state = 'staging'
          AND publication.manifest_sha256 = OLD.manifest_sha256
          AND publication.recovery_sha256 = NEW.recovery_sha256
          AND publication.r2_storage_key = NEW.r2_storage_key
          AND publication.r2_version = NEW.r2_version
          AND publication.sidecar_driver_id = NEW.sidecar_driver_id
          AND publication.sidecar_storage_key = NEW.sidecar_storage_key
          AND NEW.revision = OLD.revision + 1
          AND operation.kind = 'copy'
          AND operation.state = 'committing'
          AND operation.incarnation = state.incarnation
          AND publication.client_id = lease.owner_client_id
          AND publication.incarnation = state.incarnation
          AND publication.incarnation = lease.incarnation
          AND publication.fencing_token = lease.fencing_token
          AND state.mode = 'active'
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
    ) THEN RAISE(ABORT, 'recovery head update requires the current copy fence') END;
END;

CREATE TRIGGER committed_copy_requires_published_recovery
BEFORE UPDATE OF state ON copy_publication_intents
WHEN NEW.state = 'committed' AND OLD.state != 'committed'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM copy_intents AS copy
        JOIN operations AS operation ON operation.id = copy.operation_id
        JOIN leases AS lease
          ON lease.id = NEW.lease_id
         AND lease.operation_id = copy.operation_id
        JOIN control_plane_state AS state ON state.singleton = 1
        JOIN recovery_manifests AS recovery
          ON recovery.manifest_sha256 = copy.manifest_sha256
        WHERE copy.operation_id = NEW.operation_id
          AND operation.kind = 'copy'
          AND operation.state = 'committing'
          AND operation.incarnation = state.incarnation
          AND state.mode = 'active'
          AND NEW.client_id = lease.owner_client_id
          AND NEW.incarnation = state.incarnation
          AND NEW.incarnation = lease.incarnation
          AND NEW.fencing_token = lease.fencing_token
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
          AND recovery.recovery_sha256 = NEW.recovery_sha256
          AND recovery.r2_storage_key = NEW.r2_storage_key
          AND recovery.r2_version = NEW.r2_version
          AND recovery.sidecar_driver_id = NEW.sidecar_driver_id
          AND recovery.sidecar_storage_key = NEW.sidecar_storage_key
          AND recovery.revision = copy.source_recovery_revision + 1
    ) THEN RAISE(ABORT, 'copy commit requires the current published recovery') END;

    SELECT CASE WHEN (
        SELECT COUNT(*)
        FROM copy_publication_locations
        WHERE operation_id = NEW.operation_id
    ) != NEW.expected_location_count
    THEN RAISE(ABORT, 'copy commit requires every staged location') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM copy_publication_locations AS published
        JOIN locations AS location ON location.id = published.location_id
        JOIN copy_intents AS copy ON copy.operation_id = published.operation_id
        WHERE published.operation_id = NEW.operation_id
          AND (
              location.state != 'available'
              OR location.verified_at IS NULL
              OR location.driver_id != copy.destination_driver_id
          )
    ) THEN RAISE(ABORT, 'copy commit requires verified destination locations') END;
END;
