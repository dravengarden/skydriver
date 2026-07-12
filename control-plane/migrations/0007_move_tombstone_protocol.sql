PRAGMA foreign_keys = ON;

CREATE TABLE move_intents (
    operation_id TEXT PRIMARY KEY REFERENCES copy_intents(operation_id) ON DELETE CASCADE,
    source_driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    expected_source_location_count INTEGER NOT NULL CHECK (
        expected_source_location_count > 0
    ),
    minimum_available_replicas INTEGER NOT NULL CHECK (
        minimum_available_replicas BETWEEN 1 AND 64
    ),
    grace_seconds INTEGER NOT NULL CHECK (grace_seconds BETWEEN 60 AND 31536000),
    state TEXT NOT NULL CHECK (
        state IN (
            'copying',
            'destination_published',
            'source_delete_pending',
            'deleting',
            'succeeded',
            'failed'
        )
    ),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE move_sources (
    operation_id TEXT NOT NULL REFERENCES move_intents(operation_id) ON DELETE CASCADE,
    location_id TEXT NOT NULL REFERENCES locations(id),
    location_revision INTEGER NOT NULL CHECK (location_revision > 0),
    state TEXT NOT NULL CHECK (
        state IN ('planned', 'tombstoned', 'delete_pending', 'deleted', 'cancelled')
    ),
    tombstone_revision INTEGER CHECK (
        tombstone_revision IS NULL OR tombstone_revision > location_revision
    ),
    grace_until INTEGER,
    deleted_at INTEGER,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (operation_id, location_id)
) STRICT;

CREATE TABLE move_tombstone_intents (
    operation_id TEXT PRIMARY KEY REFERENCES move_intents(operation_id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES clients(id),
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256) = 64
        AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_recovery_sha256 TEXT NOT NULL CHECK (
        length(source_recovery_sha256) = 64
        AND source_recovery_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_recovery_revision INTEGER NOT NULL CHECK (source_recovery_revision > 1),
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
    expected_source_location_count INTEGER NOT NULL CHECK (
        expected_source_location_count > 0
    ),
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    lease_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    state TEXT NOT NULL CHECK (state IN ('staging', 'committed')),
    created_at INTEGER NOT NULL,
    committed_at INTEGER,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_move_intents_state_time
ON move_intents(state, updated_at);

CREATE INDEX idx_move_sources_state_grace
ON move_sources(state, grace_until, updated_at);

CREATE INDEX idx_move_tombstone_intents_state_time
ON move_tombstone_intents(state, updated_at);

DROP TRIGGER recovery_manifest_head_update_requires_copy_fence;

CREATE TRIGGER recovery_manifest_head_update_requires_transfer_fence
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
        JOIN operations AS operation ON operation.id = copy.operation_id
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
          AND (
              (operation.kind = 'copy' AND operation.state = 'committing')
              OR (
                  operation.kind = 'move'
                  AND operation.state = 'running'
                  AND operation.phase = 'verifying'
              )
          )
          AND operation.incarnation = state.incarnation
          AND publication.client_id = lease.owner_client_id
          AND publication.incarnation = state.incarnation
          AND publication.incarnation = lease.incarnation
          AND publication.fencing_token = lease.fencing_token
          AND state.mode = 'active'
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
    ) AND NOT EXISTS (
        SELECT 1
        FROM move_intents AS move
        JOIN copy_intents AS copy ON copy.operation_id = move.operation_id
        JOIN move_tombstone_intents AS tombstone
          ON tombstone.operation_id = move.operation_id
        JOIN operations AS operation ON operation.id = move.operation_id
        JOIN leases AS lease
          ON lease.id = tombstone.lease_id
         AND lease.operation_id = move.operation_id
        JOIN control_plane_state AS state ON state.singleton = 1
        WHERE copy.manifest_sha256 = OLD.manifest_sha256
          AND tombstone.source_recovery_sha256 = OLD.recovery_sha256
          AND tombstone.source_recovery_revision = OLD.revision
          AND tombstone.state = 'staging'
          AND tombstone.manifest_sha256 = OLD.manifest_sha256
          AND tombstone.recovery_sha256 = NEW.recovery_sha256
          AND tombstone.r2_storage_key = NEW.r2_storage_key
          AND tombstone.r2_version = NEW.r2_version
          AND tombstone.sidecar_driver_id = NEW.sidecar_driver_id
          AND tombstone.sidecar_storage_key = NEW.sidecar_storage_key
          AND NEW.revision = OLD.revision + 1
          AND operation.kind = 'move'
          AND operation.state = 'running'
          AND operation.phase = 'source_delete_pending'
          AND operation.incarnation = state.incarnation
          AND tombstone.client_id = lease.owner_client_id
          AND tombstone.incarnation = state.incarnation
          AND tombstone.incarnation = lease.incarnation
          AND tombstone.fencing_token = lease.fencing_token
          AND state.mode = 'active'
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
    ) THEN RAISE(ABORT, 'recovery head update requires the current transfer fence') END;
END;

DROP TRIGGER committed_copy_requires_published_recovery;

CREATE TRIGGER committed_replication_requires_published_recovery
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
          AND (
              (operation.kind = 'copy' AND operation.state = 'committing')
              OR (
                  operation.kind = 'move'
                  AND operation.state = 'running'
                  AND operation.phase = 'verifying'
              )
          )
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
    ) THEN RAISE(ABORT, 'replication commit requires the current published recovery') END;

    SELECT CASE WHEN (
        SELECT COUNT(*)
        FROM copy_publication_locations
        WHERE operation_id = NEW.operation_id
    ) != NEW.expected_location_count
    THEN RAISE(ABORT, 'replication commit requires every staged location') END;

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
    ) THEN RAISE(ABORT, 'replication commit requires verified destination locations') END;
END;

CREATE TRIGGER move_source_tombstone_requires_fence
BEFORE UPDATE OF state ON locations
WHEN OLD.state = 'available'
  AND NEW.state = 'tombstoned'
  AND EXISTS (
      SELECT 1
      FROM move_sources
      WHERE location_id = OLD.id AND state = 'planned'
  )
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM move_sources AS source
        JOIN move_tombstone_intents AS tombstone
          ON tombstone.operation_id = source.operation_id
        JOIN operations AS operation ON operation.id = source.operation_id
        JOIN leases AS lease
          ON lease.id = tombstone.lease_id
         AND lease.operation_id = source.operation_id
        JOIN control_plane_state AS state ON state.singleton = 1
        WHERE source.location_id = OLD.id
          AND source.state = 'planned'
          AND source.location_revision = OLD.revision
          AND tombstone.state = 'staging'
          AND operation.kind = 'move'
          AND operation.state = 'running'
          AND operation.phase = 'source_delete_pending'
          AND operation.incarnation = state.incarnation
          AND tombstone.client_id = lease.owner_client_id
          AND tombstone.incarnation = state.incarnation
          AND tombstone.incarnation = lease.incarnation
          AND tombstone.fencing_token = lease.fencing_token
          AND state.mode = 'active'
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
    ) THEN RAISE(ABORT, 'move tombstone requires the current live fence') END;
END;

CREATE TRIGGER committed_move_tombstone_requires_safe_sources
BEFORE UPDATE OF state ON move_tombstone_intents
WHEN NEW.state = 'committed' AND OLD.state != 'committed'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM move_intents AS move
        JOIN copy_intents AS copy ON copy.operation_id = move.operation_id
        JOIN operations AS operation ON operation.id = move.operation_id
        JOIN leases AS lease
          ON lease.id = NEW.lease_id
         AND lease.operation_id = move.operation_id
        JOIN control_plane_state AS state ON state.singleton = 1
        JOIN recovery_manifests AS recovery
          ON recovery.manifest_sha256 = copy.manifest_sha256
        WHERE move.operation_id = NEW.operation_id
          AND operation.kind = 'move'
          AND operation.state = 'running'
          AND operation.phase = 'source_delete_pending'
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
          AND recovery.revision = NEW.source_recovery_revision + 1
    ) THEN RAISE(ABORT, 'move tombstone requires the current published recovery') END;

    SELECT CASE WHEN (
        SELECT COUNT(*) FROM move_sources WHERE operation_id = NEW.operation_id
    ) != NEW.expected_source_location_count
    THEN RAISE(ABORT, 'move tombstone requires every pinned source') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM move_sources AS source
        JOIN locations AS location ON location.id = source.location_id
        WHERE source.operation_id = NEW.operation_id
          AND (
              source.state != 'tombstoned'
              OR source.tombstone_revision != location.revision
              OR source.grace_until IS NULL
              OR location.state != 'tombstoned'
              OR location.tombstoned_at IS NULL
          )
    ) THEN RAISE(ABORT, 'move tombstone requires durable source grace records') END;
END;
