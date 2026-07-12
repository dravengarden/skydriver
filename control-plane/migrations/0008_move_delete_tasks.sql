PRAGMA foreign_keys = ON;

CREATE TABLE move_delete_tasks (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES move_intents(operation_id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    storage_key TEXT NOT NULL CHECK (length(storage_key) BETWEEN 1 AND 4096),
    expected_location_count INTEGER NOT NULL CHECK (expected_location_count > 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'deleted', 'failed')),
    owner_client_id TEXT REFERENCES clients(id),
    incarnation TEXT CHECK (incarnation IS NULL OR length(incarnation) = 32),
    fencing_token INTEGER NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    lease_expires_at INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_code TEXT,
    claimed_at INTEGER,
    deleted_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (operation_id, driver_id, storage_key)
) STRICT;

CREATE INDEX idx_move_delete_tasks_claim
ON move_delete_tasks(state, lease_expires_at, updated_at);

CREATE VIEW safe_move_delete_tasks AS
SELECT task.id
FROM move_delete_tasks AS task
JOIN move_intents AS move ON move.operation_id = task.operation_id
JOIN copy_intents AS copy ON copy.operation_id = move.operation_id
JOIN move_tombstone_intents AS tombstone ON tombstone.operation_id = move.operation_id
JOIN operations AS operation ON operation.id = move.operation_id
JOIN control_plane_state AS control ON control.singleton = 1
JOIN recovery_manifests AS recovery ON recovery.manifest_sha256 = copy.manifest_sha256
WHERE move.state IN ('source_delete_pending', 'deleting')
  AND operation.kind = 'move'
  AND operation.state = 'running'
  AND operation.phase IN ('source_delete_pending', 'deleting')
  AND operation.incarnation = control.incarnation
  AND control.mode = 'active'
  AND recovery.recovery_sha256 = tombstone.recovery_sha256
  AND recovery.revision = tombstone.source_recovery_revision + 1
  AND tombstone.state = 'committed'
  AND NOT EXISTS (
      SELECT 1
      FROM leases AS lease
      JOIN restore_intents AS restore ON restore.operation_id = lease.operation_id
      WHERE restore.version_id = copy.version_id
        AND lease.lease_kind = 'read'
        AND lease.incarnation = control.incarnation
        AND lease.released_at IS NULL
        AND lease.expires_at > unixepoch()
  )
  AND NOT EXISTS (
      SELECT 1
      FROM move_sources AS source
      JOIN locations AS location ON location.id = source.location_id
      WHERE source.operation_id = move.operation_id
        AND location.driver_id = task.driver_id
        AND location.storage_key = task.storage_key
        AND (
            source.state != 'tombstoned'
            OR source.grace_until IS NULL
            OR source.grace_until > unixepoch()
            OR location.state != 'tombstoned'
            OR source.tombstone_revision != location.revision
        )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM locations AS shared
      WHERE shared.driver_id = task.driver_id
        AND shared.storage_key = task.storage_key
        AND (
            shared.state NOT IN ('tombstoned', 'deleted')
            OR NOT EXISTS (
                SELECT 1 FROM move_sources AS source
                WHERE source.operation_id = move.operation_id
                  AND source.location_id = shared.id
                  AND source.state IN ('tombstoned', 'deleted')
            )
        )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM move_sources AS source
      JOIN locations AS removed ON removed.id = source.location_id
      WHERE source.operation_id = move.operation_id
        AND removed.driver_id = task.driver_id
        AND removed.storage_key = task.storage_key
        AND (
            SELECT COUNT(*) FROM locations AS replica
            WHERE replica.extent_id = removed.extent_id
              AND replica.state = 'available'
        ) < move.minimum_available_replicas
  )
  AND (
      SELECT COUNT(*)
      FROM move_sources AS source
      JOIN locations AS location ON location.id = source.location_id
      WHERE source.operation_id = move.operation_id
        AND location.driver_id = task.driver_id
        AND location.storage_key = task.storage_key
        AND source.state = 'tombstoned'
        AND location.state = 'tombstoned'
  ) = task.expected_location_count;

CREATE TRIGGER claimed_move_delete_requires_safe_object
BEFORE UPDATE OF state, owner_client_id, incarnation, fencing_token, lease_expires_at
ON move_delete_tasks
WHEN NEW.state = 'claimed'
  AND (
      OLD.state != 'claimed'
      OR NEW.owner_client_id IS NOT OLD.owner_client_id
      OR NEW.incarnation IS NOT OLD.incarnation
      OR NEW.fencing_token != OLD.fencing_token
      OR NEW.lease_expires_at IS NOT OLD.lease_expires_at
  )
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM move_intents AS move
        JOIN copy_intents AS copy ON copy.operation_id = move.operation_id
        JOIN move_tombstone_intents AS tombstone
          ON tombstone.operation_id = move.operation_id
        JOIN operations AS operation ON operation.id = move.operation_id
        JOIN control_plane_state AS control ON control.singleton = 1
        JOIN clients AS client ON client.id = NEW.owner_client_id
        JOIN recovery_manifests AS recovery
          ON recovery.manifest_sha256 = copy.manifest_sha256
        WHERE move.operation_id = NEW.operation_id
          AND move.state IN ('source_delete_pending', 'deleting')
          AND operation.kind = 'move'
          AND operation.state = 'running'
          AND operation.phase IN ('source_delete_pending', 'deleting')
          AND operation.incarnation = control.incarnation
          AND control.mode = 'active'
          AND client.state = 'online'
          AND NEW.incarnation = control.incarnation
          AND NEW.fencing_token > OLD.fencing_token
          AND NEW.lease_expires_at > unixepoch()
          AND recovery.recovery_sha256 = tombstone.recovery_sha256
          AND recovery.revision = tombstone.source_recovery_revision + 1
          AND tombstone.state = 'committed'
          AND EXISTS (
              SELECT 1 FROM client_namespace_permissions
              WHERE client_id = NEW.owner_client_id
                AND namespace_id = operation.namespace_id
                AND role IN ('janitor', 'administrator')
          )
          AND NOT EXISTS (
              SELECT 1
              FROM leases AS lease
              JOIN restore_intents AS restore ON restore.operation_id = lease.operation_id
              WHERE restore.version_id = copy.version_id
                AND lease.lease_kind = 'read'
                AND lease.incarnation = control.incarnation
                AND lease.released_at IS NULL
                AND lease.expires_at > unixepoch()
          )
          AND NOT EXISTS (
              SELECT 1
              FROM move_sources AS source
              JOIN locations AS location ON location.id = source.location_id
              WHERE source.operation_id = move.operation_id
                AND location.driver_id = NEW.driver_id
                AND location.storage_key = NEW.storage_key
                AND (
                    source.state != 'tombstoned'
                    OR source.grace_until IS NULL
                    OR source.grace_until > unixepoch()
                    OR location.state != 'tombstoned'
                    OR source.tombstone_revision != location.revision
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM locations AS shared
              WHERE shared.driver_id = NEW.driver_id
                AND shared.storage_key = NEW.storage_key
                AND (
                    shared.state NOT IN ('tombstoned', 'deleted')
                    OR NOT EXISTS (
                        SELECT 1 FROM move_sources AS source
                        WHERE source.operation_id = move.operation_id
                          AND source.location_id = shared.id
                          AND source.state IN ('tombstoned', 'deleted')
                    )
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM move_sources AS source
              JOIN locations AS removed ON removed.id = source.location_id
              WHERE source.operation_id = move.operation_id
                AND removed.driver_id = NEW.driver_id
                AND removed.storage_key = NEW.storage_key
                AND (
                    SELECT COUNT(*) FROM locations AS replica
                    WHERE replica.extent_id = removed.extent_id
                      AND replica.state = 'available'
                ) < move.minimum_available_replicas
          )
    ) THEN RAISE(ABORT, 'move delete claim requires a safe current object') END;

    SELECT CASE WHEN (
        SELECT COUNT(*)
        FROM move_sources AS source
        JOIN locations AS location ON location.id = source.location_id
        WHERE source.operation_id = NEW.operation_id
          AND location.driver_id = NEW.driver_id
          AND location.storage_key = NEW.storage_key
          AND source.state = 'tombstoned'
          AND location.state = 'tombstoned'
    ) != NEW.expected_location_count
    THEN RAISE(ABORT, 'move delete claim requires every object location') END;
END;

CREATE TRIGGER move_source_delete_requires_task_fence
BEFORE UPDATE OF state ON locations
WHEN OLD.state = 'tombstoned' AND NEW.state = 'deleted'
  AND EXISTS (
      SELECT 1 FROM move_sources
      WHERE location_id = OLD.id AND state = 'tombstoned'
  )
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM move_sources AS source
        JOIN move_delete_tasks AS task ON task.operation_id = source.operation_id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE source.location_id = OLD.id
          AND source.state = 'tombstoned'
          AND task.driver_id = OLD.driver_id
          AND task.storage_key = OLD.storage_key
          AND task.state = 'claimed'
          AND task.incarnation = control.incarnation
          AND task.lease_expires_at > unixepoch()
          AND task.owner_client_id IS NOT NULL
          AND task.fencing_token > 0
          AND control.mode = 'active'
    ) THEN RAISE(ABORT, 'move source delete requires the current task fence') END;
END;

CREATE TRIGGER completed_move_delete_requires_deleted_locations
BEFORE UPDATE OF state ON move_delete_tasks
WHEN NEW.state = 'deleted' AND OLD.state != 'deleted'
BEGIN
    SELECT CASE WHEN OLD.state != 'claimed'
      OR OLD.owner_client_id IS NULL
      OR OLD.incarnation IS NULL
      OR OLD.fencing_token = 0
      OR OLD.lease_expires_at <= unixepoch()
    THEN RAISE(ABORT, 'move delete completion requires a live claim') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM move_sources AS source
        JOIN locations AS location ON location.id = source.location_id
        WHERE source.operation_id = NEW.operation_id
          AND location.driver_id = NEW.driver_id
          AND location.storage_key = NEW.storage_key
          AND (source.state != 'deleted' OR location.state != 'deleted')
    ) THEN RAISE(ABORT, 'move delete completion requires deleted locations') END;

    SELECT CASE WHEN (
        SELECT COUNT(*)
        FROM move_sources AS source
        JOIN locations AS location ON location.id = source.location_id
        WHERE source.operation_id = NEW.operation_id
          AND location.driver_id = NEW.driver_id
          AND location.storage_key = NEW.storage_key
          AND source.state = 'deleted'
          AND location.state = 'deleted'
    ) != NEW.expected_location_count
    THEN RAISE(ABORT, 'move delete completion requires every object location') END;
END;
