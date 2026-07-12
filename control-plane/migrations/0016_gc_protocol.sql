PRAGMA foreign_keys = ON;

CREATE TABLE gc_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    cutoff_at INTEGER NOT NULL,
    grace_seconds INTEGER NOT NULL CHECK (grace_seconds BETWEEN 60 AND 31536000),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE gc_delete_tasks (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES gc_intents(operation_id) ON DELETE CASCADE,
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

CREATE INDEX idx_gc_delete_tasks_claim
ON gc_delete_tasks(state, lease_expires_at, updated_at);

CREATE TABLE gc_version_references (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES object_versions(id),
    PRIMARY KEY (operation_id, version_id)
) STRICT;

INSERT OR IGNORE INTO gc_version_references SELECT operation_id, version_id FROM restore_intents;
INSERT OR IGNORE INTO gc_version_references SELECT operation_id, version_id FROM copy_intents;
INSERT OR IGNORE INTO gc_version_references SELECT operation_id, version_id FROM verify_intents;
INSERT OR IGNORE INTO gc_version_references SELECT operation_id, version_id FROM reconcile_intents;
INSERT OR IGNORE INTO gc_version_references SELECT operation_id, version_id FROM repair_intents;
INSERT OR IGNORE INTO gc_version_references SELECT operation_id, version_id FROM compact_intents;

CREATE TRIGGER index_restore_version_for_gc
AFTER INSERT ON restore_intents
BEGIN
    INSERT OR IGNORE INTO gc_version_references VALUES (NEW.operation_id, NEW.version_id);
END;

CREATE TRIGGER index_copy_version_for_gc
AFTER INSERT ON copy_intents
BEGIN
    INSERT OR IGNORE INTO gc_version_references VALUES (NEW.operation_id, NEW.version_id);
END;

CREATE TRIGGER index_verify_version_for_gc
AFTER INSERT ON verify_intents
BEGIN
    INSERT OR IGNORE INTO gc_version_references VALUES (NEW.operation_id, NEW.version_id);
END;

CREATE TRIGGER index_reconcile_version_for_gc
AFTER INSERT ON reconcile_intents
BEGIN
    INSERT OR IGNORE INTO gc_version_references VALUES (NEW.operation_id, NEW.version_id);
END;

CREATE TRIGGER index_repair_version_for_gc
AFTER INSERT ON repair_intents
BEGIN
    INSERT OR IGNORE INTO gc_version_references VALUES (NEW.operation_id, NEW.version_id);
END;

CREATE TRIGGER index_compact_version_for_gc
AFTER INSERT ON compact_intents
BEGIN
    INSERT OR IGNORE INTO gc_version_references VALUES (NEW.operation_id, NEW.version_id);
END;

CREATE VIEW gc_active_version_leases AS
SELECT reference.version_id
FROM gc_version_references AS reference
JOIN leases AS lease ON lease.operation_id = reference.operation_id
JOIN control_plane_state AS control ON control.singleton = 1
WHERE lease.incarnation = control.incarnation
  AND lease.released_at IS NULL
  AND lease.expires_at > unixepoch()
UNION
SELECT lease.resource_id
FROM leases AS lease
JOIN control_plane_state AS control ON control.singleton = 1
WHERE lease.resource_kind = 'version'
  AND lease.incarnation = control.incarnation
  AND lease.released_at IS NULL
  AND lease.expires_at > unixepoch();

CREATE VIEW gc_protected_locations AS
SELECT location.id AS location_id
FROM locations AS location
JOIN extents AS extent ON extent.id = location.extent_id
JOIN version_packs AS version_pack ON version_pack.pack_id = extent.pack_id
JOIN object_versions AS version ON version.id = version_pack.version_id
WHERE version.state = 'published'
UNION
SELECT location.id
FROM locations AS location
JOIN extents AS extent ON extent.id = location.extent_id
JOIN version_packs AS version_pack ON version_pack.pack_id = extent.pack_id
JOIN gc_active_version_leases AS active ON active.version_id = version_pack.version_id
UNION
SELECT location.id
FROM locations AS location
JOIN recovery_manifests AS recovery
  ON recovery.sidecar_driver_id = location.driver_id
 AND recovery.sidecar_storage_key = location.storage_key
WHERE recovery.state = 'durable'
UNION
SELECT source.location_id
FROM move_sources AS source
WHERE source.state NOT IN ('deleted', 'cancelled');

CREATE VIEW gc_markable_locations AS
SELECT intent.operation_id, location.id AS location_id
FROM gc_intents AS intent
JOIN gc_epochs AS epoch ON epoch.id = intent.operation_id
JOIN operations AS operation ON operation.id = intent.operation_id
JOIN control_plane_state AS control ON control.singleton = 1
JOIN locations AS location ON location.state = 'available'
JOIN extents AS extent ON extent.id = location.extent_id
JOIN packs AS pack ON pack.id = extent.pack_id
WHERE epoch.state = 'marking'
  AND operation.kind = 'gc'
  AND operation.state = 'running'
  AND operation.phase = 'marking'
  AND operation.incarnation = control.incarnation
  AND epoch.incarnation = control.incarnation
  AND control.mode = 'active'
  AND pack.namespace_id = operation.namespace_id
  AND location.created_at <= intent.cutoff_at
  AND location.id NOT IN (SELECT location_id FROM gc_protected_locations)
  AND NOT EXISTS (
      SELECT 1
      FROM locations AS shared
      JOIN extents AS shared_extent ON shared_extent.id = shared.extent_id
      JOIN packs AS shared_pack ON shared_pack.id = shared_extent.pack_id
      WHERE shared.driver_id = location.driver_id
        AND shared.storage_key = location.storage_key
        AND (
            shared.state != 'available'
            OR shared.created_at > intent.cutoff_at
            OR shared_pack.namespace_id != operation.namespace_id
            OR shared.id IN (SELECT location_id FROM gc_protected_locations)
        )
  );

CREATE VIEW safe_gc_delete_tasks AS
SELECT task.id
FROM gc_delete_tasks AS task
JOIN gc_intents AS intent ON intent.operation_id = task.operation_id
JOIN gc_epochs AS epoch ON epoch.id = task.operation_id
JOIN operations AS operation ON operation.id = task.operation_id
JOIN control_plane_state AS control ON control.singleton = 1
WHERE epoch.state IN ('grace', 'sweeping')
  AND epoch.grace_until IS NOT NULL
  AND epoch.grace_until <= unixepoch()
  AND operation.kind = 'gc'
  AND operation.state = 'running'
  AND operation.phase IN ('grace', 'sweeping')
  AND operation.incarnation = control.incarnation
  AND epoch.incarnation = control.incarnation
  AND control.mode = 'active'
  AND NOT EXISTS (
      SELECT 1
      FROM gc_candidates AS candidate
      JOIN locations AS location ON location.id = candidate.location_id
      WHERE candidate.gc_epoch_id = task.operation_id
        AND location.driver_id = task.driver_id
        AND location.storage_key = task.storage_key
        AND (
            candidate.state NOT IN ('marked', 'delete_pending', 'failed')
            OR location.state != 'tombstoned'
            OR candidate.location_revision != location.revision
            OR location.id IN (SELECT location_id FROM gc_protected_locations)
        )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM locations AS shared
      WHERE shared.driver_id = task.driver_id
        AND shared.storage_key = task.storage_key
        AND NOT EXISTS (
            SELECT 1
            FROM gc_candidates AS candidate
            WHERE candidate.gc_epoch_id = task.operation_id
              AND candidate.location_id = shared.id
              AND candidate.state IN ('marked', 'delete_pending', 'failed')
              AND candidate.location_revision = shared.revision
        )
  )
  AND (
      SELECT COUNT(*)
      FROM gc_candidates AS candidate
      JOIN locations AS location ON location.id = candidate.location_id
      WHERE candidate.gc_epoch_id = task.operation_id
        AND location.driver_id = task.driver_id
        AND location.storage_key = task.storage_key
        AND candidate.state IN ('marked', 'delete_pending', 'failed')
        AND location.state = 'tombstoned'
        AND candidate.location_revision = location.revision
  ) = task.expected_location_count;

CREATE TRIGGER gc_intent_requires_current_operation_epoch
BEFORE INSERT ON gc_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM operations AS operation
        JOIN gc_epochs AS epoch ON epoch.id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE operation.id = NEW.operation_id
          AND operation.kind = 'gc'
          AND operation.state = 'planned'
          AND operation.incarnation = control.incarnation
          AND epoch.namespace_id = operation.namespace_id
          AND epoch.incarnation = control.incarnation
          AND epoch.state = 'marking'
          AND control.mode = 'active'
    ) THEN RAISE(ABORT, 'GC intent requires the current planned epoch') END;
END;

CREATE TRIGGER gc_intent_is_immutable
BEFORE UPDATE ON gc_intents
BEGIN
    SELECT RAISE(ABORT, 'GC intent is immutable');
END;

CREATE TRIGGER gc_epoch_state_transition_is_monotonic
BEFORE UPDATE OF state ON gc_epochs
WHEN OLD.state != NEW.state
  AND NOT (
      (OLD.state = 'marking' AND NEW.state IN ('grace', 'succeeded', 'failed'))
      OR (OLD.state = 'grace' AND NEW.state IN ('sweeping', 'succeeded', 'failed'))
      OR (OLD.state = 'sweeping' AND NEW.state IN ('succeeded', 'failed'))
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid GC epoch state transition');
END;

CREATE TRIGGER gc_candidate_state_transition_is_monotonic
BEFORE UPDATE OF state ON gc_candidates
WHEN OLD.state != NEW.state
  AND NOT (
      (OLD.state = 'marked' AND NEW.state IN ('cancelled', 'delete_pending', 'failed'))
      OR (OLD.state = 'delete_pending' AND NEW.state IN ('deleted', 'failed'))
      OR (OLD.state = 'failed' AND NEW.state IN ('delete_pending', 'cancelled'))
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid GC candidate state transition');
END;

CREATE TRIGGER gc_location_tombstone_requires_fence
BEFORE UPDATE OF state ON locations
WHEN OLD.state = 'available'
  AND NEW.state = 'tombstoned'
  AND EXISTS (
      SELECT 1
      FROM gc_candidates AS candidate
      WHERE candidate.location_id = OLD.id
        AND candidate.state = 'marked'
        AND candidate.location_revision = NEW.revision
  )
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM gc_candidates AS candidate
        JOIN gc_intents AS intent ON intent.operation_id = candidate.gc_epoch_id
        JOIN gc_epochs AS epoch ON epoch.id = candidate.gc_epoch_id
        JOIN operations AS operation ON operation.id = candidate.gc_epoch_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE candidate.location_id = OLD.id
          AND candidate.location_revision = OLD.revision + 1
          AND candidate.state = 'marked'
          AND operation.kind = 'gc'
          AND operation.state = 'running'
          AND operation.phase = 'marking'
          AND operation.incarnation = control.incarnation
          AND epoch.incarnation = control.incarnation
          AND epoch.state = 'marking'
          AND lease.lease_kind = 'write'
          AND lease.owner_client_id = operation.requested_by
          AND lease.incarnation = control.incarnation
          AND lease.fencing_token > 0
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
          AND control.mode = 'active'
    ) THEN RAISE(ABORT, 'GC tombstone requires the current mark fence') END;
END;

CREATE TRIGGER gc_grace_requires_durable_candidates
BEFORE UPDATE OF state ON gc_epochs
WHEN OLD.state = 'marking' AND NEW.state = 'grace'
BEGIN
    SELECT CASE WHEN NEW.grace_until IS NULL OR NEW.grace_until <= unixepoch()
      THEN RAISE(ABORT, 'GC grace requires a future deadline') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM gc_candidates WHERE gc_epoch_id = NEW.id
    ) THEN RAISE(ABORT, 'GC grace requires marked candidates') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM gc_candidates AS candidate
        JOIN locations AS location ON location.id = candidate.location_id
        WHERE candidate.gc_epoch_id = NEW.id
          AND (
              candidate.state != 'marked'
              OR location.state != 'tombstoned'
              OR candidate.location_revision != location.revision
              OR location.tombstoned_at IS NULL
          )
    ) THEN RAISE(ABORT, 'GC grace requires durable tombstones') END;
END;

CREATE TRIGGER claimed_gc_delete_requires_safe_object
BEFORE UPDATE OF state, owner_client_id, incarnation, fencing_token, lease_expires_at
ON gc_delete_tasks
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
        FROM safe_gc_delete_tasks AS safe
        JOIN operations AS operation ON operation.id = NEW.operation_id
        JOIN control_plane_state AS control ON control.singleton = 1
        JOIN clients AS client ON client.id = NEW.owner_client_id
        WHERE safe.id = NEW.id
          AND client.state = 'online'
          AND NEW.incarnation = control.incarnation
          AND NEW.fencing_token > OLD.fencing_token
          AND NEW.lease_expires_at > unixepoch()
          AND EXISTS (
              SELECT 1
              FROM client_namespace_permissions
              WHERE client_id = NEW.owner_client_id
                AND namespace_id = operation.namespace_id
                AND role IN ('janitor', 'administrator')
          )
    ) THEN RAISE(ABORT, 'GC delete claim requires a safe current object') END;
END;

CREATE TRIGGER gc_location_delete_requires_task_fence
BEFORE UPDATE OF state ON locations
WHEN OLD.state = 'tombstoned'
  AND NEW.state = 'deleted'
  AND EXISTS (
      SELECT 1
      FROM gc_candidates
      WHERE location_id = OLD.id AND state = 'delete_pending'
  )
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM gc_candidates AS candidate
        JOIN gc_delete_tasks AS task ON task.operation_id = candidate.gc_epoch_id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE candidate.location_id = OLD.id
          AND candidate.state = 'delete_pending'
          AND candidate.location_revision = OLD.revision
          AND task.driver_id = OLD.driver_id
          AND task.storage_key = OLD.storage_key
          AND task.state = 'claimed'
          AND task.incarnation = control.incarnation
          AND task.lease_expires_at > unixepoch()
          AND task.owner_client_id IS NOT NULL
          AND task.fencing_token > 0
          AND control.mode = 'active'
    ) THEN RAISE(ABORT, 'GC delete requires the current task fence') END;
END;

CREATE TRIGGER completed_gc_delete_requires_deleted_locations
BEFORE UPDATE OF state ON gc_delete_tasks
WHEN NEW.state = 'deleted' AND OLD.state != 'deleted'
BEGIN
    SELECT CASE WHEN OLD.state != 'claimed'
      OR OLD.owner_client_id IS NULL
      OR OLD.incarnation IS NULL
      OR OLD.fencing_token = 0
      OR OLD.lease_expires_at <= unixepoch()
    THEN RAISE(ABORT, 'GC delete completion requires a live claim') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM gc_candidates AS candidate
        JOIN locations AS location ON location.id = candidate.location_id
        WHERE candidate.gc_epoch_id = NEW.operation_id
          AND location.driver_id = NEW.driver_id
          AND location.storage_key = NEW.storage_key
          AND (candidate.state != 'deleted' OR location.state != 'deleted')
    ) THEN RAISE(ABORT, 'GC delete completion requires deleted locations') END;

    SELECT CASE WHEN (
        SELECT COUNT(*)
        FROM gc_candidates AS candidate
        JOIN locations AS location ON location.id = candidate.location_id
        WHERE candidate.gc_epoch_id = NEW.operation_id
          AND location.driver_id = NEW.driver_id
          AND location.storage_key = NEW.storage_key
          AND candidate.state = 'deleted'
          AND location.state = 'deleted'
    ) != NEW.expected_location_count
    THEN RAISE(ABORT, 'GC delete completion requires every object location') END;
END;
