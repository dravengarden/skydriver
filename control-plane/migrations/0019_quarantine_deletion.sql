PRAGMA foreign_keys = ON;

ALTER TABLE quarantined_provider_objects
ADD COLUMN driver_revision INTEGER NOT NULL DEFAULT 1 CHECK (driver_revision > 0);

UPDATE quarantined_provider_objects AS quarantine
SET driver_revision = COALESCE(
    (
        SELECT intent.driver_revision
        FROM quarantine_action_intents AS intent
        JOIN quarantine_action_completions AS completion
          ON completion.operation_id = intent.operation_id
        WHERE intent.driver_id = quarantine.driver_id
          AND intent.storage_key = quarantine.storage_key
          AND completion.state = 'committed'
          AND completion.result_state = quarantine.state
        ORDER BY completion.completed_at DESC
        LIMIT 1
    ),
    (SELECT revision FROM driver_instances WHERE id = quarantine.driver_id)
);

CREATE TRIGGER quarantine_action_requires_pinned_driver_revision
BEFORE INSERT ON quarantine_action_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM quarantined_provider_objects AS quarantine
        WHERE quarantine.driver_id = NEW.driver_id
          AND quarantine.storage_key = NEW.storage_key
          AND quarantine.driver_revision = NEW.driver_revision
    ) THEN RAISE(ABORT, 'quarantine action requires the inventoried driver revision') END;
END;

CREATE TRIGGER quarantine_completion_requires_pinned_driver_revision
BEFORE INSERT ON quarantine_action_completions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM quarantine_action_intents AS intent
        JOIN quarantined_provider_objects AS quarantine
          ON quarantine.driver_id = intent.driver_id
         AND quarantine.storage_key = intent.storage_key
        WHERE intent.operation_id = NEW.operation_id
          AND quarantine.driver_revision = intent.driver_revision
    ) THEN RAISE(ABORT, 'quarantine completion requires the inventoried driver revision') END;
END;

CREATE TABLE quarantine_delete_tasks (
    id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 8192),
    operation_id TEXT NOT NULL UNIQUE
        REFERENCES quarantine_action_intents(operation_id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    driver_revision INTEGER NOT NULL CHECK (driver_revision > 0),
    storage_key TEXT NOT NULL CHECK (length(storage_key) BETWEEN 1 AND 4096),
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    provider_version TEXT CHECK (
        provider_version IS NULL OR length(provider_version) BETWEEN 1 AND 4096
    ),
    etag TEXT CHECK (etag IS NULL OR length(etag) BETWEEN 1 AND 4096),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    delete_after INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'claimed', 'failed', 'deleted', 'superseded')
    ),
    owner_client_id TEXT REFERENCES clients(id),
    incarnation TEXT CHECK (incarnation IS NULL OR length(incarnation) = 32),
    fencing_token INTEGER NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    lease_expires_at INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_code TEXT CHECK (
        last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 256
    ),
    completion_outcome TEXT CHECK (
        completion_outcome IS NULL OR completion_outcome IN ('deleted', 'already_absent')
    ),
    claimed_at INTEGER,
    deleted_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (driver_id, storage_key)
        REFERENCES quarantined_provider_objects(driver_id, storage_key),
    CHECK (state != 'claimed' OR (
        owner_client_id IS NOT NULL
        AND incarnation IS NOT NULL
        AND fencing_token > 0
        AND lease_expires_at IS NOT NULL
    )),
    CHECK (state != 'deleted' OR (
        deleted_at IS NOT NULL AND completion_outcome IS NOT NULL
    ))
) STRICT;

CREATE INDEX idx_quarantine_delete_tasks_claim
ON quarantine_delete_tasks(state, lease_expires_at, updated_at);

CREATE VIEW safe_quarantine_delete_tasks AS
SELECT task.id
FROM quarantine_delete_tasks AS task
JOIN quarantine_action_intents AS intent ON intent.operation_id = task.operation_id
JOIN quarantine_action_completions AS completion
  ON completion.operation_id = task.operation_id
JOIN operations AS operation ON operation.id = task.operation_id
JOIN quarantined_provider_objects AS quarantine
  ON quarantine.driver_id = task.driver_id
 AND quarantine.storage_key = task.storage_key
JOIN driver_instances AS driver ON driver.id = task.driver_id
JOIN control_plane_state AS control ON control.singleton = 1
WHERE intent.action = 'tombstone'
  AND completion.state = 'committed'
  AND completion.result_state = 'tombstoned'
  AND operation.kind = 'gc'
  AND operation.state = 'succeeded'
  AND control.mode = 'active'
  AND driver.enabled = 1
  AND driver.revision = task.driver_revision
  AND quarantine.state = 'tombstoned'
  AND quarantine.namespace_id = operation.namespace_id
  AND quarantine.driver_revision = task.driver_revision
  AND quarantine.revision >= task.expected_revision
  AND quarantine.provider_version IS task.provider_version
  AND quarantine.etag IS task.etag
  AND quarantine.size_bytes = task.size_bytes
  AND quarantine.delete_after = task.delete_after
  AND task.delete_after <= unixepoch()
  AND NOT EXISTS (
      SELECT 1 FROM locations AS location
      WHERE location.driver_id = task.driver_id
        AND location.storage_key = task.storage_key
        AND location.state != 'deleted'
  )
  AND NOT EXISTS (
      SELECT 1 FROM recovery_manifests AS recovery
      WHERE recovery.sidecar_driver_id = task.driver_id
        AND recovery.sidecar_storage_key = task.storage_key
        AND recovery.state != 'missing'
  );

CREATE TRIGGER quarantine_delete_task_requires_exact_tombstone
BEFORE INSERT ON quarantine_delete_tasks
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM quarantine_action_intents AS intent
        JOIN quarantine_action_completions AS completion
          ON completion.operation_id = intent.operation_id
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN quarantined_provider_objects AS quarantine
          ON quarantine.driver_id = intent.driver_id
         AND quarantine.storage_key = intent.storage_key
        WHERE intent.operation_id = NEW.operation_id
          AND intent.action = 'tombstone'
          AND completion.result_state = 'tombstoned'
          AND operation.kind = 'gc'
          AND (
              (
                  completion.state = 'staging'
                  AND operation.state = 'running'
                  AND operation.phase = 'reviewing_quarantine'
              )
              OR (completion.state = 'committed' AND operation.state = 'succeeded')
          )
          AND NEW.driver_id = intent.driver_id
          AND NEW.driver_revision = intent.driver_revision
          AND NEW.storage_key = intent.storage_key
          AND NEW.expected_revision = completion.result_revision
          AND NEW.provider_version IS intent.provider_version
          AND NEW.etag IS intent.etag
          AND NEW.size_bytes = intent.size_bytes
          AND NEW.delete_after = completion.delete_after
          AND NEW.state = 'pending'
          AND quarantine.namespace_id = operation.namespace_id
          AND quarantine.state = 'tombstoned'
          AND quarantine.driver_revision = intent.driver_revision
          AND quarantine.revision = completion.result_revision
          AND quarantine.provider_version IS intent.provider_version
          AND quarantine.etag IS intent.etag
          AND quarantine.size_bytes = intent.size_bytes
          AND quarantine.delete_after = completion.delete_after
    ) THEN RAISE(ABORT, 'quarantine delete task requires the exact staged tombstone') END;
END;

CREATE TRIGGER quarantine_tombstone_commit_requires_delete_task
BEFORE UPDATE OF state ON quarantine_action_completions
WHEN NEW.state = 'committed'
  AND OLD.state = 'staging'
  AND NEW.action = 'tombstone'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM quarantine_action_intents AS intent
        JOIN quarantine_delete_tasks AS task ON task.operation_id = intent.operation_id
        WHERE intent.operation_id = NEW.operation_id
          AND task.driver_id = intent.driver_id
          AND task.driver_revision = intent.driver_revision
          AND task.storage_key = intent.storage_key
          AND task.expected_revision = NEW.result_revision
          AND task.provider_version IS intent.provider_version
          AND task.etag IS intent.etag
          AND task.size_bytes = intent.size_bytes
          AND task.delete_after = NEW.delete_after
          AND task.state = 'pending'
    ) THEN RAISE(ABORT, 'tombstone commit requires an exact delete task') END;
END;

CREATE TRIGGER quarantine_delete_task_identity_is_immutable
BEFORE UPDATE OF operation_id, driver_id, driver_revision, storage_key,
                 expected_revision, provider_version, etag, size_bytes, delete_after
ON quarantine_delete_tasks
BEGIN
    SELECT RAISE(ABORT, 'quarantine delete task identity is immutable');
END;

CREATE TRIGGER quarantine_delete_task_state_is_monotonic
BEFORE UPDATE OF state ON quarantine_delete_tasks
WHEN OLD.state != NEW.state
  AND NOT (
      (OLD.state IN ('pending', 'failed') AND NEW.state IN ('claimed', 'superseded'))
      OR (OLD.state = 'claimed' AND NEW.state IN ('failed', 'deleted', 'superseded'))
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid quarantine delete task transition');
END;

CREATE TRIGGER claimed_quarantine_delete_requires_safe_object
BEFORE UPDATE OF state, owner_client_id, incarnation, fencing_token, lease_expires_at
ON quarantine_delete_tasks
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
        FROM safe_quarantine_delete_tasks AS safe
        JOIN operations AS operation ON operation.id = NEW.operation_id
        JOIN control_plane_state AS control ON control.singleton = 1
        JOIN clients AS client ON client.id = NEW.owner_client_id
        WHERE safe.id = NEW.id
          AND client.state = 'online'
          AND NEW.incarnation = control.incarnation
          AND NEW.fencing_token > OLD.fencing_token
          AND NEW.lease_expires_at > unixepoch()
          AND EXISTS (
              SELECT 1 FROM client_namespace_permissions
              WHERE client_id = NEW.owner_client_id
                AND namespace_id = operation.namespace_id
                AND role IN ('janitor', 'administrator')
          )
    ) THEN RAISE(ABORT, 'quarantine delete claim requires a safe current object') END;
END;

CREATE TRIGGER quarantine_object_delete_requires_task_fence
BEFORE UPDATE OF state ON quarantined_provider_objects
WHEN OLD.state = 'tombstoned' AND NEW.state = 'deleted'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM quarantine_delete_tasks AS task
        JOIN safe_quarantine_delete_tasks AS safe ON safe.id = task.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE task.driver_id = OLD.driver_id
          AND task.storage_key = OLD.storage_key
          AND task.state = 'claimed'
          AND task.driver_revision = OLD.driver_revision
          AND OLD.revision >= task.expected_revision
          AND task.provider_version IS OLD.provider_version
          AND task.etag IS OLD.etag
          AND task.size_bytes = OLD.size_bytes
          AND task.delete_after = OLD.delete_after
          AND task.incarnation = control.incarnation
          AND task.lease_expires_at > unixepoch()
          AND task.owner_client_id IS NOT NULL
          AND task.fencing_token > 0
          AND control.mode = 'active'
          AND NEW.driver_revision = OLD.driver_revision
          AND NEW.revision = OLD.revision + 1
          AND NEW.provider_version IS OLD.provider_version
          AND NEW.etag IS OLD.etag
          AND NEW.size_bytes = OLD.size_bytes
          AND NEW.delete_after = OLD.delete_after
          AND NEW.deleted_at IS NOT NULL
    ) THEN RAISE(ABORT, 'quarantine delete requires the current safe task fence') END;
END;

CREATE TRIGGER completed_quarantine_delete_requires_deleted_object
BEFORE UPDATE OF state ON quarantine_delete_tasks
WHEN NEW.state = 'deleted' AND OLD.state != 'deleted'
BEGIN
    SELECT CASE WHEN OLD.state != 'claimed'
      OR OLD.owner_client_id IS NULL
      OR OLD.incarnation IS NULL
      OR OLD.fencing_token = 0
      OR OLD.lease_expires_at <= unixepoch()
      OR NEW.completion_outcome IS NULL
      OR NEW.deleted_at IS NULL
    THEN RAISE(ABORT, 'quarantine delete completion requires a live claim') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM quarantined_provider_objects AS quarantine
        WHERE quarantine.driver_id = NEW.driver_id
          AND quarantine.storage_key = NEW.storage_key
          AND quarantine.state = 'deleted'
          AND quarantine.driver_revision = NEW.driver_revision
          AND quarantine.revision > NEW.expected_revision
          AND quarantine.provider_version IS NEW.provider_version
          AND quarantine.etag IS NEW.etag
          AND quarantine.size_bytes = NEW.size_bytes
          AND quarantine.delete_after = NEW.delete_after
          AND quarantine.deleted_at = NEW.deleted_at
    ) THEN RAISE(ABORT, 'quarantine delete completion requires the exact deleted object') END;
END;

CREATE TRIGGER supersede_quarantine_delete_after_identity_change
AFTER UPDATE OF state, driver_revision, provider_version, etag, size_bytes, delete_after
ON quarantined_provider_objects
WHEN NEW.state NOT IN ('tombstoned', 'deleted')
  OR EXISTS (
      SELECT 1 FROM quarantine_delete_tasks AS task
      WHERE task.driver_id = NEW.driver_id
        AND task.storage_key = NEW.storage_key
        AND task.state IN ('pending', 'claimed', 'failed')
        AND (
            task.driver_revision != NEW.driver_revision
            OR task.provider_version IS NOT NEW.provider_version
            OR task.etag IS NOT NEW.etag
            OR task.size_bytes != NEW.size_bytes
            OR task.delete_after IS NOT NEW.delete_after
        )
  )
BEGIN
    UPDATE quarantine_delete_tasks
    SET state = 'superseded', lease_expires_at = NULL,
        last_error_code = 'quarantine_identity_changed', updated_at = unixepoch()
    WHERE driver_id = NEW.driver_id
      AND storage_key = NEW.storage_key
      AND state IN ('pending', 'claimed', 'failed');
END;

INSERT OR IGNORE INTO quarantine_delete_tasks (
    id, operation_id, driver_id, driver_revision, storage_key, expected_revision,
    provider_version, etag, size_bytes, delete_after, state, created_at, updated_at
)
SELECT
    completion.operation_id || '/quarantine-delete', completion.operation_id,
    intent.driver_id, intent.driver_revision, intent.storage_key,
    completion.result_revision, intent.provider_version, intent.etag,
    intent.size_bytes, completion.delete_after, 'pending',
    completion.completed_at, completion.completed_at
FROM quarantine_action_completions AS completion
JOIN quarantine_action_intents AS intent ON intent.operation_id = completion.operation_id
JOIN operations AS operation ON operation.id = completion.operation_id
JOIN quarantined_provider_objects AS quarantine
  ON quarantine.driver_id = intent.driver_id
 AND quarantine.storage_key = intent.storage_key
WHERE intent.action = 'tombstone'
  AND completion.state = 'committed'
  AND completion.result_state = 'tombstoned'
  AND operation.kind = 'gc'
  AND operation.state = 'succeeded'
  AND quarantine.state = 'tombstoned'
  AND quarantine.driver_revision = intent.driver_revision
  AND quarantine.revision >= completion.result_revision
  AND quarantine.provider_version IS intent.provider_version
  AND quarantine.etag IS intent.etag
  AND quarantine.size_bytes = intent.size_bytes
  AND quarantine.delete_after = completion.delete_after;
