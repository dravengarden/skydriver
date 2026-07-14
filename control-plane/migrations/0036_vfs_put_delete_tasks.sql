PRAGMA foreign_keys = ON;

-- One expired or abandoned complete-object upload maps to one fenced delete
-- task. Migration 0040 moves hosted provider I/O to server cron while keeping
-- this immutable evidence and state machine for compatible databases.
CREATE TABLE vfs_put_delete_tasks (
    id TEXT PRIMARY KEY REFERENCES vfs_put_intents(id) ON DELETE CASCADE,
    driver_revision INTEGER NOT NULL CHECK (driver_revision > 0),
    evidence_sha256 TEXT NOT NULL CHECK (
        length(evidence_sha256) = 64
        AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    delete_after INTEGER NOT NULL CHECK (delete_after > 0),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'claimed', 'failed', 'deleted', 'superseded')
    ),
    owner_token_id TEXT REFERENCES vfs_token_verifiers(id),
    incarnation TEXT,
    fencing_token INTEGER NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    lease_expires_at INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_code TEXT,
    completion_outcome TEXT CHECK (
        completion_outcome IS NULL OR completion_outcome IN ('deleted', 'already_absent')
    ),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    claimed_at INTEGER,
    completed_at INTEGER,
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    CHECK ((state = 'claimed') = (owner_token_id IS NOT NULL)),
    CHECK ((state = 'claimed') = (incarnation IS NOT NULL)),
    CHECK ((state = 'claimed') = (lease_expires_at IS NOT NULL)),
    CHECK ((state = 'deleted') = (completion_outcome IS NOT NULL)),
    CHECK ((state = 'deleted') = (completed_at IS NOT NULL))
) STRICT;

CREATE INDEX idx_vfs_put_delete_tasks_claimable
ON vfs_put_delete_tasks(state, delete_after, lease_expires_at, updated_at)
WHERE state IN ('pending', 'claimed', 'failed');

CREATE TRIGGER validate_vfs_put_delete_task_insert
BEFORE INSERT ON vfs_put_delete_tasks
BEGIN
    SELECT CASE WHEN NEW.state != 'pending'
      OR NEW.owner_token_id IS NOT NULL
      OR NEW.incarnation IS NOT NULL
      OR NEW.fencing_token != 0
      OR NEW.lease_expires_at IS NOT NULL
      OR NEW.attempt_count != 0
      OR NEW.last_error_code IS NOT NULL
      OR NEW.completion_outcome IS NOT NULL
      OR NEW.claimed_at IS NOT NULL
      OR NEW.completed_at IS NOT NULL
      OR NOT EXISTS (
          SELECT 1
          FROM vfs_put_intents AS intent
          JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = intent.id
          JOIN driver_instances AS driver ON driver.id = intent.driver_id
          WHERE intent.id = NEW.id
            AND intent.state IN ('expired', 'abandoned')
            AND evidence.commit_sha256 = NEW.evidence_sha256
            AND driver.revision = NEW.driver_revision
            AND NOT EXISTS (
                SELECT 1 FROM vfs_put_receipts WHERE intent_id = intent.id
            )
      )
    THEN RAISE(ABORT, 'invalid VFS put delete task') END;
END;

CREATE TRIGGER protect_vfs_put_delete_task_identity
BEFORE UPDATE OF id, driver_revision, evidence_sha256, delete_after, created_at
ON vfs_put_delete_tasks
BEGIN
    SELECT RAISE(ABORT, 'VFS put delete task identity is immutable');
END;

CREATE TRIGGER validate_vfs_put_delete_task_transition
BEFORE UPDATE OF state ON vfs_put_delete_tasks
WHEN NOT (
    (OLD.state IN ('pending', 'failed') AND NEW.state IN ('claimed', 'superseded'))
    OR (OLD.state = 'claimed' AND NEW.state IN ('claimed', 'failed', 'deleted', 'superseded'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid VFS put delete task transition');
END;

CREATE VIEW safe_vfs_put_delete_tasks AS
SELECT task.id
FROM vfs_put_delete_tasks AS task
JOIN vfs_put_intents AS intent ON intent.id = task.id
JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = intent.id
JOIN driver_instances AS driver ON driver.id = intent.driver_id
WHERE task.state IN ('pending', 'claimed', 'failed')
  AND task.delete_after <= unixepoch()
  AND intent.state IN ('expired', 'abandoned')
  AND evidence.commit_sha256 = task.evidence_sha256
  AND driver.enabled = 1
  AND driver.revision = task.driver_revision
  AND NOT EXISTS (SELECT 1 FROM vfs_put_receipts WHERE intent_id = intent.id)
  AND NOT EXISTS (
      SELECT 1
      FROM vfs_locations AS location
      WHERE location.driver_id = intent.driver_id
        AND location.storage_key = intent.storage_key
        AND location.state != 'deleted'
  );

CREATE TRIGGER supersede_vfs_put_delete_task_on_location_insert
AFTER INSERT ON vfs_locations
WHEN NEW.state != 'deleted'
BEGIN
    UPDATE vfs_put_delete_tasks
    SET state = 'superseded', owner_token_id = NULL, incarnation = NULL,
        lease_expires_at = NULL, last_error_code = NULL, updated_at = unixepoch()
    WHERE id IN (
        SELECT task.id
        FROM vfs_put_delete_tasks AS task
        JOIN vfs_put_intents AS intent ON intent.id = task.id
        WHERE intent.driver_id = NEW.driver_id
          AND intent.storage_key = NEW.storage_key
          AND task.state IN ('pending', 'claimed', 'failed')
    );
END;

CREATE TRIGGER supersede_vfs_put_delete_task_on_location_update
AFTER UPDATE OF state ON vfs_locations
WHEN NEW.state != 'deleted'
BEGIN
    UPDATE vfs_put_delete_tasks
    SET state = 'superseded', owner_token_id = NULL, incarnation = NULL,
        lease_expires_at = NULL, last_error_code = NULL, updated_at = unixepoch()
    WHERE id IN (
        SELECT task.id
        FROM vfs_put_delete_tasks AS task
        JOIN vfs_put_intents AS intent ON intent.id = task.id
        WHERE intent.driver_id = NEW.driver_id
          AND intent.storage_key = NEW.storage_key
          AND task.state IN ('pending', 'claimed', 'failed')
    );
END;
