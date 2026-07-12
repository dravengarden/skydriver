PRAGMA foreign_keys = ON;

CREATE TABLE reconcile_observations (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    condition TEXT NOT NULL CHECK (condition IN ('unindexed', 'orphan', 'degraded')),
    subject_id TEXT NOT NULL,
    evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
    lease_id TEXT NOT NULL,
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (operation_id, condition, subject_id)
) STRICT;

CREATE TABLE reconcile_completions (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    report_sha256 TEXT NOT NULL UNIQUE CHECK (length(report_sha256) = 64),
    unindexed_count INTEGER NOT NULL CHECK (unindexed_count >= 0),
    orphan_count INTEGER NOT NULL CHECK (orphan_count >= 0),
    degraded_count INTEGER NOT NULL CHECK (degraded_count >= 0),
    state TEXT NOT NULL DEFAULT 'staging' CHECK (state IN ('staging', 'committed')),
    completed_at INTEGER NOT NULL,
    committed_at INTEGER
) STRICT;

CREATE TRIGGER reconcile_observation_requires_live_fence
BEFORE INSERT ON reconcile_observations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM reconcile_intents AS intent
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE intent.operation_id = NEW.operation_id
          AND operation.kind = 'reconcile'
          AND operation.state = 'running'
          AND lease.id = NEW.lease_id
          AND lease.owner_client_id = operation.requested_by
          AND lease.lease_kind = 'write'
          AND lease.incarnation = NEW.incarnation
          AND lease.fencing_token = NEW.fencing_token
          AND lease.incarnation = control.incarnation
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
          AND control.mode = 'active'
    ) THEN RAISE(ABORT, 'reconcile observation requires live fence') END;
END;

CREATE TRIGGER reconcile_completion_commit_requires_closed_operation
BEFORE UPDATE OF state ON reconcile_completions
WHEN NEW.state = 'committed' AND OLD.state = 'staging'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM operations AS operation
        JOIN operation_components AS component
          ON component.id = operation.id || '/reconcile'
        JOIN leases AS lease ON lease.operation_id = operation.id
        WHERE operation.id = NEW.operation_id
          AND operation.kind = 'reconcile'
          AND operation.state = 'succeeded'
          AND component.state = 'succeeded'
          AND lease.lease_kind = 'write'
          AND lease.released_at IS NOT NULL
    ) THEN RAISE(ABORT, 'reconcile completion requires closed operation and lease') END;
END;
