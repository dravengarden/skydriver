PRAGMA foreign_keys = ON;

DROP TRIGGER inventory_completion_requires_classified_report;

CREATE TABLE quarantined_provider_objects_v2 (
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    storage_key TEXT NOT NULL CHECK (length(storage_key) BETWEEN 1 AND 4096),
    namespace_id TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    provider_version TEXT CHECK (
        provider_version IS NULL OR length(provider_version) BETWEEN 1 AND 4096
    ),
    etag TEXT CHECK (etag IS NULL OR length(etag) BETWEEN 1 AND 4096),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('quarantined', 'acknowledged', 'tombstoned', 'resolved', 'deleted')
    ),
    quarantine_until INTEGER NOT NULL,
    acknowledgement_reason TEXT CHECK (
        acknowledgement_reason IS NULL OR length(acknowledgement_reason) BETWEEN 1 AND 2048
    ),
    acknowledged_at INTEGER,
    tombstone_reason TEXT CHECK (
        tombstone_reason IS NULL OR length(tombstone_reason) BETWEEN 1 AND 2048
    ),
    tombstoned_at INTEGER,
    delete_after INTEGER,
    deleted_at INTEGER,
    first_observed_at INTEGER NOT NULL,
    last_observed_at INTEGER NOT NULL,
    last_operation_id TEXT REFERENCES operations(id) ON DELETE SET NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    PRIMARY KEY (driver_id, storage_key),
    CHECK (quarantine_until >= first_observed_at),
    CHECK (delete_after IS NULL OR tombstoned_at IS NOT NULL),
    CHECK (delete_after IS NULL OR delete_after >= tombstoned_at),
    CHECK (deleted_at IS NULL OR delete_after IS NOT NULL),
    CHECK (
        state != 'quarantined'
        OR (
            acknowledgement_reason IS NULL
            AND acknowledged_at IS NULL
            AND tombstone_reason IS NULL
            AND tombstoned_at IS NULL
            AND delete_after IS NULL
            AND deleted_at IS NULL
        )
    ),
    CHECK (
        state != 'acknowledged'
        OR (
            acknowledgement_reason IS NOT NULL
            AND acknowledged_at IS NOT NULL
            AND tombstone_reason IS NULL
            AND tombstoned_at IS NULL
            AND delete_after IS NULL
            AND deleted_at IS NULL
        )
    ),
    CHECK (
        state != 'tombstoned'
        OR (
            acknowledgement_reason IS NOT NULL
            AND acknowledged_at IS NOT NULL
            AND tombstone_reason IS NOT NULL
            AND tombstoned_at IS NOT NULL
            AND delete_after IS NOT NULL
            AND deleted_at IS NULL
        )
    ),
    CHECK (state != 'deleted' OR deleted_at IS NOT NULL)
) STRICT;

INSERT INTO quarantined_provider_objects_v2 (
    driver_id,
    storage_key,
    namespace_id,
    provider_version,
    etag,
    size_bytes,
    state,
    quarantine_until,
    first_observed_at,
    last_observed_at,
    last_operation_id,
    revision
)
SELECT
    driver_id,
    storage_key,
    namespace_id,
    provider_version,
    etag,
    size_bytes,
    state,
    quarantine_until,
    first_observed_at,
    last_observed_at,
    last_operation_id,
    revision
FROM quarantined_provider_objects;

DROP TABLE quarantined_provider_objects;
ALTER TABLE quarantined_provider_objects_v2 RENAME TO quarantined_provider_objects;

CREATE INDEX idx_quarantined_provider_objects_namespace_state
ON quarantined_provider_objects(namespace_id, state, quarantine_until);

CREATE TABLE quarantine_action_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('acknowledge', 'tombstone')),
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    driver_revision INTEGER NOT NULL CHECK (driver_revision > 0),
    storage_key TEXT NOT NULL CHECK (length(storage_key) BETWEEN 1 AND 4096),
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    provider_version TEXT CHECK (
        provider_version IS NULL OR length(provider_version) BETWEEN 1 AND 4096
    ),
    etag TEXT CHECK (etag IS NULL OR length(etag) BETWEEN 1 AND 4096),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 2048),
    grace_seconds INTEGER NOT NULL CHECK (grace_seconds BETWEEN 60 AND 31536000),
    created_at INTEGER NOT NULL,
    UNIQUE (operation_id, action, driver_id, storage_key, expected_revision),
    FOREIGN KEY (driver_id, storage_key)
        REFERENCES quarantined_provider_objects(driver_id, storage_key)
) STRICT;

CREATE TABLE quarantine_action_completions (
    operation_id TEXT PRIMARY KEY REFERENCES quarantine_action_intents(operation_id)
        ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('acknowledge', 'tombstone')),
    lease_id TEXT NOT NULL CHECK (length(lease_id) BETWEEN 1 AND 256),
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    result_revision INTEGER NOT NULL CHECK (result_revision > 1),
    result_state TEXT NOT NULL CHECK (result_state IN ('acknowledged', 'tombstoned')),
    delete_after INTEGER,
    state TEXT NOT NULL DEFAULT 'staging' CHECK (state IN ('staging', 'committed')),
    completed_at INTEGER NOT NULL,
    committed_at INTEGER,
    CHECK (
        (action = 'acknowledge' AND result_state = 'acknowledged' AND delete_after IS NULL)
        OR (action = 'tombstone' AND result_state = 'tombstoned' AND delete_after IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER quarantine_action_intent_requires_reviewable_object
BEFORE INSERT ON quarantine_action_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM operations AS operation
        JOIN quarantined_provider_objects AS quarantine
          ON quarantine.driver_id = NEW.driver_id
         AND quarantine.storage_key = NEW.storage_key
        JOIN driver_instances AS driver ON driver.id = quarantine.driver_id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE operation.id = NEW.operation_id
          AND operation.kind = 'gc'
          AND operation.state = 'planned'
          AND operation.namespace_id = quarantine.namespace_id
          AND operation.incarnation = control.incarnation
          AND control.mode = 'active'
          AND driver.enabled = 1
          AND driver.revision = NEW.driver_revision
          AND quarantine.revision = NEW.expected_revision
          AND quarantine.provider_version IS NEW.provider_version
          AND quarantine.etag IS NEW.etag
          AND quarantine.size_bytes = NEW.size_bytes
          AND (
              (
                  NEW.action = 'acknowledge'
                  AND quarantine.state = 'quarantined'
                  AND quarantine.quarantine_until <= unixepoch()
              )
              OR (NEW.action = 'tombstone' AND quarantine.state = 'acknowledged')
          )
          AND NOT EXISTS (
              SELECT 1 FROM locations AS location
              WHERE location.driver_id = quarantine.driver_id
                AND location.storage_key = quarantine.storage_key
                AND location.state != 'deleted'
          )
          AND NOT EXISTS (
              SELECT 1 FROM recovery_manifests AS recovery
              WHERE recovery.sidecar_driver_id = quarantine.driver_id
                AND recovery.sidecar_storage_key = quarantine.storage_key
                AND recovery.state != 'missing'
          )
    ) THEN RAISE(ABORT, 'quarantine action requires an exact reviewable object') END;
END;

CREATE TRIGGER quarantine_action_completion_requires_live_fence
BEFORE INSERT ON quarantine_action_completions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM quarantine_action_intents AS intent
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN quarantined_provider_objects AS quarantine
          ON quarantine.driver_id = intent.driver_id
         AND quarantine.storage_key = intent.storage_key
        JOIN driver_instances AS driver ON driver.id = intent.driver_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE intent.operation_id = NEW.operation_id
          AND NEW.action = intent.action
          AND NEW.result_revision = intent.expected_revision + 1
          AND operation.kind = 'gc'
          AND operation.state = 'running'
          AND operation.phase = 'reviewing_quarantine'
          AND operation.requested_by = lease.owner_client_id
          AND operation.incarnation = control.incarnation
          AND driver.enabled = 1
          AND driver.revision = intent.driver_revision
          AND lease.id = NEW.lease_id
          AND lease.lease_kind = 'write'
          AND lease.fencing_token = NEW.fencing_token
          AND lease.incarnation = NEW.incarnation
          AND lease.incarnation = control.incarnation
          AND lease.released_at IS NULL
          AND lease.expires_at > NEW.completed_at
          AND control.mode = 'active'
          AND quarantine.namespace_id = operation.namespace_id
          AND quarantine.revision = intent.expected_revision
          AND quarantine.provider_version IS intent.provider_version
          AND quarantine.etag IS intent.etag
          AND quarantine.size_bytes = intent.size_bytes
          AND (
              (
                  intent.action = 'acknowledge'
                  AND quarantine.state = 'quarantined'
                  AND quarantine.quarantine_until <= NEW.completed_at
                  AND NEW.result_state = 'acknowledged'
                  AND NEW.delete_after IS NULL
              )
              OR (
                  intent.action = 'tombstone'
                  AND quarantine.state = 'acknowledged'
                  AND NEW.result_state = 'tombstoned'
                  AND NEW.delete_after = NEW.completed_at + intent.grace_seconds
              )
          )
          AND NOT EXISTS (
              SELECT 1 FROM locations AS location
              WHERE location.driver_id = quarantine.driver_id
                AND location.storage_key = quarantine.storage_key
                AND location.state != 'deleted'
          )
          AND NOT EXISTS (
              SELECT 1 FROM recovery_manifests AS recovery
              WHERE recovery.sidecar_driver_id = quarantine.driver_id
                AND recovery.sidecar_storage_key = quarantine.storage_key
                AND recovery.state != 'missing'
          )
    ) THEN RAISE(ABORT, 'quarantine completion requires a live exact fence') END;
END;

CREATE TRIGGER quarantine_object_review_requires_staged_completion
BEFORE UPDATE OF state ON quarantined_provider_objects
WHEN NEW.state IN ('acknowledged', 'tombstoned') AND NEW.state != OLD.state
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM quarantine_action_intents AS intent
        JOIN quarantine_action_completions AS completion
          ON completion.operation_id = intent.operation_id
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE intent.driver_id = OLD.driver_id
          AND intent.storage_key = OLD.storage_key
          AND intent.expected_revision = OLD.revision
          AND intent.provider_version IS OLD.provider_version
          AND intent.etag IS OLD.etag
          AND intent.size_bytes = OLD.size_bytes
          AND completion.state = 'staging'
          AND completion.action = intent.action
          AND completion.result_state = NEW.state
          AND completion.result_revision = NEW.revision
          AND operation.kind = 'gc'
          AND operation.state = 'running'
          AND operation.phase = 'reviewing_quarantine'
          AND operation.namespace_id = OLD.namespace_id
          AND operation.id = NEW.last_operation_id
          AND operation.requested_by = lease.owner_client_id
          AND lease.id = completion.lease_id
          AND lease.lease_kind = 'write'
          AND lease.fencing_token = completion.fencing_token
          AND lease.incarnation = completion.incarnation
          AND lease.incarnation = control.incarnation
          AND lease.released_at IS NULL
          AND lease.expires_at > completion.completed_at
          AND control.mode = 'active'
          AND NEW.revision = OLD.revision + 1
          AND NEW.provider_version IS OLD.provider_version
          AND NEW.etag IS OLD.etag
          AND NEW.size_bytes = OLD.size_bytes
          AND (
              (
                  intent.action = 'acknowledge'
                  AND OLD.state = 'quarantined'
                  AND OLD.quarantine_until <= completion.completed_at
                  AND NEW.acknowledgement_reason = intent.reason
                  AND NEW.acknowledged_at = completion.completed_at
                  AND NEW.tombstone_reason IS NULL
                  AND NEW.tombstoned_at IS NULL
                  AND NEW.delete_after IS NULL
              )
              OR (
                  intent.action = 'tombstone'
                  AND OLD.state = 'acknowledged'
                  AND NEW.acknowledgement_reason = OLD.acknowledgement_reason
                  AND NEW.acknowledged_at = OLD.acknowledged_at
                  AND NEW.tombstone_reason = intent.reason
                  AND NEW.tombstoned_at = completion.completed_at
                  AND NEW.delete_after = completion.delete_after
              )
          )
          AND NOT EXISTS (
              SELECT 1 FROM locations AS location
              WHERE location.driver_id = OLD.driver_id
                AND location.storage_key = OLD.storage_key
                AND location.state != 'deleted'
          )
          AND NOT EXISTS (
              SELECT 1 FROM recovery_manifests AS recovery
              WHERE recovery.sidecar_driver_id = OLD.driver_id
                AND recovery.sidecar_storage_key = OLD.storage_key
                AND recovery.state != 'missing'
          )
    ) THEN RAISE(ABORT, 'quarantine object review requires staged fenced completion') END;
END;

CREATE TRIGGER quarantine_action_completion_commit_requires_closed_operation
BEFORE UPDATE OF state ON quarantine_action_completions
WHEN NEW.state = 'committed' AND OLD.state = 'staging'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM quarantine_action_intents AS intent
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN operation_components AS component
          ON component.id = operation.id || '/quarantine'
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN quarantined_provider_objects AS quarantine
          ON quarantine.driver_id = intent.driver_id
         AND quarantine.storage_key = intent.storage_key
        WHERE operation.id = NEW.operation_id
          AND operation.kind = 'gc'
          AND operation.state = 'succeeded'
          AND component.state = 'succeeded'
          AND lease.id = NEW.lease_id
          AND lease.lease_kind = 'write'
          AND lease.incarnation = NEW.incarnation
          AND lease.fencing_token = NEW.fencing_token
          AND lease.released_at IS NOT NULL
          AND quarantine.revision = NEW.result_revision
          AND quarantine.state = NEW.result_state
          AND quarantine.last_operation_id = operation.id
          AND EXISTS (
              SELECT 1 FROM integrity_findings AS finding
              WHERE finding.namespace_id = operation.namespace_id
                AND finding.subject_kind = 'provider_object'
                AND finding.subject_id = json_array(intent.driver_id, intent.storage_key)
                AND finding.condition = 'quarantined'
                AND finding.state = NEW.result_state
          )
          AND (
              (NEW.action = 'acknowledge' AND quarantine.delete_after IS NULL)
              OR (
                  NEW.action = 'tombstone'
                  AND quarantine.delete_after = NEW.delete_after
              )
          )
    ) THEN RAISE(ABORT, 'quarantine completion requires closed operation and exact result') END;
END;

CREATE VIEW inventory_report_attempts AS
SELECT DISTINCT operation_id, fencing_token
FROM inventory_report_pages;

CREATE VIEW inventory_missing_subjects AS
SELECT attempt.operation_id, attempt.fencing_token, 'location' AS subject_kind,
       location.id AS subject_id
FROM inventory_report_attempts AS attempt
JOIN inventory_intents AS intent ON intent.operation_id = attempt.operation_id
JOIN operations AS operation ON operation.id = intent.operation_id
JOIN locations AS location ON location.driver_id = intent.driver_id
JOIN extents AS extent ON extent.id = location.extent_id
JOIN packs AS pack ON pack.id = extent.pack_id
WHERE pack.namespace_id = operation.namespace_id
  AND location.state IN ('verified', 'available')
  AND substr(location.storage_key, 1, length(intent.prefix) + 1) = intent.prefix || '/'
  AND NOT EXISTS (
      SELECT 1 FROM inventory_report_objects AS report
      WHERE report.operation_id = attempt.operation_id
        AND report.fencing_token = attempt.fencing_token
        AND report.storage_key = location.storage_key
  )
UNION ALL
SELECT attempt.operation_id, attempt.fencing_token, 'manifest', recovery.manifest_sha256
FROM inventory_report_attempts AS attempt
JOIN inventory_intents AS intent ON intent.operation_id = attempt.operation_id
JOIN operations AS operation ON operation.id = intent.operation_id
JOIN recovery_manifests AS recovery ON recovery.sidecar_driver_id = intent.driver_id
JOIN object_versions AS version ON version.id = recovery.version_id
JOIN objects AS object ON object.id = version.object_id
WHERE object.namespace_id = operation.namespace_id
  AND recovery.state = 'durable'
  AND substr(recovery.sidecar_storage_key, 1, length(intent.prefix) + 1)
      = intent.prefix || '/'
  AND NOT EXISTS (
      SELECT 1 FROM inventory_report_objects AS report
      WHERE report.operation_id = attempt.operation_id
        AND report.fencing_token = attempt.fencing_token
        AND report.storage_key = recovery.sidecar_storage_key
  );

CREATE VIEW inventory_report_counts AS
SELECT
    attempt.operation_id,
    attempt.fencing_token,
    (
        SELECT COUNT(*) FROM inventory_report_pages AS page
        WHERE page.operation_id = attempt.operation_id
          AND page.fencing_token = attempt.fencing_token
    ) AS page_count,
    (
        SELECT COUNT(*) FROM inventory_report_objects AS report
        WHERE report.operation_id = attempt.operation_id
          AND report.fencing_token = attempt.fencing_token
    ) AS object_count,
    (
        SELECT COUNT(*)
        FROM inventory_report_objects AS report
        JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id
        WHERE report.operation_id = attempt.operation_id
          AND report.fencing_token = attempt.fencing_token
          AND (
              EXISTS (
                  SELECT 1 FROM locations AS location
                  WHERE location.driver_id = intent.driver_id
                    AND location.storage_key = report.storage_key
                    AND location.state != 'deleted'
              )
              OR EXISTS (
                  SELECT 1 FROM recovery_manifests AS recovery
                  WHERE recovery.sidecar_driver_id = intent.driver_id
                    AND recovery.sidecar_storage_key = report.storage_key
                    AND recovery.state != 'missing'
              )
          )
    ) AS known_count,
    (
        SELECT COUNT(*) FROM inventory_missing_subjects AS missing
        WHERE missing.operation_id = attempt.operation_id
          AND missing.fencing_token = attempt.fencing_token
    ) AS missing_count
FROM inventory_report_attempts AS attempt;

CREATE TRIGGER inventory_completion_requires_classified_report
BEFORE INSERT ON inventory_completions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM inventory_intents AS intent
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        JOIN inventory_report_counts AS counts
          ON counts.operation_id = intent.operation_id
         AND counts.fencing_token = NEW.fencing_token
        WHERE intent.operation_id = NEW.operation_id
          AND operation.kind = 'reconcile'
          AND operation.state = 'running'
          AND operation.phase = 'inventorying'
          AND operation.requested_by = lease.owner_client_id
          AND lease.lease_kind = 'write'
          AND lease.fencing_token = NEW.fencing_token
          AND lease.incarnation = control.incarnation
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
          AND control.mode = 'active'
          AND counts.page_count = NEW.page_count
          AND counts.object_count = NEW.object_count
          AND counts.known_count = NEW.known_count
          AND counts.object_count - counts.known_count = NEW.quarantined_count
          AND counts.missing_count = NEW.missing_count
          AND EXISTS (
              SELECT 1 FROM inventory_report_pages AS final
              WHERE final.operation_id = NEW.operation_id
                AND final.fencing_token = NEW.fencing_token
                AND final.sequence = NEW.page_count
                AND final.next_cursor = ''
          )
    ) THEN RAISE(ABORT, 'inventory completion requires a live classified final report') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM inventory_report_objects AS report
        JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id
        JOIN operations AS operation ON operation.id = intent.operation_id
        WHERE report.operation_id = NEW.operation_id
          AND report.fencing_token = NEW.fencing_token
          AND NOT EXISTS (
              SELECT 1 FROM locations AS location
              WHERE location.driver_id = intent.driver_id
                AND location.storage_key = report.storage_key
                AND location.state != 'deleted'
          )
          AND NOT EXISTS (
              SELECT 1 FROM recovery_manifests AS recovery
              WHERE recovery.sidecar_driver_id = intent.driver_id
                AND recovery.sidecar_storage_key = report.storage_key
                AND recovery.state != 'missing'
          )
          AND NOT EXISTS (
              SELECT 1 FROM quarantined_provider_objects AS quarantine
              WHERE quarantine.driver_id = intent.driver_id
                AND quarantine.storage_key = report.storage_key
                AND quarantine.namespace_id = operation.namespace_id
                AND quarantine.state IN ('quarantined', 'acknowledged', 'tombstoned')
          )
    ) THEN RAISE(ABORT, 'inventory completion requires every unknown object retained') END;
END;
