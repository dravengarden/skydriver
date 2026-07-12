PRAGMA foreign_keys = ON;

CREATE TABLE integrity_findings_v2 (
    id TEXT PRIMARY KEY,
    namespace_id TEXT REFERENCES namespaces(id) ON DELETE SET NULL,
    subject_kind TEXT NOT NULL CHECK (
        subject_kind IN (
            'driver',
            'manifest',
            'version',
            'pack',
            'extent',
            'location',
            'provider_object',
            'key'
        )
    ),
    subject_id TEXT NOT NULL,
    condition TEXT NOT NULL CHECK (
        condition IN (
            'driver_unavailable',
            'unindexed',
            'degraded',
            'missing',
            'corrupt',
            'key_unavailable',
            'unsupported_suite',
            'orphan',
            'quarantined',
            'unrecoverable'
        )
    ),
    state TEXT NOT NULL CHECK (
        state IN ('open', 'acknowledged', 'tombstoned', 'resolved')
    ),
    evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
    first_observed_at INTEGER NOT NULL,
    last_observed_at INTEGER NOT NULL,
    acknowledged_at INTEGER,
    resolved_at INTEGER,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    UNIQUE (subject_kind, subject_id, condition, state)
) STRICT;

INSERT INTO integrity_findings_v2 SELECT * FROM integrity_findings;
DROP TABLE integrity_findings;
ALTER TABLE integrity_findings_v2 RENAME TO integrity_findings;

CREATE TABLE inventory_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    driver_revision INTEGER NOT NULL CHECK (driver_revision > 0),
    prefix TEXT NOT NULL CHECK (length(prefix) BETWEEN 1 AND 2048),
    quarantine_grace_seconds INTEGER NOT NULL CHECK (
        quarantine_grace_seconds BETWEEN 60 AND 31536000
    ),
    created_at INTEGER NOT NULL,
    UNIQUE (operation_id, driver_id, prefix)
) STRICT;

CREATE INDEX idx_inventory_intents_driver_prefix
ON inventory_intents(driver_id, prefix);

CREATE TABLE inventory_report_pages (
    operation_id TEXT NOT NULL REFERENCES inventory_intents(operation_id) ON DELETE CASCADE,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    cursor TEXT NOT NULL CHECK (length(cursor) <= 4096),
    next_cursor TEXT NOT NULL CHECK (length(next_cursor) <= 4096),
    report_sha256 TEXT NOT NULL CHECK (length(report_sha256) = 64),
    object_count INTEGER NOT NULL CHECK (object_count BETWEEN 0 AND 64),
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (operation_id, fencing_token, sequence),
    UNIQUE (operation_id, fencing_token, cursor),
    CHECK (
        (sequence = 1 AND cursor = '')
        OR (sequence > 1 AND cursor != '')
    ),
    CHECK (next_cursor = '' OR object_count > 0)
) STRICT;

CREATE TABLE inventory_report_objects (
    operation_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    page_sequence INTEGER NOT NULL CHECK (page_sequence > 0),
    storage_key TEXT NOT NULL CHECK (length(storage_key) BETWEEN 1 AND 4096),
    provider_version TEXT CHECK (
        provider_version IS NULL OR length(provider_version) BETWEEN 1 AND 4096
    ),
    etag TEXT CHECK (etag IS NULL OR length(etag) BETWEEN 1 AND 4096),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (operation_id, fencing_token, storage_key),
    FOREIGN KEY (operation_id, fencing_token, page_sequence)
        REFERENCES inventory_report_pages(operation_id, fencing_token, sequence)
        ON DELETE CASCADE
) STRICT;

CREATE INDEX idx_inventory_report_objects_page
ON inventory_report_objects(operation_id, fencing_token, page_sequence);

CREATE TABLE quarantined_provider_objects (
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    storage_key TEXT NOT NULL CHECK (length(storage_key) BETWEEN 1 AND 4096),
    namespace_id TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    provider_version TEXT CHECK (
        provider_version IS NULL OR length(provider_version) BETWEEN 1 AND 4096
    ),
    etag TEXT CHECK (etag IS NULL OR length(etag) BETWEEN 1 AND 4096),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    state TEXT NOT NULL CHECK (state IN ('quarantined', 'resolved')),
    quarantine_until INTEGER NOT NULL,
    first_observed_at INTEGER NOT NULL,
    last_observed_at INTEGER NOT NULL,
    last_operation_id TEXT REFERENCES operations(id) ON DELETE SET NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    PRIMARY KEY (driver_id, storage_key),
    CHECK (quarantine_until >= first_observed_at)
) STRICT;

CREATE INDEX idx_quarantined_provider_objects_namespace_state
ON quarantined_provider_objects(namespace_id, state, quarantine_until);

CREATE TABLE inventory_completions (
    operation_id TEXT PRIMARY KEY REFERENCES inventory_intents(operation_id) ON DELETE CASCADE,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    report_sha256 TEXT NOT NULL CHECK (length(report_sha256) = 64),
    page_count INTEGER NOT NULL CHECK (page_count > 0),
    object_count INTEGER NOT NULL CHECK (object_count >= 0),
    known_count INTEGER NOT NULL CHECK (known_count >= 0),
    quarantined_count INTEGER NOT NULL CHECK (quarantined_count >= 0),
    missing_count INTEGER NOT NULL CHECK (missing_count >= 0),
    state TEXT NOT NULL DEFAULT 'staging' CHECK (state IN ('staging', 'committed')),
    completed_at INTEGER NOT NULL,
    committed_at INTEGER
) STRICT;

CREATE TRIGGER inventory_intent_requires_current_operation
BEFORE INSERT ON inventory_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM operations AS operation
        JOIN driver_instances AS driver ON driver.id = NEW.driver_id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE operation.id = NEW.operation_id
          AND operation.kind = 'reconcile'
          AND operation.state = 'planned'
          AND operation.incarnation = control.incarnation
          AND control.mode = 'active'
          AND driver.enabled = 1
          AND driver.revision = NEW.driver_revision
          AND NOT EXISTS (
              SELECT 1 FROM reconcile_intents
              WHERE operation_id = operation.id
          )
    ) THEN RAISE(ABORT, 'inventory intent requires a current reconcile operation and driver') END;
END;

CREATE TRIGGER inventory_reconcile_intent_exclusive
BEFORE INSERT ON reconcile_intents
WHEN EXISTS (
    SELECT 1 FROM inventory_intents WHERE operation_id = NEW.operation_id
)
BEGIN
    SELECT RAISE(ABORT, 'reconcile operation already owns an inventory intent');
END;

CREATE TRIGGER inventory_page_requires_live_fence
BEFORE INSERT ON inventory_report_pages
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM inventory_intents AS intent
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN driver_instances AS driver ON driver.id = intent.driver_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE intent.operation_id = NEW.operation_id
          AND operation.kind = 'reconcile'
          AND operation.state = 'running'
          AND operation.phase = 'inventorying'
          AND operation.requested_by = lease.owner_client_id
          AND operation.incarnation = control.incarnation
          AND driver.enabled = 1
          AND driver.revision = intent.driver_revision
          AND lease.lease_kind = 'write'
          AND lease.fencing_token = NEW.fencing_token
          AND lease.incarnation = control.incarnation
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
          AND control.mode = 'active'
    ) THEN RAISE(ABORT, 'inventory page requires a live fence') END;

    SELECT CASE WHEN NEW.sequence > 1 AND NOT EXISTS (
        SELECT 1
        FROM inventory_report_pages AS previous
        WHERE previous.operation_id = NEW.operation_id
          AND previous.fencing_token = NEW.fencing_token
          AND previous.sequence = NEW.sequence - 1
          AND previous.next_cursor = NEW.cursor
          AND previous.next_cursor != ''
    ) THEN RAISE(ABORT, 'inventory page cursor chain is incomplete') END;
END;

CREATE TRIGGER inventory_object_requires_page_and_scope
BEFORE INSERT ON inventory_report_objects
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM inventory_report_pages AS page
        JOIN inventory_intents AS intent ON intent.operation_id = page.operation_id
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE page.operation_id = NEW.operation_id
          AND page.fencing_token = NEW.fencing_token
          AND page.sequence = NEW.page_sequence
          AND substr(NEW.storage_key, 1, length(intent.prefix) + 1) = intent.prefix || '/'
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
    ) THEN RAISE(ABORT, 'inventory object requires a live page and owned prefix') END;
END;

CREATE TRIGGER inventory_completion_commit_requires_closed_operation
BEFORE UPDATE OF state ON inventory_completions
WHEN NEW.state = 'committed' AND OLD.state = 'staging'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM operations AS operation
        JOIN operation_components AS component
          ON component.id = operation.id || '/inventory'
        JOIN leases AS lease ON lease.operation_id = operation.id
        WHERE operation.id = NEW.operation_id
          AND operation.kind = 'reconcile'
          AND operation.state = 'succeeded'
          AND component.state = 'succeeded'
          AND lease.lease_kind = 'write'
          AND lease.fencing_token = NEW.fencing_token
          AND lease.released_at IS NOT NULL
    ) THEN RAISE(ABORT, 'inventory completion requires closed operation and lease') END;
END;

CREATE TRIGGER inventory_completion_requires_classified_report
BEFORE INSERT ON inventory_completions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM inventory_intents AS intent
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
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
    ) THEN RAISE(ABORT, 'inventory completion requires a live fence') END;

    SELECT CASE WHEN NEW.page_count != (
        SELECT COUNT(*)
        FROM inventory_report_pages
        WHERE operation_id = NEW.operation_id
          AND fencing_token = NEW.fencing_token
    ) OR NOT EXISTS (
        SELECT 1
        FROM inventory_report_pages
        WHERE operation_id = NEW.operation_id
          AND fencing_token = NEW.fencing_token
          AND sequence = NEW.page_count
          AND next_cursor = ''
    ) THEN RAISE(ABORT, 'inventory completion requires a final page') END;

    SELECT CASE WHEN NEW.object_count != (
        SELECT COUNT(*)
        FROM inventory_report_objects
        WHERE operation_id = NEW.operation_id
          AND fencing_token = NEW.fencing_token
    ) THEN RAISE(ABORT, 'inventory completion object count changed') END;

    SELECT CASE WHEN NEW.known_count != (
        SELECT COUNT(*)
        FROM inventory_report_objects AS report
        JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id
        WHERE report.operation_id = NEW.operation_id
          AND report.fencing_token = NEW.fencing_token
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
    ) THEN RAISE(ABORT, 'inventory completion known count changed') END;

    SELECT CASE WHEN NEW.quarantined_count != NEW.object_count - NEW.known_count
    THEN RAISE(ABORT, 'inventory completion quarantine count changed') END;

    SELECT CASE WHEN NEW.missing_count != (
        SELECT COUNT(*)
        FROM (
            SELECT 'location' AS subject_kind, location.id AS subject_id
            FROM inventory_intents AS intent
            JOIN operations AS operation ON operation.id = intent.operation_id
            JOIN locations AS location ON location.driver_id = intent.driver_id
            JOIN extents AS extent ON extent.id = location.extent_id
            JOIN packs AS pack ON pack.id = extent.pack_id
            WHERE intent.operation_id = NEW.operation_id
              AND pack.namespace_id = operation.namespace_id
              AND location.state IN ('verified', 'available')
              AND substr(location.storage_key, 1, length(intent.prefix) + 1)
                  = intent.prefix || '/'
              AND NOT EXISTS (
                  SELECT 1 FROM inventory_report_objects AS report
                  WHERE report.operation_id = NEW.operation_id
                    AND report.fencing_token = NEW.fencing_token
                    AND report.storage_key = location.storage_key
              )
            UNION ALL
            SELECT 'manifest', recovery.manifest_sha256
            FROM inventory_intents AS intent
            JOIN operations AS operation ON operation.id = intent.operation_id
            JOIN recovery_manifests AS recovery
              ON recovery.sidecar_driver_id = intent.driver_id
            JOIN object_versions AS version ON version.id = recovery.version_id
            JOIN objects AS object ON object.id = version.object_id
            WHERE intent.operation_id = NEW.operation_id
              AND object.namespace_id = operation.namespace_id
              AND recovery.state = 'durable'
              AND substr(recovery.sidecar_storage_key, 1, length(intent.prefix) + 1)
                  = intent.prefix || '/'
              AND NOT EXISTS (
                  SELECT 1 FROM inventory_report_objects AS report
                  WHERE report.operation_id = NEW.operation_id
                    AND report.fencing_token = NEW.fencing_token
                    AND report.storage_key = recovery.sidecar_storage_key
              )
        )
    ) THEN RAISE(ABORT, 'inventory completion missing count changed') END;

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
                AND quarantine.state = 'quarantined'
          )
    ) THEN RAISE(ABORT, 'inventory completion requires every unknown object in quarantine') END;
END;
