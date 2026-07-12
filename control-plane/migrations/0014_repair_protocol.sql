PRAGMA foreign_keys = ON;

CREATE TABLE repair_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES object_versions(id),
    manifest_sha256 TEXT NOT NULL,
    recovery_revision INTEGER NOT NULL CHECK (recovery_revision > 0),
    target_driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    expected_object_count INTEGER NOT NULL CHECK (expected_object_count > 0),
    expected_target_count INTEGER NOT NULL CHECK (expected_target_count > 0),
    created_at INTEGER NOT NULL,
    UNIQUE (operation_id, version_id, manifest_sha256, recovery_revision, target_driver_id)
) STRICT;

CREATE TABLE repair_objects (
    operation_id TEXT NOT NULL REFERENCES repair_intents(operation_id) ON DELETE CASCADE,
    storage_key TEXT NOT NULL,
    provider_version TEXT,
    expected_bytes INTEGER NOT NULL CHECK (expected_bytes > 0),
    state TEXT NOT NULL DEFAULT 'planned' CHECK (state IN ('planned', 'repaired')),
    observed_provider_version TEXT,
    observed_etag TEXT,
    repaired_at INTEGER,
    CHECK ((state = 'planned' AND observed_provider_version IS NULL AND
            observed_etag IS NULL AND repaired_at IS NULL) OR
           (state = 'repaired' AND repaired_at IS NOT NULL)),
    PRIMARY KEY (operation_id, storage_key)
) STRICT;

CREATE TABLE repair_targets (
    operation_id TEXT NOT NULL REFERENCES repair_intents(operation_id) ON DELETE CASCADE,
    location_id TEXT NOT NULL REFERENCES locations(id),
    location_revision INTEGER NOT NULL CHECK (location_revision > 0),
    storage_key TEXT NOT NULL,
    provider_version TEXT,
    storage_offset INTEGER NOT NULL CHECK (storage_offset >= 0),
    storage_length INTEGER NOT NULL CHECK (storage_length > 0),
    state TEXT NOT NULL DEFAULT 'planned' CHECK (state IN ('planned', 'repaired')),
    repaired_at INTEGER,
    CHECK ((state = 'planned' AND repaired_at IS NULL) OR
           (state = 'repaired' AND repaired_at IS NOT NULL)),
    PRIMARY KEY (operation_id, location_id),
    FOREIGN KEY (operation_id, storage_key)
        REFERENCES repair_objects(operation_id, storage_key)
) STRICT;

CREATE INDEX idx_repair_targets_location_state
ON repair_targets(location_id, state);

CREATE TABLE repair_completions (
    operation_id TEXT PRIMARY KEY REFERENCES repair_intents(operation_id) ON DELETE CASCADE,
    report_sha256 TEXT NOT NULL UNIQUE CHECK (length(report_sha256) = 64),
    object_count INTEGER NOT NULL CHECK (object_count > 0),
    location_count INTEGER NOT NULL CHECK (location_count > 0),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
    lease_id TEXT NOT NULL,
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    state TEXT NOT NULL DEFAULT 'staging' CHECK (state IN ('staging', 'committed')),
    completed_at INTEGER NOT NULL,
    committed_at INTEGER
) STRICT;

CREATE TABLE repair_completion_objects (
    operation_id TEXT NOT NULL REFERENCES repair_completions(operation_id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    storage_key TEXT NOT NULL,
    provider_version TEXT,
    etag TEXT,
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    PRIMARY KEY (operation_id, storage_key),
    FOREIGN KEY (operation_id, storage_key)
        REFERENCES repair_objects(operation_id, storage_key)
) STRICT;

CREATE TRIGGER repair_intent_requires_published_recovery
BEFORE INSERT ON repair_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM object_versions AS version
        JOIN recovery_manifests AS recovery ON recovery.version_id = version.id
        WHERE version.id = NEW.version_id
          AND version.state = 'published'
          AND version.manifest_sha256 = NEW.manifest_sha256
          AND recovery.manifest_sha256 = NEW.manifest_sha256
          AND recovery.revision = NEW.recovery_revision
          AND recovery.state = 'durable'
          AND recovery.verified_at IS NOT NULL
    ) THEN RAISE(ABORT, 'repair intent requires published durable recovery') END;
END;

CREATE TRIGGER repair_object_requires_pinned_provider_object
BEFORE INSERT ON repair_objects
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repair_intents AS intent
        JOIN locations AS location
          ON location.driver_id = intent.target_driver_id
         AND location.storage_key = NEW.storage_key
         AND location.provider_version IS NEW.provider_version
        JOIN extents AS extent ON extent.id = location.extent_id
        JOIN version_packs AS version_pack ON version_pack.pack_id = extent.pack_id
        WHERE intent.operation_id = NEW.operation_id
          AND version_pack.version_id = intent.version_id
          AND location.state = 'missing'
    ) THEN RAISE(ABORT, 'repair object must contain a pinned missing location') END;
END;

CREATE TRIGGER repair_target_requires_pinned_missing_location
BEFORE INSERT ON repair_targets
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repair_intents AS intent
        JOIN locations AS location ON location.id = NEW.location_id
        JOIN extents AS extent ON extent.id = location.extent_id
        JOIN version_packs AS version_pack ON version_pack.pack_id = extent.pack_id
        WHERE intent.operation_id = NEW.operation_id
          AND version_pack.version_id = intent.version_id
          AND location.driver_id = intent.target_driver_id
          AND location.state = 'missing'
          AND location.revision = NEW.location_revision
          AND location.storage_key = NEW.storage_key
          AND location.provider_version IS NEW.provider_version
          AND location.storage_offset = NEW.storage_offset
          AND location.storage_length = NEW.storage_length
          AND EXISTS(SELECT 1 FROM repair_objects AS object
                     WHERE object.operation_id = NEW.operation_id
                       AND object.storage_key = NEW.storage_key
                       AND object.provider_version IS NEW.provider_version)
    ) THEN RAISE(ABORT, 'repair target must be a pinned missing location') END;
END;

CREATE TRIGGER repair_component_requires_complete_plan
BEFORE INSERT ON operation_components
WHEN NEW.component_kind = 'repair'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repair_intents AS intent
        WHERE intent.operation_id = NEW.operation_id
          AND (SELECT COUNT(*)
               FROM repair_targets AS target
               WHERE target.operation_id = intent.operation_id) = intent.expected_target_count
          AND (SELECT COUNT(*)
               FROM repair_objects AS object
               WHERE object.operation_id = intent.operation_id) = intent.expected_object_count
    ) THEN RAISE(ABORT, 'repair component requires a complete target plan') END;
END;

CREATE TRIGGER repair_completion_requires_live_fence
BEFORE INSERT ON repair_completions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repair_intents AS intent
        JOIN operations AS operation ON operation.id = intent.operation_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE intent.operation_id = NEW.operation_id
          AND operation.kind = 'copy'
          AND operation.state = 'running'
          AND operation.phase = 'repairing'
          AND lease.id = NEW.lease_id
          AND lease.owner_client_id = operation.requested_by
          AND lease.incarnation = NEW.incarnation
          AND lease.fencing_token = NEW.fencing_token
          AND lease.lease_kind = 'write'
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
          AND lease.incarnation = control.incarnation
          AND control.mode = 'active'
          AND NEW.object_count = intent.expected_object_count
          AND NEW.location_count = intent.expected_target_count
          AND NEW.ciphertext_bytes = operation.useful_bytes_total
    ) THEN RAISE(ABORT, 'repair completion requires the current live fence') END;
END;

CREATE TRIGGER repair_completion_object_requires_pinned_result
BEFORE INSERT ON repair_completion_objects
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repair_intents AS intent
        JOIN repair_objects AS object
          ON object.operation_id = intent.operation_id
         AND object.storage_key = NEW.storage_key
        WHERE intent.operation_id = NEW.operation_id
          AND intent.target_driver_id = NEW.driver_id
          AND object.state = 'planned'
          AND object.expected_bytes = NEW.size_bytes
          AND (object.provider_version IS NULL OR
               object.provider_version = NEW.provider_version)
    ) THEN RAISE(ABORT, 'repair result differs from the pinned provider object') END;
END;

CREATE TRIGGER missing_location_reactivation_requires_repair_fence
BEFORE UPDATE OF state ON locations
WHEN OLD.state = 'missing' AND NEW.state = 'verified'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repair_targets AS target
        JOIN repair_completions AS completion
          ON completion.operation_id = target.operation_id
         AND completion.state = 'staging'
        JOIN operations AS operation ON operation.id = target.operation_id
        JOIN leases AS lease ON lease.operation_id = operation.id
        JOIN control_plane_state AS control ON control.singleton = 1
        WHERE target.location_id = OLD.id
          AND target.location_revision = OLD.revision
          AND target.state = 'planned'
          AND operation.state = 'verifying'
          AND lease.id = completion.lease_id
          AND lease.incarnation = completion.incarnation
          AND lease.fencing_token = completion.fencing_token
          AND lease.owner_client_id = operation.requested_by
          AND lease.lease_kind = 'write'
          AND lease.released_at IS NULL
          AND lease.expires_at > unixepoch()
          AND lease.incarnation = control.incarnation
          AND control.mode = 'active'
    ) THEN RAISE(ABORT, 'missing location reactivation requires a live repair fence') END;
END;

CREATE TRIGGER repaired_object_requires_matching_completion
BEFORE UPDATE OF state ON repair_objects
WHEN OLD.state = 'planned' AND NEW.state = 'repaired'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repair_completion_objects AS completed
        WHERE completed.operation_id = NEW.operation_id
          AND completed.storage_key = NEW.storage_key
          AND completed.size_bytes = NEW.expected_bytes
          AND completed.provider_version IS NEW.observed_provider_version
          AND completed.etag IS NEW.observed_etag
    ) THEN RAISE(ABORT, 'repaired object requires matching completion evidence') END;
END;

CREATE TRIGGER repaired_target_requires_available_location
BEFORE UPDATE OF state ON repair_targets
WHEN OLD.state = 'planned' AND NEW.state = 'repaired'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM locations AS location
        JOIN repair_objects AS object
          ON object.operation_id = NEW.operation_id
         AND object.storage_key = NEW.storage_key
        WHERE location.id = NEW.location_id
          AND location.state = 'available'
          AND location.revision = NEW.location_revision + 2
          AND object.state = 'repaired'
    ) THEN RAISE(ABORT, 'repaired target requires the reverified location') END;
END;

CREATE TRIGGER repair_commit_requires_complete_reactivation
BEFORE UPDATE OF state ON operations
WHEN OLD.state = 'verifying' AND NEW.state = 'committing'
     AND EXISTS(SELECT 1 FROM repair_intents WHERE operation_id = OLD.id)
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repair_intents AS intent
        JOIN repair_completions AS completion ON completion.operation_id = intent.operation_id
        WHERE intent.operation_id = NEW.id
          AND completion.state = 'staging'
          AND (SELECT COUNT(*) FROM repair_objects AS object
               WHERE object.operation_id = intent.operation_id
                 AND object.state = 'repaired') = intent.expected_object_count
          AND (SELECT COUNT(*) FROM repair_targets AS target
               WHERE target.operation_id = intent.operation_id
                 AND target.state = 'repaired') = intent.expected_target_count
          AND (SELECT COUNT(*) FROM repair_completion_objects AS completed
               WHERE completed.operation_id = intent.operation_id) = intent.expected_object_count
    ) THEN RAISE(ABORT, 'repair commit requires complete target reactivation') END;
END;

CREATE TRIGGER repair_completion_commit_requires_closed_operation
BEFORE UPDATE OF state ON repair_completions
WHEN NEW.state = 'committed' AND OLD.state = 'staging'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM operations AS operation
        JOIN operation_components AS component
          ON component.id = operation.id || '/repair'
        JOIN leases AS lease ON lease.operation_id = operation.id
        WHERE operation.id = NEW.operation_id
          AND operation.kind = 'copy'
          AND operation.state = 'succeeded'
          AND component.state = 'succeeded'
          AND lease.id = NEW.lease_id
          AND lease.incarnation = NEW.incarnation
          AND lease.fencing_token = NEW.fencing_token
          AND lease.lease_kind = 'write'
          AND lease.released_at IS NOT NULL
    ) THEN RAISE(ABORT, 'repair completion requires closed operation and lease') END;
END;
