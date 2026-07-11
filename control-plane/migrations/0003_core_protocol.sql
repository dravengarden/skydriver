PRAGMA foreign_keys = ON;

CREATE TABLE control_plane_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    incarnation TEXT NOT NULL UNIQUE CHECK (
        length(incarnation) = 32
        AND incarnation NOT GLOB '*[^0-9a-f]*'
    ),
    mode TEXT NOT NULL CHECK (mode IN ('active', 'maintenance', 'recovering')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    recovered_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

INSERT INTO control_plane_state (
    singleton,
    incarnation,
    mode,
    created_at,
    updated_at
)
VALUES (
    1,
    lower(hex(randomblob(16))),
    'active',
    unixepoch(),
    unixepoch()
);

CREATE TABLE namespaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 256),
    crypto_suite TEXT NOT NULL,
    root_key_version INTEGER NOT NULL DEFAULT 1 CHECK (root_key_version > 0),
    active_key_epoch INTEGER NOT NULL DEFAULT 1 CHECK (active_key_epoch > 0),
    replica_policy_json TEXT NOT NULL CHECK (json_valid(replica_policy_json)),
    retention_policy_json TEXT NOT NULL CHECK (json_valid(retention_policy_json)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE driver_instances (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    config_json TEXT NOT NULL CHECK (json_valid(config_json)),
    credential_ref TEXT REFERENCES credential_envelopes(id),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE credential_envelopes (
    id TEXT PRIMARY KEY,
    envelope_algorithm TEXT NOT NULL,
    key_version TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL,
    rotated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 256),
    sdk_version TEXT NOT NULL,
    capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
    labels_json TEXT NOT NULL CHECK (json_valid(labels_json)),
    state TEXT NOT NULL CHECK (state IN ('online', 'offline', 'disabled')),
    last_heartbeat_at INTEGER,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE client_token_verifiers (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    verifier_algorithm TEXT NOT NULL CHECK (verifier_algorithm = 'sha256/v1'),
    verifier_sha256 TEXT NOT NULL UNIQUE CHECK (length(verifier_sha256) = 64),
    expires_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE client_namespace_permissions (
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    namespace_id TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (
        role IN ('reader', 'importer', 'relay', 'restorer', 'janitor', 'administrator')
    ),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (client_id, namespace_id, role)
) STRICT;

CREATE TABLE objects (
    id TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    logical_name TEXT NOT NULL CHECK (length(logical_name) BETWEEN 1 AND 2048),
    current_generation INTEGER CHECK (current_generation IS NULL OR current_generation > 0),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (namespace_id, logical_name)
) STRICT;

CREATE TABLE object_versions (
    id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation > 0),
    manifest_sha256 TEXT NOT NULL UNIQUE CHECK (length(manifest_sha256) = 64),
    plaintext_sha256 TEXT CHECK (
        plaintext_sha256 IS NULL OR length(plaintext_sha256) = 64
    ),
    plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes >= 0),
    chunk_count INTEGER NOT NULL CHECK (chunk_count >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('staging', 'published', 'retired', 'tombstoned')
    ),
    published_at INTEGER,
    created_at INTEGER NOT NULL,
    UNIQUE (object_id, generation)
) STRICT;

CREATE TABLE recovery_manifests (
    manifest_sha256 TEXT PRIMARY KEY CHECK (length(manifest_sha256) = 64),
    version_id TEXT NOT NULL UNIQUE REFERENCES object_versions(id) ON DELETE CASCADE,
    schema_version TEXT NOT NULL CHECK (schema_version = 'carrack.recovery.v1'),
    r2_storage_key TEXT NOT NULL UNIQUE CHECK (length(r2_storage_key) BETWEEN 1 AND 4096),
    sidecar_driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    sidecar_storage_key TEXT NOT NULL CHECK (
        length(sidecar_storage_key) BETWEEN 1 AND 4096
    ),
    state TEXT NOT NULL CHECK (state IN ('staging', 'durable', 'missing', 'corrupt')),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
    verified_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (sidecar_driver_id, sidecar_storage_key)
) STRICT;

CREATE TABLE packs (
    id TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    crypto_suite TEXT NOT NULL,
    root_key_version INTEGER NOT NULL CHECK (root_key_version > 0),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    ciphertext_sha256 TEXT NOT NULL UNIQUE CHECK (length(ciphertext_sha256) = 64),
    plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes > 0),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
    frame_bytes INTEGER NOT NULL CHECK (frame_bytes > 0),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE extents (
    id TEXT PRIMARY KEY,
    pack_id TEXT NOT NULL REFERENCES packs(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    first_frame INTEGER NOT NULL CHECK (first_frame >= 0),
    frame_count INTEGER NOT NULL CHECK (frame_count > 0),
    ciphertext_offset INTEGER NOT NULL CHECK (ciphertext_offset >= 0),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
    ciphertext_sha256 TEXT NOT NULL CHECK (length(ciphertext_sha256) = 64),
    created_at INTEGER NOT NULL,
    UNIQUE (pack_id, ordinal),
    UNIQUE (pack_id, first_frame),
    UNIQUE (pack_id, ciphertext_offset),
    UNIQUE (ciphertext_sha256, ciphertext_bytes)
) STRICT;

CREATE TABLE version_packs (
    version_id TEXT NOT NULL REFERENCES object_versions(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    pack_id TEXT NOT NULL REFERENCES packs(id),
    plaintext_offset INTEGER NOT NULL CHECK (plaintext_offset >= 0),
    PRIMARY KEY (version_id, ordinal),
    UNIQUE (version_id, pack_id)
) STRICT;

CREATE TABLE chunks (
    id TEXT PRIMARY KEY,
    plaintext_sha256 TEXT NOT NULL CHECK (length(plaintext_sha256) = 64),
    plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes > 0),
    created_at INTEGER NOT NULL,
    UNIQUE (plaintext_sha256, plaintext_bytes)
) STRICT;

CREATE TABLE version_chunks (
    version_id TEXT NOT NULL REFERENCES object_versions(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    chunk_id TEXT NOT NULL REFERENCES chunks(id),
    plaintext_offset INTEGER NOT NULL CHECK (plaintext_offset >= 0),
    PRIMARY KEY (version_id, ordinal)
) STRICT;

CREATE TABLE pack_entries (
    pack_id TEXT NOT NULL REFERENCES packs(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    chunk_id TEXT NOT NULL REFERENCES chunks(id),
    plaintext_offset INTEGER NOT NULL CHECK (plaintext_offset >= 0),
    plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes > 0),
    ciphertext_offset INTEGER NOT NULL CHECK (ciphertext_offset >= 0),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
    PRIMARY KEY (pack_id, ordinal),
    UNIQUE (pack_id, chunk_id, plaintext_offset)
) STRICT;

CREATE TABLE locations (
    id TEXT PRIMARY KEY,
    extent_id TEXT NOT NULL REFERENCES extents(id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    storage_key TEXT NOT NULL CHECK (length(storage_key) BETWEEN 1 AND 4096),
    provider_version TEXT,
    storage_offset INTEGER NOT NULL CHECK (storage_offset >= 0),
    storage_length INTEGER NOT NULL CHECK (storage_length > 0),
    ciphertext_sha256 TEXT NOT NULL CHECK (length(ciphertext_sha256) = 64),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
    state TEXT NOT NULL CHECK (
        state IN (
            'staging',
            'verified',
            'available',
            'missing',
            'corrupt',
            'quarantined',
            'tombstoned',
            'deleted'
        )
    ),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    verified_at INTEGER,
    tombstoned_at INTEGER,
    deleted_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (driver_id, storage_key, storage_offset, storage_length)
) STRICT;

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL REFERENCES namespaces(id),
    kind TEXT NOT NULL CHECK (
        kind IN ('import', 'copy', 'move', 'restore', 'compact', 'verify', 'reconcile', 'gc')
    ),
    state TEXT NOT NULL CHECK (
        state IN ('planned', 'running', 'verifying', 'committing', 'succeeded', 'failed', 'cancelled')
    ),
    phase TEXT NOT NULL CHECK (length(phase) BETWEEN 1 AND 128),
    idempotency_key TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES clients(id),
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    useful_bytes_total INTEGER CHECK (useful_bytes_total IS NULL OR useful_bytes_total >= 0),
    useful_bytes_verified INTEGER NOT NULL DEFAULT 0 CHECK (useful_bytes_verified >= 0),
    wire_bytes_read INTEGER NOT NULL DEFAULT 0 CHECK (wire_bytes_read >= 0),
    wire_bytes_written INTEGER NOT NULL DEFAULT 0 CHECK (wire_bytes_written >= 0),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    throttle_count INTEGER NOT NULL DEFAULT 0 CHECK (throttle_count >= 0),
    error_code TEXT,
    error_message TEXT,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    started_at INTEGER,
    finished_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (namespace_id, idempotency_key)
) STRICT;

CREATE TABLE operation_components (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    client_id TEXT REFERENCES clients(id) ON DELETE SET NULL,
    component_kind TEXT NOT NULL CHECK (length(component_kind) BETWEEN 1 AND 128),
    source_driver_id TEXT REFERENCES driver_instances(id),
    destination_driver_id TEXT REFERENCES driver_instances(id),
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'running', 'stalled', 'verifying', 'succeeded', 'failed', 'cancelled')
    ),
    current_attempt INTEGER NOT NULL DEFAULT 0 CHECK (current_attempt >= 0),
    useful_bytes_total INTEGER CHECK (useful_bytes_total IS NULL OR useful_bytes_total >= 0),
    useful_bytes_verified INTEGER NOT NULL DEFAULT 0 CHECK (useful_bytes_verified >= 0),
    wire_bytes_read INTEGER NOT NULL DEFAULT 0 CHECK (wire_bytes_read >= 0),
    wire_bytes_written INTEGER NOT NULL DEFAULT 0 CHECK (wire_bytes_written >= 0),
    active_nanoseconds INTEGER NOT NULL DEFAULT 0 CHECK (active_nanoseconds >= 0),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    throttle_count INTEGER NOT NULL DEFAULT 0 CHECK (throttle_count >= 0),
    last_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_sample_at INTEGER,
    lease_id TEXT,
    fencing_token INTEGER CHECK (fencing_token IS NULL OR fencing_token > 0),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    started_at INTEGER,
    finished_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE operation_attempts (
    component_id TEXT NOT NULL REFERENCES operation_components(id) ON DELETE CASCADE,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    client_id TEXT NOT NULL REFERENCES clients(id),
    lease_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    state TEXT NOT NULL CHECK (state IN ('running', 'succeeded', 'failed', 'superseded')),
    last_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    wire_bytes_read INTEGER NOT NULL DEFAULT 0 CHECK (wire_bytes_read >= 0),
    wire_bytes_written INTEGER NOT NULL DEFAULT 0 CHECK (wire_bytes_written >= 0),
    useful_bytes_verified INTEGER NOT NULL DEFAULT 0 CHECK (useful_bytes_verified >= 0),
    active_nanoseconds INTEGER NOT NULL DEFAULT 0 CHECK (active_nanoseconds >= 0),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    throttle_count INTEGER NOT NULL DEFAULT 0 CHECK (throttle_count >= 0),
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    PRIMARY KEY (component_id, attempt)
) STRICT;

CREATE TABLE leases (
    id TEXT PRIMARY KEY,
    resource_kind TEXT NOT NULL CHECK (
        resource_kind IN ('namespace', 'object', 'version', 'pack', 'location', 'operation', 'component')
    ),
    resource_id TEXT NOT NULL,
    lease_kind TEXT NOT NULL CHECK (lease_kind IN ('read', 'write', 'delete')),
    owner_client_id TEXT NOT NULL REFERENCES clients(id),
    operation_id TEXT REFERENCES operations(id) ON DELETE CASCADE,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    expires_at INTEGER NOT NULL,
    released_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (resource_kind, resource_id, lease_kind)
) STRICT;

CREATE TABLE telemetry_minute_buckets (
    component_id TEXT NOT NULL REFERENCES operation_components(id) ON DELETE CASCADE,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    bucket_start INTEGER NOT NULL,
    first_observed_at INTEGER NOT NULL,
    last_observed_at INTEGER NOT NULL,
    sample_count INTEGER NOT NULL CHECK (sample_count > 0),
    wire_bytes_read_delta INTEGER NOT NULL CHECK (wire_bytes_read_delta >= 0),
    wire_bytes_written_delta INTEGER NOT NULL CHECK (wire_bytes_written_delta >= 0),
    useful_bytes_verified_delta INTEGER NOT NULL CHECK (useful_bytes_verified_delta >= 0),
    active_nanoseconds_delta INTEGER NOT NULL CHECK (active_nanoseconds_delta >= 0),
    retry_count_delta INTEGER NOT NULL CHECK (retry_count_delta >= 0),
    throttle_count_delta INTEGER NOT NULL CHECK (throttle_count_delta >= 0),
    PRIMARY KEY (component_id, attempt, bucket_start),
    FOREIGN KEY (component_id, attempt)
        REFERENCES operation_attempts(component_id, attempt) ON DELETE CASCADE
) STRICT;

CREATE TABLE telemetry_rollups (
    component_id TEXT NOT NULL REFERENCES operation_components(id) ON DELETE CASCADE,
    resolution TEXT NOT NULL CHECK (resolution IN ('hour', 'day')),
    bucket_start INTEGER NOT NULL,
    active_nanoseconds INTEGER NOT NULL CHECK (active_nanoseconds >= 0),
    wall_nanoseconds INTEGER NOT NULL CHECK (wall_nanoseconds >= 0),
    wire_bytes_read INTEGER NOT NULL CHECK (wire_bytes_read >= 0),
    wire_bytes_written INTEGER NOT NULL CHECK (wire_bytes_written >= 0),
    useful_bytes_verified INTEGER NOT NULL CHECK (useful_bytes_verified >= 0),
    retry_count INTEGER NOT NULL CHECK (retry_count >= 0),
    throttle_count INTEGER NOT NULL CHECK (throttle_count >= 0),
    sample_count INTEGER NOT NULL CHECK (sample_count > 0),
    PRIMARY KEY (component_id, resolution, bucket_start)
) STRICT;

CREATE TABLE gc_epochs (
    id TEXT PRIMARY KEY,
    namespace_id TEXT REFERENCES namespaces(id) ON DELETE CASCADE,
    incarnation TEXT NOT NULL CHECK (length(incarnation) = 32),
    state TEXT NOT NULL CHECK (state IN ('marking', 'grace', 'sweeping', 'succeeded', 'failed')),
    grace_until INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE gc_candidates (
    gc_epoch_id TEXT NOT NULL REFERENCES gc_epochs(id) ON DELETE CASCADE,
    location_id TEXT NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
    location_revision INTEGER NOT NULL CHECK (location_revision > 0),
    state TEXT NOT NULL CHECK (state IN ('marked', 'cancelled', 'delete_pending', 'deleted', 'failed')),
    reason TEXT NOT NULL,
    marked_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (gc_epoch_id, location_id)
) STRICT;

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    namespace_id TEXT REFERENCES namespaces(id) ON DELETE SET NULL,
    operation_id TEXT REFERENCES operations(id) ON DELETE SET NULL,
    client_id TEXT REFERENCES clients(id) ON DELETE SET NULL,
    event_kind TEXT NOT NULL,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    details_json TEXT NOT NULL CHECK (json_valid(details_json)),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE integrity_findings (
    id TEXT PRIMARY KEY,
    namespace_id TEXT REFERENCES namespaces(id) ON DELETE SET NULL,
    subject_kind TEXT NOT NULL CHECK (
        subject_kind IN ('driver', 'manifest', 'version', 'pack', 'extent', 'location', 'key')
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

CREATE INDEX idx_clients_state_heartbeat
ON clients(state, last_heartbeat_at);

CREATE INDEX idx_client_permissions_namespace_role
ON client_namespace_permissions(namespace_id, role, client_id);

CREATE INDEX idx_object_versions_object_state
ON object_versions(object_id, state, generation);

CREATE INDEX idx_extents_pack_ordinal
ON extents(pack_id, ordinal);

CREATE INDEX idx_locations_extent_state
ON locations(extent_id, state);

CREATE INDEX idx_locations_driver_state
ON locations(driver_id, state, updated_at);

CREATE INDEX idx_operations_state_updated
ON operations(state, updated_at);

CREATE INDEX idx_components_operation_state
ON operation_components(operation_id, state, updated_at);

CREATE INDEX idx_components_client_state
ON operation_components(client_id, state, last_sample_at);

CREATE INDEX idx_leases_expiry
ON leases(expires_at, released_at);

CREATE INDEX idx_telemetry_minute_time
ON telemetry_minute_buckets(bucket_start, component_id);

CREATE INDEX idx_telemetry_rollups_time
ON telemetry_rollups(resolution, bucket_start, component_id);

CREATE INDEX idx_gc_candidates_state
ON gc_candidates(state, updated_at);

CREATE INDEX idx_audit_events_subject_time
ON audit_events(subject_kind, subject_id, created_at);

CREATE INDEX idx_integrity_findings_state_time
ON integrity_findings(state, last_observed_at);

CREATE TRIGGER publish_version_requires_recovery_manifest
BEFORE UPDATE OF state ON object_versions
WHEN NEW.state = 'published' AND OLD.state != 'published'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM recovery_manifests
        WHERE version_id = NEW.id
          AND manifest_sha256 = NEW.manifest_sha256
          AND state = 'durable'
          AND verified_at IS NOT NULL
    ) THEN RAISE(ABORT, 'published version requires a durable recovery manifest') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM version_packs AS version_pack
        JOIN extents AS extent ON extent.pack_id = version_pack.pack_id
        WHERE version_pack.version_id = NEW.id
          AND NOT EXISTS (
              SELECT 1
              FROM locations AS location
              WHERE location.extent_id = extent.id
                AND location.state IN ('verified', 'available')
                AND location.verified_at IS NOT NULL
          )
    ) THEN RAISE(ABORT, 'published version requires every extent to be verified') END;
END;

CREATE TRIGGER object_version_must_start_staging
BEFORE INSERT ON object_versions
WHEN NEW.state != 'staging'
BEGIN
    SELECT RAISE(ABORT, 'object version must start in staging');
END;

CREATE TRIGGER current_generation_requires_published_version
BEFORE UPDATE OF current_generation ON objects
WHEN NEW.current_generation IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM object_versions
        WHERE object_id = NEW.id
          AND generation = NEW.current_generation
          AND state = 'published'
    ) THEN RAISE(ABORT, 'object generation must reference a published version') END;
END;

CREATE TRIGGER immutable_published_version_identity
BEFORE UPDATE OF manifest_sha256, plaintext_sha256, plaintext_bytes, chunk_count
ON object_versions
WHEN OLD.state IN ('published', 'retired', 'tombstoned')
BEGIN
    SELECT RAISE(ABORT, 'published object version identity is immutable');
END;

CREATE TRIGGER location_identity_must_match_extent
BEFORE INSERT ON locations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM extents
        WHERE id = NEW.extent_id
          AND ciphertext_sha256 = NEW.ciphertext_sha256
          AND ciphertext_bytes = NEW.ciphertext_bytes
    ) THEN RAISE(ABORT, 'location identity must match its extent') END;
END;

CREATE TRIGGER location_must_start_staging
BEFORE INSERT ON locations
WHEN NEW.state != 'staging'
BEGIN
    SELECT RAISE(ABORT, 'location must start in staging');
END;

CREATE TRIGGER location_state_transition_is_monotonic
BEFORE UPDATE OF state ON locations
WHEN OLD.state != NEW.state
  AND NOT (
      (OLD.state = 'staging' AND NEW.state IN ('verified', 'quarantined'))
      OR (OLD.state = 'verified' AND NEW.state IN ('available', 'quarantined'))
      OR (OLD.state = 'available' AND NEW.state IN (
          'missing', 'corrupt', 'quarantined', 'tombstoned'
      ))
      OR (OLD.state = 'missing' AND NEW.state IN ('verified', 'tombstoned'))
      OR (OLD.state = 'corrupt' AND NEW.state = 'quarantined')
      OR (OLD.state = 'quarantined' AND NEW.state IN ('verified', 'tombstoned'))
      OR (OLD.state = 'tombstoned' AND NEW.state IN ('available', 'deleted'))
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid location state transition');
END;

CREATE TRIGGER operation_requires_current_incarnation
BEFORE INSERT ON operations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM control_plane_state
        WHERE singleton = 1
          AND mode = 'active'
          AND incarnation = NEW.incarnation
    ) THEN RAISE(ABORT, 'operation requires the active incarnation') END;
END;

CREATE TRIGGER operation_state_transition_is_monotonic
BEFORE UPDATE OF state ON operations
WHEN OLD.state != NEW.state
  AND NOT (
      (OLD.state = 'planned' AND NEW.state IN ('running', 'cancelled'))
      OR (OLD.state = 'running' AND NEW.state IN ('verifying', 'failed', 'cancelled'))
      OR (OLD.state = 'verifying' AND NEW.state IN ('committing', 'failed', 'cancelled'))
      OR (OLD.state = 'committing' AND NEW.state IN ('succeeded', 'failed'))
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid operation state transition');
END;

CREATE TRIGGER lease_requires_current_incarnation
BEFORE INSERT ON leases
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM control_plane_state
        WHERE singleton = 1
          AND mode = 'active'
          AND incarnation = NEW.incarnation
    ) THEN RAISE(ABORT, 'lease requires the active incarnation') END;
END;

CREATE TRIGGER operation_attempt_requires_current_incarnation
BEFORE INSERT ON operation_attempts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM control_plane_state
        WHERE singleton = 1
          AND mode = 'active'
          AND incarnation = NEW.incarnation
    ) THEN RAISE(ABORT, 'operation attempt requires the active incarnation') END;
END;

CREATE TRIGGER gc_epoch_requires_current_incarnation
BEFORE INSERT ON gc_epochs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM control_plane_state
        WHERE singleton = 1
          AND mode = 'active'
          AND incarnation = NEW.incarnation
    ) THEN RAISE(ABORT, 'GC epoch requires the active incarnation') END;
END;
