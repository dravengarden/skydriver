PRAGMA foreign_keys = ON;

-- Direct provider reads are invisible to the Worker. A durable lease closes
-- the interval between issuing a download plan and the client finishing its
-- exact immutable-object read. Expiry is deliberately fail-safe: abandoned
-- clients can delay deletion, never make a live read unsafe.
CREATE TABLE vfs_read_leases (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'
    ),
    version_id TEXT NOT NULL REFERENCES vfs_file_versions(id),
    location_id TEXT NOT NULL REFERENCES vfs_locations(id),
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    completed_at INTEGER CHECK (completed_at IS NULL OR completed_at >= created_at)
) STRICT;

CREATE INDEX idx_vfs_read_leases_location_active
ON vfs_read_leases(location_id, expires_at)
WHERE completed_at IS NULL;

CREATE INDEX idx_vfs_read_leases_expiry
ON vfs_read_leases(expires_at, id)
WHERE completed_at IS NULL;

CREATE INDEX idx_vfs_locations_tombstone_deadline
ON vfs_locations(delete_after, id)
WHERE state = 'tombstoned';

-- Compatibility-era abandoned-Put tasks are now claimed only by server cron.
-- A hosted adapter gap is durable and excluded from hot retries.
ALTER TABLE vfs_put_delete_tasks ADD COLUMN server_blocked_at INTEGER;

CREATE INDEX idx_vfs_put_delete_tasks_server_claim
ON vfs_put_delete_tasks(state, delete_after, id)
WHERE state IN ('pending', 'failed') AND server_blocked_at IS NULL;

-- One server-owned task is the durable fence for an exact provider object.
-- No SDK or ordinary filesystem CLI command can claim or complete it.
CREATE TABLE vfs_location_delete_tasks (
    id TEXT PRIMARY KEY REFERENCES vfs_locations(id),
    expected_location_revision INTEGER NOT NULL CHECK (expected_location_revision > 0),
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    driver_revision INTEGER NOT NULL CHECK (driver_revision > 0),
    storage_key TEXT NOT NULL,
    native_id TEXT,
    provider_version TEXT,
    etag TEXT,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'claimed', 'retry', 'blocked', 'deleted')
    ),
    fencing_token INTEGER NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    lease_expires_at INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    delete_after INTEGER NOT NULL,
    last_error_code TEXT,
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    completed_at INTEGER,
    CHECK ((state = 'claimed') = (lease_expires_at IS NOT NULL)),
    CHECK ((state = 'deleted') = (completed_at IS NOT NULL))
) STRICT;

CREATE INDEX idx_vfs_location_delete_tasks_claim
ON vfs_location_delete_tasks(state, delete_after, lease_expires_at, id);

CREATE TRIGGER protect_vfs_location_delete_task_identity
BEFORE UPDATE OF id, driver_id, storage_key, native_id, provider_version, etag, size_bytes
ON vfs_location_delete_tasks
BEGIN
    SELECT RAISE(ABORT, 'VFS location delete task identity is immutable');
END;
