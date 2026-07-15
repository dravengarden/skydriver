PRAGMA foreign_keys = ON;

CREATE TABLE vfs_provider_inventory_state (
    driver_id TEXT PRIMARY KEY REFERENCES driver_instances(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    state TEXT NOT NULL DEFAULT 'idle' CHECK (
        state IN ('idle', 'scanning', 'complete', 'unsupported', 'error')
    ),
    cursor TEXT,
    scanned_objects INTEGER NOT NULL DEFAULT 0 CHECK (scanned_objects >= 0),
    unknown_objects INTEGER NOT NULL DEFAULT 0 CHECK (unknown_objects >= 0),
    last_started_at INTEGER,
    last_completed_at INTEGER,
    last_error_code TEXT,
    updated_at INTEGER NOT NULL CHECK (updated_at > 0)
) STRICT;

CREATE INDEX vfs_provider_inventory_due
ON vfs_provider_inventory_state(state, updated_at, driver_id);

CREATE TABLE vfs_provider_quarantine (
    driver_id TEXT NOT NULL REFERENCES driver_instances(id) ON DELETE CASCADE,
    storage_key TEXT NOT NULL,
    storage_key_sha256 TEXT NOT NULL CHECK (
        length(storage_key_sha256) = 64
        AND storage_key_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL DEFAULT 'observed' CHECK (state IN ('observed', 'resolved')),
    provider_version TEXT,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    first_seen_generation INTEGER NOT NULL CHECK (first_seen_generation > 0),
    last_seen_generation INTEGER NOT NULL CHECK (
        last_seen_generation >= first_seen_generation
    ),
    observation_count INTEGER NOT NULL DEFAULT 1 CHECK (observation_count > 0),
    first_seen_at INTEGER NOT NULL CHECK (first_seen_at > 0),
    last_seen_at INTEGER NOT NULL CHECK (last_seen_at >= first_seen_at),
    resolved_at INTEGER,
    PRIMARY KEY (driver_id, storage_key)
) STRICT;

CREATE INDEX vfs_provider_quarantine_by_state_seen
ON vfs_provider_quarantine(state, last_seen_at, driver_id);

CREATE INDEX vfs_provider_quarantine_by_driver_state
ON vfs_provider_quarantine(driver_id, state, last_seen_at);
