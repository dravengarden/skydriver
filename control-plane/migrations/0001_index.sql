PRAGMA foreign_keys = ON;

CREATE TABLE transfer_jobs (
    id TEXT PRIMARY KEY,
    source_uri TEXT NOT NULL,
    destination_uri TEXT NOT NULL,
    transfer_mode TEXT NOT NULL CHECK (transfer_mode = 'direct'),
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
    agent_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE logical_objects (
    id TEXT PRIMARY KEY,
    source_uri TEXT NOT NULL,
    plaintext_size INTEGER NOT NULL CHECK (plaintext_size >= 0),
    plaintext_sha256 TEXT,
    manifest_sha256 TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE blocks (
    sha256 TEXT PRIMARY KEY,
    plaintext_size INTEGER NOT NULL CHECK (plaintext_size > 0),
    ciphertext_size INTEGER NOT NULL CHECK (ciphertext_size > 0),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE object_blocks (
    object_id TEXT NOT NULL REFERENCES logical_objects(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    block_sha256 TEXT NOT NULL REFERENCES blocks(sha256),
    plaintext_offset INTEGER NOT NULL CHECK (plaintext_offset >= 0),
    PRIMARY KEY (object_id, ordinal)
) STRICT;

CREATE TABLE replicas (
    block_sha256 TEXT NOT NULL REFERENCES blocks(sha256) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('present', 'uploading', 'missing', 'corrupt')),
    verified_at INTEGER,
    PRIMARY KEY (block_sha256, provider, storage_key)
) STRICT;

CREATE INDEX idx_transfer_jobs_state_updated
ON transfer_jobs(state, updated_at);

CREATE INDEX idx_replicas_provider_state
ON replicas(provider, state);
