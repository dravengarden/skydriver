PRAGMA foreign_keys = ON;

-- Persist exact provider evidence before optimistic VFS publication. This is
-- intentionally separate from the final put receipt: a directory conflict may
-- reject publication after the immutable provider object already exists.
CREATE TABLE vfs_put_upload_evidence (
    intent_id TEXT PRIMARY KEY REFERENCES vfs_put_intents(id) ON DELETE CASCADE,
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    commit_sha256 TEXT NOT NULL CHECK (
        length(commit_sha256) = 64
        AND commit_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    block_manifest_r2_version TEXT NOT NULL CHECK (
        length(CAST(block_manifest_r2_version AS BLOB)) BETWEEN 1 AND 1024
    ),
    encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes >= 0),
    encoded_sha256 TEXT NOT NULL CHECK (
        length(encoded_sha256) = 64
        AND encoded_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    verification_method TEXT NOT NULL CHECK (
        verification_method IN ('provider_checksum', 'complete_readback')
    ),
    native_id TEXT,
    provider_version TEXT,
    etag TEXT,
    verified_at INTEGER NOT NULL CHECK (verified_at > 0)
) STRICT;

CREATE INDEX idx_vfs_put_upload_evidence_token_time
ON vfs_put_upload_evidence(token_id, verified_at DESC);

CREATE TRIGGER validate_vfs_put_upload_evidence_insert
BEFORE INSERT ON vfs_put_upload_evidence
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_put_intents AS intent
        JOIN vfs_token_verifiers AS token ON token.id = NEW.token_id
        WHERE intent.id = NEW.intent_id
          AND intent.state = 'prepared'
          AND intent.expires_at > unixepoch()
          AND token.principal_id = intent.principal_id
    ) THEN RAISE(ABORT, 'VFS upload evidence requires a live prepared intent') END;
END;

CREATE TRIGGER protect_vfs_put_upload_evidence
BEFORE UPDATE ON vfs_put_upload_evidence
BEGIN
    SELECT RAISE(ABORT, 'VFS upload evidence is immutable');
END;

CREATE TRIGGER require_vfs_put_receipt_upload_evidence
BEFORE INSERT ON vfs_put_receipts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_put_upload_evidence AS evidence
        WHERE evidence.intent_id = NEW.intent_id
          AND evidence.commit_sha256 = NEW.commit_sha256
          AND evidence.block_manifest_r2_version = NEW.block_manifest_r2_version
          AND evidence.encoded_bytes = NEW.encoded_bytes
          AND evidence.encoded_sha256 = NEW.encoded_sha256
          AND evidence.verification_method = NEW.verification_method
          AND evidence.native_id IS NEW.native_id
          AND evidence.provider_version IS NEW.provider_version
          AND evidence.etag IS NEW.etag
    ) THEN RAISE(ABORT, 'VFS put receipt requires matching upload evidence') END;
END;
