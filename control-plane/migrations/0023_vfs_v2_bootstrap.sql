PRAGMA foreign_keys = ON;

-- The operator bootstrap is deliberately global and one-shot. Its bearer
-- secret is derived from the Worker master key and the immutable request
-- identity, so an exact retry can recover a lost response without storing the
-- bearer secret in D1.
CREATE TABLE vfs_bootstrap_receipts (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
        AND trim(idempotency_key) = idempotency_key
    ),
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    admin_subject TEXT NOT NULL CHECK (
        length(CAST(admin_subject AS BLOB)) BETWEEN 1 AND 128
    ),
    filesystem_id TEXT NOT NULL UNIQUE REFERENCES vfs_filesystems(id),
    principal_id TEXT NOT NULL UNIQUE REFERENCES vfs_principals(id),
    root_directory_id TEXT NOT NULL UNIQUE REFERENCES vfs_directories(id),
    token_id TEXT NOT NULL UNIQUE REFERENCES vfs_token_verifiers(id),
    driver_id TEXT NOT NULL UNIQUE REFERENCES driver_instances(id),
    crypto_suite TEXT NOT NULL CHECK (
        length(CAST(crypto_suite AS BLOB)) BETWEEN 1 AND 128
    ),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    token_expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    CHECK (token_expires_at > created_at)
) STRICT;

CREATE TRIGGER reject_vfs_bootstrap_receipt_update
BEFORE UPDATE ON vfs_bootstrap_receipts
BEGIN
    SELECT RAISE(ABORT, 'VFS bootstrap receipt is immutable');
END;

CREATE TRIGGER reject_vfs_bootstrap_receipt_delete
BEFORE DELETE ON vfs_bootstrap_receipts
BEGIN
    SELECT RAISE(ABORT, 'VFS bootstrap receipt is retained');
END;
