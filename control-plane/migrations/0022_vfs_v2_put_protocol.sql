PRAGMA foreign_keys = ON;

CREATE TABLE vfs_directory_drivers (
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    write_priority INTEGER NOT NULL CHECK (write_priority >= 0),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    created_by TEXT NOT NULL REFERENCES vfs_principals(id),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (directory_id, driver_id)
) STRICT;

CREATE UNIQUE INDEX unique_active_vfs_directory_driver_priority
ON vfs_directory_drivers(directory_id, write_priority)
WHERE state = 'active';

CREATE TABLE vfs_directory_key_epochs (
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id) ON DELETE CASCADE,
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    crypto_suite TEXT NOT NULL CHECK (
        length(CAST(crypto_suite AS BLOB)) BETWEEN 1 AND 128
    ),
    envelope_algorithm TEXT CHECK (
        envelope_algorithm IS NULL
        OR length(CAST(envelope_algorithm AS BLOB)) BETWEEN 1 AND 128
    ),
    master_key_version TEXT CHECK (
        master_key_version IS NULL
        OR length(CAST(master_key_version AS BLOB)) BETWEEN 1 AND 128
    ),
    nonce BLOB,
    ciphertext BLOB,
    state TEXT NOT NULL DEFAULT 'available' CHECK (
        state IN ('available', 'retired', 'destroyed')
    ),
    created_by TEXT NOT NULL REFERENCES vfs_principals(id),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    retired_at INTEGER,
    destroyed_at INTEGER,
    PRIMARY KEY (directory_id, key_epoch),
    CHECK (
        (
            crypto_suite = 'plaintext/v1'
            AND envelope_algorithm IS NULL
            AND master_key_version IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
        )
        OR (
            crypto_suite != 'plaintext/v1'
            AND envelope_algorithm IS NOT NULL
            AND master_key_version IS NOT NULL
            AND (
                (
                    state != 'destroyed'
                    AND nonce IS NOT NULL
                    AND length(nonce) BETWEEN 12 AND 64
                    AND ciphertext IS NOT NULL
                    AND length(ciphertext) BETWEEN 32 AND 4096
                )
                OR (
                    state = 'destroyed'
                    AND nonce IS NULL
                    AND ciphertext IS NULL
                )
            )
        )
    ),
    CHECK ((state IN ('retired', 'destroyed')) = (retired_at IS NOT NULL)),
    CHECK ((state = 'destroyed') = (destroyed_at IS NOT NULL))
) STRICT;

CREATE TRIGGER validate_vfs_directory_key_state_transition
BEFORE UPDATE OF state ON vfs_directory_key_epochs
WHEN NOT (
    (OLD.state = 'available' AND NEW.state = 'retired')
    OR (OLD.state = 'retired' AND NEW.state = 'destroyed')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid VFS directory-key state transition');
END;

CREATE TRIGGER protect_vfs_directory_key_identity
BEFORE UPDATE OF
    directory_id, key_epoch, crypto_suite, envelope_algorithm,
    master_key_version, created_by, created_at
ON vfs_directory_key_epochs
BEGIN
    SELECT RAISE(ABORT, 'VFS directory-key identity is immutable');
END;

CREATE TRIGGER protect_live_vfs_directory_key_material
BEFORE UPDATE OF nonce, ciphertext ON vfs_directory_key_epochs
WHEN NOT (
    OLD.state = 'retired'
    AND NEW.state = 'destroyed'
    AND NEW.nonce IS NULL
    AND NEW.ciphertext IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'VFS directory-key material is immutable');
END;

CREATE TRIGGER validate_vfs_directory_crypto_update
BEFORE UPDATE OF crypto_suite, active_key_epoch ON vfs_directories
BEGIN
    SELECT CASE WHEN NEW.active_key_epoch < OLD.active_key_epoch
        THEN RAISE(ABORT, 'VFS directory key epoch cannot decrease') END;
    SELECT CASE WHEN NEW.crypto_suite != 'plaintext/v1' AND NOT EXISTS (
        SELECT 1
        FROM vfs_directory_key_epochs AS key_epoch
        WHERE key_epoch.directory_id = NEW.id
          AND key_epoch.key_epoch = NEW.active_key_epoch
          AND key_epoch.crypto_suite = NEW.crypto_suite
          AND key_epoch.state = 'available'
    ) THEN RAISE(ABORT, 'VFS directory crypto requires an available key epoch') END;
END;

CREATE TABLE vfs_put_intents (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES vfs_principals(id),
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    entry_name TEXT NOT NULL CHECK (
        length(CAST(entry_name AS BLOB)) BETWEEN 1 AND 255
        AND entry_name NOT IN ('.', '..')
        AND instr(entry_name, '/') = 0
        AND instr(entry_name, char(0)) = 0
    ),
    expected_entry_revision INTEGER NOT NULL CHECK (expected_entry_revision >= 0),
    expected_file_revision INTEGER NOT NULL CHECK (expected_file_revision >= 0),
    expected_current_version_id TEXT,
    file_id TEXT NOT NULL CHECK (
        length(file_id) = 32
        AND file_id NOT GLOB '*[^0-9a-f]*'
        AND file_id != '00000000000000000000000000000000'
    ),
    version_id TEXT NOT NULL UNIQUE CHECK (
        length(version_id) = 32
        AND version_id NOT GLOB '*[^0-9a-f]*'
        AND version_id != '00000000000000000000000000000000'
    ),
    location_id TEXT NOT NULL UNIQUE CHECK (
        length(location_id) = 32
        AND location_id NOT GLOB '*[^0-9a-f]*'
        AND location_id != '00000000000000000000000000000000'
    ),
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    storage_key TEXT NOT NULL,
    plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes >= 0),
    verification_block_bytes INTEGER NOT NULL CHECK (verification_block_bytes > 0),
    verification_block_count INTEGER NOT NULL CHECK (
        verification_block_count >= 0
        AND verification_block_count = CASE
            WHEN plaintext_bytes = 0 THEN 0
            ELSE 1 + (plaintext_bytes - 1) / verification_block_bytes
        END
    ),
    file_root TEXT NOT NULL CHECK (
        length(file_root) = 64
        AND file_root NOT GLOB '*[^0-9a-f]*'
    ),
    metadata_root TEXT NOT NULL CHECK (
        length(metadata_root) = 64
        AND metadata_root NOT GLOB '*[^0-9a-f]*'
    ),
    block_manifest_sha256 TEXT NOT NULL CHECK (
        length(block_manifest_sha256) = 64
        AND block_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    block_manifest_bytes INTEGER NOT NULL CHECK (block_manifest_bytes > 0),
    block_manifest_r2_key TEXT NOT NULL CHECK (
        length(CAST(block_manifest_r2_key AS BLOB)) BETWEEN 1 AND 4096
    ),
    crypto_suite TEXT NOT NULL CHECK (
        length(CAST(crypto_suite AS BLOB)) BETWEEN 1 AND 128
    ),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    encryption_frame_bytes INTEGER NOT NULL CHECK (encryption_frame_bytes > 0),
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
        AND trim(idempotency_key) = idempotency_key
    ),
    state TEXT NOT NULL DEFAULT 'prepared' CHECK (
        state IN ('prepared', 'committed', 'abandoned', 'expired')
    ),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    committed_at INTEGER,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    UNIQUE (principal_id, directory_id, idempotency_key),
    UNIQUE (driver_id, storage_key),
    CHECK (
        length(storage_key) = 62
        AND substr(storage_key, 1, 11) = 'objects/v2/'
        AND length(substr(storage_key, 12, 2)) = 2
        AND substr(storage_key, 12, 2) NOT GLOB '*[^0-9a-f]*'
        AND substr(storage_key, 14, 1) = '/'
        AND length(substr(storage_key, 15)) = 48
        AND substr(storage_key, 15) NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        (
            expected_entry_revision = 0
            AND expected_file_revision = 0
            AND expected_current_version_id IS NULL
        )
        OR (
            expected_entry_revision > 0
            AND expected_file_revision > 0
            AND expected_current_version_id IS NOT NULL
            AND length(expected_current_version_id) = 32
            AND expected_current_version_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    CHECK (expires_at > created_at),
    CHECK ((state = 'committed') = (committed_at IS NOT NULL))
) STRICT;

CREATE INDEX idx_vfs_put_intents_expiry
ON vfs_put_intents(state, expires_at);

CREATE TRIGGER require_prepared_vfs_put_intent_insert
BEFORE INSERT ON vfs_put_intents
WHEN NEW.state != 'prepared' OR NEW.committed_at IS NOT NULL OR NEW.revision != 1
BEGIN
    SELECT RAISE(ABORT, 'VFS put intent must begin prepared');
END;

CREATE TRIGGER validate_vfs_put_intent_target
BEFORE INSERT ON vfs_put_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_directories AS directory
        JOIN vfs_directory_drivers AS placement
          ON placement.directory_id = directory.id
         AND placement.driver_id = NEW.driver_id
        JOIN driver_instances AS driver ON driver.id = placement.driver_id
        WHERE directory.id = NEW.directory_id
          AND directory.filesystem_id = NEW.filesystem_id
          AND directory.state = 'active'
          AND directory.crypto_suite = NEW.crypto_suite
          AND directory.active_key_epoch = NEW.key_epoch
          AND placement.state = 'active'
          AND driver.enabled = 1
          AND (
              directory.crypto_suite = 'plaintext/v1'
              OR EXISTS (
                  SELECT 1
                  FROM vfs_directory_key_epochs AS key_epoch
                  WHERE key_epoch.directory_id = directory.id
                    AND key_epoch.key_epoch = directory.active_key_epoch
                    AND key_epoch.crypto_suite = directory.crypto_suite
                    AND key_epoch.state = 'available'
              )
          )
    ) THEN RAISE(ABORT, 'VFS put target or placement is unavailable') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM vfs_locations
        WHERE driver_id = NEW.driver_id AND storage_key = NEW.storage_key
    ) THEN RAISE(ABORT, 'VFS put storage key is already published') END;

    SELECT CASE WHEN NOT (
        (
            NEW.expected_entry_revision = 0
            AND NOT EXISTS (
                SELECT 1 FROM vfs_directory_entries
                WHERE directory_id = NEW.directory_id AND name = NEW.entry_name
            )
            AND NOT EXISTS (
                SELECT 1 FROM vfs_files WHERE id = NEW.file_id
            )
        )
        OR EXISTS (
            SELECT 1
            FROM vfs_directory_entries AS entry
            JOIN vfs_files AS file ON file.id = entry.file_id
            WHERE entry.directory_id = NEW.directory_id
              AND entry.name = NEW.entry_name
              AND entry.kind = 'file'
              AND entry.revision = NEW.expected_entry_revision
              AND entry.file_id = NEW.file_id
              AND entry.version_id = NEW.expected_current_version_id
              AND file.filesystem_id = NEW.filesystem_id
              AND file.current_version_id = NEW.expected_current_version_id
              AND file.revision = NEW.expected_file_revision
              AND file.state = 'active'
        )
    ) THEN RAISE(ABORT, 'VFS put precondition no longer matches the entry') END;

    SELECT CASE WHEN NEW.expires_at <= unixepoch()
        THEN RAISE(ABORT, 'VFS put intent already expired') END;
END;

CREATE TRIGGER validate_vfs_put_intent_authority
BEFORE INSERT ON vfs_put_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        WITH RECURSIVE ancestors(id, parent_id) AS (
            SELECT id, parent_id
            FROM vfs_directories
            WHERE id = NEW.directory_id
            UNION
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        )
        SELECT 1
        FROM vfs_token_verifiers AS token
        JOIN vfs_principals AS principal ON principal.id = token.principal_id
        WHERE token.id = NEW.token_id
          AND token.principal_id = NEW.principal_id
          AND token.sealed_at IS NOT NULL
          AND token.revoked_at IS NULL
          AND token.expires_at > unixepoch()
          AND token.snapshot_id IS NULL
          AND principal.state = 'active'
          AND EXISTS (
              SELECT 1 FROM ancestors WHERE id = token.root_directory_id
          )
          AND EXISTS (
              SELECT 1 FROM vfs_token_actions
              WHERE token_id = token.id AND action = 'content.write'
          )
          AND EXISTS (
              SELECT 1 FROM vfs_token_actions
              WHERE token_id = token.id AND action = 'driver.use'
          )
          AND (
              NOT EXISTS (
                  SELECT 1 FROM vfs_token_drivers WHERE token_id = token.id
              )
              OR EXISTS (
                  SELECT 1 FROM vfs_token_drivers
                  WHERE token_id = token.id AND driver_id = NEW.driver_id
              )
          )
    ) THEN RAISE(ABORT, 'VFS put prepare lacks token authority') END;

    SELECT CASE WHEN (
        SELECT COUNT(DISTINCT grant.action)
        FROM vfs_acl_grants AS grant
        WHERE grant.action IN ('content.write', 'driver.use')
          AND grant.directory_id IN (
              WITH RECURSIVE acl_directories(id, parent_id, acl_inherits) AS (
                  SELECT id, parent_id, acl_inherits
                  FROM vfs_directories
                  WHERE id = NEW.directory_id
                  UNION
                  SELECT parent.id, parent.parent_id, parent.acl_inherits
                  FROM vfs_directories AS parent
                  JOIN acl_directories AS child ON child.parent_id = parent.id
                  WHERE child.acl_inherits = 1
              )
              SELECT id FROM acl_directories
          )
          AND (
              grant.principal_id = NEW.principal_id
              OR EXISTS (
                  SELECT 1
                  FROM vfs_group_members AS membership
                  WHERE membership.group_id = grant.group_id
                    AND membership.principal_id = NEW.principal_id
              )
          )
    ) != 2 THEN RAISE(ABORT, 'VFS put prepare lacks ACL authority') END;
END;

CREATE TRIGGER protect_vfs_put_intent_identity
BEFORE UPDATE OF
    id, filesystem_id, principal_id, token_id, directory_id, entry_name,
    expected_entry_revision, expected_file_revision, expected_current_version_id,
    file_id, version_id, location_id, driver_id, storage_key, plaintext_bytes,
    verification_block_bytes, verification_block_count, file_root, metadata_root,
    block_manifest_sha256, block_manifest_bytes, block_manifest_r2_key,
    crypto_suite, key_epoch, encryption_frame_bytes, request_sha256,
    idempotency_key, expires_at, created_at
ON vfs_put_intents
BEGIN
    SELECT RAISE(ABORT, 'VFS put intent identity is immutable');
END;

CREATE TRIGGER protect_vfs_put_intent_revision
BEFORE UPDATE OF revision ON vfs_put_intents
WHEN NEW.state = OLD.state
BEGIN
    SELECT RAISE(ABORT, 'VFS put-intent revision changes only with state');
END;

CREATE TRIGGER validate_vfs_put_intent_state_transition
BEFORE UPDATE OF state ON vfs_put_intents
WHEN NEW.revision != OLD.revision + 1
  OR NOT (
    OLD.state = 'prepared'
    AND NEW.state IN ('committed', 'abandoned', 'expired')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid VFS put-intent state transition');
END;

CREATE TABLE vfs_put_directory_updates (
    intent_id TEXT NOT NULL REFERENCES vfs_put_intents(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    expected_data_root TEXT NOT NULL CHECK (
        length(expected_data_root) = 64
        AND expected_data_root NOT GLOB '*[^0-9a-f]*'
    ),
    new_data_root TEXT NOT NULL CHECK (
        length(new_data_root) = 64
        AND new_data_root NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (intent_id, ordinal),
    UNIQUE (intent_id, directory_id),
    CHECK (expected_data_root != new_data_root)
) STRICT;

CREATE TRIGGER validate_vfs_put_directory_update_insert
BEFORE INSERT ON vfs_put_directory_updates
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_put_intents AS intent
        JOIN vfs_directories AS directory ON directory.id = NEW.directory_id
        WHERE intent.id = NEW.intent_id
          AND intent.state = 'prepared'
          AND intent.expires_at > unixepoch()
          AND directory.filesystem_id = intent.filesystem_id
          AND directory.revision = NEW.expected_revision
          AND directory.data_root = NEW.expected_data_root
    ) THEN RAISE(ABORT, 'VFS put directory update lost its expected revision') END;

    SELECT CASE WHEN NEW.ordinal = 0 AND NOT EXISTS (
        SELECT 1 FROM vfs_put_intents
        WHERE id = NEW.intent_id AND directory_id = NEW.directory_id
    ) THEN RAISE(ABORT, 'first VFS put directory update must be the target') END;

    SELECT CASE WHEN NEW.ordinal > 0 AND NOT EXISTS (
        SELECT 1
        FROM vfs_put_directory_updates AS child_update
        JOIN vfs_directories AS child ON child.id = child_update.directory_id
        WHERE child_update.intent_id = NEW.intent_id
          AND child_update.ordinal = NEW.ordinal - 1
          AND child.parent_id = NEW.directory_id
    ) THEN RAISE(ABORT, 'VFS put directory updates must form an ancestor chain') END;
END;

CREATE TRIGGER protect_vfs_put_directory_update
BEFORE UPDATE ON vfs_put_directory_updates
BEGIN
    SELECT RAISE(ABORT, 'VFS put directory update is immutable');
END;

ALTER TABLE vfs_catalog_revisions
ADD COLUMN mutation_kind TEXT;

ALTER TABLE vfs_catalog_revisions
ADD COLUMN mutation_id TEXT;

CREATE UNIQUE INDEX unique_vfs_catalog_mutation
ON vfs_catalog_revisions(mutation_kind, mutation_id)
WHERE mutation_id IS NOT NULL;

CREATE TRIGGER validate_vfs_catalog_mutation_identity_insert
BEFORE INSERT ON vfs_catalog_revisions
WHEN (NEW.mutation_kind IS NULL) != (NEW.mutation_id IS NULL)
  OR (
      NEW.mutation_kind IS NOT NULL
      AND (
          length(CAST(NEW.mutation_kind AS BLOB)) NOT BETWEEN 1 AND 64
          OR length(CAST(NEW.mutation_id AS BLOB)) NOT BETWEEN 1 AND 256
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'VFS catalog mutation identity is incomplete');
END;

CREATE TRIGGER require_pending_vfs_catalog_revision_insert
BEFORE INSERT ON vfs_catalog_revisions
WHEN NEW.state != 'pending'
  OR NEW.materialized_at IS NOT NULL
  OR NEW.published_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'VFS catalog revision must begin pending');
END;

CREATE TRIGGER validate_vfs_catalog_revision_state_transition
BEFORE UPDATE OF state ON vfs_catalog_revisions
WHEN NOT (
    (OLD.state = 'pending' AND NEW.state = 'materialized')
    OR (OLD.state = 'materialized' AND NEW.state = 'published')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid VFS catalog-revision state transition');
END;

CREATE TRIGGER protect_vfs_catalog_revision_identity
BEFORE UPDATE OF
    filesystem_id, parent_revision_id, root_data_root, created_at,
    mutation_kind, mutation_id
ON vfs_catalog_revisions
BEGIN
    SELECT RAISE(ABORT, 'VFS catalog-revision identity is immutable');
END;

CREATE TABLE vfs_catalog_mutation_heads (
    filesystem_id TEXT PRIMARY KEY REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    revision_id INTEGER NOT NULL UNIQUE REFERENCES vfs_catalog_revisions(id),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at > 0)
) STRICT;

CREATE TRIGGER validate_vfs_catalog_mutation_head_update
BEFORE UPDATE ON vfs_catalog_mutation_heads
WHEN NEW.filesystem_id != OLD.filesystem_id
  OR NEW.revision != OLD.revision + 1
  OR NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'VFS catalog mutation head requires the next revision');
END;

CREATE TABLE vfs_put_receipts (
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
    verified_at INTEGER NOT NULL CHECK (verified_at > 0),
    native_id TEXT,
    provider_version TEXT,
    etag TEXT,
    entry_revision INTEGER NOT NULL CHECK (entry_revision > 0),
    catalog_revision_id INTEGER NOT NULL REFERENCES vfs_catalog_revisions(id),
    committed_at INTEGER NOT NULL CHECK (committed_at >= verified_at)
) STRICT;

CREATE TRIGGER validate_vfs_put_receipt_insert
BEFORE INSERT ON vfs_put_receipts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_put_intents
        WHERE id = NEW.intent_id
          AND state = 'prepared'
          AND expires_at > unixepoch()
    ) THEN RAISE(ABORT, 'VFS put receipt requires a prepared intent') END;
END;

CREATE TRIGGER protect_vfs_put_receipt
BEFORE UPDATE ON vfs_put_receipts
BEGIN
    SELECT RAISE(ABORT, 'VFS put receipt is immutable');
END;

CREATE TRIGGER validate_committed_vfs_put_intent
BEFORE UPDATE OF state ON vfs_put_intents
WHEN NEW.state = 'committed'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        WITH RECURSIVE ancestors(id, parent_id) AS (
            SELECT id, parent_id
            FROM vfs_directories
            WHERE id = NEW.directory_id
            UNION
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        )
        SELECT 1
        FROM vfs_put_receipts AS receipt
        JOIN vfs_token_verifiers AS token ON token.id = receipt.token_id
        JOIN vfs_principals AS principal ON principal.id = token.principal_id
        WHERE receipt.intent_id = NEW.id
          AND token.principal_id = NEW.principal_id
          AND token.sealed_at IS NOT NULL
          AND token.revoked_at IS NULL
          AND token.expires_at > unixepoch()
          AND token.snapshot_id IS NULL
          AND principal.state = 'active'
          AND EXISTS (
              SELECT 1 FROM ancestors WHERE id = token.root_directory_id
          )
          AND EXISTS (
              SELECT 1 FROM vfs_token_actions
              WHERE token_id = token.id AND action = 'content.write'
          )
          AND EXISTS (
              SELECT 1 FROM vfs_token_actions
              WHERE token_id = token.id AND action = 'driver.use'
          )
          AND (
              NOT EXISTS (
                  SELECT 1 FROM vfs_token_drivers WHERE token_id = token.id
              )
              OR EXISTS (
                  SELECT 1 FROM vfs_token_drivers
                  WHERE token_id = token.id AND driver_id = NEW.driver_id
              )
          )
    ) THEN RAISE(ABORT, 'VFS put commit lost its token authority') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_directories AS directory
        JOIN vfs_directory_drivers AS placement
          ON placement.directory_id = directory.id
         AND placement.driver_id = NEW.driver_id
        JOIN driver_instances AS driver ON driver.id = placement.driver_id
        WHERE directory.id = NEW.directory_id
          AND directory.filesystem_id = NEW.filesystem_id
          AND directory.state = 'active'
          AND directory.crypto_suite = NEW.crypto_suite
          AND directory.active_key_epoch = NEW.key_epoch
          AND placement.state = 'active'
          AND driver.enabled = 1
          AND (
              directory.crypto_suite = 'plaintext/v1'
              OR EXISTS (
                  SELECT 1
                  FROM vfs_directory_key_epochs AS key_epoch
                  WHERE key_epoch.directory_id = directory.id
                    AND key_epoch.key_epoch = directory.active_key_epoch
                    AND key_epoch.crypto_suite = directory.crypto_suite
                    AND key_epoch.state = 'available'
              )
          )
    ) THEN RAISE(ABORT, 'VFS put commit lost its target placement') END;

    SELECT CASE WHEN (
        SELECT COUNT(DISTINCT grant.action)
        FROM vfs_acl_grants AS grant
        WHERE grant.action IN ('content.write', 'driver.use')
          AND grant.directory_id IN (
              WITH RECURSIVE acl_directories(id, parent_id, acl_inherits) AS (
                  SELECT id, parent_id, acl_inherits
                  FROM vfs_directories
                  WHERE id = NEW.directory_id
                  UNION
                  SELECT parent.id, parent.parent_id, parent.acl_inherits
                  FROM vfs_directories AS parent
                  JOIN acl_directories AS child ON child.parent_id = parent.id
                  WHERE child.acl_inherits = 1
              )
              SELECT id FROM acl_directories
          )
          AND (
              grant.principal_id = NEW.principal_id
              OR EXISTS (
                  SELECT 1
                  FROM vfs_group_members AS membership
                  WHERE membership.group_id = grant.group_id
                    AND membership.principal_id = NEW.principal_id
              )
          )
    ) != 2 THEN RAISE(ABORT, 'VFS put commit lost its ACL authority') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_put_receipts AS receipt
        JOIN vfs_files AS file ON file.id = NEW.file_id
        JOIN vfs_file_versions AS version ON version.id = NEW.version_id
        JOIN vfs_locations AS location ON location.id = NEW.location_id
        JOIN vfs_directory_entries AS entry
          ON entry.directory_id = NEW.directory_id
         AND entry.name = NEW.entry_name
        JOIN vfs_catalog_revisions AS catalog
          ON catalog.id = receipt.catalog_revision_id
        JOIN vfs_catalog_mutation_heads AS head
          ON head.filesystem_id = NEW.filesystem_id
         AND head.revision_id = catalog.id
        WHERE receipt.intent_id = NEW.id
          AND receipt.entry_revision = NEW.expected_entry_revision + 1
          AND file.filesystem_id = NEW.filesystem_id
          AND file.current_version_id = NEW.version_id
          AND file.revision = NEW.expected_file_revision + 1
          AND version.file_id = NEW.file_id
          AND version.plaintext_bytes = NEW.plaintext_bytes
          AND version.verification_block_bytes = NEW.verification_block_bytes
          AND version.verification_block_count = NEW.verification_block_count
          AND version.file_root = NEW.file_root
          AND version.block_manifest_sha256 = NEW.block_manifest_sha256
          AND version.block_manifest_bytes = NEW.block_manifest_bytes
          AND version.block_manifest_r2_key = NEW.block_manifest_r2_key
          AND version.block_manifest_r2_version = receipt.block_manifest_r2_version
          AND version.crypto_suite = NEW.crypto_suite
          AND version.key_epoch = NEW.key_epoch
          AND version.encryption_frame_bytes = NEW.encryption_frame_bytes
          AND version.encoded_bytes = receipt.encoded_bytes
          AND version.encoded_sha256 = receipt.encoded_sha256
          AND version.state = 'published'
          AND location.version_id = NEW.version_id
          AND location.driver_id = NEW.driver_id
          AND location.storage_key = NEW.storage_key
          AND location.size_bytes = receipt.encoded_bytes
          AND location.object_sha256 = receipt.encoded_sha256
          AND location.native_id IS receipt.native_id
          AND location.provider_version IS receipt.provider_version
          AND location.etag IS receipt.etag
          AND location.state = 'available'
          AND entry.kind = 'file'
          AND entry.file_id = NEW.file_id
          AND entry.version_id = NEW.version_id
          AND entry.size_bytes = NEW.plaintext_bytes
          AND entry.data_root = NEW.file_root
          AND entry.metadata_root = NEW.metadata_root
          AND entry.revision = receipt.entry_revision
          AND catalog.filesystem_id = NEW.filesystem_id
          AND catalog.mutation_kind = 'put'
          AND catalog.mutation_id = NEW.id
    ) THEN RAISE(ABORT, 'VFS put receipt does not match published metadata') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_put_directory_updates
        WHERE intent_id = NEW.id AND ordinal = 0 AND directory_id = NEW.directory_id
    ) OR EXISTS (
        SELECT 1
        FROM vfs_put_directory_updates AS directory_update
        JOIN vfs_directories AS directory ON directory.id = directory_update.directory_id
        WHERE directory_update.intent_id = NEW.id
          AND (
              directory.revision != directory_update.expected_revision + 1
              OR directory.data_root != directory_update.new_data_root
          )
    ) OR EXISTS (
        SELECT 1
        FROM vfs_put_directory_updates AS parent_update
        JOIN vfs_put_directory_updates AS child_update
          ON child_update.intent_id = parent_update.intent_id
         AND child_update.ordinal = parent_update.ordinal - 1
        JOIN vfs_directories AS child ON child.id = child_update.directory_id
        WHERE parent_update.intent_id = NEW.id
          AND parent_update.ordinal > 0
          AND NOT EXISTS (
              SELECT 1
              FROM vfs_directory_entries AS entry
              WHERE entry.directory_id = parent_update.directory_id
                AND entry.kind = 'directory'
                AND entry.child_directory_id = child_update.directory_id
                AND entry.name = child.name
                AND entry.data_root = child_update.new_data_root
          )
    ) OR NOT EXISTS (
        SELECT 1
        FROM vfs_put_directory_updates AS root_update
        JOIN vfs_directories AS root ON root.id = root_update.directory_id
        JOIN vfs_put_receipts AS receipt ON receipt.intent_id = NEW.id
        JOIN vfs_catalog_revisions AS catalog
          ON catalog.id = receipt.catalog_revision_id
        WHERE root_update.intent_id = NEW.id
          AND root.parent_id IS NULL
          AND catalog.root_data_root = root_update.new_data_root
          AND NOT EXISTS (
              SELECT 1
              FROM vfs_put_directory_updates AS later
              WHERE later.intent_id = NEW.id
                AND later.ordinal > root_update.ordinal
          )
    ) THEN RAISE(ABORT, 'VFS put directory-root chain did not commit') END;
END;
