PRAGMA foreign_keys = ON;

CREATE TABLE vfs_directory_create_intents (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES vfs_principals(id),
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    parent_directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    child_directory_id TEXT NOT NULL UNIQUE CHECK (
        length(child_directory_id) = 32
        AND child_directory_id NOT GLOB '*[^0-9a-f]*'
        AND child_directory_id != '00000000000000000000000000000000'
    ),
    name TEXT NOT NULL CHECK (
        length(CAST(name AS BLOB)) BETWEEN 1 AND 255
        AND name NOT IN ('.', '..')
        AND instr(name, '/') = 0
        AND instr(name, char(0)) = 0
    ),
    crypto_suite TEXT NOT NULL CHECK (
        length(CAST(crypto_suite AS BLOB)) BETWEEN 1 AND 128
    ),
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
        AND trim(idempotency_key) = idempotency_key
    ),
    state TEXT NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared', 'committed')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    committed_at INTEGER,
    UNIQUE (token_id, idempotency_key),
    CHECK ((state = 'committed') = (committed_at IS NOT NULL))
) STRICT;

CREATE TABLE vfs_directory_create_updates (
    intent_id TEXT NOT NULL REFERENCES vfs_directory_create_intents(id) ON DELETE CASCADE,
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

CREATE TRIGGER validate_vfs_directory_create_update_insert
BEFORE INSERT ON vfs_directory_create_updates
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_directory_create_intents AS intent
        JOIN vfs_directories AS directory ON directory.id = NEW.directory_id
        WHERE intent.id = NEW.intent_id
          AND intent.state = 'prepared'
          AND directory.filesystem_id = intent.filesystem_id
          AND directory.revision = NEW.expected_revision
          AND directory.data_root = NEW.expected_data_root
    ) THEN RAISE(ABORT, 'VFS mkdir update lost its expected revision') END;

    SELECT CASE WHEN NEW.ordinal = 0 AND NOT EXISTS (
        SELECT 1 FROM vfs_directory_create_intents
        WHERE id = NEW.intent_id AND parent_directory_id = NEW.directory_id
    ) THEN RAISE(ABORT, 'first VFS mkdir update must be the parent') END;

    SELECT CASE WHEN NEW.ordinal > 0 AND NOT EXISTS (
        SELECT 1
        FROM vfs_directory_create_updates AS child_update
        JOIN vfs_directories AS child ON child.id = child_update.directory_id
        WHERE child_update.intent_id = NEW.intent_id
          AND child_update.ordinal = NEW.ordinal - 1
          AND child.parent_id = NEW.directory_id
    ) THEN RAISE(ABORT, 'VFS mkdir updates must form an ancestor chain') END;
END;

CREATE TRIGGER protect_vfs_directory_create_update
BEFORE UPDATE ON vfs_directory_create_updates
BEGIN
    SELECT RAISE(ABORT, 'VFS mkdir update proof is immutable');
END;

CREATE TABLE vfs_directory_create_receipts (
    intent_id TEXT PRIMARY KEY REFERENCES vfs_directory_create_intents(id) ON DELETE CASCADE,
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id),
    parent_directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    directory_id TEXT NOT NULL UNIQUE REFERENCES vfs_directories(id),
    name TEXT NOT NULL,
    data_root TEXT NOT NULL CHECK (
        length(data_root) = 64
        AND data_root NOT GLOB '*[^0-9a-f]*'
    ),
    crypto_suite TEXT NOT NULL,
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    catalog_revision_id INTEGER NOT NULL REFERENCES vfs_catalog_revisions(id),
    created_at INTEGER NOT NULL CHECK (created_at > 0)
) STRICT;

CREATE TRIGGER validate_vfs_directory_create_receipt_insert
BEFORE INSERT ON vfs_directory_create_receipts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_directory_create_intents
        WHERE id = NEW.intent_id
          AND token_id = NEW.token_id
          AND request_sha256 = NEW.request_sha256
          AND filesystem_id = NEW.filesystem_id
          AND parent_directory_id = NEW.parent_directory_id
          AND child_directory_id = NEW.directory_id
          AND name = NEW.name
          AND crypto_suite = NEW.crypto_suite
          AND state = 'prepared'
    ) THEN RAISE(ABORT, 'VFS mkdir receipt does not match its intent') END;
END;

CREATE TRIGGER protect_vfs_directory_create_receipt
BEFORE UPDATE ON vfs_directory_create_receipts
BEGIN
    SELECT RAISE(ABORT, 'VFS mkdir receipt is immutable');
END;

CREATE TRIGGER validate_vfs_directory_create_commit
BEFORE UPDATE OF state ON vfs_directory_create_intents
WHEN NEW.state = 'committed'
BEGIN
    SELECT CASE WHEN OLD.state != 'prepared'
        OR NEW.revision != OLD.revision + 1
        OR NEW.committed_at IS NULL
        THEN RAISE(ABORT, 'invalid VFS mkdir state transition') END;

    -- Reauthorize at the transaction's final state. This is the commit fence
    -- for token revocation, parent-chain revocation, and ACL changes.
    SELECT CASE WHEN NOT EXISTS (
        WITH RECURSIVE
        ancestors(id, parent_id) AS (
            SELECT id, parent_id
            FROM vfs_directories
            WHERE id = NEW.parent_directory_id
            UNION
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        ),
        acl_directories(id, parent_id, acl_inherits) AS (
            SELECT id, parent_id, acl_inherits
            FROM vfs_directories
            WHERE id = NEW.parent_directory_id
            UNION
            SELECT parent.id, parent.parent_id, parent.acl_inherits
            FROM vfs_directories AS parent
            JOIN acl_directories AS child ON child.parent_id = parent.id
            WHERE child.acl_inherits = 1
        ),
        token_chain(
            id, parent_token_id, principal_id, sealed_at, revoked_at, expires_at
        ) AS (
            SELECT id, parent_token_id, principal_id, sealed_at, revoked_at, expires_at
            FROM vfs_token_verifiers
            WHERE id = NEW.token_id
            UNION
            SELECT parent.id, parent.parent_token_id, parent.principal_id,
                   parent.sealed_at, parent.revoked_at, parent.expires_at
            FROM vfs_token_verifiers AS parent
            JOIN token_chain AS child ON child.parent_token_id = parent.id
        )
        SELECT 1
        FROM vfs_token_verifiers AS token
        JOIN vfs_principals AS principal ON principal.id = token.principal_id
        JOIN vfs_directories AS target ON target.id = NEW.parent_directory_id
        WHERE token.id = NEW.token_id
          AND token.principal_id = NEW.principal_id
          AND token.sealed_at IS NOT NULL
          AND token.revoked_at IS NULL
          AND token.expires_at > unixepoch()
          AND token.snapshot_id IS NULL
          AND principal.state = 'active'
          AND target.state = 'active'
          AND EXISTS (
              SELECT 1 FROM ancestors WHERE id = token.root_directory_id
          )
          AND EXISTS (
              SELECT 1 FROM vfs_token_actions
              WHERE token_id = token.id AND action = 'content.write'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM token_chain AS chain
              WHERE chain.sealed_at IS NULL
                 OR chain.revoked_at IS NOT NULL
                 OR chain.expires_at <= unixepoch()
                 OR chain.principal_id != token.principal_id
          )
          AND EXISTS (
              SELECT 1
              FROM vfs_acl_grants AS grant
              WHERE grant.action = 'content.write'
                AND grant.directory_id IN (SELECT id FROM acl_directories)
                AND (
                    grant.principal_id = token.principal_id
                    OR EXISTS (
                        SELECT 1
                        FROM vfs_group_members AS membership
                        WHERE membership.group_id = grant.group_id
                          AND membership.principal_id = token.principal_id
                    )
                )
          )
    ) THEN RAISE(ABORT, 'VFS mkdir lost current authority') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_directory_create_receipts AS receipt
        JOIN vfs_directories AS child ON child.id = receipt.directory_id
        JOIN vfs_directory_key_epochs AS key_epoch
          ON key_epoch.directory_id = child.id
         AND key_epoch.key_epoch = receipt.key_epoch
        JOIN vfs_directory_entries AS entry
          ON entry.directory_id = receipt.parent_directory_id
         AND entry.name = receipt.name
        JOIN vfs_catalog_revisions AS catalog
          ON catalog.id = receipt.catalog_revision_id
        JOIN vfs_catalog_mutation_heads AS head
          ON head.filesystem_id = receipt.filesystem_id
         AND head.revision_id = catalog.id
        WHERE receipt.intent_id = NEW.id
          AND receipt.token_id = NEW.token_id
          AND child.filesystem_id = NEW.filesystem_id
          AND child.parent_id = NEW.parent_directory_id
          AND child.name = NEW.name
          AND child.data_root = receipt.data_root
          AND child.crypto_suite = NEW.crypto_suite
          AND child.active_key_epoch = receipt.key_epoch
          AND child.acl_inherits = 1
          AND child.state = 'active'
          AND child.revision = 1
          AND child.acl_revision = 1
          AND key_epoch.crypto_suite = child.crypto_suite
          AND key_epoch.state = 'available'
          AND entry.kind = 'directory'
          AND entry.child_directory_id = child.id
          AND entry.size_bytes = 0
          AND entry.data_root = child.data_root
          AND entry.metadata_root IS NULL
          AND entry.revision = 1
          AND catalog.filesystem_id = NEW.filesystem_id
          AND catalog.mutation_kind = 'mkdir'
          AND catalog.mutation_id = NEW.id
          AND EXISTS (
              SELECT 1
              FROM vfs_directory_drivers AS placement
              JOIN driver_instances AS driver ON driver.id = placement.driver_id
              WHERE placement.directory_id = child.id
                AND placement.state = 'active'
                AND driver.enabled = 1
          )
    ) THEN RAISE(ABORT, 'VFS mkdir receipt does not match published metadata') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_directory_create_updates
        WHERE intent_id = NEW.id
          AND ordinal = 0
          AND directory_id = NEW.parent_directory_id
    ) OR EXISTS (
        SELECT 1
        FROM vfs_directory_create_updates AS directory_update
        JOIN vfs_directories AS directory ON directory.id = directory_update.directory_id
        WHERE directory_update.intent_id = NEW.id
          AND (
              directory.revision != directory_update.expected_revision + 1
              OR directory.data_root != directory_update.new_data_root
          )
    ) OR EXISTS (
        SELECT 1
        FROM vfs_directory_create_updates AS parent_update
        JOIN vfs_directory_create_updates AS child_update
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
        FROM vfs_directory_create_updates AS root_update
        JOIN vfs_directories AS root ON root.id = root_update.directory_id
        JOIN vfs_directory_create_receipts AS receipt ON receipt.intent_id = NEW.id
        JOIN vfs_catalog_revisions AS catalog
          ON catalog.id = receipt.catalog_revision_id
        WHERE root_update.intent_id = NEW.id
          AND root.parent_id IS NULL
          AND catalog.root_data_root = root_update.new_data_root
          AND NOT EXISTS (
              SELECT 1
              FROM vfs_directory_create_updates AS later
              WHERE later.intent_id = NEW.id
                AND later.ordinal > root_update.ordinal
          )
    ) THEN RAISE(ABORT, 'VFS mkdir directory-root chain did not commit') END;
END;

CREATE TRIGGER reject_vfs_directory_create_intent_delete
BEFORE DELETE ON vfs_directory_create_intents
WHEN OLD.state = 'committed'
BEGIN
    SELECT RAISE(ABORT, 'committed VFS mkdir intent is retained');
END;
