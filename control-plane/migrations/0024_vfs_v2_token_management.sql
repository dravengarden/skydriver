PRAGMA foreign_keys = ON;

-- Token issuance is recoverable without retaining bearer material. The Worker
-- derives the bearer from its master key and this immutable request identity;
-- D1 retains only the SHA-256 verifier on vfs_token_verifiers.
CREATE TABLE vfs_token_issue_receipts (
    parent_token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
        AND trim(idempotency_key) = idempotency_key
    ),
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    principal_id TEXT NOT NULL REFERENCES vfs_principals(id),
    root_directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    token_id TEXT NOT NULL UNIQUE REFERENCES vfs_token_verifiers(id),
    actions_json TEXT NOT NULL CHECK (
        json_valid(actions_json)
        AND json_type(actions_json) = 'array'
        AND json_array_length(actions_json) > 0
    ),
    driver_ids_json TEXT CHECK (
        driver_ids_json IS NULL
        OR (
            json_valid(driver_ids_json)
            AND json_type(driver_ids_json) = 'array'
            AND json_array_length(driver_ids_json) > 0
        )
    ),
    snapshot_id TEXT REFERENCES vfs_snapshots(id),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (parent_token_id, idempotency_key),
    CHECK (expires_at > created_at)
) STRICT;

CREATE TRIGGER validate_vfs_token_issue_receipt
BEFORE INSERT ON vfs_token_issue_receipts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_token_verifiers AS child
        WHERE child.id = NEW.token_id
          AND child.parent_token_id = NEW.parent_token_id
          AND child.principal_id = NEW.principal_id
          AND child.root_directory_id = NEW.root_directory_id
          AND child.snapshot_id IS NEW.snapshot_id
          AND child.expires_at = NEW.expires_at
          AND child.sealed_at IS NOT NULL
          AND child.revoked_at IS NULL
    ) THEN RAISE(ABORT, 'VFS token issue receipt does not match its child') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM json_each(NEW.actions_json) AS requested
        WHERE requested.type != 'text'
           OR NOT EXISTS (
               SELECT 1 FROM vfs_token_actions AS actual
               WHERE actual.token_id = NEW.token_id
                 AND actual.action = requested.value
           )
    ) OR EXISTS (
        SELECT 1
        FROM vfs_token_actions AS actual
        WHERE actual.token_id = NEW.token_id
          AND NOT EXISTS (
              SELECT 1 FROM json_each(NEW.actions_json) AS requested
              WHERE requested.value = actual.action
          )
    ) OR (
        SELECT COUNT(*) FROM vfs_token_actions WHERE token_id = NEW.token_id
    ) != json_array_length(NEW.actions_json)
    THEN RAISE(ABORT, 'VFS token issue receipt actions do not match') END;

    SELECT CASE WHEN (
        NEW.driver_ids_json IS NULL
        AND EXISTS (
            SELECT 1 FROM vfs_token_drivers WHERE token_id = NEW.token_id
        )
    ) OR (
        NEW.driver_ids_json IS NOT NULL
        AND (
            EXISTS (
                SELECT 1
                FROM json_each(NEW.driver_ids_json) AS requested
                WHERE requested.type != 'text'
                   OR NOT EXISTS (
                       SELECT 1 FROM vfs_token_drivers AS actual
                       WHERE actual.token_id = NEW.token_id
                         AND actual.driver_id = requested.value
                   )
            )
            OR EXISTS (
                SELECT 1
                FROM vfs_token_drivers AS actual
                WHERE actual.token_id = NEW.token_id
                  AND NOT EXISTS (
                      SELECT 1 FROM json_each(NEW.driver_ids_json) AS requested
                      WHERE requested.value = actual.driver_id
                  )
            )
            OR (
                SELECT COUNT(*) FROM vfs_token_drivers WHERE token_id = NEW.token_id
            ) != json_array_length(NEW.driver_ids_json)
        )
    ) THEN RAISE(ABORT, 'VFS token issue receipt drivers do not match') END;

    -- This final receipt is the transaction's authorization fence. If token or
    -- ACL authority changed before the D1 batch began, RAISE rolls back the
    -- child verifier, scope rows, seal, audit event, and receipt together.
    SELECT CASE WHEN NOT EXISTS (
        WITH RECURSIVE
        ancestors(id, parent_id) AS (
            SELECT id, parent_id
            FROM vfs_directories
            WHERE id = NEW.root_directory_id
            UNION
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        ),
        acl_directories(id, parent_id, acl_inherits) AS (
            SELECT id, parent_id, acl_inherits
            FROM vfs_directories
            WHERE id = NEW.root_directory_id
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
            WHERE id = NEW.parent_token_id
            UNION
            SELECT parent.id, parent.parent_token_id, parent.principal_id,
                   parent.sealed_at, parent.revoked_at, parent.expires_at
            FROM vfs_token_verifiers AS parent
            JOIN token_chain AS child ON child.parent_token_id = parent.id
        )
        SELECT 1
        FROM vfs_token_verifiers AS token
        JOIN vfs_principals AS principal ON principal.id = token.principal_id
        JOIN vfs_directories AS target ON target.id = NEW.root_directory_id
        WHERE token.id = NEW.parent_token_id
          AND token.principal_id = NEW.principal_id
          AND token.sealed_at IS NOT NULL
          AND token.revoked_at IS NULL
          AND token.expires_at > unixepoch()
          AND principal.state = 'active'
          AND target.state = 'active'
          AND EXISTS (
              SELECT 1 FROM ancestors WHERE id = token.root_directory_id
          )
          AND EXISTS (
              SELECT 1 FROM vfs_token_actions
              WHERE token_id = token.id AND action = 'token.issue'
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
              WHERE grant.action = 'token.issue'
                AND grant.directory_id IN (
                    SELECT id FROM acl_directories
                )
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
    ) THEN RAISE(ABORT, 'VFS token issue lost current authority') END;
END;

CREATE TRIGGER reject_vfs_token_issue_receipt_update
BEFORE UPDATE ON vfs_token_issue_receipts
BEGIN
    SELECT RAISE(ABORT, 'VFS token issue receipt is immutable');
END;

CREATE TRIGGER reject_vfs_token_issue_receipt_delete
BEFORE DELETE ON vfs_token_issue_receipts
BEGIN
    SELECT RAISE(ABORT, 'VFS token issue receipt is retained');
END;

CREATE TABLE vfs_token_revoke_receipts (
    authorizing_token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
        AND trim(idempotency_key) = idempotency_key
    ),
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    principal_id TEXT NOT NULL REFERENCES vfs_principals(id),
    target_token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    root_directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    revoked_at INTEGER NOT NULL CHECK (revoked_at > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (authorizing_token_id, idempotency_key),
    CHECK (target_token_id != authorizing_token_id)
) STRICT;

CREATE TRIGGER validate_vfs_token_revoke_receipt
BEFORE INSERT ON vfs_token_revoke_receipts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_token_verifiers AS target
        WHERE target.id = NEW.target_token_id
          AND target.principal_id = NEW.principal_id
          AND target.root_directory_id = NEW.root_directory_id
          AND target.revoked_at = NEW.revoked_at
    ) THEN RAISE(ABORT, 'VFS token revoke receipt does not match its target') END;

    SELECT CASE WHEN NOT EXISTS (
        WITH RECURSIVE
        ancestors(id, parent_id) AS (
            SELECT id, parent_id
            FROM vfs_directories
            WHERE id = NEW.root_directory_id
            UNION
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        ),
        acl_directories(id, parent_id, acl_inherits) AS (
            SELECT id, parent_id, acl_inherits
            FROM vfs_directories
            WHERE id = NEW.root_directory_id
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
            WHERE id = NEW.authorizing_token_id
            UNION
            SELECT parent.id, parent.parent_token_id, parent.principal_id,
                   parent.sealed_at, parent.revoked_at, parent.expires_at
            FROM vfs_token_verifiers AS parent
            JOIN token_chain AS child ON child.parent_token_id = parent.id
        )
        SELECT 1
        FROM vfs_token_verifiers AS token
        JOIN vfs_principals AS principal ON principal.id = token.principal_id
        JOIN vfs_directories AS target ON target.id = NEW.root_directory_id
        WHERE token.id = NEW.authorizing_token_id
          AND token.principal_id = NEW.principal_id
          AND token.sealed_at IS NOT NULL
          AND token.revoked_at IS NULL
          AND token.expires_at > unixepoch()
          AND principal.state = 'active'
          AND target.state = 'active'
          AND EXISTS (
              SELECT 1 FROM ancestors WHERE id = token.root_directory_id
          )
          AND EXISTS (
              SELECT 1 FROM vfs_token_actions
              WHERE token_id = token.id AND action = 'token.issue'
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
              WHERE grant.action = 'token.issue'
                AND grant.directory_id IN (
                    SELECT id FROM acl_directories
                )
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
    ) THEN RAISE(ABORT, 'VFS token revoke lost current authority') END;
END;

CREATE TRIGGER reject_vfs_token_revoke_receipt_update
BEFORE UPDATE ON vfs_token_revoke_receipts
BEGIN
    SELECT RAISE(ABORT, 'VFS token revoke receipt is immutable');
END;

CREATE TRIGGER reject_vfs_token_revoke_receipt_delete
BEFORE DELETE ON vfs_token_revoke_receipts
BEGIN
    SELECT RAISE(ABORT, 'VFS token revoke receipt is retained');
END;
