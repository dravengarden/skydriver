PRAGMA foreign_keys = ON;

ALTER TABLE vfs_directories
ADD COLUMN placement_revision INTEGER NOT NULL DEFAULT 1 CHECK (placement_revision > 0);

CREATE TRIGGER bump_vfs_placement_after_insert
AFTER INSERT ON vfs_directory_drivers
BEGIN
    UPDATE vfs_directories
    SET placement_revision = placement_revision + 1,
        updated_at = MAX(updated_at, NEW.created_at)
    WHERE id = NEW.directory_id;
END;

CREATE TRIGGER bump_vfs_placement_after_delete
AFTER DELETE ON vfs_directory_drivers
BEGIN
    UPDATE vfs_directories
    SET placement_revision = placement_revision + 1,
        updated_at = MAX(updated_at, unixepoch())
    WHERE id = OLD.directory_id;
END;

CREATE TRIGGER bump_vfs_placement_after_update
AFTER UPDATE ON vfs_directory_drivers
BEGIN
    UPDATE vfs_directories
    SET placement_revision = placement_revision + 1,
        updated_at = MAX(updated_at, NEW.updated_at)
    WHERE id = NEW.directory_id;
END;

CREATE TABLE vfs_policy_mutation_intents (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    kind TEXT NOT NULL CHECK (kind IN ('acl.replace', 'placement.replace')),
    principal_id TEXT NOT NULL REFERENCES vfs_principals(id),
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
        AND trim(idempotency_key) = idempotency_key
    ),
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    final_revision INTEGER NOT NULL CHECK (final_revision >= expected_revision),
    payload_json TEXT NOT NULL CHECK (
        json_valid(payload_json) AND json_type(payload_json) = 'object'
    ),
    state TEXT NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared', 'committed')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    committed_at INTEGER,
    UNIQUE (token_id, kind, idempotency_key),
    CHECK ((state = 'committed') = (committed_at IS NOT NULL))
) STRICT;

-- The intent is inserted before any policy rows change. D1 batch statements
-- execute in one transaction, so this trigger is the authorization and
-- expected-revision fence while still allowing an administrator to remove its
-- own final grant deliberately.
CREATE TRIGGER validate_vfs_policy_mutation_intent_insert
BEFORE INSERT ON vfs_policy_mutation_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        WITH RECURSIVE
        ancestors(id, parent_id) AS (
            SELECT id, parent_id FROM vfs_directories WHERE id = NEW.directory_id
            UNION
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        ),
        acl_directories(id, parent_id, acl_inherits) AS (
            SELECT id, parent_id, acl_inherits
            FROM vfs_directories WHERE id = NEW.directory_id
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
            FROM vfs_token_verifiers WHERE id = NEW.token_id
            UNION
            SELECT parent.id, parent.parent_token_id, parent.principal_id,
                   parent.sealed_at, parent.revoked_at, parent.expires_at
            FROM vfs_token_verifiers AS parent
            JOIN token_chain AS child ON child.parent_token_id = parent.id
        )
        SELECT 1
        FROM vfs_token_verifiers AS token
        JOIN vfs_principals AS principal ON principal.id = token.principal_id
        JOIN vfs_directories AS target ON target.id = NEW.directory_id
        WHERE token.id = NEW.token_id
          AND token.principal_id = NEW.principal_id
          AND token.sealed_at IS NOT NULL
          AND token.revoked_at IS NULL
          AND token.expires_at > unixepoch()
          AND token.snapshot_id IS NULL
          AND principal.state = 'active'
          AND target.state = 'active'
          AND EXISTS (SELECT 1 FROM ancestors WHERE id = token.root_directory_id)
          AND EXISTS (
              SELECT 1 FROM vfs_token_actions
              WHERE token_id = token.id
                AND action = CASE NEW.kind
                    WHEN 'acl.replace' THEN 'acl.manage'
                    ELSE 'driver.manage'
                END
          )
          AND NOT EXISTS (
              SELECT 1 FROM token_chain AS chain
              WHERE chain.sealed_at IS NULL
                 OR chain.revoked_at IS NOT NULL
                 OR chain.expires_at <= unixepoch()
                 OR chain.principal_id != token.principal_id
          )
          AND EXISTS (
              SELECT 1
              FROM vfs_acl_grants AS grant
              WHERE grant.action = CASE NEW.kind
                        WHEN 'acl.replace' THEN 'acl.manage'
                        ELSE 'driver.manage'
                    END
                AND grant.directory_id IN (SELECT id FROM acl_directories)
                AND (
                    grant.principal_id = token.principal_id
                    OR EXISTS (
                        SELECT 1 FROM vfs_group_members AS membership
                        WHERE membership.group_id = grant.group_id
                          AND membership.principal_id = token.principal_id
                    )
                )
          )
          AND (
              NEW.kind != 'placement.replace'
              OR NOT EXISTS (
                  SELECT 1 FROM vfs_token_drivers WHERE token_id = token.id
              )
          )
          AND (
              (NEW.kind = 'acl.replace' AND target.acl_revision = NEW.expected_revision)
              OR (
                  NEW.kind = 'placement.replace'
                  AND target.placement_revision = NEW.expected_revision
              )
          )
    ) THEN RAISE(ABORT, 'VFS policy mutation lacks current authority or revision') END;
END;

CREATE TABLE vfs_policy_mutation_receipts (
    intent_id TEXT PRIMARY KEY REFERENCES vfs_policy_mutation_intents(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    request_sha256 TEXT NOT NULL,
    final_revision INTEGER NOT NULL CHECK (final_revision > 0),
    committed_at INTEGER NOT NULL CHECK (committed_at > 0)
) STRICT;

CREATE TRIGGER validate_vfs_policy_mutation_receipt_insert
BEFORE INSERT ON vfs_policy_mutation_receipts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_policy_mutation_intents
        WHERE id = NEW.intent_id
          AND kind = NEW.kind
          AND token_id = NEW.token_id
          AND directory_id = NEW.directory_id
          AND request_sha256 = NEW.request_sha256
          AND final_revision = NEW.final_revision
          AND state = 'prepared'
    ) THEN RAISE(ABORT, 'VFS policy receipt does not match its intent') END;
END;

CREATE TRIGGER protect_vfs_policy_mutation_receipt
BEFORE UPDATE ON vfs_policy_mutation_receipts
BEGIN
    SELECT RAISE(ABORT, 'VFS policy receipt is immutable');
END;

CREATE TRIGGER validate_vfs_policy_mutation_commit
BEFORE UPDATE OF state ON vfs_policy_mutation_intents
WHEN NEW.state = 'committed'
BEGIN
    SELECT CASE WHEN OLD.state != 'prepared'
        OR NEW.revision != OLD.revision + 1
        OR NEW.committed_at IS NULL
        OR NOT EXISTS (
            SELECT 1 FROM vfs_policy_mutation_receipts
            WHERE intent_id = NEW.id
              AND kind = NEW.kind
              AND final_revision = NEW.final_revision
        )
        THEN RAISE(ABORT, 'invalid VFS policy mutation transition') END;

    SELECT CASE WHEN NEW.kind = 'acl.replace' AND (
        NOT EXISTS (
            SELECT 1 FROM vfs_principals
            WHERE id = json_extract(NEW.payload_json, '$.principal_id')
              AND state = 'active'
        )
        OR (
            SELECT acl_revision FROM vfs_directories WHERE id = NEW.directory_id
        ) != NEW.final_revision
        OR EXISTS (
            SELECT 1
            FROM vfs_acl_grants AS grant
            WHERE grant.directory_id = NEW.directory_id
              AND grant.principal_id = json_extract(NEW.payload_json, '$.principal_id')
              AND (
                  NOT EXISTS (
                      SELECT 1 FROM json_each(NEW.payload_json, '$.actions') AS requested
                      WHERE requested.value = grant.action
                  )
                  OR grant.source_role IS NOT json_extract(NEW.payload_json, '$.source_role')
              )
        )
        OR EXISTS (
            SELECT 1
            FROM json_each(NEW.payload_json, '$.actions') AS requested
            WHERE requested.type != 'text'
               OR NOT EXISTS (
                   SELECT 1 FROM vfs_acl_grants AS grant
                   WHERE grant.directory_id = NEW.directory_id
                     AND grant.principal_id = json_extract(NEW.payload_json, '$.principal_id')
                     AND grant.action = requested.value
                     AND grant.source_role IS json_extract(NEW.payload_json, '$.source_role')
               )
        )
        OR (
            SELECT COUNT(*) FROM vfs_acl_grants
            WHERE directory_id = NEW.directory_id
              AND principal_id = json_extract(NEW.payload_json, '$.principal_id')
        ) != json_array_length(NEW.payload_json, '$.actions')
    ) THEN RAISE(ABORT, 'VFS ACL replacement did not commit exactly') END;

    SELECT CASE WHEN NEW.kind = 'placement.replace' AND (
        (
            SELECT placement_revision FROM vfs_directories WHERE id = NEW.directory_id
        ) != NEW.final_revision
        OR EXISTS (
            SELECT 1
            FROM vfs_directory_drivers AS placement
            WHERE placement.directory_id = NEW.directory_id
              AND (
                  placement.state != 'active'
                  OR NOT EXISTS (
                      SELECT 1
                      FROM json_each(NEW.payload_json, '$.placements') AS requested
                      WHERE json_extract(requested.value, '$.driver_id') = placement.driver_id
                        AND json_extract(requested.value, '$.write_priority') = placement.write_priority
                  )
              )
        )
        OR EXISTS (
            SELECT 1
            FROM json_each(NEW.payload_json, '$.placements') AS requested
            WHERE json_type(requested.value) != 'object'
               OR NOT EXISTS (
                   SELECT 1
                   FROM vfs_directory_drivers AS placement
                   JOIN driver_instances AS driver ON driver.id = placement.driver_id
                   WHERE placement.directory_id = NEW.directory_id
                     AND placement.driver_id = json_extract(requested.value, '$.driver_id')
                     AND placement.write_priority = json_extract(requested.value, '$.write_priority')
                     AND placement.state = 'active'
                     AND driver.enabled = 1
               )
        )
        OR (
            SELECT COUNT(*) FROM vfs_directory_drivers
            WHERE directory_id = NEW.directory_id
        ) != json_array_length(NEW.payload_json, '$.placements')
    ) THEN RAISE(ABORT, 'VFS placement replacement did not commit exactly') END;
END;

CREATE TRIGGER reject_vfs_policy_mutation_intent_delete
BEFORE DELETE ON vfs_policy_mutation_intents
WHEN OLD.state = 'committed'
BEGIN
    SELECT RAISE(ABORT, 'committed VFS policy intent is retained');
END;
