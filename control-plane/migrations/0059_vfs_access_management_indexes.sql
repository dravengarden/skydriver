PRAGMA foreign_keys = ON;

CREATE INDEX IF NOT EXISTS vfs_principals_by_state_id
ON vfs_principals(state, id);

CREATE INDEX IF NOT EXISTS vfs_groups_by_filesystem_id
ON vfs_groups(filesystem_id, id);

CREATE INDEX IF NOT EXISTS vfs_group_members_by_principal_group
ON vfs_group_members(principal_id, group_id);

ALTER TABLE vfs_group_members
ADD COLUMN group_revision INTEGER NOT NULL DEFAULT 1 CHECK (group_revision > 0);

CREATE TRIGGER validate_vfs_group_member_insert_revision
BEFORE INSERT ON vfs_group_members
WHEN NOT EXISTS (
    SELECT 1 FROM vfs_groups
    WHERE id = NEW.group_id AND revision = NEW.group_revision
)
BEGIN
    SELECT RAISE(ABORT, 'VFS group membership revision conflict');
END;

CREATE TRIGGER bump_vfs_group_after_member_insert
AFTER INSERT ON vfs_group_members
BEGIN
    UPDATE vfs_groups
    SET revision = revision + 1,
        updated_at = MAX(updated_at, NEW.created_at)
    WHERE id = NEW.group_id AND revision = NEW.group_revision;
END;

CREATE TRIGGER validate_vfs_group_member_update_revision
BEFORE UPDATE OF group_revision ON vfs_group_members
WHEN NOT EXISTS (
    SELECT 1 FROM vfs_groups
    WHERE id = NEW.group_id AND revision = NEW.group_revision
)
BEGIN
    SELECT RAISE(ABORT, 'VFS group membership revision conflict');
END;

CREATE TRIGGER bump_vfs_group_after_member_update
AFTER UPDATE OF group_revision ON vfs_group_members
BEGIN
    UPDATE vfs_groups
    SET revision = revision + 1,
        updated_at = MAX(updated_at, unixepoch())
    WHERE id = NEW.group_id AND revision = NEW.group_revision;
END;

CREATE TRIGGER validate_vfs_access_creation_receipt
BEFORE INSERT ON management_creation_receipts
WHEN NEW.kind = 'access.create'
 AND NOT (
    EXISTS (
        SELECT 1 FROM vfs_principals
        WHERE id = NEW.resource_id AND revision = NEW.final_revision
          AND json_extract(NEW.result_json, '$.operation') = 'principal.create'
    )
    OR EXISTS (
        SELECT 1 FROM vfs_groups
        WHERE id = NEW.resource_id AND revision = NEW.final_revision
          AND json_extract(NEW.result_json, '$.operation') = 'group.create'
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'access creation receipt requires committed resource');
END;

CREATE TRIGGER validate_vfs_access_mutation_receipt
BEFORE INSERT ON management_mutation_receipts
WHEN NEW.kind = 'access.mutation'
 AND NOT (
    EXISTS (
        SELECT 1 FROM vfs_principals
        WHERE id = NEW.resource_id AND revision = NEW.final_revision
          AND json_extract(NEW.result_json, '$.operation') = 'principal.update'
    )
    OR EXISTS (
        SELECT 1 FROM vfs_groups
        WHERE id = NEW.resource_id AND revision = NEW.final_revision
          AND json_extract(NEW.result_json, '$.operation') IN (
              'group.update', 'membership.add', 'membership.remove'
          )
    )
    OR (
        json_extract(NEW.result_json, '$.operation') = 'group.delete'
        AND NOT EXISTS (SELECT 1 FROM vfs_groups WHERE id = NEW.resource_id)
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'access mutation receipt requires committed revision');
END;

DROP TRIGGER validate_vfs_policy_mutation_commit;

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
        NOT (
            (
                json_type(NEW.payload_json, '$.principal_id') = 'text'
                AND json_type(NEW.payload_json, '$.group_id') = 'null'
                AND EXISTS (
                    SELECT 1 FROM vfs_principals
                    WHERE id = json_extract(NEW.payload_json, '$.principal_id')
                      AND state = 'active'
                )
            )
            OR (
                json_type(NEW.payload_json, '$.principal_id') = 'null'
                AND json_type(NEW.payload_json, '$.group_id') = 'text'
                AND EXISTS (
                    SELECT 1 FROM vfs_groups AS group_row
                    JOIN vfs_directories AS directory
                      ON directory.filesystem_id = group_row.filesystem_id
                    WHERE group_row.id = json_extract(NEW.payload_json, '$.group_id')
                      AND directory.id = NEW.directory_id
                )
            )
        )
        OR (
            SELECT acl_revision FROM vfs_directories WHERE id = NEW.directory_id
        ) != NEW.final_revision
        OR EXISTS (
            SELECT 1 FROM vfs_acl_grants AS grant
            WHERE grant.directory_id = NEW.directory_id
              AND (
                  grant.principal_id = json_extract(NEW.payload_json, '$.principal_id')
                  OR grant.group_id = json_extract(NEW.payload_json, '$.group_id')
              )
              AND (
                  NOT EXISTS (
                      SELECT 1 FROM json_each(NEW.payload_json, '$.actions') AS requested
                      WHERE requested.value = grant.action
                  )
                  OR grant.source_role IS NOT json_extract(NEW.payload_json, '$.source_role')
              )
        )
        OR EXISTS (
            SELECT 1 FROM json_each(NEW.payload_json, '$.actions') AS requested
            WHERE requested.type != 'text'
               OR NOT EXISTS (
                   SELECT 1 FROM vfs_acl_grants AS grant
                   WHERE grant.directory_id = NEW.directory_id
                     AND (
                         grant.principal_id = json_extract(NEW.payload_json, '$.principal_id')
                         OR grant.group_id = json_extract(NEW.payload_json, '$.group_id')
                     )
                     AND grant.action = requested.value
                     AND grant.source_role IS json_extract(NEW.payload_json, '$.source_role')
               )
        )
        OR (
            SELECT COUNT(*) FROM vfs_acl_grants
            WHERE directory_id = NEW.directory_id
              AND (
                  principal_id = json_extract(NEW.payload_json, '$.principal_id')
                  OR group_id = json_extract(NEW.payload_json, '$.group_id')
              )
        ) != json_array_length(NEW.payload_json, '$.actions')
    ) THEN RAISE(ABORT, 'VFS ACL replacement did not commit exactly') END;

    SELECT CASE WHEN NEW.kind = 'placement.replace' AND (
        (
            SELECT placement_revision FROM vfs_directories WHERE id = NEW.directory_id
        ) != NEW.final_revision
        OR EXISTS (
            SELECT 1 FROM vfs_directory_drivers AS placement
            WHERE placement.directory_id = NEW.directory_id
              AND (
                  placement.state != 'active'
                  OR NOT EXISTS (
                      SELECT 1 FROM json_each(NEW.payload_json, '$.placements') AS requested
                      WHERE json_extract(requested.value, '$.driver_id') = placement.driver_id
                        AND json_extract(requested.value, '$.write_priority') = placement.write_priority
                  )
              )
        )
        OR EXISTS (
            SELECT 1 FROM json_each(NEW.payload_json, '$.placements') AS requested
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
