PRAGMA foreign_keys = ON;

-- `vfs_directory_drivers` remains the materialized effective-driver row used
-- by the already-fenced Put protocol. V71 narrows it to exactly one row per
-- directory and records only root defaults and explicit non-root mount points
-- separately. This preserves immutable locations while removing per-file
-- placement choice from future publication.
CREATE TABLE vfs_mount_migration_selection (
    directory_id TEXT PRIMARY KEY REFERENCES vfs_directories(id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    created_by TEXT NOT NULL REFERENCES vfs_principals(id),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

INSERT INTO vfs_mount_migration_selection (
    directory_id, driver_id, created_by, created_at, updated_at
)
SELECT directory_id, driver_id, created_by, created_at, updated_at
FROM (
    SELECT placement.*,
           row_number() OVER (
               PARTITION BY placement.directory_id
               ORDER BY CASE placement.state WHEN 'active' THEN 0 ELSE 1 END,
                        placement.write_priority, placement.driver_id
           ) AS ordinal
    FROM vfs_directory_drivers AS placement
)
WHERE ordinal = 1;

-- Older hosted bootstrap deliberately left the root placement empty until the
-- R2 provisioner ran. Its immutable receipt still binds the intended default,
-- so upgrade that state deterministically instead of leaving the filesystem
-- without a backing driver.
INSERT OR IGNORE INTO vfs_mount_migration_selection (
    directory_id, driver_id, created_by, created_at, updated_at
)
SELECT receipt.root_directory_id, receipt.driver_id, receipt.principal_id,
       receipt.created_at, receipt.created_at
FROM vfs_bootstrap_receipts AS receipt;

-- A historical partial bootstrap may also have descendants without a copied
-- placement. Inherit the nearest materialized ancestor during migration; no
-- provider data is moved and every existing explicit transition is retained.
WITH RECURSIVE effective(
    directory_id, driver_id, created_by, created_at, updated_at
) AS (
    SELECT root.id, selected.driver_id, selected.created_by,
           selected.created_at, selected.updated_at
    FROM vfs_directories AS root
    JOIN vfs_mount_migration_selection AS selected
      ON selected.directory_id = root.id
    WHERE root.parent_id IS NULL
    UNION ALL
    SELECT child.id,
           COALESCE(selected.driver_id, parent.driver_id),
           COALESCE(selected.created_by, parent.created_by),
           COALESCE(selected.created_at, parent.created_at),
           COALESCE(selected.updated_at, parent.updated_at)
    FROM effective AS parent
    JOIN vfs_directories AS child ON child.parent_id = parent.directory_id
    LEFT JOIN vfs_mount_migration_selection AS selected
      ON selected.directory_id = child.id
)
INSERT OR IGNORE INTO vfs_mount_migration_selection (
    directory_id, driver_id, created_by, created_at, updated_at
)
SELECT directory_id, driver_id, created_by, created_at, updated_at
FROM effective;

DELETE FROM vfs_directory_drivers
WHERE NOT EXISTS (
    SELECT 1
    FROM vfs_mount_migration_selection AS selected
    WHERE selected.directory_id = vfs_directory_drivers.directory_id
      AND selected.driver_id = vfs_directory_drivers.driver_id
);

INSERT OR IGNORE INTO vfs_directory_drivers (
    directory_id, driver_id, write_priority, state,
    created_by, created_at, updated_at
)
SELECT directory_id, driver_id, 0, 'active',
       created_by, created_at, updated_at
FROM vfs_mount_migration_selection;

UPDATE vfs_directory_drivers
SET write_priority = 0, state = 'active', updated_at = MAX(updated_at, unixepoch());

CREATE TABLE vfs_directory_mounts (
    directory_id TEXT PRIMARY KEY REFERENCES vfs_directories(id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    kind TEXT NOT NULL CHECK (kind IN ('default', 'mount')),
    created_by TEXT NOT NULL REFERENCES vfs_principals(id),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    FOREIGN KEY (directory_id, driver_id)
        REFERENCES vfs_directory_drivers(directory_id, driver_id)
) STRICT;

CREATE INDEX idx_vfs_directory_mounts_driver
ON vfs_directory_mounts(driver_id, directory_id);

INSERT INTO vfs_directory_mounts (
    directory_id, driver_id, kind, created_by, created_at
)
SELECT directory.id, selected.driver_id, 'default',
       selected.created_by, selected.created_at
FROM vfs_directories AS directory
JOIN vfs_mount_migration_selection AS selected
  ON selected.directory_id = directory.id
WHERE directory.parent_id IS NULL;

INSERT INTO vfs_directory_mounts (
    directory_id, driver_id, kind, created_by, created_at
)
SELECT child.id, child_selected.driver_id, 'mount',
       child_selected.created_by, child_selected.created_at
FROM vfs_directories AS child
JOIN vfs_mount_migration_selection AS child_selected
  ON child_selected.directory_id = child.id
JOIN vfs_mount_migration_selection AS parent_selected
  ON parent_selected.directory_id = child.parent_id
WHERE child.parent_id IS NOT NULL
  AND child_selected.driver_id != parent_selected.driver_id;

-- Existing nested driver transitions cannot be represented without moving
-- data. Abort the migration instead of silently changing their meaning.
CREATE TABLE vfs_mount_migration_assertion (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

INSERT INTO vfs_mount_migration_assertion(valid)
SELECT CASE WHEN EXISTS (
    WITH RECURSIVE mounted_descendants(directory_id, ancestor_mount_id) AS (
        SELECT child.id, mount.directory_id
        FROM vfs_directory_mounts AS mount
        JOIN vfs_directories AS child ON child.parent_id = mount.directory_id
        WHERE mount.kind = 'mount'
        UNION ALL
        SELECT child.id, descendants.ancestor_mount_id
        FROM mounted_descendants AS descendants
        JOIN vfs_directories AS child ON child.parent_id = descendants.directory_id
    )
    SELECT 1
    FROM mounted_descendants AS descendants
    JOIN vfs_directory_mounts AS nested
      ON nested.directory_id = descendants.directory_id
     AND nested.kind = 'mount'
) THEN 0 ELSE 1 END;

INSERT INTO vfs_mount_migration_assertion(valid)
SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM vfs_directories AS directory
    WHERE directory.state = 'active'
      AND (
          (SELECT COUNT(*) FROM vfs_directory_drivers AS effective
           WHERE effective.directory_id = directory.id
             AND effective.state = 'active') != 1
          OR (
              directory.parent_id IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM vfs_directory_mounts AS mount
                  WHERE mount.directory_id = directory.id
                    AND mount.kind = 'default'
              )
          )
          OR (
              directory.parent_id IS NOT NULL
              AND (
                  (
                      (SELECT driver_id FROM vfs_directory_drivers
                       WHERE directory_id = directory.id)
                      =
                      (SELECT driver_id FROM vfs_directory_drivers
                       WHERE directory_id = directory.parent_id)
                      AND EXISTS (
                          SELECT 1 FROM vfs_directory_mounts
                          WHERE directory_id = directory.id
                      )
                  )
                  OR (
                      (SELECT driver_id FROM vfs_directory_drivers
                       WHERE directory_id = directory.id)
                      !=
                      (SELECT driver_id FROM vfs_directory_drivers
                       WHERE directory_id = directory.parent_id)
                      AND NOT EXISTS (
                          SELECT 1 FROM vfs_directory_mounts AS mount
                          WHERE mount.directory_id = directory.id
                            AND mount.kind = 'mount'
                      )
                  )
              )
          )
      )
) THEN 0 ELSE 1 END;

DROP TABLE vfs_mount_migration_assertion;
DROP TABLE vfs_mount_migration_selection;

CREATE TRIGGER validate_vfs_directory_mount_insert
BEFORE INSERT ON vfs_directory_mounts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_directories AS directory
        WHERE directory.id = NEW.directory_id
          AND directory.state = 'active'
          AND (
              (NEW.kind = 'default' AND directory.parent_id IS NULL)
              OR (NEW.kind = 'mount' AND directory.parent_id IS NOT NULL)
          )
    ) THEN RAISE(ABORT, 'VFS mount kind does not match its directory') END;

    SELECT CASE WHEN NEW.kind = 'mount' AND EXISTS (
        SELECT 1 FROM vfs_directory_entries
        WHERE directory_id = NEW.directory_id
    ) THEN RAISE(ABORT, 'VFS mount target must be empty') END;

    SELECT CASE WHEN NEW.kind = 'mount' AND EXISTS (
        WITH RECURSIVE ancestors(id, parent_id) AS (
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS target
            JOIN vfs_directories AS parent ON parent.id = target.parent_id
            WHERE target.id = NEW.directory_id
            UNION ALL
            SELECT parent.id, parent.parent_id
            FROM ancestors AS child
            JOIN vfs_directories AS parent ON parent.id = child.parent_id
        )
        SELECT 1
        FROM ancestors
        JOIN vfs_directory_mounts AS mount ON mount.directory_id = ancestors.id
        WHERE mount.kind = 'mount'
    ) THEN RAISE(ABORT, 'nested VFS mounts are forbidden') END;
END;

CREATE TRIGGER reject_vfs_directory_mount_update
BEFORE UPDATE ON vfs_directory_mounts
BEGIN
    SELECT RAISE(ABORT, 'VFS mounts use replace-all mutation');
END;

CREATE TRIGGER validate_single_vfs_effective_driver_insert
BEFORE INSERT ON vfs_directory_drivers
BEGIN
    SELECT CASE WHEN NEW.write_priority != 0 OR NEW.state != 'active'
        OR EXISTS (
            SELECT 1 FROM vfs_directory_drivers
            WHERE directory_id = NEW.directory_id
        )
        THEN RAISE(ABORT, 'VFS directory requires one active effective driver') END;
END;

CREATE TRIGGER reject_vfs_effective_driver_update
BEFORE UPDATE OF driver_id, write_priority, state ON vfs_directory_drivers
BEGIN
    SELECT RAISE(ABORT, 'VFS effective driver uses mount replacement');
END;

-- The Worker performs the same check to return a useful conflict response,
-- but only this trigger shares the placement-replacement transaction with
-- concurrent namespace mutations. A driver transition is therefore fenced
-- against any entry that existed when the intent was inserted. Later entry
-- inserts observe the new effective driver or conflict with the transaction;
-- there is no check-then-mutate window.
CREATE TRIGGER validate_vfs_mount_policy_intent_insert
BEFORE INSERT ON vfs_policy_mutation_intents
WHEN NEW.kind = 'placement.replace'
BEGIN
    SELECT CASE WHEN json_array_length(NEW.payload_json, '$.placements') != 1
        OR json_type(NEW.payload_json, '$.placements[0].driver_id') != 'text'
        OR json_extract(NEW.payload_json, '$.placements[0].write_priority') != 0
        THEN RAISE(ABORT, 'VFS mount replacement requires one effective driver') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_directory_drivers AS effective
        WHERE effective.directory_id = NEW.directory_id
          AND effective.driver_id = json_extract(
              NEW.payload_json, '$.placements[0].driver_id'
          )
    ) AND EXISTS (
        WITH RECURSIVE descendants(id) AS (
            SELECT id FROM vfs_directories WHERE id = NEW.directory_id
            UNION ALL
            SELECT child.id
            FROM descendants AS parent
            JOIN vfs_directories AS child ON child.parent_id = parent.id
            WHERE child.state = 'active'
        )
        SELECT 1
        FROM vfs_directory_entries
        WHERE directory_id IN (SELECT id FROM descendants)
    ) THEN RAISE(ABORT, 'VFS mount target must be empty before changing driver') END;
END;

CREATE TRIGGER validate_vfs_mount_policy_commit
BEFORE UPDATE OF state ON vfs_policy_mutation_intents
WHEN NEW.kind = 'placement.replace' AND NEW.state = 'committed'
BEGIN
    SELECT CASE WHEN json_array_length(NEW.payload_json, '$.placements') != 1
        OR json_extract(NEW.payload_json, '$.placements[0].write_priority') != 0
        OR NOT EXISTS (
            SELECT 1
            FROM vfs_directories AS target
            JOIN vfs_directory_drivers AS effective
              ON effective.directory_id = target.id
             AND effective.driver_id = json_extract(
                 NEW.payload_json, '$.placements[0].driver_id'
             )
            WHERE target.id = NEW.directory_id
              AND effective.state = 'active'
              AND effective.write_priority = 0
              AND (
                  (
                      target.parent_id IS NULL
                      AND EXISTS (
                          SELECT 1 FROM vfs_directory_mounts AS mount
                          WHERE mount.directory_id = target.id
                            AND mount.driver_id = effective.driver_id
                            AND mount.kind = 'default'
                      )
                  )
                  OR (
                      target.parent_id IS NOT NULL
                      AND (
                          (
                              effective.driver_id = (
                                  SELECT driver_id FROM vfs_directory_drivers
                                  WHERE directory_id = target.parent_id
                              )
                              AND NOT EXISTS (
                                  SELECT 1 FROM vfs_directory_mounts
                                  WHERE directory_id = target.id
                              )
                          )
                          OR EXISTS (
                              SELECT 1 FROM vfs_directory_mounts AS mount
                              WHERE mount.directory_id = target.id
                                AND mount.driver_id = effective.driver_id
                                AND mount.kind = 'mount'
                          )
                      )
                  )
              )
        )
        THEN RAISE(ABORT, 'VFS mount replacement did not commit exactly') END;
END;

CREATE TRIGGER validate_vfs_rename_mount_insert
BEFORE INSERT ON vfs_rename_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_directory_drivers AS source
        JOIN vfs_directory_drivers AS destination
          ON destination.driver_id = source.driver_id
        WHERE source.directory_id = NEW.source_directory_id
          AND destination.directory_id = NEW.destination_directory_id
          AND source.state = 'active'
          AND destination.state = 'active'
    ) THEN RAISE(ABORT, 'VFS rename cannot cross effective drivers') END;

    SELECT CASE WHEN NEW.entry_kind = 'directory' AND EXISTS (
        SELECT 1 FROM vfs_directory_mounts
        WHERE directory_id = NEW.subject_id AND kind = 'mount'
    ) THEN RAISE(ABORT, 'VFS mount points cannot be renamed') END;
END;

CREATE TRIGGER validate_vfs_remove_mount_insert
BEFORE INSERT ON vfs_remove_intents
WHEN NEW.entry_kind = 'directory'
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM vfs_directory_mounts
        WHERE directory_id = NEW.subject_id AND kind = 'mount'
    ) THEN RAISE(ABORT, 'VFS mount point must be unmounted before removal') END;
END;
