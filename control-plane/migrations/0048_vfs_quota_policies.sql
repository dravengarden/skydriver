PRAGMA foreign_keys = ON;

CREATE TABLE vfs_directory_quota_policies (
    directory_id TEXT PRIMARY KEY REFERENCES vfs_directories(id) ON DELETE CASCADE,
    max_file_bytes INTEGER CHECK (max_file_bytes IS NULL OR max_file_bytes > 0),
    max_logical_bytes INTEGER CHECK (max_logical_bytes IS NULL OR max_logical_bytes > 0),
    max_file_count INTEGER CHECK (max_file_count IS NULL OR max_file_count > 0),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at > 0)
) STRICT;

CREATE TABLE driver_quota_policies (
    driver_id TEXT PRIMARY KEY REFERENCES driver_instances(id) ON DELETE CASCADE,
    max_physical_bytes INTEGER CHECK (max_physical_bytes IS NULL OR max_physical_bytes > 0),
    max_object_count INTEGER CHECK (max_object_count IS NULL OR max_object_count > 0),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at > 0)
) STRICT;

INSERT INTO vfs_directory_quota_policies (directory_id, updated_at)
SELECT id, updated_at FROM vfs_directories;

INSERT INTO driver_quota_policies (driver_id, updated_at)
SELECT id, updated_at FROM driver_instances;

CREATE TRIGGER create_default_vfs_directory_quota_policy
AFTER INSERT ON vfs_directories
BEGIN
    INSERT INTO vfs_directory_quota_policies (directory_id, updated_at)
    VALUES (NEW.id, NEW.updated_at);
END;

CREATE TRIGGER create_default_driver_quota_policy
AFTER INSERT ON driver_instances
BEGIN
    INSERT INTO driver_quota_policies (driver_id, updated_at)
    VALUES (NEW.id, NEW.updated_at);
END;

CREATE INDEX idx_vfs_put_intents_driver_reservations
ON vfs_put_intents(driver_id, state, expires_at);

CREATE INDEX idx_vfs_locations_driver_usage
ON vfs_locations(driver_id, state, size_bytes);

CREATE TRIGGER validate_vfs_directory_quota_revision
BEFORE UPDATE ON vfs_directory_quota_policies
WHEN NEW.directory_id != OLD.directory_id
  OR NEW.revision != OLD.revision + 1
  OR NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'directory quota mutation requires the next revision');
END;

CREATE TRIGGER validate_driver_quota_revision
BEFORE UPDATE ON driver_quota_policies
WHEN NEW.driver_id != OLD.driver_id
  OR NEW.revision != OLD.revision + 1
  OR NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'driver quota mutation requires the next revision');
END;

CREATE TRIGGER validate_directory_quota_receipt
BEFORE INSERT ON management_mutation_receipts
WHEN NEW.kind = 'directory.quota'
 AND NOT EXISTS (
    SELECT 1 FROM vfs_directory_quota_policies
    WHERE directory_id = NEW.resource_id
      AND revision = NEW.final_revision
      AND max_file_bytes IS json_extract(NEW.result_json, '$.max_file_bytes')
      AND max_logical_bytes IS json_extract(NEW.result_json, '$.max_logical_bytes')
      AND max_file_count IS json_extract(NEW.result_json, '$.max_file_count')
 )
BEGIN
    SELECT RAISE(ABORT, 'directory quota receipt requires committed policy');
END;

CREATE TRIGGER validate_driver_quota_receipt
BEFORE INSERT ON management_mutation_receipts
WHEN NEW.kind = 'driver.quota'
 AND NOT EXISTS (
    SELECT 1 FROM driver_quota_policies
    WHERE driver_id = NEW.resource_id
      AND revision = NEW.final_revision
      AND max_physical_bytes IS json_extract(NEW.result_json, '$.max_physical_bytes')
      AND max_object_count IS json_extract(NEW.result_json, '$.max_object_count')
 )
BEGIN
    SELECT RAISE(ABORT, 'driver quota receipt requires committed policy');
END;

CREATE TRIGGER enforce_vfs_put_max_file_bytes
BEFORE INSERT ON vfs_put_intents
BEGIN
    SELECT CASE WHEN EXISTS (
        WITH RECURSIVE ancestors(id, parent_id) AS (
            SELECT id, parent_id FROM vfs_directories WHERE id = NEW.directory_id
            UNION ALL
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        )
        SELECT 1
        FROM ancestors
        JOIN vfs_directory_quota_policies AS quota ON quota.directory_id = ancestors.id
        WHERE quota.max_file_bytes IS NOT NULL
          AND NEW.plaintext_bytes > quota.max_file_bytes
    ) THEN RAISE(ABORT, 'VFS file exceeds an inherited directory limit') END;
END;

CREATE TRIGGER enforce_vfs_put_logical_quota
BEFORE INSERT ON vfs_put_intents
BEGIN
    SELECT CASE WHEN EXISTS (
        WITH RECURSIVE
        ancestors(id, parent_id) AS (
            SELECT id, parent_id FROM vfs_directories WHERE id = NEW.directory_id
            UNION ALL
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        ),
        quota_roots(id, max_logical_bytes) AS (
            SELECT ancestors.id, quota.max_logical_bytes
            FROM ancestors
            JOIN vfs_directory_quota_policies AS quota ON quota.directory_id = ancestors.id
            WHERE quota.max_logical_bytes IS NOT NULL
        ),
        descendants(quota_id, directory_id) AS (
            SELECT id, id FROM quota_roots
            UNION ALL
            SELECT descendants.quota_id, child.id
            FROM descendants
            JOIN vfs_directories AS child ON child.parent_id = descendants.directory_id
            WHERE child.state = 'active'
        ),
        committed(quota_id, bytes) AS (
            SELECT descendants.quota_id, COALESCE(SUM(version.plaintext_bytes), 0)
            FROM descendants
            LEFT JOIN vfs_directory_entries AS entry
              ON entry.directory_id = descendants.directory_id AND entry.kind = 'file'
            LEFT JOIN vfs_files AS file
              ON file.id = entry.file_id AND file.state = 'active'
            LEFT JOIN vfs_file_versions AS version ON version.id = file.current_version_id
            GROUP BY descendants.quota_id
        ),
        reserved(quota_id, bytes) AS (
            SELECT descendants.quota_id,
                   COALESCE(SUM(MAX(intent.plaintext_bytes - COALESCE(previous.plaintext_bytes, 0), 0)), 0)
            FROM descendants
            LEFT JOIN vfs_put_intents AS intent
              ON intent.directory_id = descendants.directory_id
             AND intent.state = 'prepared'
             AND intent.expires_at > unixepoch()
            LEFT JOIN vfs_file_versions AS previous
              ON previous.id = intent.expected_current_version_id
            GROUP BY descendants.quota_id
        )
        SELECT 1
        FROM quota_roots
        JOIN committed ON committed.quota_id = quota_roots.id
        JOIN reserved ON reserved.quota_id = quota_roots.id
        LEFT JOIN vfs_file_versions AS replaced ON replaced.id = NEW.expected_current_version_id
        WHERE committed.bytes + reserved.bytes
              + MAX(NEW.plaintext_bytes - COALESCE(replaced.plaintext_bytes, 0), 0)
              > quota_roots.max_logical_bytes
    ) THEN RAISE(ABORT, 'VFS directory logical-byte quota exhausted') END;
END;

CREATE TRIGGER enforce_vfs_put_file_count_quota
BEFORE INSERT ON vfs_put_intents
WHEN NEW.expected_current_version_id IS NULL
BEGIN
    SELECT CASE WHEN EXISTS (
        WITH RECURSIVE
        ancestors(id, parent_id) AS (
            SELECT id, parent_id FROM vfs_directories WHERE id = NEW.directory_id
            UNION ALL
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        ),
        quota_roots(id, max_file_count) AS (
            SELECT ancestors.id, quota.max_file_count
            FROM ancestors
            JOIN vfs_directory_quota_policies AS quota ON quota.directory_id = ancestors.id
            WHERE quota.max_file_count IS NOT NULL
        ),
        descendants(quota_id, directory_id) AS (
            SELECT id, id FROM quota_roots
            UNION ALL
            SELECT descendants.quota_id, child.id
            FROM descendants
            JOIN vfs_directories AS child ON child.parent_id = descendants.directory_id
            WHERE child.state = 'active'
        )
        SELECT 1
        FROM quota_roots
        WHERE (
            SELECT COUNT(*)
            FROM descendants
            JOIN vfs_directory_entries AS entry
              ON entry.directory_id = descendants.directory_id AND entry.kind = 'file'
            JOIN vfs_files AS file ON file.id = entry.file_id AND file.state = 'active'
            WHERE descendants.quota_id = quota_roots.id
        ) + (
            SELECT COUNT(*)
            FROM descendants
            JOIN vfs_put_intents AS intent
              ON intent.directory_id = descendants.directory_id
             AND intent.state = 'prepared'
             AND intent.expires_at > unixepoch()
             AND intent.expected_current_version_id IS NULL
            WHERE descendants.quota_id = quota_roots.id
        ) + 1 > quota_roots.max_file_count
    ) THEN RAISE(ABORT, 'VFS directory file-count quota exhausted') END;
END;

CREATE TRIGGER enforce_vfs_put_driver_quota
BEFORE INSERT ON vfs_put_intents
WHEN EXISTS (SELECT 1 FROM driver_quota_policies WHERE driver_id = NEW.driver_id)
BEGIN
    SELECT CASE WHEN (
        SELECT COALESCE(SUM(size_bytes), 0)
        FROM vfs_locations
        WHERE driver_id = NEW.driver_id AND state != 'deleted'
    ) + (
        SELECT COALESCE(SUM(
            CASE
                WHEN crypto_suite = 'plaintext/v1' THEN plaintext_bytes
                ELSE plaintext_bytes + 16 * CASE
                    WHEN plaintext_bytes = 0 THEN 0
                    ELSE 1 + (plaintext_bytes - 1) / encryption_frame_bytes
                END
            END
        ), 0)
        FROM vfs_put_intents
        WHERE driver_id = NEW.driver_id
          AND state = 'prepared'
          AND expires_at > unixepoch()
    ) + CASE
        WHEN NEW.crypto_suite = 'plaintext/v1' THEN NEW.plaintext_bytes
        ELSE NEW.plaintext_bytes + 16 * CASE
            WHEN NEW.plaintext_bytes = 0 THEN 0
            ELSE 1 + (NEW.plaintext_bytes - 1) / NEW.encryption_frame_bytes
        END
    END > COALESCE((
        SELECT max_physical_bytes FROM driver_quota_policies WHERE driver_id = NEW.driver_id
    ), 9223372036854775807)
    THEN RAISE(ABORT, 'VFS driver physical-byte quota exhausted') END;

    SELECT CASE WHEN (
        SELECT COUNT(*) FROM vfs_locations
        WHERE driver_id = NEW.driver_id AND state != 'deleted'
    ) + (
        SELECT COUNT(*) FROM vfs_put_intents
        WHERE driver_id = NEW.driver_id
          AND state = 'prepared'
          AND expires_at > unixepoch()
    ) + 1 > COALESCE((
        SELECT max_object_count FROM driver_quota_policies WHERE driver_id = NEW.driver_id
    ), 9223372036854775807)
    THEN RAISE(ABORT, 'VFS driver object-count quota exhausted') END;
END;
