PRAGMA foreign_keys = ON;

CREATE TABLE vfs_actions (
    name TEXT PRIMARY KEY CHECK (
        name IN (
            'directory.list',
            'content.read',
            'content.write',
            'entry.delete',
            'snapshot.publish',
            'acl.manage',
            'token.issue',
            'driver.use',
            'driver.manage',
            'gc.run',
            'audit.read',
            'system.manage'
        )
    )
) STRICT;

INSERT INTO vfs_actions (name) VALUES
    ('directory.list'),
    ('content.read'),
    ('content.write'),
    ('entry.delete'),
    ('snapshot.publish'),
    ('acl.manage'),
    ('token.issue'),
    ('driver.use'),
    ('driver.manage'),
    ('gc.run'),
    ('audit.read'),
    ('system.manage');

CREATE TRIGGER reject_vfs_action_update
BEFORE UPDATE ON vfs_actions
BEGIN
    SELECT RAISE(ABORT, 'VFS actions are protocol constants');
END;

CREATE TRIGGER reject_vfs_action_delete
BEFORE DELETE ON vfs_actions
BEGIN
    SELECT RAISE(ABORT, 'VFS actions are protocol constants');
END;

CREATE TABLE vfs_filesystems (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    name TEXT NOT NULL UNIQUE CHECK (
        length(CAST(name AS BLOB)) BETWEEN 1 AND 256
        AND trim(name) = name
    ),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE vfs_principals (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    kind TEXT NOT NULL CHECK (kind IN ('human', 'service')),
    display_name TEXT NOT NULL CHECK (
        length(CAST(display_name AS BLOB)) BETWEEN 1 AND 256
        AND trim(display_name) = display_name
    ),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE vfs_principal_clients (
    principal_id TEXT PRIMARY KEY REFERENCES vfs_principals(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL UNIQUE REFERENCES clients(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL CHECK (created_at > 0)
) STRICT;

CREATE TABLE vfs_directories (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    parent_id TEXT,
    name TEXT NOT NULL,
    data_root TEXT NOT NULL CHECK (
        length(data_root) = 64
        AND data_root NOT GLOB '*[^0-9a-f]*'
    ),
    crypto_suite TEXT NOT NULL CHECK (
        length(CAST(crypto_suite AS BLOB)) BETWEEN 1 AND 128
    ),
    active_key_epoch INTEGER NOT NULL CHECK (active_key_epoch > 0),
    acl_inherits INTEGER NOT NULL DEFAULT 1 CHECK (acl_inherits IN (0, 1)),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'tombstoned')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    acl_revision INTEGER NOT NULL DEFAULT 1 CHECK (acl_revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (id, filesystem_id),
    UNIQUE (filesystem_id, parent_id, name),
    FOREIGN KEY (parent_id, filesystem_id)
        REFERENCES vfs_directories(id, filesystem_id),
    CHECK (
        (parent_id IS NULL AND name = '' AND acl_inherits = 0)
        OR (
            parent_id IS NOT NULL
            AND length(CAST(name AS BLOB)) BETWEEN 1 AND 255
            AND name NOT IN ('.', '..')
            AND instr(name, '/') = 0
            AND instr(name, char(0)) = 0
        )
    )
) STRICT;

CREATE UNIQUE INDEX one_vfs_root_per_filesystem
ON vfs_directories(filesystem_id)
WHERE parent_id IS NULL;

CREATE TRIGGER validate_vfs_directory_revision_update
BEFORE UPDATE OF
    filesystem_id, parent_id, name, data_root, crypto_suite,
    active_key_epoch, acl_inherits, state
ON vfs_directories
WHEN NEW.revision != OLD.revision + 1 OR NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'VFS directory mutation requires the next revision');
END;

CREATE TRIGGER reject_vfs_directory_self_parent_insert
BEFORE INSERT ON vfs_directories
WHEN NEW.parent_id IS NEW.id
BEGIN
    SELECT RAISE(ABORT, 'VFS directory graph must be acyclic');
END;

CREATE TRIGGER reject_vfs_directory_cycle_update
BEFORE UPDATE OF parent_id, filesystem_id ON vfs_directories
WHEN NEW.parent_id IS NOT NULL
BEGIN
    SELECT CASE WHEN EXISTS (
        WITH RECURSIVE ancestors(id, parent_id) AS (
            SELECT id, parent_id
            FROM vfs_directories
            WHERE id = NEW.parent_id
            UNION
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        )
        SELECT 1 FROM ancestors WHERE id = NEW.id
    ) THEN RAISE(ABORT, 'VFS directory graph must be acyclic') END;
END;

CREATE TABLE vfs_groups (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (
        length(CAST(name AS BLOB)) BETWEEN 1 AND 256
        AND trim(name) = name
    ),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (filesystem_id, name),
    UNIQUE (id, filesystem_id)
) STRICT;

CREATE TABLE vfs_group_members (
    group_id TEXT NOT NULL REFERENCES vfs_groups(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES vfs_principals(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (group_id, principal_id)
) STRICT;

CREATE TABLE vfs_acl_grants (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id) ON DELETE CASCADE,
    principal_id TEXT REFERENCES vfs_principals(id) ON DELETE CASCADE,
    group_id TEXT REFERENCES vfs_groups(id) ON DELETE CASCADE,
    action TEXT NOT NULL REFERENCES vfs_actions(name),
    source_role TEXT CHECK (
        source_role IS NULL
        OR source_role IN (
            'viewer', 'editor', 'publisher', 'security_administrator',
            'storage_operator', 'janitor', 'system_administrator'
        )
    ),
    created_by TEXT NOT NULL REFERENCES vfs_principals(id),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    CHECK ((principal_id IS NULL) != (group_id IS NULL))
) STRICT;

CREATE UNIQUE INDEX unique_vfs_principal_grant
ON vfs_acl_grants(directory_id, principal_id, action)
WHERE principal_id IS NOT NULL;

CREATE UNIQUE INDEX unique_vfs_group_grant
ON vfs_acl_grants(directory_id, group_id, action)
WHERE group_id IS NOT NULL;

CREATE TRIGGER bump_vfs_acl_after_insert
AFTER INSERT ON vfs_acl_grants
BEGIN
    UPDATE vfs_directories
    SET acl_revision = acl_revision + 1,
        updated_at = MAX(updated_at, NEW.created_at)
    WHERE id = NEW.directory_id;
END;

CREATE TRIGGER bump_vfs_acl_after_delete
AFTER DELETE ON vfs_acl_grants
BEGIN
    UPDATE vfs_directories
    SET acl_revision = acl_revision + 1,
        updated_at = MAX(updated_at, unixepoch())
    WHERE id = OLD.directory_id;
END;

CREATE TRIGGER validate_vfs_group_grant_filesystem
BEFORE INSERT ON vfs_acl_grants
WHEN NEW.group_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_groups AS group_record
        JOIN vfs_directories AS directory
          ON directory.filesystem_id = group_record.filesystem_id
        WHERE group_record.id = NEW.group_id
          AND directory.id = NEW.directory_id
    ) THEN RAISE(ABORT, 'VFS ACL group belongs to another filesystem') END;
END;

CREATE TRIGGER reject_vfs_acl_grant_update
BEFORE UPDATE ON vfs_acl_grants
BEGIN
    SELECT RAISE(ABORT, 'VFS ACL grants are replaced, not updated');
END;

CREATE TABLE vfs_files (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    current_version_id TEXT,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'tombstoned')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (id, filesystem_id)
) STRICT;

CREATE TABLE vfs_file_versions (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    file_id TEXT NOT NULL REFERENCES vfs_files(id) ON DELETE CASCADE,
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
    block_manifest_sha256 TEXT NOT NULL CHECK (
        length(block_manifest_sha256) = 64
        AND block_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    block_manifest_bytes INTEGER NOT NULL CHECK (block_manifest_bytes > 0),
    block_manifest_r2_key TEXT NOT NULL CHECK (
        length(CAST(block_manifest_r2_key AS BLOB)) BETWEEN 1 AND 4096
    ),
    block_manifest_r2_version TEXT NOT NULL CHECK (
        length(CAST(block_manifest_r2_version AS BLOB)) BETWEEN 1 AND 1024
    ),
    crypto_suite TEXT NOT NULL CHECK (
        length(CAST(crypto_suite AS BLOB)) BETWEEN 1 AND 128
    ),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    encryption_frame_bytes INTEGER NOT NULL CHECK (encryption_frame_bytes > 0),
    encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes >= 0),
    encoded_sha256 TEXT NOT NULL CHECK (
        length(encoded_sha256) = 64
        AND encoded_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL DEFAULT 'staging' CHECK (
        state IN ('staging', 'verified', 'published', 'tombstoned')
    ),
    published_at INTEGER,
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    UNIQUE (file_id, id),
    CHECK ((state = 'published') = (published_at IS NOT NULL) OR state = 'tombstoned')
) STRICT;

CREATE TRIGGER validate_vfs_version_state_transition
BEFORE UPDATE OF state ON vfs_file_versions
WHEN NOT (
    (OLD.state = 'staging' AND NEW.state IN ('verified', 'tombstoned'))
    OR (OLD.state = 'verified' AND NEW.state IN ('published', 'tombstoned'))
    OR (OLD.state = 'published' AND NEW.state = 'tombstoned')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid VFS file-version state transition');
END;

CREATE TRIGGER require_staging_vfs_version_insert
BEFORE INSERT ON vfs_file_versions
WHEN NEW.state != 'staging' OR NEW.published_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'VFS file version must begin in staging');
END;

CREATE TRIGGER validate_vfs_version_publication
BEFORE UPDATE OF state ON vfs_file_versions
WHEN NEW.state = 'published'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_locations AS location
        WHERE location.version_id = NEW.id
          AND location.state = 'available'
    ) THEN RAISE(ABORT, 'published VFS version requires an available location') END;
END;

CREATE TRIGGER protect_vfs_version_identity
BEFORE UPDATE OF
    file_id, plaintext_bytes, verification_block_bytes,
    verification_block_count, file_root, block_manifest_sha256,
    block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
    crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes, encoded_sha256
ON vfs_file_versions
BEGIN
    SELECT RAISE(ABORT, 'VFS file-version identity is immutable');
END;

CREATE TRIGGER validate_vfs_current_version
BEFORE UPDATE OF current_version_id ON vfs_files
WHEN NEW.current_version_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_file_versions AS version
        WHERE version.id = NEW.current_version_id
          AND version.file_id = NEW.id
          AND version.state = 'published'
    ) THEN RAISE(ABORT, 'VFS current version must be published') END;
END;

CREATE TRIGGER require_empty_vfs_current_version_insert
BEFORE INSERT ON vfs_files
WHEN NEW.current_version_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'new VFS file cannot have a current version');
END;

CREATE TRIGGER validate_vfs_file_revision_update
BEFORE UPDATE OF current_version_id, state ON vfs_files
WHEN NOT (
    OLD.current_version_id IS NULL
    AND NEW.current_version_id IS NOT NULL
    AND NEW.state = OLD.state
    AND NEW.revision = OLD.revision
    AND NEW.updated_at >= OLD.updated_at
)
AND (NEW.revision != OLD.revision + 1 OR NEW.updated_at < OLD.updated_at)
BEGIN
    SELECT RAISE(ABORT, 'VFS file mutation requires the next revision');
END;

CREATE TRIGGER protect_current_vfs_version_delete
BEFORE DELETE ON vfs_file_versions
WHEN EXISTS (
    SELECT 1 FROM vfs_files WHERE current_version_id = OLD.id
)
BEGIN
    SELECT RAISE(ABORT, 'current VFS file version cannot be deleted');
END;

CREATE TABLE vfs_locations (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    version_id TEXT NOT NULL REFERENCES vfs_file_versions(id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    storage_key TEXT NOT NULL CHECK (
        length(CAST(storage_key AS BLOB)) BETWEEN 1 AND 4096
    ),
    native_id TEXT,
    provider_version TEXT,
    etag TEXT,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    object_sha256 TEXT NOT NULL CHECK (
        length(object_sha256) = 64
        AND object_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL DEFAULT 'staging' CHECK (
        state IN ('staging', 'verified', 'available', 'tombstoned', 'deleted')
    ),
    verified_at INTEGER,
    delete_after INTEGER,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (driver_id, storage_key),
    CHECK (
        (state IN ('verified', 'available', 'tombstoned', 'deleted'))
        = (verified_at IS NOT NULL)
    ),
    CHECK ((state IN ('tombstoned', 'deleted')) = (delete_after IS NOT NULL))
) STRICT;

CREATE TRIGGER validate_vfs_location_identity
BEFORE INSERT ON vfs_locations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_file_versions AS version
        WHERE version.id = NEW.version_id
          AND version.encoded_bytes = NEW.size_bytes
          AND version.encoded_sha256 = NEW.object_sha256
    ) THEN RAISE(ABORT, 'VFS location must contain one complete encoded version') END;
END;

CREATE TRIGGER require_staging_vfs_location_insert
BEFORE INSERT ON vfs_locations
WHEN NEW.state != 'staging'
BEGIN
    SELECT RAISE(ABORT, 'VFS location must begin in staging');
END;

CREATE TRIGGER validate_vfs_location_identity_update
BEFORE UPDATE OF version_id, size_bytes, object_sha256 ON vfs_locations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_file_versions AS version
        WHERE version.id = NEW.version_id
          AND version.encoded_bytes = NEW.size_bytes
          AND version.encoded_sha256 = NEW.object_sha256
    ) THEN RAISE(ABORT, 'VFS location must contain one complete encoded version') END;
END;

CREATE TRIGGER validate_vfs_location_state_transition
BEFORE UPDATE OF state ON vfs_locations
WHEN NOT (
    (OLD.state = 'staging' AND NEW.state = 'verified')
    OR (OLD.state = 'verified' AND NEW.state IN ('available', 'tombstoned'))
    OR (OLD.state = 'available' AND NEW.state = 'tombstoned')
    OR (OLD.state = 'tombstoned' AND NEW.state = 'deleted')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid VFS location state transition');
END;

CREATE TRIGGER protect_verified_vfs_location_identity
BEFORE UPDATE OF
    version_id, driver_id, storage_key, native_id, provider_version,
    etag, size_bytes, object_sha256
ON vfs_locations
WHEN OLD.state != 'staging'
BEGIN
    SELECT RAISE(ABORT, 'verified VFS location identity is immutable');
END;

CREATE TABLE vfs_directory_entries (
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (
        length(CAST(name AS BLOB)) BETWEEN 1 AND 255
        AND name NOT IN ('.', '..')
        AND instr(name, '/') = 0
        AND instr(name, char(0)) = 0
    ),
    kind TEXT NOT NULL CHECK (kind IN ('file', 'directory')),
    file_id TEXT REFERENCES vfs_files(id),
    version_id TEXT REFERENCES vfs_file_versions(id),
    child_directory_id TEXT REFERENCES vfs_directories(id),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    data_root TEXT NOT NULL CHECK (
        length(data_root) = 64
        AND data_root NOT GLOB '*[^0-9a-f]*'
    ),
    metadata_root TEXT CHECK (
        metadata_root IS NULL
        OR (
            length(metadata_root) = 64
            AND metadata_root NOT GLOB '*[^0-9a-f]*'
        )
    ),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (directory_id, name),
    CHECK (
        (
            kind = 'file'
            AND file_id IS NOT NULL
            AND version_id IS NOT NULL
            AND child_directory_id IS NULL
            AND metadata_root IS NOT NULL
        )
        OR (
            kind = 'directory'
            AND file_id IS NULL
            AND version_id IS NULL
            AND child_directory_id IS NOT NULL
            AND size_bytes = 0
            AND metadata_root IS NULL
        )
    )
) STRICT;

CREATE UNIQUE INDEX one_vfs_entry_per_file
ON vfs_directory_entries(file_id)
WHERE file_id IS NOT NULL;

CREATE UNIQUE INDEX one_vfs_entry_per_child_directory
ON vfs_directory_entries(child_directory_id)
WHERE child_directory_id IS NOT NULL;

CREATE TRIGGER validate_vfs_directory_entry_revision_update
BEFORE UPDATE ON vfs_directory_entries
WHEN NEW.revision != OLD.revision + 1 OR NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'VFS directory-entry mutation requires the next revision');
END;

CREATE TRIGGER validate_vfs_file_entry
BEFORE INSERT ON vfs_directory_entries
WHEN NEW.kind = 'file'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_file_versions AS version
        JOIN vfs_files AS file ON file.id = version.file_id
        JOIN vfs_directories AS directory
          ON directory.filesystem_id = file.filesystem_id
        WHERE version.id = NEW.version_id
          AND file.id = NEW.file_id
          AND directory.id = NEW.directory_id
          AND version.state = 'published'
          AND version.plaintext_bytes = NEW.size_bytes
          AND version.file_root = NEW.data_root
    ) THEN RAISE(ABORT, 'VFS file entry must pin a published matching version') END;
END;

CREATE TRIGGER validate_vfs_directory_entry
BEFORE INSERT ON vfs_directory_entries
WHEN NEW.kind = 'directory'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_directories AS child
        JOIN vfs_directories AS parent
          ON parent.filesystem_id = child.filesystem_id
        WHERE child.id = NEW.child_directory_id
          AND parent.id = NEW.directory_id
          AND child.parent_id = parent.id
          AND child.name = NEW.name
          AND child.data_root = NEW.data_root
          AND child.state = 'active'
    ) THEN RAISE(ABORT, 'VFS directory entry must match its child') END;
END;

CREATE TRIGGER validate_vfs_file_entry_update
BEFORE UPDATE ON vfs_directory_entries
WHEN NEW.kind = 'file'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_file_versions AS version
        JOIN vfs_files AS file ON file.id = version.file_id
        JOIN vfs_directories AS directory
          ON directory.filesystem_id = file.filesystem_id
        WHERE version.id = NEW.version_id
          AND file.id = NEW.file_id
          AND directory.id = NEW.directory_id
          AND version.state = 'published'
          AND version.plaintext_bytes = NEW.size_bytes
          AND version.file_root = NEW.data_root
    ) THEN RAISE(ABORT, 'VFS file entry must pin a published matching version') END;
END;

CREATE TRIGGER validate_vfs_directory_entry_update
BEFORE UPDATE ON vfs_directory_entries
WHEN NEW.kind = 'directory'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_directories AS child
        JOIN vfs_directories AS parent
          ON parent.filesystem_id = child.filesystem_id
        WHERE child.id = NEW.child_directory_id
          AND parent.id = NEW.directory_id
          AND child.parent_id = parent.id
          AND child.name = NEW.name
          AND child.data_root = NEW.data_root
          AND child.state = 'active'
    ) THEN RAISE(ABORT, 'VFS directory entry must match its child') END;
END;

CREATE TABLE vfs_catalog_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    parent_revision_id INTEGER REFERENCES vfs_catalog_revisions(id),
    root_data_root TEXT NOT NULL CHECK (
        length(root_data_root) = 64
        AND root_data_root NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'materialized', 'published')
    ),
    checkpoint_r2_key TEXT,
    checkpoint_sha256 TEXT CHECK (
        checkpoint_sha256 IS NULL
        OR (
            length(checkpoint_sha256) = 64
            AND checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    delta_r2_key TEXT,
    delta_sha256 TEXT CHECK (
        delta_sha256 IS NULL
        OR (
            length(delta_sha256) = 64
            AND delta_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    materialized_at INTEGER,
    published_at INTEGER,
    CHECK ((state = 'pending') = (materialized_at IS NULL)),
    CHECK ((state = 'published') = (published_at IS NOT NULL))
) STRICT;

CREATE TABLE vfs_catalog_outbox (
    revision_id INTEGER PRIMARY KEY REFERENCES vfs_catalog_revisions(id) ON DELETE CASCADE,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'claimed', 'done')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_owner TEXT,
    lease_expires_at INTEGER,
    last_error_code TEXT,
    updated_at INTEGER NOT NULL CHECK (updated_at > 0),
    CHECK ((state = 'claimed') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL))
) STRICT;

CREATE TABLE vfs_catalog_heads (
    filesystem_id TEXT PRIMARY KEY REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    revision_id INTEGER NOT NULL UNIQUE REFERENCES vfs_catalog_revisions(id),
    root_data_root TEXT NOT NULL CHECK (length(root_data_root) = 64),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at > 0)
) STRICT;

CREATE TABLE vfs_snapshots (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    data_root TEXT NOT NULL CHECK (
        length(data_root) = 64
        AND data_root NOT GLOB '*[^0-9a-f]*'
    ),
    catalog_revision_id INTEGER NOT NULL REFERENCES vfs_catalog_revisions(id),
    manifest_r2_key TEXT NOT NULL UNIQUE CHECK (
        length(CAST(manifest_r2_key AS BLOB)) BETWEEN 1 AND 4096
    ),
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256) = 64
        AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL DEFAULT 'retained' CHECK (state IN ('retained', 'expired')),
    created_by TEXT NOT NULL REFERENCES vfs_principals(id),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    expires_at INTEGER CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;

CREATE TABLE vfs_channels (
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (
        length(CAST(name AS BLOB)) BETWEEN 1 AND 128
        AND trim(name) = name
    ),
    snapshot_id TEXT NOT NULL REFERENCES vfs_snapshots(id),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by TEXT NOT NULL REFERENCES vfs_principals(id),
    updated_at INTEGER NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (filesystem_id, directory_id, name)
) STRICT;

CREATE TABLE vfs_token_verifiers (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 32
        AND id NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000000000000000000000000000'
    ),
    principal_id TEXT NOT NULL REFERENCES vfs_principals(id) ON DELETE CASCADE,
    root_directory_id TEXT NOT NULL REFERENCES vfs_directories(id) ON DELETE CASCADE,
    parent_token_id TEXT REFERENCES vfs_token_verifiers(id),
    verifier_algorithm TEXT NOT NULL DEFAULT 'sha256/v1' CHECK (
        verifier_algorithm = 'sha256/v1'
    ),
    verifier_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(verifier_sha256) = 64
        AND verifier_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    snapshot_id TEXT REFERENCES vfs_snapshots(id),
    expires_at INTEGER NOT NULL,
    sealed_at INTEGER,
    revoked_at INTEGER,
    issued_by TEXT NOT NULL REFERENCES vfs_principals(id),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    CHECK (expires_at > created_at),
    CHECK (sealed_at IS NULL OR sealed_at >= created_at),
    CHECK (revoked_at IS NULL OR (sealed_at IS NOT NULL AND revoked_at >= sealed_at)),
    CHECK (parent_token_id IS NULL OR parent_token_id != id)
) STRICT;

CREATE TABLE vfs_token_actions (
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id) ON DELETE CASCADE,
    action TEXT NOT NULL REFERENCES vfs_actions(name),
    PRIMARY KEY (token_id, action)
) STRICT;

CREATE TABLE vfs_token_drivers (
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    PRIMARY KEY (token_id, driver_id)
) STRICT;

CREATE TRIGGER protect_sealed_vfs_token_scope
BEFORE UPDATE OF
    principal_id, root_directory_id, parent_token_id, verifier_algorithm,
    verifier_sha256, snapshot_id, expires_at, issued_by, created_at
ON vfs_token_verifiers
WHEN OLD.sealed_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'sealed VFS token scope is immutable');
END;

CREATE TRIGGER validate_vfs_token_revocation
BEFORE UPDATE OF revoked_at ON vfs_token_verifiers
WHEN OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revoked_at < OLD.sealed_at
BEGIN
    SELECT RAISE(ABORT, 'VFS token revocation is monotonic');
END;

CREATE TRIGGER validate_vfs_token_seal
BEFORE UPDATE OF sealed_at ON vfs_token_verifiers
WHEN NEW.sealed_at IS NOT NULL
BEGIN
    SELECT CASE WHEN OLD.sealed_at IS NOT NULL
        THEN RAISE(ABORT, 'VFS token is already sealed') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_token_actions WHERE token_id = NEW.id
    ) THEN RAISE(ABORT, 'VFS token requires at least one action') END;
    SELECT CASE WHEN NEW.sealed_at >= NEW.expires_at
        THEN RAISE(ABORT, 'VFS token must be sealed before expiry') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_principals
        WHERE id = NEW.principal_id AND state = 'active'
    ) THEN RAISE(ABORT, 'VFS token principal must be active') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_directories
        WHERE id = NEW.root_directory_id AND state = 'active'
    ) THEN RAISE(ABORT, 'VFS token root must be active') END;
    SELECT CASE WHEN NEW.parent_token_id IS NOT NULL AND NOT EXISTS (
        WITH RECURSIVE ancestors(id, parent_id) AS (
            SELECT id, parent_id FROM vfs_directories WHERE id = NEW.root_directory_id
            UNION
            SELECT parent.id, parent.parent_id
            FROM vfs_directories AS parent
            JOIN ancestors AS child ON child.parent_id = parent.id
        )
        SELECT 1
        FROM vfs_token_verifiers AS parent
        WHERE parent.id = NEW.parent_token_id
          AND parent.sealed_at IS NOT NULL
          AND parent.revoked_at IS NULL
          AND parent.principal_id = NEW.principal_id
          AND parent.expires_at >= NEW.expires_at
          AND parent.expires_at > NEW.sealed_at
          AND (parent.snapshot_id IS NULL OR parent.snapshot_id IS NEW.snapshot_id)
          AND EXISTS (
              SELECT 1 FROM ancestors
              WHERE ancestors.id = parent.root_directory_id
          )
          AND NOT EXISTS (
              SELECT 1
              FROM vfs_token_actions AS child_action
              WHERE child_action.token_id = NEW.id
                AND NOT EXISTS (
                    SELECT 1 FROM vfs_token_actions AS parent_action
                    WHERE parent_action.token_id = parent.id
                      AND parent_action.action = child_action.action
                )
          )
          AND (
              NOT EXISTS (
                  SELECT 1 FROM vfs_token_drivers
                  WHERE token_id = parent.id
              )
              OR (
                  EXISTS (
                      SELECT 1 FROM vfs_token_drivers
                      WHERE token_id = NEW.id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM vfs_token_drivers AS child_driver
                      WHERE child_driver.token_id = NEW.id
                        AND NOT EXISTS (
                            SELECT 1 FROM vfs_token_drivers AS parent_driver
                            WHERE parent_driver.token_id = parent.id
                              AND parent_driver.driver_id = child_driver.driver_id
                        )
                  )
              )
          )
    ) THEN RAISE(ABORT, 'child VFS token widens its parent') END;
END;

CREATE TRIGGER protect_sealed_vfs_token_action_insert
BEFORE INSERT ON vfs_token_actions
WHEN EXISTS (
    SELECT 1 FROM vfs_token_verifiers
    WHERE id = NEW.token_id AND sealed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'sealed VFS token actions are immutable');
END;

CREATE TRIGGER protect_sealed_vfs_token_action_delete
BEFORE DELETE ON vfs_token_actions
WHEN EXISTS (
    SELECT 1 FROM vfs_token_verifiers
    WHERE id = OLD.token_id AND sealed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'sealed VFS token actions are immutable');
END;

CREATE TRIGGER protect_sealed_vfs_token_action_update
BEFORE UPDATE ON vfs_token_actions
WHEN EXISTS (
    SELECT 1 FROM vfs_token_verifiers
    WHERE id IN (OLD.token_id, NEW.token_id) AND sealed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'sealed VFS token actions are immutable');
END;

CREATE TRIGGER protect_sealed_vfs_token_driver_insert
BEFORE INSERT ON vfs_token_drivers
WHEN EXISTS (
    SELECT 1 FROM vfs_token_verifiers
    WHERE id = NEW.token_id AND sealed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'sealed VFS token drivers are immutable');
END;

CREATE TRIGGER protect_sealed_vfs_token_driver_delete
BEFORE DELETE ON vfs_token_drivers
WHEN EXISTS (
    SELECT 1 FROM vfs_token_verifiers
    WHERE id = OLD.token_id AND sealed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'sealed VFS token drivers are immutable');
END;

CREATE TRIGGER protect_sealed_vfs_token_driver_update
BEFORE UPDATE ON vfs_token_drivers
WHEN EXISTS (
    SELECT 1 FROM vfs_token_verifiers
    WHERE id IN (OLD.token_id, NEW.token_id) AND sealed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'sealed VFS token drivers are immutable');
END;

CREATE TABLE vfs_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filesystem_id TEXT REFERENCES vfs_filesystems(id),
    principal_id TEXT REFERENCES vfs_principals(id),
    token_id TEXT REFERENCES vfs_token_verifiers(id),
    event_kind TEXT NOT NULL CHECK (
        length(CAST(event_kind AS BLOB)) BETWEEN 1 AND 128
    ),
    subject_kind TEXT NOT NULL CHECK (
        length(CAST(subject_kind AS BLOB)) BETWEEN 1 AND 64
    ),
    subject_id TEXT NOT NULL CHECK (
        length(CAST(subject_id AS BLOB)) BETWEEN 1 AND 4096
    ),
    details_json TEXT NOT NULL CHECK (json_valid(details_json)),
    created_at INTEGER NOT NULL CHECK (created_at > 0)
) STRICT;
