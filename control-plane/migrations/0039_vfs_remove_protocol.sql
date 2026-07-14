PRAGMA foreign_keys = ON;

CREATE TABLE vfs_remove_intents (
    id TEXT PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES vfs_principals(id),
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    entry_name TEXT NOT NULL CHECK (length(CAST(entry_name AS BLOB)) BETWEEN 1 AND 255),
    expected_entry_revision INTEGER NOT NULL CHECK (expected_entry_revision > 0),
    entry_kind TEXT NOT NULL CHECK (entry_kind IN ('file', 'directory')),
    subject_id TEXT NOT NULL CHECK (length(subject_id) = 32),
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
    ),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    UNIQUE (token_id, idempotency_key)
) STRICT;

CREATE TABLE vfs_remove_receipts (
    intent_id TEXT PRIMARY KEY REFERENCES vfs_remove_intents(id) ON DELETE CASCADE,
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    request_sha256 TEXT NOT NULL,
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    directory_id TEXT NOT NULL,
    entry_name TEXT NOT NULL,
    entry_kind TEXT NOT NULL CHECK (entry_kind IN ('file', 'directory')),
    subject_id TEXT NOT NULL,
    catalog_revision_id INTEGER NOT NULL UNIQUE REFERENCES vfs_catalog_revisions(id),
    delete_after INTEGER,
    committed_at INTEGER NOT NULL CHECK (committed_at > 0),
    UNIQUE (token_id, intent_id)
) STRICT;

CREATE TABLE vfs_remove_directory_updates (
    intent_id TEXT NOT NULL REFERENCES vfs_remove_intents(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    expected_data_root TEXT NOT NULL CHECK (length(expected_data_root) = 64),
    new_data_root TEXT NOT NULL CHECK (length(new_data_root) = 64),
    PRIMARY KEY (intent_id, ordinal),
    UNIQUE (intent_id, directory_id),
    CHECK (expected_data_root != new_data_root)
) STRICT;

CREATE TRIGGER validate_vfs_remove_receipt
BEFORE INSERT ON vfs_remove_receipts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_remove_directory_updates WHERE intent_id = NEW.intent_id
    ) OR EXISTS (
        SELECT 1
        FROM vfs_remove_directory_updates AS update_plan
        LEFT JOIN vfs_directories AS directory ON directory.id = update_plan.directory_id
        WHERE update_plan.intent_id = NEW.intent_id
          AND (
              directory.id IS NULL
              OR directory.revision != update_plan.expected_revision + 1
              OR directory.data_root != update_plan.new_data_root
          )
    ) OR EXISTS (
        SELECT 1 FROM vfs_directory_entries AS entry
        WHERE entry.directory_id = NEW.directory_id AND entry.name = NEW.entry_name
    ) OR (
        NEW.entry_kind = 'directory' AND NOT EXISTS (
            SELECT 1 FROM vfs_directories AS directory
            WHERE directory.id = NEW.subject_id AND directory.state = 'tombstoned'
              AND NOT EXISTS (
                  SELECT 1 FROM vfs_directory_entries AS child
                  WHERE child.directory_id = directory.id
              )
        )
    ) THEN RAISE(ABORT, 'VFS remove optimistic proof was not fully applied') END;
END;

CREATE TRIGGER protect_vfs_remove_directory_update
BEFORE UPDATE ON vfs_remove_directory_updates
BEGIN
    SELECT RAISE(ABORT, 'VFS remove directory update is immutable');
END;

CREATE INDEX vfs_remove_intents_subject
ON vfs_remove_intents(entry_kind, subject_id, created_at);

CREATE TABLE vfs_rename_intents (
    id TEXT PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES vfs_principals(id),
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    source_directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    source_name TEXT NOT NULL,
    expected_source_revision INTEGER NOT NULL CHECK (expected_source_revision > 0),
    destination_directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    destination_name TEXT NOT NULL,
    entry_kind TEXT NOT NULL CHECK (entry_kind IN ('file', 'directory')),
    subject_id TEXT NOT NULL CHECK (length(subject_id) = 32),
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
    ),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    UNIQUE (token_id, idempotency_key)
) STRICT;

CREATE TABLE vfs_rename_directory_updates (
    intent_id TEXT NOT NULL REFERENCES vfs_rename_intents(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    expected_data_root TEXT NOT NULL CHECK (length(expected_data_root) = 64),
    new_data_root TEXT NOT NULL CHECK (length(new_data_root) = 64),
    PRIMARY KEY (intent_id, ordinal),
    UNIQUE (intent_id, directory_id),
    CHECK (expected_data_root != new_data_root)
) STRICT;

CREATE TABLE vfs_rename_receipts (
    intent_id TEXT PRIMARY KEY REFERENCES vfs_rename_intents(id) ON DELETE CASCADE,
    token_id TEXT NOT NULL REFERENCES vfs_token_verifiers(id),
    request_sha256 TEXT NOT NULL,
    filesystem_id TEXT NOT NULL REFERENCES vfs_filesystems(id) ON DELETE CASCADE,
    source_directory_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    destination_directory_id TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    entry_kind TEXT NOT NULL CHECK (entry_kind IN ('file', 'directory')),
    subject_id TEXT NOT NULL,
    entry_revision INTEGER NOT NULL CHECK (entry_revision > 0),
    catalog_revision_id INTEGER NOT NULL UNIQUE REFERENCES vfs_catalog_revisions(id),
    committed_at INTEGER NOT NULL CHECK (committed_at > 0),
    UNIQUE (token_id, intent_id)
) STRICT;

CREATE TRIGGER validate_vfs_rename_receipt
BEFORE INSERT ON vfs_rename_receipts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_rename_directory_updates WHERE intent_id = NEW.intent_id
    ) OR EXISTS (
        SELECT 1
        FROM vfs_rename_directory_updates AS update_plan
        LEFT JOIN vfs_directories AS directory ON directory.id = update_plan.directory_id
        WHERE update_plan.intent_id = NEW.intent_id
          AND (
              directory.id IS NULL
              OR directory.revision != update_plan.expected_revision + 1
              OR directory.data_root != update_plan.new_data_root
          )
    ) OR EXISTS (
        SELECT 1 FROM vfs_directory_entries
        WHERE directory_id = NEW.source_directory_id AND name = NEW.source_name
    ) OR NOT EXISTS (
        SELECT 1 FROM vfs_directory_entries AS entry
        WHERE entry.directory_id = NEW.destination_directory_id
          AND entry.name = NEW.destination_name
          AND entry.kind = NEW.entry_kind
          AND entry.revision = NEW.entry_revision
          AND CASE NEW.entry_kind
              WHEN 'file' THEN entry.file_id = NEW.subject_id
              ELSE entry.child_directory_id = NEW.subject_id
          END
    ) THEN RAISE(ABORT, 'VFS rename optimistic proof was not fully applied') END;
END;

CREATE INDEX vfs_rename_intents_subject
ON vfs_rename_intents(entry_kind, subject_id, created_at);
