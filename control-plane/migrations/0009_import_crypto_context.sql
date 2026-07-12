PRAGMA foreign_keys = ON;

CREATE TABLE import_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    root_key_version INTEGER NOT NULL CHECK (root_key_version > 0),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    created_at INTEGER NOT NULL
) STRICT;

INSERT INTO import_intents (operation_id, root_key_version, key_epoch, created_at)
SELECT
    operation.id,
    COALESCE(
        (
            SELECT pack.root_key_version
            FROM publication_intents AS publication
            JOIN object_versions AS version
              ON version.object_id = publication.object_id
             AND version.generation = publication.generation
            JOIN version_packs AS version_pack ON version_pack.version_id = version.id
            JOIN packs AS pack ON pack.id = version_pack.pack_id
            WHERE publication.operation_id = operation.id
            LIMIT 1
        ),
        namespace.root_key_version
    ),
    COALESCE(
        (
            SELECT pack.key_epoch
            FROM publication_intents AS publication
            JOIN object_versions AS version
              ON version.object_id = publication.object_id
             AND version.generation = publication.generation
            JOIN version_packs AS version_pack ON version_pack.version_id = version.id
            JOIN packs AS pack ON pack.id = version_pack.pack_id
            WHERE publication.operation_id = operation.id
            LIMIT 1
        ),
        namespace.active_key_epoch
    ),
    operation.created_at
FROM operations AS operation
JOIN namespaces AS namespace ON namespace.id = operation.namespace_id
WHERE operation.kind = 'import';

CREATE TRIGGER import_crypto_context_is_immutable
BEFORE UPDATE OF root_key_version, key_epoch ON import_intents
WHEN OLD.root_key_version != NEW.root_key_version OR OLD.key_epoch != NEW.key_epoch
BEGIN
    SELECT RAISE(ABORT, 'import crypto context is immutable');
END;
