PRAGMA foreign_keys = ON;

CREATE TABLE compact_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES object_versions(id),
    object_id TEXT NOT NULL REFERENCES objects(id),
    source_generation INTEGER NOT NULL CHECK (source_generation > 0),
    source_manifest_sha256 TEXT NOT NULL CHECK (
        length(source_manifest_sha256) = 64
        AND source_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_recovery_sha256 TEXT NOT NULL CHECK (
        length(source_recovery_sha256) = 64
        AND source_recovery_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_recovery_revision INTEGER NOT NULL CHECK (source_recovery_revision > 0),
    source_r2_storage_key TEXT NOT NULL CHECK (
        length(source_r2_storage_key) BETWEEN 1 AND 4096
    ),
    source_r2_version TEXT NOT NULL CHECK (
        length(source_r2_version) BETWEEN 1 AND 1024
    ),
    source_recovery_bytes INTEGER NOT NULL CHECK (source_recovery_bytes > 0),
    source_plaintext_sha256 TEXT NOT NULL CHECK (
        length(source_plaintext_sha256) = 64
        AND source_plaintext_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_plaintext_bytes INTEGER NOT NULL CHECK (source_plaintext_bytes > 0),
    source_pack_count INTEGER NOT NULL CHECK (source_pack_count > 1),
    source_root_version INTEGER NOT NULL CHECK (source_root_version > 0),
    source_key_epoch INTEGER NOT NULL CHECK (source_key_epoch > 0),
    expected_object_revision INTEGER NOT NULL CHECK (expected_object_revision > 0),
    target_generation INTEGER NOT NULL CHECK (
        target_generation > 1 AND target_generation = source_generation + 1
    ),
    target_root_version INTEGER NOT NULL CHECK (target_root_version > 0),
    target_key_epoch INTEGER NOT NULL CHECK (target_key_epoch > 0),
    destination_driver_id TEXT NOT NULL REFERENCES driver_instances(id),
    created_at INTEGER NOT NULL,
    UNIQUE (operation_id, version_id, source_recovery_revision),
    UNIQUE (operation_id, object_id, target_generation)
) STRICT;

CREATE INDEX idx_compact_intents_source
ON compact_intents(object_id, source_generation, expected_object_revision);

CREATE TRIGGER compact_intent_requires_current_published_source
BEFORE INSERT ON compact_intents
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM operations AS operation
        JOIN objects AS object ON object.id = NEW.object_id
        JOIN object_versions AS version ON version.id = NEW.version_id
        JOIN recovery_manifests AS recovery ON recovery.version_id = version.id
        JOIN namespaces AS namespace ON namespace.id = operation.namespace_id
        JOIN driver_instances AS destination ON destination.id = NEW.destination_driver_id
        WHERE operation.id = NEW.operation_id
          AND operation.kind = 'compact'
          AND operation.state = 'planned'
          AND operation.namespace_id = object.namespace_id
          AND object.current_generation = NEW.source_generation
          AND object.revision = NEW.expected_object_revision
          AND version.object_id = object.id
          AND version.generation = NEW.source_generation
          AND version.manifest_sha256 = NEW.source_manifest_sha256
          AND version.plaintext_sha256 = NEW.source_plaintext_sha256
          AND version.plaintext_bytes = NEW.source_plaintext_bytes
          AND version.pack_count = NEW.source_pack_count
          AND version.state = 'published'
          AND NOT EXISTS (
              SELECT 1
              FROM version_packs AS version_pack
              JOIN packs AS pack ON pack.id = version_pack.pack_id
              WHERE version_pack.version_id = version.id
                AND (
                    pack.root_key_version != NEW.source_root_version
                    OR pack.key_epoch != NEW.source_key_epoch
                )
          )
          AND recovery.manifest_sha256 = NEW.source_manifest_sha256
          AND recovery.recovery_sha256 = NEW.source_recovery_sha256
          AND recovery.revision = NEW.source_recovery_revision
          AND recovery.r2_storage_key = NEW.source_r2_storage_key
          AND recovery.r2_version = NEW.source_r2_version
          AND recovery.ciphertext_bytes = NEW.source_recovery_bytes
          AND recovery.state = 'durable'
          AND recovery.verified_at IS NOT NULL
          AND namespace.root_key_version = NEW.target_root_version
          AND namespace.active_key_epoch = NEW.target_key_epoch
          AND destination.enabled = 1
    ) THEN RAISE(ABORT, 'compact intent requires the current published source') END;
END;

CREATE TRIGGER compact_intent_is_immutable
BEFORE UPDATE ON compact_intents
BEGIN
    SELECT RAISE(ABORT, 'compact intent is immutable');
END;

CREATE TRIGGER published_version_pack_insert_requires_staging
BEFORE INSERT ON version_packs
WHEN EXISTS (
    SELECT 1 FROM object_versions
    WHERE id = NEW.version_id AND state != 'staging'
)
BEGIN
    SELECT RAISE(ABORT, 'published object version pack set is immutable');
END;

CREATE TRIGGER published_version_pack_update_requires_staging
BEFORE UPDATE ON version_packs
WHEN EXISTS (
    SELECT 1 FROM object_versions
    WHERE id IN (OLD.version_id, NEW.version_id) AND state != 'staging'
)
BEGIN
    SELECT RAISE(ABORT, 'published object version pack set is immutable');
END;

CREATE TRIGGER published_version_pack_delete_requires_staging
BEFORE DELETE ON version_packs
WHEN EXISTS (
    SELECT 1 FROM object_versions
    WHERE id = OLD.version_id AND state != 'staging'
)
BEGIN
    SELECT RAISE(ABORT, 'published object version pack set is immutable');
END;

CREATE TRIGGER committed_compaction_requires_repacked_generation
BEFORE UPDATE OF state ON publication_intents
WHEN NEW.state = 'committed'
  AND OLD.state != 'committed'
  AND EXISTS (
      SELECT 1 FROM compact_intents WHERE operation_id = NEW.operation_id
  )
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM compact_intents AS compact
        JOIN operations AS operation ON operation.id = compact.operation_id
        JOIN objects AS object ON object.id = compact.object_id
        JOIN object_versions AS source ON source.id = compact.version_id
        JOIN object_versions AS target
          ON target.object_id = compact.object_id
         AND target.generation = compact.target_generation
        JOIN recovery_manifests AS recovery ON recovery.version_id = target.id
        WHERE compact.operation_id = NEW.operation_id
          AND operation.kind = 'compact'
          AND operation.state = 'committing'
          AND object.current_generation = compact.target_generation
          AND source.state = 'retired'
          AND source.manifest_sha256 = compact.source_manifest_sha256
          AND target.state = 'published'
          AND target.manifest_sha256 = NEW.manifest_sha256
          AND target.plaintext_sha256 = compact.source_plaintext_sha256
          AND target.plaintext_bytes = compact.source_plaintext_bytes
          AND target.pack_count BETWEEN 1 AND compact.source_pack_count - 1
          AND recovery.manifest_sha256 = NEW.manifest_sha256
          AND recovery.state = 'durable'
          AND recovery.sidecar_driver_id = compact.destination_driver_id
          AND NOT EXISTS (
              SELECT 1
              FROM version_packs AS source_pack
              JOIN version_packs AS target_pack ON target_pack.pack_id = source_pack.pack_id
              WHERE source_pack.version_id = compact.version_id
                AND target_pack.version_id = target.id
          )
          AND NOT EXISTS (
              SELECT 1
              FROM version_packs AS target_pack
              JOIN packs AS pack ON pack.id = target_pack.pack_id
              WHERE target_pack.version_id = target.id
                AND (
                    pack.root_key_version != compact.target_root_version
                    OR pack.key_epoch != compact.target_key_epoch
                )
          )
    ) THEN RAISE(ABORT, 'compact commit requires a smaller immutable replacement generation') END;
END;
