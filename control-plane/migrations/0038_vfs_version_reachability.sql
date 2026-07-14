PRAGMA foreign_keys = ON;

-- A version keeps its original directory even after its live entry is
-- replaced or deleted. Destructive token scope is evaluated against this
-- immutable origin; versions without one remain ineligible for GC.
CREATE TABLE vfs_version_origins (
    version_id TEXT PRIMARY KEY REFERENCES vfs_file_versions(id) ON DELETE CASCADE,
    directory_id TEXT NOT NULL REFERENCES vfs_directories(id),
    created_at INTEGER NOT NULL CHECK (created_at > 0)
) STRICT;

CREATE INDEX idx_vfs_version_origins_directory
ON vfs_version_origins(directory_id, version_id);

CREATE TRIGGER validate_vfs_version_origin_insert
BEFORE INSERT ON vfs_version_origins
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_file_versions AS version
        JOIN vfs_files AS file ON file.id = version.file_id
        JOIN vfs_directories AS directory
          ON directory.filesystem_id = file.filesystem_id
        WHERE version.id = NEW.version_id
          AND directory.id = NEW.directory_id
    ) THEN RAISE(ABORT, 'VFS version origin must belong to its filesystem') END;
END;

CREATE TRIGGER protect_vfs_version_origin_update
BEFORE UPDATE ON vfs_version_origins
BEGIN
    SELECT RAISE(ABORT, 'VFS version origin is immutable');
END;

CREATE TRIGGER require_vfs_version_origin_for_publication
BEFORE UPDATE OF state ON vfs_file_versions
WHEN NEW.state = 'published'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_version_origins
        WHERE version_id = NEW.id
    ) THEN RAISE(ABORT, 'published VFS version requires an immutable origin') END;
END;

-- Backfill only versions with an exact committed Put receipt. Any other
-- historical version intentionally stays fail-closed until explicitly
-- reconciled through a future validated recovery surface.
INSERT INTO vfs_version_origins (version_id, directory_id, created_at)
SELECT intent.version_id, intent.directory_id, receipt.committed_at
FROM vfs_put_receipts AS receipt
JOIN vfs_put_intents AS intent ON intent.id = receipt.intent_id
JOIN vfs_file_versions AS version ON version.id = intent.version_id;

-- Snapshot manifests are immutable R2 metadata, but D1 GC needs a local exact
-- version set so reachability never depends on fetching R2 during a fence.
CREATE TABLE vfs_snapshot_versions (
    snapshot_id TEXT NOT NULL REFERENCES vfs_snapshots(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES vfs_file_versions(id),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (snapshot_id, version_id)
) STRICT;

CREATE INDEX idx_vfs_snapshot_versions_version
ON vfs_snapshot_versions(version_id, snapshot_id);

-- The seal binds the materialized set to the canonical ordered-version digest
-- validated by the snapshot publication API. Count is also enforced in D1.
CREATE TABLE vfs_snapshot_reachability_seals (
    snapshot_id TEXT PRIMARY KEY REFERENCES vfs_snapshots(id) ON DELETE CASCADE,
    version_count INTEGER NOT NULL CHECK (version_count >= 0),
    versions_sha256 TEXT NOT NULL CHECK (
        length(versions_sha256) = 64
        AND versions_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    sealed_at INTEGER NOT NULL CHECK (sealed_at > 0)
) STRICT;

CREATE INDEX idx_vfs_token_verifiers_snapshot_expiry
ON vfs_token_verifiers(snapshot_id, expires_at)
WHERE snapshot_id IS NOT NULL AND sealed_at IS NOT NULL;

CREATE INDEX idx_vfs_channels_snapshot
ON vfs_channels(snapshot_id);

CREATE INDEX idx_vfs_files_current_version
ON vfs_files(current_version_id)
WHERE current_version_id IS NOT NULL;

CREATE INDEX idx_vfs_directory_entries_file_version
ON vfs_directory_entries(version_id)
WHERE kind = 'file';

CREATE INDEX idx_vfs_versions_published_at
ON vfs_file_versions(published_at, id)
WHERE state = 'published';

CREATE TRIGGER validate_vfs_snapshot_version_insert
BEFORE INSERT ON vfs_snapshot_versions
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM vfs_snapshot_reachability_seals
        WHERE snapshot_id = NEW.snapshot_id
    ) THEN RAISE(ABORT, 'sealed VFS snapshot reachability is immutable') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM vfs_snapshots AS snapshot
        JOIN vfs_file_versions AS version ON version.id = NEW.version_id
        JOIN vfs_files AS file ON file.id = version.file_id
        WHERE snapshot.id = NEW.snapshot_id
          AND snapshot.state = 'retained'
          AND snapshot.filesystem_id = file.filesystem_id
          AND version.state = 'published'
    ) THEN RAISE(ABORT, 'VFS snapshot version must be published in the same filesystem') END;
END;

CREATE TRIGGER protect_vfs_snapshot_version_update
BEFORE UPDATE ON vfs_snapshot_versions
BEGIN
    SELECT RAISE(ABORT, 'VFS snapshot version identity is immutable');
END;

CREATE TRIGGER validate_vfs_snapshot_reachability_seal
BEFORE INSERT ON vfs_snapshot_reachability_seals
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM vfs_snapshots
        WHERE id = NEW.snapshot_id AND state = 'retained'
    ) THEN RAISE(ABORT, 'only a retained VFS snapshot may seal reachability') END;
    SELECT CASE WHEN NEW.version_count != (
        SELECT COUNT(*) FROM vfs_snapshot_versions
        WHERE snapshot_id = NEW.snapshot_id
    ) THEN RAISE(ABORT, 'VFS snapshot reachability count differs') END;
END;

CREATE TRIGGER protect_vfs_snapshot_reachability_seal_update
BEFORE UPDATE ON vfs_snapshot_reachability_seals
BEGIN
    SELECT RAISE(ABORT, 'VFS snapshot reachability seal is immutable');
END;

-- Retention, a channel pointer, or an unexpired sealed snapshot token protects
-- a snapshot. Token revocation deliberately does not shorten this protection:
-- an already issued direct-read capability may remain in client memory until
-- its original expiry.
CREATE VIEW vfs_protective_snapshots AS
SELECT snapshot.id, snapshot.filesystem_id
FROM vfs_snapshots AS snapshot
WHERE snapshot.state = 'retained'
   OR EXISTS (
       SELECT 1 FROM vfs_channels AS channel
       WHERE channel.snapshot_id = snapshot.id
   )
   OR EXISTS (
       SELECT 1 FROM vfs_token_verifiers AS token
       WHERE token.snapshot_id = snapshot.id
         AND token.sealed_at IS NOT NULL
         AND token.expires_at > unixepoch()
   );

-- A missing seal or a row-count mismatch blocks GC for the whole filesystem.
-- This is the critical fail-closed boundary for pre-migration snapshots,
-- partial publication, corruption, and manual D1 damage.
CREATE VIEW vfs_gc_blocked_filesystems AS
SELECT DISTINCT protective.filesystem_id
FROM vfs_protective_snapshots AS protective
LEFT JOIN vfs_snapshot_reachability_seals AS seal
  ON seal.snapshot_id = protective.id
WHERE seal.snapshot_id IS NULL
   OR seal.version_count != (
       SELECT COUNT(*) FROM vfs_snapshot_versions AS version
       WHERE version.snapshot_id = protective.id
   );

CREATE VIEW vfs_reachable_versions AS
SELECT current_version_id AS version_id
FROM vfs_files
WHERE current_version_id IS NOT NULL
UNION
SELECT version_id
FROM vfs_directory_entries
WHERE kind = 'file'
UNION
SELECT version.version_id
FROM vfs_snapshot_versions AS version
JOIN vfs_protective_snapshots AS protective
  ON protective.id = version.snapshot_id
JOIN vfs_snapshot_reachability_seals AS seal
  ON seal.snapshot_id = version.snapshot_id
WHERE seal.version_count = (
    SELECT COUNT(*) FROM vfs_snapshot_versions AS counted
    WHERE counted.snapshot_id = version.snapshot_id
);

-- This view is evidence for a later fenced mark protocol. It never changes a
-- location. Age policy, driver revision, and final fences are intentionally
-- applied when tasks are created and claimed.
CREATE VIEW safe_unreachable_vfs_locations AS
SELECT location.id, version.published_at, origin.directory_id
FROM vfs_file_versions AS version INDEXED BY idx_vfs_versions_published_at
JOIN vfs_locations AS location ON location.version_id = version.id
JOIN vfs_files AS file ON file.id = version.file_id
JOIN vfs_version_origins AS origin ON origin.version_id = version.id
JOIN driver_instances AS driver ON driver.id = location.driver_id
WHERE location.state = 'available'
  AND version.state = 'published'
  AND driver.enabled = 1
  AND (
      location.native_id IS NOT NULL
      OR location.provider_version IS NOT NULL
      OR location.etag IS NOT NULL
  )
  AND file.filesystem_id NOT IN (SELECT filesystem_id FROM vfs_gc_blocked_filesystems)
  AND NOT EXISTS (
      SELECT 1 FROM vfs_files AS current
      WHERE current.current_version_id = version.id
  )
  AND NOT EXISTS (
      SELECT 1 FROM vfs_directory_entries AS entry
      WHERE entry.kind = 'file' AND entry.version_id = version.id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM vfs_snapshot_versions AS snapshot_version
      JOIN vfs_protective_snapshots AS protective
        ON protective.id = snapshot_version.snapshot_id
      JOIN vfs_snapshot_reachability_seals AS seal
        ON seal.snapshot_id = snapshot_version.snapshot_id
      WHERE snapshot_version.version_id = version.id
        AND seal.version_count = (
            SELECT COUNT(*) FROM vfs_snapshot_versions AS counted
            WHERE counted.snapshot_id = snapshot_version.snapshot_id
        )
  );
