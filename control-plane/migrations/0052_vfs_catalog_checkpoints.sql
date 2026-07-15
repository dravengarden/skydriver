PRAGMA foreign_keys = ON;

-- A catalog revision may publish either one complete checkpoint or one delta.
-- Version and byte identity are retained beside the existing content address so
-- a later read can pin the exact immutable R2 object.
ALTER TABLE vfs_catalog_revisions
ADD COLUMN checkpoint_r2_version TEXT;

ALTER TABLE vfs_catalog_revisions
ADD COLUMN checkpoint_bytes INTEGER;

ALTER TABLE vfs_catalog_revisions
ADD COLUMN delta_r2_version TEXT;

ALTER TABLE vfs_catalog_revisions
ADD COLUMN delta_bytes INTEGER;

CREATE TRIGGER validate_vfs_catalog_materialization_transition
BEFORE UPDATE OF state ON vfs_catalog_revisions
WHEN NEW.state IN ('materialized', 'published')
  AND NOT (
    (
      NEW.checkpoint_r2_key IS NOT NULL
      AND length(CAST(NEW.checkpoint_r2_key AS BLOB)) BETWEEN 1 AND 4096
      AND NEW.checkpoint_sha256 IS NOT NULL
      AND NEW.checkpoint_r2_version IS NOT NULL
      AND length(CAST(NEW.checkpoint_r2_version AS BLOB)) BETWEEN 1 AND 1024
      AND NEW.checkpoint_bytes BETWEEN 1 AND 33554432
      AND NEW.delta_r2_key IS NULL
      AND NEW.delta_sha256 IS NULL
      AND NEW.delta_r2_version IS NULL
      AND NEW.delta_bytes IS NULL
    )
    OR
    (
      NEW.delta_r2_key IS NOT NULL
      AND length(CAST(NEW.delta_r2_key AS BLOB)) BETWEEN 1 AND 4096
      AND NEW.delta_sha256 IS NOT NULL
      AND NEW.delta_r2_version IS NOT NULL
      AND length(CAST(NEW.delta_r2_version AS BLOB)) BETWEEN 1 AND 1024
      AND NEW.delta_bytes BETWEEN 1 AND 33554432
      AND NEW.checkpoint_r2_key IS NULL
      AND NEW.checkpoint_sha256 IS NULL
      AND NEW.checkpoint_r2_version IS NULL
      AND NEW.checkpoint_bytes IS NULL
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'VFS catalog materialization identity is incomplete');
END;

CREATE TRIGGER protect_vfs_catalog_materialization_identity
BEFORE UPDATE OF
  checkpoint_r2_key, checkpoint_sha256, checkpoint_r2_version, checkpoint_bytes,
  delta_r2_key, delta_sha256, delta_r2_version, delta_bytes
ON vfs_catalog_revisions
WHEN OLD.state != 'pending'
BEGIN
  SELECT RAISE(ABORT, 'VFS catalog materialization identity is immutable');
END;

-- Writing is recorded before the R2 side effect. A failed publication can
-- therefore be identified and reclaimed without listing an entire bucket.
CREATE TABLE vfs_catalog_checkpoint_artifacts (
    revision_id INTEGER PRIMARY KEY REFERENCES vfs_catalog_revisions(id) ON DELETE CASCADE,
    r2_key TEXT NOT NULL UNIQUE CHECK (
        length(CAST(r2_key AS BLOB)) BETWEEN 1 AND 4096
    ),
    sha256 TEXT NOT NULL CHECK (
        length(sha256) = 64
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bytes INTEGER NOT NULL CHECK (bytes BETWEEN 1 AND 33554432),
    r2_version TEXT CHECK (
        r2_version IS NULL
        OR length(CAST(r2_version AS BLOB)) BETWEEN 1 AND 1024
    ),
    state TEXT NOT NULL CHECK (
        state IN ('writing', 'staged', 'published', 'orphaned')
    ),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    CHECK ((state = 'writing') = (r2_version IS NULL))
) STRICT;

CREATE TRIGGER validate_vfs_catalog_checkpoint_artifact_transition
BEFORE UPDATE OF state ON vfs_catalog_checkpoint_artifacts
WHEN NOT (
    (OLD.state = 'writing' AND NEW.state = 'staged')
    OR (OLD.state = 'staged' AND NEW.state IN ('published', 'orphaned'))
)
BEGIN
  SELECT RAISE(ABORT, 'invalid VFS catalog checkpoint artifact transition');
END;

CREATE TRIGGER protect_vfs_catalog_checkpoint_artifact_identity
BEFORE UPDATE OF revision_id, r2_key, sha256, bytes, created_at
ON vfs_catalog_checkpoint_artifacts
BEGIN
  SELECT RAISE(ABORT, 'VFS catalog checkpoint artifact identity is immutable');
END;

CREATE TRIGGER require_staged_vfs_catalog_checkpoint
BEFORE UPDATE OF state ON vfs_catalog_revisions
WHEN OLD.state = 'pending' AND NEW.state = 'materialized'
  AND NEW.checkpoint_r2_key IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM vfs_catalog_checkpoint_artifacts AS artifact
      WHERE artifact.revision_id = NEW.id
        AND artifact.r2_key = NEW.checkpoint_r2_key
        AND artifact.sha256 = NEW.checkpoint_sha256
        AND artifact.r2_version = NEW.checkpoint_r2_version
        AND artifact.bytes = NEW.checkpoint_bytes
        AND artifact.state = 'staged'
  )
BEGIN
  SELECT RAISE(ABORT, 'VFS catalog checkpoint requires its staged R2 receipt');
END;

CREATE TRIGGER require_published_vfs_catalog_checkpoint_artifact
BEFORE UPDATE OF state ON vfs_catalog_checkpoint_artifacts
WHEN NEW.state = 'published'
  AND NOT EXISTS (
      SELECT 1
      FROM vfs_catalog_revisions AS revision
      WHERE revision.id = NEW.revision_id
        AND revision.state = 'published'
        AND revision.checkpoint_r2_key = NEW.r2_key
        AND revision.checkpoint_sha256 = NEW.sha256
        AND revision.checkpoint_r2_version = NEW.r2_version
        AND revision.checkpoint_bytes = NEW.bytes
  )
BEGIN
  SELECT RAISE(ABORT, 'published VFS catalog artifact requires its exact revision');
END;

CREATE TRIGGER require_unreachable_vfs_catalog_orphan
BEFORE UPDATE OF state ON vfs_catalog_checkpoint_artifacts
WHEN NEW.state = 'orphaned'
  AND (
      EXISTS (
          SELECT 1 FROM vfs_catalog_heads
          WHERE revision_id = NEW.revision_id
      )
      OR EXISTS (
          SELECT 1
          FROM vfs_catalog_mutation_heads AS head
          JOIN vfs_catalog_revisions AS revision
            ON revision.id = NEW.revision_id
           AND head.filesystem_id = revision.filesystem_id
           AND head.revision_id = revision.id
      )
  )
BEGIN
  SELECT RAISE(ABORT, 'reachable VFS catalog artifact cannot become orphaned');
END;

CREATE INDEX idx_vfs_catalog_checkpoint_artifacts_cleanup
ON vfs_catalog_checkpoint_artifacts(state, updated_at, revision_id)
WHERE state IN ('writing', 'orphaned');

CREATE INDEX idx_vfs_catalog_revisions_pending_filesystem
ON vfs_catalog_revisions(filesystem_id, id)
WHERE state = 'pending';

-- Pending historical revisions may be collapsed into a later verified full
-- checkpoint. They remain durable mutation evidence but never claim to own an
-- R2 object that was not produced from their exact historical rows.
CREATE TABLE vfs_catalog_revision_collapses (
    revision_id INTEGER PRIMARY KEY REFERENCES vfs_catalog_revisions(id) ON DELETE CASCADE,
    superseded_by_revision_id INTEGER NOT NULL REFERENCES vfs_catalog_revisions(id),
    collapsed_at INTEGER NOT NULL CHECK (collapsed_at > 0),
    CHECK (superseded_by_revision_id > revision_id)
) STRICT;

CREATE INDEX idx_vfs_catalog_revision_collapses_checkpoint
ON vfs_catalog_revision_collapses(superseded_by_revision_id, revision_id);

CREATE TRIGGER validate_vfs_catalog_revision_collapse
BEFORE INSERT ON vfs_catalog_revision_collapses
WHEN NOT EXISTS (
    SELECT 1
    FROM vfs_catalog_revisions AS old
    JOIN vfs_catalog_revisions AS newer
      ON newer.id = NEW.superseded_by_revision_id
     AND newer.filesystem_id = old.filesystem_id
    WHERE old.id = NEW.revision_id
      AND old.state = 'pending'
      AND newer.state = 'published'
)
BEGIN
  SELECT RAISE(ABORT, 'VFS catalog collapse requires a newer published checkpoint');
END;

CREATE TRIGGER protect_vfs_catalog_revision_collapse
BEFORE UPDATE ON vfs_catalog_revision_collapses
BEGIN
  SELECT RAISE(ABORT, 'VFS catalog revision collapse is immutable');
END;

CREATE TRIGGER require_vfs_catalog_outbox_resolution
BEFORE UPDATE OF state ON vfs_catalog_outbox
WHEN NEW.state = 'done'
  AND NOT EXISTS (
      SELECT 1
      FROM vfs_catalog_revisions AS revision
      JOIN vfs_catalog_heads AS head
        ON head.filesystem_id = revision.filesystem_id
       AND head.revision_id = revision.id
      WHERE revision.id = NEW.revision_id AND revision.state = 'published'
  )
  AND NOT EXISTS (
      SELECT 1 FROM vfs_catalog_revision_collapses
      WHERE revision_id = NEW.revision_id
  )
BEGIN
  SELECT RAISE(ABORT, 'VFS catalog outbox completion requires publication or collapse');
END;

CREATE TRIGGER require_published_vfs_catalog_head_insert
BEFORE INSERT ON vfs_catalog_heads
WHEN NOT EXISTS (
    SELECT 1
    FROM vfs_catalog_revisions AS revision
    JOIN vfs_catalog_checkpoint_artifacts AS artifact
      ON artifact.revision_id = revision.id
    WHERE revision.id = NEW.revision_id
      AND revision.filesystem_id = NEW.filesystem_id
      AND revision.root_data_root = NEW.root_data_root
      AND revision.state = 'published'
      AND artifact.r2_key = revision.checkpoint_r2_key
      AND artifact.sha256 = revision.checkpoint_sha256
      AND artifact.r2_version = revision.checkpoint_r2_version
      AND artifact.bytes = revision.checkpoint_bytes
      AND artifact.state = 'published'
)
BEGIN
  SELECT RAISE(ABORT, 'VFS catalog head requires a published revision');
END;

CREATE TRIGGER require_monotonic_published_vfs_catalog_head_update
BEFORE UPDATE ON vfs_catalog_heads
WHEN NEW.filesystem_id != OLD.filesystem_id
  OR NEW.revision_id <= OLD.revision_id
  OR NEW.revision != OLD.revision + 1
  OR NEW.updated_at < OLD.updated_at
  OR NOT EXISTS (
      SELECT 1
      FROM vfs_catalog_revisions AS revision
      JOIN vfs_catalog_checkpoint_artifacts AS artifact
        ON artifact.revision_id = revision.id
      WHERE revision.id = NEW.revision_id
        AND revision.filesystem_id = NEW.filesystem_id
        AND revision.root_data_root = NEW.root_data_root
        AND revision.state = 'published'
        AND artifact.r2_key = revision.checkpoint_r2_key
        AND artifact.sha256 = revision.checkpoint_sha256
        AND artifact.r2_version = revision.checkpoint_r2_version
        AND artifact.bytes = revision.checkpoint_bytes
        AND artifact.state = 'published'
  )
BEGIN
  SELECT RAISE(ABORT, 'VFS catalog head requires the next published revision');
END;
