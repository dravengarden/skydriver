PRAGMA foreign_keys = ON;

-- A complete checkpoint remains the canonical independently verifiable
-- artifact. Deltas are optional, bounded accelerations linking one published
-- checkpoint body to a newer body through their exact SHA-256 receipts.
CREATE TABLE vfs_catalog_delta_artifacts (
    target_revision_id INTEGER PRIMARY KEY
        REFERENCES vfs_catalog_revisions(id) ON DELETE CASCADE,
    base_revision_id INTEGER NOT NULL REFERENCES vfs_catalog_revisions(id),
    base_root_data_root TEXT NOT NULL CHECK (
        length(base_root_data_root) = 64
        AND base_root_data_root NOT GLOB '*[^0-9a-f]*'
    ),
    base_checkpoint_sha256 TEXT NOT NULL CHECK (
        length(base_checkpoint_sha256) = 64
        AND base_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    checkpoint_sha256 TEXT NOT NULL CHECK (
        length(checkpoint_sha256) = 64
        AND checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    r2_key TEXT NOT NULL UNIQUE CHECK (
        length(CAST(r2_key AS BLOB)) BETWEEN 1 AND 4096
    ),
    sha256 TEXT NOT NULL CHECK (
        length(sha256) = 64
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bytes INTEGER NOT NULL CHECK (bytes BETWEEN 1 AND 8388608),
    r2_version TEXT CHECK (
        r2_version IS NULL
        OR length(CAST(r2_version AS BLOB)) BETWEEN 1 AND 1024
    ),
    state TEXT NOT NULL CHECK (
        state IN ('writing', 'staged', 'published', 'orphaned')
    ),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    CHECK ((state = 'writing') = (r2_version IS NULL)),
    CHECK (base_revision_id < target_revision_id)
) STRICT;

CREATE INDEX idx_vfs_catalog_delta_artifacts_cleanup
ON vfs_catalog_delta_artifacts(state, updated_at, target_revision_id)
WHERE state IN ('writing', 'orphaned');

CREATE INDEX idx_vfs_catalog_delta_artifacts_retirement
ON vfs_catalog_delta_artifacts(updated_at, target_revision_id)
WHERE state = 'published';

CREATE INDEX idx_vfs_catalog_checkpoint_artifacts_retirement
ON vfs_catalog_checkpoint_artifacts(updated_at, revision_id)
WHERE state = 'published';

CREATE TRIGGER validate_vfs_catalog_delta_artifact_insert
BEFORE INSERT ON vfs_catalog_delta_artifacts
WHEN NOT EXISTS (
    SELECT 1
    FROM vfs_catalog_revisions AS base
    JOIN vfs_catalog_revisions AS target
      ON target.id = NEW.target_revision_id
     AND target.filesystem_id = base.filesystem_id
    JOIN vfs_catalog_checkpoint_artifacts AS base_artifact
      ON base_artifact.revision_id = base.id
     AND base_artifact.sha256 = NEW.base_checkpoint_sha256
     AND base_artifact.state = 'published'
    JOIN vfs_catalog_checkpoint_artifacts AS target_artifact
      ON target_artifact.revision_id = target.id
     AND target_artifact.sha256 = NEW.checkpoint_sha256
     AND target_artifact.state = 'staged'
    WHERE base.id = NEW.base_revision_id
      AND base.state = 'published'
      AND base.root_data_root = NEW.base_root_data_root
      AND base.checkpoint_sha256 = NEW.base_checkpoint_sha256
      AND target.state = 'pending'
)
BEGIN
    SELECT RAISE(ABORT, 'VFS catalog delta requires exact base and target checkpoints');
END;

CREATE TRIGGER validate_vfs_catalog_delta_artifact_transition
BEFORE UPDATE OF state ON vfs_catalog_delta_artifacts
WHEN NOT (
    (OLD.state = 'writing' AND NEW.state = 'staged')
    OR (OLD.state = 'staged' AND NEW.state IN ('published', 'orphaned'))
    OR (OLD.state = 'published' AND NEW.state = 'orphaned')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid VFS catalog delta artifact transition');
END;

CREATE TRIGGER protect_vfs_catalog_delta_artifact_identity
BEFORE UPDATE OF
  target_revision_id, base_revision_id, base_root_data_root,
  base_checkpoint_sha256, checkpoint_sha256, r2_key, sha256, bytes, created_at
ON vfs_catalog_delta_artifacts
BEGIN
    SELECT RAISE(ABORT, 'VFS catalog delta artifact identity is immutable');
END;

CREATE TRIGGER require_published_vfs_catalog_delta
BEFORE UPDATE OF state ON vfs_catalog_delta_artifacts
WHEN NEW.state = 'published'
  AND NOT EXISTS (
      SELECT 1
      FROM vfs_catalog_revisions AS target
      JOIN vfs_catalog_checkpoint_artifacts AS target_artifact
        ON target_artifact.revision_id = target.id
       AND target_artifact.sha256 = NEW.checkpoint_sha256
       AND target_artifact.state = 'published'
      JOIN vfs_catalog_revisions AS base ON base.id = NEW.base_revision_id
      WHERE target.id = NEW.target_revision_id
        AND target.state = 'published'
        AND target.checkpoint_sha256 = NEW.checkpoint_sha256
        AND base.state = 'published'
        AND base.checkpoint_sha256 = NEW.base_checkpoint_sha256
        AND base.root_data_root = NEW.base_root_data_root
  )
BEGIN
    SELECT RAISE(ABORT, 'published VFS catalog delta requires exact published checkpoints');
END;

CREATE TRIGGER require_unreachable_vfs_catalog_delta_orphan
BEFORE UPDATE OF state ON vfs_catalog_delta_artifacts
WHEN NEW.state = 'orphaned'
  AND OLD.state = 'published'
  AND (
      EXISTS (
          SELECT 1 FROM vfs_catalog_heads
          WHERE revision_id = NEW.target_revision_id
      )
      OR EXISTS (
          SELECT 1
          FROM vfs_catalog_mutation_heads AS head
          JOIN vfs_catalog_revisions AS target
            ON target.id = NEW.target_revision_id
           AND head.filesystem_id = target.filesystem_id
           AND head.revision_id = target.id
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'reachable VFS catalog delta cannot become orphaned');
END;

-- Complete checkpoints are also acceleration objects after their head moves.
-- Let server maintenance retire them through the existing tracked orphan path
-- instead of accumulating one full R2 object per namespace mutation forever.
DROP TRIGGER validate_vfs_catalog_checkpoint_artifact_transition;

CREATE TRIGGER validate_vfs_catalog_checkpoint_artifact_transition
BEFORE UPDATE OF state ON vfs_catalog_checkpoint_artifacts
WHEN NOT (
    (OLD.state = 'writing' AND NEW.state = 'staged')
    OR (OLD.state = 'staged' AND NEW.state IN ('published', 'orphaned'))
    OR (OLD.state = 'published' AND NEW.state = 'orphaned')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid VFS catalog checkpoint artifact transition');
END;
