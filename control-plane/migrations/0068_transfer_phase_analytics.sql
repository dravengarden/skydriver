PRAGMA foreign_keys = ON;

-- Phase timing is folded into the existing sampled rollup rows. The coverage
-- counter prevents legacy v1 observations from being interpreted as zero-cost
-- phases, and no additional index is needed because query dimensions are
-- unchanged.
ALTER TABLE vfs_transfer_hourly_analytics
ADD COLUMN weighted_phase_transfers INTEGER NOT NULL DEFAULT 0
CHECK (weighted_phase_transfers >= 0);
ALTER TABLE vfs_transfer_hourly_analytics
ADD COLUMN weighted_plan_ms INTEGER NOT NULL DEFAULT 0 CHECK (weighted_plan_ms >= 0);
ALTER TABLE vfs_transfer_hourly_analytics
ADD COLUMN weighted_queue_ms INTEGER NOT NULL DEFAULT 0 CHECK (weighted_queue_ms >= 0);
ALTER TABLE vfs_transfer_hourly_analytics
ADD COLUMN weighted_phase_provider_ms INTEGER NOT NULL DEFAULT 0
CHECK (weighted_phase_provider_ms >= 0);
ALTER TABLE vfs_transfer_hourly_analytics
ADD COLUMN weighted_post_provider_ms INTEGER NOT NULL DEFAULT 0
CHECK (weighted_post_provider_ms >= 0);

ALTER TABLE vfs_transfer_daily_analytics
ADD COLUMN weighted_phase_transfers INTEGER NOT NULL DEFAULT 0
CHECK (weighted_phase_transfers >= 0);
ALTER TABLE vfs_transfer_daily_analytics
ADD COLUMN weighted_plan_ms INTEGER NOT NULL DEFAULT 0 CHECK (weighted_plan_ms >= 0);
ALTER TABLE vfs_transfer_daily_analytics
ADD COLUMN weighted_queue_ms INTEGER NOT NULL DEFAULT 0 CHECK (weighted_queue_ms >= 0);
ALTER TABLE vfs_transfer_daily_analytics
ADD COLUMN weighted_phase_provider_ms INTEGER NOT NULL DEFAULT 0
CHECK (weighted_phase_provider_ms >= 0);
ALTER TABLE vfs_transfer_daily_analytics
ADD COLUMN weighted_post_provider_ms INTEGER NOT NULL DEFAULT 0
CHECK (weighted_post_provider_ms >= 0);

PRAGMA optimize;
