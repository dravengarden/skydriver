PRAGMA foreign_keys = ON;

-- Canonical sampled transfer facts retain the dimensions together. This is
-- required for exact intersections such as one token using one driver in one
-- directory; independently aggregated scope rows cannot recover that
-- correlation. Analytics are advisory and never participate in VFS state.
CREATE TABLE vfs_transfer_hourly_analytics (
    bucket INTEGER NOT NULL CHECK (bucket > 0 AND bucket % 3600 = 0),
    driver_id TEXT NOT NULL,
    token_id TEXT NOT NULL,
    directory_id TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('upload', 'download')),
    weighted_transfers INTEGER NOT NULL CHECK (weighted_transfers > 0),
    weighted_bytes INTEGER NOT NULL CHECK (weighted_bytes >= 0),
    weighted_provider_ms INTEGER NOT NULL CHECK (weighted_provider_ms > 0),
    weighted_total_ms INTEGER NOT NULL CHECK (weighted_total_ms > 0),
    weighted_retries INTEGER NOT NULL CHECK (weighted_retries >= 0),
    speed_b0 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b0 >= 0),
    speed_b1 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b1 >= 0),
    speed_b2 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b2 >= 0),
    speed_b3 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b3 >= 0),
    speed_b4 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b4 >= 0),
    speed_b5 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b5 >= 0),
    speed_b6 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b6 >= 0),
    speed_b7 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b7 >= 0),
    speed_b8 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b8 >= 0),
    speed_b9 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b9 >= 0),
    speed_b10 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b10 >= 0),
    speed_b11 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b11 >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= bucket),
    PRIMARY KEY (bucket, driver_id, token_id, directory_id, direction)
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_vfs_transfer_hourly_driver_bucket
ON vfs_transfer_hourly_analytics(driver_id, bucket DESC);

CREATE INDEX idx_vfs_transfer_hourly_token_bucket
ON vfs_transfer_hourly_analytics(token_id, bucket DESC);

CREATE INDEX idx_vfs_transfer_hourly_directory_bucket
ON vfs_transfer_hourly_analytics(directory_id, bucket DESC);

CREATE TABLE vfs_transfer_daily_analytics (
    bucket INTEGER NOT NULL CHECK (bucket > 0 AND bucket % 86400 = 0),
    driver_id TEXT NOT NULL,
    token_id TEXT NOT NULL,
    directory_id TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('upload', 'download')),
    weighted_transfers INTEGER NOT NULL CHECK (weighted_transfers > 0),
    weighted_bytes INTEGER NOT NULL CHECK (weighted_bytes >= 0),
    weighted_provider_ms INTEGER NOT NULL CHECK (weighted_provider_ms > 0),
    weighted_total_ms INTEGER NOT NULL CHECK (weighted_total_ms > 0),
    weighted_retries INTEGER NOT NULL CHECK (weighted_retries >= 0),
    speed_b0 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b0 >= 0),
    speed_b1 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b1 >= 0),
    speed_b2 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b2 >= 0),
    speed_b3 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b3 >= 0),
    speed_b4 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b4 >= 0),
    speed_b5 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b5 >= 0),
    speed_b6 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b6 >= 0),
    speed_b7 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b7 >= 0),
    speed_b8 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b8 >= 0),
    speed_b9 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b9 >= 0),
    speed_b10 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b10 >= 0),
    speed_b11 INTEGER NOT NULL DEFAULT 0 CHECK (speed_b11 >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= bucket),
    PRIMARY KEY (bucket, driver_id, token_id, directory_id, direction)
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_vfs_transfer_daily_driver_bucket
ON vfs_transfer_daily_analytics(driver_id, bucket DESC);

CREATE INDEX idx_vfs_transfer_daily_token_bucket
ON vfs_transfer_daily_analytics(token_id, bucket DESC);

CREATE INDEX idx_vfs_transfer_daily_directory_bucket
ON vfs_transfer_daily_analytics(directory_id, bucket DESC);

PRAGMA optimize;
