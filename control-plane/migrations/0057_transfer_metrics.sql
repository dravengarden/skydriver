PRAGMA foreign_keys = ON;

-- One compact row per active scope and UTC day. The primary key makes bounded
-- day retirement cheap; the single secondary index serves every UI history
-- query without multiplying write cost across individual metric columns.
CREATE TABLE vfs_transfer_daily_metrics (
    day INTEGER NOT NULL CHECK (day > 0 AND day % 86400 = 0),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('global', 'driver', 'token', 'directory')),
    scope_id TEXT NOT NULL,
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
    updated_at INTEGER NOT NULL CHECK (updated_at >= day),
    PRIMARY KEY (day, scope_kind, scope_id, direction)
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_vfs_transfer_metrics_scope_day
ON vfs_transfer_daily_metrics(scope_kind, scope_id, direction, day DESC);

-- Sampling receipts make retries idempotent. They are intentionally separate
-- from transfer correctness records and may be retired after the rollup window.
CREATE TABLE vfs_transfer_metric_receipts (
    operation_id TEXT PRIMARY KEY,
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
) STRICT;

CREATE INDEX idx_vfs_transfer_metric_receipts_retirement
ON vfs_transfer_metric_receipts(recorded_at, operation_id);

-- High-volume content access evidence has a bounded one-year lifecycle. Low-
-- volume security and configuration audit events remain durable.
CREATE INDEX idx_vfs_audit_transfer_retirement
ON vfs_audit_events(created_at, id)
WHERE event_kind IN ('download_planned', 'upload_committed');

PRAGMA optimize;
