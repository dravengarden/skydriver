-- Browser operator access uses one environment-scoped Worker secret rather
-- than a username account. D1 stores only opaque session verifiers so logout
-- and expiry revoke browser access without retaining the bearer cookie.

CREATE TABLE admin_sessions (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 64
        AND id = lower(id)
        AND id NOT GLOB '*[^0-9a-f]*'
    ),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT
) STRICT;

CREATE INDEX idx_admin_sessions_expires_at
ON admin_sessions(expires_at);
