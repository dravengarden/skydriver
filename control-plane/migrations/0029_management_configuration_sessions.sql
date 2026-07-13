PRAGMA foreign_keys = ON;

CREATE TABLE admin_configuration_sessions (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 64
        AND id NOT GLOB '*[^0-9a-f]*'
    ),
    admin_session_id TEXT NOT NULL REFERENCES admin_sessions(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    created_at INTEGER NOT NULL CHECK (created_at > 0)
) STRICT;

CREATE INDEX admin_configuration_sessions_by_admin
ON admin_configuration_sessions(admin_session_id, expires_at);
