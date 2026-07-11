CREATE TABLE admin_users (
    username TEXT PRIMARY KEY CHECK (
        length(username) BETWEEN 1 AND 128
    ),
    password_hash TEXT NOT NULL CHECK (
        password_hash LIKE '$argon2id$%'
    ),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (
        enabled IN (0, 1)
    ),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
