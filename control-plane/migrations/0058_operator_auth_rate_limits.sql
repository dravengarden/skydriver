PRAGMA foreign_keys = ON;

-- Authentication throttles are small, bounded security state. Subjects are
-- keyed HMAC digests, so D1 never retains a source IP or submitted account.
CREATE TABLE operator_auth_rate_limits (
    scope TEXT NOT NULL CHECK (scope IN ('login_ip', 'login_account', 'configuration_ip')),
    subject TEXT NOT NULL CHECK (
        length(subject) = 64
        AND subject = lower(subject)
        AND subject NOT GLOB '*[^0-9a-f]*'
    ),
    window_started_at INTEGER NOT NULL CHECK (window_started_at > 0),
    attempts INTEGER NOT NULL CHECK (attempts > 0),
    blocked_until INTEGER NOT NULL CHECK (blocked_until >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= window_started_at),
    PRIMARY KEY (scope, subject)
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_operator_auth_rate_limits_retirement
ON operator_auth_rate_limits(updated_at, scope, subject);

PRAGMA optimize;
