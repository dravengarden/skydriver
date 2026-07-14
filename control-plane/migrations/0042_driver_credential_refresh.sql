PRAGMA foreign_keys = ON;

-- Refresh authority is server-owned. The encrypted refresh token remains in
-- credential_envelopes; this table contains only non-secret scheduling and
-- fencing state.
CREATE TABLE driver_credential_refreshes (
    credential_id TEXT PRIMARY KEY
        REFERENCES credential_envelopes(id) ON DELETE CASCADE,
    driver_id TEXT NOT NULL UNIQUE
        REFERENCES driver_instances(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL CHECK (issuer IN ('openlist-online/v1')),
    observed_credential_revision INTEGER NOT NULL CHECK (observed_credential_revision > 0),
    state TEXT NOT NULL DEFAULT 'ready'
        CHECK (state IN ('ready', 'claimed', 'retry', 'reauth_required')),
    fencing_token INTEGER NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    lease_expires_at INTEGER,
    refresh_after INTEGER NOT NULL CHECK (refresh_after > 0),
    retry_at INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_code TEXT,
    last_succeeded_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK ((state = 'claimed') = (lease_expires_at IS NOT NULL)),
    CHECK ((state = 'retry') = (retry_at IS NOT NULL)),
    CHECK (state != 'reauth_required' OR last_error_code IS NOT NULL)
);

CREATE INDEX idx_driver_credential_refreshes_claimable
ON driver_credential_refreshes(state, refresh_after, retry_at, lease_expires_at, driver_id)
WHERE state IN ('ready', 'retry', 'claimed');

CREATE TRIGGER validate_driver_credential_refresh_insert
BEFORE INSERT ON driver_credential_refreshes
WHEN NOT EXISTS (
    SELECT 1
    FROM driver_instances AS driver
    JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
    WHERE driver.id = NEW.driver_id
      AND credential.id = NEW.credential_id
      AND credential.revision = NEW.observed_credential_revision
)
BEGIN
    SELECT RAISE(ABORT, 'credential refresh must reference the active credential revision');
END;
