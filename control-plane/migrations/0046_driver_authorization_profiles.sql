CREATE TABLE driver_authorizations (
    id TEXT PRIMARY KEY,
    driver_id TEXT NOT NULL
        REFERENCES driver_instances(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    state TEXT NOT NULL
        CHECK (state IN ('active', 'standby', 'retiring', 'reauth_required')),
    credential_id TEXT NOT NULL UNIQUE
        REFERENCES credential_envelopes(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    activated_at INTEGER,
    retired_at INTEGER,
    refresh_health TEXT NOT NULL DEFAULT 'unknown'
        CHECK (refresh_health IN ('healthy', 'retry', 'reauth_required', 'unknown')),
    last_succeeded_at INTEGER,
    refresh_token_expires_at INTEGER,
    last_error_code TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (driver_id, label),
    CHECK (state != 'active' OR activated_at IS NOT NULL),
    CHECK (state != 'retiring' OR retired_at IS NOT NULL)
) STRICT;

CREATE UNIQUE INDEX idx_driver_authorizations_one_active
ON driver_authorizations(driver_id)
WHERE state = 'active';

CREATE INDEX idx_driver_authorizations_driver_state
ON driver_authorizations(driver_id, state, updated_at DESC, id);

INSERT INTO driver_authorizations (
    id, driver_id, label, state, credential_id, activated_at,
    refresh_health, last_succeeded_at, refresh_token_expires_at, last_error_code,
    created_at, updated_at
)
SELECT lower(hex(randomblob(16))), driver.id, 'Imported authorization',
       CASE WHEN refresh.state IN ('ready', 'claimed', 'retry')
            THEN 'active' ELSE 'reauth_required' END,
       credential.id,
       CASE WHEN refresh.state IN ('ready', 'claimed', 'retry')
            THEN credential.rotated_at ELSE NULL END,
       CASE refresh.state WHEN 'ready' THEN 'healthy' WHEN 'claimed' THEN 'healthy'
            WHEN 'retry' THEN 'retry' WHEN 'reauth_required' THEN 'reauth_required'
            ELSE 'reauth_required' END,
       refresh.last_succeeded_at, refresh.refresh_token_expires_at,
       COALESCE(refresh.last_error_code,
                CASE WHEN refresh.credential_id IS NULL THEN 'refresh_token_missing' END),
       credential.created_at, credential.rotated_at
FROM driver_instances AS driver
JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
LEFT JOIN driver_credential_refreshes AS refresh
  ON refresh.credential_id = credential.id;
