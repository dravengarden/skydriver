ALTER TABLE driver_credential_refreshes
ADD COLUMN refresh_token_expires_at INTEGER;

CREATE INDEX idx_driver_credential_refreshes_authority_expiry
ON driver_credential_refreshes(state, refresh_token_expires_at, driver_id)
WHERE state IN ('ready', 'retry', 'reauth_required');
