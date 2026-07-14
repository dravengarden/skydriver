ALTER TABLE credential_envelopes
ADD COLUMN expires_at INTEGER
CHECK (expires_at IS NULL OR expires_at > 0);
