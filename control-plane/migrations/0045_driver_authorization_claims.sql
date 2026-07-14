CREATE TABLE driver_authorization_claims (
    driver_id TEXT PRIMARY KEY,
    expected_driver_revision INTEGER NOT NULL,
    validation_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    fencing_token INTEGER NOT NULL DEFAULT 1,
    lease_expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (driver_id) REFERENCES driver_instances(id) ON DELETE CASCADE,
    CHECK (expected_driver_revision >= 1),
    CHECK (length(validation_digest) BETWEEN 16 AND 256),
    CHECK (length(idempotency_key) BETWEEN 1 AND 256),
    CHECK (fencing_token >= 1),
    CHECK (lease_expires_at > updated_at)
) STRICT;

CREATE INDEX idx_driver_authorization_claims_expired
ON driver_authorization_claims(lease_expires_at, driver_id);
