PRAGMA foreign_keys = ON;

CREATE TABLE management_creation_receipts (
    operation_id TEXT PRIMARY KEY,
    operator_subject TEXT NOT NULL,
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    final_revision INTEGER NOT NULL CHECK (final_revision = 1),
    validation_digest TEXT NOT NULL,
    result_json TEXT NOT NULL CHECK (json_valid(result_json)),
    committed_at INTEGER NOT NULL,
    UNIQUE (operator_subject, kind, idempotency_key)
) STRICT;

CREATE TRIGGER validate_driver_registration_receipt
BEFORE INSERT ON management_creation_receipts
WHEN NEW.kind = 'driver.register' AND NOT EXISTS (
    SELECT 1 FROM driver_instances
    WHERE id = NEW.resource_id
      AND revision = NEW.final_revision
      AND enabled = 0
      AND kind = json_extract(NEW.result_json, '$.kind')
      AND json(config_json) = json(json_extract(NEW.result_json, '$.config'))
 )
BEGIN
    SELECT RAISE(ABORT, 'driver registration receipt requires committed disabled driver');
END;
