PRAGMA foreign_keys = ON;

CREATE TRIGGER validate_driver_credential_receipt
BEFORE INSERT ON management_mutation_receipts
WHEN NEW.kind = 'driver.credential'
 AND NOT EXISTS (
    SELECT 1
    FROM driver_instances AS driver
    JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
    WHERE driver.id = NEW.resource_id
      AND driver.revision = NEW.final_revision
      AND credential.id = json_extract(NEW.result_json, '$.credential_id')
      AND credential.revision = json_extract(NEW.result_json, '$.credential_revision')
      AND credential.rotated_at = json_extract(NEW.result_json, '$.rotated_at')
 )
BEGIN
    SELECT RAISE(ABORT, 'driver credential receipt requires committed encrypted credential');
END;
