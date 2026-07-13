PRAGMA foreign_keys = ON;

CREATE TRIGGER validate_driver_state_receipt
BEFORE INSERT ON management_mutation_receipts
WHEN NEW.kind = 'driver.state'
 AND NOT EXISTS (
    SELECT 1 FROM driver_instances
    WHERE id = NEW.resource_id
      AND revision = NEW.final_revision
      AND enabled = json_extract(NEW.result_json, '$.enabled')
 )
BEGIN
    SELECT RAISE(ABORT, 'driver state receipt requires committed driver state');
END;
