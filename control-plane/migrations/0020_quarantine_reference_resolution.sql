PRAGMA foreign_keys = ON;

DROP TRIGGER supersede_quarantine_delete_after_identity_change;

CREATE TRIGGER supersede_quarantine_delete_after_identity_change
AFTER UPDATE OF state, driver_revision, provider_version, etag, size_bytes, delete_after
ON quarantined_provider_objects
WHEN NEW.state NOT IN ('tombstoned', 'deleted')
  OR EXISTS (
      SELECT 1 FROM quarantine_delete_tasks AS task
      WHERE task.driver_id = NEW.driver_id
        AND task.storage_key = NEW.storage_key
        AND task.state IN ('pending', 'claimed', 'failed')
        AND (
            task.driver_revision != NEW.driver_revision
            OR task.provider_version IS NOT NEW.provider_version
            OR task.etag IS NOT NEW.etag
            OR task.size_bytes != NEW.size_bytes
            OR task.delete_after IS NOT NEW.delete_after
        )
  )
BEGIN
    UPDATE quarantine_delete_tasks
    SET state = 'superseded', lease_expires_at = NULL,
        last_error_code = CASE
            WHEN NEW.state = 'resolved' THEN 'quarantine_became_referenced'
            ELSE 'quarantine_identity_changed'
        END,
        updated_at = unixepoch()
    WHERE driver_id = NEW.driver_id
      AND storage_key = NEW.storage_key
      AND state IN ('pending', 'claimed', 'failed');
END;

CREATE TRIGGER resolve_quarantine_finding_after_ledger_resolution
AFTER UPDATE OF state ON quarantined_provider_objects
WHEN NEW.state = 'resolved'
  AND OLD.state IN ('quarantined', 'acknowledged', 'tombstoned')
BEGIN
    INSERT INTO integrity_findings (
        id, namespace_id, subject_kind, subject_id, condition, state,
        evidence_json, first_observed_at, last_observed_at, acknowledged_at,
        resolved_at, revision
    )
    SELECT
        finding.id || '/resolved', finding.namespace_id, finding.subject_kind,
        finding.subject_id, finding.condition, 'resolved',
        json_set(
            finding.evidence_json,
            '$.resolution', 'provider_object_became_referenced',
            '$.resolved_at', unixepoch()
        ),
        finding.first_observed_at, unixepoch(), finding.acknowledged_at,
        unixepoch(), finding.revision + 1
    FROM integrity_findings AS finding
    WHERE finding.namespace_id = NEW.namespace_id
      AND finding.subject_kind = 'provider_object'
      AND finding.subject_id = json_array(NEW.driver_id, NEW.storage_key)
      AND finding.condition = 'quarantined'
      AND finding.state IN ('open', 'acknowledged', 'tombstoned')
    ON CONFLICT(subject_kind, subject_id, condition, state) DO UPDATE SET
        evidence_json = excluded.evidence_json,
        first_observed_at = MIN(
            integrity_findings.first_observed_at,
            excluded.first_observed_at
        ),
        last_observed_at = excluded.last_observed_at,
        acknowledged_at = COALESCE(
            excluded.acknowledged_at,
            integrity_findings.acknowledged_at
        ),
        resolved_at = excluded.resolved_at,
        revision = integrity_findings.revision + 1;

    DELETE FROM integrity_findings
    WHERE namespace_id = NEW.namespace_id
      AND subject_kind = 'provider_object'
      AND subject_id = json_array(NEW.driver_id, NEW.storage_key)
      AND condition = 'quarantined'
      AND state IN ('open', 'acknowledged', 'tombstoned');
END;

CREATE TRIGGER resolve_quarantine_after_location_insert
AFTER INSERT ON locations
WHEN NEW.state != 'deleted'
BEGIN
    INSERT OR IGNORE INTO audit_events (
        id, namespace_id, operation_id, client_id, event_kind, subject_kind,
        subject_id, details_json, created_at
    )
    SELECT
        'quarantine/reference/location/' || NEW.id || '/' || quarantine.revision,
        quarantine.namespace_id, NULL, NULL, 'quarantine_reference_resolved',
        'provider_object', json_array(quarantine.driver_id, quarantine.storage_key),
        json_object(
            'reference_kind', 'location',
            'reference_id', NEW.id,
            'reference_namespace_id', (
                SELECT pack.namespace_id
                FROM extents AS extent
                JOIN packs AS pack ON pack.id = extent.pack_id
                WHERE extent.id = NEW.extent_id
            ),
            'reference_state', NEW.state,
            'quarantine_revision', quarantine.revision,
            'result_revision', quarantine.revision + 1
        ),
        unixepoch()
    FROM quarantined_provider_objects AS quarantine
    WHERE quarantine.driver_id = NEW.driver_id
      AND quarantine.storage_key = NEW.storage_key
      AND quarantine.state IN ('quarantined', 'acknowledged', 'tombstoned');

    UPDATE quarantined_provider_objects
    SET state = 'resolved', last_observed_at = MAX(last_observed_at, unixepoch()),
        revision = revision + 1
    WHERE driver_id = NEW.driver_id
      AND storage_key = NEW.storage_key
      AND state IN ('quarantined', 'acknowledged', 'tombstoned');
END;

CREATE TRIGGER resolve_quarantine_after_location_update
AFTER UPDATE OF state, driver_id, storage_key ON locations
WHEN NEW.state != 'deleted'
BEGIN
    INSERT OR IGNORE INTO audit_events (
        id, namespace_id, operation_id, client_id, event_kind, subject_kind,
        subject_id, details_json, created_at
    )
    SELECT
        'quarantine/reference/location/' || NEW.id || '/' || quarantine.revision,
        quarantine.namespace_id, NULL, NULL, 'quarantine_reference_resolved',
        'provider_object', json_array(quarantine.driver_id, quarantine.storage_key),
        json_object(
            'reference_kind', 'location',
            'reference_id', NEW.id,
            'reference_namespace_id', (
                SELECT pack.namespace_id
                FROM extents AS extent
                JOIN packs AS pack ON pack.id = extent.pack_id
                WHERE extent.id = NEW.extent_id
            ),
            'reference_state', NEW.state,
            'quarantine_revision', quarantine.revision,
            'result_revision', quarantine.revision + 1
        ),
        unixepoch()
    FROM quarantined_provider_objects AS quarantine
    WHERE quarantine.driver_id = NEW.driver_id
      AND quarantine.storage_key = NEW.storage_key
      AND quarantine.state IN ('quarantined', 'acknowledged', 'tombstoned');

    UPDATE quarantined_provider_objects
    SET state = 'resolved', last_observed_at = MAX(last_observed_at, unixepoch()),
        revision = revision + 1
    WHERE driver_id = NEW.driver_id
      AND storage_key = NEW.storage_key
      AND state IN ('quarantined', 'acknowledged', 'tombstoned');
END;

CREATE TRIGGER resolve_quarantine_after_recovery_insert
AFTER INSERT ON recovery_manifests
WHEN NEW.state != 'missing'
BEGIN
    INSERT OR IGNORE INTO audit_events (
        id, namespace_id, operation_id, client_id, event_kind, subject_kind,
        subject_id, details_json, created_at
    )
    SELECT
        'quarantine/reference/recovery/' || NEW.manifest_sha256 || '/' || quarantine.revision,
        quarantine.namespace_id, NULL, NULL, 'quarantine_reference_resolved',
        'provider_object', json_array(quarantine.driver_id, quarantine.storage_key),
        json_object(
            'reference_kind', 'recovery_manifest',
            'reference_id', NEW.manifest_sha256,
            'reference_namespace_id', (
                SELECT object.namespace_id
                FROM object_versions AS version
                JOIN objects AS object ON object.id = version.object_id
                WHERE version.id = NEW.version_id
            ),
            'reference_state', NEW.state,
            'quarantine_revision', quarantine.revision,
            'result_revision', quarantine.revision + 1
        ),
        unixepoch()
    FROM quarantined_provider_objects AS quarantine
    WHERE quarantine.driver_id = NEW.sidecar_driver_id
      AND quarantine.storage_key = NEW.sidecar_storage_key
      AND quarantine.state IN ('quarantined', 'acknowledged', 'tombstoned');

    UPDATE quarantined_provider_objects
    SET state = 'resolved', last_observed_at = MAX(last_observed_at, unixepoch()),
        revision = revision + 1
    WHERE driver_id = NEW.sidecar_driver_id
      AND storage_key = NEW.sidecar_storage_key
      AND state IN ('quarantined', 'acknowledged', 'tombstoned');
END;

CREATE TRIGGER resolve_quarantine_after_recovery_update
AFTER UPDATE OF state, sidecar_driver_id, sidecar_storage_key ON recovery_manifests
WHEN NEW.state != 'missing'
BEGIN
    INSERT OR IGNORE INTO audit_events (
        id, namespace_id, operation_id, client_id, event_kind, subject_kind,
        subject_id, details_json, created_at
    )
    SELECT
        'quarantine/reference/recovery/' || NEW.manifest_sha256 || '/' || quarantine.revision,
        quarantine.namespace_id, NULL, NULL, 'quarantine_reference_resolved',
        'provider_object', json_array(quarantine.driver_id, quarantine.storage_key),
        json_object(
            'reference_kind', 'recovery_manifest',
            'reference_id', NEW.manifest_sha256,
            'reference_namespace_id', (
                SELECT object.namespace_id
                FROM object_versions AS version
                JOIN objects AS object ON object.id = version.object_id
                WHERE version.id = NEW.version_id
            ),
            'reference_state', NEW.state,
            'quarantine_revision', quarantine.revision,
            'result_revision', quarantine.revision + 1
        ),
        unixepoch()
    FROM quarantined_provider_objects AS quarantine
    WHERE quarantine.driver_id = NEW.sidecar_driver_id
      AND quarantine.storage_key = NEW.sidecar_storage_key
      AND quarantine.state IN ('quarantined', 'acknowledged', 'tombstoned');

    UPDATE quarantined_provider_objects
    SET state = 'resolved', last_observed_at = MAX(last_observed_at, unixepoch()),
        revision = revision + 1
    WHERE driver_id = NEW.sidecar_driver_id
      AND storage_key = NEW.sidecar_storage_key
      AND state IN ('quarantined', 'acknowledged', 'tombstoned');
END;
