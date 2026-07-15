PRAGMA foreign_keys = ON;

-- The bounded operator Activity projection reads only live cleanup work. Keep
-- these partial indexes aligned with its exact state predicates so D1 never
-- scans completed lifecycle history to render the page.
CREATE INDEX idx_vfs_r2_cleanup_activity
ON vfs_r2_upload_cleanup_tasks(state, updated_at DESC, intent_id)
WHERE state IN ('active', 'cleaning', 'failed');

CREATE INDEX idx_driver_credential_refreshes_activity
ON driver_credential_refreshes(state, updated_at DESC, credential_id)
WHERE state IN ('claimed', 'retry', 'reauth_required');

-- Evidence retention is a separate bounded Cron path from live lease and
-- cleanup claims. Index its exact retirement timestamp instead of forcing a
-- history scan through COALESCE or completed terminal rows.
CREATE INDEX idx_vfs_read_leases_retirement
ON vfs_read_leases(COALESCE(completed_at, expires_at), id);

CREATE INDEX idx_vfs_r2_cleanup_evidence_retirement
ON vfs_r2_upload_cleanup_tasks(state, completed_at, intent_id)
WHERE state IN ('cleaned', 'superseded');

PRAGMA optimize;
