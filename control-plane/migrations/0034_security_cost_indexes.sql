PRAGMA foreign_keys = ON;

-- Reverse foreign-key and lifecycle indexes for the VFS read and maintenance
-- paths. Each index corresponds to a bounded production query; no speculative
-- single-column indexes are created.
CREATE INDEX idx_vfs_directories_active_parent
ON vfs_directories(parent_id, id)
WHERE parent_id IS NOT NULL AND state = 'active';

CREATE INDEX idx_vfs_files_active_filesystem
ON vfs_files(filesystem_id, current_version_id)
WHERE state = 'active';

CREATE INDEX idx_vfs_locations_version_state_driver
ON vfs_locations(version_id, state, driver_id);

CREATE INDEX idx_vfs_locations_driver_state_version
ON vfs_locations(driver_id, state, version_id, size_bytes);

CREATE INDEX idx_vfs_directory_drivers_active_driver
ON vfs_directory_drivers(driver_id, directory_id)
WHERE state = 'active';

CREATE INDEX idx_vfs_audit_events_token_time
ON vfs_audit_events(token_id, created_at DESC)
WHERE token_id IS NOT NULL;

CREATE INDEX idx_vfs_token_verifiers_created
ON vfs_token_verifiers(created_at DESC, id);

CREATE INDEX idx_admin_configuration_sessions_expires_at
ON admin_configuration_sessions(expires_at);

CREATE INDEX idx_vfs_catalog_outbox_claimable
ON vfs_catalog_outbox(state, lease_expires_at, updated_at)
WHERE state != 'done';

CREATE INDEX idx_vfs_snapshots_expiry
ON vfs_snapshots(expires_at)
WHERE state = 'retained' AND expires_at IS NOT NULL;
