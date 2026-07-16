PRAGMA foreign_keys = ON;

-- A completed inventory generation resolves only evidence not observed in that
-- generation. Keep this convergence pass proportional to stale evidence rather
-- than every live object recorded for the driver.
CREATE INDEX vfs_provider_quarantine_by_driver_generation
ON vfs_provider_quarantine(driver_id, state, last_seen_generation, storage_key);
