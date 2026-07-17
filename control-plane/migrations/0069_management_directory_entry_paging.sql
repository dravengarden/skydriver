PRAGMA foreign_keys = ON;

-- Files browser pages are ordered with directories first and then by canonical
-- entry name. This covering prefix keeps keyset pagination bounded inside one
-- directory without adding indexes for presentation-only columns.
CREATE INDEX idx_vfs_directory_entries_management_page
ON vfs_directory_entries(directory_id, kind, name);

PRAGMA optimize;
