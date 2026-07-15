PRAGMA foreign_keys = ON;

-- Full-checkpoint delivery must prove that no active descendant cuts ACL
-- inheritance. Keep that request-time proof proportional to boundary count,
-- not the total number of directories in the filesystem.
CREATE INDEX idx_vfs_directories_active_acl_boundaries
ON vfs_directories(filesystem_id, id)
WHERE state = 'active' AND acl_inherits = 0;
