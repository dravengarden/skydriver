PRAGMA foreign_keys = ON;

-- Operator resource pickers use bounded prefix pages ordered by their human
-- labels. Keep those reads independent from total token and directory count.
CREATE INDEX idx_vfs_token_metadata_picker
ON vfs_token_metadata(lower(label), token_id);

CREATE INDEX idx_vfs_directories_picker
ON vfs_directories(lower(name), id)
WHERE state = 'active';

PRAGMA optimize;
