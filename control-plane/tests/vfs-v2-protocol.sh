#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state_directory=$(mktemp -d)

cleanup() {
  rm -rf "$state_directory"
}
trap cleanup EXIT

wrangler=(
  pnpm exec wrangler d1
  --config "$repository_root/control-plane/wrangler.jsonc"
)

"${wrangler[@]}" migrations apply CARRACK_INDEX \
  --local \
  --persist-to "$state_directory" >/dev/null

execute() {
  "${wrangler[@]}" execute CARRACK_INDEX \
    --local \
    --persist-to "$state_directory" \
    --command "$1" >/dev/null
}

expect_failure() {
  local sql=$1
  local description=$2

  if execute "$sql" 2>/dev/null; then
    echo "expected VFS V2 D1 rejection: $description" >&2
    exit 1
  fi
}

filesystem_a=10000000000000000000000000000001
filesystem_b=10000000000000000000000000000002
principal_active=20000000000000000000000000000001
principal_disabled=20000000000000000000000000000002
root_a=30000000000000000000000000000001
child_a=30000000000000000000000000000002
grandchild_a=30000000000000000000000000000003
root_b=30000000000000000000000000000011
group_a=40000000000000000000000000000001
group_b=40000000000000000000000000000002
grant_a=50000000000000000000000000000001
file_a=60000000000000000000000000000001
version_a=70000000000000000000000000000001
version_b=70000000000000000000000000000002
location_a=80000000000000000000000000000001
location_b=80000000000000000000000000000002
snapshot_a=a0000000000000000000000000000001
parent_token=90000000000000000000000000000001
child_token=90000000000000000000000000000002

execute "
CREATE TABLE vfs_v2_protocol_assertions (
  accepted INTEGER NOT NULL CHECK (accepted = 1)
) STRICT;

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 12 FROM vfs_actions;

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 25 FROM sqlite_schema
WHERE type = 'index' AND name IN (
  'idx_vfs_directories_active_parent',
  'idx_vfs_directories_active_acl_boundaries',
  'idx_vfs_files_active_filesystem',
  'idx_vfs_locations_version_state_driver',
  'idx_vfs_locations_driver_state_version',
  'idx_vfs_directory_drivers_active_driver',
  'idx_vfs_audit_events_token_time',
  'idx_vfs_token_verifiers_created',
  'idx_admin_configuration_sessions_expires_at',
  'idx_vfs_catalog_outbox_claimable',
  'idx_vfs_catalog_checkpoint_artifacts_cleanup',
  'idx_vfs_catalog_revisions_pending_filesystem',
  'idx_vfs_catalog_revision_collapses_checkpoint',
  'idx_vfs_snapshots_expiry',
  'idx_vfs_snapshot_versions_version',
  'idx_vfs_token_verifiers_snapshot_expiry',
  'idx_vfs_channels_snapshot',
  'idx_vfs_files_current_version',
  'idx_vfs_directory_entries_file_version',
  'idx_vfs_versions_published_at',
  'idx_vfs_version_origins_directory',
  'idx_vfs_r2_cleanup_activity',
  'idx_driver_credential_refreshes_activity',
  'idx_vfs_read_leases_retirement',
  'idx_vfs_r2_cleanup_evidence_retirement'
);

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 1 FROM sqlite_schema
WHERE type = 'table' AND name = 'vfs_put_upload_evidence';

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 3 FROM sqlite_schema
WHERE type = 'trigger' AND name IN (
  'validate_vfs_put_upload_evidence_insert',
  'protect_vfs_put_upload_evidence',
  'require_vfs_put_receipt_upload_evidence'
);

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 1 FROM sqlite_schema
WHERE type = 'view' AND name = 'safe_vfs_put_delete_tasks';

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 1 FROM pragma_table_info('vfs_put_delete_tasks')
WHERE name = 'revalidated_at' AND type = 'INTEGER';

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 1 FROM sqlite_schema
WHERE type = 'trigger' AND name = 'validate_vfs_put_delete_revalidation';

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 3 FROM sqlite_schema
WHERE type = 'view' AND name IN (
  'vfs_gc_blocked_filesystems',
  'vfs_reachable_versions',
  'safe_unreachable_vfs_locations'
);

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 3 FROM sqlite_schema
WHERE type = 'trigger' AND name IN (
  'protect_vfs_location_delete_task_identity',
  'validate_vfs_location_delete_task_transition',
  'validate_completed_vfs_location_delete_task'
);

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 3 FROM sqlite_schema
WHERE type = 'trigger' AND name IN (
  'validate_vfs_version_origin_insert',
  'protect_vfs_version_origin_update',
  'require_vfs_version_origin_for_publication'
);

INSERT INTO credential_envelopes (
  id, envelope_algorithm, key_version, nonce, ciphertext, created_at, rotated_at
) VALUES ('vfs-credential', 'test/v1', '1', X'01', X'02', 1, 1);

INSERT INTO driver_instances (
  id, kind, config_json, credential_ref, created_at, updated_at
) VALUES
  ('vfs-driver-1', 'localfs/v2', '{}', 'vfs-credential', 1, 1),
  ('vfs-driver-2', 's3/v2', '{}', 'vfs-credential', 1, 1);

INSERT INTO vfs_filesystems (id, name, created_at, updated_at) VALUES
  ('$filesystem_a', 'primary', 1, 1),
  ('$filesystem_b', 'secondary', 1, 1);

INSERT INTO vfs_principals (
  id, kind, display_name, state, created_at, updated_at
) VALUES
  ('$principal_active', 'service', 'VFS test client', 'active', 1, 1),
  ('$principal_disabled', 'service', 'Disabled client', 'disabled', 1, 1);

INSERT INTO vfs_directories (
  id, filesystem_id, parent_id, name, data_root, crypto_suite,
  active_key_epoch, acl_inherits, created_at, updated_at
) VALUES
  (
    '$root_a', '$filesystem_a', NULL, '',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'plaintext/v1', 1, 0, 1, 1
  ),
  (
    '$child_a', '$filesystem_a', '$root_a', 'src',
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'plaintext/v1', 1, 1, 1, 1
  ),
  (
    '$grandchild_a', '$filesystem_a', '$child_a', 'nested',
    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'plaintext/v1', 1, 1, 1, 1
  ),
  (
    '$root_b', '$filesystem_b', NULL, '',
    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'plaintext/v1', 1, 0, 1, 1
  );

INSERT INTO vfs_groups (id, filesystem_id, name, created_at, updated_at) VALUES
  ('$group_a', '$filesystem_a', 'readers', 1, 1),
  ('$group_b', '$filesystem_b', 'other readers', 1, 1);

INSERT INTO vfs_group_members (group_id, principal_id, created_at)
VALUES ('$group_a', '$principal_active', 1);

INSERT INTO vfs_acl_grants (
  id, directory_id, group_id, action, source_role, created_by, created_at
) VALUES (
  '$grant_a', '$root_a', '$group_a', 'content.read', 'viewer',
  '$principal_active', 2
);

INSERT INTO vfs_v2_protocol_assertions
SELECT acl_revision = 2 FROM vfs_directories WHERE id = '$root_a';
"

expect_failure \
  "INSERT INTO vfs_directories (
     id, filesystem_id, parent_id, name, data_root, crypto_suite,
     active_key_epoch, acl_inherits, created_at, updated_at
   ) VALUES (
     '30000000000000000000000000000004', '$filesystem_a',
     '30000000000000000000000000000004', 'cycle',
     'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
     'plaintext/v1', 1, 1, 2, 2
   );" \
  "self-parent directory"

expect_failure \
  "UPDATE vfs_directories
   SET parent_id = '$grandchild_a', revision = revision + 1, updated_at = 2
   WHERE id = '$child_a';" \
  "directory ancestry cycle"

expect_failure \
  "INSERT INTO vfs_acl_grants (
     id, directory_id, action, created_by, created_at
   ) VALUES (
     '50000000000000000000000000000002', '$root_a', 'directory.list',
     '$principal_active', 2
   );" \
  "ACL grant without exactly one subject"

expect_failure \
  "INSERT INTO vfs_acl_grants (
     id, directory_id, principal_id, group_id, action, created_by, created_at
   ) VALUES (
     '50000000000000000000000000000003', '$root_a', '$principal_active',
     '$group_a', 'directory.list', '$principal_active', 2
   );" \
  "ACL grant with two subjects"

expect_failure \
  "INSERT INTO vfs_acl_grants (
     id, directory_id, group_id, action, created_by, created_at
   ) VALUES (
     '50000000000000000000000000000004', '$root_a', '$group_b',
     'directory.list', '$principal_active', 2
   );" \
  "ACL group from another filesystem"

expect_failure \
  "UPDATE vfs_acl_grants SET action = 'directory.list' WHERE id = '$grant_a';" \
  "in-place ACL mutation without revision bump"

execute "
INSERT INTO vfs_files (id, filesystem_id, created_at, updated_at)
VALUES ('$file_a', '$filesystem_a', 3, 3);

INSERT INTO vfs_file_versions (
  id, file_id, plaintext_bytes, verification_block_bytes,
  verification_block_count, file_root, block_manifest_sha256,
  block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
  crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes,
  encoded_sha256, created_at
) VALUES (
  '$version_a', '$file_a', 10, 4, 3,
  '1111111111111111111111111111111111111111111111111111111111111111',
  '2222222222222222222222222222222222222222222222222222222222222222',
  128, 'vfs/manifests/22', 'r2-version-22', 'plaintext/v1', 1, 4, 10,
  '3333333333333333333333333333333333333333333333333333333333333333',
  3
);
"

expect_failure \
  "INSERT INTO vfs_files (
     id, filesystem_id, current_version_id, created_at, updated_at
   ) VALUES (
     '60000000000000000000000000000002', '$filesystem_a', '$version_a', 3, 3
   );" \
  "file created with a current-version pointer"

expect_failure \
  "INSERT INTO vfs_file_versions (
     id, file_id, plaintext_bytes, verification_block_bytes,
     verification_block_count, file_root, block_manifest_sha256,
     block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
     crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes,
     encoded_sha256, state, published_at, created_at
   ) VALUES (
     '70000000000000000000000000000002', '$file_a', 0, 4, 0,
     '4444444444444444444444444444444444444444444444444444444444444444',
     '5555555555555555555555555555555555555555555555555555555555555555',
     64, 'vfs/manifests/55', 'r2-version-55', 'plaintext/v1', 1, 4, 0,
     '6666666666666666666666666666666666666666666666666666666666666666',
     'published', 4, 4
   );" \
  "file version inserted directly as published"

expect_failure \
  "INSERT INTO vfs_locations (
     id, version_id, driver_id, storage_key, size_bytes, object_sha256,
     created_at, updated_at
   ) VALUES (
     '$location_a', '$version_a', 'vfs-driver-1', 'objects/wrong-size', 9,
     '3333333333333333333333333333333333333333333333333333333333333333',
     4, 4
   );" \
  "location that is not the complete encoded object"

expect_failure \
  "INSERT INTO vfs_locations (
     id, version_id, driver_id, storage_key, size_bytes, object_sha256,
     state, verified_at, created_at, updated_at
   ) VALUES (
     '$location_a', '$version_a', 'vfs-driver-1', 'objects/preverified', 10,
     '3333333333333333333333333333333333333333333333333333333333333333',
     'verified', 4, 4, 4
   );" \
  "location inserted after bypassing staging"

execute "
INSERT INTO vfs_locations (
  id, version_id, driver_id, storage_key, size_bytes, object_sha256,
  created_at, updated_at
) VALUES (
  '$location_a', '$version_a', 'vfs-driver-1', 'objects/v2/00/object-a', 10,
  '3333333333333333333333333333333333333333333333333333333333333333',
  4, 4
);

INSERT INTO vfs_version_origins (version_id, directory_id, created_at)
VALUES ('$version_a', '$child_a', 4);

UPDATE vfs_file_versions SET state = 'verified' WHERE id = '$version_a';
"

expect_failure \
  "UPDATE vfs_file_versions
   SET state = 'published', published_at = 5
   WHERE id = '$version_a';" \
  "publication without an available complete location"

expect_failure \
  "UPDATE vfs_locations
   SET size_bytes = 9
   WHERE id = '$location_a';" \
  "staging location identity changed away from its version"

execute "
UPDATE vfs_locations
SET state = 'verified', verified_at = 5, revision = revision + 1, updated_at = 5
WHERE id = '$location_a';
UPDATE vfs_locations
SET state = 'available', revision = revision + 1, updated_at = 6
WHERE id = '$location_a';
UPDATE vfs_file_versions
SET state = 'published', published_at = 6
WHERE id = '$version_a';
UPDATE vfs_files
SET current_version_id = '$version_a', updated_at = 6
WHERE id = '$file_a';
"

expect_failure \
  "UPDATE vfs_file_versions SET plaintext_bytes = 9 WHERE id = '$version_a';" \
  "immutable file-version identity mutation"

expect_failure \
  "DELETE FROM vfs_file_versions WHERE id = '$version_a';" \
  "deletion of a current file version"

expect_failure \
  "INSERT INTO vfs_directory_entries (
     directory_id, name, kind, file_id, version_id, size_bytes,
     data_root, metadata_root, created_at, updated_at
   ) VALUES (
     '$child_a', 'asset.bin', 'file', '$file_a', '$version_a', 9,
     '1111111111111111111111111111111111111111111111111111111111111111',
     '7777777777777777777777777777777777777777777777777777777777777777',
     7, 7
   );" \
  "file entry whose size does not match its pinned version"

execute "
INSERT INTO vfs_directory_entries (
  directory_id, name, kind, file_id, version_id, size_bytes,
  data_root, metadata_root, created_at, updated_at
) VALUES (
  '$child_a', 'asset.bin', 'file', '$file_a', '$version_a', 10,
  '1111111111111111111111111111111111111111111111111111111111111111',
  '7777777777777777777777777777777777777777777777777777777777777777',
  7, 7
);

INSERT INTO vfs_directory_entries (
  directory_id, name, kind, child_directory_id, size_bytes,
  data_root, created_at, updated_at
) VALUES
  (
    '$root_a', 'src', 'directory', '$child_a', 0,
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    7, 7
  ),
  (
    '$child_a', 'nested', 'directory', '$grandchild_a', 0,
    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    7, 7
  );
"

expect_failure \
  "UPDATE vfs_directory_entries
   SET size_bytes = 9, revision = revision + 1, updated_at = 8
   WHERE directory_id = '$child_a' AND name = 'asset.bin';" \
  "file entry update that no longer matches its version"

expect_failure \
  "UPDATE vfs_directory_entries
   SET data_root = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
       revision = revision + 1,
       updated_at = 8
   WHERE directory_id = '$root_a' AND name = 'src';" \
  "directory entry update that no longer matches its child"

execute "
INSERT INTO vfs_token_verifiers (
  id, principal_id, root_directory_id, verifier_sha256, expires_at,
  issued_by, created_at
) VALUES (
  '$parent_token', '$principal_active', '$child_a',
  '8111111111111111111111111111111111111111111111111111111111111111',
  1000, '$principal_active', 10
);
INSERT INTO vfs_token_actions (token_id, action) VALUES
  ('$parent_token', 'content.read'),
  ('$parent_token', 'driver.use');
INSERT INTO vfs_token_drivers (token_id, driver_id)
VALUES ('$parent_token', 'vfs-driver-1');
UPDATE vfs_token_verifiers SET sealed_at = 20 WHERE id = '$parent_token';

INSERT INTO vfs_token_verifiers (
  id, principal_id, root_directory_id, parent_token_id, verifier_sha256,
  expires_at, issued_by, created_at
) VALUES (
  '$child_token', '$principal_active', '$grandchild_a', '$parent_token',
  '8222222222222222222222222222222222222222222222222222222222222222',
  900, '$principal_active', 21
);
INSERT INTO vfs_token_actions (token_id, action)
VALUES ('$child_token', 'content.read');
INSERT INTO vfs_token_drivers (token_id, driver_id)
VALUES ('$child_token', 'vfs-driver-1');
UPDATE vfs_token_verifiers SET sealed_at = 22 WHERE id = '$child_token';
"

expect_failure \
  "UPDATE vfs_token_actions
   SET action = 'directory.list'
   WHERE token_id = '$child_token' AND action = 'content.read';" \
  "UPDATE of a sealed token action"

expect_failure \
  "UPDATE vfs_token_drivers
   SET driver_id = 'vfs-driver-2'
   WHERE token_id = '$child_token' AND driver_id = 'vfs-driver-1';" \
  "UPDATE of a sealed token driver allowlist"

expect_failure \
  "UPDATE vfs_token_verifiers SET expires_at = 899 WHERE id = '$child_token';" \
  "UPDATE of sealed token scope"

execute "
INSERT INTO vfs_token_verifiers (
  id, principal_id, root_directory_id, parent_token_id, verifier_sha256,
  expires_at, issued_by, created_at
) VALUES (
  '90000000000000000000000000000003', '$principal_active', '$grandchild_a',
  '$parent_token',
  '8333333333333333333333333333333333333333333333333333333333333333',
  900, '$principal_active', 21
);
INSERT INTO vfs_token_actions (token_id, action)
VALUES ('90000000000000000000000000000003', 'content.write');
"

expect_failure \
  "UPDATE vfs_token_verifiers
   SET sealed_at = 23
   WHERE id = '90000000000000000000000000000003';" \
  "child token action wider than parent"

execute "
INSERT INTO vfs_token_verifiers (
  id, principal_id, root_directory_id, parent_token_id, verifier_sha256,
  expires_at, issued_by, created_at
) VALUES (
  '90000000000000000000000000000004', '$principal_active', '$grandchild_a',
  '$parent_token',
  '8444444444444444444444444444444444444444444444444444444444444444',
  900, '$principal_active', 21
);
INSERT INTO vfs_token_actions (token_id, action)
VALUES ('90000000000000000000000000000004', 'content.read');
INSERT INTO vfs_token_drivers (token_id, driver_id)
VALUES ('90000000000000000000000000000004', 'vfs-driver-2');
"

expect_failure \
  "UPDATE vfs_token_verifiers
   SET sealed_at = 23
   WHERE id = '90000000000000000000000000000004';" \
  "child token driver allowlist wider than parent"

execute "
INSERT INTO vfs_token_verifiers (
  id, principal_id, root_directory_id, parent_token_id, verifier_sha256,
  expires_at, issued_by, created_at
) VALUES (
  '90000000000000000000000000000005', '$principal_active', '$root_a',
  '$parent_token',
  '8555555555555555555555555555555555555555555555555555555555555555',
  900, '$principal_active', 21
);
INSERT INTO vfs_token_actions (token_id, action)
VALUES ('90000000000000000000000000000005', 'content.read');
INSERT INTO vfs_token_drivers (token_id, driver_id)
VALUES ('90000000000000000000000000000005', 'vfs-driver-1');
"

expect_failure \
  "UPDATE vfs_token_verifiers
   SET sealed_at = 23
   WHERE id = '90000000000000000000000000000005';" \
  "child token subtree wider than parent"

execute "
INSERT INTO vfs_token_verifiers (
  id, principal_id, root_directory_id, parent_token_id, verifier_sha256,
  expires_at, issued_by, created_at
) VALUES (
  '90000000000000000000000000000006', '$principal_active', '$grandchild_a',
  '$parent_token',
  '8666666666666666666666666666666666666666666666666666666666666666',
  1001, '$principal_active', 21
);
INSERT INTO vfs_token_actions (token_id, action)
VALUES ('90000000000000000000000000000006', 'content.read');
"

expect_failure \
  "UPDATE vfs_token_verifiers
   SET sealed_at = 23
   WHERE id = '90000000000000000000000000000006';" \
  "child token expiry later than parent"

execute "
INSERT INTO vfs_token_verifiers (
  id, principal_id, root_directory_id, verifier_sha256, expires_at,
  issued_by, created_at
) VALUES
  (
    '90000000000000000000000000000007', '$principal_active', '$root_a',
    '8777777777777777777777777777777777777777777777777777777777777777',
    100, '$principal_active', 10
  ),
  (
    '90000000000000000000000000000008', '$principal_disabled', '$root_a',
    '8888888888888888888888888888888888888888888888888888888888888888',
    100, '$principal_active', 10
  );
INSERT INTO vfs_token_actions (token_id, action)
VALUES ('90000000000000000000000000000008', 'content.read');
"

expect_failure \
  "UPDATE vfs_token_verifiers
   SET sealed_at = 20
   WHERE id = '90000000000000000000000000000007';" \
  "token without actions"

expect_failure \
  "UPDATE vfs_token_verifiers
   SET sealed_at = 20
   WHERE id = '90000000000000000000000000000008';" \
  "token for a disabled principal"

execute "
INSERT INTO vfs_file_versions (
  id, file_id, plaintext_bytes, verification_block_bytes,
  verification_block_count, file_root, block_manifest_sha256,
  block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
  crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes,
  encoded_sha256, created_at
) VALUES (
  '$version_b', '$file_a', 10, 4, 3,
  '9111111111111111111111111111111111111111111111111111111111111111',
  '9222222222222222222222222222222222222222222222222222222222222222',
  128, 'vfs/manifests/92', 'r2-version-92', 'plaintext/v1', 1, 4, 10,
  '9333333333333333333333333333333333333333333333333333333333333333',
  unixepoch()
);
INSERT INTO vfs_locations (
  id, version_id, driver_id, storage_key, native_id, provider_version, etag,
  size_bytes, object_sha256, created_at, updated_at
) VALUES (
  '$location_b', '$version_b', 'vfs-driver-1', 'objects/v2/00/object-b',
  'native-b', 'provider-b', 'etag-b', 10,
  '9333333333333333333333333333333333333333333333333333333333333333',
  unixepoch(), unixepoch()
);
INSERT INTO vfs_version_origins (version_id, directory_id, created_at)
VALUES ('$version_b', '$child_a', unixepoch());
UPDATE vfs_file_versions SET state = 'verified' WHERE id = '$version_b';
UPDATE vfs_locations
SET state = 'verified', verified_at = unixepoch(), revision = revision + 1,
    updated_at = unixepoch()
WHERE id = '$location_b';
UPDATE vfs_locations
SET state = 'available', revision = revision + 1, updated_at = unixepoch()
WHERE id = '$location_b';
UPDATE vfs_file_versions
SET state = 'published', published_at = unixepoch()
WHERE id = '$version_b';

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 1 FROM safe_unreachable_vfs_locations
WHERE id = '$location_b';

INSERT INTO vfs_catalog_revisions (
  filesystem_id, root_data_root, created_at
) VALUES (
  '$filesystem_a',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  unixepoch()
);
INSERT INTO vfs_snapshots (
  id, filesystem_id, directory_id, data_root, catalog_revision_id,
  manifest_r2_key, manifest_sha256, created_by, created_at
) VALUES (
  '$snapshot_a', '$filesystem_a', '$root_a',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  last_insert_rowid(), 'vfs/snapshots/a',
  '9444444444444444444444444444444444444444444444444444444444444444',
  '$principal_active', unixepoch()
);

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 1 FROM vfs_gc_blocked_filesystems
WHERE filesystem_id = '$filesystem_a';
INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 0 FROM safe_unreachable_vfs_locations
WHERE id = '$location_b';

INSERT INTO vfs_snapshot_versions (snapshot_id, version_id, created_at)
VALUES ('$snapshot_a', '$version_b', unixepoch());

INSERT INTO vfs_catalog_checkpoint_artifacts (
  revision_id, r2_key, sha256, bytes, state, created_at, updated_at
)
SELECT catalog_revision_id, 'vfs/catalog/checkpoints/test.json',
       '9666666666666666666666666666666666666666666666666666666666666666',
       128, 'writing', unixepoch(), unixepoch()
FROM vfs_snapshots WHERE id = '$snapshot_a';
INSERT INTO vfs_catalog_outbox (revision_id, updated_at)
SELECT catalog_revision_id, unixepoch()
FROM vfs_snapshots WHERE id = '$snapshot_a';
"

expect_failure \
  "UPDATE vfs_catalog_checkpoint_artifacts
   SET state = 'orphaned', updated_at = unixepoch()
   WHERE revision_id = (
     SELECT catalog_revision_id FROM vfs_snapshots WHERE id = '$snapshot_a'
   );" \
  "checkpoint artifact bypassing the staged receipt"

expect_failure \
  "UPDATE vfs_catalog_revisions
   SET state = 'materialized', materialized_at = unixepoch(),
       checkpoint_r2_key = 'vfs/catalog/checkpoints/test.json',
       checkpoint_sha256 =
         '9666666666666666666666666666666666666666666666666666666666666666',
       checkpoint_r2_version = 'r2-test-version', checkpoint_bytes = 128
   WHERE id = (
     SELECT catalog_revision_id FROM vfs_snapshots WHERE id = '$snapshot_a'
   );" \
  "catalog materialization without a staged R2 receipt"

expect_failure \
  "UPDATE vfs_catalog_outbox SET state = 'done'
   WHERE revision_id = (
     SELECT catalog_revision_id FROM vfs_snapshots WHERE id = '$snapshot_a'
   );" \
  "catalog outbox completion without a published head or collapse"

execute "
UPDATE vfs_catalog_checkpoint_artifacts
SET state = 'staged', r2_version = 'r2-test-version', updated_at = unixepoch()
WHERE revision_id = (
  SELECT catalog_revision_id FROM vfs_snapshots WHERE id = '$snapshot_a'
);
INSERT INTO vfs_catalog_mutation_heads (
  filesystem_id, revision_id, updated_at
)
SELECT filesystem_id, id, unixepoch()
FROM vfs_catalog_revisions
WHERE id = (
  SELECT catalog_revision_id FROM vfs_snapshots WHERE id = '$snapshot_a'
);
"

expect_failure \
  "UPDATE vfs_catalog_checkpoint_artifacts
   SET state = 'orphaned', updated_at = unixepoch()
   WHERE revision_id = (
     SELECT catalog_revision_id FROM vfs_snapshots WHERE id = '$snapshot_a'
   );" \
  "checkpoint artifact orphaned while it remains the mutation head"

expect_failure \
  "UPDATE vfs_catalog_checkpoint_artifacts
   SET state = 'published', updated_at = unixepoch()
   WHERE revision_id = (
     SELECT catalog_revision_id FROM vfs_snapshots WHERE id = '$snapshot_a'
   );" \
  "checkpoint artifact published before its exact catalog revision"

execute "
DELETE FROM vfs_catalog_mutation_heads WHERE filesystem_id = '$filesystem_a';
UPDATE vfs_catalog_checkpoint_artifacts
SET state = 'orphaned', updated_at = unixepoch()
WHERE revision_id = (
  SELECT catalog_revision_id FROM vfs_snapshots WHERE id = '$snapshot_a'
);
"

expect_failure \
  "INSERT INTO vfs_snapshot_reachability_seals (
     snapshot_id, version_count, versions_sha256, sealed_at
   ) VALUES (
     '$snapshot_a', 2,
     '9555555555555555555555555555555555555555555555555555555555555555',
     unixepoch()
   );" \
  "snapshot reachability seal with the wrong version count"

execute "
INSERT INTO vfs_snapshot_reachability_seals (
  snapshot_id, version_count, versions_sha256, sealed_at
) VALUES (
  '$snapshot_a', 1,
  '9555555555555555555555555555555555555555555555555555555555555555',
  unixepoch()
);
INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 0 FROM vfs_gc_blocked_filesystems
WHERE filesystem_id = '$filesystem_a';
INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 1 FROM vfs_reachable_versions WHERE version_id = '$version_b';
INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 0 FROM safe_unreachable_vfs_locations
WHERE id = '$location_b';
UPDATE vfs_snapshots SET state = 'expired' WHERE id = '$snapshot_a';
INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 1 FROM safe_unreachable_vfs_locations
WHERE id = '$location_b';

INSERT INTO vfs_token_verifiers (
  id, principal_id, root_directory_id, verifier_sha256, snapshot_id,
  expires_at, issued_by, created_at
) VALUES (
  '90000000000000000000000000000009', '$principal_active', '$root_a',
  '8999999999999999999999999999999999999999999999999999999999999999',
  '$snapshot_a', unixepoch() + 3600, '$principal_active', unixepoch()
);
INSERT INTO vfs_token_actions (token_id, action)
VALUES ('90000000000000000000000000000009', 'content.read');
UPDATE vfs_token_verifiers SET sealed_at = unixepoch()
WHERE id = '90000000000000000000000000000009';
INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 0 FROM safe_unreachable_vfs_locations
WHERE id = '$location_b';
UPDATE vfs_token_verifiers SET revoked_at = unixepoch()
WHERE id = '90000000000000000000000000000009';
INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 0 FROM safe_unreachable_vfs_locations
WHERE id = '$location_b';
DELETE FROM vfs_token_verifiers
WHERE id = '90000000000000000000000000000009';
INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 1 FROM safe_unreachable_vfs_locations
WHERE id = '$location_b';
"

expect_failure \
  "INSERT INTO vfs_snapshot_versions (snapshot_id, version_id, created_at)
   VALUES ('$snapshot_a', '$version_a', unixepoch());" \
  "version insertion after snapshot reachability was sealed"

expect_failure \
  "UPDATE vfs_version_origins
   SET directory_id = '$root_a'
   WHERE version_id = '$version_b';" \
  "mutation of immutable VFS version origin"

execute "
UPDATE vfs_locations
SET state = 'tombstoned', delete_after = unixepoch() + 3600,
    revision = revision + 1, updated_at = unixepoch()
WHERE id = '$location_b';
INSERT INTO vfs_location_delete_tasks (
  id, expected_location_revision, driver_id, driver_revision, storage_key,
  native_id, provider_version, etag, size_bytes, delete_after, created_at, updated_at
) SELECT location.id, location.revision, location.driver_id, driver.revision,
         location.storage_key, location.native_id, location.provider_version,
         location.etag, location.size_bytes, location.delete_after,
         unixepoch(), unixepoch()
  FROM vfs_locations AS location
  JOIN driver_instances AS driver ON driver.id = location.driver_id
 WHERE location.id = '$location_b';
"

expect_failure \
  "UPDATE vfs_location_delete_tasks
   SET driver_revision = driver_revision + 1
   WHERE id = '$location_b';" \
  "mutation of immutable lifecycle task identity"

expect_failure \
  "UPDATE vfs_location_delete_tasks
   SET state = 'blocked', last_error_code = 'unsafe', updated_at = unixepoch()
   WHERE id = '$location_b';" \
  "lifecycle task bypassing a fenced claim"

execute "
UPDATE vfs_location_delete_tasks
SET state = 'claimed', fencing_token = fencing_token + 1,
    lease_expires_at = unixepoch() + 120, attempt_count = attempt_count + 1,
    updated_at = unixepoch()
WHERE id = '$location_b';
"

expect_failure \
  "UPDATE vfs_location_delete_tasks
   SET state = 'deleted', lease_expires_at = NULL,
       completed_at = unixepoch(), updated_at = unixepoch()
   WHERE id = '$location_b';" \
  "lifecycle completion before the exact location is deleted"

expect_failure \
  "UPDATE vfs_location_delete_tasks
   SET state = 'retry', lease_expires_at = NULL,
       last_error_code = 'provider_delete_failed', updated_at = unixepoch()
   WHERE id = '$location_b';" \
  "lifecycle retry without an explicit retry schedule"

execute "
UPDATE vfs_location_delete_tasks
SET state = 'retry', lease_expires_at = NULL,
    retry_at = unixepoch() + 120, last_error_code = 'provider_delete_failed',
    updated_at = unixepoch()
WHERE id = '$location_b';
"

expect_failure \
  "UPDATE vfs_location_delete_tasks
   SET state = 'claimed', fencing_token = fencing_token + 1,
       lease_expires_at = unixepoch() + 120, attempt_count = attempt_count + 1,
       updated_at = unixepoch()
   WHERE id = '$location_b';" \
  "lifecycle reclaim that retains its retry schedule"

execute "
UPDATE vfs_location_delete_tasks
SET state = 'claimed', fencing_token = fencing_token + 1,
    lease_expires_at = unixepoch() + 120, retry_at = NULL,
    attempt_count = attempt_count + 1, updated_at = unixepoch()
WHERE id = '$location_b';
"

# Model a Worker that completed the provider Delete under fence 1 but lost its
# response until after fence 2 reclaimed the expired task. Both statements in
# the production completion batch must reject that stale outcome. The current
# owner retains the claimed task and the tombstoned location for an idempotent
# exact-Stat retry.
execute "
INSERT INTO vfs_v2_protocol_assertions
SELECT fencing_token = 2 AND state = 'claimed'
FROM vfs_location_delete_tasks WHERE id = '$location_b';

UPDATE vfs_locations
SET state = 'deleted', revision = revision + 1, updated_at = unixepoch()
WHERE id = '$location_b' AND state = 'tombstoned'
  AND EXISTS (
      SELECT 1 FROM vfs_location_delete_tasks AS task
      WHERE task.id = '$location_b' AND task.state = 'claimed'
        AND task.fencing_token = 1
  );

UPDATE vfs_location_delete_tasks
SET state = 'deleted', lease_expires_at = NULL,
    completed_at = unixepoch(), updated_at = unixepoch()
WHERE id = '$location_b' AND state = 'claimed' AND fencing_token = 1;

INSERT INTO vfs_v2_protocol_assertions
SELECT location.state = 'tombstoned'
       AND task.state = 'claimed'
       AND task.fencing_token = 2
  FROM vfs_locations AS location
  JOIN vfs_location_delete_tasks AS task ON task.id = location.id
 WHERE location.id = '$location_b';
"

execute "
UPDATE vfs_location_delete_tasks
SET state = 'blocked', lease_expires_at = NULL,
    last_error_code = 'fault_injection_complete', updated_at = unixepoch()
WHERE id = '$location_b';
"

execute "
INSERT INTO vfs_v2_protocol_assertions
SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);
"
