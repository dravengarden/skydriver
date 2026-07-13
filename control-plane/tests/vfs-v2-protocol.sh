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
location_a=80000000000000000000000000000001
parent_token=90000000000000000000000000000001
child_token=90000000000000000000000000000002

execute "
CREATE TABLE vfs_v2_protocol_assertions (
  accepted INTEGER NOT NULL CHECK (accepted = 1)
) STRICT;

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 12 FROM vfs_actions;

INSERT INTO vfs_v2_protocol_assertions
SELECT COUNT(*) = 10 FROM sqlite_schema
WHERE type = 'index' AND name IN (
  'idx_vfs_directories_active_parent',
  'idx_vfs_files_active_filesystem',
  'idx_vfs_locations_version_state_driver',
  'idx_vfs_locations_driver_state_version',
  'idx_vfs_directory_drivers_active_driver',
  'idx_vfs_audit_events_token_time',
  'idx_vfs_token_verifiers_created',
  'idx_admin_configuration_sessions_expires_at',
  'idx_vfs_catalog_outbox_claimable',
  'idx_vfs_snapshots_expiry'
);

INSERT INTO credential_envelopes (
  id, envelope_algorithm, key_version, nonce, ciphertext, created_at, rotated_at
) VALUES ('vfs-credential', 'test/v1', '1', X'01', X'02', 1, 1);

INSERT INTO driver_instances (
  id, kind, config_json, credential_ref, created_at, updated_at
) VALUES
  ('vfs-driver-1', 'localfs/v2', '{}', 'vfs-credential', 1, 1),
  ('vfs-driver-2', 's3/v2', '{}', 'vfs-credential', 1, 1);

INSERT INTO clients (
  id, name, sdk_version, capabilities_json, labels_json, state,
  created_at, updated_at
) VALUES ('vfs-client', 'VFS client', 'v2', '{}', '{}', 'online', 1, 1);

INSERT INTO vfs_filesystems (id, name, created_at, updated_at) VALUES
  ('$filesystem_a', 'primary', 1, 1),
  ('$filesystem_b', 'secondary', 1, 1);

INSERT INTO vfs_principals (
  id, kind, display_name, state, created_at, updated_at
) VALUES
  ('$principal_active', 'service', 'VFS test client', 'active', 1, 1),
  ('$principal_disabled', 'service', 'Disabled client', 'disabled', 1, 1);

INSERT INTO vfs_principal_clients (principal_id, client_id, created_at)
VALUES ('$principal_active', 'vfs-client', 1);

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
INSERT INTO vfs_v2_protocol_assertions
SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);
"
