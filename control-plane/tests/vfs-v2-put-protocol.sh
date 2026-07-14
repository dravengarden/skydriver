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
    echo "expected VFS V2 put rejection: $description" >&2
    exit 1
  fi
}

filesystem=11000000000000000000000000000001
principal=21000000000000000000000000000001
root=31000000000000000000000000000001
directory=31000000000000000000000000000002
token=41000000000000000000000000000001
restricted_token=41000000000000000000000000000002
intent=51000000000000000000000000000001
contender=51000000000000000000000000000002
file=61000000000000000000000000000001
version=71000000000000000000000000000001
location=81000000000000000000000000000001
old_root=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
old_directory_root=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
new_directory_root=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
new_root=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
file_root=1111111111111111111111111111111111111111111111111111111111111111
metadata_root=2222222222222222222222222222222222222222222222222222222222222222
manifest_sha=3333333333333333333333333333333333333333333333333333333333333333
encoded_sha=4444444444444444444444444444444444444444444444444444444444444444
request_sha=5555555555555555555555555555555555555555555555555555555555555555
commit_sha=6666666666666666666666666666666666666666666666666666666666666666
storage_key=objects/v2/ab/abababababababababababababababababababababababab

execute "
CREATE TABLE vfs_put_protocol_assertions (
  accepted INTEGER NOT NULL CHECK (accepted = 1)
) STRICT;

INSERT INTO credential_envelopes (
  id, envelope_algorithm, key_version, nonce, ciphertext, created_at, rotated_at
) VALUES ('put-credential', 'test/v1', '1', X'01', X'02', 1, 1);

INSERT INTO driver_instances (
  id, kind, config_json, credential_ref, created_at, updated_at
) VALUES
  ('put-driver-1', 'localfs/v2', '{}', 'put-credential', 1, 1),
  ('put-driver-2', 's3/v2', '{}', 'put-credential', 1, 1);

INSERT INTO vfs_filesystems (id, name, created_at, updated_at)
VALUES ('$filesystem', 'put protocol', 1, 1);

INSERT INTO vfs_principals (
  id, kind, display_name, state, created_at, updated_at
) VALUES ('$principal', 'service', 'Put protocol client', 'active', 1, 1);

INSERT INTO vfs_directories (
  id, filesystem_id, parent_id, name, data_root, crypto_suite,
  active_key_epoch, acl_inherits, created_at, updated_at
) VALUES
  (
    '$root', '$filesystem', NULL, '', '$old_root', 'plaintext/v1',
    1, 0, 1, 1
  ),
  (
    '$directory', '$filesystem', '$root', 'uploads', '$old_directory_root',
    'plaintext/v1', 1, 1, 1, 1
  );

INSERT INTO vfs_directory_entries (
  directory_id, name, kind, child_directory_id, size_bytes,
  data_root, created_at, updated_at
) VALUES (
  '$root', 'uploads', 'directory', '$directory', 0,
  '$old_directory_root', 1, 1
);

INSERT INTO vfs_directory_drivers (
  directory_id, driver_id, write_priority, created_by, created_at, updated_at
) VALUES ('$directory', 'put-driver-1', 0, '$principal', 1, 1);

INSERT INTO vfs_acl_grants (
  id, directory_id, principal_id, action, source_role, created_by, created_at
) VALUES
  (
    '91000000000000000000000000000001', '$root', '$principal',
    'content.write', 'editor', '$principal', 1
  ),
  (
    '91000000000000000000000000000002', '$root', '$principal',
    'driver.use', 'storage_operator', '$principal', 1
  );

INSERT INTO vfs_token_verifiers (
  id, principal_id, root_directory_id, verifier_sha256, expires_at,
  issued_by, created_at
) VALUES
  (
    '$token', '$principal', '$directory',
    '7111111111111111111111111111111111111111111111111111111111111111',
    unixepoch() + 3600, '$principal', unixepoch()
  ),
  (
    '$restricted_token', '$principal', '$directory',
    '7222222222222222222222222222222222222222222222222222222222222222',
    unixepoch() + 3600, '$principal', unixepoch()
  );
INSERT INTO vfs_token_actions (token_id, action) VALUES
  ('$token', 'content.write'),
  ('$token', 'driver.use'),
  ('$restricted_token', 'content.write');
INSERT INTO vfs_token_drivers (token_id, driver_id) VALUES
  ('$token', 'put-driver-1'),
  ('$restricted_token', 'put-driver-1');
UPDATE vfs_token_verifiers SET sealed_at = unixepoch()
WHERE id IN ('$token', '$restricted_token');
"

expect_failure \
  "INSERT INTO vfs_put_intents (
     id, filesystem_id, principal_id, token_id, directory_id, entry_name,
     expected_entry_revision, expected_file_revision, file_id, version_id,
     location_id, driver_id, storage_key, plaintext_bytes,
     verification_block_bytes, verification_block_count, file_root,
     metadata_root, block_manifest_sha256, block_manifest_bytes,
     block_manifest_r2_key, crypto_suite, key_epoch, encryption_frame_bytes,
     request_sha256, idempotency_key, expires_at, created_at
   ) VALUES (
     '51000000000000000000000000000003', '$filesystem', '$principal',
     '$restricted_token', '$directory', 'denied.bin', 0, 0,
     '61000000000000000000000000000003',
     '71000000000000000000000000000003',
     '81000000000000000000000000000003', 'put-driver-1',
     'objects/v2/ac/acacacacacacacacacacacacacacacacacacacacacacacac',
     10, 4, 3, '$file_root', '$metadata_root', '$manifest_sha', 128,
     'vfs/blocks/33', 'plaintext/v1', 1, 4, '$request_sha',
     'denied-prepare', unixepoch() + 1800, unixepoch()
   );" \
  "prepare token without driver.use"

expect_failure \
  "INSERT INTO vfs_put_intents (
     id, filesystem_id, principal_id, token_id, directory_id, entry_name,
     expected_entry_revision, expected_file_revision, file_id, version_id,
     location_id, driver_id, storage_key, plaintext_bytes,
     verification_block_bytes, verification_block_count, file_root,
     metadata_root, block_manifest_sha256, block_manifest_bytes,
     block_manifest_r2_key, crypto_suite, key_epoch, encryption_frame_bytes,
     request_sha256, idempotency_key, expires_at, created_at
   ) VALUES (
     '51000000000000000000000000000004', '$filesystem', '$principal', '$token',
     '$directory', 'wrong-driver.bin', 0, 0,
     '61000000000000000000000000000004',
     '71000000000000000000000000000004',
     '81000000000000000000000000000004', 'put-driver-2',
     'objects/v2/ad/adadadadadadadadadadadadadadadadadadadadadadadad',
     10, 4, 3, '$file_root', '$metadata_root', '$manifest_sha', 128,
     'vfs/blocks/33', 'plaintext/v1', 1, 4, '$request_sha',
     'wrong-placement', unixepoch() + 1800, unixepoch()
   );" \
  "driver outside directory placement"

execute "
INSERT INTO vfs_put_intents (
  id, filesystem_id, principal_id, token_id, directory_id, entry_name,
  expected_entry_revision, expected_file_revision, file_id, version_id,
  location_id, driver_id, storage_key, plaintext_bytes,
  verification_block_bytes, verification_block_count, file_root,
  metadata_root, block_manifest_sha256, block_manifest_bytes,
  block_manifest_r2_key, crypto_suite, key_epoch, encryption_frame_bytes,
  request_sha256, idempotency_key, expires_at, created_at
) VALUES
  (
    '$intent', '$filesystem', '$principal', '$token', '$directory', 'asset.bin',
    0, 0, '$file', '$version', '$location', 'put-driver-1', '$storage_key',
    10, 4, 3, '$file_root', '$metadata_root', '$manifest_sha', 128,
    'vfs/blocks/33', 'plaintext/v1', 1, 4, '$request_sha', 'put-asset',
    unixepoch() + 1800, unixepoch()
  ),
  (
    '$contender', '$filesystem', '$principal', '$token', '$directory', 'asset.bin',
    0, 0, '61000000000000000000000000000002',
    '71000000000000000000000000000002',
    '81000000000000000000000000000002', 'put-driver-1',
    'objects/v2/ae/aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae',
    10, 4, 3, '$file_root', '$metadata_root', '$manifest_sha', 128,
    'vfs/blocks/33', 'plaintext/v1', 1, 4,
    '5777777777777777777777777777777777777777777777777777777777777777',
    'put-asset-contender', unixepoch() + 1800, unixepoch()
  );

INSERT INTO vfs_put_protocol_assertions
SELECT COUNT(*) = 2 FROM vfs_put_intents WHERE state = 'prepared';
"

expect_failure \
  "INSERT INTO vfs_put_intents (
     id, filesystem_id, principal_id, token_id, directory_id, entry_name,
     expected_entry_revision, expected_file_revision, file_id, version_id,
     location_id, driver_id, storage_key, plaintext_bytes,
     verification_block_bytes, verification_block_count, file_root,
     metadata_root, block_manifest_sha256, block_manifest_bytes,
     block_manifest_r2_key, crypto_suite, key_epoch, encryption_frame_bytes,
     request_sha256, idempotency_key, expires_at, created_at
   ) VALUES (
     '51000000000000000000000000000005', '$filesystem', '$principal', '$token',
     '$directory', 'other.bin', 0, 0,
     '61000000000000000000000000000005',
     '71000000000000000000000000000005',
     '81000000000000000000000000000005', 'put-driver-1',
     'objects/v2/af/afafafafafafafafafafafafafafafafafafafafafafafaf',
     10, 4, 3, '$file_root', '$metadata_root', '$manifest_sha', 128,
     'vfs/blocks/33', 'plaintext/v1', 1, 4,
     '5888888888888888888888888888888888888888888888888888888888888888',
     'put-asset', unixepoch() + 1800, unixepoch()
   );" \
  "idempotency key reused with another request"

execute "
INSERT INTO vfs_files (id, filesystem_id, created_at, updated_at)
VALUES ('$file', '$filesystem', unixepoch(), unixepoch());

INSERT INTO vfs_file_versions (
  id, file_id, plaintext_bytes, verification_block_bytes,
  verification_block_count, file_root, block_manifest_sha256,
  block_manifest_bytes, block_manifest_r2_key, block_manifest_r2_version,
  crypto_suite, key_epoch, encryption_frame_bytes, encoded_bytes,
  encoded_sha256, created_at
) VALUES (
  '$version', '$file', 10, 4, 3, '$file_root', '$manifest_sha', 128,
  'vfs/blocks/33', 'r2-block-version-1', 'plaintext/v1', 1, 4, 10,
  '$encoded_sha', unixepoch()
);

INSERT INTO vfs_locations (
  id, version_id, driver_id, storage_key, native_id, provider_version, etag,
  size_bytes, object_sha256, created_at, updated_at
) VALUES (
  '$location', '$version', 'put-driver-1', '$storage_key', 'native-object-1',
  'provider-version-1', 'etag-1', 10, '$encoded_sha', unixepoch(), unixepoch()
);
INSERT INTO vfs_version_origins (version_id, directory_id, created_at)
VALUES ('$version', '$directory', unixepoch());
UPDATE vfs_locations
SET state = 'verified', verified_at = unixepoch(),
    revision = revision + 1, updated_at = unixepoch()
WHERE id = '$location';
UPDATE vfs_locations
SET state = 'available', revision = revision + 1, updated_at = unixepoch()
WHERE id = '$location';
UPDATE vfs_file_versions SET state = 'verified' WHERE id = '$version';
UPDATE vfs_file_versions
SET state = 'published', published_at = unixepoch()
WHERE id = '$version';
UPDATE vfs_files
SET current_version_id = '$version', updated_at = unixepoch()
WHERE id = '$file';

INSERT INTO vfs_directory_entries (
  directory_id, name, kind, file_id, version_id, size_bytes,
  data_root, metadata_root, created_at, updated_at
) VALUES (
  '$directory', 'asset.bin', 'file', '$file', '$version', 10,
  '$file_root', '$metadata_root', unixepoch(), unixepoch()
);

INSERT INTO vfs_put_directory_updates (
  intent_id, ordinal, directory_id, expected_revision,
  expected_data_root, new_data_root
) VALUES
  ('$intent', 0, '$directory', 1, '$old_directory_root', '$new_directory_root'),
  ('$intent', 1, '$root', 1, '$old_root', '$new_root');

UPDATE vfs_directories
SET data_root = '$new_directory_root', revision = revision + 1,
    updated_at = unixepoch()
WHERE id = '$directory' AND revision = 1 AND data_root = '$old_directory_root';
UPDATE vfs_directory_entries
SET data_root = '$new_directory_root', revision = revision + 1,
    updated_at = unixepoch()
WHERE directory_id = '$root' AND name = 'uploads' AND revision = 1;
UPDATE vfs_directories
SET data_root = '$new_root', revision = revision + 1, updated_at = unixepoch()
WHERE id = '$root' AND revision = 1 AND data_root = '$old_root';

INSERT INTO vfs_catalog_revisions (
  filesystem_id, parent_revision_id, root_data_root, state,
  created_at, mutation_kind, mutation_id
) VALUES ('$filesystem', NULL, '$new_root', 'pending', unixepoch(), 'put', '$intent');
INSERT INTO vfs_catalog_outbox (revision_id, updated_at)
SELECT id, unixepoch() FROM vfs_catalog_revisions
WHERE mutation_kind = 'put' AND mutation_id = '$intent';
INSERT INTO vfs_catalog_mutation_heads (
  filesystem_id, revision_id, updated_at
)
SELECT filesystem_id, id, unixepoch() FROM vfs_catalog_revisions
WHERE mutation_kind = 'put' AND mutation_id = '$intent';

INSERT INTO vfs_put_upload_evidence (
  intent_id, token_id, commit_sha256, block_manifest_r2_version,
  encoded_bytes, encoded_sha256, verification_method,
  native_id, provider_version, etag, verified_at
) VALUES (
  '$intent', '$token', '$commit_sha', 'r2-block-version-1',
  10, '$encoded_sha', 'complete_readback',
  'native-object-1', 'provider-version-1', 'etag-1', unixepoch()
);

INSERT INTO vfs_put_receipts (
  intent_id, token_id, commit_sha256, block_manifest_r2_version,
  encoded_bytes, encoded_sha256, verification_method, verified_at,
  native_id, provider_version, etag,
  entry_revision, catalog_revision_id, committed_at
)
SELECT
  '$intent', '$token', '$commit_sha', 'r2-block-version-1', 10, '$encoded_sha',
  'complete_readback', unixepoch(), 'native-object-1', 'provider-version-1',
  'etag-1', 1, id, unixepoch()
FROM vfs_catalog_revisions
WHERE mutation_kind = 'put' AND mutation_id = '$intent';

UPDATE vfs_put_intents
SET state = 'committed', committed_at = unixepoch(), revision = revision + 1
WHERE id = '$intent';

INSERT INTO vfs_put_protocol_assertions
SELECT intent.state = 'committed'
       AND file.current_version_id = '$version'
       AND version.state = 'published'
       AND location.state = 'available'
       AND entry.revision = 1
       AND catalog.state = 'pending'
       AND outbox.state = 'pending'
FROM vfs_put_intents AS intent
JOIN vfs_files AS file ON file.id = '$file'
JOIN vfs_file_versions AS version ON version.id = '$version'
JOIN vfs_locations AS location ON location.id = '$location'
JOIN vfs_directory_entries AS entry
  ON entry.directory_id = '$directory' AND entry.name = 'asset.bin'
JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = intent.id
JOIN vfs_put_receipts AS receipt ON receipt.intent_id = intent.id
JOIN vfs_catalog_revisions AS catalog ON catalog.id = receipt.catalog_revision_id
JOIN vfs_catalog_outbox AS outbox ON outbox.revision_id = catalog.id
WHERE intent.id = '$intent';

INSERT INTO vfs_put_protocol_assertions
SELECT state = 'prepared' FROM vfs_put_intents WHERE id = '$contender';
"

expect_failure \
  "UPDATE vfs_put_intents SET entry_name = 'changed.bin' WHERE id = '$intent';" \
  "mutation of immutable prepared identity"

expect_failure \
  "UPDATE vfs_put_receipts SET etag = 'changed' WHERE intent_id = '$intent';" \
  "mutation of durable commit receipt"

expect_failure \
  "UPDATE vfs_put_upload_evidence SET etag = 'changed' WHERE intent_id = '$intent';" \
  "mutation of immutable upload evidence"

expect_failure \
  "UPDATE vfs_put_directory_updates
   SET new_data_root = '$old_root'
   WHERE intent_id = '$intent' AND ordinal = 1;" \
  "mutation of committed directory CAS evidence"

expect_failure \
  "UPDATE vfs_directories SET data_root = '$old_root' WHERE id = '$root';" \
  "directory root mutation without the next revision"

expect_failure \
  "UPDATE vfs_put_intents
   SET state = 'committed', committed_at = unixepoch(), revision = revision + 1
   WHERE id = '$contender';" \
  "losing contender without matching publication receipt"

execute "
INSERT INTO vfs_put_upload_evidence (
  intent_id, token_id, commit_sha256, block_manifest_r2_version,
  encoded_bytes, encoded_sha256, verification_method,
  native_id, provider_version, etag, verified_at
) VALUES (
  '$contender', '$token',
  '7777777777777777777777777777777777777777777777777777777777777777',
  'r2-block-version-contender', 10, '$encoded_sha', 'complete_readback',
  'native-contender', 'provider-contender', 'etag-contender', unixepoch()
);
UPDATE vfs_put_intents
SET state = 'expired', revision = revision + 1
WHERE id = '$contender';
INSERT INTO vfs_put_delete_tasks (
  id, driver_revision, evidence_sha256, delete_after, created_at, updated_at
) VALUES (
  '$contender', 1,
  '7777777777777777777777777777777777777777777777777777777777777777',
  unixepoch() - 1, unixepoch(), unixepoch()
);
INSERT INTO vfs_put_protocol_assertions
SELECT COUNT(*) = 1 FROM safe_vfs_put_delete_tasks WHERE id = '$contender';
"

expect_failure \
  "UPDATE vfs_put_delete_tasks SET delete_after = unixepoch() + 1 WHERE id = '$contender';" \
  "mutation of immutable VFS put delete identity"

execute "
UPDATE vfs_token_verifiers SET revoked_at = unixepoch() WHERE id = '$token';
"

expect_failure \
  "UPDATE vfs_token_verifiers SET revoked_at = NULL WHERE id = '$token';" \
  "token revocation rollback"

expect_failure \
  "INSERT INTO vfs_put_intents (
     id, filesystem_id, principal_id, token_id, directory_id, entry_name,
     expected_entry_revision, expected_file_revision, file_id, version_id,
     location_id, driver_id, storage_key, plaintext_bytes,
     verification_block_bytes, verification_block_count, file_root,
     metadata_root, block_manifest_sha256, block_manifest_bytes,
     block_manifest_r2_key, crypto_suite, key_epoch, encryption_frame_bytes,
     request_sha256, idempotency_key, expires_at, created_at
   ) VALUES (
     '51000000000000000000000000000006', '$filesystem', '$principal', '$token',
     '$directory', 'revoked.bin', 0, 0,
     '61000000000000000000000000000006',
     '71000000000000000000000000000006',
     '81000000000000000000000000000006', 'put-driver-1',
     'objects/v2/b0/b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0',
     10, 4, 3, '$file_root', '$metadata_root', '$manifest_sha', 128,
     'vfs/blocks/33', 'plaintext/v1', 1, 4,
     '5999999999999999999999999999999999999999999999999999999999999999',
     'revoked-token', unixepoch() + 1800, unixepoch()
   );" \
  "prepare after token revocation"

expect_failure \
  "INSERT INTO vfs_catalog_revisions (
     filesystem_id, root_data_root, state, materialized_at, published_at,
     created_at, mutation_kind, mutation_id
   ) VALUES (
     '$filesystem', '$new_root', 'published', unixepoch(), unixepoch(),
     unixepoch(), 'put', 'forged'
   );" \
  "catalog revision inserted directly as published"

execute "
INSERT INTO vfs_put_protocol_assertions
SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);
"
