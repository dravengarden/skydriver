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
    echo "expected D1 rejection: $description" >&2
    exit 1
  fi
}

execute "
CREATE TABLE protocol_assertions (
  accepted INTEGER NOT NULL CHECK (accepted = 1)
) STRICT;
INSERT INTO protocol_assertions
SELECT length(incarnation) = 32
       AND incarnation NOT GLOB '*[^0-9a-f]*'
       AND incarnation != '00000000000000000000000000000000'
FROM control_plane_state
WHERE singleton = 1;

INSERT INTO credential_envelopes (
  id, envelope_algorithm, key_version, nonce, ciphertext, created_at, rotated_at
) VALUES ('credential-1', 'test/v1', '1', X'01', X'02', 1, 1);

INSERT INTO driver_instances (
  id, kind, config_json, credential_ref, created_at, updated_at
) VALUES ('driver-1', 'test/v1', '{}', 'credential-1', 1, 1);

INSERT INTO namespaces (
  id, name, crypto_suite, root_key_version, active_key_epoch,
  replica_policy_json, retention_policy_json, created_at, updated_at
) VALUES (
  '202122232425262728292a2b2c2d2e2f',
  'test',
  'carrack-aes128gcm-hkdfsha256-v1',
  1,
  1,
  '{}',
  '{}',
  1,
  1
);

INSERT INTO objects (
  id, namespace_id, logical_name, created_at, updated_at
) VALUES (
  'object-1',
  '202122232425262728292a2b2c2d2e2f',
  'logical/object',
  1,
  1
);

INSERT INTO object_versions (
  id, object_id, generation, manifest_sha256, plaintext_sha256,
  plaintext_bytes, chunk_count, pack_count, state, created_at
) VALUES (
  'version-1',
  'object-1',
  1,
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
  8,
  1,
  1,
  'staging',
  1
);

INSERT INTO packs (
  id, namespace_id, crypto_suite, root_key_version, key_epoch,
  ciphertext_sha256, plaintext_bytes, ciphertext_bytes, frame_bytes, created_at
) VALUES (
  '404142434445464748494a4b4c4d4e4f',
  '202122232425262728292a2b2c2d2e2f',
  'carrack-aes128gcm-hkdfsha256-v1',
  1,
  1,
  '1111111111111111111111111111111111111111111111111111111111111111',
  8,
  24,
  8,
  1
);

INSERT INTO extents (
  id, pack_id, ordinal, first_frame, frame_count, ciphertext_offset,
  ciphertext_bytes, ciphertext_sha256, created_at
) VALUES (
  'extent-1',
  '404142434445464748494a4b4c4d4e4f',
  0,
  0,
  1,
  0,
  24,
  '2222222222222222222222222222222222222222222222222222222222222222',
  1
);

INSERT INTO version_packs (
  version_id, ordinal, pack_id, plaintext_offset
) VALUES ('version-1', 0, '404142434445464748494a4b4c4d4e4f', 0);

INSERT INTO locations (
  id, extent_id, driver_id, storage_key, storage_offset, storage_length, ciphertext_sha256,
  ciphertext_bytes, state, verified_at, created_at, updated_at
) VALUES (
  'location-1',
  'extent-1',
  'driver-1',
  'packs/40/pack',
  0,
  24,
  '2222222222222222222222222222222222222222222222222222222222222222',
  24,
  'staging',
  NULL,
  1,
  1
);
UPDATE locations
SET state = 'verified', verified_at = 2, revision = revision + 1, updated_at = 2
WHERE id = 'location-1';

INSERT INTO locations (
  id, extent_id, driver_id, storage_key, storage_offset, storage_length,
  ciphertext_sha256, ciphertext_bytes, state, created_at, updated_at
) VALUES (
  'location-2', 'extent-1', 'driver-1', 'packs/40/pack', 24, 24,
  '2222222222222222222222222222222222222222222222222222222222222222',
  24, 'staging', 2, 2
);"

expect_failure \
  "UPDATE object_versions SET state = 'published' WHERE id = 'version-1';" \
  "publication without durable recovery manifest"

execute "
INSERT INTO recovery_manifests (
  manifest_sha256, version_id, schema_version, r2_storage_key,
  sidecar_driver_id, sidecar_storage_key, state, ciphertext_bytes,
  verified_at, created_at, updated_at
) VALUES (
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  'version-1',
  'carrack.recovery.v1',
  'manifests/01/manifest.json',
  'driver-1',
  'manifests/01/manifest.json',
  'durable',
  1024,
  2,
  1,
  2
);
UPDATE object_versions
SET state = 'published', published_at = 2
WHERE id = 'version-1';
UPDATE objects
SET current_generation = 1, revision = revision + 1, updated_at = 2
WHERE id = 'object-1';
INSERT INTO protocol_assertions
SELECT state = 'published'
FROM object_versions
WHERE id = 'version-1';
PRAGMA foreign_key_check;"

expect_failure \
  "UPDATE object_versions SET plaintext_bytes = 9 WHERE id = 'version-1';" \
  "mutation of published identity"

execute "
INSERT INTO object_versions (
  id, object_id, generation, manifest_sha256, plaintext_sha256,
  plaintext_bytes, chunk_count, state, created_at
) VALUES (
  'version-2',
  'object-1',
  2,
  '3333333333333333333333333333333333333333333333333333333333333333',
  '4444444444444444444444444444444444444444444444444444444444444444',
  0,
  0,
  'staging',
  3
);"

expect_failure \
  "UPDATE objects SET current_generation = 2 WHERE id = 'object-1';" \
  "object pointer to unpublished generation"

expect_failure \
  "INSERT INTO object_versions (
     id, object_id, generation, manifest_sha256, plaintext_sha256,
     plaintext_bytes, chunk_count, state, created_at
   ) VALUES (
     'version-3', 'object-1', 3,
     '5555555555555555555555555555555555555555555555555555555555555555',
     '6666666666666666666666666666666666666666666666666666666666666666',
     0, 0, 'published', 4
   );" \
  "object version inserted directly as published"

expect_failure \
  "INSERT INTO locations (
     id, extent_id, driver_id, storage_key, storage_offset, storage_length, ciphertext_sha256,
     ciphertext_bytes, state, created_at, updated_at
   ) VALUES (
     'location-bad', 'extent-1', 'driver-1', 'bad', 0, 24,
     '7777777777777777777777777777777777777777777777777777777777777777',
     24, 'staging', 4, 4
   );" \
  "location whose identity differs from its extent"

expect_failure \
  "INSERT INTO locations (
     id, extent_id, driver_id, storage_key, storage_offset, storage_length,
     ciphertext_sha256, ciphertext_bytes, state, created_at, updated_at
   ) VALUES (
     'location-bad-range', 'extent-1', 'driver-1', 'bad-range', 7, 23,
     '2222222222222222222222222222222222222222222222222222222222222222',
     24, 'staging', 4, 4
   );" \
  "provider range shorter than its extent"

execute "
INSERT INTO clients (
  id, name, sdk_version, capabilities_json, labels_json, state, created_at, updated_at
) VALUES ('client-1', 'test-client', 'test', '[]', '{}', 'online', 1, 1);

INSERT INTO operations (
  id, namespace_id, kind, state, phase, idempotency_key, requested_by,
  incarnation, created_at, updated_at
)
SELECT
  'operation-1',
  '202122232425262728292a2b2c2d2e2f',
  'import',
  'planned',
  'planned',
  'idempotency-1',
  'client-1',
  incarnation,
  1,
  1
FROM control_plane_state
WHERE singleton = 1;

INSERT INTO import_intents (operation_id, root_key_version, key_epoch, created_at)
VALUES ('operation-1', 1, 1, 1);

INSERT INTO leases (
  id, resource_kind, resource_id, lease_kind, owner_client_id,
  operation_id, fencing_token, incarnation, expires_at, created_at, updated_at
)
SELECT
  'lease-1',
  'operation',
  'operation-1',
  'write',
  'client-1',
  'operation-1',
  1,
  incarnation,
  unixepoch() + 60,
  unixepoch(),
  unixepoch()
FROM control_plane_state
WHERE singleton = 1;"

expect_failure \
  "UPDATE operations SET state = 'succeeded' WHERE id = 'operation-1';" \
  "operation skipping required states"

expect_failure \
  "INSERT INTO operations (
     id, namespace_id, kind, state, phase, idempotency_key, requested_by,
     incarnation, created_at, updated_at
   ) VALUES (
     'operation-stale',
     '202122232425262728292a2b2c2d2e2f',
     'import',
     'planned',
     'planned',
     'idempotency-stale',
     'client-1',
     'ffffffffffffffffffffffffffffffff',
     1,
     1
   );" \
  "operation from a stale incarnation"

expect_failure \
  "UPDATE import_intents SET key_epoch = 2 WHERE operation_id = 'operation-1';" \
  "mutation of a pinned import crypto context"

execute "
UPDATE operations
SET state = 'running', phase = 'transferring', revision = revision + 1, updated_at = 2
WHERE id = 'operation-1';

INSERT INTO publication_intents (
  operation_id, client_id, namespace_id, object_id, generation,
  manifest_sha256, recovery_sha256, r2_storage_key, r2_version,
  sidecar_driver_id, sidecar_storage_key, expected_object_revision,
  incarnation, lease_id, fencing_token, state, created_at, updated_at
)
SELECT
  'operation-1', 'client-1', '202122232425262728292a2b2c2d2e2f',
  'object-1', 2,
  '3333333333333333333333333333333333333333333333333333333333333333',
  '7777777777777777777777777777777777777777777777777777777777777777',
  'manifests/33/recovery.json', 'r2-version-2',
  'driver-1', 'manifests/33/sidecar.json', 2,
  incarnation, 'lease-1', 1, 'staging', 2, 2
FROM control_plane_state WHERE singleton = 1;
"

expect_failure \
  "UPDATE publication_intents SET state = 'committed'
   WHERE operation_id = 'operation-1';" \
  "publication before its object version becomes visible"

execute "
INSERT INTO recovery_manifests (
  manifest_sha256, version_id, schema_version, r2_storage_key,
  sidecar_driver_id, sidecar_storage_key, state, ciphertext_bytes,
  verified_at, created_at, updated_at
) VALUES (
  '3333333333333333333333333333333333333333333333333333333333333333',
  'version-2', 'carrack.recovery.v1', 'manifests/33/recovery.json',
  'driver-1', 'manifests/33/sidecar.json', 'durable', 512, 3, 2, 3
);
UPDATE object_versions
SET state = 'published', published_at = 3
WHERE id = 'version-2';
UPDATE objects
SET current_generation = 2, revision = revision + 1, updated_at = 3
WHERE id = 'object-1' AND revision = 2;
UPDATE leases
SET fencing_token = 2, updated_at = 3
WHERE id = 'lease-1';"

expect_failure \
  "UPDATE publication_intents
   SET state = 'committed', committed_at = 3, updated_at = 3
   WHERE operation_id = 'operation-1';" \
  "publication through a superseded fencing token"

execute "
UPDATE publication_intents
SET fencing_token = 2, updated_at = 3
WHERE operation_id = 'operation-1' AND state = 'staging';
UPDATE publication_intents
SET state = 'committed', committed_at = 3, updated_at = 3
WHERE operation_id = 'operation-1';
UPDATE operations
SET state = 'verifying', phase = 'verifying', revision = revision + 1, updated_at = 3
WHERE id = 'operation-1';
UPDATE operations
SET state = 'committing', phase = 'committing', revision = revision + 1, updated_at = 3
WHERE id = 'operation-1';
UPDATE operations
SET state = 'succeeded', phase = 'succeeded', revision = revision + 1,
    finished_at = 3, updated_at = 3
WHERE id = 'operation-1';
UPDATE leases SET released_at = unixepoch(), updated_at = unixepoch()
WHERE id = 'lease-1';
INSERT INTO protocol_assertions
SELECT operation.state = 'succeeded'
       AND intent.state = 'committed'
       AND object.current_generation = 2
FROM operations AS operation
JOIN publication_intents AS intent ON intent.operation_id = operation.id
JOIN objects AS object ON object.id = intent.object_id
WHERE operation.id = 'operation-1';
PRAGMA foreign_key_check;"

execute "
UPDATE recovery_manifests
SET recovery_sha256 = '8888888888888888888888888888888888888888888888888888888888888888',
    r2_version = 'base-r2-version', updated_at = 4
WHERE manifest_sha256 = '3333333333333333333333333333333333333333333333333333333333333333';"

expect_failure \
  "UPDATE recovery_manifests
   SET recovery_sha256 = '9999999999999999999999999999999999999999999999999999999999999999',
       r2_storage_key = 'manifests/99/recovery.json', r2_version = 'copy-r2-version',
       sidecar_storage_key = 'manifests/99/sidecar.json', revision = revision + 1
   WHERE manifest_sha256 = '3333333333333333333333333333333333333333333333333333333333333333';" \
  "recovery head replacement without a copy fence"

execute "
INSERT INTO operations (
  id, namespace_id, kind, state, phase, idempotency_key, requested_by,
  incarnation, useful_bytes_total, created_at, updated_at
)
SELECT
  'copy-operation-1', '202122232425262728292a2b2c2d2e2f', 'copy', 'planned', 'planned',
  'copy-idempotency-1', 'client-1', incarnation, 24, 4, 4
FROM control_plane_state WHERE singleton = 1;
INSERT INTO copy_intents (
  operation_id, version_id, manifest_sha256, source_recovery_sha256,
  source_recovery_revision, source_r2_storage_key, source_r2_version,
  source_recovery_bytes, destination_driver_id, created_at
) VALUES (
  'copy-operation-1', 'version-2',
  '3333333333333333333333333333333333333333333333333333333333333333',
  '8888888888888888888888888888888888888888888888888888888888888888',
  1, 'manifests/33/recovery.json', 'base-r2-version', 512, 'driver-1', 4
);
INSERT INTO leases (
  id, resource_kind, resource_id, lease_kind, owner_client_id,
  operation_id, fencing_token, incarnation, expires_at, created_at, updated_at
)
SELECT
  'copy-lease-1', 'operation', 'copy-operation-1', 'write', 'client-1',
  'copy-operation-1', 1, incarnation, unixepoch() + 60, unixepoch(), unixepoch()
FROM control_plane_state WHERE singleton = 1;
UPDATE operations
SET state = 'running', phase = 'transferring', revision = revision + 1, updated_at = 4
WHERE id = 'copy-operation-1';
INSERT INTO copy_publication_intents (
  operation_id, client_id, manifest_sha256, recovery_sha256,
  r2_storage_key, r2_version, sidecar_driver_id, sidecar_storage_key,
  expected_location_count, incarnation, lease_id, fencing_token,
  state, created_at, updated_at
)
SELECT
  'copy-operation-1', 'client-1',
  '3333333333333333333333333333333333333333333333333333333333333333',
  '9999999999999999999999999999999999999999999999999999999999999999',
  'manifests/99/recovery.json', 'copy-r2-version',
  'driver-1', 'manifests/99/sidecar.json', 0,
  incarnation, 'copy-lease-1', 1, 'staging', 4, 4
FROM control_plane_state WHERE singleton = 1;
UPDATE operations
SET state = 'verifying', phase = 'verifying', revision = revision + 1, updated_at = 4
WHERE id = 'copy-operation-1';
UPDATE operations
SET state = 'committing', phase = 'committing', revision = revision + 1, updated_at = 4
WHERE id = 'copy-operation-1';"

expect_failure \
  "UPDATE copy_publication_intents
   SET state = 'committed', committed_at = 4, updated_at = 4
   WHERE operation_id = 'copy-operation-1';" \
  "copy commit before its recovery head is visible"

execute "UPDATE leases SET fencing_token = 2, updated_at = 5 WHERE id = 'copy-lease-1';"

expect_failure \
  "UPDATE recovery_manifests
   SET recovery_sha256 = '9999999999999999999999999999999999999999999999999999999999999999',
       r2_storage_key = 'manifests/99/recovery.json', r2_version = 'copy-r2-version',
       sidecar_storage_key = 'manifests/99/sidecar.json', revision = revision + 1
   WHERE manifest_sha256 = '3333333333333333333333333333333333333333333333333333333333333333';" \
  "recovery head replacement through a superseded copy fence"

execute "
UPDATE copy_publication_intents SET fencing_token = 2, updated_at = 5
WHERE operation_id = 'copy-operation-1' AND state = 'staging';
UPDATE recovery_manifests
SET recovery_sha256 = '9999999999999999999999999999999999999999999999999999999999999999',
    r2_storage_key = 'manifests/99/recovery.json', r2_version = 'copy-r2-version',
    sidecar_storage_key = 'manifests/99/sidecar.json', revision = revision + 1, updated_at = 5
WHERE manifest_sha256 = '3333333333333333333333333333333333333333333333333333333333333333';
UPDATE copy_publication_intents SET state = 'committed', committed_at = 5, updated_at = 5
WHERE operation_id = 'copy-operation-1';
UPDATE operations
SET state = 'succeeded', phase = 'succeeded', revision = revision + 1,
    finished_at = 5, updated_at = 5
WHERE id = 'copy-operation-1';
UPDATE leases SET released_at = unixepoch(), updated_at = unixepoch()
WHERE id = 'copy-lease-1';
INSERT INTO protocol_assertions
SELECT recovery.recovery_sha256 =
         '9999999999999999999999999999999999999999999999999999999999999999'
       AND recovery.revision = 2
       AND publication.state = 'committed'
       AND operation.state = 'succeeded'
FROM recovery_manifests AS recovery
JOIN copy_intents AS copy ON copy.manifest_sha256 = recovery.manifest_sha256
JOIN copy_publication_intents AS publication ON publication.operation_id = copy.operation_id
JOIN operations AS operation ON operation.id = copy.operation_id
WHERE copy.operation_id = 'copy-operation-1';
PRAGMA foreign_key_check;"

expect_failure \
  "UPDATE recovery_manifests SET revision = revision + 1
   WHERE manifest_sha256 = '3333333333333333333333333333333333333333333333333333333333333333';" \
  "published recovery revision change without a new copy operation"

execute "
UPDATE locations
SET state = 'available', revision = revision + 1, updated_at = 6
WHERE id = 'location-1' AND state = 'verified';
INSERT INTO operations (
  id, namespace_id, kind, state, phase, idempotency_key, requested_by,
  incarnation, useful_bytes_total, created_at, updated_at
)
SELECT
  'verify-operation-1', '202122232425262728292a2b2c2d2e2f', 'verify',
  'planned', 'planned', 'verify-idempotency-1', 'client-1', incarnation, 24, 6, 6
FROM control_plane_state WHERE singleton = 1;
INSERT INTO verify_intents (
  operation_id, version_id, manifest_sha256, recovery_revision, driver_id, created_at
) VALUES (
  'verify-operation-1', 'version-1',
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  1, 'driver-1', 6
);
UPDATE operations
SET state = 'running', phase = 'verifying', revision = revision + 1, updated_at = 6
WHERE id = 'verify-operation-1';
INSERT INTO integrity_observations (
  operation_id, location_id, condition, evidence_json, observed_at
) VALUES (
  'verify-operation-1', 'location-1', 'verified',
  '{\"extent_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\"}',
  6
);
INSERT INTO protocol_assertions
SELECT intent.recovery_revision = 1
       AND observation.condition = 'verified'
FROM verify_intents AS intent
JOIN integrity_observations AS observation
  ON observation.operation_id = intent.operation_id
WHERE intent.operation_id = 'verify-operation-1';
PRAGMA foreign_key_check;"

expect_failure \
  "INSERT INTO integrity_observations (
     operation_id, location_id, condition, evidence_json, observed_at
   ) VALUES (
     'verify-operation-1', 'location-2', 'missing', '{}', 6
   );" \
  "verify observation outside the pinned available location set"
