#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

dependency_manifests=(Cargo.toml Cargo.lock go.mod go.sum package.json pnpm-lock.yaml)
if rg --line-number --ignore-case \
  'github\.com/(OpenListTeam/)?OpenList|api\.oplist\.org|name = "openlist"' \
  "${dependency_manifests[@]}"; then
  echo "OpenList must not be a Carrack build or runtime dependency" >&2
  exit 1
fi

if rg --line-number \
  '"(aliyundrive-open/v2|r2/v1|local-filesystem/v2)"' \
  crates/carrack-client/src control-plane/src; then
  echo "driver wire kinds must have one source in carrack-driver-contract" >&2
  exit 1
fi
if rg --line-number \
  '^struct (AliyunConfig|AliyunDriveConfig|LocalFilesystemConfig|R2Config|Config)[[:space:]]*\{' \
  crates/carrack-client/src/aliyun.rs control-plane/src/r2_signing.rs \
  control-plane/src/management_driver_registration.rs \
  control-plane/src/vfs_provider_inventory.rs control-plane/src/vfs_server_lifecycle.rs; then
  echo "serialized driver configuration shapes must live in carrack-driver-contract" >&2
  exit 1
fi
if ! rg -q 'carrack-driver-contract' crates/carrack-client/Cargo.toml \
  || ! rg -q 'carrack-driver-contract' control-plane/Cargo.toml; then
  echo "native and control-plane registries must share carrack-driver-contract" >&2
  exit 1
fi
if rg --line-number 'carrack-driver-contract' crates/carrack-sdk-core/Cargo.toml; then
  echo "portable correctness core must remain independent of driver kinds" >&2
  exit 1
fi
if rg --line-number \
  '(^|[[:space:]])(reqwest|tokio|rusqlite|worker|cap-std|fs2|aes-gcm|hkdf|sha2)[[:space:]]*=' \
  crates/carrack-driver-contract/Cargo.toml; then
  echo "driver contract must remain free of I/O, runtime, database, provider, and crypto dependencies" >&2
  exit 1
fi

if rg --line-number --ignore-case \
  '(^|[[:space:]])(reqwest|tokio|rusqlite|worker|cap-std|fs2)[[:space:]]*=' \
  crates/carrack-sdk-core/Cargo.toml; then
  echo "carrack-sdk-core must remain free of I/O, runtime, database, and provider dependencies" >&2
  exit 1
fi

if rg --line-number \
  'carrack\.vfs\.(file\.(leaf|empty|node|root)|directory\.(file-entry|child-entry|empty|node|root)|block-manifest)\.v1' \
  crates/carrack-client/src control-plane/src web/src; then
  echo "portable integrity domains must be implemented only by carrack-sdk-core" >&2
  exit 1
fi

if ! rg -q 'carrack_sdk_core' control-plane/src/vfs_merkle.rs \
  || ! rg -q 'validate_block_manifest' control-plane/src/vfs_merkle.rs \
  || ! rg -q 'directory_merkle_root' control-plane/src/vfs_merkle.rs; then
  echo "the Worker Merkle adapter must delegate final validation to carrack-sdk-core" >&2
  exit 1
fi

if rg --line-number 'sha2|unicode_normalization|canonical_tree|domain_hasher' \
  control-plane/src/vfs_merkle.rs; then
  echo "the Worker Merkle adapter must not implement integrity algorithms" >&2
  exit 1
fi

if rg --line-number \
  'carrack\.vfs\.file-frame\.v1|carrack\.vfs\.file-key\.v1|encrypt_in_place_detached|decrypt_in_place_detached|Hkdf' \
  crates/carrack-client/src \
  || rg --line-number '^[[:space:]]*(aes-gcm|hkdf)[[:space:]]*=' \
    crates/carrack-client/Cargo.toml; then
  echo "native client I/O must delegate version key and frame cryptography to carrack-sdk-core" >&2
  exit 1
fi

if rg --line-number 'crate::(crypto|catalog|acceptance)' \
  crates/carrack-sdk-core/src/integrity.rs \
  || rg --line-number 'crate::(integrity|catalog|acceptance)' \
    crates/carrack-sdk-core/src/crypto.rs \
  || rg --line-number 'crate::(integrity|crypto|catalog|acceptance)' \
    crates/carrack-sdk-core/src/canonical.rs; then
  echo "portable core leaf modules must remain orthogonal" >&2
  exit 1
fi

core_modules=(acceptance canonical catalog crypto error integrity)
for core_module in "${core_modules[@]}"; do
  if ! test -f "crates/carrack-sdk-core/src/$core_module.rs"; then
    echo "required portable core module is missing: $core_module" >&2
    exit 1
  fi
done

if rg --line-number 'carrack-sdk-core|carrack-control-plane|reqwest' \
  crates/carrack-cli/Cargo.toml crates/carrack-cli/src; then
  echo "CLI binaries must remain thin carrack-client consumers" >&2
  exit 1
fi

if rg --line-number \
  'FileMerkle|DirectoryMerkle|BlockManifestExpectation|validate_block_manifest|directory_merkle_root' \
  crates/carrack-cli/src web/src; then
  echo "CLI and UI must not implement portable correctness rules" >&2
  exit 1
fi

if rg --line-number --ignore-case \
  'OpenListTeam|api\.oplist\.org|openlist' \
  crates/carrack-client/src crates/carrack-cli/src; then
  echo "native Rust clients must not link to or call OpenList" >&2
  exit 1
fi

driver_orchestrators=(
  crates/carrack-client/src/transfer.rs
  crates/carrack-client/src/download.rs
)
if rg --line-number \
  'aliyundrive-open/v2|r2/v1|local-filesystem/v2|crate::(aliyun|r2|local)::' \
  "${driver_orchestrators[@]}"; then
  echo "transfer orchestration must use the stable driver registry, not provider knowledge" >&2
  exit 1
fi
for driver_orchestrator in "${driver_orchestrators[@]}"; do
  if ! rg -q 'DriverRegistry' "$driver_orchestrator"; then
    echo "transfer orchestration must enter providers through DriverRegistry: $driver_orchestrator" >&2
    exit 1
  fi
done
if rg --line-number 'crate::driver|crate::(aliyun|r2|local)' crates/carrack-sdk-core/src; then
  echo "portable correctness modules must remain independent of native drivers" >&2
  exit 1
fi
if rg --line-number 'access_grant_from_plaintext' \
  control-plane/src/vfs_download.rs control-plane/src/vfs_grants.rs; then
  echo "VFS authorization modules must project provider authority through driver_registry" >&2
  exit 1
fi
if rg --line-number 'r2_signing::|multipart_grant_from_plaintext' \
  control-plane/src/vfs_grants.rs; then
  echo "VFS grant state machines must project provider authority through driver_registry" >&2
  exit 1
fi
if ! rg -q 'project_access_grant' control-plane/src/driver_registry.rs \
  || ! rg -q 'driver_registry::project_access_grant' control-plane/src/vfs_download.rs \
  || ! rg -q 'driver_registry::project_access_grant' control-plane/src/vfs_grants.rs; then
  echo "Worker object grants must use the stable control-plane driver registry" >&2
  exit 1
fi
if ! rg -q 'project_multipart_grant' control-plane/src/driver_registry.rs \
  || ! rg -q 'driver_registry::project_multipart_grant' control-plane/src/vfs_grants.rs; then
  echo "Worker multipart grants must use the stable control-plane driver registry" >&2
  exit 1
fi
if rg --line-number \
  'worker::\{[^}]*Fetch|Fetch::|RequestInit|Headers::|aliyun_post|delete_from_plaintext|cleanup_upload_from_plaintext|resume_multipart_upload|r2_signing::|AliyunCredential|AliyunDriveConfig|R2Config' \
  control-plane/src/vfs_provider_inventory.rs \
  control-plane/src/vfs_server_lifecycle.rs; then
  echo "VFS state machines must enter provider I/O through driver adapters" >&2
  exit 1
fi
if ! rg -q 'driver_inventory::list_page' control-plane/src/vfs_provider_inventory.rs \
  || ! rg -q 'driver_lifecycle::delete_object' control-plane/src/vfs_server_lifecycle.rs \
  || ! rg -q 'driver_lifecycle::cleanup_r2_upload' control-plane/src/vfs_server_lifecycle.rs; then
  echo "Worker inventory and lifecycle must use stable driver adapter boundaries" >&2
  exit 1
fi
if rg --line-number \
  'D1Database|\.prepare\(|SELECT |INSERT |UPDATE |DELETE FROM ' \
  control-plane/src/driver_authorization.rs control-plane/src/driver_configuration.rs \
  control-plane/src/driver_inventory.rs control-plane/src/driver_lifecycle.rs \
  control-plane/src/driver_renewal.rs; then
  echo "driver policy and provider adapters must not own D1 state, claims, fences, or publication" >&2
  exit 1
fi
if rg --line-number 'Fetch::|OPENLIST_RENEW_ENDPOINT|AliyunCredential|jwt_claims' \
  control-plane/src/driver_credentials.rs; then
  echo "credential state machines must not implement provider renewal protocols" >&2
  exit 1
fi
if ! rg -q 'driver_renewal::renew' control-plane/src/driver_credentials.rs; then
  echo "credential renewal must enter provider I/O through driver_renewal" >&2
  exit 1
fi
if ! rg -q "state = 'scanning' AND cursor IS" control-plane/src/vfs_provider_inventory.rs \
  || ! rg -q 'last_seen_generation <' control-plane/src/vfs_provider_inventory.rs; then
  echo "provider inventory publication must fence every page by generation and input cursor" >&2
  exit 1
fi
if ! rg -q 'provider_identity_mismatch' control-plane/src/vfs_server_lifecycle.rs \
  || ! rg -q '\.head\(&key\)' control-plane/src/driver_lifecycle.rs \
  || ! rg -q 'stat_from_plaintext' control-plane/src/driver_lifecycle.rs; then
  echo "hosted lifecycle must exact-Stat provider identity before Delete" >&2
  exit 1
fi
if rg -q 'remove_file\(&relative\)' crates/carrack-client/src/local.rs; then
  echo "native adapters must retain ambiguous provider objects for fenced lifecycle" >&2
  exit 1
fi
if rg --line-number 'management_driver_registration::' \
  control-plane/src/management_driver_configuration.rs \
  control-plane/src/management_driver_credentials.rs; then
  echo "management subsystems must share pure driver configuration policy, not registration transactions" >&2
  exit 1
fi
if ! rg -q 'driver_configuration::normalize' control-plane/src/management_driver_registration.rs \
  || ! rg -q 'driver_configuration::valid_stored' control-plane/src/management_driver_configuration.rs \
  || ! rg -q 'driver_configuration::valid_stored' control-plane/src/management_driver_credentials.rs; then
  echo "registration, credential, and enablement paths must share driver configuration policy" >&2
  exit 1
fi
if rg --line-number 'driver_credentials::|r2_signing::|CredentialAuthorization::' \
  control-plane/src/management_driver_credentials.rs; then
  echo "credential transactions must enter provider validation through driver_authorization" >&2
  exit 1
fi
if ! rg -q 'driver_authorization::validate' control-plane/src/management_driver_credentials.rs \
  || ! rg -q 'driver_authorization::authorize' control-plane/src/management_driver_credentials.rs; then
  echo "credential validation and apply must share the provider authorization adapter" >&2
  exit 1
fi
if ! rg -q 'driver_authorization::same_authority' control-plane/src/management_driver_credentials.rs; then
  echo "credential replacement must preserve the existing provider authority identity" >&2
  exit 1
fi

put_key_body="$(sed -n '/pub(crate) async fn grant_put_key(/,/pub(crate) async fn grant_put_driver(/p' control-plane/src/vfs_grants.rs)"
if rg -q 'ensure_fresh' <<<"$put_key_body"; then
  echo "directory-key grants must not depend on or mutate provider credential state" >&2
  exit 1
fi
put_driver_body="$(sed -n '/pub(crate) async fn grant_put_driver(/,/pub(crate) async fn grant_put_r2_multipart(/p' control-plane/src/vfs_grants.rs)"
put_driver_authorized_line="$(rg -n 'if !grant_allowed' <<<"$put_driver_body" | head -n1 | cut -d: -f1)"
put_driver_refresh_line="$(rg -n 'driver_credentials::ensure_fresh' <<<"$put_driver_body" | head -n1 | cut -d: -f1)"
if test -z "$put_driver_authorized_line" || test -z "$put_driver_refresh_line" \
  || test "$put_driver_authorized_line" -ge "$put_driver_refresh_line"; then
  echo "Put driver grants must authorize before provider credential renewal" >&2
  exit 1
fi
download_authorized_line="$(rg -n 'if !vfs_access::authorized' control-plane/src/vfs_download.rs | head -n1 | cut -d: -f1)"
download_refresh_line="$(rg -n 'driver_credentials::ensure_fresh' control-plane/src/vfs_download.rs | head -n1 | cut -d: -f1)"
if test -z "$download_authorized_line" || test -z "$download_refresh_line" \
  || test "$download_authorized_line" -ge "$download_refresh_line"; then
  echo "download planning must authorize before provider credential renewal" >&2
  exit 1
fi

if test -e cmd/carrack/main.go || test -e cmd/carrackctl/main.go; then
  echo "public Carrack CLIs must be the native Rust binaries" >&2
  exit 1
fi

legacy_go_paths=(archive cryptostream manifest provider sdk internal/cli driver/aliyundrive)
for legacy_path in "${legacy_go_paths[@]}"; do
  if test -d "$legacy_path" && find "$legacy_path" -type f -name '*.go' -print -quit | grep -q .; then
    echo "legacy Go archive code is forbidden under $legacy_path" >&2
    exit 1
  fi
done

if find transfer -maxdepth 1 -type f -name '*.go' -print -quit | grep -q .; then
  echo "only the V2 transfer/journal Go oracle may remain under transfer" >&2
  exit 1
fi

if rg --line-number \
  'github\.com/dravengarden/carrack/(archive|cryptostream|manifest|provider|sdk)(/|"|$)' \
  --glob '*.go' .; then
  echo "retained Go conformance packages must not import the removed archive stack" >&2
  exit 1
fi

legacy_schemas=(
  schemas/bundle.v1.schema.json
  schemas/bundle-plan.v1.schema.json
  schemas/manifest.v1.schema.json
  schemas/recovery-manifest.v1.schema.json
  schemas/crypto-v1-vectors.json
)
for legacy_schema in "${legacy_schemas[@]}"; do
  if test -e "$legacy_schema"; then
    echo "legacy archive schema is forbidden: $legacy_schema" >&2
    exit 1
  fi
done

legacy_rust_modules=(
  clients compaction copying garbage_collection integrity inventory key_grants keys
  manifest_archive manifests move_deletion moving operations protocol publication
  quarantine quarantine_deletion reconciliation repairing restoration telemetry verification
)
for legacy_module in "${legacy_rust_modules[@]}"; do
  if test -e "control-plane/src/$legacy_module.rs"; then
    echo "legacy archive Worker module is forbidden: $legacy_module" >&2
    exit 1
  fi
done

if rg --line-number \
  '/api/v1/|/api/(clients|client/session|summary|components/live|integrity/findings|recovery/)' \
  control-plane/src web/src; then
  echo "legacy archive HTTP routes are forbidden" >&2
  exit 1
fi

if ! rg -U -q \
  'FROM vfs_r2_upload_cleanup_tasks AS task\n\s+CROSS JOIN vfs_put_intents AS intent' \
  control-plane/src/management.rs; then
  echo "Activity must keep R2 cleanup as the indexed outer relation" >&2
  exit 1
fi
