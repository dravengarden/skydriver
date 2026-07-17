use std::fmt::Write as _;

use carrack_driver_contract::DriverKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{
    D1Database, D1PreparedStatement, Date, Env, Request, Response, Result, wasm_bindgen::JsValue,
};
use zeroize::Zeroize as _;

use crate::{
    environment_defaults,
    vfs_envelopes::{
        ENCRYPTED_SUITE, ENVELOPE_ALGORITHM, MASTER_KEY_VERSION, PLAINTEXT_SUITE, blob_binding,
        derive_bootstrap_token, seal_directory_key,
    },
    vfs_identifiers::new_uuid_v7_hex,
    vfs_merkle::directory_root,
    vfs_tokens::token_verifier,
};

const BOOTSTRAP_SCHEMA: &str = "carrack.vfs.bootstrap-receipt.v1";
const LOCAL_FILESYSTEM_KIND: &str = DriverKind::LocalFilesystemV2.as_str();
const DEFAULT_TOKEN_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
const MINIMUM_TOKEN_LIFETIME_SECONDS: u64 = 60 * 60;
const MAXIMUM_TOKEN_LIFETIME_SECONDS: u64 = 365 * 24 * 60 * 60;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_DRIVER_ID_BYTES: usize = 256;
const MAXIMUM_LOCAL_ROOT_BYTES: usize = 4_096;
const MAXIMUM_IDEMPOTENCY_BYTES: usize = 256;

const ACTIONS: [&str; 12] = [
    "directory.list",
    "content.read",
    "content.write",
    "entry.delete",
    "snapshot.publish",
    "acl.manage",
    "token.issue",
    "driver.use",
    "driver.manage",
    "gc.run",
    "audit.read",
    "system.manage",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRequest {
    filesystem_name: String,
    principal_display_name: String,
    local_driver_id: Option<String>,
    local_root: Option<String>,
    crypto_suite: Option<String>,
    token_lifetime_seconds: Option<u64>,
    idempotency_key: String,
}

#[derive(Serialize)]
struct BootstrapIdentity<'a> {
    filesystem_name: &'a str,
    principal_display_name: &'a str,
    local_driver_id: &'a str,
    local_root: &'a str,
    crypto_suite: &'a str,
    token_lifetime_seconds: u64,
    idempotency_key: &'a str,
}

#[derive(Serialize)]
struct EnvironmentBootstrapIdentity<'a> {
    filesystem_name: &'a str,
    principal_display_name: &'a str,
    driver_id: &'a str,
    crypto_suite: &'a str,
    token_lifetime_seconds: u64,
    idempotency_key: &'a str,
}

struct BootstrapDriver {
    id: String,
    kind: &'static str,
    config_json: String,
    create: bool,
    place: bool,
}

#[derive(Deserialize)]
struct BootstrapReceiptRow {
    idempotency_key: String,
    request_sha256: String,
    admin_subject: String,
    filesystem_id: String,
    principal_id: String,
    root_directory_id: String,
    token_id: String,
    driver_id: String,
    crypto_suite: String,
    key_epoch: u64,
    token_expires_at: u64,
}

#[derive(Serialize)]
struct BootstrapResponse {
    schema: &'static str,
    filesystem_id: String,
    principal_id: String,
    root_directory_id: String,
    token_id: String,
    driver_id: String,
    crypto_suite: String,
    key_epoch: u64,
    token_expires_at: u64,
    token: String,
}

/// Creates the first VFS root, administrator principal, local driver, key
/// epoch, ACL, and bearer token in one D1 batch.
///
/// The route is available only through an authenticated operator session and
/// the database accepts exactly one immutable bootstrap receipt. The bearer
/// token is deterministically derived from the Worker master key and request
/// identity, allowing an exact retry to recover a lost response without
/// storing bearer material in D1.
pub(crate) async fn bootstrap(
    request: &mut Request,
    env: &Env,
    admin_subject: &str,
) -> Result<Response> {
    let requested = request.json::<BootstrapRequest>().await?;
    let crypto_suite = requested.crypto_suite.as_deref().unwrap_or(ENCRYPTED_SUITE);
    let token_lifetime_seconds = requested
        .token_lifetime_seconds
        .unwrap_or(DEFAULT_TOKEN_LIFETIME_SECONDS);
    if !valid_request(&requested, crypto_suite, token_lifetime_seconds)
        || !valid_string(admin_subject, 128)
    {
        return Response::error("invalid VFS bootstrap request", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let now = current_unix_seconds();
    let Some(driver) = resolve_driver(env, &database, &requested, now).await? else {
        return Response::error("invalid VFS bootstrap driver selection", 400);
    };
    let request_digest =
        request_identity(&requested, &driver, crypto_suite, token_lifetime_seconds)?;
    let request_sha256 = lowercase_hex(&request_digest)?;

    if let Some(receipt) = load_receipt(&database).await? {
        return replay_response(
            env,
            receipt,
            admin_subject,
            &requested.idempotency_key,
            &request_sha256,
            &request_digest,
        );
    }

    let filesystem_id = new_uuid_v7_hex()?;
    let principal_id = new_uuid_v7_hex()?;
    let root_directory_id = new_uuid_v7_hex()?;
    let token_id = new_uuid_v7_hex()?;
    let empty_root = lowercase_hex(&directory_root(&[]).map_err(|error| {
        worker::Error::RustError(format!("compute empty VFS root: {error:?}"))
    })?)?;
    let token_expires_at = now.checked_add(token_lifetime_seconds).ok_or_else(|| {
        worker::Error::RustError("VFS bootstrap token expiry overflows".to_owned())
    })?;
    let token = derive_bootstrap_token(env, &request_digest, &requested.idempotency_key)?;
    let verifier = token_verifier(&token);
    let mut directory_key = [0_u8; 32];
    let envelope = if crypto_suite == ENCRYPTED_SUITE {
        getrandom::fill(&mut directory_key).map_err(|error| {
            worker::Error::RustError(format!("generate VFS directory key: {error}"))
        })?;
        Some(seal_directory_key(
            env,
            &root_directory_id,
            1,
            crypto_suite,
            &directory_key,
        )?)
    } else {
        None
    };
    directory_key.zeroize();

    let statements = bootstrap_statements(
        &database,
        &requested,
        &driver,
        admin_subject,
        crypto_suite,
        &request_sha256,
        &filesystem_id,
        &principal_id,
        &root_directory_id,
        &token_id,
        &verifier,
        &empty_root,
        envelope.as_ref(),
        now,
        token_expires_at,
    )?;
    let batch_result = database.batch(statements).await;

    let receipt = load_receipt(&database).await?;
    let Some(receipt) = receipt else {
        batch_result?;
        return Response::error("VFS bootstrap was not committed", 409);
    };

    replay_response(
        env,
        receipt,
        admin_subject,
        &requested.idempotency_key,
        &request_sha256,
        &request_digest,
    )
}

/// Re-derives the current unexpired bootstrap authority from immutable receipt
/// identity. The bearer remains absent from D1 and is returned only to an
/// explicitly reauthenticated operator recovery request.
pub(crate) async fn recover(env: &Env, admin_subject: &str) -> Result<Response> {
    let database = env.d1("CARRACK_INDEX")?;
    let Some(receipt) = load_receipt(&database).await? else {
        return Response::error("VFS has not been bootstrapped", 404);
    };
    if receipt.admin_subject != admin_subject {
        return Response::error("bootstrap authority subject mismatch", 403);
    }
    if receipt.token_expires_at <= current_unix_seconds() {
        return Response::error("bootstrap authority has expired", 409);
    }
    let digest = hex::decode(&receipt.request_sha256)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| worker::Error::RustError("invalid bootstrap receipt digest".to_owned()))?;
    let token = derive_bootstrap_token(env, &digest, &receipt.idempotency_key)?;
    let stored_verifier = database
        .prepare("SELECT verifier_sha256 FROM vfs_token_verifiers WHERE id = ?1")
        .bind(&[JsValue::from_str(&receipt.token_id)])?
        .first::<String>(Some("verifier_sha256"))
        .await?;
    if stored_verifier.as_deref() != Some(&token_verifier(&token)) {
        return Err(worker::Error::RustError(
            "bootstrap authority master key does not match the immutable receipt".to_owned(),
        ));
    }
    let now = current_unix_seconds();
    database
        .prepare(
            "INSERT INTO vfs_audit_events (
                 filesystem_id, principal_id, token_id, event_kind, subject_kind,
                 subject_id, details_json, created_at
             ) VALUES (?1, ?2, ?3, 'bootstrap_authority_recovered', 'token', ?3, ?4, ?5)",
        )
        .bind(&[
            JsValue::from_str(&receipt.filesystem_id),
            JsValue::from_str(&receipt.principal_id),
            JsValue::from_str(&receipt.token_id),
            JsValue::from_str(&serde_json::json!({ "admin_subject": admin_subject }).to_string()),
            number_binding(now),
        ])?
        .run()
        .await?;
    let mut response = Response::from_json(&BootstrapResponse {
        schema: BOOTSTRAP_SCHEMA,
        filesystem_id: receipt.filesystem_id,
        principal_id: receipt.principal_id,
        root_directory_id: receipt.root_directory_id,
        token_id: receipt.token_id,
        driver_id: receipt.driver_id,
        crypto_suite: receipt.crypto_suite,
        key_epoch: receipt.key_epoch,
        token_expires_at: receipt.token_expires_at,
        token,
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    response.headers_mut().set("Pragma", "no-cache")?;
    Ok(response)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the one-shot bootstrap transaction is intentionally visible as one statement set"
)]
fn bootstrap_statements(
    database: &D1Database,
    requested: &BootstrapRequest,
    driver: &BootstrapDriver,
    admin_subject: &str,
    crypto_suite: &str,
    request_sha256: &str,
    filesystem_id: &str,
    principal_id: &str,
    root_directory_id: &str,
    token_id: &str,
    verifier: &str,
    empty_root: &str,
    envelope: Option<&crate::vfs_envelopes::SealedEnvelope>,
    now: u64,
    token_expires_at: u64,
) -> Result<Vec<D1PreparedStatement>> {
    let mut statements = vec![
        database
            .prepare(
                "INSERT INTO vfs_filesystems (id, name, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?3)",
            )
            .bind(&[
                JsValue::from_str(filesystem_id),
                JsValue::from_str(&requested.filesystem_name),
                number_binding(now),
            ])?,
        database
            .prepare(
                "INSERT INTO vfs_principals (\
                     id, kind, display_name, created_at, updated_at\
                 ) VALUES (?1, 'human', ?2, ?3, ?3)",
            )
            .bind(&[
                JsValue::from_str(principal_id),
                JsValue::from_str(&requested.principal_display_name),
                number_binding(now),
            ])?,
        database
            .prepare(
                "INSERT INTO vfs_directories (\
                     id, filesystem_id, parent_id, name, data_root, crypto_suite,\
                     active_key_epoch, acl_inherits, created_at, updated_at\
                 ) VALUES (?1, ?2, NULL, '', ?3, ?4, 1, 0, ?5, ?5)",
            )
            .bind(&[
                JsValue::from_str(root_directory_id),
                JsValue::from_str(filesystem_id),
                JsValue::from_str(empty_root),
                JsValue::from_str(crypto_suite),
                number_binding(now),
            ])?,
    ];

    statements.push(directory_key_statement(
        database,
        root_directory_id,
        principal_id,
        crypto_suite,
        envelope,
        now,
    )?);
    if driver.create {
        statements.push(
            database
                .prepare(
                    "INSERT INTO driver_instances (\
                         id, kind, config_json, credential_ref, created_at, updated_at,\
                         lifecycle_owner\
                     ) VALUES (?1, ?2, ?3, NULL, ?4, ?4, 'legacy-bootstrap')",
                )
                .bind(&[
                    JsValue::from_str(&driver.id),
                    JsValue::from_str(driver.kind),
                    JsValue::from_str(&driver.config_json),
                    number_binding(now),
                ])?,
        );
    }
    if driver.place {
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_directory_drivers (\
                         directory_id, driver_id, write_priority, created_by,\
                         created_at, updated_at\
                     ) VALUES (?1, ?2, 0, ?3, ?4, ?4)",
                )
                .bind(&[
                    JsValue::from_str(root_directory_id),
                    JsValue::from_str(&driver.id),
                    JsValue::from_str(principal_id),
                    number_binding(now),
                ])?,
        );
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_directory_mounts (
                         directory_id, driver_id, kind, created_by, created_at
                     ) VALUES (?1, ?2, 'default', ?3, ?4)",
                )
                .bind(&[
                    JsValue::from_str(root_directory_id),
                    JsValue::from_str(&driver.id),
                    JsValue::from_str(principal_id),
                    number_binding(now),
                ])?,
        );
    }

    for action in ACTIONS {
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_acl_grants (\
                         id, directory_id, principal_id, action, created_by, created_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?3, ?5)",
                )
                .bind(&[
                    JsValue::from_str(&new_uuid_v7_hex()?),
                    JsValue::from_str(root_directory_id),
                    JsValue::from_str(principal_id),
                    JsValue::from_str(action),
                    number_binding(now),
                ])?,
        );
    }

    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_token_verifiers (\
                     id, principal_id, root_directory_id, verifier_sha256,\
                     expires_at, issued_by, created_at\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?2, ?6)",
            )
            .bind(&[
                JsValue::from_str(token_id),
                JsValue::from_str(principal_id),
                JsValue::from_str(root_directory_id),
                JsValue::from_str(verifier),
                number_binding(token_expires_at),
                number_binding(now),
            ])?,
    );
    for action in ACTIONS {
        statements.push(
            database
                .prepare("INSERT INTO vfs_token_actions (token_id, action) VALUES (?1, ?2)")
                .bind(&[JsValue::from_str(token_id), JsValue::from_str(action)])?,
        );
    }
    statements.push(
        database
            .prepare("UPDATE vfs_token_verifiers SET sealed_at = ?2 WHERE id = ?1")
            .bind(&[JsValue::from_str(token_id), number_binding(now)])?,
    );

    let audit_details = serde_json::json!({
        "admin_subject": admin_subject,
        "crypto_suite": crypto_suite,
        "driver_id": driver.id,
    })
    .to_string();
    statements.extend([
        database
            .prepare(
                "INSERT INTO vfs_audit_events (\
                     filesystem_id, principal_id, token_id, event_kind, subject_kind,\
                     subject_id, details_json, created_at\
                 ) VALUES (?1, ?2, ?3, 'filesystem_bootstrapped', 'filesystem', ?1, ?4, ?5)",
            )
            .bind(&[
                JsValue::from_str(filesystem_id),
                JsValue::from_str(principal_id),
                JsValue::from_str(token_id),
                JsValue::from_str(&audit_details),
                number_binding(now),
            ])?,
        database
            .prepare(
                "INSERT INTO vfs_bootstrap_receipts (\
                     singleton, idempotency_key, request_sha256, admin_subject,\
                     filesystem_id, principal_id, root_directory_id, token_id,\
                     driver_id, crypto_suite, key_epoch, token_expires_at, created_at\
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11)",
            )
            .bind(&[
                JsValue::from_str(&requested.idempotency_key),
                JsValue::from_str(request_sha256),
                JsValue::from_str(admin_subject),
                JsValue::from_str(filesystem_id),
                JsValue::from_str(principal_id),
                JsValue::from_str(root_directory_id),
                JsValue::from_str(token_id),
                JsValue::from_str(&driver.id),
                JsValue::from_str(crypto_suite),
                number_binding(token_expires_at),
                number_binding(now),
            ])?,
    ]);

    Ok(statements)
}

fn directory_key_statement(
    database: &D1Database,
    directory_id: &str,
    principal_id: &str,
    crypto_suite: &str,
    envelope: Option<&crate::vfs_envelopes::SealedEnvelope>,
    now: u64,
) -> Result<D1PreparedStatement> {
    if crypto_suite == PLAINTEXT_SUITE {
        return database
            .prepare(
                "INSERT INTO vfs_directory_key_epochs (\
                     directory_id, key_epoch, crypto_suite, created_by, created_at\
                 ) VALUES (?1, 1, ?2, ?3, ?4)",
            )
            .bind(&[
                JsValue::from_str(directory_id),
                JsValue::from_str(crypto_suite),
                JsValue::from_str(principal_id),
                number_binding(now),
            ]);
    }

    let envelope = envelope.ok_or_else(|| {
        worker::Error::RustError("encrypted VFS bootstrap omitted its key envelope".to_owned())
    })?;
    database
        .prepare(
            "INSERT INTO vfs_directory_key_epochs (\
                 directory_id, key_epoch, crypto_suite, envelope_algorithm,\
                 master_key_version, nonce, ciphertext, created_by, created_at\
             ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&[
            JsValue::from_str(directory_id),
            JsValue::from_str(crypto_suite),
            JsValue::from_str(ENVELOPE_ALGORITHM),
            JsValue::from_str(MASTER_KEY_VERSION),
            blob_binding(&envelope.nonce),
            blob_binding(&envelope.ciphertext),
            JsValue::from_str(principal_id),
            number_binding(now),
        ])
}

async fn load_receipt(database: &D1Database) -> Result<Option<BootstrapReceiptRow>> {
    database
        .prepare(
            "SELECT idempotency_key, request_sha256, admin_subject, filesystem_id,\
                    principal_id, root_directory_id, token_id, driver_id,\
                    crypto_suite, key_epoch, token_expires_at \
             FROM vfs_bootstrap_receipts WHERE singleton = 1",
        )
        .first::<BootstrapReceiptRow>(None)
        .await
}

fn replay_response(
    env: &Env,
    receipt: BootstrapReceiptRow,
    admin_subject: &str,
    idempotency_key: &str,
    request_sha256: &str,
    request_digest: &[u8; 32],
) -> Result<Response> {
    if receipt.admin_subject != admin_subject
        || receipt.idempotency_key != idempotency_key
        || receipt.request_sha256 != request_sha256
    {
        return Response::error("VFS has already been bootstrapped", 409);
    }

    let token = derive_bootstrap_token(env, request_digest, idempotency_key)?;
    let mut response = Response::from_json(&BootstrapResponse {
        schema: BOOTSTRAP_SCHEMA,
        filesystem_id: receipt.filesystem_id,
        principal_id: receipt.principal_id,
        root_directory_id: receipt.root_directory_id,
        token_id: receipt.token_id,
        driver_id: receipt.driver_id,
        crypto_suite: receipt.crypto_suite,
        key_epoch: receipt.key_epoch,
        token_expires_at: receipt.token_expires_at,
        token,
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    response.headers_mut().set("Pragma", "no-cache")?;
    Ok(response)
}

fn valid_request(
    request: &BootstrapRequest,
    crypto_suite: &str,
    token_lifetime_seconds: u64,
) -> bool {
    let valid_driver = match (&request.local_driver_id, &request.local_root) {
        (Some(driver_id), Some(root)) => {
            valid_string(driver_id, MAXIMUM_DRIVER_ID_BYTES) && valid_local_root(root)
        }
        (None, None) => true,
        _ => false,
    };
    valid_string(&request.filesystem_name, MAXIMUM_NAME_BYTES)
        && valid_string(&request.principal_display_name, MAXIMUM_NAME_BYTES)
        && valid_driver
        && matches!(crypto_suite, ENCRYPTED_SUITE | PLAINTEXT_SUITE)
        && (MINIMUM_TOKEN_LIFETIME_SECONDS..=MAXIMUM_TOKEN_LIFETIME_SECONDS)
            .contains(&token_lifetime_seconds)
        && valid_string(&request.idempotency_key, MAXIMUM_IDEMPOTENCY_BYTES)
}

fn valid_local_root(root: &str) -> bool {
    root.starts_with('/')
        && root.len() <= MAXIMUM_LOCAL_ROOT_BYTES
        && !root.contains('\0')
        && (root == "/" || !root.ends_with('/'))
        && !root
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

async fn resolve_driver(
    env: &Env,
    database: &D1Database,
    requested: &BootstrapRequest,
    now: u64,
) -> Result<Option<BootstrapDriver>> {
    match (&requested.local_driver_id, &requested.local_root) {
        (Some(driver_id), Some(root)) => Ok(Some(BootstrapDriver {
            id: driver_id.clone(),
            kind: LOCAL_FILESYSTEM_KIND,
            config_json: serde_json::json!({ "root": root }).to_string(),
            create: true,
            place: true,
        })),
        (None, None) => {
            environment_defaults::ensure(env, database, now).await?;
            let Some(config) = environment_defaults::configured_r2(env)? else {
                return Ok(None);
            };
            Ok(Some(BootstrapDriver {
                id: environment_defaults::DEFAULT_R2_DRIVER_ID.to_owned(),
                kind: DriverKind::R2V1.as_str(),
                config_json: serde_json::to_string(&config)?,
                create: false,
                place: true,
            }))
        }
        _ => Ok(None),
    }
}

fn request_identity(
    requested: &BootstrapRequest,
    driver: &BootstrapDriver,
    crypto_suite: &str,
    token_lifetime_seconds: u64,
) -> Result<[u8; 32]> {
    let (domain, encoded) = if driver.kind == LOCAL_FILESYSTEM_KIND {
        let (Some(local_driver_id), Some(local_root)) = (
            requested.local_driver_id.as_deref(),
            requested.local_root.as_deref(),
        ) else {
            return Err(worker::Error::RustError(
                "local bootstrap identity is incomplete".to_owned(),
            ));
        };
        let identity = BootstrapIdentity {
            filesystem_name: &requested.filesystem_name,
            principal_display_name: &requested.principal_display_name,
            local_driver_id,
            local_root,
            crypto_suite,
            token_lifetime_seconds,
            idempotency_key: &requested.idempotency_key,
        };
        (
            b"carrack.vfs.bootstrap.v1\0".as_slice(),
            serde_json::to_vec(&identity)?,
        )
    } else {
        let identity = EnvironmentBootstrapIdentity {
            filesystem_name: &requested.filesystem_name,
            principal_display_name: &requested.principal_display_name,
            driver_id: &driver.id,
            crypto_suite,
            token_lifetime_seconds,
            idempotency_key: &requested.idempotency_key,
        };
        (
            b"carrack.vfs.bootstrap.environment.v2\0".as_slice(),
            serde_json::to_vec(&identity)?,
        )
    };
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn lowercase_hex(bytes: &[u8]) -> Result<String> {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}")
            .map_err(|error| worker::Error::RustError(format!("encode VFS digest: {error}")))?;
    }
    Ok(encoded)
}

fn number_binding(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> BootstrapRequest {
        BootstrapRequest {
            filesystem_name: "Carrack".to_owned(),
            principal_display_name: "Operator".to_owned(),
            local_driver_id: Some("local-main".to_owned()),
            local_root: Some("/srv/carrack".to_owned()),
            crypto_suite: None,
            token_lifetime_seconds: None,
            idempotency_key: "bootstrap-production-v1".to_owned(),
        }
    }

    #[test]
    fn validates_default_encrypted_bootstrap() {
        let request = request();
        assert!(valid_request(
            &request,
            ENCRYPTED_SUITE,
            DEFAULT_TOKEN_LIFETIME_SECONDS
        ));
    }

    #[test]
    fn rejects_ambiguous_or_relative_local_roots() {
        for root in ["relative", "/srv/../secret", "/srv/carrack/"] {
            let request = BootstrapRequest {
                local_root: Some(root.to_owned()),
                ..request()
            };
            assert!(!valid_request(
                &request,
                ENCRYPTED_SUITE,
                DEFAULT_TOKEN_LIFETIME_SECONDS
            ));
        }
        let request = BootstrapRequest {
            local_root: None,
            ..request()
        };
        assert!(!valid_request(
            &request,
            ENCRYPTED_SUITE,
            DEFAULT_TOKEN_LIFETIME_SECONDS
        ));
    }

    #[test]
    fn accepts_environment_driver_selection() {
        let request = BootstrapRequest {
            local_driver_id: None,
            local_root: None,
            ..request()
        };
        assert!(valid_request(
            &request,
            ENCRYPTED_SUITE,
            DEFAULT_TOKEN_LIFETIME_SECONDS
        ));
    }

    #[test]
    fn bootstrap_identity_includes_normalized_defaults() {
        let request = request();
        let driver = BootstrapDriver {
            id: "local-main".to_owned(),
            kind: LOCAL_FILESYSTEM_KIND,
            config_json: r#"{"root":"/srv/carrack"}"#.to_owned(),
            create: true,
            place: true,
        };
        let first = request_identity(
            &request,
            &driver,
            ENCRYPTED_SUITE,
            DEFAULT_TOKEN_LIFETIME_SECONDS,
        )
        .expect("hash bootstrap");
        let second = request_identity(
            &request,
            &driver,
            ENCRYPTED_SUITE,
            DEFAULT_TOKEN_LIFETIME_SECONDS,
        )
        .expect("rehash bootstrap");
        assert_eq!(first, second);
        assert_ne!(first, [0; 32]);
        assert_eq!(
            lowercase_hex(&first).expect("encode digest"),
            "f9d269ed0033a26536b360960738a6d80e782e870cdc336b61db8cb7c85b9450"
        );
    }
}
