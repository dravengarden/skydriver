use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use carrack_driver_contract::{DriverKind, GrantMode};
use serde::{Deserialize, Serialize};
use worker::{D1Database, Date, Env, Request, Response, Result, wasm_bindgen::JsValue};
use zeroize::Zeroize as _;

use crate::{
    driver_credentials, driver_registry,
    vfs_envelopes::{
        DirectoryEnvelopeRef, PLAINTEXT_SUITE, open_directory_key, open_driver_credential,
    },
    vfs_put, vfs_put_deletion,
    vfs_tokens::AuthenticatedVfsToken,
};

const KEY_GRANT_SCHEMA: &str = "carrack.vfs.directory-key-grant.v1";
const DRIVER_GRANT_SCHEMA: &str = "carrack.vfs.driver-grant.v1";
const PUT_DELETE_DRIVER_GRANT_SCHEMA: &str = "carrack.vfs.put-delete-driver-grant.v1";

#[derive(Deserialize)]
struct PutGrantRow {
    intent_id: String,
    filesystem_id: String,
    principal_id: String,
    directory_id: String,
    version_id: String,
    driver_id: String,
    storage_key: String,
    crypto_suite: String,
    key_epoch: u64,
    state: String,
    expires_at: u64,
    key_envelope_algorithm: Option<String>,
    key_master_version: Option<String>,
    key_nonce: Option<Vec<u8>>,
    key_ciphertext: Option<Vec<u8>>,
    driver_kind: String,
    driver_config_json: String,
    driver_revision: u64,
    credential_id: Option<String>,
    credential_algorithm: Option<String>,
    credential_key_version: Option<String>,
    credential_nonce: Option<Vec<u8>>,
    credential_ciphertext: Option<Vec<u8>>,
    credential_revision: Option<u64>,
    credential_expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct PutDeleteGrantRow {
    task_id: String,
    filesystem_id: String,
    driver_id: String,
    storage_key: String,
    driver_kind: String,
    driver_config_json: String,
    driver_revision: u64,
    lease_expires_at: u64,
    credential_id: Option<String>,
    credential_algorithm: Option<String>,
    credential_key_version: Option<String>,
    credential_nonce: Option<Vec<u8>>,
    credential_ciphertext: Option<Vec<u8>>,
    credential_revision: Option<u64>,
    credential_expires_at: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct R2MultipartGrantRequest {
    upload_id: String,
    first_part: u32,
    part_count: u32,
}

#[derive(Serialize)]
struct KeyGrantResponse {
    schema: &'static str,
    intent_id: String,
    directory_id: String,
    version_id: String,
    crypto_suite: String,
    key_epoch: u64,
    directory_key: Option<String>,
    expires_at: u64,
}

#[derive(Serialize)]
struct DriverGrantResponse {
    schema: &'static str,
    intent_id: String,
    driver_id: String,
    driver_kind: String,
    driver_revision: u64,
    config: serde_json::Value,
    credential: Option<serde_json::Value>,
    expires_at: u64,
}

#[derive(Serialize)]
struct PutDeleteDriverGrantResponse {
    schema: &'static str,
    task_id: String,
    driver_id: String,
    driver_kind: String,
    driver_revision: u64,
    config: serde_json::Value,
    credential: Option<serde_json::Value>,
    expires_at: u64,
}

/// Returns one authorized directory epoch secret for an immutable Put intent.
///
/// The caller derives the per-version file key locally. The grant is bounded
/// by the shorter token or intent expiry and is never cached by intermediaries.
pub(crate) async fn grant_put_key(
    env: &Env,
    token: &AuthenticatedVfsToken,
    intent_id: &str,
) -> Result<Response> {
    let database = env.d1("CARRACK_INDEX")?;
    let Some(context) = load_context(&database, intent_id).await? else {
        return Response::error("VFS put intent was not found", 404);
    };
    if !grant_allowed(&database, token, &context).await? {
        return Response::error("VFS directory-key grant is not authorized", 403);
    }

    let mut directory_key = if context.crypto_suite == PLAINTEXT_SUITE {
        None
    } else {
        let (algorithm, version, nonce, ciphertext) = directory_envelope(&context)?;
        Some(open_directory_key(
            env,
            &DirectoryEnvelopeRef {
                directory_id: &context.directory_id,
                key_epoch: context.key_epoch,
                crypto_suite: &context.crypto_suite,
                algorithm,
                master_key_version: version,
                nonce,
                ciphertext,
            },
        )?)
    };
    record_audit(
        &database,
        token,
        &context,
        "directory_key_granted",
        serde_json::json!({
            "intent_id": context.intent_id,
            "key_epoch": context.key_epoch,
            "version_id": context.version_id,
        }),
    )
    .await?;

    let encoded_key = directory_key
        .as_ref()
        .map(|key| URL_SAFE_NO_PAD.encode(key));
    if let Some(key) = directory_key.as_mut() {
        key.zeroize();
    }
    no_store(Response::from_json(&KeyGrantResponse {
        schema: KEY_GRANT_SCHEMA,
        intent_id: context.intent_id,
        directory_id: context.directory_id,
        version_id: context.version_id,
        crypto_suite: context.crypto_suite,
        key_epoch: context.key_epoch,
        directory_key: encoded_key,
        expires_at: context.expires_at.min(token.expires_at),
    })?)
}

/// Returns one authorized compiled-driver configuration and optional decrypted
/// credential for an immutable Put intent. The control plane does not open the
/// provider or relay payload bytes.
pub(crate) async fn grant_put_driver(
    env: &Env,
    token: &AuthenticatedVfsToken,
    intent_id: &str,
) -> Result<Response> {
    let database = env.d1("CARRACK_INDEX")?;
    let Some(mut context) = load_context(&database, intent_id).await? else {
        return Response::error("VFS put intent was not found", 404);
    };
    if !grant_allowed(&database, token, &context).await? {
        return Response::error("VFS driver grant is not authorized", 403);
    }
    // Authorization must precede provider I/O and credential-state mutation.
    if let Some(expires_at) = context.credential_expires_at
        && expires_at <= current_unix_seconds() + 5 * 60
    {
        if !driver_credentials::ensure_fresh(env, &context.driver_id, expires_at).await? {
            return Response::error("VFS driver credential requires reauthentication", 503);
        }
        let Some(reloaded) = load_context(&database, intent_id).await? else {
            return Response::error("VFS put intent changed during credential renewal", 409);
        };
        if !grant_allowed(&database, token, &reloaded).await? {
            return Response::error("VFS driver grant changed during credential renewal", 409);
        }
        context = reloaded;
    }
    let driver_kind = driver_registry::compiled_kind(&context.driver_kind)?;
    if driver_kind.grant_mode() == GrantMode::SignedObject && context.state != "prepared" {
        return Response::error("VFS Put is no longer uploadable", 409);
    }

    let config = serde_json::from_str::<serde_json::Value>(&context.driver_config_json).map_err(
        |error| {
            worker::Error::RustError(format!("decode stored VFS driver configuration: {error}"))
        },
    )?;
    let credential = decrypt_credential(
        env,
        &context,
        "PUT",
        context.expires_at.min(token.expires_at),
    )?;
    if driver_kind == DriverKind::R2V1 {
        database
            .prepare(
                "INSERT INTO vfs_r2_upload_cleanup_tasks (
                     intent_id, driver_revision, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(intent_id) DO NOTHING",
            )
            .bind(&[
                JsValue::from_str(&context.intent_id),
                JsValue::from_str(&context.driver_revision.to_string()),
                JsValue::from_str(&current_unix_seconds().to_string()),
            ])?
            .run()
            .await?;
    }
    record_audit(
        &database,
        token,
        &context,
        "driver_granted",
        serde_json::json!({
            "credential_present": credential.is_some(),
            "driver_id": context.driver_id,
            "driver_revision": context.driver_revision,
            "intent_id": context.intent_id,
        }),
    )
    .await?;

    no_store(Response::from_json(&DriverGrantResponse {
        schema: DRIVER_GRANT_SCHEMA,
        intent_id: context.intent_id,
        driver_id: context.driver_id,
        driver_kind: context.driver_kind,
        driver_revision: context.driver_revision,
        config,
        credential,
        expires_at: context.expires_at.min(token.expires_at),
    })?)
}

/// Signs one bounded batch of R2 multipart operations for an authorized Put.
///
/// The upload ID is provider-issued, while the object key, driver revision,
/// credential, expiry, and caller remain pinned to the immutable Put intent.
pub(crate) async fn grant_put_r2_multipart(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    intent_id: &str,
) -> Result<Response> {
    let requested = request.json::<R2MultipartGrantRequest>().await?;
    let database = env.d1("CARRACK_INDEX")?;
    let Some(context) = load_context(&database, intent_id).await? else {
        return Response::error("VFS put intent was not found", 404);
    };
    if !grant_allowed(&database, token, &context).await? {
        return Response::error("VFS multipart grant is not authorized", 403);
    }
    if context.state != "prepared" {
        return Response::error("VFS Put is no longer uploadable", 409);
    }
    if driver_registry::compiled_kind(&context.driver_kind)? != DriverKind::R2V1 {
        return Response::error("VFS driver does not support R2 multipart grants", 400);
    }
    let Some(credential_id) = context.credential_id.as_deref() else {
        return Response::error("R2 driver credential is absent", 409);
    };
    let (Some(algorithm), Some(version), Some(nonce), Some(ciphertext), Some(revision)) = (
        context.credential_algorithm.as_deref(),
        context.credential_key_version.as_deref(),
        context.credential_nonce.as_deref(),
        context.credential_ciphertext.as_deref(),
        context.credential_revision,
    ) else {
        return Err(worker::Error::RustError(
            "R2 driver credential envelope is incomplete".to_owned(),
        ));
    };
    let mut plaintext = open_driver_credential(
        env,
        credential_id,
        revision,
        algorithm,
        version,
        nonce,
        ciphertext,
    )?;
    let grant = driver_registry::project_multipart_grant(
        driver_registry::compiled_kind(&context.driver_kind)?,
        &driver_registry::MultipartGrantRequest {
            config_json: &context.driver_config_json,
            storage_key: &context.storage_key,
            plaintext: &plaintext,
            upload_id: &requested.upload_id,
            first_part: requested.first_part,
            part_count: requested.part_count,
            maximum_expires_at: context.expires_at.min(token.expires_at),
        },
    );
    plaintext.zeroize();
    let Ok(grant) = grant else {
        return Response::error("invalid R2 multipart grant request", 400);
    };
    let bound = database
        .prepare(
            "UPDATE vfs_r2_upload_cleanup_tasks
             SET upload_id = ?1, updated_at = ?2
             WHERE intent_id = ?3 AND state = 'active'
               AND (upload_id IS NULL OR upload_id = ?1)",
        )
        .bind(&[
            JsValue::from_str(&requested.upload_id),
            JsValue::from_str(&current_unix_seconds().to_string()),
            JsValue::from_str(&context.intent_id),
        ])?
        .run()
        .await?
        .meta()?
        .and_then(|metadata| metadata.changes)
        .unwrap_or_default();
    if bound != 1 {
        return Response::error("R2 multipart upload identity conflict", 409);
    }
    record_audit(
        &database,
        token,
        &context,
        "r2_multipart_granted",
        serde_json::json!({
            "first_part": requested.first_part,
            "part_count": requested.part_count,
            "intent_id": context.intent_id,
        }),
    )
    .await?;
    no_store(Response::from_json(&grant)?)
}

/// Returns the pinned compiled-driver configuration for a currently fenced
/// expired-upload deletion. A grant never authorizes a different driver
/// revision and expires no later than the claim lease.
pub(crate) async fn grant_put_delete_driver(
    env: &Env,
    token: &AuthenticatedVfsToken,
    task_id: &str,
) -> Result<Response> {
    let database = env.d1("CARRACK_INDEX")?;
    if !vfs_put_deletion::authorized(&database, token, task_id).await? {
        return Response::error("VFS put-delete driver grant is not authorized", 403);
    }
    let Some(mut context) = load_put_delete_context(&database, token, task_id).await? else {
        return Response::error("VFS put-delete task has no current safe fence", 409);
    };
    if let Some(expires_at) = context.credential_expires_at
        && expires_at <= current_unix_seconds() + 5 * 60
    {
        if !driver_credentials::ensure_fresh(env, &context.driver_id, expires_at).await? {
            return Response::error("VFS driver credential requires reauthentication", 503);
        }
        let Some(reloaded) = load_put_delete_context(&database, token, task_id).await? else {
            return Response::error(
                "VFS put-delete fence changed during credential renewal",
                409,
            );
        };
        context = reloaded;
    }
    let config = serde_json::from_str::<serde_json::Value>(&context.driver_config_json).map_err(
        |error| {
            worker::Error::RustError(format!("decode stored VFS driver configuration: {error}"))
        },
    )?;
    let credential = decrypt_put_delete_credential(
        env,
        &context,
        "DELETE",
        context.lease_expires_at.min(token.expires_at),
    )?;
    record_put_delete_audit(
        &database,
        token,
        &context,
        serde_json::json!({
            "credential_present": credential.is_some(),
            "driver_id": context.driver_id,
            "driver_revision": context.driver_revision,
        }),
    )
    .await?;

    no_store(Response::from_json(&PutDeleteDriverGrantResponse {
        schema: PUT_DELETE_DRIVER_GRANT_SCHEMA,
        task_id: context.task_id,
        driver_id: context.driver_id,
        driver_kind: context.driver_kind,
        driver_revision: context.driver_revision,
        config,
        credential,
        expires_at: context.lease_expires_at.min(token.expires_at),
    })?)
}

async fn grant_allowed(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    context: &PutGrantRow,
) -> Result<bool> {
    Ok(context.principal_id == token.principal_id
        && matches!(context.state.as_str(), "prepared" | "committed")
        && context.expires_at > current_unix_seconds()
        && vfs_put::authorized(database, token, &context.directory_id, &context.driver_id).await?)
}

fn directory_envelope(context: &PutGrantRow) -> Result<(&str, &str, &[u8], &[u8])> {
    match (
        context.key_envelope_algorithm.as_deref(),
        context.key_master_version.as_deref(),
        context.key_nonce.as_deref(),
        context.key_ciphertext.as_deref(),
    ) {
        (Some(algorithm), Some(version), Some(nonce), Some(ciphertext)) => {
            Ok((algorithm, version, nonce, ciphertext))
        }
        _ => Err(worker::Error::RustError(
            "encrypted VFS directory has no complete key envelope".to_owned(),
        )),
    }
}

fn decrypt_credential(
    env: &Env,
    context: &PutGrantRow,
    method: &str,
    expires_at: u64,
) -> Result<Option<serde_json::Value>> {
    let Some(credential_id) = context.credential_id.as_deref() else {
        return Ok(None);
    };
    let (Some(algorithm), Some(version), Some(nonce), Some(ciphertext), Some(revision)) = (
        context.credential_algorithm.as_deref(),
        context.credential_key_version.as_deref(),
        context.credential_nonce.as_deref(),
        context.credential_ciphertext.as_deref(),
        context.credential_revision,
    ) else {
        return Err(worker::Error::RustError(
            "VFS driver credential envelope is incomplete".to_owned(),
        ));
    };

    let mut plaintext = open_driver_credential(
        env,
        credential_id,
        revision,
        algorithm,
        version,
        nonce,
        ciphertext,
    )?;
    let kind = driver_registry::compiled_kind(&context.driver_kind)?;
    let decoded = driver_registry::project_access_grant(
        kind,
        method,
        &context.driver_config_json,
        &context.storage_key,
        &plaintext,
        expires_at,
    );
    plaintext.zeroize();
    Ok(Some(decoded?))
}

fn decrypt_put_delete_credential(
    env: &Env,
    context: &PutDeleteGrantRow,
    method: &str,
    expires_at: u64,
) -> Result<Option<serde_json::Value>> {
    let Some(credential_id) = context.credential_id.as_deref() else {
        return Ok(None);
    };
    let (Some(algorithm), Some(version), Some(nonce), Some(ciphertext), Some(revision)) = (
        context.credential_algorithm.as_deref(),
        context.credential_key_version.as_deref(),
        context.credential_nonce.as_deref(),
        context.credential_ciphertext.as_deref(),
        context.credential_revision,
    ) else {
        return Err(worker::Error::RustError(
            "VFS driver credential envelope is incomplete".to_owned(),
        ));
    };
    let mut plaintext = open_driver_credential(
        env,
        credential_id,
        revision,
        algorithm,
        version,
        nonce,
        ciphertext,
    )?;
    let kind = driver_registry::compiled_kind(&context.driver_kind)?;
    let decoded = driver_registry::project_access_grant(
        kind,
        method,
        &context.driver_config_json,
        &context.storage_key,
        &plaintext,
        expires_at,
    );
    plaintext.zeroize();
    Ok(Some(decoded?))
}

async fn load_context(database: &D1Database, intent_id: &str) -> Result<Option<PutGrantRow>> {
    database
        .prepare(
            "SELECT intent.id AS intent_id, intent.filesystem_id, intent.principal_id,\
                    intent.directory_id, intent.version_id, intent.driver_id, intent.storage_key,\
                    intent.crypto_suite, intent.key_epoch, intent.state, intent.expires_at,\
                    key_epoch.envelope_algorithm AS key_envelope_algorithm,\
                    key_epoch.master_key_version AS key_master_version,\
                    key_epoch.nonce AS key_nonce, key_epoch.ciphertext AS key_ciphertext,\
                    driver.kind AS driver_kind, driver.config_json AS driver_config_json,\
                    driver.revision AS driver_revision,\
                    credential.id AS credential_id,\
                    credential.envelope_algorithm AS credential_algorithm,\
                    credential.key_version AS credential_key_version,\
                    credential.nonce AS credential_nonce,\
                    credential.ciphertext AS credential_ciphertext,\
                    credential.revision AS credential_revision,\
                    credential.expires_at AS credential_expires_at \
             FROM vfs_put_intents AS intent \
             JOIN driver_instances AS driver ON driver.id = intent.driver_id \
             LEFT JOIN vfs_directory_key_epochs AS key_epoch \
               ON key_epoch.directory_id = intent.directory_id \
              AND key_epoch.key_epoch = intent.key_epoch \
              AND key_epoch.crypto_suite = intent.crypto_suite \
             LEFT JOIN credential_envelopes AS credential \
               ON credential.id = driver.credential_ref \
             WHERE intent.id = ?1",
        )
        .bind(&[JsValue::from_str(intent_id)])?
        .first::<PutGrantRow>(None)
        .await
}

async fn load_put_delete_context(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    task_id: &str,
) -> Result<Option<PutDeleteGrantRow>> {
    database
        .prepare(
            "SELECT task.id AS task_id, intent.filesystem_id,\
                    intent.driver_id, intent.storage_key, driver.kind AS driver_kind,\
                    driver.config_json AS driver_config_json,\
                    task.driver_revision, task.lease_expires_at,\
                    credential.id AS credential_id,\
                    credential.envelope_algorithm AS credential_algorithm,\
                    credential.key_version AS credential_key_version,\
                    credential.nonce AS credential_nonce,\
                    credential.ciphertext AS credential_ciphertext,\
                    credential.revision AS credential_revision,\
                    credential.expires_at AS credential_expires_at \
             FROM vfs_put_delete_tasks AS task \
             JOIN vfs_put_intents AS intent ON intent.id = task.id \
             JOIN driver_instances AS driver ON driver.id = intent.driver_id \
             LEFT JOIN credential_envelopes AS credential \
               ON credential.id = driver.credential_ref \
             WHERE task.id = ?1 AND task.state = 'claimed' \
               AND task.owner_token_id = ?2 AND task.lease_expires_at > ?3 \
               AND task.incarnation = (\
                   SELECT incarnation FROM control_plane_state WHERE singleton = 1\
               ) \
               AND driver.enabled = 1 AND driver.revision = task.driver_revision \
               AND task.id IN (SELECT id FROM safe_vfs_put_delete_tasks)",
        )
        .bind(&[
            JsValue::from_str(task_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&current_unix_seconds().to_string()),
        ])?
        .first::<PutDeleteGrantRow>(None)
        .await
}

async fn record_audit(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    context: &PutGrantRow,
    event_kind: &str,
    details: serde_json::Value,
) -> Result<()> {
    database
        .prepare(
            "INSERT INTO vfs_audit_events (\
                 filesystem_id, principal_id, token_id, event_kind, subject_kind,\
                 subject_id, details_json, created_at\
             ) VALUES (?1, ?2, ?3, ?4, 'put_intent', ?5, ?6, ?7)",
        )
        .bind(&[
            JsValue::from_str(&context.filesystem_id),
            JsValue::from_str(&token.principal_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(event_kind),
            JsValue::from_str(&context.intent_id),
            JsValue::from_str(&details.to_string()),
            JsValue::from_str(&current_unix_seconds().to_string()),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn record_put_delete_audit(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    context: &PutDeleteGrantRow,
    details: serde_json::Value,
) -> Result<()> {
    database
        .prepare(
            "INSERT INTO vfs_audit_events (\
                 filesystem_id, principal_id, token_id, event_kind, subject_kind,\
                 subject_id, details_json, created_at\
             ) VALUES (?1, ?2, ?3, 'put_delete_driver_granted',\
                       'put_delete_task', ?4, ?5, ?6)",
        )
        .bind(&[
            JsValue::from_str(&context.filesystem_id),
            JsValue::from_str(&token.principal_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&context.task_id),
            JsValue::from_str(&details.to_string()),
            JsValue::from_str(&current_unix_seconds().to_string()),
        ])?
        .run()
        .await?;
    Ok(())
}

fn no_store(mut response: Response) -> Result<Response> {
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    response.headers_mut().set("Pragma", "no-cache")?;
    Ok(response)
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}
