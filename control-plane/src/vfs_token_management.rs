use std::{collections::BTreeSet, fmt::Write as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{
    D1Database, D1PreparedStatement, Date, Env, Request, Response, Result, wasm_bindgen::JsValue,
};

use skydriver_sdk_core::VFS_ACTIONS as ACTIONS;

use crate::{
    vfs_access,
    vfs_envelopes::derive_child_token,
    vfs_identifiers::new_uuid_v7_hex,
    vfs_tokens::{AuthenticatedVfsToken, token_verifier},
};

const TOKEN_ISSUE_SCHEMA: &str = "carrack.vfs.token-issue-receipt.v1";
const TOKEN_REVOKE_SCHEMA: &str = "carrack.vfs.token-revoke-receipt.v1";
const MINIMUM_TOKEN_LIFETIME_SECONDS: u64 = 60;
const MAXIMUM_IDEMPOTENCY_BYTES: usize = 256;
const MAXIMUM_DRIVER_ID_BYTES: usize = 256;
const MAXIMUM_DRIVER_SCOPE: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueTokenRequest {
    root_directory_id: String,
    actions: Vec<String>,
    driver_ids: Option<Vec<String>>,
    expires_at: u64,
    idempotency_key: String,
}

#[derive(Serialize)]
struct IssueTokenIdentity<'a> {
    root_directory_id: &'a str,
    actions: &'a [String],
    driver_ids: Option<&'a [String]>,
    expires_at: u64,
    idempotency_key: &'a str,
}

#[derive(Deserialize)]
struct TokenIssueReceiptRow {
    request_sha256: String,
    principal_id: String,
    root_directory_id: String,
    token_id: String,
    actions_json: String,
    driver_ids_json: Option<String>,
    expires_at: u64,
    verifier_sha256: String,
}

#[derive(Serialize)]
struct IssueTokenResponse {
    schema: &'static str,
    token_id: String,
    principal_id: String,
    parent_token_id: String,
    root_directory_id: String,
    actions: Vec<String>,
    driver_ids: Option<Vec<String>>,
    expires_at: u64,
    token: String,
}

#[derive(Deserialize)]
struct TokenScopeRow {
    snapshot_id: Option<String>,
}

#[derive(Deserialize)]
struct StringRow {
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeTokenRequest {
    idempotency_key: String,
}

#[derive(Serialize)]
struct RevokeTokenIdentity<'a> {
    target_token_id: &'a str,
    idempotency_key: &'a str,
}

#[derive(Deserialize)]
struct TargetTokenRow {
    principal_id: String,
    root_directory_id: String,
    revoked_at: Option<u64>,
}

#[derive(Deserialize)]
struct TokenRevokeReceiptRow {
    request_sha256: String,
    principal_id: String,
    target_token_id: String,
    root_directory_id: String,
    revoked_at: u64,
}

#[derive(Serialize)]
struct RevokeTokenResponse {
    schema: &'static str,
    token_id: String,
    principal_id: String,
    root_directory_id: String,
    revoked_at: u64,
    state: &'static str,
}

/// Issues one same-principal child token whose directory, actions, drivers,
/// and expiry can only narrow the authenticated parent.
pub(crate) async fn issue(
    request: &mut Request,
    env: &Env,
    parent: &AuthenticatedVfsToken,
) -> Result<Response> {
    let mut requested = request.json::<IssueTokenRequest>().await?;
    canonicalize_strings(&mut requested.actions);
    if let Some(driver_ids) = &mut requested.driver_ids {
        canonicalize_strings(driver_ids);
    }
    if !valid_issue_request(&requested) {
        return Response::error("invalid VFS token issue request", 400);
    }

    let identity = IssueTokenIdentity {
        root_directory_id: &requested.root_directory_id,
        actions: &requested.actions,
        driver_ids: requested.driver_ids.as_deref(),
        expires_at: requested.expires_at,
        idempotency_key: &requested.idempotency_key,
    };
    let request_digest = request_identity(b"carrack.vfs.token-issue.v1\0", &identity)?;
    let request_sha256 = lowercase_hex(&request_digest)?;
    let database = env.d1("SKYDRIVER_INDEX")?;

    if !vfs_access::authorized(
        &database,
        parent,
        &requested.root_directory_id,
        "token.issue",
    )
    .await?
    {
        return Response::error("VFS token-issue authority required", 403);
    }

    let now = current_unix_seconds();
    if requested.expires_at < now.saturating_add(MINIMUM_TOKEN_LIFETIME_SECONDS)
        || requested.expires_at > parent.expires_at
    {
        return Response::error("VFS child-token expiry is outside its parent", 400);
    }
    if !scope_narrows_parent(&database, parent, &requested).await? {
        return Response::error("VFS child token would widen its parent", 400);
    }

    if let Some(receipt) =
        load_issue_receipt(&database, &parent.id, &requested.idempotency_key).await?
    {
        return issue_response(
            env,
            parent,
            receipt,
            &request_sha256,
            &request_digest,
            &requested.idempotency_key,
        );
    }

    if let Some(driver_ids) = &requested.driver_ids
        && !all_drivers_enabled(&database, driver_ids).await?
    {
        return Response::error("VFS child token references an unavailable driver", 400);
    }

    let token_id = new_uuid_v7_hex()?;
    let bearer = derive_child_token(env, &parent.id, &request_digest, &requested.idempotency_key)?;
    let verifier = token_verifier(&bearer);
    let statements = issue_statements(
        &database,
        parent,
        &requested,
        &request_sha256,
        &token_id,
        &verifier,
        now,
    )?;
    let batch_result = database.batch(statements).await;

    if let Some(receipt) =
        load_issue_receipt(&database, &parent.id, &requested.idempotency_key).await?
    {
        return issue_response(
            env,
            parent,
            receipt,
            &request_sha256,
            &request_digest,
            &requested.idempotency_key,
        );
    }

    if let Err(error) = batch_result {
        worker::console_warn!("VFS child-token transaction conflicted: {error:?}");
    }
    Response::error(
        "VFS token issuance conflicted; retry the exact request",
        409,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the issuance transaction intentionally exposes every immutable row"
)]
fn issue_statements(
    database: &D1Database,
    parent: &AuthenticatedVfsToken,
    requested: &IssueTokenRequest,
    request_sha256: &str,
    token_id: &str,
    verifier: &str,
    now: u64,
) -> Result<Vec<D1PreparedStatement>> {
    let actions_json = serde_json::to_string(&requested.actions)?;
    let driver_ids_json = requested
        .driver_ids
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let mut statements = vec![
        database
            .prepare(
                "INSERT INTO vfs_token_verifiers (
                     id, principal_id, root_directory_id, parent_token_id,
                     verifier_sha256, expires_at, issued_by, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?2, ?7)",
            )
            .bind(&[
                JsValue::from_str(token_id),
                JsValue::from_str(&parent.principal_id),
                JsValue::from_str(&requested.root_directory_id),
                JsValue::from_str(&parent.id),
                JsValue::from_str(verifier),
                number_binding(requested.expires_at),
                number_binding(now),
            ])?,
    ];

    for action in &requested.actions {
        statements.push(
            database
                .prepare("INSERT INTO vfs_token_actions (token_id, action) VALUES (?1, ?2)")
                .bind(&[JsValue::from_str(token_id), JsValue::from_str(action)])?,
        );
    }
    if let Some(driver_ids) = &requested.driver_ids {
        for driver_id in driver_ids {
            statements.push(
                database
                    .prepare("INSERT INTO vfs_token_drivers (token_id, driver_id) VALUES (?1, ?2)")
                    .bind(&[JsValue::from_str(token_id), JsValue::from_str(driver_id)])?,
            );
        }
    }
    statements.push(
        database
            .prepare("UPDATE vfs_token_verifiers SET sealed_at = ?2 WHERE id = ?1")
            .bind(&[JsValue::from_str(token_id), number_binding(now)])?,
    );

    let audit_details = serde_json::json!({
        "actions": requested.actions,
        "driver_ids": requested.driver_ids,
        "expires_at": requested.expires_at,
        "parent_token_id": parent.id,
        "root_directory_id": requested.root_directory_id,
    })
    .to_string();
    statements.extend([
        database
            .prepare(
                "INSERT INTO vfs_audit_events (
                     filesystem_id, principal_id, token_id, event_kind,
                     subject_kind, subject_id, details_json, created_at
                 )
                 SELECT directory.filesystem_id, ?1, ?2, 'token_issued',
                        'token', ?3, ?4, ?5
                 FROM vfs_directories AS directory WHERE directory.id = ?6",
            )
            .bind(&[
                JsValue::from_str(&parent.principal_id),
                JsValue::from_str(&parent.id),
                JsValue::from_str(token_id),
                JsValue::from_str(&audit_details),
                number_binding(now),
                JsValue::from_str(&requested.root_directory_id),
            ])?,
        database
            .prepare(
                "INSERT INTO vfs_token_issue_receipts (
                     parent_token_id, idempotency_key, request_sha256,
                     principal_id, root_directory_id, token_id, actions_json,
                     driver_ids_json, snapshot_id, expires_at, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10)",
            )
            .bind(&[
                JsValue::from_str(&parent.id),
                JsValue::from_str(&requested.idempotency_key),
                JsValue::from_str(request_sha256),
                JsValue::from_str(&parent.principal_id),
                JsValue::from_str(&requested.root_directory_id),
                JsValue::from_str(token_id),
                JsValue::from_str(&actions_json),
                optional_string_binding(driver_ids_json.as_deref()),
                number_binding(requested.expires_at),
                number_binding(now),
            ])?,
    ]);

    Ok(statements)
}

async fn scope_narrows_parent(
    database: &D1Database,
    parent: &AuthenticatedVfsToken,
    requested: &IssueTokenRequest,
) -> Result<bool> {
    let Some(scope) = database
        .prepare("SELECT snapshot_id FROM vfs_token_verifiers WHERE id = ?1")
        .bind(&[JsValue::from_str(&parent.id)])?
        .first::<TokenScopeRow>(None)
        .await?
    else {
        return Ok(false);
    };
    if scope.snapshot_id.is_some() {
        return Ok(false);
    }

    let parent_actions = database
        .prepare(
            "SELECT action AS value FROM vfs_token_actions
             WHERE token_id = ?1 ORDER BY action",
        )
        .bind(&[JsValue::from_str(&parent.id)])?
        .all()
        .await?
        .results::<StringRow>()?
        .into_iter()
        .map(|row| row.value)
        .collect::<BTreeSet<_>>();
    if requested
        .actions
        .iter()
        .any(|action| !parent_actions.contains(action))
    {
        return Ok(false);
    }

    let parent_drivers = database
        .prepare(
            "SELECT driver_id AS value FROM vfs_token_drivers
             WHERE token_id = ?1 ORDER BY driver_id",
        )
        .bind(&[JsValue::from_str(&parent.id)])?
        .all()
        .await?
        .results::<StringRow>()?
        .into_iter()
        .map(|row| row.value)
        .collect::<BTreeSet<_>>();
    if parent_drivers.is_empty() {
        return Ok(true);
    }
    let Some(child_drivers) = &requested.driver_ids else {
        return Ok(false);
    };
    Ok(child_drivers
        .iter()
        .all(|driver_id| parent_drivers.contains(driver_id)))
}

async fn all_drivers_enabled(database: &D1Database, driver_ids: &[String]) -> Result<bool> {
    #[derive(Deserialize)]
    struct EnabledRow {
        enabled: u64,
    }

    for driver_id in driver_ids {
        let enabled = database
            .prepare("SELECT enabled FROM driver_instances WHERE id = ?1")
            .bind(&[JsValue::from_str(driver_id)])?
            .first::<EnabledRow>(None)
            .await?;
        if enabled.is_none_or(|row| row.enabled != 1) {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn load_issue_receipt(
    database: &D1Database,
    parent_token_id: &str,
    idempotency_key: &str,
) -> Result<Option<TokenIssueReceiptRow>> {
    database
        .prepare(
            "SELECT receipt.request_sha256, receipt.principal_id,
                    receipt.root_directory_id, receipt.token_id,
                    receipt.actions_json, receipt.driver_ids_json,
                    receipt.expires_at, token.verifier_sha256
             FROM vfs_token_issue_receipts AS receipt
             JOIN vfs_token_verifiers AS token ON token.id = receipt.token_id
             WHERE receipt.parent_token_id = ?1 AND receipt.idempotency_key = ?2",
        )
        .bind(&[
            JsValue::from_str(parent_token_id),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<TokenIssueReceiptRow>(None)
        .await
}

fn issue_response(
    env: &Env,
    parent: &AuthenticatedVfsToken,
    receipt: TokenIssueReceiptRow,
    request_sha256: &str,
    request_digest: &[u8; 32],
    idempotency_key: &str,
) -> Result<Response> {
    if receipt.request_sha256 != request_sha256 || receipt.principal_id != parent.principal_id {
        return Response::error("VFS token idempotency key already has another request", 409);
    }
    let actions = serde_json::from_str::<Vec<String>>(&receipt.actions_json)?;
    let driver_ids = receipt
        .driver_ids_json
        .as_deref()
        .map(serde_json::from_str::<Vec<String>>)
        .transpose()?;
    let bearer = derive_child_token(env, &parent.id, request_digest, idempotency_key)?;
    if token_verifier(&bearer) != receipt.verifier_sha256 {
        return Err(worker::Error::RustError(
            "VFS token receipt verifier diverged from derived bearer".to_owned(),
        ));
    }

    let mut response = Response::from_json(&IssueTokenResponse {
        schema: TOKEN_ISSUE_SCHEMA,
        token_id: receipt.token_id,
        principal_id: receipt.principal_id,
        parent_token_id: parent.id.clone(),
        root_directory_id: receipt.root_directory_id,
        actions,
        driver_ids,
        expires_at: receipt.expires_at,
        token: bearer,
    })?;
    no_store(&mut response)?;
    Ok(response)
}

/// Revokes one same-principal token. Revocation is monotonic and becomes
/// effective for the entire descendant chain on the next authentication.
#[allow(
    clippy::too_many_lines,
    reason = "the revoke handler keeps validation, replay, and its short transaction together"
)]
pub(crate) async fn revoke(
    request: &mut Request,
    env: &Env,
    authorizer: &AuthenticatedVfsToken,
    target_token_id: &str,
) -> Result<Response> {
    if !valid_identifier(target_token_id) || target_token_id == authorizer.id {
        return Response::error("invalid VFS token revocation target", 400);
    }
    let requested = request.json::<RevokeTokenRequest>().await?;
    if !valid_string(&requested.idempotency_key, MAXIMUM_IDEMPOTENCY_BYTES) {
        return Response::error("invalid VFS token revocation request", 400);
    }
    let identity = RevokeTokenIdentity {
        target_token_id,
        idempotency_key: &requested.idempotency_key,
    };
    let request_digest = request_identity(b"carrack.vfs.token-revoke.v1\0", &identity)?;
    let request_sha256 = lowercase_hex(&request_digest)?;
    let database = env.d1("SKYDRIVER_INDEX")?;

    let Some(target) = load_target_token(&database, target_token_id).await? else {
        return Response::error("VFS token not found", 404);
    };
    if target.principal_id != authorizer.principal_id {
        return Response::error("VFS token-issue authority required", 403);
    }
    if !vfs_access::authorized(
        &database,
        authorizer,
        &target.root_directory_id,
        "token.issue",
    )
    .await?
    {
        return Response::error("VFS token-issue authority required", 403);
    }

    if let Some(receipt) =
        load_revoke_receipt(&database, &authorizer.id, &requested.idempotency_key).await?
    {
        return revoke_response(receipt, &request_sha256);
    }
    if target.revoked_at.is_some() {
        return Response::error("VFS token is already revoked", 409);
    }

    let now = current_unix_seconds();
    let audit_details = serde_json::json!({
        "authorizing_token_id": authorizer.id,
        "root_directory_id": target.root_directory_id,
        "target_token_id": target_token_id,
    })
    .to_string();
    let statements = vec![
        database
            .prepare(
                "UPDATE vfs_token_verifiers SET revoked_at = ?2
                 WHERE id = ?1 AND revoked_at IS NULL",
            )
            .bind(&[JsValue::from_str(target_token_id), number_binding(now)])?,
        database
            .prepare(
                "INSERT INTO vfs_audit_events (
                     filesystem_id, principal_id, token_id, event_kind,
                     subject_kind, subject_id, details_json, created_at
                 )
                 SELECT directory.filesystem_id, ?1, ?2, 'token_revoked',
                        'token', ?3, ?4, ?5
                 FROM vfs_directories AS directory WHERE directory.id = ?6",
            )
            .bind(&[
                JsValue::from_str(&authorizer.principal_id),
                JsValue::from_str(&authorizer.id),
                JsValue::from_str(target_token_id),
                JsValue::from_str(&audit_details),
                number_binding(now),
                JsValue::from_str(&target.root_directory_id),
            ])?,
        database
            .prepare(
                "INSERT INTO vfs_token_revoke_receipts (
                     authorizing_token_id, idempotency_key, request_sha256,
                     principal_id, target_token_id, root_directory_id,
                     revoked_at, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            )
            .bind(&[
                JsValue::from_str(&authorizer.id),
                JsValue::from_str(&requested.idempotency_key),
                JsValue::from_str(&request_sha256),
                JsValue::from_str(&authorizer.principal_id),
                JsValue::from_str(target_token_id),
                JsValue::from_str(&target.root_directory_id),
                number_binding(now),
            ])?,
    ];
    let batch_result = database.batch(statements).await;

    if let Some(receipt) =
        load_revoke_receipt(&database, &authorizer.id, &requested.idempotency_key).await?
    {
        return revoke_response(receipt, &request_sha256);
    }
    if let Err(error) = batch_result {
        worker::console_warn!("VFS token-revoke transaction conflicted: {error:?}");
    }
    Response::error(
        "VFS token revocation conflicted; retry the exact request",
        409,
    )
}

async fn load_target_token(
    database: &D1Database,
    token_id: &str,
) -> Result<Option<TargetTokenRow>> {
    database
        .prepare(
            "SELECT principal_id, root_directory_id, revoked_at
             FROM vfs_token_verifiers WHERE id = ?1 AND sealed_at IS NOT NULL",
        )
        .bind(&[JsValue::from_str(token_id)])?
        .first::<TargetTokenRow>(None)
        .await
}

async fn load_revoke_receipt(
    database: &D1Database,
    authorizing_token_id: &str,
    idempotency_key: &str,
) -> Result<Option<TokenRevokeReceiptRow>> {
    database
        .prepare(
            "SELECT request_sha256, principal_id, target_token_id,
                    root_directory_id, revoked_at
             FROM vfs_token_revoke_receipts
             WHERE authorizing_token_id = ?1 AND idempotency_key = ?2",
        )
        .bind(&[
            JsValue::from_str(authorizing_token_id),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<TokenRevokeReceiptRow>(None)
        .await
}

fn revoke_response(receipt: TokenRevokeReceiptRow, request_sha256: &str) -> Result<Response> {
    if receipt.request_sha256 != request_sha256 {
        return Response::error("VFS token idempotency key already has another request", 409);
    }
    let mut response = Response::from_json(&RevokeTokenResponse {
        schema: TOKEN_REVOKE_SCHEMA,
        token_id: receipt.target_token_id,
        principal_id: receipt.principal_id,
        root_directory_id: receipt.root_directory_id,
        revoked_at: receipt.revoked_at,
        state: "revoked",
    })?;
    no_store(&mut response)?;
    Ok(response)
}

fn valid_issue_request(request: &IssueTokenRequest) -> bool {
    valid_identifier(&request.root_directory_id)
        && !request.actions.is_empty()
        && request.actions.len() <= ACTIONS.len()
        && request
            .actions
            .iter()
            .all(|action| ACTIONS.contains(&action.as_str()))
        && request.driver_ids.as_ref().is_none_or(|driver_ids| {
            !driver_ids.is_empty()
                && driver_ids.len() <= MAXIMUM_DRIVER_SCOPE
                && driver_ids
                    .iter()
                    .all(|driver_id| valid_string(driver_id, MAXIMUM_DRIVER_ID_BYTES))
        })
        && i64::try_from(request.expires_at).is_ok()
        && valid_string(&request.idempotency_key, MAXIMUM_IDEMPOTENCY_BYTES)
}

fn canonicalize_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

fn request_identity<T: Serialize>(domain: &[u8], identity: &T) -> Result<[u8; 32]> {
    let encoded = serde_json::to_vec(identity)?;
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

fn optional_string_binding(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}

fn number_binding(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

fn no_store(response: &mut Response) -> Result<()> {
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    response.headers_mut().set("Pragma", "no-cache")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_identity_is_order_independent_after_canonicalization() {
        let mut actions = vec!["token.issue".to_owned(), "directory.list".to_owned()];
        canonicalize_strings(&mut actions);
        let identity = IssueTokenIdentity {
            root_directory_id: "019f10b4d77d7000a123456789abcdef",
            actions: &actions,
            driver_ids: None,
            expires_at: 2_000_000_000,
            idempotency_key: "ai-reader-1",
        };

        let digest =
            request_identity(b"carrack.vfs.token-issue.v1\0", &identity).expect("request digest");
        assert_eq!(digest.len(), 32);
        assert_eq!(actions, ["directory.list", "token.issue"]);
    }

    #[test]
    fn issue_request_rejects_empty_driver_scope() {
        let request = IssueTokenRequest {
            root_directory_id: "019f10b4d77d7000a123456789abcdef".to_owned(),
            actions: vec!["directory.list".to_owned()],
            driver_ids: Some(Vec::new()),
            expires_at: 2_000_000_000,
            idempotency_key: "reader-1".to_owned(),
        };

        assert!(!valid_issue_request(&request));
    }
}
