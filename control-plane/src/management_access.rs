use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{operator_sessions, vfs_identifiers};

const DATABASE_BINDING: &str = "CARRACK_INDEX";
const ADMIN_TOKEN_BINDING: &str = "CARRACK_ADMIN_TOKEN";
const VALIDATION_LIFETIME_SECONDS: u64 = 5 * 60;
const MUTATION_KIND: &str = "access.mutation";
const CREATION_KIND: &str = "access.create";
const VALIDATION_DOMAIN: &[u8] = b"carrack.management.validation.access.v1\0";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    operation: String,
    resource_id: Option<String>,
    filesystem_id: Option<String>,
    principal_id: Option<String>,
    group_id: Option<String>,
    kind: Option<String>,
    display_name: Option<String>,
    state: Option<String>,
    name: Option<String>,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    desired: Desired,
    validation_expires_at: u64,
    validation_digest: String,
    idempotency_key: String,
}

#[derive(Deserialize, Serialize)]
struct PrincipalRow {
    id: String,
    kind: String,
    display_name: String,
    state: String,
    revision: u64,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize, Serialize)]
struct GroupRow {
    id: String,
    filesystem_id: String,
    name: String,
    revision: u64,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize, Serialize)]
struct MembershipRow {
    group_id: String,
    principal_id: String,
    created_at: u64,
}

#[derive(Deserialize)]
struct ReceiptRow {
    resource_id: String,
    request_sha256: String,
    validation_digest: String,
    result_json: String,
}

#[derive(Serialize)]
struct Snapshot {
    schema: &'static str,
    observed_at: u64,
    principals: Vec<PrincipalRow>,
    groups: Vec<GroupRow>,
    memberships: Vec<MembershipRow>,
}

#[derive(Serialize)]
struct ValidationResponse {
    schema: &'static str,
    desired: Desired,
    validation_expires_at: u64,
    validation_digest: String,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct ReceiptResponse {
    schema: &'static str,
    operation_id: String,
    operation: String,
    resource_id: String,
    final_revision: u64,
    committed_at: u64,
    state: &'static str,
}

pub(crate) async fn snapshot(request: Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(&request, env).await? {
        return Response::error("authentication required", 401);
    }
    let database = env.d1(DATABASE_BINDING)?;
    let principals = database
        .prepare(
            "SELECT id, kind, display_name, state, revision, created_at, updated_at
             FROM vfs_principals ORDER BY display_name, id",
        )
        .all()
        .await?
        .results::<PrincipalRow>()?;
    let groups = database
        .prepare(
            "SELECT id, filesystem_id, name, revision, created_at, updated_at
             FROM vfs_groups ORDER BY filesystem_id, name, id",
        )
        .all()
        .await?
        .results::<GroupRow>()?;
    let memberships = database
        .prepare(
            "SELECT group_id, principal_id, created_at
             FROM vfs_group_members ORDER BY group_id, principal_id",
        )
        .all()
        .await?
        .results::<MembershipRow>()?;
    no_store_json(&Snapshot {
        schema: "carrack.management.access.v1",
        observed_at: now_seconds(),
        principals,
        groups,
        memberships,
    })
}

pub(crate) async fn validate(request: &mut Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }
    let mut desired = request.json::<Desired>().await?;
    if normalize_and_validate_shape(&mut desired).is_err() {
        return Response::error("invalid access mutation shape", 400);
    }
    let database = env.d1(DATABASE_BINDING)?;
    if let Err(error) = validate_current_state(&database, &desired).await {
        return Response::error(error.to_string(), 409);
    }
    let warnings = warnings(&database, &desired).await?;
    let validation_expires_at = now_seconds() + VALIDATION_LIFETIME_SECONDS;
    no_store_json(&ValidationResponse {
        schema: "carrack.management.access-validation.v1",
        validation_digest: validation_digest(env, &desired, validation_expires_at)?,
        desired,
        validation_expires_at,
        warnings,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "signed validation, idempotent receipt, CAS mutation, and audit form one transaction"
)]
pub(crate) async fn apply(request: &mut Request, env: &Env) -> Result<Response> {
    if !operator_sessions::configuration_authorized(request, env).await? {
        return Response::error("configuration session required", 403);
    }
    let requested = request.json::<ApplyRequest>().await?;
    let now = now_seconds();
    if !valid_text(&requested.idempotency_key, 256)
        || requested.validation_expires_at < now
        || requested.validation_expires_at > now + VALIDATION_LIFETIME_SECONDS
    {
        return Response::error("invalid or expired access mutation", 409);
    }
    let mut desired = requested.desired;
    if normalize_and_validate_shape(&mut desired).is_err() {
        return Response::error("invalid access mutation shape", 400);
    }
    let expected_digest = validation_digest(env, &desired, requested.validation_expires_at)?;
    if !constant_time_equal(&requested.validation_digest, &expected_digest) {
        return Response::error("validation digest does not match desired state", 409);
    }
    let request_sha256 = request_sha256(&desired)?;
    let database = env.d1(DATABASE_BINDING)?;
    if let Some(stored) = load_receipt(&database, &requested.idempotency_key).await? {
        return replay(
            stored,
            resource_id(&desired),
            &request_sha256,
            &requested.validation_digest,
        );
    }
    if let Err(error) = validate_current_state(&database, &desired).await {
        return Response::error(error.to_string(), 409);
    }
    let operation_id = vfs_identifiers::new_uuid_v7_hex()?;
    let final_revision = if desired.expected_revision == 0 {
        1
    } else {
        desired.expected_revision + 1
    };
    let receipt = ReceiptResponse {
        schema: "carrack.management.access-receipt.v1",
        operation_id: operation_id.clone(),
        operation: desired.operation.clone(),
        resource_id: resource_id(&desired).to_owned(),
        final_revision,
        committed_at: now,
        state: "committed",
    };
    let result_json = serde_json::to_string(&receipt).map_err(|error| json_error(&error))?;
    let mut statements = mutation_statements(&database, &desired, now)?;
    if desired.operation.ends_with(".create") {
        statements.push(
            database
                .prepare(
                    "INSERT INTO management_creation_receipts (
                         operation_id, operator_subject, kind, resource_id, idempotency_key,
                         request_sha256, final_revision, validation_digest,
                         result_json, committed_at
                     ) VALUES (?1, 'operator', ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8)",
                )
                .bind(&[
                    JsValue::from_str(&operation_id),
                    JsValue::from_str(CREATION_KIND),
                    JsValue::from_str(resource_id(&desired)),
                    JsValue::from_str(&requested.idempotency_key),
                    JsValue::from_str(&request_sha256),
                    JsValue::from_str(&requested.validation_digest),
                    JsValue::from_str(&result_json),
                    number(now),
                ])?,
        );
    } else {
        statements.push(
            database
                .prepare(
                    "INSERT INTO management_mutation_receipts (
                     operation_id, operator_subject, kind, resource_id, idempotency_key,
                     request_sha256, expected_revision, final_revision, validation_digest,
                     result_json, committed_at
                 ) VALUES (?1, 'operator', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )
                .bind(&[
                    JsValue::from_str(&operation_id),
                    JsValue::from_str(MUTATION_KIND),
                    JsValue::from_str(resource_id(&desired)),
                    JsValue::from_str(&requested.idempotency_key),
                    JsValue::from_str(&request_sha256),
                    number(desired.expected_revision),
                    number(final_revision),
                    JsValue::from_str(&requested.validation_digest),
                    JsValue::from_str(&result_json),
                    number(now),
                ])?,
        );
    }
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_audit_events (
                     filesystem_id, principal_id, token_id, event_kind, subject_kind,
                     subject_id, details_json, created_at
                 ) VALUES (?1, NULL, NULL, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&[
                optional(desired.filesystem_id.as_deref()),
                JsValue::from_str(&desired.operation),
                JsValue::from_str(subject_kind(&desired.operation)),
                JsValue::from_str(resource_id(&desired)),
                JsValue::from_str(
                    &serde_json::json!({"source":"operator","final_revision":final_revision})
                        .to_string(),
                ),
                number(now),
            ])?,
    );
    if let Err(error) = database.batch(statements).await {
        if let Some(stored) = load_receipt(&database, &requested.idempotency_key).await? {
            return replay(
                stored,
                resource_id(&desired),
                &request_sha256,
                &requested.validation_digest,
            );
        }
        return Err(worker::Error::RustError(format!(
            "access mutation failed: {error}"
        )));
    }
    no_store_json(&receipt)
}

fn normalize_and_validate_shape(desired: &mut Desired) -> Result<()> {
    if desired.operation.ends_with(".create") && desired.resource_id.is_none() {
        desired.resource_id = Some(vfs_identifiers::new_uuid_v7_hex()?);
    }
    let valid = match desired.operation.as_str() {
        "principal.create" => {
            desired.expected_revision == 0
                && desired.resource_id.as_deref().is_some_and(valid_id)
                && desired.filesystem_id.is_none()
                && desired.principal_id.is_none()
                && desired.group_id.is_none()
                && desired
                    .kind
                    .as_deref()
                    .is_some_and(|value| matches!(value, "human" | "service"))
                && desired
                    .display_name
                    .as_deref()
                    .is_some_and(|value| valid_text(value, 256))
                && desired.state.as_deref() == Some("active")
                && desired.name.is_none()
        }
        "principal.update" => {
            desired.expected_revision > 0
                && desired.resource_id.as_deref().is_some_and(valid_id)
                && desired
                    .kind
                    .as_deref()
                    .is_some_and(|value| matches!(value, "human" | "service"))
                && desired
                    .display_name
                    .as_deref()
                    .is_some_and(|value| valid_text(value, 256))
                && desired
                    .state
                    .as_deref()
                    .is_some_and(|value| matches!(value, "active" | "disabled"))
                && desired.filesystem_id.is_none()
                && desired.principal_id.is_none()
                && desired.group_id.is_none()
                && desired.name.is_none()
        }
        "group.create" => {
            desired.expected_revision == 0
                && desired.resource_id.as_deref().is_some_and(valid_id)
                && desired.filesystem_id.as_deref().is_some_and(valid_id)
                && desired
                    .name
                    .as_deref()
                    .is_some_and(|value| valid_text(value, 256))
                && desired.principal_id.is_none()
                && desired.group_id.is_none()
                && desired.kind.is_none()
                && desired.display_name.is_none()
                && desired.state.is_none()
        }
        "group.update" | "group.delete" => {
            desired.expected_revision > 0
                && desired.resource_id.as_deref().is_some_and(valid_id)
                && desired.filesystem_id.as_deref().is_some_and(valid_id)
                && (desired.operation == "group.delete"
                    || desired
                        .name
                        .as_deref()
                        .is_some_and(|value| valid_text(value, 256)))
                && desired.principal_id.is_none()
                && desired.group_id.is_none()
                && desired.kind.is_none()
                && desired.display_name.is_none()
                && desired.state.is_none()
        }
        "membership.add" | "membership.remove" => {
            desired.expected_revision > 0
                && desired.resource_id.as_deref().is_some_and(valid_id)
                && desired.filesystem_id.as_deref().is_some_and(valid_id)
                && desired.principal_id.as_deref().is_some_and(valid_id)
                && desired.group_id.as_deref() == desired.resource_id.as_deref()
                && desired.kind.is_none()
                && desired.display_name.is_none()
                && desired.state.is_none()
                && desired.name.is_none()
        }
        _ => false,
    };
    if !valid {
        return Err(worker::Error::RustError(
            "invalid access mutation shape".to_owned(),
        ));
    }
    Ok(())
}

async fn validate_current_state(database: &worker::D1Database, desired: &Desired) -> Result<()> {
    match desired.operation.as_str() {
        "principal.create" => {
            if principal(database, resource_id(desired)).await?.is_some() {
                return Err(conflict("principal already exists"));
            }
        }
        "principal.update" => {
            let Some(current) = principal(database, resource_id(desired)).await? else {
                return Err(conflict("principal not found"));
            };
            if current.revision != desired.expected_revision {
                return Err(conflict("principal revision conflict"));
            }
            if desired.state.as_deref() == Some("disabled") {
                let bootstrap = database
                    .prepare(
                        "SELECT EXISTS (
                             SELECT 1 FROM vfs_bootstrap_receipts WHERE principal_id = ?1
                         ) AS present",
                    )
                    .bind(&[JsValue::from_str(resource_id(desired))])?
                    .first::<u64>(Some("present"))
                    .await?
                    .unwrap_or(0);
                if bootstrap == 1 {
                    return Err(conflict("bootstrap recovery principal cannot be disabled"));
                }
                let active = database.prepare("SELECT COUNT(*) AS count FROM vfs_principals WHERE state = 'active' AND id != ?1")
                    .bind(&[JsValue::from_str(resource_id(desired))])?.first::<u64>(Some("count")).await?.unwrap_or(0);
                if active == 0 {
                    return Err(conflict("last active principal cannot be disabled"));
                }
            }
        }
        "group.create" => {
            let exists = database.prepare("SELECT EXISTS (SELECT 1 FROM vfs_filesystems WHERE id = ?1 AND state = 'active') AS present")
                .bind(&[JsValue::from_str(desired.filesystem_id.as_deref().unwrap_or_default())])?.first::<u64>(Some("present")).await?.unwrap_or(0);
            if exists != 1 {
                return Err(conflict("filesystem not found"));
            }
        }
        "group.update" | "group.delete" | "membership.add" | "membership.remove" => {
            let Some(current) = group(database, resource_id(desired)).await? else {
                return Err(conflict("group not found"));
            };
            if current.revision != desired.expected_revision
                || Some(current.filesystem_id.as_str()) != desired.filesystem_id.as_deref()
            {
                return Err(conflict("group revision conflict"));
            }
            if desired.operation.starts_with("membership.") {
                let principal_id = desired.principal_id.as_deref().unwrap_or_default();
                let Some(principal) = principal(database, principal_id).await? else {
                    return Err(conflict("principal not found"));
                };
                if principal.state != "active" {
                    return Err(conflict("principal is disabled"));
                }
                let member = database.prepare("SELECT EXISTS (SELECT 1 FROM vfs_group_members WHERE group_id = ?1 AND principal_id = ?2) AS present")
                    .bind(&[JsValue::from_str(resource_id(desired)), JsValue::from_str(principal_id)])?.first::<u64>(Some("present")).await?.unwrap_or(0) == 1;
                if member != (desired.operation == "membership.remove") {
                    return Err(conflict("membership already has requested state"));
                }
            }
        }
        _ => return Err(conflict("unsupported access mutation")),
    }
    Ok(())
}

fn mutation_statements<'a>(
    database: &'a worker::D1Database,
    desired: &'a Desired,
    now: u64,
) -> Result<Vec<worker::D1PreparedStatement>> {
    let id = resource_id(desired);
    let statement = match desired.operation.as_str() {
        "principal.create" => database.prepare("INSERT INTO vfs_principals (id, kind, display_name, state, revision, created_at, updated_at) VALUES (?1, ?2, ?3, 'active', 1, ?4, ?4)")
            .bind(&[JsValue::from_str(id), JsValue::from_str(desired.kind.as_deref().unwrap_or_default()), JsValue::from_str(desired.display_name.as_deref().unwrap_or_default()), number(now)])?,
        "principal.update" => database.prepare("UPDATE vfs_principals SET kind = ?1, display_name = ?2, state = ?3, revision = revision + 1, updated_at = ?4 WHERE id = ?5 AND revision = ?6")
            .bind(&[JsValue::from_str(desired.kind.as_deref().unwrap_or_default()), JsValue::from_str(desired.display_name.as_deref().unwrap_or_default()), JsValue::from_str(desired.state.as_deref().unwrap_or_default()), number(now), JsValue::from_str(id), number(desired.expected_revision)])?,
        "group.create" => database.prepare("INSERT INTO vfs_groups (id, filesystem_id, name, revision, created_at, updated_at) VALUES (?1, ?2, ?3, 1, ?4, ?4)")
            .bind(&[JsValue::from_str(id), JsValue::from_str(desired.filesystem_id.as_deref().unwrap_or_default()), JsValue::from_str(desired.name.as_deref().unwrap_or_default()), number(now)])?,
        "group.update" => database.prepare("UPDATE vfs_groups SET name = ?1, revision = revision + 1, updated_at = ?2 WHERE id = ?3 AND filesystem_id = ?4 AND revision = ?5")
            .bind(&[JsValue::from_str(desired.name.as_deref().unwrap_or_default()), number(now), JsValue::from_str(id), JsValue::from_str(desired.filesystem_id.as_deref().unwrap_or_default()), number(desired.expected_revision)])?,
        "group.delete" => database.prepare("DELETE FROM vfs_groups WHERE id = ?1 AND filesystem_id = ?2 AND revision = ?3")
            .bind(&[JsValue::from_str(id), JsValue::from_str(desired.filesystem_id.as_deref().unwrap_or_default()), number(desired.expected_revision)])?,
        "membership.add" => database.prepare("INSERT INTO vfs_group_members (group_id, principal_id, created_at, group_revision) VALUES (?1, ?2, ?3, ?4)")
            .bind(&[JsValue::from_str(id), JsValue::from_str(desired.principal_id.as_deref().unwrap_or_default()), number(now), number(desired.expected_revision)])?,
        "membership.remove" => database.prepare("UPDATE vfs_group_members SET group_revision = ?1 WHERE group_id = ?2 AND principal_id = ?3")
            .bind(&[number(desired.expected_revision), JsValue::from_str(id), JsValue::from_str(desired.principal_id.as_deref().unwrap_or_default())])?,
        _ => return Err(conflict("unsupported access mutation")),
    };
    let mut statements = vec![statement];
    if desired.operation == "membership.remove" {
        statements.push(
            database
                .prepare("DELETE FROM vfs_group_members WHERE group_id = ?1 AND principal_id = ?2")
                .bind(&[
                    JsValue::from_str(id),
                    JsValue::from_str(desired.principal_id.as_deref().unwrap_or_default()),
                ])?,
        );
    }
    Ok(statements)
}

async fn warnings(database: &worker::D1Database, desired: &Desired) -> Result<Vec<String>> {
    let mut result = Vec::new();
    if desired.operation == "principal.update" && desired.state.as_deref() == Some("disabled") {
        let count = database.prepare("SELECT COUNT(*) AS count FROM vfs_token_verifiers WHERE principal_id = ?1 AND revoked_at IS NULL AND expires_at > ?2")
            .bind(&[JsValue::from_str(resource_id(desired)), number(now_seconds())])?.first::<u64>(Some("count")).await?.unwrap_or(0);
        if count > 0 {
            result.push(format!(
                "Disabling this principal immediately rejects {count} active token(s)."
            ));
        }
    }
    if desired.operation == "group.delete" {
        result
            .push("Deleting this group immediately removes all inherited group grants.".to_owned());
    }
    Ok(result)
}

async fn principal(database: &worker::D1Database, id: &str) -> Result<Option<PrincipalRow>> {
    database.prepare("SELECT id, kind, display_name, state, revision, created_at, updated_at FROM vfs_principals WHERE id = ?1")
        .bind(&[JsValue::from_str(id)])?.first::<PrincipalRow>(None).await
}

async fn group(database: &worker::D1Database, id: &str) -> Result<Option<GroupRow>> {
    database.prepare("SELECT id, filesystem_id, name, revision, created_at, updated_at FROM vfs_groups WHERE id = ?1")
        .bind(&[JsValue::from_str(id)])?.first::<GroupRow>(None).await
}

async fn load_receipt(
    database: &worker::D1Database,
    idempotency_key: &str,
) -> Result<Option<ReceiptRow>> {
    database
        .prepare(
            "SELECT resource_id, request_sha256, validation_digest, result_json
                      FROM management_mutation_receipts
                      WHERE operator_subject = 'operator' AND kind = ?1 AND idempotency_key = ?3
                      UNION ALL
                      SELECT resource_id, request_sha256, validation_digest, result_json
                      FROM management_creation_receipts
                      WHERE operator_subject = 'operator' AND kind = ?2 AND idempotency_key = ?3
                      LIMIT 1",
        )
        .bind(&[
            JsValue::from_str(MUTATION_KIND),
            JsValue::from_str(CREATION_KIND),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<ReceiptRow>(None)
        .await
}

fn replay(
    stored: ReceiptRow,
    id: &str,
    request_sha256: &str,
    validation_digest: &str,
) -> Result<Response> {
    if stored.resource_id != id
        || stored.request_sha256 != request_sha256
        || stored.validation_digest != validation_digest
    {
        return Response::error("idempotency key reused for different input", 409);
    }
    let mut response = Response::ok(stored.result_json)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn validation_digest(env: &Env, desired: &Desired, expires_at: u64) -> Result<String> {
    let secret = env.secret(ADMIN_TOKEN_BINDING)?.to_string();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    mac.update(VALIDATION_DOMAIN);
    mac.update(&canonical(desired)?);
    mac.update(&expires_at.to_be_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn request_sha256(desired: &Desired) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(VALIDATION_DOMAIN);
    hash.update(canonical(desired)?);
    Ok(lowercase_hex(&hash.finalize()))
}

fn canonical(desired: &Desired) -> Result<Vec<u8>> {
    serde_json::to_vec(desired).map_err(|error| json_error(&error))
}
fn resource_id(desired: &Desired) -> &str {
    desired.resource_id.as_deref().unwrap_or_default()
}
fn subject_kind(operation: &str) -> &str {
    if operation.starts_with("principal.") {
        "principal"
    } else {
        "group"
    }
}
fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value != "00000000000000000000000000000000"
}
fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn optional(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}
fn number(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}
fn conflict(message: &str) -> worker::Error {
    worker::Error::RustError(message.to_owned())
}
fn json_error(error: &serde_json::Error) -> worker::Error {
    worker::Error::RustError(error.to_string())
}
fn now_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}
fn no_store_json<T: Serialize>(value: &T) -> Result<Response> {
    let mut response = Response::from_json(value)?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}
fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String writes cannot fail");
    }
    output
}
fn constant_time_equal(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (URL_SAFE_NO_PAD.decode(left), URL_SAFE_NO_PAD.decode(right))
    else {
        return false;
    };
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[cfg(test)]
mod tests {
    use super::{Desired, normalize_and_validate_shape};

    #[test]
    fn validates_create_identity_and_rejects_ambiguous_shapes() {
        let mut desired = Desired {
            operation: "principal.create".to_owned(),
            resource_id: Some("00000000000000000000000000000001".to_owned()),
            filesystem_id: None,
            principal_id: None,
            group_id: None,
            kind: Some("service".to_owned()),
            display_name: Some("Release agent".to_owned()),
            state: Some("active".to_owned()),
            name: None,
            expected_revision: 0,
        };
        normalize_and_validate_shape(&mut desired).expect("valid principal");
        assert_eq!(desired.resource_id.as_deref().map(str::len), Some(32));
        desired.filesystem_id = desired.resource_id.clone();
        assert!(normalize_and_validate_shape(&mut desired).is_err());
    }
}
