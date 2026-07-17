use std::{collections::BTreeSet, fmt::Write as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{D1Database, Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use carrack_sdk_core::VFS_ACTIONS as ACTIONS;

use crate::{
    vfs_access, vfs_identifiers::new_uuid_v7_hex, vfs_mounts, vfs_tokens::AuthenticatedVfsToken,
};

const ACL_SCHEMA: &str = "carrack.vfs.acl.v1";
const PLACEMENT_SCHEMA: &str = "carrack.vfs.placements.v1";
const POLICY_RECEIPT_SCHEMA: &str = "carrack.vfs.policy-mutation-receipt.v1";
const MAXIMUM_IDEMPOTENCY_BYTES: usize = 256;
const MAXIMUM_DRIVER_ID_BYTES: usize = 256;

#[derive(Deserialize, Serialize)]
struct ACLGrant {
    id: String,
    principal_id: Option<String>,
    group_id: Option<String>,
    action: String,
    source_role: Option<String>,
}

#[derive(Deserialize)]
struct DirectoryPolicyRow {
    acl_inherits: u64,
    acl_revision: u64,
    placement_revision: u64,
}

#[derive(Serialize)]
struct ACLResponse {
    schema: &'static str,
    directory_id: String,
    acl_inherits: bool,
    acl_revision: u64,
    grants: Vec<ACLGrant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceACLRequest {
    principal_id: Option<String>,
    group_id: Option<String>,
    actions: Option<Vec<String>>,
    role: Option<String>,
    expected_acl_revision: u64,
    idempotency_key: String,
}

#[derive(Serialize)]
struct ACLPayload<'a> {
    principal_id: Option<&'a str>,
    group_id: Option<&'a str>,
    actions: &'a [String],
    source_role: Option<&'a str>,
}

#[derive(Deserialize, Serialize)]
struct Placement {
    driver_id: String,
    write_priority: u64,
}

#[derive(Deserialize, Serialize)]
struct PlacementView {
    driver_id: String,
    driver_kind: String,
    driver_revision: u64,
    write_priority: u64,
    state: String,
    mount_kind: String,
}

#[derive(Serialize)]
struct PlacementsResponse {
    schema: &'static str,
    directory_id: String,
    placement_revision: u64,
    placements: Vec<PlacementView>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplacePlacementsRequest {
    placements: Vec<Placement>,
    expected_placement_revision: u64,
    idempotency_key: String,
}

#[derive(Serialize)]
struct PlacementsPayload<'a> {
    placements: &'a [Placement],
}

#[derive(Deserialize)]
struct CountRow {
    count: u64,
}

#[derive(Deserialize)]
struct PresentRow {
    present: u64,
}

#[derive(Deserialize)]
struct PolicyReceiptRow {
    intent_id: String,
    kind: String,
    request_sha256: String,
    directory_id: String,
    payload_json: String,
    final_revision: u64,
    committed_at: u64,
}

#[derive(Serialize)]
struct PolicyMutationResponse {
    schema: &'static str,
    operation_id: String,
    kind: String,
    directory_id: String,
    final_revision: u64,
    policy: serde_json::Value,
    committed_at: u64,
    state: &'static str,
}

pub(crate) async fn list_acl(
    env: &Env,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
) -> Result<Response> {
    if !valid_identifier(directory_id) {
        return Response::error("invalid VFS directory ID", 400);
    }
    let database = env.d1("CARRACK_INDEX")?;
    if !vfs_access::authorized(&database, token, directory_id, "acl.manage").await? {
        return Response::error("VFS ACL-management authority required", 403);
    }
    let Some(policy) = load_policy(&database, directory_id).await? else {
        return Response::error("VFS directory not found", 404);
    };
    let grants = database
        .prepare(
            "SELECT id, principal_id, group_id, action, source_role
             FROM vfs_acl_grants WHERE directory_id = ?1
             ORDER BY COALESCE(principal_id, group_id), action",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .all()
        .await?
        .results::<ACLGrant>()?;

    Response::from_json(&ACLResponse {
        schema: ACL_SCHEMA,
        directory_id: directory_id.to_owned(),
        acl_inherits: policy.acl_inherits == 1,
        acl_revision: policy.acl_revision,
        grants,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "ACL replacement keeps CAS and exact replay together"
)]
pub(crate) async fn replace_acl(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
) -> Result<Response> {
    if !valid_identifier(directory_id) {
        return Response::error("invalid VFS directory ID", 400);
    }
    let requested = request.json::<ReplaceACLRequest>().await?;
    let Some((mut actions, source_role)) = resolve_acl_scope(&requested) else {
        return Response::error("invalid VFS ACL replacement", 400);
    };
    actions.sort();
    actions.dedup();
    let subject = match (
        requested.principal_id.as_deref(),
        requested.group_id.as_deref(),
    ) {
        (Some(principal_id), None) if valid_identifier(principal_id) => ("principal", principal_id),
        (None, Some(group_id)) if valid_identifier(group_id) => ("group", group_id),
        _ => return Response::error("exactly one valid ACL subject is required", 400),
    };
    if requested.expected_acl_revision == 0
        || !valid_string(&requested.idempotency_key, MAXIMUM_IDEMPOTENCY_BYTES)
    {
        return Response::error("invalid VFS ACL replacement", 400);
    }
    let payload = serde_json::to_value(ACLPayload {
        principal_id: requested.principal_id.as_deref(),
        group_id: requested.group_id.as_deref(),
        actions: &actions,
        source_role,
    })?;
    let request_digest = policy_identity(
        "acl.replace",
        directory_id,
        requested.expected_acl_revision,
        &payload,
        &requested.idempotency_key,
    )?;
    let request_sha256 = lowercase_hex(&request_digest)?;
    let database = env.d1("CARRACK_INDEX")?;
    if let Some(receipt) =
        load_receipt(&database, token, "acl.replace", &requested.idempotency_key).await?
    {
        return receipt_response(receipt, &request_sha256);
    }
    if !vfs_access::authorized(&database, token, directory_id, "acl.manage").await? {
        return Response::error("VFS ACL-management authority required", 403);
    }
    let Some(policy) = load_policy(&database, directory_id).await? else {
        return Response::error("VFS directory not found", 404);
    };
    let subject_available = if subject.0 == "principal" {
        principal_active(&database, subject.1).await?
    } else {
        group_available(&database, directory_id, subject.1).await?
    };
    if !subject_available {
        return Response::error("VFS ACL subject is unavailable", 400);
    }
    if policy.acl_revision != requested.expected_acl_revision {
        return Response::error("VFS ACL revision changed", 409);
    }
    let old_count = subject_grant_count(&database, directory_id, subject.0, subject.1).await?;
    let final_revision =
        policy.acl_revision + old_count + u64::try_from(actions.len()).unwrap_or(u64::MAX);
    let operation_id = new_uuid_v7_hex()?;
    let now = current_unix_seconds();
    let payload_json = payload.to_string();
    let mut statements = vec![policy_intent_statement(
        &database,
        &operation_id,
        "acl.replace",
        token,
        directory_id,
        &request_sha256,
        &requested.idempotency_key,
        policy.acl_revision,
        final_revision,
        &payload_json,
        now,
    )?];
    let subject_column = if subject.0 == "principal" {
        "principal_id"
    } else {
        "group_id"
    };
    statements.push(
        database
            .prepare(format!(
                "DELETE FROM vfs_acl_grants WHERE directory_id = ?1 AND {subject_column} = ?2"
            ))
            .bind(&[
                JsValue::from_str(directory_id),
                JsValue::from_str(subject.1),
            ])?,
    );
    for action in &actions {
        statements.push(
            database
                .prepare(format!(
                    "INSERT INTO vfs_acl_grants (
                 id, directory_id, {subject_column}, action, source_role, created_by, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                ))
                .bind(&[
                    JsValue::from_str(&new_uuid_v7_hex()?),
                    JsValue::from_str(directory_id),
                    JsValue::from_str(subject.1),
                    JsValue::from_str(action),
                    optional_binding(source_role),
                    JsValue::from_str(&token.principal_id),
                    number_binding(now),
                ])?,
        );
    }
    statements.extend(policy_finish_statements(
        &database,
        &operation_id,
        "acl.replace",
        token,
        directory_id,
        &request_sha256,
        final_revision,
        &payload_json,
        now,
    )?);
    let batch_result = database.batch(statements).await;
    if let Some(receipt) =
        load_receipt(&database, token, "acl.replace", &requested.idempotency_key).await?
    {
        return receipt_response(receipt, &request_sha256);
    }
    if let Err(error) = batch_result {
        worker::console_warn!("VFS ACL replacement conflicted: {error:?}");
    }
    Response::error("VFS ACL replacement conflicted", 409)
}

pub(crate) async fn list_placements(
    env: &Env,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
) -> Result<Response> {
    if !valid_identifier(directory_id) {
        return Response::error("invalid VFS directory ID", 400);
    }
    let database = env.d1("CARRACK_INDEX")?;
    if !vfs_access::authorized(&database, token, directory_id, "driver.manage").await?
        || token_is_driver_scoped(&database, token).await?
    {
        return Response::error("unscoped VFS driver-management authority required", 403);
    }
    let Some(policy) = load_policy(&database, directory_id).await? else {
        return Response::error("VFS directory not found", 404);
    };
    let placements = database
        .prepare(
            "SELECT placement.driver_id, driver.kind AS driver_kind,
                driver.revision AS driver_revision, placement.write_priority,
                placement.state,
                COALESCE(mount.kind, 'inherited') AS mount_kind
         FROM vfs_directory_drivers AS placement
         JOIN driver_instances AS driver ON driver.id = placement.driver_id
         LEFT JOIN vfs_directory_mounts AS mount
           ON mount.directory_id = placement.directory_id
          AND mount.driver_id = placement.driver_id
         WHERE placement.directory_id = ?1
         ORDER BY placement.write_priority, placement.driver_id",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .all()
        .await?
        .results::<PlacementView>()?;
    Response::from_json(&PlacementsResponse {
        schema: PLACEMENT_SCHEMA,
        directory_id: directory_id.to_owned(),
        placement_revision: policy.placement_revision,
        placements,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "placement replacement keeps CAS and exact replay together"
)]
pub(crate) async fn replace_placements(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
) -> Result<Response> {
    if !valid_identifier(directory_id) {
        return Response::error("invalid VFS directory ID", 400);
    }
    let mut requested = request.json::<ReplacePlacementsRequest>().await?;
    requested.placements.sort_by(|left, right| {
        left.write_priority
            .cmp(&right.write_priority)
            .then_with(|| left.driver_id.cmp(&right.driver_id))
    });
    if !valid_placements_request(&requested) {
        return Response::error("invalid VFS placement replacement", 400);
    }
    let payload = serde_json::to_value(PlacementsPayload {
        placements: &requested.placements,
    })?;
    let request_digest = policy_identity(
        "placement.replace",
        directory_id,
        requested.expected_placement_revision,
        &payload,
        &requested.idempotency_key,
    )?;
    let request_sha256 = lowercase_hex(&request_digest)?;
    let database = env.d1("CARRACK_INDEX")?;
    if let Some(receipt) = load_receipt(
        &database,
        token,
        "placement.replace",
        &requested.idempotency_key,
    )
    .await?
    {
        return receipt_response(receipt, &request_sha256);
    }
    if !vfs_access::authorized(&database, token, directory_id, "driver.manage").await?
        || token_is_driver_scoped(&database, token).await?
    {
        return Response::error("unscoped VFS driver-management authority required", 403);
    }
    if !all_placement_drivers_enabled(&database, &requested.placements).await? {
        return Response::error("VFS placement references an unavailable driver", 400);
    }
    let Some(policy) = load_policy(&database, directory_id).await? else {
        return Response::error("VFS directory not found", 404);
    };
    if policy.placement_revision != requested.expected_placement_revision {
        return Response::error("VFS placement revision changed", 409);
    }
    let placement = &requested.placements[0];
    let Some(mount_relationship) =
        vfs_mounts::desired(&database, directory_id, &placement.driver_id).await?
    else {
        return Response::error("VFS mount would be nested or has no parent backing", 409);
    };
    if !vfs_mounts::change_is_safe(&database, directory_id, &placement.driver_id).await? {
        return Response::error("VFS mount target must be empty before changing driver", 409);
    }
    let mount_kind = mount_relationship.stored_kind();
    let old_count = placement_count(&database, directory_id).await?;
    let final_revision = policy.placement_revision
        + old_count
        + u64::try_from(requested.placements.len()).unwrap_or(u64::MAX);
    let operation_id = new_uuid_v7_hex()?;
    let now = current_unix_seconds();
    let payload_json = payload.to_string();
    let mut statements = vec![policy_intent_statement(
        &database,
        &operation_id,
        "placement.replace",
        token,
        directory_id,
        &request_sha256,
        &requested.idempotency_key,
        policy.placement_revision,
        final_revision,
        &payload_json,
        now,
    )?];
    statements.push(
        database
            .prepare("DELETE FROM vfs_directory_mounts WHERE directory_id = ?1")
            .bind(&[JsValue::from_str(directory_id)])?,
    );
    statements.push(
        database
            .prepare("DELETE FROM vfs_directory_drivers WHERE directory_id = ?1")
            .bind(&[JsValue::from_str(directory_id)])?,
    );
    for placement in &requested.placements {
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_directory_drivers (
                 directory_id, driver_id, write_priority, state, created_by, created_at, updated_at
             ) VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?5)",
                )
                .bind(&[
                    JsValue::from_str(directory_id),
                    JsValue::from_str(&placement.driver_id),
                    number_binding(placement.write_priority),
                    JsValue::from_str(&token.principal_id),
                    number_binding(now),
                ])?,
        );
    }
    if let Some(kind) = mount_kind {
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_directory_mounts (
                         directory_id, driver_id, kind, created_by, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                )
                .bind(&[
                    JsValue::from_str(directory_id),
                    JsValue::from_str(&placement.driver_id),
                    JsValue::from_str(kind),
                    JsValue::from_str(&token.principal_id),
                    number_binding(now),
                ])?,
        );
    }
    statements.extend(policy_finish_statements(
        &database,
        &operation_id,
        "placement.replace",
        token,
        directory_id,
        &request_sha256,
        final_revision,
        &payload_json,
        now,
    )?);
    let batch_result = database.batch(statements).await;
    if let Some(receipt) = load_receipt(
        &database,
        token,
        "placement.replace",
        &requested.idempotency_key,
    )
    .await?
    {
        return receipt_response(receipt, &request_sha256);
    }
    if let Err(error) = batch_result {
        worker::console_warn!("VFS placement replacement conflicted: {error:?}");
    }
    Response::error("VFS placement replacement conflicted", 409)
}

#[allow(
    clippy::too_many_arguments,
    reason = "all mutation fence fields are explicit"
)]
fn policy_intent_statement(
    database: &D1Database,
    operation_id: &str,
    kind: &str,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
    request_sha256: &str,
    idempotency_key: &str,
    expected_revision: u64,
    final_revision: u64,
    payload_json: &str,
    now: u64,
) -> Result<worker::D1PreparedStatement> {
    database
        .prepare(
            "INSERT INTO vfs_policy_mutation_intents (
             id, kind, principal_id, token_id, directory_id, request_sha256,
             idempotency_key, expected_revision, final_revision, payload_json, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(kind),
            JsValue::from_str(&token.principal_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(directory_id),
            JsValue::from_str(request_sha256),
            JsValue::from_str(idempotency_key),
            number_binding(expected_revision),
            number_binding(final_revision),
            JsValue::from_str(payload_json),
            number_binding(now),
        ])
}

#[allow(
    clippy::too_many_arguments,
    reason = "receipt, audit, and final state share one identity"
)]
fn policy_finish_statements(
    database: &D1Database,
    operation_id: &str,
    kind: &str,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
    request_sha256: &str,
    final_revision: u64,
    payload_json: &str,
    now: u64,
) -> Result<Vec<worker::D1PreparedStatement>> {
    Ok(vec![
        database
            .prepare(
                "INSERT INTO vfs_policy_mutation_receipts (
                 intent_id, kind, token_id, directory_id, request_sha256,
                 final_revision, committed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                JsValue::from_str(kind),
                JsValue::from_str(&token.id),
                JsValue::from_str(directory_id),
                JsValue::from_str(request_sha256),
                number_binding(final_revision),
                number_binding(now),
            ])?,
        database
            .prepare(
                "INSERT INTO vfs_audit_events (
                 filesystem_id, principal_id, token_id, event_kind,
                 subject_kind, subject_id, details_json, created_at
             )
             SELECT filesystem_id, ?1, ?2, ?3, 'directory', id, ?4, ?5
             FROM vfs_directories WHERE id = ?6",
            )
            .bind(&[
                JsValue::from_str(&token.principal_id),
                JsValue::from_str(&token.id),
                JsValue::from_str(kind),
                JsValue::from_str(payload_json),
                number_binding(now),
                JsValue::from_str(directory_id),
            ])?,
        database
            .prepare(
                "UPDATE vfs_policy_mutation_intents
             SET state = 'committed', committed_at = ?1, revision = revision + 1
             WHERE id = ?2 AND state = 'prepared' AND revision = 1",
            )
            .bind(&[number_binding(now), JsValue::from_str(operation_id)])?,
    ])
}

async fn load_policy(
    database: &D1Database,
    directory_id: &str,
) -> Result<Option<DirectoryPolicyRow>> {
    database
        .prepare(
            "SELECT acl_inherits, acl_revision, placement_revision
         FROM vfs_directories WHERE id = ?1 AND state = 'active'",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<DirectoryPolicyRow>(None)
        .await
}

async fn load_receipt(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    kind: &str,
    idempotency_key: &str,
) -> Result<Option<PolicyReceiptRow>> {
    database
        .prepare(
            "SELECT intent.id AS intent_id, intent.kind, intent.request_sha256,
                intent.directory_id, intent.payload_json, receipt.final_revision,
                receipt.committed_at
         FROM vfs_policy_mutation_intents AS intent
         JOIN vfs_policy_mutation_receipts AS receipt ON receipt.intent_id = intent.id
         WHERE intent.token_id = ?1 AND intent.kind = ?2 AND intent.idempotency_key = ?3
           AND intent.state = 'committed'",
        )
        .bind(&[
            JsValue::from_str(&token.id),
            JsValue::from_str(kind),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<PolicyReceiptRow>(None)
        .await
}

fn receipt_response(receipt: PolicyReceiptRow, request_sha256: &str) -> Result<Response> {
    if receipt.request_sha256 != request_sha256 {
        return Response::error(
            "VFS policy idempotency key already has another request",
            409,
        );
    }
    Response::from_json(&PolicyMutationResponse {
        schema: POLICY_RECEIPT_SCHEMA,
        operation_id: receipt.intent_id,
        kind: receipt.kind,
        directory_id: receipt.directory_id,
        final_revision: receipt.final_revision,
        policy: serde_json::from_str(&receipt.payload_json)?,
        committed_at: receipt.committed_at,
        state: "committed",
    })
}

fn resolve_acl_scope(request: &ReplaceACLRequest) -> Option<(Vec<String>, Option<&str>)> {
    match (&request.actions, request.role.as_deref()) {
        (Some(actions), None)
            if actions
                .iter()
                .all(|action| ACTIONS.contains(&action.as_str())) =>
        {
            Some((actions.clone(), None))
        }
        (None, Some(role)) => role_actions(role).map(|actions| {
            (
                actions.iter().map(|action| (*action).to_owned()).collect(),
                Some(role),
            )
        }),
        _ => None,
    }
}

fn role_actions(role: &str) -> Option<&'static [&'static str]> {
    match role {
        "viewer" => Some(&["directory.list", "content.read"]),
        "editor" => Some(&[
            "directory.list",
            "content.read",
            "content.write",
            "entry.delete",
        ]),
        "publisher" => Some(&[
            "directory.list",
            "content.read",
            "content.write",
            "entry.delete",
            "snapshot.publish",
        ]),
        "security_administrator" => {
            Some(&["directory.list", "acl.manage", "token.issue", "audit.read"])
        }
        "storage_operator" => Some(&["driver.use", "driver.manage", "audit.read"]),
        "janitor" => Some(&["driver.use", "gc.run", "audit.read"]),
        "system_administrator" => Some(&[
            "acl.manage",
            "token.issue",
            "driver.manage",
            "gc.run",
            "audit.read",
            "system.manage",
        ]),
        _ => None,
    }
}

fn valid_placements_request(request: &ReplacePlacementsRequest) -> bool {
    if request.placements.len() != 1
        || request.expected_placement_revision == 0
        || !valid_string(&request.idempotency_key, MAXIMUM_IDEMPOTENCY_BYTES)
    {
        return false;
    }
    let mut drivers = BTreeSet::new();
    let mut priorities = BTreeSet::new();
    request.placements.iter().all(|placement| {
        valid_string(&placement.driver_id, MAXIMUM_DRIVER_ID_BYTES)
            && placement.write_priority == 0
            && drivers.insert(&placement.driver_id)
            && priorities.insert(placement.write_priority)
    })
}

async fn principal_active(database: &D1Database, principal_id: &str) -> Result<bool> {
    present(database, "SELECT EXISTS (SELECT 1 FROM vfs_principals WHERE id = ?1 AND state = 'active') AS present", principal_id).await
}
async fn group_available(
    database: &D1Database,
    directory_id: &str,
    group_id: &str,
) -> Result<bool> {
    let row = database
        .prepare(
            "SELECT EXISTS (
        SELECT 1 FROM vfs_groups AS group_row
        JOIN vfs_directories AS directory ON directory.filesystem_id = group_row.filesystem_id
        WHERE group_row.id = ?1 AND directory.id = ?2 AND directory.state = 'active'
    ) AS present",
        )
        .bind(&[JsValue::from_str(group_id), JsValue::from_str(directory_id)])?
        .first::<PresentRow>(None)
        .await?;
    Ok(row.is_some_and(|result| result.present == 1))
}
async fn token_is_driver_scoped(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
) -> Result<bool> {
    present(
        database,
        "SELECT EXISTS (SELECT 1 FROM vfs_token_drivers WHERE token_id = ?1) AS present",
        &token.id,
    )
    .await
}
async fn present(database: &D1Database, sql: &str, value: &str) -> Result<bool> {
    let row = database
        .prepare(sql)
        .bind(&[JsValue::from_str(value)])?
        .first::<PresentRow>(None)
        .await?;
    Ok(row.is_some_and(|result| result.present == 1))
}
async fn subject_grant_count(
    database: &D1Database,
    directory_id: &str,
    subject_kind: &str,
    subject_id: &str,
) -> Result<u64> {
    let column = if subject_kind == "principal" {
        "principal_id"
    } else {
        "group_id"
    };
    count(
        database,
        &format!(
            "SELECT COUNT(*) AS count FROM vfs_acl_grants WHERE directory_id = ?1 AND {column} = ?2"
        ),
        directory_id,
        Some(subject_id),
    )
    .await
}
async fn placement_count(database: &D1Database, directory_id: &str) -> Result<u64> {
    count(
        database,
        "SELECT COUNT(*) AS count FROM vfs_directory_drivers WHERE directory_id = ?1",
        directory_id,
        None,
    )
    .await
}
async fn count(database: &D1Database, sql: &str, first: &str, second: Option<&str>) -> Result<u64> {
    let bindings = second.map_or_else(
        || vec![JsValue::from_str(first)],
        |value| vec![JsValue::from_str(first), JsValue::from_str(value)],
    );
    Ok(database
        .prepare(sql)
        .bind(&bindings)?
        .first::<CountRow>(None)
        .await?
        .map_or(0, |row| row.count))
}
async fn all_placement_drivers_enabled(
    database: &D1Database,
    placements: &[Placement],
) -> Result<bool> {
    for placement in placements {
        if !present(database, "SELECT EXISTS (SELECT 1 FROM driver_instances WHERE id = ?1 AND enabled = 1) AS present", &placement.driver_id).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn policy_identity(
    kind: &str,
    directory_id: &str,
    expected_revision: u64,
    payload: &serde_json::Value,
    idempotency_key: &str,
) -> Result<[u8; 32]> {
    let encoded = serde_json::to_vec(&serde_json::json!({
        "directory_id": directory_id, "expected_revision": expected_revision,
        "idempotency_key": idempotency_key, "kind": kind, "policy": payload,
    }))?;
    let mut hasher = Sha256::new();
    hasher.update(b"carrack.vfs.policy-mutation.v1\0");
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}
fn lowercase_hex(bytes: &[u8]) -> Result<String> {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}")
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
    }
    Ok(encoded)
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
fn optional_binding(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}
fn number_binding(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}
fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}
