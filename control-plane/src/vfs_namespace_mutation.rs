use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;
use worker::{
    D1Database, D1PreparedStatement, Date, Env, Request, Response, Result, wasm_bindgen::JsValue,
};

use crate::{
    vfs_access,
    vfs_identifiers::new_uuid_v7_hex,
    vfs_mounts,
    vfs_put_commit::{RootPlan, RootPlanResult, plan_entry_removal_roots, plan_entry_rename_roots},
    vfs_tokens::AuthenticatedVfsToken,
};

const MAXIMUM_REBASE_ATTEMPTS: usize = 4;
const DELETE_GRACE_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoveRequest {
    name: String,
    expected_entry_revision: u64,
    idempotency_key: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RenameRequest {
    source_name: String,
    expected_source_revision: u64,
    destination_directory_id: String,
    destination_name: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
struct ReceiptQuery {
    idempotency_key: String,
}

#[derive(Deserialize)]
struct EntryRow {
    filesystem_id: String,
    kind: String,
    file_id: Option<String>,
    version_id: Option<String>,
    child_directory_id: Option<String>,
    revision: u64,
    size_bytes: u64,
    data_root: String,
    metadata_root: Option<String>,
}

#[derive(Deserialize)]
struct CountRow {
    count: u64,
}

#[derive(Deserialize)]
struct ReceiptRow {
    intent_id: String,
    request_sha256: String,
    filesystem_id: String,
    directory_id: String,
    entry_name: String,
    entry_kind: String,
    subject_id: String,
    catalog_revision_id: u64,
    delete_after: Option<u64>,
    committed_at: u64,
}

#[derive(Serialize)]
struct RemoveResponse {
    schema: &'static str,
    operation_id: String,
    filesystem_id: String,
    directory_id: String,
    name: String,
    kind: String,
    subject_id: String,
    catalog_revision_id: u64,
    delete_after: Option<u64>,
    committed_at: u64,
    state: &'static str,
}

#[derive(Deserialize)]
struct RenameReceiptRow {
    intent_id: String,
    request_sha256: String,
    filesystem_id: String,
    source_directory_id: String,
    source_name: String,
    destination_directory_id: String,
    destination_name: String,
    entry_kind: String,
    subject_id: String,
    entry_revision: u64,
    catalog_revision_id: u64,
    committed_at: u64,
}

#[derive(Serialize)]
struct RenameResponse {
    schema: &'static str,
    operation_id: String,
    filesystem_id: String,
    source_directory_id: String,
    source_name: String,
    destination_directory_id: String,
    destination_name: String,
    kind: String,
    subject_id: String,
    entry_revision: u64,
    catalog_revision_id: u64,
    committed_at: u64,
    state: &'static str,
}

/// Atomically removes one exact file or empty directory from the namespace.
/// File payload locations become tombstones for server-owned delayed GC.
#[allow(
    clippy::too_many_lines,
    reason = "remove keeps idempotency, optimistic Merkle proof, and tombstoning in one handler"
)]
pub(crate) async fn remove(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
) -> Result<Response> {
    let requested = request.json::<RemoveRequest>().await?;
    if !valid_identifier(directory_id)
        || !valid_name(&requested.name)
        || requested.expected_entry_revision == 0
        || !valid_idempotency_key(&requested.idempotency_key)
    {
        return Response::error("invalid VFS remove request", 400);
    }
    let request_sha256 = request_digest(directory_id, &requested)?;
    let database = env.d1("SKYDRIVER_INDEX")?;
    if !vfs_access::authorized(&database, token, directory_id, "entry.delete").await? {
        return Response::error("VFS entry-delete authority required", 403);
    }
    if let Some(receipt) = load_receipt(&database, &token.id, &requested.idempotency_key).await? {
        return receipt_response(receipt, Some(&request_sha256));
    }
    let Some(entry) = load_entry(&database, directory_id, &requested.name).await? else {
        return Response::error("VFS entry was not found", 404);
    };
    if entry.revision != requested.expected_entry_revision {
        return Response::error("VFS entry revision changed", 409);
    }
    let subject_id = match entry.kind.as_str() {
        "file" => entry.file_id.as_deref(),
        "directory" => entry.child_directory_id.as_deref(),
        _ => None,
    }
    .filter(|value| valid_identifier(value))
    .ok_or_else(|| worker::Error::RustError("VFS entry subject is invalid".to_owned()))?;
    if entry.kind == "directory" && !directory_is_empty(&database, subject_id).await? {
        return Response::error("VFS directory is not empty", 409);
    }
    if entry.kind == "directory" && vfs_mounts::is_explicit(&database, subject_id).await? {
        return Response::error("VFS mount point must be unmounted before removal", 409);
    }
    let operation_id = new_uuid_v7_hex()?;
    let now = current_unix_seconds();
    let delete_after = (entry.kind == "file").then_some(now + DELETE_GRACE_SECONDS);
    for _ in 0..MAXIMUM_REBASE_ATTEMPTS {
        let plan = match plan_entry_removal_roots(
            &database,
            &entry.filesystem_id,
            directory_id,
            &requested.name,
            requested.expected_entry_revision,
        )
        .await?
        {
            RootPlanResult::Planned(plan) => plan,
            RootPlanResult::Contended => continue,
            RootPlanResult::PreconditionChanged => {
                return Response::error("VFS remove precondition changed", 409);
            }
        };
        let statements = remove_statements(
            &database,
            token,
            &requested,
            &request_sha256,
            &operation_id,
            &entry,
            directory_id,
            subject_id,
            delete_after,
            &plan,
            now,
        )?;
        if database.batch(statements).await.is_ok() {
            let Some(receipt) =
                load_receipt(&database, &token.id, &requested.idempotency_key).await?
            else {
                return Response::error("VFS remove omitted its receipt", 409);
            };
            return receipt_response(receipt, Some(&request_sha256));
        }
        if let Some(receipt) =
            load_receipt(&database, &token.id, &requested.idempotency_key).await?
        {
            return receipt_response(receipt, Some(&request_sha256));
        }
    }
    Response::error("VFS directory roots remained contended", 409)
}

/// Atomically renames or moves one entry without copying its complete object.
#[allow(
    clippy::too_many_lines,
    reason = "rename binds two authorization scopes to one two-branch optimistic Merkle proof"
)]
pub(crate) async fn rename(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    source_directory_id: &str,
) -> Result<Response> {
    let requested = request.json::<RenameRequest>().await?;
    if !valid_identifier(source_directory_id)
        || !valid_identifier(&requested.destination_directory_id)
        || !valid_name(&requested.source_name)
        || !valid_name(&requested.destination_name)
        || requested.expected_source_revision == 0
        || !valid_idempotency_key(&requested.idempotency_key)
        || (source_directory_id == requested.destination_directory_id
            && requested.source_name == requested.destination_name)
    {
        return Response::error("invalid VFS rename request", 400);
    }
    let request_sha256 = rename_request_digest(source_directory_id, &requested)?;
    let database = env.d1("SKYDRIVER_INDEX")?;
    if !vfs_access::authorized(&database, token, source_directory_id, "entry.delete").await?
        || !vfs_access::authorized(
            &database,
            token,
            &requested.destination_directory_id,
            "content.write",
        )
        .await?
    {
        return Response::error("VFS rename requires entry.delete and content.write", 403);
    }
    if let Some(receipt) =
        load_rename_receipt(&database, &token.id, &requested.idempotency_key).await?
    {
        return rename_receipt_response(receipt, Some(&request_sha256));
    }
    let Some(entry) = load_entry(&database, source_directory_id, &requested.source_name).await?
    else {
        return Response::error("VFS rename source was not found", 404);
    };
    if entry.revision != requested.expected_source_revision {
        return Response::error("VFS rename source revision changed", 409);
    }
    let Some(destination_filesystem_id) =
        load_directory_filesystem(&database, &requested.destination_directory_id).await?
    else {
        return Response::error("VFS rename destination was not found", 404);
    };
    if destination_filesystem_id != entry.filesystem_id {
        return Response::error("VFS rename cannot cross filesystems", 409);
    }
    let subject_id = match entry.kind.as_str() {
        "file" => entry.file_id.as_deref(),
        "directory" => entry.child_directory_id.as_deref(),
        _ => None,
    }
    .filter(|value| valid_identifier(value))
    .ok_or_else(|| worker::Error::RustError("VFS rename subject is invalid".to_owned()))?;
    if !vfs_mounts::same_effective_driver(
        &database,
        source_directory_id,
        &requested.destination_directory_id,
    )
    .await?
    {
        return Response::error("VFS rename cannot cross mounted drivers", 409);
    }
    if entry.kind == "directory" && vfs_mounts::is_explicit(&database, subject_id).await? {
        return Response::error("VFS mount point cannot be renamed", 409);
    }
    let operation_id = new_uuid_v7_hex()?;
    let now = current_unix_seconds();
    for _ in 0..MAXIMUM_REBASE_ATTEMPTS {
        let plan = match plan_entry_rename_roots(
            &database,
            &entry.filesystem_id,
            source_directory_id,
            &requested.source_name,
            requested.expected_source_revision,
            &requested.destination_directory_id,
            &requested.destination_name,
        )
        .await?
        {
            RootPlanResult::Planned(plan) => plan,
            RootPlanResult::Contended => continue,
            RootPlanResult::PreconditionChanged => {
                return Response::error("VFS rename precondition changed", 409);
            }
        };
        let statements = rename_statements(
            &database,
            token,
            &requested,
            &request_sha256,
            &operation_id,
            &entry,
            source_directory_id,
            subject_id,
            &plan,
            now,
        )?;
        if database.batch(statements).await.is_ok() {
            let Some(receipt) =
                load_rename_receipt(&database, &token.id, &requested.idempotency_key).await?
            else {
                return Response::error("VFS rename omitted its receipt", 409);
            };
            return rename_receipt_response(receipt, Some(&request_sha256));
        }
        if let Some(receipt) =
            load_rename_receipt(&database, &token.id, &requested.idempotency_key).await?
        {
            return rename_receipt_response(receipt, Some(&request_sha256));
        }
    }
    Response::error("VFS directory roots remained contended", 409)
}

/// Looks up a committed removal by the token-scoped idempotency identity.
/// This makes a lost mutation response recoverable without retaining locks.
pub(crate) async fn remove_receipt(
    request: &Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
) -> Result<Response> {
    let Ok(query) = request.query::<ReceiptQuery>() else {
        return Response::error("invalid VFS remove receipt query", 400);
    };
    if !valid_idempotency_key(&query.idempotency_key) {
        return Response::error("invalid VFS remove receipt query", 400);
    }
    let database = env.d1("SKYDRIVER_INDEX")?;
    let Some(receipt) = load_receipt(&database, &token.id, &query.idempotency_key).await? else {
        return Response::error("VFS remove receipt was not found", 404);
    };
    receipt_response(receipt, None)
}

/// Looks up a committed rename by the token-scoped idempotency identity.
pub(crate) async fn rename_receipt(
    request: &Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
) -> Result<Response> {
    let Ok(query) = request.query::<ReceiptQuery>() else {
        return Response::error("invalid VFS rename receipt query", 400);
    };
    if !valid_idempotency_key(&query.idempotency_key) {
        return Response::error("invalid VFS rename receipt query", 400);
    }
    let database = env.d1("SKYDRIVER_INDEX")?;
    let Some(receipt) = load_rename_receipt(&database, &token.id, &query.idempotency_key).await?
    else {
        return Response::error("VFS rename receipt was not found", 404);
    };
    rename_receipt_response(receipt, None)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the atomic cross-branch rename remains visible as one D1 statement set"
)]
fn rename_statements(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    requested: &RenameRequest,
    request_sha256: &str,
    operation_id: &str,
    entry: &EntryRow,
    source_directory_id: &str,
    subject_id: &str,
    plan: &RootPlan,
    now: u64,
) -> Result<Vec<D1PreparedStatement>> {
    let mut statements = vec![
        database
            .prepare(
                "INSERT INTO vfs_rename_intents (
             id, filesystem_id, principal_id, token_id, source_directory_id,
             source_name, expected_source_revision, destination_directory_id,
             destination_name, entry_kind, subject_id, request_sha256,
             idempotency_key, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                JsValue::from_str(&entry.filesystem_id),
                JsValue::from_str(&token.principal_id),
                JsValue::from_str(&token.id),
                JsValue::from_str(source_directory_id),
                JsValue::from_str(&requested.source_name),
                number(requested.expected_source_revision),
                JsValue::from_str(&requested.destination_directory_id),
                JsValue::from_str(&requested.destination_name),
                JsValue::from_str(&entry.kind),
                JsValue::from_str(subject_id),
                JsValue::from_str(request_sha256),
                JsValue::from_str(&requested.idempotency_key),
                number(now),
            ])?,
    ];
    for (ordinal, update) in plan.directories.iter().enumerate() {
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_rename_directory_updates (
                 intent_id, ordinal, directory_id, expected_revision,
                 expected_data_root, new_data_root
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .bind(&[
                    JsValue::from_str(operation_id),
                    number(
                        u64::try_from(ordinal)
                            .map_err(|error| worker::Error::RustError(error.to_string()))?,
                    ),
                    JsValue::from_str(&update.directory_id),
                    number(update.expected_revision),
                    JsValue::from_str(&update.expected_root),
                    JsValue::from_str(&update.new_root),
                ])?,
        );
    }
    statements.push(
        database
            .prepare(
                "DELETE FROM vfs_directory_entries
         WHERE directory_id = ?1 AND name = ?2 AND revision = ?3",
            )
            .bind(&[
                JsValue::from_str(source_directory_id),
                JsValue::from_str(&requested.source_name),
                number(requested.expected_source_revision),
            ])?,
    );
    if entry.kind == "directory" {
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_directories SET parent_id = ?1, name = ?2,
                 revision = revision + 1, updated_at = MAX(updated_at, ?3)
             WHERE id = ?4 AND parent_id = ?5 AND name = ?6 AND state = 'active'",
                )
                .bind(&[
                    JsValue::from_str(&requested.destination_directory_id),
                    JsValue::from_str(&requested.destination_name),
                    number(now),
                    JsValue::from_str(subject_id),
                    JsValue::from_str(source_directory_id),
                    JsValue::from_str(&requested.source_name),
                ])?,
        );
    }
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_directory_entries (
             directory_id, name, kind, file_id, version_id, child_directory_id,
             size_bytes, data_root, metadata_root, revision, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            )
            .bind(&[
                JsValue::from_str(&requested.destination_directory_id),
                JsValue::from_str(&requested.destination_name),
                JsValue::from_str(&entry.kind),
                entry
                    .file_id
                    .as_deref()
                    .map_or(JsValue::NULL, JsValue::from_str),
                entry
                    .version_id
                    .as_deref()
                    .map_or(JsValue::NULL, JsValue::from_str),
                entry
                    .child_directory_id
                    .as_deref()
                    .map_or(JsValue::NULL, JsValue::from_str),
                number(entry.size_bytes),
                JsValue::from_str(&entry.data_root),
                entry
                    .metadata_root
                    .as_deref()
                    .map_or(JsValue::NULL, JsValue::from_str),
                number(entry.revision + 1),
                number(now),
            ])?,
    );
    for update in &plan.directories {
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_directories SET data_root = ?1, revision = revision + 1,
                 updated_at = MAX(updated_at, ?2)
             WHERE id = ?3 AND revision = ?4 AND data_root = ?5",
                )
                .bind(&[
                    JsValue::from_str(&update.new_root),
                    number(now),
                    JsValue::from_str(&update.directory_id),
                    number(update.expected_revision),
                    JsValue::from_str(&update.expected_root),
                ])?,
        );
    }
    for link in &plan.links {
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_directory_entries SET data_root = ?1, revision = revision + 1,
                 updated_at = MAX(updated_at, ?2)
             WHERE directory_id = ?3 AND name = ?4 AND kind = 'directory'
               AND child_directory_id = ?5 AND revision = ?6",
                )
                .bind(&[
                    JsValue::from_str(&link.new_child_root),
                    number(now),
                    JsValue::from_str(&link.parent_directory_id),
                    JsValue::from_str(&link.name),
                    JsValue::from_str(&link.child_directory_id),
                    number(link.expected_revision),
                ])?,
        );
    }
    statements.extend(catalog_statements(
        database,
        &entry.filesystem_id,
        operation_id,
        &plan.root,
        "rename",
        now,
    )?);
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_rename_receipts (
             intent_id, token_id, request_sha256, filesystem_id,
             source_directory_id, source_name, destination_directory_id,
             destination_name, entry_kind, subject_id, entry_revision,
             catalog_revision_id, committed_at
         ) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                  catalog.id, ?12
           FROM vfs_catalog_revisions AS catalog
          WHERE catalog.mutation_kind = 'rename' AND catalog.mutation_id = ?1",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                JsValue::from_str(&token.id),
                JsValue::from_str(request_sha256),
                JsValue::from_str(&entry.filesystem_id),
                JsValue::from_str(source_directory_id),
                JsValue::from_str(&requested.source_name),
                JsValue::from_str(&requested.destination_directory_id),
                JsValue::from_str(&requested.destination_name),
                JsValue::from_str(&entry.kind),
                JsValue::from_str(subject_id),
                number(entry.revision + 1),
                number(now),
            ])?,
    );
    statements.push(database.prepare(
        "INSERT INTO vfs_audit_events (
             filesystem_id, principal_id, token_id, event_kind, subject_kind,
             subject_id, details_json, created_at
         ) VALUES (?1, ?2, ?3, 'entry_renamed', ?4, ?5, ?6, ?7)",
    ).bind(&[
        JsValue::from_str(&entry.filesystem_id), JsValue::from_str(&token.principal_id),
        JsValue::from_str(&token.id), JsValue::from_str(&entry.kind), JsValue::from_str(subject_id),
        JsValue::from_str(&serde_json::json!({
            "source_directory_id": source_directory_id, "source_name": requested.source_name,
            "destination_directory_id": requested.destination_directory_id,
            "destination_name": requested.destination_name,
        }).to_string()), number(now),
    ])?);
    Ok(statements)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the atomic remove publication remains visible as one statement set"
)]
fn remove_statements(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    requested: &RemoveRequest,
    request_sha256: &str,
    operation_id: &str,
    entry: &EntryRow,
    directory_id: &str,
    subject_id: &str,
    delete_after: Option<u64>,
    plan: &RootPlan,
    now: u64,
) -> Result<Vec<D1PreparedStatement>> {
    let mut statements = vec![
        database
            .prepare(
                "INSERT INTO vfs_remove_intents (
             id, filesystem_id, principal_id, token_id, directory_id, entry_name,
             expected_entry_revision, entry_kind, subject_id, request_sha256,
             idempotency_key, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                JsValue::from_str(&entry.filesystem_id),
                JsValue::from_str(&token.principal_id),
                JsValue::from_str(&token.id),
                JsValue::from_str(directory_id),
                JsValue::from_str(&requested.name),
                number(requested.expected_entry_revision),
                JsValue::from_str(&entry.kind),
                JsValue::from_str(subject_id),
                JsValue::from_str(request_sha256),
                JsValue::from_str(&requested.idempotency_key),
                number(now),
            ])?,
    ];
    for (ordinal, update) in plan.directories.iter().enumerate() {
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_remove_directory_updates (
                 intent_id, ordinal, directory_id, expected_revision,
                 expected_data_root, new_data_root
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .bind(&[
                    JsValue::from_str(operation_id),
                    number(
                        u64::try_from(ordinal)
                            .map_err(|error| worker::Error::RustError(error.to_string()))?,
                    ),
                    JsValue::from_str(&update.directory_id),
                    number(update.expected_revision),
                    JsValue::from_str(&update.expected_root),
                    JsValue::from_str(&update.new_root),
                ])?,
        );
    }
    statements.push(
        database
            .prepare(
                "DELETE FROM vfs_directory_entries
         WHERE directory_id = ?1 AND name = ?2 AND revision = ?3",
            )
            .bind(&[
                JsValue::from_str(directory_id),
                JsValue::from_str(&requested.name),
                number(requested.expected_entry_revision),
            ])?,
    );
    if entry.kind == "file" {
        let version_id = entry.version_id.as_deref().ok_or_else(|| {
            worker::Error::RustError("VFS file removal omitted version identity".to_owned())
        })?;
        statements.extend([
            database
                .prepare(
                    "UPDATE vfs_files SET current_version_id = NULL, state = 'tombstoned',
                     revision = revision + 1, updated_at = MAX(updated_at, ?1)
                 WHERE id = ?2 AND state = 'active' AND current_version_id = ?3",
                )
                .bind(&[
                    number(now),
                    JsValue::from_str(subject_id),
                    JsValue::from_str(version_id),
                ])?,
            database
                .prepare(
                    "UPDATE vfs_file_versions SET state = 'tombstoned'
                 WHERE id = ?1 AND state = 'published'",
                )
                .bind(&[JsValue::from_str(version_id)])?,
            database
                .prepare(
                    "UPDATE vfs_locations SET state = 'tombstoned', delete_after = ?1,
                     revision = revision + 1, updated_at = MAX(updated_at, ?2)
                 WHERE version_id = ?3 AND state = 'available'",
                )
                .bind(&[
                    number(delete_after.unwrap_or(now)),
                    number(now),
                    JsValue::from_str(version_id),
                ])?,
        ]);
    } else {
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_directories SET state = 'tombstoned', revision = revision + 1,
                 updated_at = MAX(updated_at, ?1)
             WHERE id = ?2 AND state = 'active'",
                )
                .bind(&[number(now), JsValue::from_str(subject_id)])?,
        );
    }
    for (index, update) in plan.directories.iter().enumerate() {
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_directories SET data_root = ?1, revision = revision + 1,
                 updated_at = MAX(updated_at, ?2)
             WHERE id = ?3 AND revision = ?4 AND data_root = ?5",
                )
                .bind(&[
                    JsValue::from_str(&update.new_root),
                    number(now),
                    JsValue::from_str(&update.directory_id),
                    number(update.expected_revision),
                    JsValue::from_str(&update.expected_root),
                ])?,
        );
        if let Some(link) = plan.links.get(index) {
            statements.push(
                database
                    .prepare(
                        "UPDATE vfs_directory_entries SET data_root = ?1, revision = revision + 1,
                     updated_at = MAX(updated_at, ?2)
                 WHERE directory_id = ?3 AND name = ?4 AND kind = 'directory'
                   AND child_directory_id = ?5 AND revision = ?6",
                    )
                    .bind(&[
                        JsValue::from_str(&link.new_child_root),
                        number(now),
                        JsValue::from_str(&link.parent_directory_id),
                        JsValue::from_str(&link.name),
                        JsValue::from_str(&link.child_directory_id),
                        number(link.expected_revision),
                    ])?,
            );
        }
    }
    statements.extend(catalog_statements(
        database,
        &entry.filesystem_id,
        operation_id,
        &plan.root,
        "remove",
        now,
    )?);
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_remove_receipts (
             intent_id, token_id, request_sha256, filesystem_id, directory_id,
             entry_name, entry_kind, subject_id, catalog_revision_id, delete_after, committed_at
         ) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, catalog.id, ?9, ?10
           FROM vfs_catalog_revisions AS catalog
          WHERE catalog.mutation_kind = 'remove' AND catalog.mutation_id = ?1",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                JsValue::from_str(&token.id),
                JsValue::from_str(request_sha256),
                JsValue::from_str(&entry.filesystem_id),
                JsValue::from_str(directory_id),
                JsValue::from_str(&requested.name),
                JsValue::from_str(&entry.kind),
                JsValue::from_str(subject_id),
                delete_after.map_or(JsValue::NULL, number),
                number(now),
            ])?,
    );
    statements.push(database.prepare(
        "INSERT INTO vfs_audit_events (
             filesystem_id, principal_id, token_id, event_kind, subject_kind,
             subject_id, details_json, created_at
         ) VALUES (?1, ?2, ?3, 'entry_removed', ?4, ?5, ?6, ?7)",
    ).bind(&[
        JsValue::from_str(&entry.filesystem_id), JsValue::from_str(&token.principal_id),
        JsValue::from_str(&token.id), JsValue::from_str(&entry.kind),
        JsValue::from_str(subject_id),
        JsValue::from_str(&serde_json::json!({"directory_id": directory_id, "name": requested.name, "delete_after": delete_after}).to_string()),
        number(now),
    ])?);
    Ok(statements)
}

fn catalog_statements(
    database: &D1Database,
    filesystem_id: &str,
    operation_id: &str,
    root: &str,
    mutation_kind: &str,
    now: u64,
) -> Result<Vec<D1PreparedStatement>> {
    Ok(vec![
        database.prepare(
            "INSERT INTO vfs_catalog_revisions (
                 filesystem_id, parent_revision_id, root_data_root, state,
                 created_at, mutation_kind, mutation_id
             ) VALUES (?1, (SELECT revision_id FROM vfs_catalog_mutation_heads WHERE filesystem_id = ?1),
                       ?2, 'pending', ?3, ?4, ?5)",
        ).bind(&[JsValue::from_str(filesystem_id), JsValue::from_str(root), number(now), JsValue::from_str(mutation_kind), JsValue::from_str(operation_id)])?,
        database.prepare(
            "INSERT INTO vfs_catalog_outbox (revision_id, updated_at)
             SELECT id, ?1 FROM vfs_catalog_revisions
              WHERE mutation_kind = ?2 AND mutation_id = ?3",
        ).bind(&[number(now), JsValue::from_str(mutation_kind), JsValue::from_str(operation_id)])?,
        database.prepare(
            "INSERT INTO vfs_catalog_mutation_heads (filesystem_id, revision_id, updated_at)
             SELECT filesystem_id, id, ?1 FROM vfs_catalog_revisions
              WHERE mutation_kind = ?2 AND mutation_id = ?3
             ON CONFLICT(filesystem_id) DO UPDATE SET revision_id = excluded.revision_id,
                 revision = vfs_catalog_mutation_heads.revision + 1, updated_at = excluded.updated_at",
        ).bind(&[number(now), JsValue::from_str(mutation_kind), JsValue::from_str(operation_id)])?,
    ])
}

async fn load_entry(
    database: &D1Database,
    directory_id: &str,
    name: &str,
) -> Result<Option<EntryRow>> {
    database
        .prepare(
            "SELECT directory.filesystem_id, entry.kind, entry.file_id, entry.version_id,
                entry.child_directory_id, entry.revision, entry.size_bytes,
                entry.data_root, entry.metadata_root
         FROM vfs_directory_entries AS entry
         JOIN vfs_directories AS directory ON directory.id = entry.directory_id
         WHERE entry.directory_id = ?1 AND entry.name = ?2 AND directory.state = 'active'",
        )
        .bind(&[JsValue::from_str(directory_id), JsValue::from_str(name)])?
        .first::<EntryRow>(None)
        .await
}

async fn load_directory_filesystem(
    database: &D1Database,
    directory_id: &str,
) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct FilesystemRow {
        filesystem_id: String,
    }
    Ok(database
        .prepare(
            "SELECT filesystem_id FROM vfs_directories
             WHERE id = ?1 AND state = 'active'",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<FilesystemRow>(None)
        .await?
        .map(|row| row.filesystem_id))
}

async fn directory_is_empty(database: &D1Database, directory_id: &str) -> Result<bool> {
    Ok(database
        .prepare("SELECT COUNT(*) AS count FROM vfs_directory_entries WHERE directory_id = ?1")
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<CountRow>(None)
        .await?
        .is_some_and(|row| row.count == 0))
}

async fn load_receipt(
    database: &D1Database,
    token_id: &str,
    idempotency_key: &str,
) -> Result<Option<ReceiptRow>> {
    database
        .prepare(
            "SELECT receipt.intent_id, receipt.request_sha256, receipt.filesystem_id,
                receipt.directory_id, receipt.entry_name, receipt.entry_kind,
                receipt.subject_id, receipt.catalog_revision_id, receipt.delete_after,
                receipt.committed_at
         FROM vfs_remove_receipts AS receipt
         JOIN vfs_remove_intents AS intent ON intent.id = receipt.intent_id
         WHERE receipt.token_id = ?1 AND intent.idempotency_key = ?2",
        )
        .bind(&[
            JsValue::from_str(token_id),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<ReceiptRow>(None)
        .await
}

async fn load_rename_receipt(
    database: &D1Database,
    token_id: &str,
    idempotency_key: &str,
) -> Result<Option<RenameReceiptRow>> {
    database
        .prepare(
            "SELECT receipt.intent_id, receipt.request_sha256, receipt.filesystem_id,
                receipt.source_directory_id, receipt.source_name,
                receipt.destination_directory_id, receipt.destination_name,
                receipt.entry_kind, receipt.subject_id, receipt.entry_revision,
                receipt.catalog_revision_id, receipt.committed_at
             FROM vfs_rename_receipts AS receipt
             JOIN vfs_rename_intents AS intent ON intent.id = receipt.intent_id
             WHERE receipt.token_id = ?1 AND intent.idempotency_key = ?2",
        )
        .bind(&[
            JsValue::from_str(token_id),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<RenameReceiptRow>(None)
        .await
}

fn receipt_response(receipt: ReceiptRow, expected_digest: Option<&str>) -> Result<Response> {
    if expected_digest.is_some_and(|digest| receipt.request_sha256 != digest) {
        return Response::error("VFS remove idempotency identity changed", 409);
    }
    let mut response = Response::from_json(&RemoveResponse {
        schema: "carrack.vfs.remove-receipt.v1",
        operation_id: receipt.intent_id,
        filesystem_id: receipt.filesystem_id,
        directory_id: receipt.directory_id,
        name: receipt.entry_name,
        kind: receipt.entry_kind,
        subject_id: receipt.subject_id,
        catalog_revision_id: receipt.catalog_revision_id,
        delete_after: receipt.delete_after,
        committed_at: receipt.committed_at,
        state: "committed",
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn rename_receipt_response(
    receipt: RenameReceiptRow,
    expected_digest: Option<&str>,
) -> Result<Response> {
    if expected_digest.is_some_and(|digest| receipt.request_sha256 != digest) {
        return Response::error("VFS rename idempotency identity changed", 409);
    }
    let mut response = Response::from_json(&RenameResponse {
        schema: "carrack.vfs.rename-receipt.v1",
        operation_id: receipt.intent_id,
        filesystem_id: receipt.filesystem_id,
        source_directory_id: receipt.source_directory_id,
        source_name: receipt.source_name,
        destination_directory_id: receipt.destination_directory_id,
        destination_name: receipt.destination_name,
        kind: receipt.entry_kind,
        subject_id: receipt.subject_id,
        entry_revision: receipt.entry_revision,
        catalog_revision_id: receipt.catalog_revision_id,
        committed_at: receipt.committed_at,
        state: "committed",
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn request_digest(directory_id: &str, request: &RemoveRequest) -> Result<String> {
    let encoded = serde_json::to_vec(&serde_json::json!({
        "directory_id": directory_id,
        "expected_entry_revision": request.expected_entry_revision,
        "idempotency_key": request.idempotency_key,
        "name": request.name,
    }))?;
    lowercase_hex(&Sha256::digest(encoded))
}

fn rename_request_digest(source_directory_id: &str, request: &RenameRequest) -> Result<String> {
    let encoded = serde_json::to_vec(&serde_json::json!({
        "destination_directory_id": request.destination_directory_id,
        "destination_name": request.destination_name,
        "expected_source_revision": request.expected_source_revision,
        "idempotency_key": request.idempotency_key,
        "source_directory_id": source_directory_id,
        "source_name": request.source_name,
    }))?;
    lowercase_hex(&Sha256::digest(encoded))
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 255
        && !value.contains(['/', '\0'])
        && value.nfc().eq(value.chars())
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn lowercase_hex(bytes: &[u8]) -> Result<String> {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
    }
    Ok(encoded)
}

fn number(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}
fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}
