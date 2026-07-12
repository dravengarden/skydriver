use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{
    D1Database, D1PreparedStatement, Env, Request, Response, Result, wasm_bindgen::JsValue,
};

use crate::{clients::AuthenticatedClient, copying, manifests};

const MAXIMUM_REPAIR_TARGETS: usize = 50_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    manifest_sha256: String,
    target_driver_id: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    manifest_sha256: String,
    objects: Vec<CompletedObject>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletedObject {
    driver_id: String,
    storage_key: String,
    provider_version: Option<String>,
    etag: Option<String>,
    size_bytes: u64,
}

#[derive(Deserialize, Serialize)]
struct RepairOperation {
    id: String,
    namespace_id: String,
    kind: String,
    state: String,
    phase: String,
    requested_by: String,
    incarnation: String,
    revision: u64,
    useful_bytes_total: u64,
    version_id: String,
    object_id: String,
    generation: u64,
    manifest_sha256: String,
    recovery_revision: u64,
    target_driver_id: String,
    expected_object_count: u64,
    expected_target_count: u64,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
struct RecoveryRow {
    version_id: String,
    object_id: String,
    generation: u64,
    manifest_sha256: String,
    recovery_sha256: Option<String>,
    revision: u64,
    r2_storage_key: String,
    r2_version: Option<String>,
    ciphertext_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RepairTargetRow {
    id: String,
    location_revision: u64,
    extent_sha256: String,
    driver_id: String,
    storage_key: String,
    provider_version: Option<String>,
    offset: u64,
    length: u64,
}

#[derive(Serialize)]
struct RepairObjectCandidate {
    storage_key: String,
    provider_version: Option<String>,
    expected_bytes: u64,
}

struct RepairPlanShape {
    objects: Vec<RepairObjectCandidate>,
    useful_bytes: u64,
}

#[derive(Deserialize)]
struct RepairObjectRow {
    storage_key: String,
    provider_version: Option<String>,
    expected_bytes: u64,
}

#[derive(Deserialize)]
struct CompletionRow {
    report_sha256: String,
    object_count: u64,
    location_count: u64,
    ciphertext_bytes: u64,
    recovery_revision: u64,
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Serialize)]
struct CompletedRepair {
    operation_id: String,
    manifest_sha256: String,
    state: &'static str,
    objects_repaired: u64,
    locations_repaired: u64,
    ciphertext_bytes: u64,
    recovery_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct SnapshotHead {
    manifest_sha256: String,
    recovery_sha256: Option<String>,
    recovery_revision: u64,
    r2_storage_key: String,
    r2_version: Option<String>,
    recovery_bytes: u64,
    target_driver_id: String,
    useful_bytes_total: u64,
    expected_object_count: u64,
    expected_target_count: u64,
}

#[derive(Deserialize, Serialize)]
struct IndexedLocation {
    id: String,
    extent_sha256: String,
    driver_id: String,
    storage_key: String,
    provider_version: Option<String>,
    offset: u64,
    length: u64,
    state: String,
}

#[derive(Deserialize)]
struct TargetIDRow {
    location_id: String,
}

#[derive(Serialize)]
struct RepairSnapshot {
    recovery: serde_json::Value,
    recovery_revision: u64,
    target_driver_id: String,
    target_location_ids: Vec<String>,
    locations: Vec<IndexedLocation>,
}

#[derive(Hash, Eq, PartialEq)]
struct LocationIdentity {
    extent_sha256: String,
    driver_id: String,
    storage_key: String,
    provider_version: Option<String>,
    offset: u64,
    length: u64,
}

impl From<&manifests::Location> for LocationIdentity {
    fn from(location: &manifests::Location) -> Self {
        Self {
            extent_sha256: location.extent_sha256.clone(),
            driver_id: location.driver_id.clone(),
            storage_key: location.storage_key.clone(),
            provider_version: location.provider_version.clone(),
            offset: location.offset,
            length: location.length,
        }
    }
}

impl From<&RepairTargetRow> for LocationIdentity {
    fn from(location: &RepairTargetRow) -> Self {
        Self {
            extent_sha256: location.extent_sha256.clone(),
            driver_id: location.driver_id.clone(),
            storage_key: location.storage_key.clone(),
            provider_version: location.provider_version.clone(),
            offset: location.offset,
            length: location.length,
        }
    }
}

pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !copying::valid_hex(&requested.namespace_id, 32)
        || !copying::valid_hex(&requested.manifest_sha256, 64)
        || !copying::valid_string(&requested.target_driver_id, 256)
        || !copying::valid_string(&requested.idempotency_key, 256)
    {
        return Response::error("invalid repair operation", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    if let Some(existing) = find_operation(
        &database,
        &requested.namespace_id,
        &requested.idempotency_key,
        &client.id,
    )
    .await?
    {
        return operation_response(&existing, &requested);
    }

    let Some(recovery) = load_recovery_row(&database, client, &requested).await? else {
        return Response::error("published repair recovery is unavailable", 404);
    };
    let loaded = copying::load_recovery(
        env,
        &recovery.r2_storage_key,
        recovery.r2_version.as_deref(),
        recovery.ciphertext_bytes,
    )
    .await?;
    if !recovery_matches(&loaded, &recovery, &requested) {
        return Response::error("published repair recovery identity changed", 503);
    }

    let targets =
        load_missing_targets(&database, &recovery.version_id, &requested.target_driver_id).await?;
    if targets.is_empty() {
        return Response::error("repair target driver has no missing locations", 409);
    }
    if targets.len() > MAXIMUM_REPAIR_TARGETS {
        return Response::error("repair target set exceeds the operation bound", 409);
    }
    let plan = match validate_targets(&loaded.validated, &targets) {
        Ok(plan) => plan,
        Err(error) => return Response::error(error, 409),
    };

    let operation_id = copying::random_hex()?;
    let now = copying::current_unix_seconds().to_string();
    let statements = create_statements(
        &database,
        client,
        &requested,
        &recovery,
        &plan.objects,
        &targets,
        plan.useful_bytes,
        &operation_id,
        &now,
    )?;
    database.batch(statements).await?;

    let operation = find_operation(
        &database,
        &requested.namespace_id,
        &requested.idempotency_key,
        &client.id,
    )
    .await?;
    let Some(operation) = operation else {
        return Response::error("repair rejected or idempotency identity conflicts", 409);
    };

    operation_response(&operation, &requested)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "repair creation keeps one atomic operation, target plan, and component batch visible"
)]
fn create_statements(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &CreateRequest,
    recovery: &RecoveryRow,
    objects: &[RepairObjectCandidate],
    targets: &[RepairTargetRow],
    useful_bytes: u64,
    operation_id: &str,
    now: &str,
) -> Result<Vec<D1PreparedStatement>> {
    let target_count = u64::try_from(targets.len())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let object_count = u64::try_from(objects.len())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let encoded_objects = serde_json::to_string(objects)
        .map_err(|error| worker::Error::RustError(format!("encode repair objects: {error}")))?;
    let encoded_targets = serde_json::to_string(targets)
        .map_err(|error| worker::Error::RustError(format!("encode repair targets: {error}")))?;
    let insert_operation = database
        .prepare(
            "INSERT INTO operations (\
                 id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                 incarnation, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT ?1, ?2, 'copy', 'planned', 'planned', ?3, ?4, \
                    control.incarnation, ?5, ?6, ?6 \
             FROM control_plane_state AS control \
             JOIN recovery_manifests AS recovery ON recovery.manifest_sha256 = ?7 \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN driver_instances AS target ON target.id = ?8 \
             WHERE control.singleton = 1 AND control.mode = 'active' \
               AND object.namespace_id = ?2 AND version.state = 'published' \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND recovery.version_id = ?9 AND recovery.revision = ?10 \
               AND target.enabled = 1 \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?4 AND namespace_id = ?2 \
                            AND role IN ('relay', 'administrator')) \
             ON CONFLICT(namespace_id, idempotency_key) DO NOTHING",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            copying::integer(useful_bytes)?,
            JsValue::from_str(now),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.target_driver_id),
            JsValue::from_str(&recovery.version_id),
            copying::integer(recovery.revision)?,
        ])?;
    let insert_intent = database
        .prepare(
            "INSERT OR IGNORE INTO repair_intents (\
                 operation_id, version_id, manifest_sha256, recovery_revision, \
                 target_driver_id, expected_object_count, expected_target_count, created_at\
             ) \
             SELECT operation.id, recovery.version_id, recovery.manifest_sha256, \
                    recovery.revision, ?1, ?2, ?3, ?4 \
             FROM operations AS operation \
             JOIN recovery_manifests AS recovery ON recovery.manifest_sha256 = ?5 \
             WHERE operation.namespace_id = ?6 AND operation.idempotency_key = ?7 \
               AND operation.requested_by = ?8 AND operation.kind = 'copy' \
               AND recovery.version_id = ?9 AND recovery.revision = ?10 \
               AND NOT EXISTS(SELECT 1 FROM copy_intents AS copy \
                              WHERE copy.operation_id = operation.id)",
        )
        .bind(&[
            JsValue::from_str(&requested.target_driver_id),
            copying::integer(object_count)?,
            copying::integer(target_count)?,
            JsValue::from_str(now),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            JsValue::from_str(&recovery.version_id),
            copying::integer(recovery.revision)?,
        ])?;
    let insert_objects = database
        .prepare(
            "INSERT OR IGNORE INTO repair_objects (\
                 operation_id, storage_key, provider_version, expected_bytes, state\
             ) \
             SELECT operation.id, json_extract(candidate.value, '$.storage_key'), \
                    json_extract(candidate.value, '$.provider_version'), \
                    json_extract(candidate.value, '$.expected_bytes'), 'planned' \
             FROM operations AS operation \
             JOIN repair_intents AS intent ON intent.operation_id = operation.id \
             JOIN json_each(?1) AS candidate \
             WHERE operation.namespace_id = ?2 AND operation.idempotency_key = ?3 \
               AND operation.requested_by = ?4 AND operation.kind = 'copy'",
        )
        .bind(&[
            JsValue::from_str(&encoded_objects),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?;
    let insert_targets = database
        .prepare(
            "INSERT OR IGNORE INTO repair_targets (\
                 operation_id, location_id, location_revision, storage_key, provider_version, \
                 storage_offset, storage_length, state\
             ) \
             SELECT operation.id, location.id, location.revision, location.storage_key, \
                    location.provider_version, location.storage_offset, \
                    location.storage_length, 'planned' \
             FROM operations AS operation \
             JOIN repair_intents AS intent ON intent.operation_id = operation.id \
             JOIN json_each(?1) AS candidate \
             JOIN locations AS location \
               ON location.id = json_extract(candidate.value, '$.id') \
             JOIN extents AS extent ON extent.id = location.extent_id \
             JOIN version_packs AS version_pack ON version_pack.pack_id = extent.pack_id \
             WHERE operation.namespace_id = ?2 AND operation.idempotency_key = ?3 \
               AND operation.requested_by = ?4 AND operation.kind = 'copy' \
               AND version_pack.version_id = intent.version_id \
               AND location.driver_id = intent.target_driver_id \
               AND location.state = 'missing' \
               AND location.revision = json_extract(candidate.value, '$.location_revision') \
               AND extent.ciphertext_sha256 = json_extract(candidate.value, '$.extent_sha256') \
               AND location.driver_id = json_extract(candidate.value, '$.driver_id') \
               AND location.storage_key = json_extract(candidate.value, '$.storage_key') \
               AND location.provider_version IS \
                   json_extract(candidate.value, '$.provider_version') \
               AND location.storage_offset = json_extract(candidate.value, '$.offset') \
               AND location.storage_length = json_extract(candidate.value, '$.length')",
        )
        .bind(&[
            JsValue::from_str(&encoded_targets),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?;
    let insert_component = database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, destination_driver_id, state, \
                 useful_bytes_total, created_at, updated_at\
             ) \
             SELECT operation.id || '/repair', operation.id, ?1, 'repair', \
                    intent.target_driver_id, 'pending', operation.useful_bytes_total, ?2, ?2 \
             FROM operations AS operation \
             JOIN repair_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?1 AND operation.kind = 'copy'",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(now),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
        ])?;

    Ok(vec![
        insert_operation,
        insert_intent,
        insert_objects,
        insert_targets,
        insert_component,
    ])
}

pub(crate) async fn fetch_snapshot(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid repair operation ID", 400);
    }
    let requested = request.json::<SnapshotRequest>().await?;
    if !copying::valid_string(&requested.lease_id, 256)
        || !copying::valid_hex(&requested.incarnation, 32)
        || requested.fencing_token == 0
    {
        return Response::error("invalid repair snapshot fence", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let head = load_snapshot_head(&database, operation_id, client, &requested).await?;
    let Some(head) = head else {
        return Response::error("repair snapshot fence is stale or unavailable", 409);
    };
    let loaded = copying::load_recovery(
        env,
        &head.r2_storage_key,
        head.r2_version.as_deref(),
        head.recovery_bytes,
    )
    .await?;
    if loaded.validated.manifest_sha256 != head.manifest_sha256
        || head
            .recovery_sha256
            .as_ref()
            .is_some_and(|digest| digest != &loaded.recovery_sha256)
    {
        return Response::error("repair recovery identity changed", 503);
    }

    let recovery = serde_json::from_slice::<serde_json::Value>(&loaded.encoded)?;
    let locations = load_indexed_locations(&database, operation_id).await?;
    let target_location_ids = load_target_ids(&database, operation_id).await?;
    if u64::try_from(target_location_ids.len()).ok() != Some(head.expected_target_count) {
        return Response::error("repair target plan is incomplete", 409);
    }
    let rechecked = load_snapshot_head(&database, operation_id, client, &requested).await?;
    if rechecked.as_ref() != Some(&head) {
        return Response::error("repair snapshot changed while it was read", 409);
    }

    Response::from_json(&RepairSnapshot {
        recovery,
        recovery_revision: head.recovery_revision,
        target_driver_id: head.target_driver_id,
        target_location_ids,
        locations,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "repair replay, live-fence validation, and one atomic metadata commit remain visible"
)]
pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid repair operation ID", 400);
    }

    let mut completed = request.json::<CompleteRequest>().await?;
    if !valid_completion(&completed) {
        return Response::error("invalid repair completion", 400);
    }
    completed.objects.sort_by(|left, right| {
        left.driver_id
            .cmp(&right.driver_id)
            .then_with(|| left.storage_key.cmp(&right.storage_key))
    });
    let canonical = serde_json::to_vec(&(
        completed.manifest_sha256.as_str(),
        completed.objects.as_slice(),
    ))?;
    let report_sha256 = lowercase_hex(&Sha256::digest(canonical));
    let database = env.d1("CARRACK_INDEX")?;

    if let Some(existing) = find_completion(
        &database,
        operation_id,
        &client.id,
        &completed.manifest_sha256,
    )
    .await?
    {
        if existing.report_sha256 != report_sha256
            || existing.lease_id != completed.lease_id
            || existing.incarnation != completed.incarnation
            || existing.fencing_token != completed.fencing_token
        {
            return Response::error("repair completion replay changed fence or evidence", 409);
        }

        return completion_response(operation_id, &completed.manifest_sha256, &existing);
    }

    let snapshot_request = SnapshotRequest {
        lease_id: completed.lease_id.clone(),
        incarnation: completed.incarnation.clone(),
        fencing_token: completed.fencing_token,
    };
    let head = load_snapshot_head(&database, operation_id, client, &snapshot_request).await?;
    let Some(head) = head else {
        return Response::error("repair completion fence is stale or unavailable", 409);
    };
    if head.manifest_sha256 != completed.manifest_sha256 {
        return Response::error("repair completion changed the manifest identity", 409);
    }

    let planned = load_repair_objects(&database, operation_id).await?;
    let repaired_bytes = match validate_completed_objects(&completed.objects, &planned, &head) {
        Ok(bytes) => bytes,
        Err(error) => return Response::error(error, 409),
    };
    let object_count = u64::try_from(completed.objects.len())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let now = copying::current_unix_seconds().to_string();
    let statements = completion_statements(
        &database,
        operation_id,
        client,
        &completed,
        &report_sha256,
        object_count,
        head.expected_target_count,
        repaired_bytes,
        &now,
    )?;
    database.batch(statements).await?;

    let committed = find_completion(
        &database,
        operation_id,
        &client.id,
        &completed.manifest_sha256,
    )
    .await?;
    let Some(committed) = committed else {
        return Response::error("repair completion fence is stale or incomplete", 409);
    };
    if committed.report_sha256 != report_sha256 {
        return Response::error("repair completion report identity changed", 409);
    }

    completion_response(operation_id, &completed.manifest_sha256, &committed)
}

fn valid_completion(completed: &CompleteRequest) -> bool {
    copying::valid_string(&completed.lease_id, 256)
        && copying::valid_hex(&completed.incarnation, 32)
        && completed.fencing_token > 0
        && copying::valid_hex(&completed.manifest_sha256, 64)
        && !completed.objects.is_empty()
        && completed.objects.len() <= MAXIMUM_REPAIR_TARGETS
        && completed.objects.iter().all(valid_completed_object)
}

fn valid_completed_object(object: &CompletedObject) -> bool {
    copying::valid_string(&object.driver_id, 256)
        && copying::valid_string(&object.storage_key, 4_096)
        && object.size_bytes > 0
        && object.size_bytes <= i64::MAX.unsigned_abs()
        && object
            .provider_version
            .as_ref()
            .is_none_or(|value| copying::valid_string(value, 1_024))
        && object
            .etag
            .as_ref()
            .is_none_or(|value| copying::valid_string(value, 4_096))
}

fn validate_completed_objects(
    completed: &[CompletedObject],
    planned: &[RepairObjectRow],
    head: &SnapshotHead,
) -> std::result::Result<u64, String> {
    if u64::try_from(planned.len()).ok() != Some(head.expected_object_count)
        || planned.len() != completed.len()
    {
        return Err("repair completion does not cover every pinned object".to_owned());
    }

    let mut by_key = planned
        .iter()
        .map(|object| (object.storage_key.as_str(), object))
        .collect::<HashMap<_, _>>();
    let mut repaired_bytes = 0_u64;
    for object in completed {
        let Some(expected) = by_key.remove(object.storage_key.as_str()) else {
            return Err("repair completion identifies an unpinned object".to_owned());
        };
        if object.driver_id != head.target_driver_id
            || object.size_bytes != expected.expected_bytes
            || expected
                .provider_version
                .as_ref()
                .is_some_and(|version| object.provider_version.as_ref() != Some(version))
        {
            return Err("repair completion changed a provider object identity".to_owned());
        }
        repaired_bytes = repaired_bytes
            .checked_add(object.size_bytes)
            .ok_or_else(|| "repair completion byte count overflows".to_owned())?;
    }
    if !by_key.is_empty() || repaired_bytes != head.useful_bytes_total {
        return Err("repair completion omitted pinned provider bytes".to_owned());
    }

    Ok(repaired_bytes)
}

async fn load_repair_objects(
    database: &D1Database,
    operation_id: &str,
) -> Result<Vec<RepairObjectRow>> {
    database
        .prepare(
            "SELECT storage_key, provider_version, expected_bytes \
             FROM repair_objects WHERE operation_id = ?1 AND state = 'planned' \
             ORDER BY storage_key",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .all()
        .await?
        .results::<RepairObjectRow>()
}

async fn find_completion(
    database: &D1Database,
    operation_id: &str,
    client_id: &str,
    manifest_sha256: &str,
) -> Result<Option<CompletionRow>> {
    database
        .prepare(
            "SELECT completion.report_sha256, completion.object_count, \
                    completion.location_count, completion.ciphertext_bytes, \
                    intent.recovery_revision, completion.lease_id, \
                    completion.incarnation, completion.fencing_token \
             FROM repair_completions AS completion \
             JOIN repair_intents AS intent ON intent.operation_id = completion.operation_id \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             WHERE operation.id = ?1 AND operation.kind = 'copy' \
               AND operation.state = 'succeeded' AND operation.requested_by = ?2 \
               AND intent.manifest_sha256 = ?3 AND completion.state = 'committed' \
               AND lease.id = completion.lease_id \
               AND lease.incarnation = completion.incarnation \
               AND lease.fencing_token = completion.fencing_token \
               AND lease.released_at IS NOT NULL",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(client_id),
            JsValue::from_str(manifest_sha256),
        ])?
        .first::<CompletionRow>(None)
        .await
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the short fenced repair commit is intentionally auditable as one statement set"
)]
fn completion_statements(
    database: &D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    completed: &CompleteRequest,
    report_sha256: &str,
    object_count: u64,
    location_count: u64,
    ciphertext_bytes: u64,
    now: &str,
) -> Result<Vec<D1PreparedStatement>> {
    let encoded_objects = serde_json::to_string(&completed.objects).map_err(|error| {
        worker::Error::RustError(format!("encode repaired provider objects: {error}"))
    })?;
    let insert_completion = database
        .prepare(
            "INSERT INTO repair_completions (\
                 operation_id, report_sha256, object_count, location_count, ciphertext_bytes, \
                 lease_id, incarnation, fencing_token, completed_at\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(report_sha256),
            copying::integer(object_count)?,
            copying::integer(location_count)?,
            copying::integer(ciphertext_bytes)?,
            JsValue::from_str(&completed.lease_id),
            JsValue::from_str(&completed.incarnation),
            copying::integer(completed.fencing_token)?,
            JsValue::from_str(now),
        ])?;
    let insert_objects = database
        .prepare(
            "INSERT INTO repair_completion_objects (\
                 operation_id, driver_id, storage_key, provider_version, etag, size_bytes\
             ) \
             SELECT ?1, json_extract(object.value, '$.driver_id'), \
                    json_extract(object.value, '$.storage_key'), \
                    json_extract(object.value, '$.provider_version'), \
                    json_extract(object.value, '$.etag'), \
                    json_extract(object.value, '$.size_bytes') \
             FROM json_each(?2) AS object",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&encoded_objects),
        ])?;
    let start_verification = database
        .prepare(
            "UPDATE operations SET state = 'verifying', phase = 'verifying', \
                 revision = revision + 1, updated_at = ?1 \
             WHERE id = ?2 AND kind = 'copy' AND state = 'running' \
               AND EXISTS(SELECT 1 FROM repair_completions \
                          WHERE operation_id = ?2 AND report_sha256 = ?3 \
                            AND state = 'staging')",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            JsValue::from_str(report_sha256),
        ])?;
    let verify_locations = database
        .prepare(
            "UPDATE locations SET state = 'verified', revision = revision + 1, \
                 verified_at = ?1, updated_at = ?1 \
             WHERE state = 'missing' \
               AND EXISTS(SELECT 1 FROM repair_targets AS target \
                          JOIN repair_completions AS completion \
                            ON completion.operation_id = target.operation_id \
                          WHERE target.operation_id = ?2 AND target.location_id = locations.id \
                            AND target.location_revision = locations.revision \
                            AND target.state = 'planned' \
                            AND completion.report_sha256 = ?3 \
                            AND completion.state = 'staging')",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            JsValue::from_str(report_sha256),
        ])?;
    let publish_locations = database
        .prepare(
            "UPDATE locations SET state = 'available', revision = revision + 1, updated_at = ?1 \
             WHERE state = 'verified' \
               AND EXISTS(SELECT 1 FROM repair_targets AS target \
                          JOIN repair_completions AS completion \
                            ON completion.operation_id = target.operation_id \
                          WHERE target.operation_id = ?2 AND target.location_id = locations.id \
                            AND locations.revision = target.location_revision + 1 \
                            AND target.state = 'planned' \
                            AND completion.report_sha256 = ?3 \
                            AND completion.state = 'staging')",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            JsValue::from_str(report_sha256),
        ])?;
    let complete_objects = database
        .prepare(
            "UPDATE repair_objects AS object \
             SET state = 'repaired', \
                 observed_provider_version = (\
                     SELECT completed.provider_version FROM repair_completion_objects AS completed \
                     WHERE completed.operation_id = object.operation_id \
                       AND completed.storage_key = object.storage_key), \
                 observed_etag = (\
                     SELECT completed.etag FROM repair_completion_objects AS completed \
                     WHERE completed.operation_id = object.operation_id \
                       AND completed.storage_key = object.storage_key), \
                 repaired_at = ?1 \
             WHERE object.operation_id = ?2 AND object.state = 'planned' \
               AND EXISTS(SELECT 1 FROM repair_completion_objects AS completed \
                          WHERE completed.operation_id = object.operation_id \
                            AND completed.storage_key = object.storage_key)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(operation_id)])?;
    let complete_targets = database
        .prepare(
            "UPDATE repair_targets AS target SET state = 'repaired', repaired_at = ?1 \
             WHERE target.operation_id = ?2 AND target.state = 'planned' \
               AND EXISTS(SELECT 1 FROM repair_objects AS object \
                          WHERE object.operation_id = target.operation_id \
                            AND object.storage_key = target.storage_key \
                            AND object.state = 'repaired') \
               AND EXISTS(SELECT 1 FROM locations AS location \
                          WHERE location.id = target.location_id \
                            AND location.state = 'available' \
                            AND location.revision = target.location_revision + 2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(operation_id)])?;
    let resolve_missing = database
        .prepare(
            "UPDATE integrity_findings \
             SET state = 'resolved', resolved_at = ?1, last_observed_at = ?1, \
                 revision = revision + 1 \
             WHERE subject_kind = 'location' AND condition = 'missing' AND state = 'open' \
               AND EXISTS(SELECT 1 FROM repair_targets AS target \
                          WHERE target.operation_id = ?2 \
                            AND target.location_id = integrity_findings.subject_id \
                            AND target.state = 'repaired')",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(operation_id)])?;
    let resolve_degraded = database
        .prepare(
            "UPDATE integrity_findings \
             SET state = 'resolved', resolved_at = ?1, last_observed_at = ?1, \
                 revision = revision + 1 \
             WHERE subject_kind = 'extent' AND condition = 'degraded' AND state = 'open' \
               AND EXISTS(\
                   SELECT 1 FROM repair_targets AS target \
                   JOIN repair_intents AS intent ON intent.operation_id = target.operation_id \
                   JOIN operations AS operation ON operation.id = intent.operation_id \
                   JOIN namespaces AS namespace ON namespace.id = operation.namespace_id \
                   JOIN locations AS repaired ON repaired.id = target.location_id \
                   JOIN extents AS repaired_extent ON repaired_extent.id = repaired.extent_id \
                   WHERE target.operation_id = ?2 AND target.state = 'repaired' \
                     AND repaired_extent.ciphertext_sha256 = integrity_findings.subject_id \
                     AND (SELECT COUNT(*) FROM version_packs AS version_pack \
                          JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
                          JOIN locations AS location ON location.extent_id = extent.id \
                          WHERE version_pack.version_id = intent.version_id \
                            AND extent.ciphertext_sha256 = integrity_findings.subject_id \
                            AND location.state = 'available') >= \
                         COALESCE(json_extract(namespace.replica_policy_json, \
                                              '$.minimum_available_replicas'), 1))",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(operation_id)])?;
    let commit_operation = database
        .prepare(
            "UPDATE operations SET state = 'committing', phase = 'committing', \
                 revision = revision + 1, updated_at = ?1 \
             WHERE id = ?2 AND kind = 'copy' AND state = 'verifying' \
               AND EXISTS(SELECT 1 FROM repair_completions \
                          WHERE operation_id = ?2 AND report_sha256 = ?3 \
                            AND state = 'staging')",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            JsValue::from_str(report_sha256),
        ])?;
    let finish_operation = database
        .prepare(
            "UPDATE operations SET state = 'succeeded', phase = 'completed', \
                 useful_bytes_verified = useful_bytes_total, revision = revision + 1, \
                 finished_at = ?1, updated_at = ?1 \
             WHERE id = ?2 AND kind = 'copy' AND state = 'committing' \
               AND EXISTS(SELECT 1 FROM repair_completions \
                          WHERE operation_id = ?2 AND report_sha256 = ?3 \
                            AND state = 'staging')",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            JsValue::from_str(report_sha256),
        ])?;
    let finish_attempt = database
        .prepare(
            "UPDATE operation_attempts SET state = 'succeeded', finished_at = ?1 \
             WHERE component_id = ?2 || '/repair' AND attempt = ?3 AND state = 'running' \
               AND lease_id = ?4 AND incarnation = ?5",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            copying::integer(completed.fencing_token)?,
            JsValue::from_str(&completed.lease_id),
            JsValue::from_str(&completed.incarnation),
        ])?;
    let finish_component = database
        .prepare(
            "UPDATE operation_components \
             SET state = 'succeeded', useful_bytes_verified = useful_bytes_total, \
                 finished_at = ?1, revision = revision + 1, updated_at = ?1 \
             WHERE id = ?2 || '/repair' AND operation_id = ?2 \
               AND lease_id = ?3 AND fencing_token = ?4 AND state = 'running' \
               AND EXISTS(SELECT 1 FROM operations \
                          WHERE id = ?2 AND state = 'succeeded')",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            JsValue::from_str(&completed.lease_id),
            copying::integer(completed.fencing_token)?,
        ])?;
    let release_lease = database
        .prepare(
            "UPDATE leases SET released_at = ?1, updated_at = ?1 \
             WHERE id = ?2 AND operation_id = ?3 AND owner_client_id = ?4 \
               AND incarnation = ?5 AND fencing_token = ?6 AND lease_kind = 'write' \
               AND released_at IS NULL AND expires_at > ?1 \
               AND EXISTS(SELECT 1 FROM operations \
                          WHERE id = ?3 AND state = 'succeeded')",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(&completed.lease_id),
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&completed.incarnation),
            copying::integer(completed.fencing_token)?,
        ])?;
    let commit_completion = database
        .prepare(
            "UPDATE repair_completions SET state = 'committed', committed_at = ?1 \
             WHERE operation_id = ?2 AND report_sha256 = ?3 AND state = 'staging'",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            JsValue::from_str(report_sha256),
        ])?;

    Ok(vec![
        insert_completion,
        insert_objects,
        start_verification,
        verify_locations,
        publish_locations,
        complete_objects,
        complete_targets,
        resolve_missing,
        resolve_degraded,
        commit_operation,
        finish_operation,
        finish_attempt,
        finish_component,
        release_lease,
        commit_completion,
    ])
}

fn completion_response(
    operation_id: &str,
    manifest_sha256: &str,
    completion: &CompletionRow,
) -> Result<Response> {
    Response::from_json(&CompletedRepair {
        operation_id: operation_id.to_owned(),
        manifest_sha256: manifest_sha256.to_owned(),
        state: "succeeded",
        objects_repaired: completion.object_count,
        locations_repaired: completion.location_count,
        ciphertext_bytes: completion.ciphertext_bytes,
        recovery_revision: completion.recovery_revision,
    })
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    encoded
}

async fn load_recovery_row(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &CreateRequest,
) -> Result<Option<RecoveryRow>> {
    database
        .prepare(
            "SELECT recovery.version_id, object.id AS object_id, version.generation, \
                    recovery.manifest_sha256, recovery.recovery_sha256, recovery.revision, \
                    recovery.r2_storage_key, recovery.r2_version, recovery.ciphertext_bytes \
             FROM recovery_manifests AS recovery \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN driver_instances AS target ON target.id = ?3 \
             WHERE recovery.manifest_sha256 = ?1 AND object.namespace_id = ?2 \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND version.state = 'published' AND target.enabled = 1 \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?4 AND namespace_id = ?2 \
                            AND role IN ('relay', 'administrator'))",
        )
        .bind(&[
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.target_driver_id),
            JsValue::from_str(&client.id),
        ])?
        .first::<RecoveryRow>(None)
        .await
}

async fn load_missing_targets(
    database: &D1Database,
    version_id: &str,
    target_driver_id: &str,
) -> Result<Vec<RepairTargetRow>> {
    database
        .prepare(
            "SELECT location.id, location.revision AS location_revision, \
                    extent.ciphertext_sha256 AS extent_sha256, location.driver_id, \
                    location.storage_key, location.provider_version, \
                    location.storage_offset AS offset, location.storage_length AS length \
             FROM version_packs AS version_pack \
             JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
             JOIN locations AS location ON location.extent_id = extent.id \
             WHERE version_pack.version_id = ?1 AND location.driver_id = ?2 \
               AND location.state = 'missing' \
             ORDER BY location.id",
        )
        .bind(&[
            JsValue::from_str(version_id),
            JsValue::from_str(target_driver_id),
        ])?
        .all()
        .await?
        .results::<RepairTargetRow>()
}

fn recovery_matches(
    loaded: &copying::LoadedRecovery,
    recovery: &RecoveryRow,
    requested: &CreateRequest,
) -> bool {
    loaded.validated.manifest_sha256 == recovery.manifest_sha256
        && loaded.validated.manifest_sha256 == requested.manifest_sha256
        && loaded.validated.namespace_id == requested.namespace_id
        && loaded.validated.object_id == recovery.object_id
        && loaded.validated.generation == recovery.generation
        && recovery
            .recovery_sha256
            .as_ref()
            .is_none_or(|expected| expected == &loaded.recovery_sha256)
}

fn validate_targets(
    recovery: &manifests::ValidatedRecovery,
    targets: &[RepairTargetRow],
) -> std::result::Result<RepairPlanShape, String> {
    let recovery_locations = recovery
        .recovery
        .locations
        .iter()
        .map(|location| (LocationIdentity::from(location), location))
        .collect::<HashMap<_, _>>();
    let mut target_objects = HashSet::new();

    for target in targets {
        let Some(location) = recovery_locations.get(&LocationIdentity::from(target)) else {
            return Err("repair target is absent from pinned recovery".to_owned());
        };
        if target.id != manifests::location_id(location) {
            return Err("repair target has an inconsistent location identity".to_owned());
        }
        target_objects.insert((target.driver_id.as_str(), target.storage_key.as_str()));
    }

    let mut ranges = HashMap::<(&str, &str), Vec<(u64, u64, Option<&str>)>>::new();
    for location in &recovery.recovery.locations {
        let object = (location.driver_id.as_str(), location.storage_key.as_str());
        if target_objects.contains(&object) {
            ranges.entry(object).or_default().push((
                location.offset,
                location.length,
                location.provider_version.as_deref(),
            ));
        }
    }

    let mut useful_bytes = 0_u64;
    let mut objects = Vec::with_capacity(ranges.len());
    for ((_, storage_key), object_ranges) in &mut ranges {
        object_ranges.sort_unstable();
        let mut expected_offset = 0_u64;
        let provider_version = object_ranges.first().and_then(|range| range.2);
        for (offset, length, version) in object_ranges {
            if *offset != expected_offset {
                return Err(format!(
                    "repair target object {storage_key:?} is not gapless"
                ));
            }
            if *version != provider_version {
                return Err(format!(
                    "repair target object {storage_key:?} has inconsistent provider versions"
                ));
            }
            expected_offset = expected_offset
                .checked_add(*length)
                .ok_or_else(|| "repair target object length overflows".to_owned())?;
        }
        useful_bytes = useful_bytes
            .checked_add(expected_offset)
            .ok_or_else(|| "repair operation byte count overflows".to_owned())?;
        objects.push(RepairObjectCandidate {
            storage_key: (*storage_key).to_owned(),
            provider_version: provider_version.map(str::to_owned),
            expected_bytes: expected_offset,
        });
    }
    objects.sort_by(|left, right| left.storage_key.cmp(&right.storage_key));

    Ok(RepairPlanShape {
        objects,
        useful_bytes,
    })
}

async fn load_snapshot_head(
    database: &D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &SnapshotRequest,
) -> Result<Option<SnapshotHead>> {
    database
        .prepare(
            "SELECT intent.manifest_sha256, recovery.recovery_sha256, \
                    intent.recovery_revision, recovery.r2_storage_key, recovery.r2_version, \
                    recovery.ciphertext_bytes AS recovery_bytes, intent.target_driver_id, \
                    operation.useful_bytes_total, intent.expected_object_count, \
                    intent.expected_target_count \
             FROM repair_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN recovery_manifests AS recovery ON recovery.version_id = intent.version_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'copy' \
               AND operation.state = 'running' AND operation.phase = 'repairing' \
               AND operation.requested_by = ?2 \
               AND recovery.manifest_sha256 = intent.manifest_sha256 \
               AND recovery.revision = intent.recovery_revision \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND lease.id = ?3 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.lease_kind = 'write' AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND lease.incarnation = control.incarnation \
               AND control.mode = 'active' \
               AND (SELECT COUNT(*) FROM repair_targets AS target \
                    WHERE target.operation_id = intent.operation_id \
                      AND target.state = 'planned') = intent.expected_target_count \
               AND (SELECT COUNT(*) FROM repair_objects AS object \
                    WHERE object.operation_id = intent.operation_id \
                      AND object.state = 'planned') = intent.expected_object_count \
               AND NOT EXISTS(\
                   SELECT 1 FROM repair_targets AS target \
                   LEFT JOIN locations AS location ON location.id = target.location_id \
                   WHERE target.operation_id = intent.operation_id \
                     AND (location.id IS NULL OR location.state != 'missing' \
                          OR location.revision != target.location_revision \
                          OR location.storage_key != target.storage_key \
                          OR location.provider_version IS NOT target.provider_version \
                          OR location.storage_offset != target.storage_offset \
                          OR location.storage_length != target.storage_length))",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            copying::integer(requested.fencing_token)?,
        ])?
        .first::<SnapshotHead>(None)
        .await
}

async fn load_indexed_locations(
    database: &D1Database,
    operation_id: &str,
) -> Result<Vec<IndexedLocation>> {
    database
        .prepare(
            "SELECT location.id, extent.ciphertext_sha256 AS extent_sha256, \
                    location.driver_id, location.storage_key, location.provider_version, \
                    location.storage_offset AS offset, location.storage_length AS length, \
                    location.state \
             FROM repair_intents AS intent \
             JOIN version_packs AS version_pack ON version_pack.version_id = intent.version_id \
             JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
             JOIN locations AS location ON location.extent_id = extent.id \
             WHERE intent.operation_id = ?1 ORDER BY location.id",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .all()
        .await?
        .results::<IndexedLocation>()
}

async fn load_target_ids(database: &D1Database, operation_id: &str) -> Result<Vec<String>> {
    let rows = database
        .prepare(
            "SELECT location_id FROM repair_targets \
             WHERE operation_id = ?1 AND state = 'planned' ORDER BY location_id",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .all()
        .await?
        .results::<TargetIDRow>()?;

    Ok(rows.into_iter().map(|row| row.location_id).collect())
}

async fn find_operation(
    database: &D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<RepairOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, intent.version_id, \
                    object.id AS object_id, version.generation, intent.manifest_sha256, \
                    intent.recovery_revision, intent.target_driver_id, \
                    intent.expected_object_count, intent.expected_target_count, \
                    operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN repair_intents AS intent ON intent.operation_id = operation.id \
             JOIN object_versions AS version ON version.id = intent.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'copy'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<RepairOperation>(None)
        .await
}

fn operation_response(operation: &RepairOperation, requested: &CreateRequest) -> Result<Response> {
    if operation.manifest_sha256 != requested.manifest_sha256
        || operation.target_driver_id != requested.target_driver_id
    {
        return Response::error("idempotency key pins another repair", 409);
    }

    Response::from_json(operation)
}
