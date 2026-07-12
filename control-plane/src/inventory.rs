use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{D1Database, Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, copying};

const DEFAULT_QUARANTINE_GRACE_SECONDS: u64 = 86_400;
const MINIMUM_QUARANTINE_GRACE_SECONDS: u64 = 60;
const MAXIMUM_QUARANTINE_GRACE_SECONDS: u64 = 31_536_000;
const MAXIMUM_PAGE_OBJECTS: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    driver_id: String,
    prefix: String,
    idempotency_key: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RetentionPolicy {
    #[serde(default, rename = "move_grace_seconds")]
    _move_grace: Option<u64>,
    #[serde(default, rename = "gc_minimum_age_seconds")]
    _gc_minimum_age: Option<u64>,
    #[serde(default, rename = "gc_grace_seconds")]
    _gc_grace: Option<u64>,
    inventory_quarantine_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct ScopeRow {
    retention_policy_json: String,
    driver_revision: u64,
}

#[derive(Deserialize, Serialize)]
struct InventoryOperation {
    id: String,
    namespace_id: String,
    kind: String,
    state: String,
    phase: String,
    requested_by: String,
    incarnation: String,
    revision: u64,
    driver_id: String,
    driver_revision: u64,
    prefix: String,
    quarantine_grace_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_report_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_pages: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_objects: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_known: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_quarantined: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_missing: Option<u64>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fence {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InventoryObject {
    storage_key: String,
    size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    sequence: u64,
    cursor: String,
    next_cursor: String,
    objects: Vec<InventoryObject>,
}

#[derive(Deserialize)]
struct LiveInventory {
    prefix: String,
}

#[derive(Deserialize)]
struct StoredPage {
    sequence: u64,
    cursor: String,
    next_cursor: String,
    report_sha256: String,
    object_count: u64,
    stored_object_count: u64,
}

#[derive(Serialize)]
struct PageResponse {
    operation_id: String,
    sequence: u64,
    report_sha256: String,
    object_count: u64,
    next_cursor: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    last_sequence: u64,
    report_sha256: String,
}

#[derive(Clone, Copy)]
struct ClassificationCounts {
    pages: u64,
    objects: u64,
    known: u64,
    quarantined: u64,
    missing: u64,
}

#[derive(Deserialize)]
struct CountRow {
    value: u64,
}

#[derive(Deserialize)]
struct CompletionRow {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    report_sha256: String,
    page_count: u64,
    object_count: u64,
    known_count: u64,
    quarantined_count: u64,
    missing_count: u64,
}

#[derive(Serialize)]
struct CompletedInventory {
    operation_id: String,
    state: &'static str,
    report_sha256: String,
    pages: u64,
    objects: u64,
    known: u64,
    quarantined: u64,
    missing: u64,
}

#[allow(
    clippy::too_many_lines,
    reason = "operation, pinned inventory scope, and component form one idempotent creation"
)]
pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !copying::valid_hex(&requested.namespace_id, 32)
        || !copying::valid_string(&requested.driver_id, 256)
        || !valid_prefix(&requested.prefix)
        || !copying::valid_string(&requested.idempotency_key, 256)
    {
        return Response::error("invalid inventory reconciliation", 400);
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

    let scope = database
        .prepare(
            "SELECT namespace.retention_policy_json, driver.revision AS driver_revision \
             FROM namespaces AS namespace \
             JOIN driver_instances AS driver ON driver.id = ?1 AND driver.enabled = 1 \
             WHERE namespace.id = ?2 \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?3 AND namespace_id = namespace.id \
                            AND role = 'administrator')",
        )
        .bind(&[
            JsValue::from_str(&requested.driver_id),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&client.id),
        ])?
        .first::<ScopeRow>(None)
        .await?;
    let Some(scope) = scope else {
        return Response::error("inventory scope is unavailable or unauthorized", 409);
    };
    let grace_seconds = parse_quarantine_grace(&scope.retention_policy_json)?;
    let operation_id = random_hex()?;
    let now = current_unix_seconds().to_string();
    let insert_operation = database
        .prepare(
            "INSERT INTO operations (\
                 id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                 incarnation, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT ?1, namespace.id, 'reconcile', 'planned', 'planned', ?2, ?3, \
                    control.incarnation, 0, ?4, ?4 \
             FROM namespaces AS namespace \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             JOIN driver_instances AS driver ON driver.id = ?5 \
             WHERE namespace.id = ?6 AND control.mode = 'active' AND driver.enabled = 1 \
               AND driver.revision = ?7 \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?3 AND namespace_id = namespace.id \
                            AND role = 'administrator') \
             ON CONFLICT(namespace_id, idempotency_key) DO NOTHING",
        )
        .bind(&[
            JsValue::from_str(&operation_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            JsValue::from_str(&now),
            JsValue::from_str(&requested.driver_id),
            JsValue::from_str(&requested.namespace_id),
            copying::integer(scope.driver_revision)?,
        ])?;
    let insert_intent = database
        .prepare(
            "INSERT OR IGNORE INTO inventory_intents (\
                 operation_id, driver_id, driver_revision, prefix, \
                 quarantine_grace_seconds, created_at\
             ) \
             SELECT operation.id, driver.id, driver.revision, ?1, ?2, ?3 \
             FROM operations AS operation \
             JOIN driver_instances AS driver ON driver.id = ?4 \
             WHERE operation.namespace_id = ?5 AND operation.idempotency_key = ?6 \
               AND operation.requested_by = ?7 AND operation.kind = 'reconcile' \
               AND driver.enabled = 1 AND driver.revision = ?8",
        )
        .bind(&[
            JsValue::from_str(&requested.prefix),
            copying::integer(grace_seconds)?,
            JsValue::from_str(&now),
            JsValue::from_str(&requested.driver_id),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            copying::integer(scope.driver_revision)?,
        ])?;
    let insert_component = database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, source_driver_id, state, \
                 useful_bytes_total, created_at, updated_at\
             ) \
             SELECT operation.id || '/inventory', operation.id, ?1, 'inventory', \
                    intent.driver_id, 'pending', 0, ?2, ?2 \
             FROM operations AS operation \
             JOIN inventory_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?1 AND operation.kind = 'reconcile'",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(&now),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
        ])?;
    database
        .batch(vec![insert_operation, insert_intent, insert_component])
        .await?;

    let operation = find_operation(
        &database,
        &requested.namespace_id,
        &requested.idempotency_key,
        &client.id,
    )
    .await?;
    let Some(operation) = operation else {
        return Response::error("inventory reconciliation identity conflicts", 409);
    };
    operation_response(&operation, &requested)
}

#[allow(
    clippy::too_many_lines,
    reason = "page validation and its atomic D1 append remain adjacent for replay safety"
)]
pub(crate) async fn report_page(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid inventory operation ID", 400);
    }
    let requested = request.json::<PageRequest>().await?;
    if !valid_fence(&Fence {
        lease_id: requested.lease_id.clone(),
        incarnation: requested.incarnation.clone(),
        fencing_token: requested.fencing_token,
    }) || requested.sequence == 0
        || !valid_cursor(&requested.cursor)
        || !valid_cursor(&requested.next_cursor)
        || (requested.sequence == 1) != requested.cursor.is_empty()
        || requested.objects.len() > MAXIMUM_PAGE_OBJECTS
        || (!requested.next_cursor.is_empty() && requested.objects.is_empty())
        || !valid_inventory_objects(&requested.objects)
        || !valid_inventory_page_order(
            &requested.cursor,
            &requested.next_cursor,
            &requested.objects,
        )
    {
        return Response::error("invalid inventory report page", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let fence = Fence {
        lease_id: requested.lease_id.clone(),
        incarnation: requested.incarnation.clone(),
        fencing_token: requested.fencing_token,
    };
    let live = load_live_inventory(&database, operation_id, client, &fence).await?;
    let Some(live) = live else {
        return Response::error("inventory report fence is stale or unavailable", 409);
    };
    if requested
        .objects
        .iter()
        .any(|object| !within_prefix(&live.prefix, &object.storage_key))
    {
        return Response::error("inventory report object is outside the pinned prefix", 400);
    }
    if requested.sequence > 1 {
        let previous = load_page(
            &database,
            operation_id,
            requested.fencing_token,
            requested.sequence - 1,
        )
        .await?;
        if previous
            .as_ref()
            .is_none_or(|page| page.next_cursor.is_empty() || page.next_cursor != requested.cursor)
        {
            return Response::error("inventory report cursor chain is incomplete", 409);
        }
    }

    let report_sha256 = page_sha256(&requested)?;
    let now = current_unix_seconds().to_string();
    let mut statements = Vec::with_capacity(requested.objects.len() + 1);
    statements.push(
        database
            .prepare(
                "INSERT OR IGNORE INTO inventory_report_pages (\
                     operation_id, fencing_token, sequence, cursor, next_cursor, \
                     report_sha256, object_count, observed_at\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                copying::integer(requested.fencing_token)?,
                copying::integer(requested.sequence)?,
                JsValue::from_str(&requested.cursor),
                JsValue::from_str(&requested.next_cursor),
                JsValue::from_str(&report_sha256),
                copying::integer(requested.objects.len() as u64)?,
                JsValue::from_str(&now),
            ])?,
    );
    for object in &requested.objects {
        statements.push(
            database
                .prepare(
                    "INSERT OR IGNORE INTO inventory_report_objects (\
                         operation_id, fencing_token, page_sequence, storage_key, \
                         provider_version, etag, size_bytes, observed_at\
                     ) \
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 \
                     WHERE EXISTS(SELECT 1 FROM inventory_report_pages \
                                  WHERE operation_id = ?1 AND fencing_token = ?2 \
                                    AND sequence = ?3 AND report_sha256 = ?9)",
                )
                .bind(&[
                    JsValue::from_str(operation_id),
                    copying::integer(requested.fencing_token)?,
                    copying::integer(requested.sequence)?,
                    JsValue::from_str(&object.storage_key),
                    optional_string(object.provider_version.as_deref()),
                    optional_string(object.etag.as_deref()),
                    copying::integer(object.size_bytes)?,
                    JsValue::from_str(&now),
                    JsValue::from_str(&report_sha256),
                ])?,
        );
    }
    database.batch(statements).await?;

    let stored = load_page(
        &database,
        operation_id,
        requested.fencing_token,
        requested.sequence,
    )
    .await?;
    let Some(stored) = stored else {
        return Response::error("inventory report page was not committed", 409);
    };
    if stored.report_sha256 != report_sha256
        || stored.cursor != requested.cursor
        || stored.next_cursor != requested.next_cursor
        || stored.object_count != requested.objects.len() as u64
        || stored.stored_object_count != stored.object_count
    {
        return Response::error("inventory report page replay changed", 409);
    }

    Response::from_json(&PageResponse {
        operation_id: operation_id.to_owned(),
        sequence: stored.sequence,
        report_sha256,
        object_count: stored.object_count,
        next_cursor: stored.next_cursor,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "full-report validation, classification, and fenced closure are one commit protocol"
)]
pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid inventory operation ID", 400);
    }
    let requested = request.json::<CompleteRequest>().await?;
    let fence = Fence {
        lease_id: requested.lease_id.clone(),
        incarnation: requested.incarnation.clone(),
        fencing_token: requested.fencing_token,
    };
    if !valid_fence(&fence)
        || requested.last_sequence == 0
        || !copying::valid_hex(&requested.report_sha256, 64)
    {
        return Response::error("invalid inventory completion", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    if load_live_inventory(&database, operation_id, client, &fence)
        .await?
        .is_none()
    {
        if let Some(response) =
            replay_completion(&database, operation_id, client, &requested).await?
        {
            return Ok(response);
        }

        return Response::error("inventory completion fence is stale or unavailable", 409);
    }

    let pages = load_pages(&database, operation_id, requested.fencing_token).await?;
    let Some(report_sha256) = validate_complete_pages(&pages, requested.last_sequence) else {
        return Response::error("inventory report page chain is incomplete", 409);
    };
    if report_sha256 != requested.report_sha256 {
        return Response::error("inventory completion report identity changed", 409);
    }
    let counts = classification_counts(
        &database,
        operation_id,
        requested.fencing_token,
        pages.len() as u64,
    )
    .await?;
    let conflicting_scopes =
        count_scope_conflicts(&database, operation_id, requested.fencing_token).await?;
    if conflicting_scopes > 0 {
        return Response::error(
            "inventory objects overlap another namespace quarantine",
            409,
        );
    }

    let now = current_unix_seconds().to_string();
    let mut statements = classification_statements(&database, operation_id, &requested, &now)?;
    append_completion_statements(
        &database,
        &mut statements,
        operation_id,
        client,
        &requested,
        counts,
        &now,
    )?;
    database.batch(statements).await?;

    let completion = load_committed_completion(&database, operation_id, &client.id).await?;
    let Some(completion) = completion else {
        return Response::error("inventory completion was not committed", 409);
    };
    if completion.report_sha256 != requested.report_sha256 {
        return Response::error("inventory completion report changed", 409);
    }

    completion_response(operation_id, completion)
}

async fn find_operation(
    database: &D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<InventoryOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, intent.driver_id, intent.driver_revision, \
                    intent.prefix, intent.quarantine_grace_seconds, \
                    completion.report_sha256 AS completed_report_sha256, \
                    completion.page_count AS completed_pages, \
                    completion.object_count AS completed_objects, \
                    completion.known_count AS completed_known, \
                    completion.quarantined_count AS completed_quarantined, \
                    completion.missing_count AS completed_missing, \
                    operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN inventory_intents AS intent ON intent.operation_id = operation.id \
             LEFT JOIN inventory_completions AS completion \
               ON completion.operation_id = operation.id AND completion.state = 'committed' \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'reconcile'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<InventoryOperation>(None)
        .await
}

fn operation_response(
    operation: &InventoryOperation,
    requested: &CreateRequest,
) -> Result<Response> {
    if operation.driver_id != requested.driver_id || operation.prefix != requested.prefix {
        return Response::error("idempotency key pins another inventory scope", 409);
    }

    Response::from_json(operation)
}

async fn load_live_inventory(
    database: &D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    fence: &Fence,
) -> Result<Option<LiveInventory>> {
    database
        .prepare(
            "SELECT intent.prefix \
             FROM inventory_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN driver_instances AS driver ON driver.id = intent.driver_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'reconcile' \
               AND operation.state = 'running' AND operation.phase = 'inventorying' \
               AND operation.requested_by = ?2 AND operation.incarnation = control.incarnation \
               AND driver.enabled = 1 AND driver.revision = intent.driver_revision \
               AND lease.id = ?3 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.lease_kind = 'write' AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND lease.incarnation = control.incarnation \
               AND control.mode = 'active'",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&fence.lease_id),
            JsValue::from_str(&fence.incarnation),
            copying::integer(fence.fencing_token)?,
        ])?
        .first::<LiveInventory>(None)
        .await
}

async fn load_page(
    database: &D1Database,
    operation_id: &str,
    fencing_token: u64,
    sequence: u64,
) -> Result<Option<StoredPage>> {
    database
        .prepare(
            "SELECT page.sequence, page.cursor, page.next_cursor, page.report_sha256, \
                    page.object_count, \
                    (SELECT COUNT(*) FROM inventory_report_objects AS object \
                     WHERE object.operation_id = page.operation_id \
                       AND object.fencing_token = page.fencing_token \
                       AND object.page_sequence = page.sequence) AS stored_object_count \
             FROM inventory_report_pages AS page \
             WHERE page.operation_id = ?1 AND page.fencing_token = ?2 \
               AND page.sequence = ?3",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            copying::integer(fencing_token)?,
            copying::integer(sequence)?,
        ])?
        .first::<StoredPage>(None)
        .await
}

async fn load_pages(
    database: &D1Database,
    operation_id: &str,
    fencing_token: u64,
) -> Result<Vec<StoredPage>> {
    database
        .prepare(
            "SELECT page.sequence, page.cursor, page.next_cursor, page.report_sha256, \
                    page.object_count, \
                    (SELECT COUNT(*) FROM inventory_report_objects AS object \
                     WHERE object.operation_id = page.operation_id \
                       AND object.fencing_token = page.fencing_token \
                       AND object.page_sequence = page.sequence) AS stored_object_count \
             FROM inventory_report_pages AS page \
             WHERE page.operation_id = ?1 AND page.fencing_token = ?2 \
             ORDER BY page.sequence",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            copying::integer(fencing_token)?,
        ])?
        .all()
        .await?
        .results::<StoredPage>()
}

fn validate_complete_pages(pages: &[StoredPage], last_sequence: u64) -> Option<String> {
    if pages.len() as u64 != last_sequence {
        return None;
    }

    let mut digest = Sha256::new();
    for (index, page) in pages.iter().enumerate() {
        let sequence = index as u64 + 1;
        if page.sequence != sequence
            || page.object_count != page.stored_object_count
            || (sequence == 1) != page.cursor.is_empty()
            || (sequence < last_sequence && page.next_cursor.is_empty())
            || (sequence == last_sequence && !page.next_cursor.is_empty())
            || (index > 0 && pages[index - 1].next_cursor != page.cursor)
            || !copying::valid_hex(&page.report_sha256, 64)
        {
            return None;
        }
        digest.update(page.report_sha256.as_bytes());
    }

    Some(lowercase_hex(&digest.finalize()))
}

async fn classification_counts(
    database: &D1Database,
    operation_id: &str,
    fencing_token: u64,
    pages: u64,
) -> Result<ClassificationCounts> {
    let objects = scalar_count(
        database,
        "SELECT COUNT(*) AS value FROM inventory_report_objects \
         WHERE operation_id = ?1 AND fencing_token = ?2",
        operation_id,
        fencing_token,
    )
    .await?;
    let known = scalar_count(
        database,
        "SELECT COUNT(*) AS value \
         FROM inventory_report_objects AS report \
         JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id \
         WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
           AND (\
               EXISTS(SELECT 1 FROM locations AS location \
                      WHERE location.driver_id = intent.driver_id \
                        AND location.storage_key = report.storage_key \
                        AND location.state != 'deleted') \
               OR EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                         WHERE recovery.sidecar_driver_id = intent.driver_id \
                           AND recovery.sidecar_storage_key = report.storage_key \
                           AND recovery.state != 'missing')\
           )",
        operation_id,
        fencing_token,
    )
    .await?;
    let missing = scalar_count(
        database,
        "SELECT COUNT(*) AS value FROM (\
             SELECT 'location' AS subject_kind, location.id AS subject_id \
             FROM inventory_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN locations AS location ON location.driver_id = intent.driver_id \
             JOIN extents AS extent ON extent.id = location.extent_id \
             JOIN packs AS pack ON pack.id = extent.pack_id \
             WHERE intent.operation_id = ?1 AND pack.namespace_id = operation.namespace_id \
               AND location.state IN ('verified', 'available') \
               AND substr(location.storage_key, 1, length(intent.prefix) + 1) \
                   = intent.prefix || '/' \
               AND NOT EXISTS(SELECT 1 FROM inventory_report_objects AS report \
                              WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
                                AND report.storage_key = location.storage_key) \
             UNION ALL \
             SELECT 'manifest', recovery.manifest_sha256 \
             FROM inventory_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN recovery_manifests AS recovery \
               ON recovery.sidecar_driver_id = intent.driver_id \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             WHERE intent.operation_id = ?1 AND object.namespace_id = operation.namespace_id \
               AND recovery.state = 'durable' \
               AND substr(recovery.sidecar_storage_key, 1, length(intent.prefix) + 1) \
                   = intent.prefix || '/' \
               AND NOT EXISTS(SELECT 1 FROM inventory_report_objects AS report \
                              WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
                                AND report.storage_key = recovery.sidecar_storage_key)\
         )",
        operation_id,
        fencing_token,
    )
    .await?;

    Ok(ClassificationCounts {
        pages,
        objects,
        known,
        quarantined: objects.saturating_sub(known),
        missing,
    })
}

async fn scalar_count(
    database: &D1Database,
    sql: &str,
    operation_id: &str,
    fencing_token: u64,
) -> Result<u64> {
    let row = database
        .prepare(sql)
        .bind(&[
            JsValue::from_str(operation_id),
            copying::integer(fencing_token)?,
        ])?
        .first::<CountRow>(None)
        .await?;

    Ok(row.map_or(0, |value| value.value))
}

async fn count_scope_conflicts(
    database: &D1Database,
    operation_id: &str,
    fencing_token: u64,
) -> Result<u64> {
    scalar_count(
        database,
        "SELECT COUNT(*) AS value \
         FROM inventory_report_objects AS report \
         JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id \
         JOIN operations AS operation ON operation.id = intent.operation_id \
         JOIN quarantined_provider_objects AS quarantine \
           ON quarantine.driver_id = intent.driver_id \
          AND quarantine.storage_key = report.storage_key \
         WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
           AND quarantine.namespace_id != operation.namespace_id \
           AND NOT EXISTS(SELECT 1 FROM locations AS location \
                          WHERE location.driver_id = intent.driver_id \
                            AND location.storage_key = report.storage_key \
                            AND location.state != 'deleted') \
           AND NOT EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                          WHERE recovery.sidecar_driver_id = intent.driver_id \
                            AND recovery.sidecar_storage_key = report.storage_key \
                            AND recovery.state != 'missing')",
        operation_id,
        fencing_token,
    )
    .await
}

#[allow(
    clippy::too_many_lines,
    reason = "set-based quarantine, resolution, and missing finding statements stay auditable together"
)]
fn classification_statements(
    database: &D1Database,
    operation_id: &str,
    requested: &CompleteRequest,
    now: &str,
) -> Result<Vec<worker::D1PreparedStatement>> {
    let common = || {
        Ok::<_, worker::Error>([
            JsValue::from_str(operation_id),
            copying::integer(requested.fencing_token)?,
            JsValue::from_str(now),
        ])
    };
    let quarantine = database
        .prepare(
            "INSERT INTO quarantined_provider_objects (\
                 driver_id, storage_key, namespace_id, provider_version, etag, size_bytes, \
                 driver_revision, state, quarantine_until, first_observed_at, last_observed_at, \
                 last_operation_id\
             ) \
             SELECT intent.driver_id, report.storage_key, operation.namespace_id, \
                    report.provider_version, report.etag, report.size_bytes, \
                    intent.driver_revision, 'quarantined', \
                    CAST(?3 AS INTEGER) + intent.quarantine_grace_seconds, ?3, ?3, operation.id \
             FROM inventory_report_objects AS report \
             JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
               AND NOT EXISTS(SELECT 1 FROM locations AS location \
                              WHERE location.driver_id = intent.driver_id \
                                AND location.storage_key = report.storage_key \
                                AND location.state != 'deleted') \
               AND NOT EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                              WHERE recovery.sidecar_driver_id = intent.driver_id \
                                AND recovery.sidecar_storage_key = report.storage_key \
                                AND recovery.state != 'missing') \
             ON CONFLICT(driver_id, storage_key) DO UPDATE SET \
                 provider_version = excluded.provider_version, etag = excluded.etag, \
                 size_bytes = excluded.size_bytes, driver_revision = excluded.driver_revision, \
                 state = CASE \
                     WHEN quarantined_provider_objects.state IN ('resolved', 'deleted') \
                       OR quarantined_provider_objects.driver_revision != excluded.driver_revision \
                       OR quarantined_provider_objects.provider_version IS NOT excluded.provider_version \
                       OR quarantined_provider_objects.etag IS NOT excluded.etag \
                       OR quarantined_provider_objects.size_bytes != excluded.size_bytes \
                     THEN 'quarantined' ELSE quarantined_provider_objects.state END, \
                 quarantine_until = CASE \
                     WHEN quarantined_provider_objects.state IN ('resolved', 'deleted') \
                       OR quarantined_provider_objects.driver_revision != excluded.driver_revision \
                       OR quarantined_provider_objects.provider_version IS NOT excluded.provider_version \
                       OR quarantined_provider_objects.etag IS NOT excluded.etag \
                       OR quarantined_provider_objects.size_bytes != excluded.size_bytes \
                     THEN excluded.quarantine_until \
                     ELSE quarantined_provider_objects.quarantine_until END, \
                 acknowledgement_reason = CASE \
                     WHEN quarantined_provider_objects.state IN ('resolved', 'deleted') \
                       OR quarantined_provider_objects.driver_revision != excluded.driver_revision \
                       OR quarantined_provider_objects.provider_version IS NOT excluded.provider_version \
                       OR quarantined_provider_objects.etag IS NOT excluded.etag \
                       OR quarantined_provider_objects.size_bytes != excluded.size_bytes \
                     THEN NULL ELSE quarantined_provider_objects.acknowledgement_reason END, \
                 acknowledged_at = CASE \
                     WHEN quarantined_provider_objects.state IN ('resolved', 'deleted') \
                       OR quarantined_provider_objects.driver_revision != excluded.driver_revision \
                       OR quarantined_provider_objects.provider_version IS NOT excluded.provider_version \
                       OR quarantined_provider_objects.etag IS NOT excluded.etag \
                       OR quarantined_provider_objects.size_bytes != excluded.size_bytes \
                     THEN NULL ELSE quarantined_provider_objects.acknowledged_at END, \
                 tombstone_reason = CASE \
                     WHEN quarantined_provider_objects.state IN ('resolved', 'deleted') \
                       OR quarantined_provider_objects.driver_revision != excluded.driver_revision \
                       OR quarantined_provider_objects.provider_version IS NOT excluded.provider_version \
                       OR quarantined_provider_objects.etag IS NOT excluded.etag \
                       OR quarantined_provider_objects.size_bytes != excluded.size_bytes \
                     THEN NULL ELSE quarantined_provider_objects.tombstone_reason END, \
                 tombstoned_at = CASE \
                     WHEN quarantined_provider_objects.state IN ('resolved', 'deleted') \
                       OR quarantined_provider_objects.driver_revision != excluded.driver_revision \
                       OR quarantined_provider_objects.provider_version IS NOT excluded.provider_version \
                       OR quarantined_provider_objects.etag IS NOT excluded.etag \
                       OR quarantined_provider_objects.size_bytes != excluded.size_bytes \
                     THEN NULL ELSE quarantined_provider_objects.tombstoned_at END, \
                 delete_after = CASE \
                     WHEN quarantined_provider_objects.state IN ('resolved', 'deleted') \
                       OR quarantined_provider_objects.driver_revision != excluded.driver_revision \
                       OR quarantined_provider_objects.provider_version IS NOT excluded.provider_version \
                       OR quarantined_provider_objects.etag IS NOT excluded.etag \
                       OR quarantined_provider_objects.size_bytes != excluded.size_bytes \
                     THEN NULL ELSE quarantined_provider_objects.delete_after END, \
                 deleted_at = CASE \
                     WHEN quarantined_provider_objects.state IN ('resolved', 'deleted') \
                       OR quarantined_provider_objects.driver_revision != excluded.driver_revision \
                       OR quarantined_provider_objects.provider_version IS NOT excluded.provider_version \
                       OR quarantined_provider_objects.etag IS NOT excluded.etag \
                       OR quarantined_provider_objects.size_bytes != excluded.size_bytes \
                     THEN NULL ELSE quarantined_provider_objects.deleted_at END, \
                 last_observed_at = excluded.last_observed_at, \
                 last_operation_id = excluded.last_operation_id, \
                 revision = quarantined_provider_objects.revision + 1 \
             WHERE quarantined_provider_objects.namespace_id = excluded.namespace_id",
        )
        .bind(&common()?)?;
    let resolve_superseded_findings = database
        .prepare(
            "UPDATE integrity_findings AS finding \
             SET state = 'resolved', resolved_at = ?3, last_observed_at = ?3, \
                 revision = revision + 1 \
             WHERE finding.subject_kind = 'provider_object' \
               AND finding.condition = 'quarantined' \
               AND finding.state IN ('acknowledged', 'tombstoned') \
               AND EXISTS(\
                   SELECT 1 \
                   FROM inventory_report_objects AS report \
                   JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id \
                   JOIN operations AS operation ON operation.id = intent.operation_id \
                   JOIN quarantined_provider_objects AS quarantine \
                     ON quarantine.driver_id = intent.driver_id \
                    AND quarantine.storage_key = report.storage_key \
                   WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
                     AND finding.namespace_id = operation.namespace_id \
                     AND finding.subject_id = json_array(intent.driver_id, report.storage_key) \
                     AND quarantine.namespace_id = operation.namespace_id \
                     AND quarantine.state = 'quarantined' \
                     AND quarantine.last_operation_id = operation.id\
               )",
        )
        .bind(&common()?)?;
    let quarantine_findings = database
        .prepare(
            "INSERT INTO integrity_findings (\
                 id, namespace_id, subject_kind, subject_id, condition, state, evidence_json, \
                 first_observed_at, last_observed_at\
             ) \
             SELECT operation.id || '/quarantine/' || report.storage_key, \
                    operation.namespace_id, 'provider_object', \
                    json_array(intent.driver_id, report.storage_key), \
                    'quarantined', 'open', \
                    json_object(\
                        'source', 'provider_inventory', 'operation_id', operation.id, \
                        'driver_id', intent.driver_id, 'driver_revision', intent.driver_revision, \
                        'storage_key', report.storage_key, \
                        'provider_version', report.provider_version, 'etag', report.etag, \
                        'size_bytes', report.size_bytes, \
                        'quarantine_until', quarantine.quarantine_until\
                    ), ?3, ?3 \
             FROM inventory_report_objects AS report \
             JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN quarantined_provider_objects AS quarantine \
               ON quarantine.driver_id = intent.driver_id \
              AND quarantine.storage_key = report.storage_key \
              AND quarantine.namespace_id = operation.namespace_id \
              AND quarantine.state = 'quarantined' \
             WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
               AND NOT EXISTS(SELECT 1 FROM locations AS location \
                              WHERE location.driver_id = intent.driver_id \
                                AND location.storage_key = report.storage_key \
                                AND location.state != 'deleted') \
               AND NOT EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                              WHERE recovery.sidecar_driver_id = intent.driver_id \
                                AND recovery.sidecar_storage_key = report.storage_key \
                                AND recovery.state != 'missing') \
             ON CONFLICT(subject_kind, subject_id, condition, state) DO UPDATE SET \
                 evidence_json = excluded.evidence_json, \
                 last_observed_at = excluded.last_observed_at, \
                 revision = integrity_findings.revision + 1",
        )
        .bind(&common()?)?;
    let refresh_managed_findings = database
        .prepare(
            "UPDATE integrity_findings AS finding \
             SET evidence_json = (\
                     SELECT json_object(\
                         'source', 'provider_inventory', 'operation_id', operation.id, \
                         'driver_id', intent.driver_id, 'driver_revision', intent.driver_revision, \
                         'storage_key', report.storage_key, \
                         'provider_version', report.provider_version, 'etag', report.etag, \
                         'size_bytes', report.size_bytes, \
                         'quarantine_until', quarantine.quarantine_until, \
                         'acknowledgement_reason', quarantine.acknowledgement_reason, \
                         'acknowledged_at', quarantine.acknowledged_at, \
                         'tombstone_reason', quarantine.tombstone_reason, \
                         'tombstoned_at', quarantine.tombstoned_at, \
                         'delete_after', quarantine.delete_after\
                     ) \
                     FROM inventory_report_objects AS report \
                     JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id \
                     JOIN operations AS operation ON operation.id = intent.operation_id \
                     JOIN quarantined_provider_objects AS quarantine \
                       ON quarantine.driver_id = intent.driver_id \
                      AND quarantine.storage_key = report.storage_key \
                     WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
                       AND finding.namespace_id = operation.namespace_id \
                       AND finding.subject_id = json_array(intent.driver_id, report.storage_key) \
                       AND quarantine.state = finding.state \
                     LIMIT 1\
                 ), \
                 last_observed_at = ?3, revision = revision + 1 \
             WHERE finding.subject_kind = 'provider_object' \
               AND finding.condition = 'quarantined' \
               AND finding.state IN ('acknowledged', 'tombstoned') \
               AND EXISTS(\
                   SELECT 1 \
                   FROM inventory_report_objects AS report \
                   JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id \
                   JOIN operations AS operation ON operation.id = intent.operation_id \
                   JOIN quarantined_provider_objects AS quarantine \
                     ON quarantine.driver_id = intent.driver_id \
                    AND quarantine.storage_key = report.storage_key \
                   WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
                     AND finding.namespace_id = operation.namespace_id \
                     AND finding.subject_id = json_array(intent.driver_id, report.storage_key) \
                     AND quarantine.state = finding.state\
               )",
        )
        .bind(&common()?)?;
    let resolve_quarantine = database
        .prepare(
            "UPDATE quarantined_provider_objects AS quarantine \
             SET state = 'resolved', last_observed_at = ?3, last_operation_id = ?1, \
                 revision = revision + 1 \
             WHERE quarantine.namespace_id = (\
                       SELECT namespace_id FROM operations WHERE id = ?1\
                   ) \
               AND EXISTS(\
                   SELECT 1 \
                   FROM inventory_report_objects AS report \
                   JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id \
                   WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
                     AND intent.driver_id = quarantine.driver_id \
                     AND report.storage_key = quarantine.storage_key \
                     AND (\
                         EXISTS(SELECT 1 FROM locations AS location \
                                WHERE location.driver_id = intent.driver_id \
                                  AND location.storage_key = report.storage_key \
                                  AND location.state != 'deleted') \
                         OR EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                                   WHERE recovery.sidecar_driver_id = intent.driver_id \
                                     AND recovery.sidecar_storage_key = report.storage_key \
                                     AND recovery.state != 'missing')\
                     )\
               )",
        )
        .bind(&common()?)?;
    let resolve_findings = database
        .prepare(
            "UPDATE integrity_findings AS finding \
             SET state = 'resolved', resolved_at = ?3, last_observed_at = ?3, \
                 revision = revision + 1 \
             WHERE finding.namespace_id = (SELECT namespace_id FROM operations WHERE id = ?1) \
               AND finding.subject_kind = 'provider_object' \
               AND finding.condition = 'quarantined' \
               AND finding.state IN ('open', 'acknowledged', 'tombstoned') \
               AND EXISTS(\
                   SELECT 1 \
                   FROM inventory_report_objects AS report \
                   JOIN inventory_intents AS intent ON intent.operation_id = report.operation_id \
                   WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
                     AND finding.subject_id = json_array(intent.driver_id, report.storage_key) \
                     AND (\
                         EXISTS(SELECT 1 FROM locations AS location \
                                WHERE location.driver_id = intent.driver_id \
                                  AND location.storage_key = report.storage_key \
                                  AND location.state != 'deleted') \
                         OR EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                                   WHERE recovery.sidecar_driver_id = intent.driver_id \
                                     AND recovery.sidecar_storage_key = report.storage_key \
                                     AND recovery.state != 'missing')\
                     )\
               )",
        )
        .bind(&common()?)?;
    let missing_locations = database
        .prepare(
            "INSERT INTO integrity_findings (\
                 id, namespace_id, subject_kind, subject_id, condition, state, evidence_json, \
                 first_observed_at, last_observed_at\
             ) \
             SELECT operation.id || '/inventory-missing/location/' || location.id, \
                    operation.namespace_id, 'location', location.id, 'missing', 'open', \
                    json_object(\
                        'source', 'provider_inventory', 'operation_id', operation.id, \
                        'driver_id', intent.driver_id, 'storage_key', location.storage_key, \
                        'location_revision', location.revision\
                    ), ?3, ?3 \
             FROM inventory_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN locations AS location ON location.driver_id = intent.driver_id \
             JOIN extents AS extent ON extent.id = location.extent_id \
             JOIN packs AS pack ON pack.id = extent.pack_id \
             WHERE intent.operation_id = ?1 AND pack.namespace_id = operation.namespace_id \
               AND location.state IN ('verified', 'available') \
               AND substr(location.storage_key, 1, length(intent.prefix) + 1) \
                   = intent.prefix || '/' \
               AND NOT EXISTS(SELECT 1 FROM inventory_report_objects AS report \
                              WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
                                AND report.storage_key = location.storage_key) \
             ON CONFLICT(subject_kind, subject_id, condition, state) DO UPDATE SET \
                 evidence_json = excluded.evidence_json, \
                 last_observed_at = excluded.last_observed_at, \
                 revision = integrity_findings.revision + 1",
        )
        .bind(&common()?)?;
    let missing_sidecars = database
        .prepare(
            "INSERT INTO integrity_findings (\
                 id, namespace_id, subject_kind, subject_id, condition, state, evidence_json, \
                 first_observed_at, last_observed_at\
             ) \
             SELECT operation.id || '/inventory-missing/manifest/' || recovery.manifest_sha256, \
                    operation.namespace_id, 'manifest', recovery.manifest_sha256, \
                    'missing', 'open', \
                    json_object(\
                        'source', 'provider_inventory', 'operation_id', operation.id, \
                        'driver_id', intent.driver_id, \
                        'storage_key', recovery.sidecar_storage_key, \
                        'recovery_revision', recovery.revision\
                    ), ?3, ?3 \
             FROM inventory_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN recovery_manifests AS recovery \
               ON recovery.sidecar_driver_id = intent.driver_id \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             WHERE intent.operation_id = ?1 AND object.namespace_id = operation.namespace_id \
               AND recovery.state = 'durable' \
               AND substr(recovery.sidecar_storage_key, 1, length(intent.prefix) + 1) \
                   = intent.prefix || '/' \
               AND NOT EXISTS(SELECT 1 FROM inventory_report_objects AS report \
                              WHERE report.operation_id = ?1 AND report.fencing_token = ?2 \
                                AND report.storage_key = recovery.sidecar_storage_key) \
             ON CONFLICT(subject_kind, subject_id, condition, state) DO UPDATE SET \
                 evidence_json = excluded.evidence_json, \
                 last_observed_at = excluded.last_observed_at, \
                 revision = integrity_findings.revision + 1",
        )
        .bind(&common()?)?;

    Ok(vec![
        quarantine,
        resolve_superseded_findings,
        quarantine_findings,
        refresh_managed_findings,
        resolve_quarantine,
        resolve_findings,
        missing_locations,
        missing_sidecars,
    ])
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "all inventory completion fence dimensions and state transitions remain explicit"
)]
fn append_completion_statements(
    database: &D1Database,
    statements: &mut Vec<worker::D1PreparedStatement>,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &CompleteRequest,
    counts: ClassificationCounts,
    now: &str,
) -> Result<()> {
    statements.push(
        database
            .prepare(
                "INSERT INTO inventory_completions (\
                     operation_id, fencing_token, report_sha256, page_count, object_count, \
                     known_count, quarantined_count, missing_count, completed_at\
                 ) \
                 SELECT operation.id, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 \
                 FROM operations AS operation \
                 JOIN inventory_intents AS intent ON intent.operation_id = operation.id \
                 JOIN leases AS lease ON lease.operation_id = operation.id \
                 JOIN control_plane_state AS control ON control.singleton = 1 \
                 WHERE operation.id = ?9 AND operation.kind = 'reconcile' \
                   AND operation.state = 'running' AND operation.phase = 'inventorying' \
                   AND operation.requested_by = ?10 AND lease.id = ?11 \
                   AND lease.owner_client_id = ?10 AND lease.incarnation = ?12 \
                   AND lease.fencing_token = ?1 AND lease.lease_kind = 'write' \
                   AND lease.released_at IS NULL AND lease.expires_at > ?8 \
                   AND lease.incarnation = control.incarnation AND control.mode = 'active'",
            )
            .bind(&[
                copying::integer(requested.fencing_token)?,
                JsValue::from_str(&requested.report_sha256),
                copying::integer(counts.pages)?,
                copying::integer(counts.objects)?,
                copying::integer(counts.known)?,
                copying::integer(counts.quarantined)?,
                copying::integer(counts.missing)?,
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&requested.incarnation),
            ])?,
    );
    for (from, to, phase) in [
        ("running", "verifying", "verifying_inventory"),
        ("verifying", "committing", "committing_inventory"),
        ("committing", "succeeded", "completed"),
    ] {
        statements.push(
            database
                .prepare(
                    "UPDATE operations SET state = ?1, phase = ?2, revision = revision + 1, \
                         finished_at = CASE WHEN ?1 = 'succeeded' THEN ?3 ELSE finished_at END, \
                         updated_at = ?3 \
                     WHERE id = ?4 AND kind = 'reconcile' AND state = ?5 \
                       AND EXISTS(SELECT 1 FROM inventory_completions \
                                  WHERE operation_id = ?4 AND report_sha256 = ?6)",
                )
                .bind(&[
                    JsValue::from_str(to),
                    JsValue::from_str(phase),
                    JsValue::from_str(now),
                    JsValue::from_str(operation_id),
                    JsValue::from_str(from),
                    JsValue::from_str(&requested.report_sha256),
                ])?,
        );
    }
    statements.push(
        database
            .prepare(
                "UPDATE operation_attempts SET state = 'succeeded', finished_at = ?1 \
                 WHERE component_id = ?2 || '/inventory' AND attempt = ?3 \
                   AND state = 'running' AND lease_id = ?4 AND incarnation = ?5",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                copying::integer(requested.fencing_token)?,
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&requested.incarnation),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE operation_components \
                 SET state = 'succeeded', finished_at = ?1, revision = revision + 1, \
                     updated_at = ?1 \
                 WHERE id = ?2 || '/inventory' AND operation_id = ?2 \
                   AND lease_id = ?3 AND fencing_token = ?4 AND state = 'running' \
                   AND EXISTS(SELECT 1 FROM operations WHERE id = ?2 AND state = 'succeeded')",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                JsValue::from_str(&requested.lease_id),
                copying::integer(requested.fencing_token)?,
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE leases SET released_at = ?1, updated_at = ?1 \
                 WHERE id = ?2 AND operation_id = ?3 AND owner_client_id = ?4 \
                   AND incarnation = ?5 AND fencing_token = ?6 AND lease_kind = 'write' \
                   AND released_at IS NULL AND expires_at > ?1 \
                   AND EXISTS(SELECT 1 FROM operations WHERE id = ?3 AND state = 'succeeded')",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&requested.incarnation),
                copying::integer(requested.fencing_token)?,
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE inventory_completions SET state = 'committed', committed_at = ?1 \
                 WHERE operation_id = ?2 AND report_sha256 = ?3 AND state = 'staging'",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                JsValue::from_str(&requested.report_sha256),
            ])?,
    );

    Ok(())
}

async fn replay_completion(
    database: &D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &CompleteRequest,
) -> Result<Option<Response>> {
    let completion = load_committed_completion(database, operation_id, &client.id).await?;
    let Some(completion) = completion else {
        return Ok(None);
    };
    if completion.lease_id != requested.lease_id
        || completion.incarnation != requested.incarnation
        || completion.fencing_token != requested.fencing_token
    {
        return Ok(Some(Response::error(
            "inventory completion replay changed its fence",
            409,
        )?));
    }
    if completion.report_sha256 != requested.report_sha256
        || completion.page_count != requested.last_sequence
    {
        return Ok(Some(Response::error(
            "inventory completion replay changed report",
            409,
        )?));
    }

    Ok(Some(completion_response(operation_id, completion)?))
}

async fn load_committed_completion(
    database: &D1Database,
    operation_id: &str,
    client_id: &str,
) -> Result<Option<CompletionRow>> {
    database
        .prepare(
            "SELECT lease.id AS lease_id, lease.incarnation, completion.fencing_token, \
                    completion.report_sha256, completion.page_count, \
                    completion.object_count, completion.known_count, \
                    completion.quarantined_count, completion.missing_count \
             FROM inventory_completions AS completion \
             JOIN operations AS operation ON operation.id = completion.operation_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
               AND lease.fencing_token = completion.fencing_token \
             WHERE operation.id = ?1 AND operation.kind = 'reconcile' \
               AND operation.state = 'succeeded' AND operation.requested_by = ?2 \
               AND completion.state = 'committed'",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(client_id),
        ])?
        .first::<CompletionRow>(None)
        .await
}

fn completion_response(operation_id: &str, completion: CompletionRow) -> Result<Response> {
    Response::from_json(&CompletedInventory {
        operation_id: operation_id.to_owned(),
        state: "succeeded",
        report_sha256: completion.report_sha256,
        pages: completion.page_count,
        objects: completion.object_count,
        known: completion.known_count,
        quarantined: completion.quarantined_count,
        missing: completion.missing_count,
    })
}

fn page_sha256(page: &PageRequest) -> Result<String> {
    let encoded = serde_json::to_vec(&(
        page.sequence,
        &page.cursor,
        &page.next_cursor,
        &page.objects,
    ))?;

    Ok(lowercase_hex(&Sha256::digest(encoded)))
}

fn parse_quarantine_grace(encoded: &str) -> Result<u64> {
    let policy = serde_json::from_str::<RetentionPolicy>(encoded)
        .map_err(|error| worker::Error::RustError(format!("decode retention policy: {error}")))?;
    let grace = policy
        .inventory_quarantine_seconds
        .unwrap_or(DEFAULT_QUARANTINE_GRACE_SECONDS);
    if !(MINIMUM_QUARANTINE_GRACE_SECONDS..=MAXIMUM_QUARANTINE_GRACE_SECONDS).contains(&grace) {
        return Err(worker::Error::RustError(
            "inventory quarantine policy is out of range".to_owned(),
        ));
    }

    Ok(grace)
}

fn valid_fence(fence: &Fence) -> bool {
    copying::valid_string(&fence.lease_id, 256)
        && copying::valid_hex(&fence.incarnation, 32)
        && fence.fencing_token > 0
}

fn valid_inventory_objects(objects: &[InventoryObject]) -> bool {
    let mut previous = None;
    for object in objects {
        if !valid_storage_key(&object.storage_key)
            || object.size_bytes > i64::MAX as u64
            || object
                .provider_version
                .as_deref()
                .is_some_and(|value| !copying::valid_string(value, 4_096))
            || object
                .etag
                .as_deref()
                .is_some_and(|value| !copying::valid_string(value, 4_096))
            || previous.is_some_and(|key| key >= object.storage_key.as_str())
        {
            return false;
        }
        previous = Some(object.storage_key.as_str());
    }

    true
}

fn valid_inventory_page_order(
    cursor: &str,
    next_cursor: &str,
    objects: &[InventoryObject],
) -> bool {
    if objects.is_empty() {
        return next_cursor.is_empty();
    }

    if !cursor.is_empty() && objects[0].storage_key.as_str() <= cursor {
        return false;
    }

    next_cursor.is_empty()
        || objects
            .last()
            .is_some_and(|object| object.storage_key == next_cursor)
}

fn valid_prefix(prefix: &str) -> bool {
    valid_path(prefix, 2_048)
}

fn valid_storage_key(key: &str) -> bool {
    valid_path(key, 4_096)
}

fn valid_path(value: &str, maximum: usize) -> bool {
    copying::valid_string(value, maximum)
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn valid_cursor(cursor: &str) -> bool {
    cursor.is_empty() || valid_storage_key(cursor)
}

fn within_prefix(prefix: &str, key: &str) -> bool {
    key.strip_prefix(prefix)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn optional_string(value: Option<&str>) -> JsValue {
    value.map_or_else(JsValue::null, JsValue::from_str)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate inventory ID: {error}")))?;
    Ok(lowercase_hex(&random))
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::{
        InventoryObject, valid_inventory_objects, valid_inventory_page_order, valid_prefix,
        within_prefix,
    };

    #[test]
    fn validates_inventory_scope_and_ordering() {
        assert!(valid_prefix("archive/namespace"));
        assert!(!valid_prefix("/archive"));
        assert!(!valid_prefix("archive/../other"));
        assert!(within_prefix("archive", "archive/objects/one"));
        assert!(!within_prefix("archive", "archive-other/object"));

        let ordered = vec![
            InventoryObject {
                storage_key: "archive/a".to_owned(),
                size_bytes: 1,
                provider_version: None,
                etag: None,
            },
            InventoryObject {
                storage_key: "archive/b".to_owned(),
                size_bytes: 2,
                provider_version: Some("v2".to_owned()),
                etag: Some("etag".to_owned()),
            },
        ];
        assert!(valid_inventory_objects(&ordered));

        assert!(valid_inventory_page_order(
            "archive/0",
            "archive/b",
            &ordered
        ));
        assert!(valid_inventory_page_order("archive/0", "", &ordered));
        assert!(!valid_inventory_page_order("archive/a", "", &ordered));
        assert!(!valid_inventory_page_order(
            "archive/0",
            "archive/c",
            &ordered
        ));
        assert!(valid_inventory_page_order("", "", &[]));
        assert!(!valid_inventory_page_order("", "archive/a", &[]));

        let mut reversed = ordered;
        reversed.reverse();
        assert!(!valid_inventory_objects(&reversed));
    }
}
