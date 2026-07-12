use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use worker::{D1Database, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{
    clients::AuthenticatedClient,
    copying::{self, LoadedRecovery},
    manifests,
};

const DEFAULT_MINIMUM_AVAILABLE_REPLICAS: u64 = 1;
const DEFAULT_MOVE_GRACE_SECONDS: u64 = 86_400;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    manifest_sha256: String,
    source_driver_id: String,
    destination_driver_id: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TombstoneRequest {
    operation_id: String,
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    manifest_sha256: String,
    recovery_sha256: String,
    r2_key: String,
    r2_version: String,
    sidecar_driver_id: String,
    sidecar_storage_key: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ReplicaPolicy {
    minimum_available_replicas: Option<u64>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RetentionPolicy {
    #[serde(rename = "move_grace_seconds")]
    move_grace: Option<u64>,
    #[serde(default, rename = "gc_minimum_age_seconds")]
    _gc_minimum_age: Option<u64>,
    #[serde(default, rename = "gc_grace_seconds")]
    _gc_grace: Option<u64>,
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
    replica_policy_json: String,
    retention_policy_json: String,
}

#[derive(Deserialize, Serialize)]
struct MoveOperation {
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
    source_recovery_sha256: String,
    source_recovery_revision: u64,
    source_driver_id: String,
    destination_driver_id: String,
    source_location_count: u64,
    minimum_available_replicas: u64,
    grace_seconds: u64,
    move_state: String,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
struct MoveHeadRow {
    manifest_sha256: String,
    source_recovery_revision: u64,
    destination_driver_id: String,
    source_driver_id: String,
    expected_source_location_count: u64,
    minimum_available_replicas: u64,
    grace_seconds: u64,
    move_state: String,
    recovery_sha256: String,
    recovery_revision: u64,
    r2_storage_key: String,
    r2_version: String,
    recovery_bytes: u64,
}

#[derive(Deserialize)]
struct MoveSourceRow {
    location_id: String,
    location_revision: u64,
    extent_sha256: String,
    driver_id: String,
    storage_key: String,
    provider_version: Option<String>,
    storage_offset: u64,
    storage_length: u64,
    state: String,
}

#[derive(Deserialize)]
struct TombstoneIntentRow {
    client_id: String,
    manifest_sha256: String,
    source_recovery_sha256: String,
    source_recovery_revision: u64,
    recovery_sha256: String,
    r2_storage_key: String,
    r2_version: String,
    sidecar_driver_id: String,
    sidecar_storage_key: String,
    expected_source_location_count: u64,
    incarnation: String,
    lease_id: String,
    fencing_token: u64,
    state: String,
}

#[derive(Deserialize)]
struct CountRow {
    count: u64,
}

#[derive(Deserialize, Serialize)]
struct TombstoneResponse {
    operation_id: String,
    manifest_sha256: String,
    recovery_sha256: String,
    source_driver_id: String,
    source_locations_tombstoned: u64,
    recovery_revision: u64,
    grace_until: u64,
    state: &'static str,
}

#[derive(Eq, Hash, PartialEq)]
struct LocationIdentity {
    extent_sha256: String,
    driver_id: String,
    storage_key: String,
    offset: u64,
    length: u64,
}

impl From<&manifests::Location> for LocationIdentity {
    fn from(location: &manifests::Location) -> Self {
        Self {
            extent_sha256: location.extent_sha256.clone(),
            driver_id: location.driver_id.clone(),
            storage_key: location.storage_key.clone(),
            offset: location.offset,
            length: location.length,
        }
    }
}

impl From<&MoveSourceRow> for LocationIdentity {
    fn from(location: &MoveSourceRow) -> Self {
        Self {
            extent_sha256: location.extent_sha256.clone(),
            driver_id: location.driver_id.clone(),
            storage_key: location.storage_key.clone(),
            offset: location.storage_offset,
            length: location.storage_length,
        }
    }
}

pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !valid_create_request(&requested) {
        return Response::error("invalid move operation", 400);
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
        if !operation_matches(&existing, &requested) {
            return Response::error("idempotency key pins another move", 409);
        }
        ensure_source_plan(env, &database, &existing).await?;
        return Response::from_json(&existing);
    }

    let Some(recovery) = load_recovery_row(&database, client, &requested).await? else {
        return Response::error("published move source is unavailable", 404);
    };
    let loaded = copying::load_recovery(
        env,
        &recovery.r2_storage_key,
        recovery.r2_version.as_deref(),
        recovery.ciphertext_bytes,
    )
    .await?;
    if !recovery_matches(&loaded, &recovery, &requested.namespace_id) {
        return Response::error("published recovery identity changed", 503);
    }
    validate_source_coverage(&loaded, &requested.source_driver_id)?;

    let minimum_available_replicas = parse_replica_policy(&recovery.replica_policy_json)?;
    let grace_seconds = parse_retention_policy(&recovery.retention_policy_json)?;
    let source_location_count = source_location_count(&loaded, &requested.source_driver_id)?;
    let useful_bytes = copying::recovery_ciphertext_bytes(&loaded.validated)?;
    let operation_id = copying::random_hex()?;
    let now = copying::current_unix_seconds().to_string();
    create_operation(
        &database,
        client,
        &requested,
        &recovery,
        &loaded,
        useful_bytes,
        source_location_count,
        minimum_available_replicas,
        grace_seconds,
        &operation_id,
        &now,
    )
    .await?;

    let Some(operation) = find_operation(
        &database,
        &requested.namespace_id,
        &requested.idempotency_key,
        &client.id,
    )
    .await?
    else {
        return Response::error("move rejected or idempotency identity conflicts", 409);
    };
    if !operation_matches(&operation, &requested) {
        return Response::error("idempotency key pins another move", 409);
    }
    ensure_source_plan(env, &database, &operation).await?;

    Response::from_json(&operation)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "move creation keeps its pinned source transaction visible"
)]
async fn create_operation(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &CreateRequest,
    recovery: &RecoveryRow,
    loaded: &LoadedRecovery,
    useful_bytes: u64,
    source_location_count: u64,
    minimum_available_replicas: u64,
    grace_seconds: u64,
    operation_id: &str,
    now: &str,
) -> Result<()> {
    let backfill = database
        .prepare(
            "UPDATE recovery_manifests \
             SET recovery_sha256 = ?1, r2_version = ?2, updated_at = ?3 \
             WHERE manifest_sha256 = ?4 AND version_id = ?5 AND revision = ?6 \
               AND r2_storage_key = ?7 AND ciphertext_bytes = ?8 \
               AND (recovery_sha256 IS NULL OR recovery_sha256 = ?1) \
               AND (r2_version IS NULL OR r2_version = ?2)",
        )
        .bind(&[
            JsValue::from_str(&loaded.recovery_sha256),
            JsValue::from_str(&loaded.r2_version),
            JsValue::from_str(now),
            JsValue::from_str(&recovery.manifest_sha256),
            JsValue::from_str(&recovery.version_id),
            copying::integer(recovery.revision)?,
            JsValue::from_str(&recovery.r2_storage_key),
            copying::integer(recovery.ciphertext_bytes)?,
        ])?;
    let insert_operation = database
        .prepare(
            "INSERT INTO operations (\
                 id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                 incarnation, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT ?1, ?2, 'move', 'planned', 'planned', ?3, ?4, state.incarnation, \
                    ?5, ?6, ?6 \
             FROM control_plane_state AS state \
             JOIN recovery_manifests AS recovery ON recovery.manifest_sha256 = ?7 \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN driver_instances AS source ON source.id = ?8 \
             JOIN driver_instances AS destination ON destination.id = ?9 \
             WHERE state.singleton = 1 AND state.mode = 'active' \
               AND object.namespace_id = ?2 AND version.state = 'published' \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND recovery.recovery_sha256 = ?10 AND recovery.revision = ?11 \
               AND recovery.r2_storage_key = ?12 AND recovery.r2_version = ?13 \
               AND source.enabled = 1 AND destination.enabled = 1 AND source.id != destination.id \
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
            JsValue::from_str(&requested.source_driver_id),
            JsValue::from_str(&requested.destination_driver_id),
            JsValue::from_str(&loaded.recovery_sha256),
            copying::integer(recovery.revision)?,
            JsValue::from_str(&recovery.r2_storage_key),
            JsValue::from_str(&loaded.r2_version),
        ])?;
    let insert_copy = database
        .prepare(
            "INSERT OR IGNORE INTO copy_intents (\
                 operation_id, version_id, manifest_sha256, source_recovery_sha256, \
                 source_recovery_revision, source_r2_storage_key, source_r2_version, \
                 source_recovery_bytes, destination_driver_id, created_at\
             ) \
             SELECT operation.id, recovery.version_id, recovery.manifest_sha256, \
                    recovery.recovery_sha256, recovery.revision, recovery.r2_storage_key, \
                    recovery.r2_version, recovery.ciphertext_bytes, ?1, ?2 \
             FROM operations AS operation \
             JOIN recovery_manifests AS recovery ON recovery.manifest_sha256 = ?3 \
             WHERE operation.namespace_id = ?4 AND operation.idempotency_key = ?5 \
               AND operation.requested_by = ?6 AND operation.kind = 'move' \
               AND recovery.recovery_sha256 = ?7 AND recovery.revision = ?8",
        )
        .bind(&[
            JsValue::from_str(&requested.destination_driver_id),
            JsValue::from_str(now),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            JsValue::from_str(&loaded.recovery_sha256),
            copying::integer(recovery.revision)?,
        ])?;
    let insert_move = database
        .prepare(
            "INSERT OR IGNORE INTO move_intents (\
                 operation_id, source_driver_id, expected_source_location_count, \
                 minimum_available_replicas, grace_seconds, state, created_at, updated_at\
             ) \
             SELECT copy.operation_id, ?1, ?2, ?3, ?4, 'copying', ?5, ?5 \
             FROM copy_intents AS copy \
             JOIN operations AS operation ON operation.id = copy.operation_id \
             WHERE operation.namespace_id = ?6 AND operation.idempotency_key = ?7 \
               AND operation.requested_by = ?8 AND operation.kind = 'move' \
               AND copy.destination_driver_id = ?9",
        )
        .bind(&[
            JsValue::from_str(&requested.source_driver_id),
            copying::integer(source_location_count)?,
            copying::integer(minimum_available_replicas)?,
            copying::integer(grace_seconds)?,
            JsValue::from_str(now),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.destination_driver_id),
        ])?;
    let insert_component = database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, source_driver_id, \
                 destination_driver_id, state, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT operation.id || '/move', operation.id, ?1, 'move', ?2, ?3, 'pending', \
                    operation.useful_bytes_total, ?4, ?4 \
             FROM operations AS operation \
             JOIN move_intents AS move ON move.operation_id = operation.id \
             WHERE operation.namespace_id = ?5 AND operation.idempotency_key = ?6 \
               AND operation.requested_by = ?1 AND operation.kind = 'move' \
               AND move.source_driver_id = ?2",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.source_driver_id),
            JsValue::from_str(&requested.destination_driver_id),
            JsValue::from_str(now),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
        ])?;

    database
        .batch(vec![
            backfill,
            insert_operation,
            insert_copy,
            insert_move,
            insert_component,
        ])
        .await?;

    Ok(())
}

async fn ensure_source_plan(
    env: &Env,
    database: &D1Database,
    operation: &MoveOperation,
) -> Result<()> {
    let row = database
        .prepare(
            "SELECT source_r2_storage_key, source_r2_version, source_recovery_bytes \
             FROM copy_intents WHERE operation_id = ?1",
        )
        .bind(&[JsValue::from_str(&operation.id)])?
        .first::<SourceArchiveRow>(None)
        .await?;
    let Some(row) = row else {
        return Err(worker::Error::RustError(
            "move source archive is unavailable".to_owned(),
        ));
    };
    let loaded = copying::load_recovery(
        env,
        &row.r2_storage_key,
        Some(&row.r2_version),
        row.recovery_bytes,
    )
    .await?;
    if loaded.recovery_sha256 != operation.source_recovery_sha256
        || loaded.validated.manifest_sha256 != operation.manifest_sha256
    {
        return Err(worker::Error::RustError(
            "pinned move recovery identity changed".to_owned(),
        ));
    }
    validate_source_coverage(&loaded, &operation.source_driver_id)?;

    let now = copying::current_unix_seconds().to_string();
    for location in loaded
        .validated
        .recovery
        .locations
        .iter()
        .filter(|location| location.driver_id == operation.source_driver_id)
    {
        database
            .prepare(
                "INSERT OR IGNORE INTO move_sources (\
                     operation_id, location_id, location_revision, state, updated_at\
                 ) \
                 SELECT ?1, location.id, location.revision, 'planned', ?2 \
                 FROM locations AS location \
                 JOIN extents AS extent ON extent.id = location.extent_id \
                 JOIN move_intents AS move ON move.operation_id = ?1 \
                 WHERE move.state = 'copying' AND move.source_driver_id = ?3 \
                   AND location.driver_id = ?3 AND location.storage_key = ?4 \
                   AND location.provider_version IS ?5 AND location.storage_offset = ?6 \
                   AND location.storage_length = ?7 AND location.state = 'available' \
                   AND extent.ciphertext_sha256 = ?8 AND extent.ciphertext_bytes = ?7",
            )
            .bind(&[
                JsValue::from_str(&operation.id),
                JsValue::from_str(&now),
                JsValue::from_str(&location.driver_id),
                JsValue::from_str(&location.storage_key),
                location
                    .provider_version
                    .as_deref()
                    .map_or_else(JsValue::null, JsValue::from_str),
                copying::integer(location.offset)?,
                copying::integer(location.length)?,
                JsValue::from_str(&location.extent_sha256),
            ])?
            .run()
            .await?;
    }

    let count = database
        .prepare("SELECT COUNT(*) AS count FROM move_sources WHERE operation_id = ?1")
        .bind(&[JsValue::from_str(&operation.id)])?
        .first::<CountRow>(None)
        .await?
        .map_or(0, |row| row.count);
    if count != operation.source_location_count {
        return Err(worker::Error::RustError(
            "move source locations changed while planning".to_owned(),
        ));
    }

    Ok(())
}

#[derive(Deserialize)]
struct SourceArchiveRow {
    #[serde(rename = "source_r2_storage_key")]
    r2_storage_key: String,
    #[serde(rename = "source_r2_version")]
    r2_version: String,
    #[serde(rename = "source_recovery_bytes")]
    recovery_bytes: u64,
}

pub(crate) async fn tombstone(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<TombstoneRequest>().await?;
    if !valid_tombstone_request(&requested) {
        return Response::error("invalid move tombstone", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let Some(move_head) = load_move_head(&database, &requested.operation_id).await? else {
        return Response::error("move operation is unavailable", 409);
    };
    if move_head.manifest_sha256 != requested.manifest_sha256
        || move_head.destination_driver_id != requested.sidecar_driver_id
    {
        return Response::error("move tombstone identity changed", 409);
    }

    if let Some(intent) = load_tombstone_intent(&database, &requested.operation_id).await?
        && intent.state == "committed"
    {
        if !tombstone_matches(&intent, client, &requested, &move_head) {
            return Response::error("move already owns a different tombstone", 409);
        }
        return tombstone_response(&database, &requested, &move_head).await;
    }

    if move_head.move_state != "destination_published"
        || move_head.recovery_revision
            != move_head
                .source_recovery_revision
                .checked_add(1)
                .ok_or_else(|| worker::Error::RustError("recovery revision overflows".to_owned()))?
    {
        return Response::error(
            "move destination is not the current published recovery",
            409,
        );
    }

    let current = copying::load_recovery(
        env,
        &move_head.r2_storage_key,
        Some(&move_head.r2_version),
        move_head.recovery_bytes,
    )
    .await?;
    if current.recovery_sha256 != move_head.recovery_sha256
        || current.validated.manifest_sha256 != move_head.manifest_sha256
    {
        return Response::error("published move recovery identity changed", 503);
    }
    let final_recovery =
        copying::load_recovery(env, &requested.r2_key, Some(&requested.r2_version), 0).await?;
    if final_recovery.recovery_sha256 != requested.recovery_sha256
        || final_recovery.validated.manifest_sha256 != move_head.manifest_sha256
    {
        return Response::error("staged move tombstone recovery identity changed", 400);
    }

    let sources = load_move_sources(&database, &requested.operation_id).await?;
    if let Err(error) = validate_tombstone(&current, &final_recovery, &move_head, &sources) {
        return Response::error(error, 400);
    }

    create_tombstone_intent(&database, client, &requested, &move_head).await?;
    let Some(intent) = load_tombstone_intent(&database, &requested.operation_id).await? else {
        return Response::error("move tombstone fence was rejected", 409);
    };
    if !tombstone_matches(&intent, client, &requested, &move_head) {
        return Response::error("move already owns a different tombstone", 409);
    }

    finalize_tombstone(
        &database,
        client,
        &requested,
        &move_head,
        final_recovery.encoded.len(),
    )
    .await?;
    let committed = load_tombstone_intent(&database, &requested.operation_id)
        .await?
        .is_some_and(|intent| intent.state == "committed");
    if !committed {
        return Response::error("move tombstone did not commit", 409);
    }

    tombstone_response(&database, &requested, &move_head).await
}

fn validate_tombstone(
    current: &LoadedRecovery,
    final_recovery: &LoadedRecovery,
    move_head: &MoveHeadRow,
    sources: &[MoveSourceRow],
) -> std::result::Result<(), String> {
    let current_content = serde_json::to_vec(&current.validated.recovery.manifest)
        .map_err(|error| format!("encode current content manifest: {error}"))?;
    let final_content = serde_json::to_vec(&final_recovery.validated.recovery.manifest)
        .map_err(|error| format!("encode final content manifest: {error}"))?;
    if current_content != final_content {
        return Err("move must preserve the immutable content manifest".to_owned());
    }
    if usize::try_from(move_head.expected_source_location_count).ok() != Some(sources.len()) {
        return Err("move source plan is incomplete".to_owned());
    }

    let pinned = sources
        .iter()
        .map(|source| {
            (
                LocationIdentity::from(source),
                source.provider_version.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    if sources.iter().any(|source| {
        source.location_id.is_empty()
            || source.location_revision == 0
            || source.driver_id != move_head.source_driver_id
            || source.state != "planned"
    }) {
        return Err("move source plan is stale".to_owned());
    }

    let current_locations = current
        .validated
        .recovery
        .locations
        .iter()
        .map(|location| {
            (
                LocationIdentity::from(location),
                location.provider_version.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    if pinned
        .iter()
        .any(|(identity, version)| current_locations.get(identity) != Some(version))
    {
        return Err("published move recovery no longer contains every pinned source".to_owned());
    }

    let final_locations = final_recovery
        .validated
        .recovery
        .locations
        .iter()
        .map(|location| {
            (
                LocationIdentity::from(location),
                location.provider_version.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    let expected = current_locations
        .iter()
        .filter(|(identity, _)| !pinned.contains_key(*identity))
        .collect::<HashMap<_, _>>();
    if final_locations.len() != expected.len()
        || expected
            .iter()
            .any(|(identity, version)| final_locations.get(*identity) != Some(*version))
    {
        return Err("move tombstone must remove exactly the pinned source locations".to_owned());
    }

    let mut replicas = HashMap::<&str, u64>::new();
    let mut destination_extents = HashSet::new();
    for location in &final_recovery.validated.recovery.locations {
        *replicas.entry(&location.extent_sha256).or_default() += 1;
        if location.driver_id == move_head.destination_driver_id {
            destination_extents.insert(location.extent_sha256.as_str());
        }
    }
    for pack in &final_recovery.validated.recovery.manifest.packs {
        for extent in &pack.extents {
            if !destination_extents.contains(extent.ciphertext_sha256.as_str()) {
                return Err("move destination does not cover every ciphertext extent".to_owned());
            }
            if replicas
                .get(extent.ciphertext_sha256.as_str())
                .copied()
                .unwrap_or_default()
                < move_head.minimum_available_replicas
            {
                return Err("move tombstone violates the minimum replica policy".to_owned());
            }
        }
    }

    Ok(())
}

async fn create_tombstone_intent(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &TombstoneRequest,
    move_head: &MoveHeadRow,
) -> Result<()> {
    let now = copying::current_unix_seconds().to_string();
    database
        .prepare(
            "INSERT INTO move_tombstone_intents (\
                 operation_id, client_id, manifest_sha256, source_recovery_sha256, \
                 source_recovery_revision, recovery_sha256, r2_storage_key, r2_version, \
                 sidecar_driver_id, sidecar_storage_key, expected_source_location_count, \
                 incarnation, lease_id, fencing_token, state, created_at, updated_at\
             ) \
             SELECT operation.id, ?1, copy.manifest_sha256, recovery.recovery_sha256, \
                    recovery.revision, ?2, ?3, ?4, ?5, ?6, move.expected_source_location_count, \
                    state.incarnation, lease.id, lease.fencing_token, 'staging', ?7, ?7 \
             FROM operations AS operation \
             JOIN copy_intents AS copy ON copy.operation_id = operation.id \
             JOIN move_intents AS move ON move.operation_id = operation.id \
             JOIN recovery_manifests AS recovery \
               ON recovery.manifest_sha256 = copy.manifest_sha256 \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             JOIN leases AS lease ON lease.id = ?8 AND lease.operation_id = operation.id \
             WHERE operation.id = ?9 AND operation.kind = 'move' \
               AND operation.state = 'running' AND operation.phase = 'destination_published' \
               AND operation.incarnation = state.incarnation \
               AND move.state = 'destination_published' AND move.source_driver_id = ?10 \
               AND copy.destination_driver_id = ?5 AND state.mode = 'active' \
               AND state.incarnation = ?11 AND lease.owner_client_id = ?1 \
               AND lease.incarnation = state.incarnation AND lease.fencing_token = ?12 \
               AND lease.released_at IS NULL AND lease.expires_at > unixepoch() \
               AND recovery.recovery_sha256 = ?13 AND recovery.revision = ?14 \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?1 AND namespace_id = operation.namespace_id \
                            AND role IN ('relay', 'administrator')) \
             ON CONFLICT(operation_id) DO UPDATE SET \
                 client_id = excluded.client_id, incarnation = excluded.incarnation, \
                 lease_id = excluded.lease_id, fencing_token = excluded.fencing_token, \
                 updated_at = excluded.updated_at \
             WHERE move_tombstone_intents.state = 'staging' \
               AND move_tombstone_intents.manifest_sha256 = excluded.manifest_sha256 \
               AND move_tombstone_intents.source_recovery_sha256 = \
                   excluded.source_recovery_sha256 \
               AND move_tombstone_intents.source_recovery_revision = \
                   excluded.source_recovery_revision \
               AND move_tombstone_intents.recovery_sha256 = excluded.recovery_sha256 \
               AND move_tombstone_intents.r2_storage_key = excluded.r2_storage_key \
               AND move_tombstone_intents.r2_version = excluded.r2_version \
               AND move_tombstone_intents.sidecar_driver_id = excluded.sidecar_driver_id \
               AND move_tombstone_intents.sidecar_storage_key = \
                   excluded.sidecar_storage_key \
               AND move_tombstone_intents.expected_source_location_count = \
                   excluded.expected_source_location_count",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.recovery_sha256),
            JsValue::from_str(&requested.r2_key),
            JsValue::from_str(&requested.r2_version),
            JsValue::from_str(&requested.sidecar_driver_id),
            JsValue::from_str(&requested.sidecar_storage_key),
            JsValue::from_str(&now),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&move_head.source_driver_id),
            JsValue::from_str(&requested.incarnation),
            copying::integer(requested.fencing_token)?,
            JsValue::from_str(&move_head.recovery_sha256),
            copying::integer(move_head.recovery_revision)?,
        ])?
        .run()
        .await?;

    Ok(())
}

#[allow(
    clippy::vec_init_then_push,
    clippy::too_many_lines,
    reason = "the complete fenced move tombstone transaction remains auditable"
)]
async fn finalize_tombstone(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &TombstoneRequest,
    move_head: &MoveHeadRow,
    recovery_bytes: usize,
) -> Result<()> {
    let now_value = copying::current_unix_seconds();
    let now = now_value.to_string();
    let grace_until = now_value
        .checked_add(move_head.grace_seconds)
        .ok_or_else(|| worker::Error::RustError("move grace deadline overflows".to_owned()))?
        .to_string();
    let next_revision = move_head
        .recovery_revision
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("recovery revision overflows".to_owned()))?;
    let mut statements = Vec::new();

    statements.push(
        database
            .prepare(
                "UPDATE operations SET phase = 'source_delete_pending', \
                        revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'move' AND state = 'running' \
                   AND phase = 'destination_published' \
                   AND EXISTS(SELECT 1 FROM move_tombstone_intents AS tombstone \
                              JOIN leases AS lease ON lease.id = tombstone.lease_id \
                              JOIN control_plane_state AS state ON state.singleton = 1 \
                              WHERE tombstone.operation_id = ?2 \
                                AND tombstone.client_id = ?3 AND tombstone.state = 'staging' \
                                AND tombstone.incarnation = state.incarnation \
                                AND lease.owner_client_id = ?3 \
                                AND lease.incarnation = state.incarnation \
                                AND lease.fencing_token = tombstone.fencing_token \
                                AND lease.released_at IS NULL \
                                AND lease.expires_at > unixepoch() AND state.mode = 'active')",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE recovery_manifests \
                 SET recovery_sha256 = ?1, r2_storage_key = ?2, r2_version = ?3, \
                     sidecar_driver_id = ?4, sidecar_storage_key = ?5, \
                     ciphertext_bytes = ?6, verified_at = ?7, updated_at = ?7, \
                     revision = revision + 1 \
                 WHERE manifest_sha256 = ?8 AND recovery_sha256 = ?9 AND revision = ?10 \
                   AND state = 'durable' \
                   AND EXISTS(SELECT 1 FROM operations \
                              WHERE id = ?11 AND kind = 'move' AND state = 'running' \
                                AND phase = 'source_delete_pending')",
            )
            .bind(&[
                JsValue::from_str(&requested.recovery_sha256),
                JsValue::from_str(&requested.r2_key),
                JsValue::from_str(&requested.r2_version),
                JsValue::from_str(&requested.sidecar_driver_id),
                JsValue::from_str(&requested.sidecar_storage_key),
                copying::integer(
                    u64::try_from(recovery_bytes)
                        .map_err(|error| worker::Error::RustError(error.to_string()))?,
                )?,
                JsValue::from_str(&now),
                JsValue::from_str(&requested.manifest_sha256),
                JsValue::from_str(&move_head.recovery_sha256),
                copying::integer(move_head.recovery_revision)?,
                JsValue::from_str(&requested.operation_id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE locations \
                 SET state = 'tombstoned', tombstoned_at = ?1, \
                     revision = revision + 1, updated_at = ?1 \
                 WHERE state = 'available' \
                   AND id IN (SELECT location_id FROM move_sources \
                              WHERE operation_id = ?2 AND state = 'planned' \
                                AND location_revision = locations.revision) \
                   AND EXISTS(SELECT 1 FROM recovery_manifests \
                              WHERE manifest_sha256 = ?3 AND recovery_sha256 = ?4 \
                                AND revision = ?5)",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&requested.manifest_sha256),
                JsValue::from_str(&requested.recovery_sha256),
                copying::integer(next_revision)?,
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE move_sources \
                 SET state = 'tombstoned', tombstone_revision = (\
                         SELECT revision FROM locations WHERE id = move_sources.location_id\
                     ), grace_until = ?1, updated_at = ?2 \
                 WHERE operation_id = ?3 AND state = 'planned' \
                   AND EXISTS(SELECT 1 FROM locations \
                              WHERE id = move_sources.location_id \
                                AND state = 'tombstoned' \
                                AND revision = move_sources.location_revision + 1)",
            )
            .bind(&[
                JsValue::from_str(&grace_until),
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE move_tombstone_intents \
                 SET state = 'committed', committed_at = ?1, updated_at = ?1 \
                 WHERE operation_id = ?2 AND state = 'staging'",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE move_intents SET state = 'source_delete_pending', updated_at = ?1 \
                 WHERE operation_id = ?2 AND state = 'destination_published' \
                   AND EXISTS(SELECT 1 FROM move_tombstone_intents \
                              WHERE operation_id = ?2 AND state = 'committed')",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE operation_attempts SET state = 'succeeded', finished_at = ?1, \
                        useful_bytes_verified = MAX(\
                            useful_bytes_verified, \
                            COALESCE((SELECT useful_bytes_total FROM operations WHERE id = ?2), 0)\
                        ) \
                 WHERE component_id = ?2 || '/move' AND attempt = ?3 AND state = 'running' \
                   AND lease_id = ?4 AND incarnation = ?5",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
                copying::integer(requested.fencing_token)?,
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&requested.incarnation),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE operation_components \
                 SET state = 'stalled', useful_bytes_verified = useful_bytes_total, \
                     lease_id = NULL, fencing_token = NULL, revision = revision + 1, \
                     updated_at = ?1 \
                 WHERE operation_id = ?2 AND component_kind = 'move' AND state = 'running' \
                   AND lease_id = ?3 AND fencing_token = ?4",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
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
                   AND released_at IS NULL \
                   AND EXISTS(SELECT 1 FROM move_intents \
                              WHERE operation_id = ?3 AND state = 'source_delete_pending')",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&requested.incarnation),
                copying::integer(requested.fencing_token)?,
            ])?,
    );

    database.batch(statements).await?;

    Ok(())
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
                    recovery.r2_storage_key, recovery.r2_version, recovery.ciphertext_bytes, \
                    namespace.replica_policy_json, namespace.retention_policy_json \
             FROM recovery_manifests AS recovery \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN namespaces AS namespace ON namespace.id = object.namespace_id \
             JOIN driver_instances AS source ON source.id = ?3 \
             JOIN driver_instances AS destination ON destination.id = ?4 \
             WHERE recovery.manifest_sha256 = ?1 AND object.namespace_id = ?2 \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND version.state = 'published' AND source.enabled = 1 \
               AND destination.enabled = 1 AND source.id != destination.id \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?5 AND namespace_id = ?2 \
                            AND role IN ('relay', 'administrator'))",
        )
        .bind(&[
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.source_driver_id),
            JsValue::from_str(&requested.destination_driver_id),
            JsValue::from_str(&client.id),
        ])?
        .first::<RecoveryRow>(None)
        .await
}

async fn find_operation(
    database: &D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<MoveOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, copy.version_id, \
                    object.id AS object_id, version.generation, copy.manifest_sha256, \
                    copy.source_recovery_sha256, copy.source_recovery_revision, \
                    move.source_driver_id, copy.destination_driver_id, \
                    move.expected_source_location_count AS source_location_count, \
                    move.minimum_available_replicas, move.grace_seconds, \
                    move.state AS move_state, operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN copy_intents AS copy ON copy.operation_id = operation.id \
             JOIN move_intents AS move ON move.operation_id = operation.id \
             JOIN object_versions AS version ON version.id = copy.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'move'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<MoveOperation>(None)
        .await
}

async fn load_move_head(database: &D1Database, operation_id: &str) -> Result<Option<MoveHeadRow>> {
    database
        .prepare(
            "SELECT copy.manifest_sha256, copy.source_recovery_revision, \
                    copy.destination_driver_id, move.source_driver_id, \
                    move.expected_source_location_count, move.minimum_available_replicas, \
                    move.grace_seconds, move.state AS move_state, recovery.recovery_sha256, \
                    recovery.revision AS recovery_revision, recovery.r2_storage_key, \
                    recovery.r2_version, recovery.ciphertext_bytes AS recovery_bytes \
             FROM copy_intents AS copy \
             JOIN move_intents AS move ON move.operation_id = copy.operation_id \
             JOIN recovery_manifests AS recovery \
               ON recovery.manifest_sha256 = copy.manifest_sha256 \
             JOIN operations AS operation ON operation.id = copy.operation_id \
             WHERE copy.operation_id = ?1 AND operation.kind = 'move'",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .first::<MoveHeadRow>(None)
        .await
}

async fn load_move_sources(
    database: &D1Database,
    operation_id: &str,
) -> Result<Vec<MoveSourceRow>> {
    database
        .prepare(
            "SELECT source.location_id, source.location_revision, extent.ciphertext_sha256 \
                    AS extent_sha256, location.driver_id, location.storage_key, \
                    location.provider_version, location.storage_offset, \
                    location.storage_length, source.state \
             FROM move_sources AS source \
             JOIN locations AS location ON location.id = source.location_id \
             JOIN extents AS extent ON extent.id = location.extent_id \
             WHERE source.operation_id = ?1 ORDER BY source.location_id",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .all()
        .await?
        .results::<MoveSourceRow>()
}

async fn load_tombstone_intent(
    database: &D1Database,
    operation_id: &str,
) -> Result<Option<TombstoneIntentRow>> {
    database
        .prepare(
            "SELECT client_id, manifest_sha256, source_recovery_sha256, \
                    source_recovery_revision, recovery_sha256, r2_storage_key, r2_version, \
                    sidecar_driver_id, sidecar_storage_key, expected_source_location_count, \
                    incarnation, lease_id, fencing_token, state \
             FROM move_tombstone_intents WHERE operation_id = ?1",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .first::<TombstoneIntentRow>(None)
        .await
}

async fn tombstone_response(
    database: &D1Database,
    requested: &TombstoneRequest,
    move_head: &MoveHeadRow,
) -> Result<Response> {
    let grace = database
        .prepare(
            "SELECT COALESCE(MAX(grace_until), 0) AS count \
             FROM move_sources WHERE operation_id = ?1 AND state = 'tombstoned'",
        )
        .bind(&[JsValue::from_str(&requested.operation_id)])?
        .first::<CountRow>(None)
        .await?
        .map_or(0, |row| row.count);
    let recovery_revision = move_head
        .recovery_revision
        .checked_add(u64::from(move_head.move_state != "source_delete_pending"))
        .ok_or_else(|| worker::Error::RustError("recovery revision overflows".to_owned()))?;

    Response::from_json(&TombstoneResponse {
        operation_id: requested.operation_id.clone(),
        manifest_sha256: requested.manifest_sha256.clone(),
        recovery_sha256: requested.recovery_sha256.clone(),
        source_driver_id: move_head.source_driver_id.clone(),
        source_locations_tombstoned: move_head.expected_source_location_count,
        recovery_revision,
        grace_until: grace,
        state: "source_delete_pending",
    })
}

fn tombstone_matches(
    intent: &TombstoneIntentRow,
    client: &AuthenticatedClient,
    requested: &TombstoneRequest,
    move_head: &MoveHeadRow,
) -> bool {
    let source_matches = if intent.state == "committed" {
        move_head.recovery_sha256 == intent.recovery_sha256
            && move_head.recovery_revision
                == intent
                    .source_recovery_revision
                    .checked_add(1)
                    .unwrap_or_default()
    } else {
        intent.source_recovery_sha256 == move_head.recovery_sha256
            && intent.source_recovery_revision == move_head.recovery_revision
    };

    intent.client_id == client.id
        && intent.manifest_sha256 == requested.manifest_sha256
        && source_matches
        && intent.recovery_sha256 == requested.recovery_sha256
        && intent.r2_storage_key == requested.r2_key
        && intent.r2_version == requested.r2_version
        && intent.sidecar_driver_id == requested.sidecar_driver_id
        && intent.sidecar_storage_key == requested.sidecar_storage_key
        && intent.expected_source_location_count == move_head.expected_source_location_count
        && intent.incarnation == requested.incarnation
        && intent.lease_id == requested.lease_id
        && intent.fencing_token == requested.fencing_token
}

fn recovery_matches(loaded: &LoadedRecovery, row: &RecoveryRow, namespace_id: &str) -> bool {
    loaded.validated.manifest_sha256 == row.manifest_sha256
        && loaded.validated.namespace_id == namespace_id
        && loaded.validated.object_id == row.object_id
        && loaded.validated.generation == row.generation
        && row
            .recovery_sha256
            .as_ref()
            .is_none_or(|digest| digest == &loaded.recovery_sha256)
        && row
            .r2_version
            .as_ref()
            .is_none_or(|version| version == &loaded.r2_version)
}

fn validate_source_coverage(recovery: &LoadedRecovery, source_driver_id: &str) -> Result<()> {
    let covered = recovery
        .validated
        .recovery
        .locations
        .iter()
        .filter(|location| location.driver_id == source_driver_id)
        .map(|location| location.extent_sha256.as_str())
        .collect::<HashSet<_>>();
    if recovery
        .validated
        .recovery
        .manifest
        .packs
        .iter()
        .any(|pack| {
            pack.extents
                .iter()
                .any(|extent| !covered.contains(extent.ciphertext_sha256.as_str()))
        })
    {
        return Err(worker::Error::RustError(
            "move source does not cover every ciphertext extent".to_owned(),
        ));
    }

    Ok(())
}

fn source_location_count(recovery: &LoadedRecovery, source_driver_id: &str) -> Result<u64> {
    let count = recovery
        .validated
        .recovery
        .locations
        .iter()
        .filter(|location| location.driver_id == source_driver_id)
        .count();
    u64::try_from(count).map_err(|error| worker::Error::RustError(error.to_string()))
}

fn parse_replica_policy(encoded: &str) -> Result<u64> {
    let policy = serde_json::from_str::<ReplicaPolicy>(encoded)
        .map_err(|error| worker::Error::RustError(format!("decode replica policy: {error}")))?;
    let minimum = policy
        .minimum_available_replicas
        .unwrap_or(DEFAULT_MINIMUM_AVAILABLE_REPLICAS);
    if !(1..=64).contains(&minimum) {
        return Err(worker::Error::RustError(
            "minimum available replicas is out of range".to_owned(),
        ));
    }
    Ok(minimum)
}

fn parse_retention_policy(encoded: &str) -> Result<u64> {
    let policy = serde_json::from_str::<RetentionPolicy>(encoded)
        .map_err(|error| worker::Error::RustError(format!("decode retention policy: {error}")))?;
    let grace = policy.move_grace.unwrap_or(DEFAULT_MOVE_GRACE_SECONDS);
    if !(60..=31_536_000).contains(&grace) {
        return Err(worker::Error::RustError(
            "move grace is out of range".to_owned(),
        ));
    }
    Ok(grace)
}

fn operation_matches(operation: &MoveOperation, requested: &CreateRequest) -> bool {
    operation.manifest_sha256 == requested.manifest_sha256
        && operation.source_driver_id == requested.source_driver_id
        && operation.destination_driver_id == requested.destination_driver_id
}

fn valid_create_request(request: &CreateRequest) -> bool {
    copying::valid_hex(&request.namespace_id, 32)
        && copying::valid_hex(&request.manifest_sha256, 64)
        && copying::valid_string(&request.source_driver_id, 256)
        && copying::valid_string(&request.destination_driver_id, 256)
        && request.source_driver_id != request.destination_driver_id
        && copying::valid_string(&request.idempotency_key, 256)
}

fn valid_tombstone_request(request: &TombstoneRequest) -> bool {
    copying::valid_hex(&request.operation_id, 32)
        && copying::valid_string(&request.lease_id, 256)
        && copying::valid_hex(&request.incarnation, 32)
        && request.fencing_token > 0
        && copying::valid_hex(&request.manifest_sha256, 64)
        && copying::valid_hex(&request.recovery_sha256, 64)
        && copying::valid_string(&request.r2_key, 4_096)
        && copying::valid_string(&request.r2_version, 1_024)
        && copying::valid_string(&request.sidecar_driver_id, 256)
        && copying::valid_string(&request.sidecar_storage_key, 4_096)
}
