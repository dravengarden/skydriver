use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{
    D1Database, D1PreparedStatement, Date, Env, Request, Response, Result, wasm_bindgen::JsValue,
};

use crate::{clients::AuthenticatedClient, manifests};

const METADATA_BATCH_STATEMENTS: usize = 40;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    manifest_sha256: String,
    destination_driver_id: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishRequest {
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

#[derive(Deserialize, Serialize)]
struct CopyOperation {
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
    destination_driver_id: String,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
struct CopyArchiveRow {
    manifest_sha256: String,
    source_recovery_sha256: String,
    source_r2_storage_key: String,
    source_r2_version: String,
    source_recovery_bytes: u64,
}

#[derive(Deserialize)]
struct CopyIntentRow {
    kind: String,
    version_id: String,
    manifest_sha256: String,
    source_recovery_sha256: String,
    source_recovery_revision: u64,
    source_r2_storage_key: String,
    source_r2_version: String,
    source_recovery_bytes: u64,
    destination_driver_id: String,
}

#[derive(Deserialize)]
struct PublicationIntentRow {
    operation_id: String,
    client_id: String,
    manifest_sha256: String,
    recovery_sha256: String,
    r2_storage_key: String,
    r2_version: String,
    sidecar_driver_id: String,
    sidecar_storage_key: String,
    expected_location_count: u64,
    incarnation: String,
    lease_id: String,
    fencing_token: u64,
    state: String,
}

#[derive(Serialize)]
struct PublishResponse {
    operation_id: String,
    manifest_sha256: String,
    recovery_sha256: String,
    destination_driver_id: String,
    locations_added: u64,
    recovery_revision: u64,
    state: &'static str,
}

pub(crate) struct LoadedRecovery {
    pub(crate) encoded: Vec<u8>,
    pub(crate) validated: manifests::ValidatedRecovery,
    pub(crate) recovery_sha256: String,
    pub(crate) r2_version: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PublicationKind {
    Copy,
    Move,
}

impl PublicationKind {
    const fn operation_kind(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Move => "move",
        }
    }

    const fn destination_state(self) -> &'static str {
        match self {
            Self::Copy => "published",
            Self::Move => "destination_published",
        }
    }
}

pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !valid_hex(&requested.namespace_id, 32)
        || !valid_hex(&requested.manifest_sha256, 64)
        || !valid_string(&requested.destination_driver_id, 256)
        || !valid_string(&requested.idempotency_key, 256)
    {
        return Response::error("invalid copy operation", 400);
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

    let Some(recovery) = load_recovery_row(
        &database,
        &requested.namespace_id,
        &requested.manifest_sha256,
        &requested.destination_driver_id,
        &client.id,
    )
    .await?
    else {
        return Response::error("published copy source is unavailable", 404);
    };
    let loaded = load_recovery(
        env,
        &recovery.r2_storage_key,
        recovery.r2_version.as_deref(),
        recovery.ciphertext_bytes,
    )
    .await?;
    if !recovery_matches_row(&loaded, &recovery, &requested.namespace_id) {
        return Response::error("published recovery identity changed", 503);
    }

    let useful_bytes = recovery_ciphertext_bytes(&loaded.validated)?;
    let operation_id = random_hex()?;
    let now = current_unix_seconds().to_string();
    let statements = create_statements(
        &database,
        client,
        &requested,
        &recovery,
        &loaded,
        useful_bytes,
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
        return Response::error("copy rejected or idempotency identity conflicts", 409);
    };

    operation_response(&operation, &requested)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "copy creation keeps its one transactional statement set visible"
)]
fn create_statements(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &CreateRequest,
    recovery: &RecoveryRow,
    loaded: &LoadedRecovery,
    useful_bytes: u64,
    operation_id: &str,
    now: &str,
) -> Result<Vec<D1PreparedStatement>> {
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
            integer(recovery.revision)?,
            JsValue::from_str(&recovery.r2_storage_key),
            integer(recovery.ciphertext_bytes)?,
        ])?;
    let insert_operation = database
        .prepare(
            "INSERT INTO operations (\
                 id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                 incarnation, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT ?1, ?2, 'copy', 'planned', 'planned', ?3, ?4, \
                    state.incarnation, ?5, ?6, ?6 \
             FROM control_plane_state AS state \
             JOIN recovery_manifests AS recovery ON recovery.manifest_sha256 = ?7 \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN driver_instances AS destination ON destination.id = ?8 \
             WHERE state.singleton = 1 AND state.mode = 'active' \
               AND object.namespace_id = ?2 AND version.state = 'published' \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND recovery.recovery_sha256 = ?9 AND recovery.revision = ?10 \
               AND recovery.r2_storage_key = ?11 AND recovery.r2_version = ?12 \
               AND destination.enabled = 1 \
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
            integer(useful_bytes)?,
            JsValue::from_str(now),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.destination_driver_id),
            JsValue::from_str(&loaded.recovery_sha256),
            integer(recovery.revision)?,
            JsValue::from_str(&recovery.r2_storage_key),
            JsValue::from_str(&loaded.r2_version),
        ])?;
    let insert_intent = database
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
               AND operation.requested_by = ?6 AND operation.kind = 'copy' \
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
            integer(recovery.revision)?,
        ])?;
    let insert_component = database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, destination_driver_id, \
                 state, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT operation.id || '/copy', operation.id, ?1, 'copy', ?2, 'pending', \
                    operation.useful_bytes_total, ?3, ?3 \
             FROM operations AS operation \
             JOIN copy_intents AS copy ON copy.operation_id = operation.id \
             WHERE operation.namespace_id = ?4 AND operation.idempotency_key = ?5 \
               AND operation.requested_by = ?1 AND operation.kind = 'copy' \
               AND copy.destination_driver_id = ?2",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.destination_driver_id),
            JsValue::from_str(now),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
        ])?;

    Ok(vec![
        backfill,
        insert_operation,
        insert_intent,
        insert_component,
    ])
}

async fn load_recovery_row(
    database: &D1Database,
    namespace_id: &str,
    manifest_sha256: &str,
    destination_driver_id: &str,
    client_id: &str,
) -> Result<Option<RecoveryRow>> {
    database
        .prepare(
            "SELECT recovery.version_id, object.id AS object_id, version.generation, \
                    recovery.manifest_sha256, recovery.recovery_sha256, recovery.revision, \
                    recovery.r2_storage_key, recovery.r2_version, recovery.ciphertext_bytes \
             FROM recovery_manifests AS recovery \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN driver_instances AS destination ON destination.id = ?3 \
             WHERE recovery.manifest_sha256 = ?1 AND object.namespace_id = ?2 \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND version.state = 'published' AND destination.enabled = 1 \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?4 AND namespace_id = ?2 \
                            AND role IN ('relay', 'administrator'))",
        )
        .bind(&[
            JsValue::from_str(manifest_sha256),
            JsValue::from_str(namespace_id),
            JsValue::from_str(destination_driver_id),
            JsValue::from_str(client_id),
        ])?
        .first::<RecoveryRow>(None)
        .await
}

async fn find_operation(
    database: &D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<CopyOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, copy.version_id, \
                    object.id AS object_id, version.generation, copy.manifest_sha256, \
                    copy.source_recovery_sha256, copy.source_recovery_revision, \
                    copy.destination_driver_id, operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN copy_intents AS copy ON copy.operation_id = operation.id \
             JOIN object_versions AS version ON version.id = copy.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'copy'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<CopyOperation>(None)
        .await
}

fn operation_response(operation: &CopyOperation, requested: &CreateRequest) -> Result<Response> {
    if operation.manifest_sha256 != requested.manifest_sha256
        || operation.destination_driver_id != requested.destination_driver_id
    {
        return Response::error("idempotency key pins another copy", 409);
    }

    Response::from_json(&operation)
}

pub(crate) async fn fetch_manifest(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    fetch_manifest_for_kind(request, env, client, operation_id, PublicationKind::Copy).await
}

pub(crate) async fn fetch_move_manifest(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    fetch_manifest_for_kind(request, env, client, operation_id, PublicationKind::Move).await
}

async fn fetch_manifest_for_kind(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
    kind: PublicationKind,
) -> Result<Response> {
    if !valid_hex(operation_id, 32) {
        return Response::error(
            format!("invalid {} operation ID", kind.operation_kind()),
            400,
        );
    }

    let requested = request.json::<ManifestRequest>().await?;
    if !valid_string(&requested.lease_id, 256)
        || !valid_hex(&requested.incarnation, 32)
        || requested.fencing_token == 0
    {
        return Response::error(
            format!("invalid {} manifest fence", kind.operation_kind()),
            400,
        );
    }

    let database = env.d1("CARRACK_INDEX")?;
    let archived = database
        .prepare(
            "SELECT copy.manifest_sha256, copy.source_recovery_sha256, \
                    copy.source_r2_storage_key, copy.source_r2_version, \
                    copy.source_recovery_bytes \
             FROM copy_intents AS copy \
             JOIN operations AS operation ON operation.id = copy.operation_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = ?6 \
               AND operation.state = 'running' AND lease.id = ?2 \
               AND lease.owner_client_id = ?3 AND lease.incarnation = ?4 \
               AND lease.fencing_token = ?5 AND lease.lease_kind = 'write' \
               AND lease.released_at IS NULL AND lease.expires_at > unixepoch() \
               AND state.mode = 'active' AND lease.incarnation = state.incarnation",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.incarnation),
            integer(requested.fencing_token)?,
            JsValue::from_str(kind.operation_kind()),
        ])?
        .first::<CopyArchiveRow>(None)
        .await?;
    let Some(archived) = archived else {
        return Response::error(
            format!(
                "{} manifest fence is stale or unavailable",
                kind.operation_kind()
            ),
            409,
        );
    };

    let loaded = load_recovery(
        env,
        &archived.source_r2_storage_key,
        Some(&archived.source_r2_version),
        archived.source_recovery_bytes,
    )
    .await?;
    if loaded.recovery_sha256 != archived.source_recovery_sha256
        || loaded.validated.manifest_sha256 != archived.manifest_sha256
    {
        return Response::error(
            format!("pinned {} recovery identity changed", kind.operation_kind()),
            503,
        );
    }

    let mut response = Response::from_bytes(loaded.encoded)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("ETag", &format!("\"{}\"", archived.source_recovery_sha256))?;

    Ok(response)
}

#[allow(
    clippy::too_many_lines,
    reason = "copy publication keeps validation, staging, and the fenced commit visible"
)]
pub(crate) async fn publish(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    publish_for_kind(request, env, client, PublicationKind::Copy).await
}

pub(crate) async fn publish_move_destination(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    publish_for_kind(request, env, client, PublicationKind::Move).await
}

async fn publish_for_kind(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    kind: PublicationKind,
) -> Result<Response> {
    let requested = request.json::<PublishRequest>().await?;
    if !valid_publish_request(&requested) {
        return Response::error(
            format!("invalid {} publication", kind.operation_kind()),
            400,
        );
    }

    let database = env.d1("CARRACK_INDEX")?;
    let Some(copy) = load_copy_intent(&database, &requested.operation_id).await? else {
        return Response::error(
            format!("{} operation is unavailable", kind.operation_kind()),
            409,
        );
    };
    if copy.kind != kind.operation_kind()
        || copy.manifest_sha256 != requested.manifest_sha256
        || copy.destination_driver_id != requested.sidecar_driver_id
    {
        return Response::error(
            format!("{} publication identity changed", kind.operation_kind()),
            409,
        );
    }

    let source = load_recovery(
        env,
        &copy.source_r2_storage_key,
        Some(&copy.source_r2_version),
        copy.source_recovery_bytes,
    )
    .await?;
    if source.recovery_sha256 != copy.source_recovery_sha256
        || source.validated.manifest_sha256 != copy.manifest_sha256
    {
        return Response::error(
            format!("pinned {} source recovery changed", kind.operation_kind()),
            503,
        );
    }

    let updated = load_recovery(env, &requested.r2_key, Some(&requested.r2_version), 0).await?;
    if updated.recovery_sha256 != requested.recovery_sha256
        || updated.validated.manifest_sha256 != copy.manifest_sha256
    {
        return Response::error(
            format!("staged {} recovery identity changed", kind.operation_kind()),
            400,
        );
    }

    let added = match validate_recovery_update(
        &source.validated,
        &updated.validated,
        &copy.destination_driver_id,
    ) {
        Ok(locations) => locations,
        Err(error) => return Response::error(error, 400),
    };

    create_publication_intent(&database, client, &requested, &copy, added.len(), kind).await?;
    let Some(intent) = load_publication_intent(&database, &requested.operation_id).await? else {
        return Response::error(
            format!("{} publication fence was rejected", kind.operation_kind()),
            409,
        );
    };
    if !publication_matches(&intent, client, &requested, added.len()) {
        return Response::error(
            format!(
                "{} operation already owns a different publication",
                kind.operation_kind()
            ),
            409,
        );
    }

    if intent.state == "committed" {
        return publish_response(&copy, &requested, added.len(), kind);
    }

    stage_locations(&database, client, &requested, &added).await?;
    match kind {
        PublicationKind::Copy => {
            finalize_copy(&database, client, &requested, &copy, updated.encoded.len()).await?;
        }
        PublicationKind::Move => {
            finalize_move_destination(&database, client, &requested, &copy, updated.encoded.len())
                .await?;
        }
    }

    let committed = load_publication_intent(&database, &requested.operation_id)
        .await?
        .is_some_and(|value| value.state == "committed");
    if !committed {
        return Response::error(
            format!("{} publication did not commit", kind.operation_kind()),
            409,
        );
    }

    publish_response(&copy, &requested, added.len(), kind)
}

async fn load_copy_intent(
    database: &D1Database,
    operation_id: &str,
) -> Result<Option<CopyIntentRow>> {
    database
        .prepare(
            "SELECT operation.kind, copy.version_id, copy.manifest_sha256, \
                    copy.source_recovery_sha256, \
                    source_recovery_revision, source_r2_storage_key, source_r2_version, \
                    source_recovery_bytes, destination_driver_id \
             FROM copy_intents AS copy \
             JOIN operations AS operation ON operation.id = copy.operation_id \
             WHERE copy.operation_id = ?1",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .first::<CopyIntentRow>(None)
        .await
}

async fn create_publication_intent(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    copy: &CopyIntentRow,
    location_count: usize,
    kind: PublicationKind,
) -> Result<()> {
    let now = current_unix_seconds().to_string();
    database
        .prepare(
            "INSERT INTO copy_publication_intents (\
                 operation_id, client_id, manifest_sha256, recovery_sha256, \
                 r2_storage_key, r2_version, sidecar_driver_id, sidecar_storage_key, \
                 expected_location_count, incarnation, lease_id, fencing_token, \
                 state, created_at, updated_at\
             ) \
             SELECT operation.id, ?1, copy.manifest_sha256, ?2, ?3, ?4, ?5, ?6, ?7, \
                    state.incarnation, lease.id, lease.fencing_token, 'staging', ?8, ?8 \
             FROM operations AS operation \
             JOIN copy_intents AS copy ON copy.operation_id = operation.id \
             JOIN recovery_manifests AS recovery \
               ON recovery.manifest_sha256 = copy.manifest_sha256 \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             JOIN leases AS lease ON lease.id = ?9 AND lease.operation_id = operation.id \
             WHERE operation.id = ?10 AND operation.kind = ?15 \
               AND operation.state = 'running' AND operation.incarnation = state.incarnation \
               AND copy.version_id = ?11 AND copy.manifest_sha256 = ?12 \
               AND copy.destination_driver_id = ?5 AND state.mode = 'active' \
               AND state.incarnation = ?13 AND lease.owner_client_id = ?1 \
               AND lease.incarnation = state.incarnation AND lease.fencing_token = ?14 \
               AND lease.released_at IS NULL AND lease.expires_at > unixepoch() \
               AND recovery.recovery_sha256 = copy.source_recovery_sha256 \
               AND recovery.revision = copy.source_recovery_revision \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?1 AND namespace_id = operation.namespace_id \
                            AND role IN ('relay', 'administrator')) \
             ON CONFLICT(operation_id) DO UPDATE SET \
                 client_id = excluded.client_id, incarnation = excluded.incarnation, \
                 lease_id = excluded.lease_id, fencing_token = excluded.fencing_token, \
                 updated_at = excluded.updated_at \
             WHERE copy_publication_intents.state = 'staging' \
               AND copy_publication_intents.manifest_sha256 = excluded.manifest_sha256 \
               AND copy_publication_intents.recovery_sha256 = excluded.recovery_sha256 \
               AND copy_publication_intents.r2_storage_key = excluded.r2_storage_key \
               AND copy_publication_intents.r2_version = excluded.r2_version \
               AND copy_publication_intents.sidecar_driver_id = excluded.sidecar_driver_id \
               AND copy_publication_intents.sidecar_storage_key = excluded.sidecar_storage_key \
               AND copy_publication_intents.expected_location_count = \
                   excluded.expected_location_count",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.recovery_sha256),
            JsValue::from_str(&requested.r2_key),
            JsValue::from_str(&requested.r2_version),
            JsValue::from_str(&requested.sidecar_driver_id),
            JsValue::from_str(&requested.sidecar_storage_key),
            integer_usize(location_count)?,
            JsValue::from_str(&now),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&copy.version_id),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.incarnation),
            integer(requested.fencing_token)?,
            JsValue::from_str(kind.operation_kind()),
        ])?
        .run()
        .await?;

    Ok(())
}

async fn load_publication_intent(
    database: &D1Database,
    operation_id: &str,
) -> Result<Option<PublicationIntentRow>> {
    database
        .prepare(
            "SELECT operation_id, client_id, manifest_sha256, recovery_sha256, \
                    r2_storage_key, r2_version, sidecar_driver_id, sidecar_storage_key, \
                    expected_location_count, incarnation, lease_id, fencing_token, state \
             FROM copy_publication_intents WHERE operation_id = ?1",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .first::<PublicationIntentRow>(None)
        .await
}

fn publication_matches(
    intent: &PublicationIntentRow,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    location_count: usize,
) -> bool {
    intent.operation_id == requested.operation_id
        && intent.client_id == client.id
        && intent.manifest_sha256 == requested.manifest_sha256
        && intent.recovery_sha256 == requested.recovery_sha256
        && intent.r2_storage_key == requested.r2_key
        && intent.r2_version == requested.r2_version
        && intent.sidecar_driver_id == requested.sidecar_driver_id
        && intent.sidecar_storage_key == requested.sidecar_storage_key
        && usize::try_from(intent.expected_location_count).ok() == Some(location_count)
        && intent.incarnation == requested.incarnation
        && intent.lease_id == requested.lease_id
        && intent.fencing_token == requested.fencing_token
}

async fn stage_locations(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    locations: &[&manifests::Location],
) -> Result<()> {
    let now = current_unix_seconds().to_string();
    let mut statements = Vec::with_capacity(locations.len() * 2);

    for location in locations {
        statements.extend(stage_location_statements(
            database, client, requested, location, &now,
        )?);
    }

    for chunk in statements.chunks(METADATA_BATCH_STATEMENTS) {
        database.batch(chunk.to_vec()).await?;
    }

    Ok(())
}

fn stage_location_statements(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    location: &manifests::Location,
    now: &str,
) -> Result<Vec<D1PreparedStatement>> {
    let location_id = manifests::location_id(location);
    let insert = database
        .prepare(
            "INSERT OR IGNORE INTO locations (\
                 id, extent_id, driver_id, storage_key, provider_version, storage_offset, \
                 storage_length, ciphertext_sha256, ciphertext_bytes, state, created_at, updated_at\
             ) \
             SELECT ?1, extent.id, ?2, ?3, ?4, ?5, ?6, extent.ciphertext_sha256, \
                    extent.ciphertext_bytes, 'staging', ?7, ?7 \
             FROM extents AS extent \
             WHERE extent.ciphertext_sha256 = ?8 AND extent.ciphertext_bytes = ?6 \
               AND EXISTS(SELECT 1 FROM copy_publication_intents AS publication \
                          JOIN copy_intents AS copy ON copy.operation_id = publication.operation_id \
                          WHERE publication.operation_id = ?9 AND publication.client_id = ?10 \
                            AND publication.state = 'staging' \
                            AND copy.destination_driver_id = ?2)",
        )
        .bind(&[
            JsValue::from_str(&location_id),
            JsValue::from_str(&location.driver_id),
            JsValue::from_str(&location.storage_key),
            location
                .provider_version
                .as_deref()
                .map_or_else(JsValue::null, JsValue::from_str),
            integer(location.offset)?,
            integer(location.length)?,
            JsValue::from_str(now),
            JsValue::from_str(&location.extent_sha256),
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
        ])?;
    let attach = database
        .prepare(
            "INSERT OR IGNORE INTO copy_publication_locations (operation_id, location_id) \
             SELECT ?1, location.id \
             FROM locations AS location \
             JOIN extents AS extent ON extent.id = location.extent_id \
             JOIN copy_publication_intents AS publication ON publication.operation_id = ?1 \
             JOIN copy_intents AS copy ON copy.operation_id = publication.operation_id \
             WHERE publication.client_id = ?2 AND publication.state = 'staging' \
               AND location.id = ?3 AND extent.ciphertext_sha256 = ?4 \
               AND extent.ciphertext_bytes = ?9 \
               AND location.driver_id = copy.destination_driver_id \
               AND location.driver_id = ?5 AND location.storage_key = ?6 \
               AND location.provider_version IS ?7 AND location.storage_offset = ?8 \
               AND location.storage_length = ?9 AND location.ciphertext_sha256 = ?4 \
               AND location.ciphertext_bytes = ?9 \
               AND location.state IN ('staging', 'verified', 'available')",
        )
        .bind(&[
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&location_id),
            JsValue::from_str(&location.extent_sha256),
            JsValue::from_str(&location.driver_id),
            JsValue::from_str(&location.storage_key),
            location
                .provider_version
                .as_deref()
                .map_or_else(JsValue::null, JsValue::from_str),
            integer(location.offset)?,
            integer(location.length)?,
        ])?;

    Ok(vec![insert, attach])
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete fenced copy transaction remains auditable in one function"
)]
async fn finalize_copy(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    copy: &CopyIntentRow,
    recovery_bytes: usize,
) -> Result<()> {
    let now = current_unix_seconds().to_string();
    let live_guard = "EXISTS(SELECT 1 FROM copy_publication_intents AS publication \
                              JOIN copy_intents AS copy \
                                ON copy.operation_id = publication.operation_id \
                              JOIN leases AS lease ON lease.id = publication.lease_id \
                              JOIN control_plane_state AS state ON state.singleton = 1 \
                              JOIN recovery_manifests AS recovery \
                                ON recovery.manifest_sha256 = copy.manifest_sha256 \
                              WHERE publication.operation_id = ?1 \
                                AND publication.client_id = ?2 \
                                AND publication.state = 'staging' \
                                AND publication.incarnation = state.incarnation \
                                AND lease.owner_client_id = ?2 \
                                AND lease.incarnation = state.incarnation \
                                AND lease.fencing_token = publication.fencing_token \
                                AND lease.released_at IS NULL \
                                AND lease.expires_at > unixepoch() \
                                AND state.mode = 'active' \
                                AND recovery.recovery_sha256 = copy.source_recovery_sha256 \
                                AND recovery.revision = copy.source_recovery_revision)";
    let mut statements = Vec::new();

    statements.push(
        database
            .prepare(format!(
                "UPDATE operations SET state = 'verifying', phase = 'verifying', \
                        revision = revision + 1, updated_at = ?3 \
                 WHERE id = ?1 AND kind = 'copy' AND state = 'running' AND {live_guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&now),
            ])?,
    );
    statements.push(
        database
            .prepare(format!(
                "UPDATE operations SET state = 'committing', phase = 'committing', \
                        revision = revision + 1, updated_at = ?3 \
                 WHERE id = ?1 AND kind = 'copy' AND state = 'verifying' AND {live_guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&now),
            ])?,
    );
    statements.push(
        database
            .prepare(format!(
                "UPDATE recovery_manifests \
                 SET recovery_sha256 = ?4, r2_storage_key = ?5, r2_version = ?6, \
                     sidecar_driver_id = ?7, sidecar_storage_key = ?8, \
                     ciphertext_bytes = ?9, verified_at = ?3, updated_at = ?3, \
                     revision = revision + 1 \
                 WHERE manifest_sha256 = ?10 AND revision = ?11 AND state = 'durable' \
                   AND EXISTS(SELECT 1 FROM operations \
                              WHERE id = ?1 AND kind = 'copy' AND state = 'committing') \
                   AND {live_guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&now),
                JsValue::from_str(&requested.recovery_sha256),
                JsValue::from_str(&requested.r2_key),
                JsValue::from_str(&requested.r2_version),
                JsValue::from_str(&requested.sidecar_driver_id),
                JsValue::from_str(&requested.sidecar_storage_key),
                integer_usize(recovery_bytes)?,
                JsValue::from_str(&requested.manifest_sha256),
                integer(copy.source_recovery_revision)?,
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE locations \
                 SET state = 'verified', verified_at = ?1, revision = revision + 1, \
                     updated_at = ?1 \
                 WHERE state = 'staging' \
                   AND id IN (SELECT location_id FROM copy_publication_locations \
                              WHERE operation_id = ?2) \
                   AND EXISTS(SELECT 1 FROM operations \
                              WHERE id = ?2 AND kind = 'copy' AND state = 'committing')",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE locations \
                 SET state = 'available', revision = revision + 1, updated_at = ?1 \
                 WHERE state = 'verified' \
                   AND id IN (SELECT location_id FROM copy_publication_locations \
                              WHERE operation_id = ?2) \
                   AND EXISTS(SELECT 1 FROM operations \
                              WHERE id = ?2 AND kind = 'copy' AND state = 'committing')",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE copy_publication_intents \
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
                "UPDATE operation_attempts \
                 SET state = 'succeeded', finished_at = ?1, \
                     useful_bytes_verified = MAX(\
                         useful_bytes_verified, \
                         COALESCE((SELECT useful_bytes_total FROM operations WHERE id = ?2), 0)\
                     ) \
                 WHERE component_id = ?2 || '/copy' AND attempt = ?3 AND state = 'running' \
                   AND lease_id = ?4 AND incarnation = ?5",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
                integer(requested.fencing_token)?,
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&requested.incarnation),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE operation_components \
                 SET state = 'succeeded', useful_bytes_verified = useful_bytes_total, \
                     finished_at = ?1, revision = revision + 1, updated_at = ?1 \
                 WHERE operation_id = ?2 AND component_kind = 'copy' AND state = 'running' \
                   AND lease_id = ?3 AND fencing_token = ?4",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&requested.lease_id),
                integer(requested.fencing_token)?,
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE operations \
                 SET state = 'succeeded', phase = 'succeeded', \
                     useful_bytes_verified = useful_bytes_total, revision = revision + 1, \
                     finished_at = ?1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'copy' AND state = 'committing' \
                   AND EXISTS(SELECT 1 FROM copy_publication_intents \
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
                "UPDATE leases SET released_at = ?1, updated_at = ?1 \
                 WHERE id = ?2 AND operation_id = ?3 AND owner_client_id = ?4 \
                   AND incarnation = ?5 AND fencing_token = ?6 AND lease_kind = 'write' \
                   AND released_at IS NULL \
                   AND EXISTS(SELECT 1 FROM operations \
                              WHERE id = ?3 AND kind = 'copy' AND state = 'succeeded')",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&requested.incarnation),
                integer(requested.fencing_token)?,
            ])?,
    );

    database.batch(statements).await?;

    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the fenced move destination transaction remains auditable in one function"
)]
async fn finalize_move_destination(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    copy: &CopyIntentRow,
    recovery_bytes: usize,
) -> Result<()> {
    let now = current_unix_seconds().to_string();
    let live_guard = "EXISTS(SELECT 1 FROM copy_publication_intents AS publication \
                              JOIN copy_intents AS copy \
                                ON copy.operation_id = publication.operation_id \
                              JOIN move_intents AS move \
                                ON move.operation_id = publication.operation_id \
                              JOIN leases AS lease ON lease.id = publication.lease_id \
                              JOIN control_plane_state AS state ON state.singleton = 1 \
                              JOIN recovery_manifests AS recovery \
                                ON recovery.manifest_sha256 = copy.manifest_sha256 \
                              WHERE publication.operation_id = ?1 \
                                AND publication.client_id = ?2 \
                                AND publication.state = 'staging' \
                                AND move.state = 'copying' \
                                AND publication.incarnation = state.incarnation \
                                AND lease.owner_client_id = ?2 \
                                AND lease.incarnation = state.incarnation \
                                AND lease.fencing_token = publication.fencing_token \
                                AND lease.released_at IS NULL \
                                AND lease.expires_at > unixepoch() \
                                AND state.mode = 'active' \
                                AND recovery.recovery_sha256 = copy.source_recovery_sha256 \
                                AND recovery.revision = copy.source_recovery_revision)";
    let mut statements = Vec::new();

    statements.push(
        database
            .prepare(format!(
                "UPDATE operations SET phase = 'verifying', revision = revision + 1, \
                        updated_at = ?3 \
                 WHERE id = ?1 AND kind = 'move' AND state = 'running' \
                   AND phase IN ('transferring', 'copying') AND {live_guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&now),
            ])?,
    );
    statements.push(
        database
            .prepare(format!(
                "UPDATE recovery_manifests \
                 SET recovery_sha256 = ?4, r2_storage_key = ?5, r2_version = ?6, \
                     sidecar_driver_id = ?7, sidecar_storage_key = ?8, \
                     ciphertext_bytes = ?9, verified_at = ?3, updated_at = ?3, \
                     revision = revision + 1 \
                 WHERE manifest_sha256 = ?10 AND revision = ?11 AND state = 'durable' \
                   AND EXISTS(SELECT 1 FROM operations \
                              WHERE id = ?1 AND kind = 'move' AND state = 'running' \
                                AND phase = 'verifying') \
                   AND {live_guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&now),
                JsValue::from_str(&requested.recovery_sha256),
                JsValue::from_str(&requested.r2_key),
                JsValue::from_str(&requested.r2_version),
                JsValue::from_str(&requested.sidecar_driver_id),
                JsValue::from_str(&requested.sidecar_storage_key),
                integer_usize(recovery_bytes)?,
                JsValue::from_str(&requested.manifest_sha256),
                integer(copy.source_recovery_revision)?,
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE locations \
                 SET state = 'verified', verified_at = ?1, revision = revision + 1, \
                     updated_at = ?1 \
                 WHERE state = 'staging' \
                   AND id IN (SELECT location_id FROM copy_publication_locations \
                              WHERE operation_id = ?2) \
                   AND EXISTS(SELECT 1 FROM operations \
                              WHERE id = ?2 AND kind = 'move' AND state = 'running' \
                                AND phase = 'verifying')",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE locations \
                 SET state = 'available', revision = revision + 1, updated_at = ?1 \
                 WHERE state = 'verified' \
                   AND id IN (SELECT location_id FROM copy_publication_locations \
                              WHERE operation_id = ?2) \
                   AND EXISTS(SELECT 1 FROM operations \
                              WHERE id = ?2 AND kind = 'move' AND state = 'running' \
                                AND phase = 'verifying')",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE copy_publication_intents \
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
                "UPDATE move_intents SET state = 'destination_published', updated_at = ?1 \
                 WHERE operation_id = ?2 AND state = 'copying' \
                   AND EXISTS(SELECT 1 FROM copy_publication_intents \
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
                "UPDATE operations \
                 SET phase = 'destination_published', revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'move' AND state = 'running' \
                   AND phase = 'verifying' \
                   AND EXISTS(SELECT 1 FROM move_intents \
                              WHERE operation_id = ?2 AND state = 'destination_published')",
            )
            .bind(&[
                JsValue::from_str(&now),
                JsValue::from_str(&requested.operation_id),
            ])?,
    );

    database.batch(statements).await?;

    Ok(())
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

fn validate_recovery_update<'a>(
    source: &manifests::ValidatedRecovery,
    updated: &'a manifests::ValidatedRecovery,
    destination_driver_id: &str,
) -> std::result::Result<Vec<&'a manifests::Location>, String> {
    let source_content = serde_json::to_vec(&source.recovery.manifest)
        .map_err(|error| format!("encode source content manifest: {error}"))?;
    let updated_content = serde_json::to_vec(&updated.recovery.manifest)
        .map_err(|error| format!("encode updated content manifest: {error}"))?;
    if source.manifest_sha256 != updated.manifest_sha256 || source_content != updated_content {
        return Err("copy must preserve the immutable content manifest".to_owned());
    }

    let source_locations = source
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
    let mut retained = HashSet::with_capacity(source_locations.len());
    let mut added = Vec::new();

    for location in &updated.recovery.locations {
        let identity = LocationIdentity::from(location);
        if let Some(provider_version) = source_locations.get(&identity) {
            if provider_version != &location.provider_version {
                return Err("copy changed an existing provider version".to_owned());
            }

            retained.insert(identity);
        } else {
            if location.driver_id != destination_driver_id {
                return Err("copy added a location outside its destination driver".to_owned());
            }

            added.push(location);
        }
    }

    if retained.len() != source_locations.len() {
        return Err("copy recovery removed a source location".to_owned());
    }

    let destination_extents = updated
        .recovery
        .locations
        .iter()
        .filter(|location| location.driver_id == destination_driver_id)
        .map(|location| location.extent_sha256.as_str())
        .collect::<HashSet<_>>();
    if updated.recovery.manifest.packs.iter().any(|pack| {
        pack.extents
            .iter()
            .any(|extent| !destination_extents.contains(extent.ciphertext_sha256.as_str()))
    }) {
        return Err("copy destination does not cover every ciphertext extent".to_owned());
    }

    Ok(added)
}

pub(crate) async fn load_recovery(
    env: &Env,
    storage_key: &str,
    expected_version: Option<&str>,
    expected_bytes: u64,
) -> Result<LoadedRecovery> {
    let bucket = env.bucket("CARRACK_MANIFESTS")?;
    let Some(object) = bucket.get(storage_key).execute().await? else {
        return Err(worker::Error::RustError(
            "recovery manifest is missing from R2".to_owned(),
        ));
    };
    let r2_version = object.version().clone();
    if expected_version.is_some_and(|expected| expected != r2_version.as_str()) {
        return Err(worker::Error::RustError(
            "recovery manifest R2 version changed".to_owned(),
        ));
    }
    let object_size = object.size();
    if expected_bytes != 0 && object_size != expected_bytes {
        return Err(worker::Error::RustError(
            "recovery manifest size changed".to_owned(),
        ));
    }

    let Some(body) = object.body() else {
        return Err(worker::Error::RustError(
            "recovery manifest body is missing".to_owned(),
        ));
    };
    let encoded = body.bytes().await?;
    let encoded_bytes = u64::try_from(encoded.len())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    if encoded_bytes != object_size {
        return Err(worker::Error::RustError(
            "recovery manifest body size changed".to_owned(),
        ));
    }

    let recovery_sha256 = lowercase_hex(&Sha256::digest(&encoded));
    let validated = manifests::validate(&encoded).map_err(|error| {
        worker::Error::RustError(format!("validate recovery manifest: {error}"))
    })?;

    Ok(LoadedRecovery {
        encoded,
        validated,
        recovery_sha256,
        r2_version,
    })
}

fn recovery_matches_row(loaded: &LoadedRecovery, row: &RecoveryRow, namespace_id: &str) -> bool {
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

pub(crate) fn recovery_ciphertext_bytes(recovery: &manifests::ValidatedRecovery) -> Result<u64> {
    let total = recovery
        .recovery
        .manifest
        .packs
        .iter()
        .try_fold(0_u64, |total, pack| total.checked_add(pack.ciphertext_size))
        .ok_or_else(|| worker::Error::RustError("copy byte total overflows".to_owned()))?;

    if total > i64::MAX.unsigned_abs() {
        return Err(worker::Error::RustError(
            "copy byte total exceeds D1 signed range".to_owned(),
        ));
    }

    Ok(total)
}

fn publish_response(
    copy: &CopyIntentRow,
    requested: &PublishRequest,
    locations_added: usize,
    kind: PublicationKind,
) -> Result<Response> {
    let recovery_revision = copy
        .source_recovery_revision
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("recovery revision overflows".to_owned()))?;

    Response::from_json(&PublishResponse {
        operation_id: requested.operation_id.clone(),
        manifest_sha256: requested.manifest_sha256.clone(),
        recovery_sha256: requested.recovery_sha256.clone(),
        destination_driver_id: copy.destination_driver_id.clone(),
        locations_added: u64::try_from(locations_added)
            .map_err(|error| worker::Error::RustError(error.to_string()))?,
        recovery_revision,
        state: kind.destination_state(),
    })
}

fn valid_publish_request(request: &PublishRequest) -> bool {
    valid_hex(&request.operation_id, 32)
        && valid_string(&request.lease_id, 256)
        && valid_hex(&request.incarnation, 32)
        && request.fencing_token > 0
        && valid_hex(&request.manifest_sha256, 64)
        && valid_hex(&request.recovery_sha256, 64)
        && valid_string(&request.r2_key, 4_096)
        && valid_string(&request.r2_version, 1_024)
        && valid_string(&request.sidecar_driver_id, 256)
        && valid_string(&request.sidecar_storage_key, 4_096)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    encoded
}

pub(crate) fn integer(value: u64) -> Result<JsValue> {
    if value > i64::MAX.unsigned_abs() {
        return Err(worker::Error::RustError(
            "integer exceeds D1 signed range".to_owned(),
        ));
    }

    Ok(JsValue::from_str(&value.to_string()))
}

fn integer_usize(value: usize) -> Result<JsValue> {
    let converted =
        u64::try_from(value).map_err(|error| worker::Error::RustError(error.to_string()))?;

    integer(converted)
}

pub(crate) fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate operation ID: {error}")))?;

    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    Ok(encoded)
}

pub(crate) fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

pub(crate) fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::{valid_hex, valid_string};

    #[test]
    fn validates_copy_protocol_boundaries() {
        assert!(valid_hex(&"ab".repeat(32), 64));
        assert!(!valid_hex(&"AB".repeat(32), 64));
        assert!(valid_string("destination", 256));
        assert!(!valid_string(" destination", 256));
    }
}
