use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use worker::{D1Database, Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, copying};

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
struct SourceRow {
    version_id: String,
    object_id: String,
    object_revision: u64,
    generation: u64,
    manifest_sha256: String,
    plaintext_sha256: String,
    plaintext_bytes: u64,
    pack_count: u64,
    recovery_sha256: Option<String>,
    recovery_revision: u64,
    r2_storage_key: String,
    r2_version: Option<String>,
    recovery_bytes: u64,
}

#[derive(Deserialize, Serialize)]
struct CompactOperation {
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
    source_generation: u64,
    source_manifest_sha256: String,
    source_recovery_sha256: String,
    source_recovery_revision: u64,
    source_plaintext_sha256: String,
    source_pack_count: u64,
    source_root_version: u32,
    source_key_epoch: u64,
    expected_object_revision: u64,
    target_generation: u64,
    target_root_version: u32,
    target_key_epoch: u64,
    destination_driver_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    published_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    published_sidecar_storage_key: Option<String>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
struct ArchiveRow {
    manifest_sha256: String,
    recovery_sha256: String,
    r2_storage_key: String,
    r2_version: String,
    recovery_bytes: u64,
}

pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !copying::valid_hex(&requested.namespace_id, 32)
        || !copying::valid_hex(&requested.manifest_sha256, 64)
        || !copying::valid_string(&requested.destination_driver_id, 256)
        || !copying::valid_string(&requested.idempotency_key, 256)
    {
        return Response::error("invalid compact operation", 400);
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

    let Some(source) = load_source(&database, client, &requested).await? else {
        return Response::error(
            "compact source is not the current multi-pack generation",
            404,
        );
    };
    let loaded = copying::load_recovery(
        env,
        &source.r2_storage_key,
        source.r2_version.as_deref(),
        source.recovery_bytes,
    )
    .await?;
    if !source_matches(&source, &loaded, &requested.namespace_id) {
        return Response::error("published compact source identity changed", 503);
    }

    let target_generation = source
        .generation
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("compact generation overflows".to_owned()))?;
    let operation_id = random_hex()?;
    let now = current_unix_seconds().to_string();
    let statements = create_statements(
        &database,
        client,
        &requested,
        &source,
        &loaded,
        target_generation,
        &operation_id,
        &now,
    )?;
    database.batch(statements).await?;

    let Some(operation) = find_operation(
        &database,
        &requested.namespace_id,
        &requested.idempotency_key,
        &client.id,
    )
    .await?
    else {
        return Response::error("compact rejected or idempotency identity conflicts", 409);
    };

    operation_response(&operation, &requested)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "compact creation keeps the complete immutable source pin visible"
)]
fn create_statements(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &CreateRequest,
    source: &SourceRow,
    loaded: &copying::LoadedRecovery,
    target_generation: u64,
    operation_id: &str,
    now: &str,
) -> Result<Vec<worker::D1PreparedStatement>> {
    let content = &loaded.validated.recovery.manifest;
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
            JsValue::from_str(&source.manifest_sha256),
            JsValue::from_str(&source.version_id),
            copying::integer(source.recovery_revision)?,
            JsValue::from_str(&source.r2_storage_key),
            copying::integer(source.recovery_bytes)?,
        ])?;
    let insert_operation = database
        .prepare(
            "INSERT INTO operations (\
                 id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                 incarnation, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT ?1, ?2, 'compact', 'planned', 'planned', ?3, ?4, \
                    control.incarnation, version.plaintext_bytes, ?5, ?5 \
             FROM control_plane_state AS control \
             JOIN recovery_manifests AS recovery ON recovery.manifest_sha256 = ?6 \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN driver_instances AS destination ON destination.id = ?7 \
             WHERE control.singleton = 1 AND control.mode = 'active' \
               AND object.namespace_id = ?2 AND object.current_generation = version.generation \
               AND object.revision = ?8 AND version.id = ?9 AND version.state = 'published' \
               AND version.pack_count = ?10 AND version.pack_count > 1 \
               AND version.plaintext_sha256 = ?11 AND version.plaintext_bytes = ?12 \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND recovery.recovery_sha256 = ?13 AND recovery.revision = ?14 \
               AND recovery.r2_storage_key = ?15 AND recovery.r2_version = ?16 \
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
            JsValue::from_str(now),
            JsValue::from_str(&source.manifest_sha256),
            JsValue::from_str(&requested.destination_driver_id),
            copying::integer(source.object_revision)?,
            JsValue::from_str(&source.version_id),
            copying::integer(source.pack_count)?,
            JsValue::from_str(&source.plaintext_sha256),
            copying::integer(source.plaintext_bytes)?,
            JsValue::from_str(&loaded.recovery_sha256),
            copying::integer(source.recovery_revision)?,
            JsValue::from_str(&source.r2_storage_key),
            JsValue::from_str(&loaded.r2_version),
        ])?;
    let insert_compact_intent = database
        .prepare(
            "INSERT OR IGNORE INTO compact_intents (\
                 operation_id, version_id, object_id, source_generation, \
                 source_manifest_sha256, source_recovery_sha256, \
                 source_recovery_revision, source_r2_storage_key, source_r2_version, \
                 source_recovery_bytes, source_plaintext_sha256, source_plaintext_bytes, \
                 source_pack_count, source_root_version, source_key_epoch, \
                 expected_object_revision, target_generation, target_root_version, \
                 target_key_epoch, destination_driver_id, created_at\
             ) \
             SELECT operation.id, version.id, object.id, version.generation, \
                    recovery.manifest_sha256, recovery.recovery_sha256, recovery.revision, \
                    recovery.r2_storage_key, recovery.r2_version, recovery.ciphertext_bytes, \
                    version.plaintext_sha256, version.plaintext_bytes, version.pack_count, \
                    ?1, ?2, object.revision, ?3, namespace.root_key_version, \
                    namespace.active_key_epoch, ?4, ?5 \
             FROM operations AS operation \
             JOIN namespaces AS namespace ON namespace.id = operation.namespace_id \
             JOIN recovery_manifests AS recovery ON recovery.manifest_sha256 = ?6 \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             WHERE operation.namespace_id = ?7 AND operation.idempotency_key = ?8 \
               AND operation.requested_by = ?9 AND operation.kind = 'compact' \
               AND operation.state = 'planned' AND version.id = ?10 \
               AND object.current_generation = version.generation \
               AND object.revision = ?11 AND recovery.recovery_sha256 = ?12 \
               AND recovery.revision = ?13",
        )
        .bind(&[
            JsValue::from_str(&content.crypto.root_version.to_string()),
            copying::integer(content.crypto.key_epoch)?,
            copying::integer(target_generation)?,
            JsValue::from_str(&requested.destination_driver_id),
            JsValue::from_str(now),
            JsValue::from_str(&source.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            JsValue::from_str(&source.version_id),
            copying::integer(source.object_revision)?,
            JsValue::from_str(&loaded.recovery_sha256),
            copying::integer(source.recovery_revision)?,
        ])?;
    let pin_target_crypto = database
        .prepare(
            "INSERT OR IGNORE INTO import_intents (\
                 operation_id, root_key_version, key_epoch, created_at\
             ) \
             SELECT compact.operation_id, compact.target_root_version, \
                    compact.target_key_epoch, compact.created_at \
             FROM compact_intents AS compact \
             JOIN operations AS operation ON operation.id = compact.operation_id \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'compact'",
        )
        .bind(&[
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?;
    let insert_component = database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, destination_driver_id, \
                 state, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT operation.id || '/compact', operation.id, ?1, 'compact', \
                    compact.destination_driver_id, 'pending', operation.useful_bytes_total, \
                    ?2, ?2 \
             FROM operations AS operation \
             JOIN compact_intents AS compact ON compact.operation_id = operation.id \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?1 AND operation.kind = 'compact'",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(now),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
        ])?;

    Ok(vec![
        backfill,
        insert_operation,
        insert_compact_intent,
        pin_target_crypto,
        insert_component,
    ])
}

async fn load_source(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &CreateRequest,
) -> Result<Option<SourceRow>> {
    database
        .prepare(
            "SELECT version.id AS version_id, object.id AS object_id, \
                    object.revision AS object_revision, version.generation, \
                    version.manifest_sha256, version.plaintext_sha256, \
                    version.plaintext_bytes, version.pack_count, \
                    recovery.recovery_sha256, recovery.revision AS recovery_revision, \
                    recovery.r2_storage_key, recovery.r2_version, \
                    recovery.ciphertext_bytes AS recovery_bytes \
             FROM recovery_manifests AS recovery \
             JOIN object_versions AS version ON version.id = recovery.version_id \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN driver_instances AS destination ON destination.id = ?3 \
             WHERE recovery.manifest_sha256 = ?1 AND object.namespace_id = ?2 \
               AND object.current_generation = version.generation \
               AND version.state = 'published' AND version.pack_count > 1 \
               AND version.plaintext_sha256 IS NOT NULL AND version.plaintext_bytes > 0 \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND destination.enabled = 1 \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?4 AND namespace_id = ?2 \
                            AND role IN ('relay', 'administrator'))",
        )
        .bind(&[
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.destination_driver_id),
            JsValue::from_str(&client.id),
        ])?
        .first::<SourceRow>(None)
        .await
}

fn source_matches(
    source: &SourceRow,
    loaded: &copying::LoadedRecovery,
    namespace_id: &str,
) -> bool {
    let content = &loaded.validated.recovery.manifest;
    loaded.validated.manifest_sha256 == source.manifest_sha256
        && loaded.validated.namespace_id == namespace_id
        && loaded.validated.object_id == source.object_id
        && loaded.validated.generation == source.generation
        && content.plaintext_sha256 == source.plaintext_sha256
        && content.plaintext_size == source.plaintext_bytes
        && u64::try_from(content.packs.len()).ok() == Some(source.pack_count)
        && source
            .recovery_sha256
            .as_ref()
            .is_none_or(|digest| digest == &loaded.recovery_sha256)
        && source
            .r2_version
            .as_ref()
            .is_none_or(|version| version == &loaded.r2_version)
}

async fn find_operation(
    database: &D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<CompactOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, compact.version_id, \
                    compact.object_id, compact.source_generation, \
                    compact.source_manifest_sha256, compact.source_recovery_sha256, \
                    compact.source_recovery_revision, compact.source_plaintext_sha256, \
                    compact.source_pack_count, compact.source_root_version, \
                    compact.source_key_epoch, compact.expected_object_revision, \
                    compact.target_generation, compact.target_root_version, \
                    compact.target_key_epoch, compact.destination_driver_id, \
                    publication.manifest_sha256 AS published_manifest_sha256, \
                    publication.sidecar_storage_key AS published_sidecar_storage_key, \
                    operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN compact_intents AS compact ON compact.operation_id = operation.id \
             LEFT JOIN publication_intents AS publication \
               ON publication.operation_id = operation.id AND publication.state = 'committed' \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'compact'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<CompactOperation>(None)
        .await
}

fn operation_response(operation: &CompactOperation, requested: &CreateRequest) -> Result<Response> {
    if operation.source_manifest_sha256 != requested.manifest_sha256
        || operation.destination_driver_id != requested.destination_driver_id
    {
        return Response::error("idempotency key pins another compact operation", 409);
    }

    Response::from_json(operation)
}

pub(crate) async fn fetch_manifest(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid compact operation ID", 400);
    }

    let requested = request.json::<ManifestRequest>().await?;
    if !copying::valid_string(&requested.lease_id, 256)
        || !copying::valid_hex(&requested.incarnation, 32)
        || requested.fencing_token == 0
    {
        return Response::error("invalid compact manifest fence", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let archived = database
        .prepare(
            "SELECT compact.source_manifest_sha256 AS manifest_sha256, \
                    compact.source_recovery_sha256 AS recovery_sha256, \
                    compact.source_r2_storage_key AS r2_storage_key, \
                    compact.source_r2_version AS r2_version, \
                    compact.source_recovery_bytes AS recovery_bytes \
             FROM compact_intents AS compact \
             JOIN operations AS operation ON operation.id = compact.operation_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'compact' \
               AND operation.state = 'running' AND operation.requested_by = ?2 \
               AND lease.id = ?3 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.lease_kind = 'write' AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND control.mode = 'active' \
               AND lease.incarnation = control.incarnation",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            copying::integer(requested.fencing_token)?,
        ])?
        .first::<ArchiveRow>(None)
        .await?;
    let Some(archived) = archived else {
        return Response::error("compact manifest fence is stale or unavailable", 409);
    };

    let loaded = copying::load_recovery(
        env,
        &archived.r2_storage_key,
        Some(&archived.r2_version),
        archived.recovery_bytes,
    )
    .await?;
    if loaded.recovery_sha256 != archived.recovery_sha256
        || loaded.validated.manifest_sha256 != archived.manifest_sha256
    {
        return Response::error("pinned compact recovery identity changed", 503);
    }

    let mut response = Response::from_bytes(loaded.encoded)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("ETag", &format!("\"{}\"", archived.recovery_sha256))?;

    Ok(response)
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate compact ID: {error}")))?;
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    Ok(encoded)
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}
