use std::{collections::HashMap, fmt::Write as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, manifests};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    manifest_sha256: String,
    driver_id: String,
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
struct ManifestArchiveRow {
    manifest_sha256: String,
    recovery_sha256: Option<String>,
    r2_storage_key: String,
    r2_version: Option<String>,
    ciphertext_bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LocationEvidence {
    extent_sha256: String,
    driver_id: String,
    storage_key: String,
    offset: u64,
    length: u64,
    condition: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    manifest_sha256: String,
    evidence: Vec<LocationEvidence>,
}

#[derive(Deserialize)]
struct VerificationLocationRow {
    id: String,
    extent_sha256: String,
    driver_id: String,
    storage_key: String,
    storage_offset: u64,
    storage_length: u64,
}

#[derive(Deserialize)]
struct CompletionRow {
    report_sha256: String,
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Serialize)]
struct CompletedVerify {
    operation_id: String,
    manifest_sha256: String,
    state: String,
    verified: u64,
    missing: u64,
    corrupt: u64,
    unavailable: u64,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct VerifyOperation {
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
    manifest_sha256: String,
    recovery_revision: u64,
    driver_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_verified: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_missing: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_corrupt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_unavailable: Option<u64>,
    created_at: u64,
    updated_at: u64,
}

#[allow(
    clippy::too_many_lines,
    reason = "the atomic operation, intent, and component creation protocol remains visible together"
)]
pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !valid_hex(&requested.namespace_id, 32)
        || !valid_hex(&requested.manifest_sha256, 64)
        || !valid_string(&requested.driver_id, 256)
        || !valid_string(&requested.idempotency_key, 256)
    {
        return Response::error("invalid verify operation", 400);
    }

    let operation_id = random_hex()?;
    let now = current_unix_seconds().to_string();
    let database = env.d1("CARRACK_INDEX")?;
    let insert_operation = database
        .prepare(
            "INSERT INTO operations (\
                 id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                 incarnation, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT ?1, ?2, 'verify', 'planned', 'planned', ?3, ?4, state.incarnation, \
                    (SELECT SUM(location.storage_length) \
                     FROM version_packs AS version_pack \
                     JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
                     JOIN locations AS location ON location.extent_id = extent.id \
                     WHERE version_pack.version_id = version.id \
                       AND location.driver_id = ?5 AND location.state = 'available'), \
                    ?6, ?6 \
             FROM control_plane_state AS state \
             JOIN object_versions AS version ON version.manifest_sha256 = ?7 \
             JOIN objects AS object ON object.id = version.object_id \
             WHERE state.singleton = 1 AND state.mode = 'active' \
               AND object.namespace_id = ?2 AND version.state = 'published' \
               AND EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                          WHERE recovery.version_id = version.id \
                            AND recovery.manifest_sha256 = version.manifest_sha256 \
                            AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL) \
               AND EXISTS(SELECT 1 FROM version_packs AS version_pack \
                          JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
                          JOIN locations AS location ON location.extent_id = extent.id \
                          WHERE version_pack.version_id = version.id \
                            AND location.driver_id = ?5 AND location.state = 'available') \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?4 AND namespace_id = ?2 \
                            AND role = 'administrator') \
             ON CONFLICT(namespace_id, idempotency_key) DO NOTHING",
        )
        .bind(&[
            JsValue::from_str(&operation_id),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.driver_id),
            JsValue::from_str(&now),
            JsValue::from_str(&requested.manifest_sha256),
        ])?;
    let insert_intent = database
        .prepare(
            "INSERT OR IGNORE INTO verify_intents (\
                 operation_id, version_id, manifest_sha256, recovery_revision, driver_id, created_at\
             ) \
             SELECT operation.id, version.id, version.manifest_sha256, recovery.revision, ?1, ?2 \
             FROM operations AS operation \
             JOIN object_versions AS version ON version.manifest_sha256 = ?3 \
             JOIN recovery_manifests AS recovery ON recovery.version_id = version.id \
             WHERE operation.namespace_id = ?4 AND operation.idempotency_key = ?5 \
               AND operation.requested_by = ?6 AND operation.kind = 'verify'",
        )
        .bind(&[
            JsValue::from_str(&requested.driver_id),
            JsValue::from_str(&now),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?;
    let insert_component = database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, source_driver_id, state, \
                 useful_bytes_total, created_at, updated_at\
             ) \
             SELECT operation.id || '/verify', operation.id, ?1, 'verify', intent.driver_id, \
                    'pending', operation.useful_bytes_total, ?2, ?2 \
             FROM operations AS operation \
             JOIN verify_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?1 AND operation.kind = 'verify'",
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
        return Response::error("verify rejected or idempotency identity conflicts", 409);
    };
    if operation.manifest_sha256 != requested.manifest_sha256
        || operation.driver_id != requested.driver_id
    {
        return Response::error("idempotency key pins another verify target", 409);
    }

    Response::from_json(&operation)
}

pub(crate) async fn fetch_manifest(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !valid_hex(operation_id, 32) {
        return Response::error("invalid verify operation ID", 400);
    }

    let requested = request.json::<ManifestRequest>().await?;
    if !valid_string(&requested.lease_id, 256)
        || !valid_hex(&requested.incarnation, 32)
        || requested.fencing_token == 0
    {
        return Response::error("invalid verify manifest fence", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let archived = database
        .prepare(
            "SELECT intent.manifest_sha256, recovery.recovery_sha256, \
                    recovery.r2_storage_key, recovery.r2_version, recovery.ciphertext_bytes \
             FROM verify_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN recovery_manifests AS recovery \
               ON recovery.version_id = intent.version_id \
              AND recovery.manifest_sha256 = intent.manifest_sha256 \
              AND recovery.revision = intent.recovery_revision \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'verify' \
               AND operation.state = 'running' AND operation.requested_by = ?2 \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND lease.id = ?3 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.lease_kind = 'write' AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND state.mode = 'active' \
               AND lease.incarnation = state.incarnation",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            JsValue::from_str(&requested.fencing_token.to_string()),
        ])?
        .first::<ManifestArchiveRow>(None)
        .await?;
    let Some(archived) = archived else {
        return Response::error("verify manifest fence is stale or unavailable", 409);
    };

    let bucket = env.bucket("CARRACK_MANIFESTS")?;
    let Some(object) = bucket.get(&archived.r2_storage_key).execute().await? else {
        return Response::error("durable recovery manifest is missing", 503);
    };
    if archived
        .r2_version
        .as_ref()
        .is_some_and(|version| version.as_str() != object.version().as_str())
    {
        return Response::error("durable recovery manifest version changed", 503);
    }
    if object.size() != archived.ciphertext_bytes {
        return Response::error("durable recovery manifest size changed", 503);
    }
    let Some(body) = object.body() else {
        return Response::error("durable recovery manifest body is missing", 503);
    };
    let encoded = body.bytes().await?;
    if archived
        .recovery_sha256
        .as_ref()
        .is_some_and(|expected| expected != &lowercase_hex(&Sha256::digest(&encoded)))
    {
        return Response::error("durable recovery manifest hash changed", 503);
    }
    let Ok(validated) = manifests::validate(&encoded) else {
        return Response::error("durable recovery manifest is corrupt", 503);
    };
    if validated.manifest_sha256 != archived.manifest_sha256 {
        return Response::error("durable recovery manifest identity changed", 503);
    }

    let mut response = Response::from_bytes(encoded)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("ETag", &format!("\"{}\"", archived.manifest_sha256))?;

    Ok(response)
}

#[allow(
    clippy::too_many_lines,
    reason = "the fenced evidence and operation completion transaction remains auditable as one protocol"
)]
pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !valid_hex(operation_id, 32) {
        return Response::error("invalid verify operation ID", 400);
    }

    let mut completed = request.json::<CompleteRequest>().await?;
    if !valid_completion(&completed) {
        return Response::error("invalid verify completion", 400);
    }
    completed.evidence.sort_by_key(evidence_key);
    let canonical = serde_json::to_vec(&(
        completed.manifest_sha256.as_str(),
        completed.evidence.as_slice(),
    ))?;
    let report_sha256 = lowercase_hex(&Sha256::digest(canonical));
    let counts = evidence_counts(&completed.evidence);
    let database = env.d1("CARRACK_INDEX")?;

    if let Some(existing) = database
        .prepare(
            "SELECT completion.report_sha256, observation.lease_id, \
                    observation.incarnation, observation.fencing_token \
             FROM verify_completions AS completion \
             JOIN operations AS operation ON operation.id = completion.operation_id \
             JOIN verify_intents AS intent ON intent.operation_id = operation.id \
             JOIN integrity_observations AS observation \
               ON observation.operation_id = completion.operation_id \
             WHERE operation.id = ?1 AND operation.kind = 'verify' \
               AND operation.state = 'succeeded' AND operation.requested_by = ?2 \
               AND completion.state = 'committed' \
               AND intent.manifest_sha256 = ?3",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&completed.manifest_sha256),
        ])?
        .first::<CompletionRow>(None)
        .await?
    {
        if existing.lease_id != completed.lease_id
            || existing.incarnation != completed.incarnation
            || existing.fencing_token != completed.fencing_token
        {
            return Response::error("verify completion replay changed its fence", 409);
        }
        if existing.report_sha256 != report_sha256 {
            return Response::error("verify completion replay changed evidence", 409);
        }

        return completion_response(operation_id, &completed.manifest_sha256, counts);
    }

    let locations =
        load_verification_locations(&database, operation_id, client, &completed).await?;
    let mut indexed = HashMap::with_capacity(locations.len());
    for location in locations {
        indexed.insert(location_key(&location)?, location);
    }
    if indexed.len() != completed.evidence.len() {
        return Response::error("verify evidence does not cover every pinned location", 409);
    }

    let now = current_unix_seconds().to_string();
    let mut statements = Vec::with_capacity(completed.evidence.len() * 3 + 7);
    for evidence in &completed.evidence {
        let Some(location) = indexed.remove(&evidence_key(evidence)) else {
            return Response::error("verify evidence identifies an unpinned location", 409);
        };
        let stored_condition = match evidence.condition.as_str() {
            "unavailable" => "driver_unavailable",
            value => value,
        };
        let evidence_json = serde_json::to_string(evidence)?;
        statements.push(
            database
                .prepare(
                    "INSERT INTO integrity_observations (\
                         operation_id, location_id, condition, evidence_json, observed_at, \
                         lease_id, incarnation, fencing_token\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )
                .bind(&[
                    JsValue::from_str(operation_id),
                    JsValue::from_str(&location.id),
                    JsValue::from_str(stored_condition),
                    JsValue::from_str(&evidence_json),
                    JsValue::from_str(&now),
                    JsValue::from_str(&completed.lease_id),
                    JsValue::from_str(&completed.incarnation),
                    JsValue::from_str(&completed.fencing_token.to_string()),
                ])?,
        );
        append_finding_statements(
            &database,
            &mut statements,
            operation_id,
            &location,
            evidence,
            &evidence_json,
            &now,
        )?;
    }
    if !indexed.is_empty() {
        return Response::error("verify evidence omitted pinned locations", 409);
    }

    append_completion_statements(
        &database,
        &mut statements,
        operation_id,
        client,
        &completed,
        &report_sha256,
        counts,
        &now,
    )?;
    database.batch(statements).await?;

    let state = database
        .prepare(
            "SELECT operation.state FROM operations AS operation \
             JOIN verify_completions AS completion ON completion.operation_id = operation.id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             WHERE operation.id = ?1 AND operation.kind = 'verify' \
               AND operation.requested_by = ?2 AND operation.state = 'succeeded' \
               AND completion.report_sha256 = ?3 AND completion.state = 'committed' \
               AND lease.id = ?4 \
               AND lease.incarnation = ?5 AND lease.fencing_token = ?6 \
               AND lease.released_at IS NOT NULL",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&report_sha256),
            JsValue::from_str(&completed.lease_id),
            JsValue::from_str(&completed.incarnation),
            JsValue::from_str(&completed.fencing_token.to_string()),
        ])?
        .first::<String>(Some("state"))
        .await?;
    if state.as_deref() != Some("succeeded") {
        return Response::error("verify completion fence is stale or incomplete", 409);
    }

    completion_response(operation_id, &completed.manifest_sha256, counts)
}

fn valid_completion(completed: &CompleteRequest) -> bool {
    valid_string(&completed.lease_id, 256)
        && valid_hex(&completed.incarnation, 32)
        && completed.fencing_token > 0
        && valid_hex(&completed.manifest_sha256, 64)
        && !completed.evidence.is_empty()
        && completed.evidence.len() <= 10_000
        && completed.evidence.iter().all(valid_evidence)
}

fn valid_evidence(evidence: &LocationEvidence) -> bool {
    valid_hex(&evidence.extent_sha256, 64)
        && valid_string(&evidence.driver_id, 256)
        && valid_string(&evidence.storage_key, 4_096)
        && evidence.length > 0
        && evidence.offset <= i64::MAX.unsigned_abs()
        && evidence.length <= i64::MAX.unsigned_abs()
        && evidence.offset.checked_add(evidence.length).is_some()
        && matches!(
            evidence.condition.as_str(),
            "verified" | "missing" | "corrupt" | "unavailable"
        )
        && evidence
            .observed_sha256
            .as_ref()
            .is_none_or(|digest| valid_hex(digest, 64))
        && (!matches!(evidence.condition.as_str(), "missing" | "unavailable")
            || evidence.observed_sha256.is_none())
}

fn evidence_key(evidence: &LocationEvidence) -> String {
    serde_json::to_string(&(
        evidence.extent_sha256.as_str(),
        evidence.driver_id.as_str(),
        evidence.storage_key.as_str(),
        evidence.offset,
        evidence.length,
    ))
    .expect("serializing a verification evidence key cannot fail")
}

fn location_key(location: &VerificationLocationRow) -> Result<String> {
    serde_json::to_string(&(
        location.extent_sha256.as_str(),
        location.driver_id.as_str(),
        location.storage_key.as_str(),
        location.storage_offset,
        location.storage_length,
    ))
    .map_err(Into::into)
}

fn evidence_counts(evidence: &[LocationEvidence]) -> (u64, u64, u64, u64) {
    let mut counts = (0, 0, 0, 0);
    for item in evidence {
        match item.condition.as_str() {
            "verified" => counts.0 += 1,
            "missing" => counts.1 += 1,
            "corrupt" => counts.2 += 1,
            "unavailable" => counts.3 += 1,
            _ => unreachable!("completion validation rejects unknown conditions"),
        }
    }
    counts
}

async fn load_verification_locations(
    database: &worker::D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    completed: &CompleteRequest,
) -> Result<Vec<VerificationLocationRow>> {
    database
        .prepare(
            "SELECT location.id, extent.ciphertext_sha256 AS extent_sha256, \
                    location.driver_id, location.storage_key, \
                    location.storage_offset, location.storage_length \
             FROM verify_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN version_packs AS version_pack ON version_pack.version_id = intent.version_id \
             JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
             JOIN locations AS location ON location.extent_id = extent.id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'verify' \
               AND operation.state = 'running' AND operation.requested_by = ?2 \
               AND intent.manifest_sha256 = ?3 AND location.driver_id = intent.driver_id \
               AND location.state = 'available' AND lease.id = ?4 \
               AND lease.owner_client_id = ?2 AND lease.incarnation = ?5 \
               AND lease.fencing_token = ?6 AND lease.lease_kind = 'write' \
               AND lease.released_at IS NULL AND lease.expires_at > unixepoch() \
               AND lease.incarnation = control.incarnation AND control.mode = 'active' \
             ORDER BY location.id",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&completed.manifest_sha256),
            JsValue::from_str(&completed.lease_id),
            JsValue::from_str(&completed.incarnation),
            JsValue::from_str(&completed.fencing_token.to_string()),
        ])?
        .all()
        .await?
        .results::<VerificationLocationRow>()
}

#[allow(
    clippy::too_many_lines,
    reason = "each evidence condition has a distinct conservative metadata effect"
)]
fn append_finding_statements(
    database: &worker::D1Database,
    statements: &mut Vec<worker::D1PreparedStatement>,
    operation_id: &str,
    location: &VerificationLocationRow,
    evidence: &LocationEvidence,
    evidence_json: &str,
    now: &str,
) -> Result<()> {
    match evidence.condition.as_str() {
        "verified" => {
            statements.push(
                database
                    .prepare(
                        "UPDATE integrity_findings \
                         SET state = 'resolved', resolved_at = ?1, last_observed_at = ?1, \
                             revision = revision + 1 \
                         WHERE subject_kind = 'location' AND subject_id = ?2 \
                           AND condition IN ('missing', 'corrupt') AND state = 'open' \
                           AND EXISTS(SELECT 1 FROM integrity_observations \
                                      WHERE operation_id = ?3 AND location_id = ?2 \
                                        AND condition = 'verified')",
                    )
                    .bind(&[
                        JsValue::from_str(now),
                        JsValue::from_str(&location.id),
                        JsValue::from_str(operation_id),
                    ])?,
            );
        }
        "missing" | "corrupt" => {
            let finding_id = format!(
                "{operation_id}/{}/{condition}",
                location.id,
                condition = evidence.condition
            );
            statements.push(
                database
                    .prepare(
                        "INSERT INTO integrity_findings (\
                             id, namespace_id, subject_kind, subject_id, condition, state, \
                             evidence_json, first_observed_at, last_observed_at\
                         ) \
                         SELECT ?1, operation.namespace_id, 'location', ?2, ?3, 'open', \
                                ?4, ?5, ?5 \
                         FROM operations AS operation \
                         WHERE operation.id = ?6 \
                           AND EXISTS(SELECT 1 FROM integrity_observations \
                                      WHERE operation_id = ?6 AND location_id = ?2 \
                                        AND condition = ?3) \
                         ON CONFLICT(subject_kind, subject_id, condition, state) DO UPDATE SET \
                             evidence_json = excluded.evidence_json, \
                             last_observed_at = excluded.last_observed_at, \
                             revision = integrity_findings.revision + 1",
                    )
                    .bind(&[
                        JsValue::from_str(&finding_id),
                        JsValue::from_str(&location.id),
                        JsValue::from_str(&evidence.condition),
                        JsValue::from_str(evidence_json),
                        JsValue::from_str(now),
                        JsValue::from_str(operation_id),
                    ])?,
            );
            statements.push(
                database
                    .prepare(
                        "UPDATE locations SET state = ?1, revision = revision + 1, updated_at = ?2 \
                         WHERE id = ?3 AND state = 'available' \
                           AND EXISTS(SELECT 1 FROM integrity_observations \
                                      WHERE operation_id = ?4 AND location_id = ?3 \
                                        AND condition = ?1)",
                    )
                    .bind(&[
                        JsValue::from_str(&evidence.condition),
                        JsValue::from_str(now),
                        JsValue::from_str(&location.id),
                        JsValue::from_str(operation_id),
                    ])?,
            );
        }
        "unavailable" => {
            let finding_id = format!("{operation_id}/{}/driver_unavailable", location.driver_id);
            statements.push(
                database
                    .prepare(
                        "INSERT INTO integrity_findings (\
                             id, namespace_id, subject_kind, subject_id, condition, state, \
                             evidence_json, first_observed_at, last_observed_at\
                         ) \
                         SELECT ?1, operation.namespace_id, 'driver', ?2, \
                                'driver_unavailable', 'open', ?3, ?4, ?4 \
                         FROM operations AS operation \
                         WHERE operation.id = ?5 \
                           AND EXISTS(SELECT 1 FROM integrity_observations \
                                      WHERE operation_id = ?5 AND location_id = ?6 \
                                        AND condition = 'driver_unavailable') \
                         ON CONFLICT(subject_kind, subject_id, condition, state) DO UPDATE SET \
                             evidence_json = excluded.evidence_json, \
                             last_observed_at = excluded.last_observed_at, \
                             revision = integrity_findings.revision + 1",
                    )
                    .bind(&[
                        JsValue::from_str(&finding_id),
                        JsValue::from_str(&location.driver_id),
                        JsValue::from_str(evidence_json),
                        JsValue::from_str(now),
                        JsValue::from_str(operation_id),
                        JsValue::from_str(&location.id),
                    ])?,
            );
        }
        _ => unreachable!("completion validation rejects unknown conditions"),
    }

    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "all completion fence dimensions and state transitions are intentionally explicit"
)]
fn append_completion_statements(
    database: &worker::D1Database,
    statements: &mut Vec<worker::D1PreparedStatement>,
    operation_id: &str,
    client: &AuthenticatedClient,
    completed: &CompleteRequest,
    report_sha256: &str,
    counts: (u64, u64, u64, u64),
    now: &str,
) -> Result<()> {
    statements.push(
        database
            .prepare(
                "INSERT INTO verify_completions (\
                     operation_id, report_sha256, verified_count, missing_count, corrupt_count, \
                     unavailable_count, completed_at\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                JsValue::from_str(report_sha256),
                JsValue::from_str(&counts.0.to_string()),
                JsValue::from_str(&counts.1.to_string()),
                JsValue::from_str(&counts.2.to_string()),
                JsValue::from_str(&counts.3.to_string()),
                JsValue::from_str(now),
            ])?,
    );
    for (from, to, phase) in [
        ("running", "verifying", "verifying"),
        ("verifying", "committing", "committing"),
        ("committing", "succeeded", "completed"),
    ] {
        statements.push(
            database
                .prepare(
                    "UPDATE operations SET state = ?1, phase = ?2, revision = revision + 1, \
                         finished_at = CASE WHEN ?1 = 'succeeded' THEN ?3 ELSE finished_at END, \
                         updated_at = ?3 \
                     WHERE id = ?4 AND kind = 'verify' AND state = ?5 \
                       AND EXISTS(SELECT 1 FROM verify_completions \
                                  WHERE operation_id = ?4 AND report_sha256 = ?6)",
                )
                .bind(&[
                    JsValue::from_str(to),
                    JsValue::from_str(phase),
                    JsValue::from_str(now),
                    JsValue::from_str(operation_id),
                    JsValue::from_str(from),
                    JsValue::from_str(report_sha256),
                ])?,
        );
    }
    statements.push(
        database
            .prepare(
                "UPDATE operation_attempts SET state = 'succeeded', finished_at = ?1 \
                 WHERE component_id = ?2 || '/verify' AND attempt = ?3 AND state = 'running' \
                   AND lease_id = ?4 AND incarnation = ?5",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                JsValue::from_str(&completed.fencing_token.to_string()),
                JsValue::from_str(&completed.lease_id),
                JsValue::from_str(&completed.incarnation),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE operation_components \
                 SET state = 'succeeded', finished_at = ?1, revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 || '/verify' AND operation_id = ?2 \
                   AND lease_id = ?3 AND fencing_token = ?4 AND state = 'running' \
                   AND EXISTS(SELECT 1 FROM operations WHERE id = ?2 AND state = 'succeeded')",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                JsValue::from_str(&completed.lease_id),
                JsValue::from_str(&completed.fencing_token.to_string()),
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
                JsValue::from_str(&completed.lease_id),
                JsValue::from_str(operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&completed.incarnation),
                JsValue::from_str(&completed.fencing_token.to_string()),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE verify_completions \
                 SET state = 'committed', committed_at = ?1 \
                 WHERE operation_id = ?2 AND report_sha256 = ?3 AND state = 'staging'",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                JsValue::from_str(report_sha256),
            ])?,
    );

    Ok(())
}

fn completion_response(
    operation_id: &str,
    manifest_sha256: &str,
    counts: (u64, u64, u64, u64),
) -> Result<Response> {
    Response::from_json(&CompletedVerify {
        operation_id: operation_id.to_owned(),
        manifest_sha256: manifest_sha256.to_owned(),
        state: "succeeded".to_owned(),
        verified: counts.0,
        missing: counts.1,
        corrupt: counts.2,
        unavailable: counts.3,
    })
}

async fn find_operation(
    database: &worker::D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<VerifyOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, intent.version_id, \
                    intent.manifest_sha256, intent.recovery_revision, intent.driver_id, \
                    completion.verified_count AS completed_verified, \
                    completion.missing_count AS completed_missing, \
                    completion.corrupt_count AS completed_corrupt, \
                    completion.unavailable_count AS completed_unavailable, \
                    operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN verify_intents AS intent ON intent.operation_id = operation.id \
             LEFT JOIN verify_completions AS completion \
               ON completion.operation_id = operation.id AND completion.state = 'committed' \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'verify'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<VerifyOperation>(None)
        .await
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate verify ID: {error}")))?;

    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    Ok(encoded)
}

fn valid_hex(value: &str, characters: usize) -> bool {
    value.len() == characters
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{valid_hex, valid_string};

    #[test]
    fn validates_verify_operation_boundaries() {
        assert!(valid_hex("0123456789abcdef0123456789abcdef", 32));
        assert!(!valid_hex("0123456789ABCDEF0123456789ABCDEF", 32));
        assert!(valid_string("driver-1", 256));
        assert!(!valid_string(" driver-1", 256));
    }
}
