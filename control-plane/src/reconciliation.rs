use std::{collections::HashMap, fmt::Write as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, copying};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    manifest_sha256: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Deserialize, Serialize)]
struct ReconcileOperation {
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
    minimum_available_replicas: u64,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
struct SnapshotHead {
    manifest_sha256: String,
    recovery_sha256: Option<String>,
    recovery_revision: u64,
    r2_storage_key: String,
    r2_version: Option<String>,
    recovery_bytes: u64,
    minimum_available_replicas: u64,
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

#[derive(Serialize)]
struct ReconcileSnapshot {
    recovery: serde_json::Value,
    recovery_revision: u64,
    minimum_available_replicas: u64,
    locations: Vec<IndexedLocation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReconcileEvidence {
    condition: String,
    subject_id: String,
    extent_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    driver_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    storage_key: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    offset: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    length: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    available: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    required: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    manifest_sha256: String,
    evidence: Vec<ReconcileEvidence>,
}

#[derive(Deserialize)]
struct CompletionRow {
    report_sha256: String,
}

#[derive(Serialize)]
struct CompletedReconcile {
    operation_id: String,
    manifest_sha256: String,
    state: String,
    unindexed: u64,
    orphan: u64,
    degraded: u64,
}

struct ResolvedFinding {
    condition: &'static str,
    subject_id: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "operation, pinned intent, and component creation remain one visible protocol"
)]
pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !valid_hex(&requested.namespace_id, 32)
        || !valid_hex(&requested.manifest_sha256, 64)
        || !valid_string(&requested.idempotency_key, 256)
    {
        return Response::error("invalid reconcile operation", 400);
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
             SELECT ?1, ?2, 'reconcile', 'planned', 'planned', ?3, ?4, \
                    control.incarnation, \
                    (SELECT COUNT(*) FROM version_packs AS version_pack \
                     JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
                     JOIN locations AS location ON location.extent_id = extent.id \
                     WHERE version_pack.version_id = version.id), ?5, ?5 \
             FROM control_plane_state AS control \
             JOIN object_versions AS version ON version.manifest_sha256 = ?6 \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN namespaces AS namespace ON namespace.id = object.namespace_id \
             WHERE control.singleton = 1 AND control.mode = 'active' \
               AND object.namespace_id = ?2 AND version.state = 'published' \
               AND COALESCE(json_extract(namespace.replica_policy_json, \
                                         '$.minimum_available_replicas'), 1) BETWEEN 1 AND 64 \
               AND EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                          WHERE recovery.version_id = version.id \
                            AND recovery.manifest_sha256 = version.manifest_sha256 \
                            AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL) \
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
            JsValue::from_str(&now),
            JsValue::from_str(&requested.manifest_sha256),
        ])?;
    let insert_intent = database
        .prepare(
            "INSERT OR IGNORE INTO reconcile_intents (\
                 operation_id, version_id, manifest_sha256, recovery_revision, \
                 minimum_available_replicas, created_at\
             ) \
             SELECT operation.id, version.id, version.manifest_sha256, recovery.revision, \
                    COALESCE(json_extract(namespace.replica_policy_json, \
                                          '$.minimum_available_replicas'), 1), ?1 \
             FROM operations AS operation \
             JOIN object_versions AS version ON version.manifest_sha256 = ?2 \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN namespaces AS namespace ON namespace.id = object.namespace_id \
             JOIN recovery_manifests AS recovery ON recovery.version_id = version.id \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?5 AND operation.kind = 'reconcile'",
        )
        .bind(&[
            JsValue::from_str(&now),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?;
    let insert_component = database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, state, useful_bytes_total, \
                 created_at, updated_at\
             ) \
             SELECT operation.id || '/reconcile', operation.id, ?1, 'reconcile', 'pending', \
                    operation.useful_bytes_total, ?2, ?2 \
             FROM operations AS operation \
             JOIN reconcile_intents AS intent ON intent.operation_id = operation.id \
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
        return Response::error("reconcile rejected or idempotency identity conflicts", 409);
    };
    if operation.manifest_sha256 != requested.manifest_sha256 {
        return Response::error("idempotency key pins another reconcile target", 409);
    }

    Response::from_json(&operation)
}

pub(crate) async fn fetch_snapshot(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !valid_hex(operation_id, 32) {
        return Response::error("invalid reconcile operation ID", 400);
    }
    let requested = request.json::<SnapshotRequest>().await?;
    if !valid_string(&requested.lease_id, 256)
        || !valid_hex(&requested.incarnation, 32)
        || requested.fencing_token == 0
    {
        return Response::error("invalid reconcile snapshot fence", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let head = load_snapshot_head(&database, operation_id, client, &requested).await?;
    let Some(head) = head else {
        return Response::error("reconcile snapshot fence is stale or unavailable", 409);
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
        return Response::error("reconcile recovery identity changed", 503);
    }
    let recovery = serde_json::from_slice::<serde_json::Value>(&loaded.encoded)?;
    let locations = load_indexed_locations(&database, operation_id).await?;

    Response::from_json(&ReconcileSnapshot {
        recovery,
        recovery_revision: head.recovery_revision,
        minimum_available_replicas: head.minimum_available_replicas,
        locations,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "server recomputation and fenced metadata completion remain one auditable protocol"
)]
pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !valid_hex(operation_id, 32) {
        return Response::error("invalid reconcile operation ID", 400);
    }
    let mut completed = request.json::<CompleteRequest>().await?;
    if !valid_string(&completed.lease_id, 256)
        || !valid_hex(&completed.incarnation, 32)
        || completed.fencing_token == 0
        || !valid_hex(&completed.manifest_sha256, 64)
        || completed.evidence.len() > 50_000
    {
        return Response::error("invalid reconcile completion", 400);
    }
    sort_evidence(&mut completed.evidence);
    let database = env.d1("CARRACK_INDEX")?;
    let head = load_snapshot_head(
        &database,
        operation_id,
        client,
        &SnapshotRequest {
            lease_id: completed.lease_id.clone(),
            incarnation: completed.incarnation.clone(),
            fencing_token: completed.fencing_token,
        },
    )
    .await?;
    let Some(head) = head else {
        if let Some(response) =
            replay_completion(&database, operation_id, client, &completed).await?
        {
            return Ok(response);
        }

        return Response::error("reconcile completion fence is stale or unavailable", 409);
    };
    let loaded = copying::load_recovery(
        env,
        &head.r2_storage_key,
        head.r2_version.as_deref(),
        head.recovery_bytes,
    )
    .await?;
    if loaded.validated.manifest_sha256 != completed.manifest_sha256
        || loaded.validated.manifest_sha256 != head.manifest_sha256
        || head
            .recovery_sha256
            .as_ref()
            .is_some_and(|digest| digest != &loaded.recovery_sha256)
    {
        return Response::error("reconcile completion recovery changed", 409);
    }
    let locations = load_indexed_locations(&database, operation_id).await?;
    let (expected, resolutions) = calculate_evidence(
        &loaded.validated,
        &locations,
        head.minimum_available_replicas,
    )?;
    if completed.evidence != expected {
        return Response::error("reconcile evidence differs from pinned snapshot", 409);
    }

    let report_sha256 = report_sha256(&completed.manifest_sha256, &expected)?;
    let counts = evidence_counts(&expected);
    let now = current_unix_seconds().to_string();
    let mut statements = Vec::with_capacity(expected.len() * 2 + 8);
    for evidence in &expected {
        let evidence_json = serde_json::to_string(evidence)?;
        statements.push(
            database
                .prepare(
                    "INSERT INTO reconcile_observations (\
                         operation_id, condition, subject_id, evidence_json, lease_id, \
                         incarnation, fencing_token, observed_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )
                .bind(&[
                    JsValue::from_str(operation_id),
                    JsValue::from_str(&evidence.condition),
                    JsValue::from_str(&evidence.subject_id),
                    JsValue::from_str(&evidence_json),
                    JsValue::from_str(&completed.lease_id),
                    JsValue::from_str(&completed.incarnation),
                    JsValue::from_str(&completed.fencing_token.to_string()),
                    JsValue::from_str(&now),
                ])?,
        );
        statements.push(finding_statement(
            &database,
            operation_id,
            evidence,
            &evidence_json,
            &now,
        )?);
    }
    for resolution in resolutions {
        statements.push(resolution_statement(
            &database,
            operation_id,
            client,
            &completed,
            &resolution,
            &now,
        )?);
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

    let committed = database
        .prepare(
            "SELECT completion.report_sha256 FROM reconcile_completions AS completion \
             JOIN operations AS operation ON operation.id = completion.operation_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             WHERE operation.id = ?1 AND operation.state = 'succeeded' \
               AND operation.requested_by = ?2 AND completion.state = 'committed' \
               AND completion.report_sha256 = ?3 AND lease.id = ?4 \
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
        .first::<CompletionRow>(None)
        .await?;
    if committed.is_none() {
        return Response::error("reconcile completion fence is stale or incomplete", 409);
    }

    completion_response(operation_id, &completed.manifest_sha256, counts)
}

async fn replay_completion(
    database: &worker::D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    completed: &CompleteRequest,
) -> Result<Option<Response>> {
    let existing = database
        .prepare(
            "SELECT completion.report_sha256 FROM reconcile_completions AS completion \
             JOIN operations AS operation ON operation.id = completion.operation_id \
             JOIN reconcile_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.id = ?1 AND operation.kind = 'reconcile' \
               AND operation.state = 'succeeded' AND operation.requested_by = ?2 \
               AND intent.manifest_sha256 = ?3 AND completion.state = 'committed'",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&completed.manifest_sha256),
        ])?
        .first::<CompletionRow>(None)
        .await?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    let requested_hash = report_sha256(&completed.manifest_sha256, &completed.evidence)?;
    if requested_hash != existing.report_sha256 {
        return Ok(Some(Response::error(
            "reconcile completion replay changed evidence",
            409,
        )?));
    }

    Ok(Some(completion_response(
        operation_id,
        &completed.manifest_sha256,
        evidence_counts(&completed.evidence),
    )?))
}

#[allow(
    clippy::too_many_lines,
    reason = "all three discrepancy and exact resolution rules remain adjacent"
)]
fn calculate_evidence(
    recovery: &crate::manifests::ValidatedRecovery,
    indexed: &[IndexedLocation],
    minimum: u64,
) -> Result<(Vec<ReconcileEvidence>, Vec<ResolvedFinding>)> {
    let mut recovery_locations = HashMap::new();
    for location in &recovery.recovery.locations {
        recovery_locations.insert(
            location_key(
                &location.extent_sha256,
                &location.driver_id,
                &location.storage_key,
                location.provider_version.as_deref().unwrap_or_default(),
                location.offset,
                location.length,
            )?,
            location,
        );
    }
    let mut indexed_locations = HashMap::new();
    for location in indexed {
        indexed_locations.insert(
            location_key(
                &location.extent_sha256,
                &location.driver_id,
                &location.storage_key,
                location.provider_version.as_deref().unwrap_or_default(),
                location.offset,
                location.length,
            )?,
            location,
        );
    }

    let mut evidence = Vec::new();
    let mut resolutions = Vec::new();
    let mut available_by_extent = HashMap::<&str, u64>::new();
    for (key, location) in &recovery_locations {
        let Some(indexed_location) = indexed_locations.get(key) else {
            evidence.push(ReconcileEvidence {
                condition: "unindexed".to_owned(),
                subject_id: key.clone(),
                extent_sha256: location.extent_sha256.clone(),
                driver_id: location.driver_id.clone(),
                storage_key: location.storage_key.clone(),
                offset: location.offset,
                length: location.length,
                available: 0,
                required: 0,
            });
            continue;
        };
        resolutions.push(ResolvedFinding {
            condition: "unindexed",
            subject_id: key.clone(),
        });
        if indexed_location.state == "available" {
            *available_by_extent
                .entry(&location.extent_sha256)
                .or_default() += 1;
        }
    }
    for (key, location) in &indexed_locations {
        if recovery_locations.contains_key(key) || location.state != "available" {
            resolutions.push(ResolvedFinding {
                condition: "orphan",
                subject_id: location.id.clone(),
            });
            continue;
        }
        evidence.push(ReconcileEvidence {
            condition: "orphan".to_owned(),
            subject_id: location.id.clone(),
            extent_sha256: location.extent_sha256.clone(),
            driver_id: location.driver_id.clone(),
            storage_key: location.storage_key.clone(),
            offset: location.offset,
            length: location.length,
            available: 0,
            required: 0,
        });
    }
    for pack in &recovery.recovery.manifest.packs {
        for extent in &pack.extents {
            let available = available_by_extent
                .get(extent.ciphertext_sha256.as_str())
                .copied()
                .unwrap_or_default();
            if available < minimum {
                evidence.push(ReconcileEvidence {
                    condition: "degraded".to_owned(),
                    subject_id: extent.ciphertext_sha256.clone(),
                    extent_sha256: extent.ciphertext_sha256.clone(),
                    driver_id: String::new(),
                    storage_key: String::new(),
                    offset: 0,
                    length: 0,
                    available,
                    required: minimum,
                });
            } else {
                resolutions.push(ResolvedFinding {
                    condition: "degraded",
                    subject_id: extent.ciphertext_sha256.clone(),
                });
            }
        }
    }
    sort_evidence(&mut evidence);

    Ok((evidence, resolutions))
}

fn sort_evidence(evidence: &mut [ReconcileEvidence]) {
    evidence.sort_by(|left, right| {
        left.condition
            .cmp(&right.condition)
            .then_with(|| left.subject_id.cmp(&right.subject_id))
    });
}

fn location_key(
    extent_sha256: &str,
    driver_id: &str,
    storage_key: &str,
    provider_version: &str,
    offset: u64,
    length: u64,
) -> Result<String> {
    Ok(serde_json::to_string(&[
        serde_json::Value::String(extent_sha256.to_owned()),
        serde_json::Value::String(driver_id.to_owned()),
        serde_json::Value::String(storage_key.to_owned()),
        serde_json::Value::String(provider_version.to_owned()),
        serde_json::Value::from(offset),
        serde_json::Value::from(length),
    ])?)
}

fn report_sha256(manifest_sha256: &str, evidence: &[ReconcileEvidence]) -> Result<String> {
    let encoded = serde_json::to_vec(&(manifest_sha256, evidence))?;
    Ok(lowercase_hex(&Sha256::digest(encoded)))
}

fn evidence_counts(evidence: &[ReconcileEvidence]) -> (u64, u64, u64) {
    let mut counts = (0, 0, 0);
    for item in evidence {
        match item.condition.as_str() {
            "unindexed" => counts.0 += 1,
            "orphan" => counts.1 += 1,
            "degraded" => counts.2 += 1,
            _ => unreachable!("server-generated reconciliation condition"),
        }
    }
    counts
}

fn finding_statement(
    database: &worker::D1Database,
    operation_id: &str,
    evidence: &ReconcileEvidence,
    evidence_json: &str,
    now: &str,
) -> Result<worker::D1PreparedStatement> {
    let subject_kind = if evidence.condition == "degraded" {
        "extent"
    } else {
        "location"
    };
    let finding_id = format!(
        "{operation_id}/{}/{condition}",
        evidence.subject_id,
        condition = evidence.condition
    );
    database
        .prepare(
            "INSERT INTO integrity_findings (\
                 id, namespace_id, subject_kind, subject_id, condition, state, evidence_json, \
                 first_observed_at, last_observed_at\
             ) \
             SELECT ?1, operation.namespace_id, ?2, ?3, ?4, 'open', ?5, ?6, ?6 \
             FROM operations AS operation \
             WHERE operation.id = ?7 \
               AND EXISTS(SELECT 1 FROM reconcile_observations \
                          WHERE operation_id = ?7 AND condition = ?4 AND subject_id = ?3) \
             ON CONFLICT(subject_kind, subject_id, condition, state) DO UPDATE SET \
                 evidence_json = excluded.evidence_json, \
                 last_observed_at = excluded.last_observed_at, \
                 revision = integrity_findings.revision + 1",
        )
        .bind(&[
            JsValue::from_str(&finding_id),
            JsValue::from_str(subject_kind),
            JsValue::from_str(&evidence.subject_id),
            JsValue::from_str(&evidence.condition),
            JsValue::from_str(evidence_json),
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
        ])
}

fn resolution_statement(
    database: &worker::D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    completed: &CompleteRequest,
    resolution: &ResolvedFinding,
    now: &str,
) -> Result<worker::D1PreparedStatement> {
    database
        .prepare(
            "UPDATE integrity_findings \
             SET state = 'resolved', resolved_at = ?1, last_observed_at = ?1, \
                 revision = revision + 1 \
             WHERE condition = ?2 AND subject_id = ?3 AND state = 'open' \
               AND EXISTS(SELECT 1 FROM operations AS operation \
                          JOIN leases AS lease ON lease.operation_id = operation.id \
                          JOIN control_plane_state AS control ON control.singleton = 1 \
                          WHERE operation.id = ?4 AND operation.kind = 'reconcile' \
                            AND operation.state = 'running' AND operation.requested_by = ?5 \
                            AND lease.id = ?6 AND lease.owner_client_id = ?5 \
                            AND lease.incarnation = ?7 AND lease.fencing_token = ?8 \
                            AND lease.lease_kind = 'write' AND lease.released_at IS NULL \
                            AND lease.expires_at > ?1 AND lease.incarnation = control.incarnation \
                            AND control.mode = 'active')",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(resolution.condition),
            JsValue::from_str(&resolution.subject_id),
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&completed.lease_id),
            JsValue::from_str(&completed.incarnation),
            JsValue::from_str(&completed.fencing_token.to_string()),
        ])
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "all completion fence dimensions and state transitions remain explicit"
)]
fn append_completion_statements(
    database: &worker::D1Database,
    statements: &mut Vec<worker::D1PreparedStatement>,
    operation_id: &str,
    client: &AuthenticatedClient,
    completed: &CompleteRequest,
    report_sha256: &str,
    counts: (u64, u64, u64),
    now: &str,
) -> Result<()> {
    statements.push(
        database
            .prepare(
                "INSERT INTO reconcile_completions (\
                     operation_id, report_sha256, unindexed_count, orphan_count, \
                     degraded_count, completed_at\
                 ) \
                 SELECT operation.id, ?1, ?2, ?3, ?4, ?5 \
                 FROM operations AS operation \
                 JOIN reconcile_intents AS intent ON intent.operation_id = operation.id \
                 JOIN leases AS lease ON lease.operation_id = operation.id \
                 JOIN control_plane_state AS control ON control.singleton = 1 \
                 WHERE operation.id = ?6 AND operation.kind = 'reconcile' \
                   AND operation.state = 'running' AND operation.requested_by = ?7 \
                   AND intent.manifest_sha256 = ?8 AND lease.id = ?9 \
                   AND lease.owner_client_id = ?7 AND lease.incarnation = ?10 \
                   AND lease.fencing_token = ?11 AND lease.lease_kind = 'write' \
                   AND lease.released_at IS NULL AND lease.expires_at > ?5 \
                   AND lease.incarnation = control.incarnation AND control.mode = 'active'",
            )
            .bind(&[
                JsValue::from_str(report_sha256),
                JsValue::from_str(&counts.0.to_string()),
                JsValue::from_str(&counts.1.to_string()),
                JsValue::from_str(&counts.2.to_string()),
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&completed.manifest_sha256),
                JsValue::from_str(&completed.lease_id),
                JsValue::from_str(&completed.incarnation),
                JsValue::from_str(&completed.fencing_token.to_string()),
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
                     WHERE id = ?4 AND kind = 'reconcile' AND state = ?5 \
                       AND EXISTS(SELECT 1 FROM reconcile_completions \
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
                 WHERE component_id = ?2 || '/reconcile' AND attempt = ?3 \
                   AND state = 'running' AND lease_id = ?4 AND incarnation = ?5",
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
                 WHERE id = ?2 || '/reconcile' AND operation_id = ?2 \
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
                "UPDATE reconcile_completions SET state = 'committed', committed_at = ?1 \
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
    counts: (u64, u64, u64),
) -> Result<Response> {
    Response::from_json(&CompletedReconcile {
        operation_id: operation_id.to_owned(),
        manifest_sha256: manifest_sha256.to_owned(),
        state: "succeeded".to_owned(),
        unindexed: counts.0,
        orphan: counts.1,
        degraded: counts.2,
    })
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if requires a reference predicate"
)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

async fn load_snapshot_head(
    database: &worker::D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &SnapshotRequest,
) -> Result<Option<SnapshotHead>> {
    database
        .prepare(
            "SELECT intent.manifest_sha256, recovery.recovery_sha256, \
                    intent.recovery_revision, recovery.r2_storage_key, recovery.r2_version, \
                    recovery.ciphertext_bytes AS recovery_bytes, \
                    intent.minimum_available_replicas \
             FROM reconcile_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN recovery_manifests AS recovery ON recovery.version_id = intent.version_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'reconcile' \
               AND operation.state = 'running' AND operation.requested_by = ?2 \
               AND recovery.manifest_sha256 = intent.manifest_sha256 \
               AND recovery.revision = intent.recovery_revision \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND lease.id = ?3 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.lease_kind = 'write' AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND lease.incarnation = control.incarnation \
               AND control.mode = 'active'",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            JsValue::from_str(&requested.fencing_token.to_string()),
        ])?
        .first::<SnapshotHead>(None)
        .await
}

async fn load_indexed_locations(
    database: &worker::D1Database,
    operation_id: &str,
) -> Result<Vec<IndexedLocation>> {
    database
        .prepare(
            "SELECT location.id, extent.ciphertext_sha256 AS extent_sha256, \
                    location.driver_id, location.storage_key, location.provider_version, \
                    location.storage_offset AS offset, location.storage_length AS length, \
                    location.state \
             FROM reconcile_intents AS intent \
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

async fn find_operation(
    database: &worker::D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<ReconcileOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, intent.version_id, \
                    intent.manifest_sha256, intent.recovery_revision, \
                    intent.minimum_available_replicas, operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN reconcile_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'reconcile'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<ReconcileOperation>(None)
        .await
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate reconcile ID: {error}")))?;
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
