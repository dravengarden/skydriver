use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use worker::{Env, Request, Response, Result, wasm_bindgen::JsValue};

const DEFAULT_LIMIT: u16 = 50;
const MAXIMUM_LIMIT: u16 = 200;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingQuery {
    state: Option<String>,
    condition: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize, Serialize)]
struct FindingCursor {
    last_observed_at: u64,
    id: String,
}

#[derive(Deserialize)]
struct FindingRow {
    id: String,
    namespace_id: Option<String>,
    namespace_name: Option<String>,
    subject_kind: String,
    subject_id: String,
    condition: String,
    state: String,
    evidence_json: String,
    first_observed_at: u64,
    last_observed_at: u64,
    resolved_at: Option<u64>,
    revision: u64,
    manifest_sha256: Option<String>,
    root_version: Option<u32>,
    extent_sha256: Option<String>,
    driver_id: Option<String>,
    storage_key: Option<String>,
    location_state: Option<String>,
    last_verified_at: Option<u64>,
    available_repair_sources: u64,
}

#[derive(Serialize)]
struct IntegrityFinding {
    id: String,
    namespace_id: Option<String>,
    namespace_name: Option<String>,
    subject_kind: String,
    subject_id: String,
    condition: String,
    state: String,
    evidence: serde_json::Value,
    first_observed_at: u64,
    last_observed_at: u64,
    resolved_at: Option<u64>,
    revision: u64,
    manifest_sha256: Option<String>,
    root_version: Option<u32>,
    extent_sha256: Option<String>,
    driver_id: Option<String>,
    storage_key: Option<String>,
    location_state: Option<String>,
    last_verified_at: Option<u64>,
    available_repair_sources: u64,
    repairable: bool,
    required_action: &'static str,
}

#[derive(Serialize)]
struct FindingsResponse {
    observed_at: u64,
    next_cursor: Option<String>,
    findings: Vec<IntegrityFinding>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete read-only finding projection remains visible beside its SQL aliases"
)]
pub(crate) async fn list(request: &Request, env: &Env) -> Result<Response> {
    if crate::read_session(request, env)?.is_none() {
        return Response::error("authentication required", 401);
    }

    let Ok(query) = request.query::<FindingQuery>() else {
        return Response::error("invalid integrity findings query", 400);
    };
    let state = query.state.as_deref().unwrap_or("open");
    if !valid_state(state)
        || query
            .condition
            .as_deref()
            .is_some_and(|condition| !valid_condition(condition))
    {
        return Response::error("invalid integrity findings filter", 400);
    }
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAXIMUM_LIMIT {
        return Response::error("integrity findings limit is out of range", 400);
    }
    let Ok(cursor) = query.cursor.as_deref().map(decode_cursor).transpose() else {
        return Response::error("invalid integrity findings cursor", 400);
    };

    let database = env.d1("CARRACK_INDEX")?;
    let cursor_time = cursor.as_ref().map_or_else(JsValue::null, |value| {
        JsValue::from_str(&value.last_observed_at.to_string())
    });
    let cursor_id = cursor
        .as_ref()
        .map_or_else(JsValue::null, |value| JsValue::from_str(&value.id));
    let condition = query
        .condition
        .as_deref()
        .map_or_else(JsValue::null, JsValue::from_str);
    let requested_rows = u32::from(limit) + 1;
    let rows = database
        .prepare(
            "SELECT finding.id, finding.namespace_id, namespace.name AS namespace_name, \
                    finding.subject_kind, finding.subject_id, finding.condition, finding.state, \
                    finding.evidence_json, finding.first_observed_at, \
                    finding.last_observed_at, finding.resolved_at, finding.revision, \
                    CASE \
                      WHEN finding.subject_kind = 'location' THEN (\
                        SELECT version.manifest_sha256 FROM version_packs AS version_pack \
                        JOIN object_versions AS version ON version.id = version_pack.version_id \
                        WHERE version_pack.pack_id = subject_extent.pack_id \
                          AND version.state = 'published' \
                        ORDER BY version.published_at DESC LIMIT 1) \
                      WHEN finding.subject_kind = 'extent' THEN (\
                        SELECT version.manifest_sha256 FROM extents AS candidate \
                        JOIN packs AS pack ON pack.id = candidate.pack_id \
                        JOIN version_packs AS version_pack ON version_pack.pack_id = pack.id \
                        JOIN object_versions AS version ON version.id = version_pack.version_id \
                        WHERE candidate.ciphertext_sha256 = finding.subject_id \
                          AND pack.namespace_id IS finding.namespace_id \
                          AND version.state = 'published' \
                        ORDER BY version.published_at DESC LIMIT 1) \
                    END AS manifest_sha256, \
                    CASE \
                      WHEN finding.subject_kind = 'location' THEN subject_pack.root_key_version \
                      WHEN finding.subject_kind = 'extent' THEN (\
                        SELECT pack.root_key_version FROM extents AS candidate \
                        JOIN packs AS pack ON pack.id = candidate.pack_id \
                        WHERE candidate.ciphertext_sha256 = finding.subject_id \
                          AND pack.namespace_id IS finding.namespace_id LIMIT 1) \
                    END AS root_version, \
                    CASE WHEN finding.subject_kind = 'extent' THEN finding.subject_id \
                         ELSE subject_extent.ciphertext_sha256 END AS extent_sha256, \
                    subject_location.driver_id, subject_location.storage_key, \
                    subject_location.state AS location_state, \
                    subject_location.verified_at AS last_verified_at, \
                    CASE \
                      WHEN finding.subject_kind = 'location' THEN (\
                        SELECT COUNT(*) FROM locations AS source \
                        WHERE source.extent_id = subject_location.extent_id \
                          AND source.id != subject_location.id \
                          AND source.state = 'available') \
                      WHEN finding.subject_kind = 'extent' THEN (\
                        SELECT COUNT(*) FROM extents AS candidate \
                        JOIN packs AS pack ON pack.id = candidate.pack_id \
                        JOIN locations AS source ON source.extent_id = candidate.id \
                        WHERE candidate.ciphertext_sha256 = finding.subject_id \
                          AND pack.namespace_id IS finding.namespace_id \
                          AND source.state = 'available') \
                      ELSE 0 \
                    END AS available_repair_sources \
             FROM integrity_findings AS finding \
             LEFT JOIN namespaces AS namespace ON namespace.id = finding.namespace_id \
             LEFT JOIN locations AS subject_location \
               ON finding.subject_kind = 'location' \
              AND subject_location.id = finding.subject_id \
             LEFT JOIN extents AS subject_extent ON subject_extent.id = subject_location.extent_id \
             LEFT JOIN packs AS subject_pack ON subject_pack.id = subject_extent.pack_id \
             WHERE finding.state = ?1 AND (?2 IS NULL OR finding.condition = ?2) \
               AND (?3 IS NULL OR finding.last_observed_at < ?3 \
                    OR (finding.last_observed_at = ?3 AND finding.id < ?4)) \
             ORDER BY finding.last_observed_at DESC, finding.id DESC LIMIT ?5",
        )
        .bind(&[
            JsValue::from_str(state),
            condition,
            cursor_time,
            cursor_id,
            JsValue::from_str(&requested_rows.to_string()),
        ])?
        .all()
        .await?
        .results::<FindingRow>()?;

    findings_response(rows, usize::from(limit))
}

fn findings_response(mut rows: Vec<FindingRow>, limit: usize) -> Result<Response> {
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = if has_more {
        rows.last().map(|row| {
            encode_cursor(&FindingCursor {
                last_observed_at: row.last_observed_at,
                id: row.id.clone(),
            })
        })
    } else {
        None
    };
    let findings = rows
        .into_iter()
        .map(IntegrityFinding::try_from)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Response::from_json(&FindingsResponse {
        observed_at: crate::current_unix_seconds(),
        next_cursor,
        findings,
    })
}

impl TryFrom<FindingRow> for IntegrityFinding {
    type Error = worker::Error;

    fn try_from(row: FindingRow) -> std::result::Result<Self, Self::Error> {
        let repairable = row.condition == "missing"
            && row.location_state.as_deref() == Some("missing")
            && row.available_repair_sources > 0;
        let required_action = required_action(&row.condition);
        let evidence = serde_json::from_str(&row.evidence_json)?;

        Ok(Self {
            id: row.id,
            namespace_id: row.namespace_id,
            namespace_name: row.namespace_name,
            subject_kind: row.subject_kind,
            subject_id: row.subject_id,
            condition: row.condition,
            state: row.state,
            evidence,
            first_observed_at: row.first_observed_at,
            last_observed_at: row.last_observed_at,
            resolved_at: row.resolved_at,
            revision: row.revision,
            manifest_sha256: row.manifest_sha256,
            root_version: row.root_version,
            extent_sha256: row.extent_sha256,
            driver_id: row.driver_id,
            storage_key: row.storage_key,
            location_state: row.location_state,
            last_verified_at: row.last_verified_at,
            available_repair_sources: row.available_repair_sources,
            repairable,
            required_action,
        })
    }
}

fn required_action(condition: &str) -> &'static str {
    match condition {
        "driver_unavailable" => "Restore provider access, then repeat verification.",
        "unindexed" => "Validate recovery ownership, then reconcile or adopt the location.",
        "degraded" => "Copy or repair from an independently available replica.",
        "missing" => "Repair from a separately verified replica.",
        "corrupt" => "Quarantine the object and relocate it through Copy.",
        "key_unavailable" => "Restore root key material; do not delete provider data.",
        "unsupported_suite" => "Use a compatible client; do not delete provider data.",
        "orphan" => "Inventory and quarantine until ownership is established.",
        "quarantined" => "Review evidence before adoption, relocation, or cleanup.",
        "unrecoverable" => "Require explicit loss acknowledgement before cleanup.",
        _ => "Review the integrity evidence before taking action.",
    }
}

fn valid_state(state: &str) -> bool {
    matches!(state, "open" | "acknowledged" | "tombstoned" | "resolved")
}

fn valid_condition(condition: &str) -> bool {
    matches!(
        condition,
        "driver_unavailable"
            | "unindexed"
            | "degraded"
            | "missing"
            | "corrupt"
            | "key_unavailable"
            | "unsupported_suite"
            | "orphan"
            | "quarantined"
            | "unrecoverable"
    )
}

fn encode_cursor(cursor: &FindingCursor) -> String {
    let encoded = serde_json::to_vec(cursor).expect("serializing a finding cursor cannot fail");

    URL_SAFE_NO_PAD.encode(encoded)
}

fn decode_cursor(encoded: &str) -> std::result::Result<FindingCursor, ()> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?;
    let cursor = serde_json::from_slice::<FindingCursor>(&decoded).map_err(|_| ())?;
    if cursor.id.is_empty() || cursor.id.len() > 4_096 || cursor.last_observed_at > i64::MAX as u64
    {
        return Err(());
    }

    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::{FindingCursor, decode_cursor, encode_cursor, required_action};

    #[test]
    fn round_trips_findings_cursor() {
        let cursor = FindingCursor {
            last_observed_at: 42,
            id: "operation/location/missing".to_owned(),
        };
        let encoded = encode_cursor(&cursor);
        let decoded = decode_cursor(&encoded).expect("cursor should decode");

        assert_eq!(decoded.last_observed_at, cursor.last_observed_at);
        assert_eq!(decoded.id, cursor.id);
        assert!(decode_cursor("not-base64!").is_err());
    }

    #[test]
    fn preserves_conservative_manual_actions() {
        assert!(required_action("missing").contains("Repair"));
        assert!(required_action("corrupt").contains("relocate"));
        assert!(required_action("unrecoverable").contains("acknowledgement"));
    }
}
