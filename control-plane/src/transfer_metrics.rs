use serde::{Deserialize, Serialize};
use worker::{Context, D1Database, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::operator_sessions;

const LARGE_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
const SAMPLE_MODULUS: u64 = 10;
const MAXIMUM_DURATION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAXIMUM_RETRIES: u64 = 1_000_000;
const RETENTION_DAYS: u64 = 400;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferTelemetry {
    pub(crate) schema: String,
    pub(crate) provider_ms: u64,
    pub(crate) total_ms: u64,
    pub(crate) retries: u64,
}

pub(crate) struct TransferIdentity<'a> {
    pub(crate) operation_id: &'a str,
    pub(crate) direction: &'static str,
    pub(crate) driver_id: &'a str,
    pub(crate) token_id: &'a str,
    pub(crate) directory_id: &'a str,
    pub(crate) encoded_bytes: u64,
}

pub(crate) struct OwnedTransferIdentity {
    pub(crate) operation_id: String,
    pub(crate) direction: &'static str,
    pub(crate) driver_id: String,
    pub(crate) token_id: String,
    pub(crate) directory_id: String,
    pub(crate) encoded_bytes: u64,
}

pub(crate) fn schedule(
    context: &Context,
    env: &Env,
    identity: OwnedTransferIdentity,
    telemetry: Option<TransferTelemetry>,
    now: u64,
) {
    if telemetry.as_ref().is_none_or(|value| !valid(value))
        || sample_weight(&identity.operation_id, identity.encoded_bytes) == 0
    {
        return;
    }
    let env = env.clone();
    context.wait_until(async move {
        let result = async {
            let database = env.d1("CARRACK_INDEX")?;
            record(
                &database,
                &TransferIdentity {
                    operation_id: &identity.operation_id,
                    direction: identity.direction,
                    driver_id: &identity.driver_id,
                    token_id: &identity.token_id,
                    directory_id: &identity.directory_id,
                    encoded_bytes: identity.encoded_bytes,
                },
                telemetry.as_ref(),
                now,
            )
            .await
        }
        .await;
        if let Err(error) = result {
            worker::console_error!("Carrack transfer telemetry was dropped: {error:?}");
        }
    });
}

#[derive(Deserialize, Serialize)]
struct MetricRow {
    day: u64,
    scope_kind: String,
    scope_id: String,
    direction: String,
    weighted_transfers: u64,
    weighted_bytes: u64,
    weighted_provider_ms: u64,
    weighted_total_ms: u64,
    weighted_retries: u64,
    speed_b0: u64,
    speed_b1: u64,
    speed_b2: u64,
    speed_b3: u64,
    speed_b4: u64,
    speed_b5: u64,
    speed_b6: u64,
    speed_b7: u64,
    speed_b8: u64,
    speed_b9: u64,
    speed_b10: u64,
    speed_b11: u64,
    updated_at: u64,
}

#[derive(Serialize)]
struct MetricsResponse {
    schema: &'static str,
    observed_at: u64,
    scope_kind: String,
    scope_id: String,
    retention_days: u64,
    window_days: u64,
    rows: Vec<MetricRow>,
}

pub(crate) async fn record(
    database: &D1Database,
    identity: &TransferIdentity<'_>,
    telemetry: Option<&TransferTelemetry>,
    now: u64,
) -> Result<()> {
    let Some(telemetry) = telemetry.filter(|value| valid(value)) else {
        return Ok(());
    };
    let weight = sample_weight(identity.operation_id, identity.encoded_bytes);
    if weight == 0 {
        return Ok(());
    }
    if !matches!(identity.direction, "upload" | "download") {
        return Ok(());
    }

    let Some(weighted_bytes) = identity.encoded_bytes.checked_mul(weight) else {
        return Ok(());
    };
    let Some(weighted_provider_ms) = telemetry.provider_ms.checked_mul(weight) else {
        return Ok(());
    };
    let Some(weighted_total_ms) = telemetry.total_ms.checked_mul(weight) else {
        return Ok(());
    };
    let Some(weighted_retries) = telemetry.retries.checked_mul(weight) else {
        return Ok(());
    };
    if [
        weight,
        weighted_bytes,
        weighted_provider_ms,
        weighted_total_ms,
        weighted_retries,
    ]
    .into_iter()
    .any(|value| i64::try_from(value).is_err())
    {
        return Ok(());
    }

    let inserted = database
        .prepare(
            "INSERT INTO vfs_transfer_metric_receipts (operation_id, recorded_at)
             VALUES (?1, ?2) ON CONFLICT(operation_id) DO NOTHING",
        )
        .bind(&[
            JsValue::from_str(identity.operation_id),
            number_binding(now),
        ])?
        .run()
        .await?
        .meta()?
        .and_then(|meta| meta.changes)
        .unwrap_or_default();
    if inserted != 1 {
        return Ok(());
    }

    let day = now - now % 86_400;
    let bucket = speed_bucket(identity.encoded_bytes, telemetry.provider_ms);
    let scopes = [
        ("global", "all"),
        ("driver", identity.driver_id),
        ("token", identity.token_id),
        ("directory", identity.directory_id),
    ];
    let mut statements = Vec::with_capacity(scopes.len());
    for (scope_kind, scope_id) in scopes {
        let bucket_column = format!("speed_b{bucket}");
        let sql = format!(
            "INSERT INTO vfs_transfer_daily_metrics (
                 day, scope_kind, scope_id, direction, weighted_transfers,
                 weighted_bytes, weighted_provider_ms, weighted_total_ms,
                 weighted_retries, {bucket_column}, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?5, ?10)
             ON CONFLICT(day, scope_kind, scope_id, direction) DO UPDATE SET
                 weighted_transfers = weighted_transfers + excluded.weighted_transfers,
                 weighted_bytes = weighted_bytes + excluded.weighted_bytes,
                 weighted_provider_ms = weighted_provider_ms + excluded.weighted_provider_ms,
                 weighted_total_ms = weighted_total_ms + excluded.weighted_total_ms,
                 weighted_retries = weighted_retries + excluded.weighted_retries,
                 {bucket_column} = {bucket_column} + excluded.{bucket_column},
                 updated_at = excluded.updated_at"
        );
        statements.push(database.prepare(&sql).bind(&[
            number_binding(day),
            JsValue::from_str(scope_kind),
            JsValue::from_str(scope_id),
            JsValue::from_str(identity.direction),
            number_binding(weight),
            number_binding(weighted_bytes),
            number_binding(weighted_provider_ms),
            number_binding(weighted_total_ms),
            number_binding(weighted_retries),
            number_binding(now),
        ])?);
    }
    database.batch(statements).await?;
    Ok(())
}

pub(crate) async fn management(
    request: &Request,
    env: &Env,
    scope_kind: Option<&str>,
    scope_id: Option<&str>,
) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }
    let Some(scope_kind) =
        scope_kind.filter(|value| matches!(*value, "global" | "driver" | "token" | "directory"))
    else {
        return Response::error("invalid metrics scope", 400);
    };
    let Some(scope_id) = scope_id.filter(|value| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && (scope_kind != "global" || *value == "all")
    }) else {
        return Response::error("invalid metrics scope ID", 400);
    };
    let url = request.url()?;
    let mut window_days = None;
    for (key, value) in url.query_pairs() {
        if key != "days" || window_days.is_some() {
            return Response::error("invalid metrics query", 400);
        }
        window_days = value.parse::<u64>().ok();
        if window_days.is_none() {
            return Response::error("invalid metrics query", 400);
        }
    }
    let window_days = window_days.unwrap_or(30);
    if !(1..=RETENTION_DAYS).contains(&window_days) {
        return Response::error("invalid metrics query", 400);
    }
    let now = worker::Date::now().as_millis() / 1_000;
    let since = now.saturating_sub(window_days * 86_400);
    let rows = env
        .d1("CARRACK_INDEX")?
        .prepare(
            "SELECT day, scope_kind, scope_id, direction, weighted_transfers,
                    weighted_bytes, weighted_provider_ms, weighted_total_ms,
                    weighted_retries, speed_b0, speed_b1, speed_b2, speed_b3,
                    speed_b4, speed_b5, speed_b6, speed_b7, speed_b8, speed_b9,
                    speed_b10, speed_b11, updated_at
             FROM vfs_transfer_daily_metrics
             WHERE scope_kind = ?1 AND scope_id = ?2 AND day >= ?3
             ORDER BY direction, day",
        )
        .bind(&[
            JsValue::from_str(scope_kind),
            JsValue::from_str(scope_id),
            number_binding(since - since % 86_400),
        ])?
        .all()
        .await?
        .results::<MetricRow>()?;
    let mut response = Response::from_json(&MetricsResponse {
        schema: "carrack.management.transfer-metrics.v1",
        observed_at: now,
        scope_kind: scope_kind.to_owned(),
        scope_id: scope_id.to_owned(),
        retention_days: RETENTION_DAYS,
        window_days,
        rows,
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn valid(value: &TransferTelemetry) -> bool {
    value.schema == "carrack.transfer-telemetry.v1"
        && value.provider_ms > 0
        && value.provider_ms <= value.total_ms
        && value.total_ms <= MAXIMUM_DURATION_MS
        && value.retries <= MAXIMUM_RETRIES
}

fn sample_weight(operation_id: &str, bytes: u64) -> u64 {
    if bytes >= LARGE_TRANSFER_BYTES {
        return 1;
    }
    if operation_id
        .as_bytes()
        .last()
        .and_then(|value| char::from(*value).to_digit(16))
        .is_some_and(|value| u64::from(value) % SAMPLE_MODULUS == 0)
    {
        SAMPLE_MODULUS
    } else {
        0
    }
}

fn speed_bucket(bytes: u64, milliseconds: u64) -> usize {
    let bytes_per_second = bytes.saturating_mul(1_000) / milliseconds.max(1);
    let units = bytes_per_second / (128 * 1024);
    if units == 0 {
        0
    } else {
        usize::try_from(units.ilog2() + 1).unwrap_or(11).min(11)
    }
}

fn number_binding(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}

#[cfg(test)]
mod tests {
    use super::{TransferTelemetry, sample_weight, speed_bucket, valid};

    #[test]
    fn samples_small_transfers_deterministically_and_keeps_large_transfers() {
        assert_eq!(sample_weight("00000000000000000000000000000000", 1), 10);
        assert_eq!(sample_weight("00000000000000000000000000000001", 1), 0);
        assert_eq!(sample_weight("ignored", 64 * 1024 * 1024), 1);
    }

    #[test]
    fn validates_bounded_observations_and_buckets_speed() {
        let observation = TransferTelemetry {
            schema: "carrack.transfer-telemetry.v1".to_owned(),
            provider_ms: 1_000,
            total_ms: 2_000,
            retries: 0,
        };
        assert!(valid(&observation));
        assert!(speed_bucket(128 * 1024, 1_000) > speed_bucket(1, 1_000));
    }
}
