use serde::{Deserialize, Serialize};
use worker::{Context, D1Database, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::operator_sessions;

const LARGE_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
const SAMPLE_MODULUS: u64 = 10;
const MAXIMUM_DURATION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAXIMUM_RETRIES: u64 = 1_000_000;
const RETENTION_DAYS: u64 = 400;
const HOURLY_RETENTION_DAYS: u64 = 45;
const MAXIMUM_ANALYTICS_ROWS: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferTelemetry {
    pub(crate) schema: String,
    pub(crate) provider_ms: u64,
    pub(crate) total_ms: u64,
    pub(crate) retries: u64,
    pub(crate) plan_ms: Option<u64>,
    pub(crate) queue_ms: Option<u64>,
    pub(crate) post_provider_ms: Option<u64>,
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
            let database = env.d1("SKYDRIVER_INDEX")?;
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
            worker::console_error!("Skydriver transfer telemetry was dropped: {error:?}");
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

#[derive(Deserialize, Serialize)]
struct AnalyticsRow {
    bucket: u64,
    group_id: String,
    direction: String,
    weighted_transfers: u64,
    weighted_bytes: u64,
    weighted_provider_ms: u64,
    weighted_total_ms: u64,
    weighted_retries: u64,
    weighted_phase_transfers: u64,
    weighted_plan_ms: u64,
    weighted_queue_ms: u64,
    weighted_phase_provider_ms: u64,
    weighted_post_provider_ms: u64,
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
}

#[derive(Serialize)]
struct AnalyticsResponse {
    schema: &'static str,
    observed_at: u64,
    from: u64,
    to: u64,
    interval: &'static str,
    group_by: String,
    driver_id: Option<String>,
    token_id: Option<String>,
    directory_id: Option<String>,
    include_descendants: bool,
    direction: String,
    approximate: bool,
    small_transfer_sample_modulus: u64,
    large_transfer_bytes: u64,
    rows: Vec<AnalyticsRow>,
}

#[derive(Default)]
struct AnalyticsQuery {
    from: Option<u64>,
    to: Option<u64>,
    interval: Option<String>,
    group_by: Option<String>,
    driver_id: Option<String>,
    token_id: Option<String>,
    directory_id: Option<String>,
    include_descendants: bool,
    direction: Option<String>,
}

struct ResolvedAnalyticsQuery {
    from: u64,
    to: u64,
    interval: &'static str,
    group_by: &'static str,
    group_expression: &'static str,
    direction: &'static str,
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

    let Some(weighted) = weighted_observation(identity, telemetry, weight) else {
        return Ok(());
    };
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

    let bucket = speed_bucket(identity.encoded_bytes, telemetry.provider_ms);
    let mut statements = Vec::with_capacity(2);
    for (table, bucket_seconds) in [
        ("vfs_transfer_hourly_analytics", 3_600),
        ("vfs_transfer_daily_analytics", 86_400),
    ] {
        let period = now - now % bucket_seconds;
        let bucket_column = format!("speed_b{bucket}");
        let sql = format!(
            "INSERT INTO {table} (
                 bucket, driver_id, token_id, directory_id, direction,
                 weighted_transfers, weighted_bytes, weighted_provider_ms,
                 weighted_total_ms, weighted_retries, weighted_phase_transfers,
                 weighted_plan_ms, weighted_queue_ms, weighted_post_provider_ms,
                 weighted_phase_provider_ms, {bucket_column}, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?6, ?16)
             ON CONFLICT(bucket, driver_id, token_id, directory_id, direction) DO UPDATE SET
                 weighted_transfers = weighted_transfers + excluded.weighted_transfers,
                 weighted_bytes = weighted_bytes + excluded.weighted_bytes,
                 weighted_provider_ms = weighted_provider_ms + excluded.weighted_provider_ms,
                 weighted_total_ms = weighted_total_ms + excluded.weighted_total_ms,
                 weighted_retries = weighted_retries + excluded.weighted_retries,
                 weighted_phase_transfers = weighted_phase_transfers + excluded.weighted_phase_transfers,
                 weighted_plan_ms = weighted_plan_ms + excluded.weighted_plan_ms,
                 weighted_queue_ms = weighted_queue_ms + excluded.weighted_queue_ms,
                 weighted_phase_provider_ms = weighted_phase_provider_ms + excluded.weighted_phase_provider_ms,
                 weighted_post_provider_ms = weighted_post_provider_ms + excluded.weighted_post_provider_ms,
                 {bucket_column} = {bucket_column} + excluded.{bucket_column},
                 updated_at = excluded.updated_at"
        );
        statements.push(database.prepare(&sql).bind(&[
            number_binding(period),
            JsValue::from_str(identity.driver_id),
            JsValue::from_str(identity.token_id),
            JsValue::from_str(identity.directory_id),
            JsValue::from_str(identity.direction),
            number_binding(weight),
            number_binding(weighted.bytes),
            number_binding(weighted.provider),
            number_binding(weighted.total),
            number_binding(weighted.retries),
            number_binding(weighted.phase_transfers),
            number_binding(weighted.plan),
            number_binding(weighted.queue),
            number_binding(weighted.post_provider),
            number_binding(weighted.phase_provider),
            number_binding(now),
        ])?);
    }
    database.batch(statements).await?;
    Ok(())
}

struct WeightedObservation {
    bytes: u64,
    provider: u64,
    total: u64,
    retries: u64,
    phase_transfers: u64,
    plan: u64,
    queue: u64,
    phase_provider: u64,
    post_provider: u64,
}

fn weighted_observation(
    identity: &TransferIdentity<'_>,
    telemetry: &TransferTelemetry,
    weight: u64,
) -> Option<WeightedObservation> {
    let phases = (identity.direction == "download")
        .then(|| telemetry.phases())
        .flatten();
    let provider = telemetry.provider_ms.checked_mul(weight)?;
    let weighted = WeightedObservation {
        bytes: identity.encoded_bytes.checked_mul(weight)?,
        provider,
        total: telemetry.total_ms.checked_mul(weight)?,
        retries: telemetry.retries.checked_mul(weight)?,
        phase_transfers: if phases.is_some() { weight } else { 0 },
        plan: phases
            .and_then(|value| value.plan.checked_mul(weight))
            .unwrap_or(0),
        queue: phases
            .and_then(|value| value.queue.checked_mul(weight))
            .unwrap_or(0),
        phase_provider: if phases.is_some() { provider } else { 0 },
        post_provider: phases
            .and_then(|value| value.post_provider.checked_mul(weight))
            .unwrap_or(0),
    };
    [
        weight,
        weighted.bytes,
        weighted.provider,
        weighted.total,
        weighted.retries,
        weighted.phase_transfers,
        weighted.plan,
        weighted.queue,
        weighted.phase_provider,
        weighted.post_provider,
    ]
    .into_iter()
    .all(|value| i64::try_from(value).is_ok())
    .then_some(weighted)
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
    let sql = legacy_metrics_sql(scope_kind);
    let rows = env
        .d1("SKYDRIVER_INDEX")?
        .prepare(&sql)
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

fn legacy_metrics_sql(scope_kind: &str) -> String {
    let current_filter = match scope_kind {
        "global" => "1 = 1",
        "driver" => "driver_id = ?2",
        "token" => "token_id = ?2",
        "directory" => "directory_id = ?2",
        _ => unreachable!("scope kind was validated"),
    };
    format!(
        "SELECT day, ?1 AS scope_kind, ?2 AS scope_id, direction,
                SUM(weighted_transfers) AS weighted_transfers,
                SUM(weighted_bytes) AS weighted_bytes,
                SUM(weighted_provider_ms) AS weighted_provider_ms,
                SUM(weighted_total_ms) AS weighted_total_ms,
                SUM(weighted_retries) AS weighted_retries,
                SUM(speed_b0) AS speed_b0, SUM(speed_b1) AS speed_b1,
                SUM(speed_b2) AS speed_b2, SUM(speed_b3) AS speed_b3,
                SUM(speed_b4) AS speed_b4, SUM(speed_b5) AS speed_b5,
                SUM(speed_b6) AS speed_b6, SUM(speed_b7) AS speed_b7,
                SUM(speed_b8) AS speed_b8, SUM(speed_b9) AS speed_b9,
                SUM(speed_b10) AS speed_b10, SUM(speed_b11) AS speed_b11,
                MAX(updated_at) AS updated_at
         FROM (
             SELECT day, direction, weighted_transfers, weighted_bytes,
                    weighted_provider_ms, weighted_total_ms, weighted_retries,
                    speed_b0, speed_b1, speed_b2, speed_b3, speed_b4, speed_b5,
                    speed_b6, speed_b7, speed_b8, speed_b9, speed_b10, speed_b11,
                    updated_at
             FROM vfs_transfer_daily_metrics
             WHERE scope_kind = ?1 AND scope_id = ?2 AND day >= ?3
             UNION ALL
             SELECT bucket AS day, direction, weighted_transfers, weighted_bytes,
                    weighted_provider_ms, weighted_total_ms, weighted_retries,
                    speed_b0, speed_b1, speed_b2, speed_b3, speed_b4, speed_b5,
                    speed_b6, speed_b7, speed_b8, speed_b9, speed_b10, speed_b11,
                    updated_at
             FROM vfs_transfer_daily_analytics
             WHERE bucket >= ?3 AND {current_filter}
         )
         GROUP BY day, direction
         ORDER BY direction, day"
    )
}

pub(crate) async fn analytics(request: &Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }
    let query = match parse_analytics_query(request) {
        Ok(query) => query,
        Err(message) => return Response::error(message, 400),
    };
    let now = worker::Date::now().as_millis() / 1_000;
    let resolved = match resolve_analytics_query(&query, now) {
        Ok(resolved) => resolved,
        Err(message) => return Response::error(message, 400),
    };
    let (sql, bindings) = analytics_statement(&query, &resolved);
    let mut rows = env
        .d1("SKYDRIVER_INDEX")?
        .prepare(&sql)
        .bind(&bindings)?
        .all()
        .await?
        .results::<AnalyticsRow>()?;
    if rows.len() > MAXIMUM_ANALYTICS_ROWS {
        return Response::error("analytics result is too large; narrow the query", 413);
    }
    rows.shrink_to_fit();
    let mut response = Response::from_json(&AnalyticsResponse {
        schema: "carrack.management.transfer-analytics.v2",
        observed_at: now,
        from: resolved.from,
        to: resolved.to,
        interval: resolved.interval,
        group_by: resolved.group_by.to_owned(),
        driver_id: query.driver_id,
        token_id: query.token_id,
        directory_id: query.directory_id,
        include_descendants: query.include_descendants,
        direction: resolved.direction.to_owned(),
        approximate: true,
        small_transfer_sample_modulus: SAMPLE_MODULUS,
        large_transfer_bytes: LARGE_TRANSFER_BYTES,
        rows,
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "private, max-age=60")?;
    Ok(response)
}

fn resolve_analytics_query(
    query: &AnalyticsQuery,
    now: u64,
) -> std::result::Result<ResolvedAnalyticsQuery, &'static str> {
    let to = query.to.unwrap_or(now).min(now);
    let from = query.from.unwrap_or_else(|| to.saturating_sub(30 * 86_400));
    if from >= to || to - from > RETENTION_DAYS * 86_400 {
        return Err("invalid analytics time range");
    }
    let short_range = to - from <= HOURLY_RETENTION_DAYS * 86_400;
    let interval = match query.interval.as_deref().unwrap_or("auto") {
        "auto" | "hour" if short_range => "hour",
        "auto" | "day" => "day",
        "hour" => return Err("hour interval exceeds retention"),
        _ => return Err("invalid analytics interval"),
    };
    let (group_by, group_expression) = match query.group_by.as_deref().unwrap_or("none") {
        "none" => ("none", "'all'"),
        "driver" => ("driver", "driver_id"),
        "token" => ("token", "token_id"),
        "directory" => ("directory", "directory_id"),
        _ => return Err("invalid analytics grouping"),
    };
    let direction = match query.direction.as_deref().unwrap_or("both") {
        "both" => "both",
        "upload" => "upload",
        "download" => "download",
        _ => return Err("invalid analytics direction"),
    };
    if query.include_descendants && query.directory_id.is_none() {
        return Err("descendant scope requires a directory");
    }
    Ok(ResolvedAnalyticsQuery {
        from,
        to,
        interval,
        group_by,
        group_expression,
        direction,
    })
}

fn analytics_statement(
    query: &AnalyticsQuery,
    resolved: &ResolvedAnalyticsQuery,
) -> (String, Vec<JsValue>) {
    let table = if resolved.interval == "hour" {
        "vfs_transfer_hourly_analytics"
    } else {
        "vfs_transfer_daily_analytics"
    };
    let bucket_seconds = if resolved.interval == "hour" {
        3_600
    } else {
        86_400
    };
    let mut bindings = vec![
        number_binding(resolved.from - resolved.from % bucket_seconds),
        number_binding(resolved.to - resolved.to % bucket_seconds),
    ];
    let mut predicates = vec!["bucket >= ?1".to_owned(), "bucket <= ?2".to_owned()];
    append_identity_predicates(query, &mut bindings, &mut predicates);
    if resolved.direction != "both" {
        bindings.push(JsValue::from_str(resolved.direction));
        predicates.push(format!("direction = ?{}", bindings.len()));
    }
    let sql = format!(
        "SELECT bucket, {} AS group_id, direction,
                SUM(weighted_transfers) AS weighted_transfers,
                SUM(weighted_bytes) AS weighted_bytes,
                SUM(weighted_provider_ms) AS weighted_provider_ms,
                SUM(weighted_total_ms) AS weighted_total_ms,
                SUM(weighted_retries) AS weighted_retries,
                SUM(weighted_phase_transfers) AS weighted_phase_transfers,
                SUM(weighted_plan_ms) AS weighted_plan_ms,
                SUM(weighted_queue_ms) AS weighted_queue_ms,
                SUM(weighted_phase_provider_ms) AS weighted_phase_provider_ms,
                SUM(weighted_post_provider_ms) AS weighted_post_provider_ms,
                SUM(speed_b0) AS speed_b0, SUM(speed_b1) AS speed_b1,
                SUM(speed_b2) AS speed_b2, SUM(speed_b3) AS speed_b3,
                SUM(speed_b4) AS speed_b4, SUM(speed_b5) AS speed_b5,
                SUM(speed_b6) AS speed_b6, SUM(speed_b7) AS speed_b7,
                SUM(speed_b8) AS speed_b8, SUM(speed_b9) AS speed_b9,
                SUM(speed_b10) AS speed_b10, SUM(speed_b11) AS speed_b11
         FROM {table}
         WHERE {}
         GROUP BY bucket, group_id, direction
         ORDER BY bucket, group_id, direction
         LIMIT {}",
        resolved.group_expression,
        predicates.join(" AND "),
        MAXIMUM_ANALYTICS_ROWS + 1
    );
    (sql, bindings)
}

fn append_identity_predicates(
    query: &AnalyticsQuery,
    bindings: &mut Vec<JsValue>,
    predicates: &mut Vec<String>,
) {
    for (column, value) in [
        ("driver_id", query.driver_id.as_deref()),
        ("token_id", query.token_id.as_deref()),
    ] {
        if let Some(value) = value {
            bindings.push(JsValue::from_str(value));
            predicates.push(format!("{column} = ?{}", bindings.len()));
        }
    }
    let Some(directory_id) = query.directory_id.as_deref() else {
        return;
    };
    bindings.push(JsValue::from_str(directory_id));
    let parameter = bindings.len();
    if query.include_descendants {
        predicates.push(format!(
            "directory_id IN (
                WITH RECURSIVE descendants(id) AS (
                    SELECT id FROM vfs_directories WHERE id = ?{parameter}
                    UNION ALL
                    SELECT child.id FROM vfs_directories AS child
                    JOIN descendants AS parent ON child.parent_id = parent.id
                    WHERE child.state = 'active'
                )
                SELECT id FROM descendants
            )"
        ));
    } else {
        predicates.push(format!("directory_id = ?{parameter}"));
    }
}

fn parse_analytics_query(request: &Request) -> std::result::Result<AnalyticsQuery, &'static str> {
    let url = request.url().map_err(|_| "invalid analytics query")?;
    let mut query = AnalyticsQuery::default();
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "from" if query.from.is_none() => {
                query.from = Some(value.parse().map_err(|_| "invalid analytics from")?);
            }
            "to" if query.to.is_none() => {
                query.to = Some(value.parse().map_err(|_| "invalid analytics to")?);
            }
            "interval" if query.interval.is_none() => query.interval = Some(value.into_owned()),
            "group_by" if query.group_by.is_none() => query.group_by = Some(value.into_owned()),
            "driver" if query.driver_id.is_none() && valid_scope_id(&value) => {
                query.driver_id = Some(value.into_owned());
            }
            "token" if query.token_id.is_none() && valid_scope_id(&value) => {
                query.token_id = Some(value.into_owned());
            }
            "directory" if query.directory_id.is_none() && valid_scope_id(&value) => {
                query.directory_id = Some(value.into_owned());
            }
            "include_descendants" if !query.include_descendants && value == "true" => {
                query.include_descendants = true;
            }
            "direction" if query.direction.is_none() => query.direction = Some(value.into_owned()),
            _ => return Err("invalid or duplicate analytics query parameter"),
        }
    }
    Ok(query)
}

fn valid_scope_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid(value: &TransferTelemetry) -> bool {
    matches!(
        value.schema.as_str(),
        "carrack.transfer-telemetry.v1" | "carrack.transfer-telemetry.v2"
    ) && value.provider_ms > 0
        && value.provider_ms <= value.total_ms
        && value.total_ms <= MAXIMUM_DURATION_MS
        && value.retries <= MAXIMUM_RETRIES
        && match value.schema.as_str() {
            "carrack.transfer-telemetry.v1" => {
                value.plan_ms.is_none()
                    && value.queue_ms.is_none()
                    && value.post_provider_ms.is_none()
            }
            "carrack.transfer-telemetry.v2" => value.phases().is_some_and(|phases| {
                phases
                    .plan
                    .checked_add(phases.queue)
                    .and_then(|total| total.checked_add(value.provider_ms))
                    .and_then(|total| total.checked_add(phases.post_provider))
                    .is_some_and(|total| total <= value.total_ms)
            }),
            _ => false,
        }
}

#[derive(Clone, Copy)]
struct TransferPhases {
    plan: u64,
    queue: u64,
    post_provider: u64,
}

impl TransferTelemetry {
    fn phases(&self) -> Option<TransferPhases> {
        Some(TransferPhases {
            plan: self.plan_ms?,
            queue: self.queue_ms?,
            post_provider: self.post_provider_ms?,
        })
    }
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
    use super::{
        AnalyticsQuery, TransferTelemetry, resolve_analytics_query, sample_weight, speed_bucket,
        valid,
    };

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
            plan_ms: None,
            queue_ms: None,
            post_provider_ms: None,
        };
        assert!(valid(&observation));
        let phased = TransferTelemetry {
            schema: "carrack.transfer-telemetry.v2".to_owned(),
            provider_ms: 1_000,
            total_ms: 2_000,
            retries: 0,
            plan_ms: Some(200),
            queue_ms: Some(300),
            post_provider_ms: Some(400),
        };
        assert!(valid(&phased));
        assert!(!valid(&TransferTelemetry {
            schema: "carrack.transfer-telemetry.v1".to_owned(),
            ..phased.clone()
        }));
        assert!(!valid(&TransferTelemetry {
            total_ms: 1_899,
            ..phased.clone()
        }));
        assert!(!valid(&TransferTelemetry {
            queue_ms: None,
            ..phased
        }));
        assert!(speed_bucket(128 * 1024, 1_000) > speed_bucket(1, 1_000));
    }

    #[test]
    fn resolves_bounded_analytics_granularity_without_widening_queries() {
        let now = 2_000_000_000;
        let short = AnalyticsQuery {
            from: Some(now - 7 * 86_400),
            to: Some(now),
            interval: Some("auto".to_owned()),
            group_by: Some("driver".to_owned()),
            direction: Some("download".to_owned()),
            ..AnalyticsQuery::default()
        };
        let resolved = resolve_analytics_query(&short, now).expect("resolve short query");
        assert_eq!(resolved.interval, "hour");
        assert_eq!(resolved.group_expression, "driver_id");
        assert_eq!(resolved.direction, "download");

        let long = AnalyticsQuery {
            from: Some(now - 90 * 86_400),
            to: Some(now),
            interval: Some("auto".to_owned()),
            ..AnalyticsQuery::default()
        };
        assert_eq!(
            resolve_analytics_query(&long, now)
                .expect("resolve long query")
                .interval,
            "day"
        );
        let forced_hour = AnalyticsQuery {
            interval: Some("hour".to_owned()),
            ..long
        };
        assert!(resolve_analytics_query(&forced_hour, now).is_err());
    }
}
