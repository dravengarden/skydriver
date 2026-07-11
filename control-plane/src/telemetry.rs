use serde::{Deserialize, Serialize};
use worker::{
    D1Database, D1PreparedStatement, Date, Env, Request, Response, Result, wasm_bindgen::JsValue,
};

use crate::clients::AuthenticatedClient;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgressRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    attempt: u64,
    sequence: u64,
    wire_bytes_read: u64,
    wire_bytes_written: u64,
    useful_bytes_verified: u64,
    active_nanoseconds: u64,
    retry_count: u64,
    throttle_count: u64,
}

#[derive(Deserialize)]
struct ProgressRow {
    component_id: String,
    attempt: u64,
    sequence: u64,
    wire_bytes_read: u64,
    wire_bytes_written: u64,
    useful_bytes_verified: u64,
    active_nanoseconds: u64,
    retry_count: u64,
    throttle_count: u64,
}

#[derive(Serialize)]
struct ProgressResponse {
    component_id: String,
    attempt: u64,
    sequence: u64,
    wire_bytes_read: u64,
    wire_bytes_written: u64,
    useful_bytes_verified: u64,
    active_nanoseconds: u64,
    retry_count: u64,
    throttle_count: u64,
    observed_at: u64,
    disposition: &'static str,
}

pub(crate) async fn report(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    let requested = request.json::<ProgressRequest>().await?;
    if !valid_request(operation_id, &requested) {
        return Response::error("invalid progress sample", 400);
    }

    let now = current_unix_seconds();
    let bucket = now - (now % 60);
    let database = env.d1("CARRACK_INDEX")?;
    let bindings = bindings(operation_id, client, &requested, now, bucket)?;
    database
        .batch(vec![
            telemetry_statement(&database, &bindings)?,
            attempt_statement(&database, &bindings)?,
            component_statement(&database, &bindings)?,
            operation_statement(&database, &bindings)?,
        ])
        .await?;

    let Some(current) = load_current(&database, operation_id, client, &requested).await? else {
        return Response::error("progress lease is stale or unavailable", 409);
    };
    let disposition = match compare_sample(&current, &requested) {
        SampleComparison::Current => "current",
        SampleComparison::Superseded => "superseded",
        SampleComparison::Conflict => return Response::error("progress counters conflict", 409),
    };

    Response::from_json(&ProgressResponse {
        component_id: current.component_id,
        attempt: current.attempt,
        sequence: current.sequence,
        wire_bytes_read: current.wire_bytes_read,
        wire_bytes_written: current.wire_bytes_written,
        useful_bytes_verified: current.useful_bytes_verified,
        active_nanoseconds: current.active_nanoseconds,
        retry_count: current.retry_count,
        throttle_count: current.throttle_count,
        observed_at: now,
        disposition,
    })
}

struct Bindings(Vec<JsValue>);

fn bindings(
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &ProgressRequest,
    now: u64,
    bucket: u64,
) -> Result<Bindings> {
    let values = [
        operation_id,
        client.id.as_str(),
        requested.lease_id.as_str(),
        requested.incarnation.as_str(),
    ]
    .into_iter()
    .map(JsValue::from_str)
    .chain(
        [
            requested.fencing_token,
            requested.sequence,
            requested.wire_bytes_read,
            requested.wire_bytes_written,
            requested.useful_bytes_verified,
            requested.active_nanoseconds,
            requested.retry_count,
            requested.throttle_count,
            now,
            bucket,
        ]
        .into_iter()
        .map(integer)
        .collect::<Result<Vec<_>>>()?,
    )
    .collect();

    Ok(Bindings(values))
}

fn telemetry_statement(database: &D1Database, bindings: &Bindings) -> Result<D1PreparedStatement> {
    database
        .prepare(
            "INSERT INTO telemetry_minute_buckets (\
                 component_id, attempt, bucket_start, first_observed_at, last_observed_at, \
                 sample_count, wire_bytes_read_delta, wire_bytes_written_delta, \
                 useful_bytes_verified_delta, active_nanoseconds_delta, retry_count_delta, \
                 throttle_count_delta\
             ) \
             SELECT attempt.component_id, attempt.attempt, ?14, ?13, ?13, 1, \
                    ?7 - attempt.wire_bytes_read, ?8 - attempt.wire_bytes_written, \
                    ?9 - attempt.useful_bytes_verified, ?10 - attempt.active_nanoseconds, \
                    ?11 - attempt.retry_count, ?12 - attempt.throttle_count \
             FROM operation_attempts AS attempt \
             JOIN operation_components AS component ON component.id = attempt.component_id \
             JOIN leases AS lease ON lease.id = attempt.lease_id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE component.operation_id = ?1 AND attempt.client_id = ?2 \
               AND attempt.lease_id = ?3 AND attempt.incarnation = ?4 \
               AND attempt.attempt = ?5 AND attempt.fencing_token = ?5 \
               AND attempt.state = 'running' AND component.current_attempt = ?5 \
               AND component.lease_id = ?3 AND component.fencing_token = ?5 \
               AND lease.owner_client_id = ?2 AND lease.operation_id = ?1 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.released_at IS NULL AND lease.expires_at > ?13 \
               AND state.mode = 'active' AND state.incarnation = ?4 \
               AND ?6 > attempt.last_sequence \
               AND ?7 >= attempt.wire_bytes_read AND ?8 >= attempt.wire_bytes_written \
               AND ?9 >= attempt.useful_bytes_verified AND ?10 >= attempt.active_nanoseconds \
               AND ?11 >= attempt.retry_count AND ?12 >= attempt.throttle_count \
             ON CONFLICT(component_id, attempt, bucket_start) DO UPDATE SET \
                 last_observed_at = excluded.last_observed_at, \
                 sample_count = telemetry_minute_buckets.sample_count + 1, \
                 wire_bytes_read_delta = telemetry_minute_buckets.wire_bytes_read_delta + \
                                         excluded.wire_bytes_read_delta, \
                 wire_bytes_written_delta = telemetry_minute_buckets.wire_bytes_written_delta + \
                                            excluded.wire_bytes_written_delta, \
                 useful_bytes_verified_delta = telemetry_minute_buckets.useful_bytes_verified_delta + \
                                               excluded.useful_bytes_verified_delta, \
                 active_nanoseconds_delta = telemetry_minute_buckets.active_nanoseconds_delta + \
                                            excluded.active_nanoseconds_delta, \
                 retry_count_delta = telemetry_minute_buckets.retry_count_delta + \
                                     excluded.retry_count_delta, \
                 throttle_count_delta = telemetry_minute_buckets.throttle_count_delta + \
                                        excluded.throttle_count_delta",
        )
        .bind(&bindings.0)
}

fn attempt_statement(database: &D1Database, bindings: &Bindings) -> Result<D1PreparedStatement> {
    database
        .prepare(
            "UPDATE operation_attempts \
             SET last_sequence = ?6, wire_bytes_read = ?7, wire_bytes_written = ?8, \
                 useful_bytes_verified = ?9, active_nanoseconds = ?10, retry_count = ?11, \
                 throttle_count = ?12 \
             WHERE component_id IN (SELECT id FROM operation_components WHERE operation_id = ?1) \
               AND client_id = ?2 AND lease_id = ?3 AND incarnation = ?4 \
               AND attempt = ?5 AND fencing_token = ?5 AND state = 'running' \
               AND ?6 > last_sequence AND ?7 >= wire_bytes_read AND ?8 >= wire_bytes_written \
               AND ?9 >= useful_bytes_verified AND ?10 >= active_nanoseconds \
               AND ?11 >= retry_count AND ?12 >= throttle_count \
               AND EXISTS(SELECT 1 FROM leases \
                          WHERE id = ?3 AND operation_id = ?1 AND owner_client_id = ?2 \
                            AND incarnation = ?4 AND fencing_token = ?5 \
                            AND released_at IS NULL AND expires_at > ?13) \
               AND EXISTS(SELECT 1 FROM control_plane_state \
                          WHERE singleton = 1 AND mode = 'active' AND incarnation = ?4)",
        )
        .bind(&bindings.0[..13])
}

fn component_statement(database: &D1Database, bindings: &Bindings) -> Result<D1PreparedStatement> {
    database
        .prepare(
            "UPDATE operation_components \
             SET useful_bytes_verified = (SELECT SUM(useful_bytes_verified) \
                                          FROM operation_attempts WHERE component_id = operation_components.id), \
                 wire_bytes_read = (SELECT SUM(wire_bytes_read) \
                                    FROM operation_attempts WHERE component_id = operation_components.id), \
                 wire_bytes_written = (SELECT SUM(wire_bytes_written) \
                                       FROM operation_attempts WHERE component_id = operation_components.id), \
                 active_nanoseconds = (SELECT SUM(active_nanoseconds) \
                                       FROM operation_attempts WHERE component_id = operation_components.id), \
                 retry_count = (SELECT SUM(retry_count) \
                                FROM operation_attempts WHERE component_id = operation_components.id), \
                 throttle_count = (SELECT SUM(throttle_count) \
                                   FROM operation_attempts WHERE component_id = operation_components.id), \
                 last_sequence = ?6, last_sample_at = ?13, revision = revision + 1, updated_at = ?13 \
             WHERE operation_id = ?1 AND client_id = ?2 AND current_attempt = ?5 \
               AND lease_id = ?3 AND fencing_token = ?5 AND last_sequence < ?6 \
               AND EXISTS(SELECT 1 FROM operation_attempts \
                          WHERE component_id = operation_components.id AND attempt = ?5 \
                            AND last_sequence = ?6 AND wire_bytes_read = ?7 \
                            AND wire_bytes_written = ?8 AND useful_bytes_verified = ?9 \
                            AND active_nanoseconds = ?10 AND retry_count = ?11 \
                            AND throttle_count = ?12)",
        )
        .bind(&bindings.0[..13])
}

fn operation_statement(database: &D1Database, bindings: &Bindings) -> Result<D1PreparedStatement> {
    database
        .prepare(
            "UPDATE operations \
             SET useful_bytes_verified = (SELECT SUM(useful_bytes_verified) \
                                          FROM operation_components WHERE operation_id = operations.id), \
                 wire_bytes_read = (SELECT SUM(wire_bytes_read) \
                                    FROM operation_components WHERE operation_id = operations.id), \
                 wire_bytes_written = (SELECT SUM(wire_bytes_written) \
                                       FROM operation_components WHERE operation_id = operations.id), \
                 retry_count = (SELECT SUM(retry_count) \
                                FROM operation_components WHERE operation_id = operations.id), \
                 throttle_count = (SELECT SUM(throttle_count) \
                                   FROM operation_components WHERE operation_id = operations.id), \
                 revision = revision + 1, updated_at = ?13 \
             WHERE id = ?1 AND state = 'running' \
               AND EXISTS(SELECT 1 FROM operation_components \
                          WHERE operation_id = ?1 AND client_id = ?2 \
                            AND current_attempt = ?5 AND last_sequence = ?6 \
                            AND lease_id = ?3 AND fencing_token = ?5) \
               AND (useful_bytes_verified != (SELECT SUM(useful_bytes_verified) \
                                               FROM operation_components WHERE operation_id = ?1) \
                    OR wire_bytes_read != (SELECT SUM(wire_bytes_read) \
                                           FROM operation_components WHERE operation_id = ?1) \
                    OR wire_bytes_written != (SELECT SUM(wire_bytes_written) \
                                              FROM operation_components WHERE operation_id = ?1) \
                    OR retry_count != (SELECT SUM(retry_count) \
                                       FROM operation_components WHERE operation_id = ?1) \
                    OR throttle_count != (SELECT SUM(throttle_count) \
                                          FROM operation_components WHERE operation_id = ?1))",
        )
        .bind(&bindings.0[..13])
}

async fn load_current(
    database: &D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &ProgressRequest,
) -> Result<Option<ProgressRow>> {
    database
        .prepare(
            "SELECT attempt.component_id, attempt.attempt, attempt.last_sequence AS sequence, \
                    attempt.wire_bytes_read, attempt.wire_bytes_written, \
                    attempt.useful_bytes_verified, attempt.active_nanoseconds, \
                    attempt.retry_count, attempt.throttle_count \
             FROM operation_attempts AS attempt \
             JOIN operation_components AS component ON component.id = attempt.component_id \
             JOIN leases AS lease ON lease.id = attempt.lease_id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE component.operation_id = ?1 AND attempt.client_id = ?2 \
               AND attempt.lease_id = ?3 AND attempt.incarnation = ?4 \
               AND attempt.attempt = ?5 AND attempt.fencing_token = ?5 \
               AND component.current_attempt = ?5 AND component.lease_id = ?3 \
               AND component.fencing_token = ?5 AND lease.owner_client_id = ?2 \
               AND lease.operation_id = ?1 AND lease.incarnation = ?4 \
               AND lease.fencing_token = ?5 AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND state.mode = 'active' \
               AND state.incarnation = ?4",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            integer(requested.fencing_token)?,
        ])?
        .first::<ProgressRow>(None)
        .await
}

enum SampleComparison {
    Current,
    Superseded,
    Conflict,
}

fn compare_sample(current: &ProgressRow, requested: &ProgressRequest) -> SampleComparison {
    if current.sequence > requested.sequence {
        return SampleComparison::Superseded;
    }

    if current.sequence == requested.sequence
        && current.wire_bytes_read == requested.wire_bytes_read
        && current.wire_bytes_written == requested.wire_bytes_written
        && current.useful_bytes_verified == requested.useful_bytes_verified
        && current.active_nanoseconds == requested.active_nanoseconds
        && current.retry_count == requested.retry_count
        && current.throttle_count == requested.throttle_count
    {
        return SampleComparison::Current;
    }

    SampleComparison::Conflict
}

fn valid_request(operation_id: &str, requested: &ProgressRequest) -> bool {
    valid_string(operation_id, 128)
        && valid_string(&requested.lease_id, 256)
        && valid_hex(&requested.incarnation, 32)
        && requested.fencing_token > 0
        && requested.attempt == requested.fencing_token
        && requested.sequence > 0
        && [
            requested.wire_bytes_read,
            requested.wire_bytes_written,
            requested.useful_bytes_verified,
            requested.active_nanoseconds,
            requested.retry_count,
            requested.throttle_count,
        ]
        .into_iter()
        .all(|value| value <= i64::MAX.unsigned_abs())
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

fn integer(value: u64) -> Result<JsValue> {
    if value > i64::MAX.unsigned_abs() {
        return Err(worker::Error::RustError(
            "integer exceeds D1 signed range".to_owned(),
        ));
    }

    Ok(JsValue::from_str(&value.to_string()))
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::{ProgressRequest, ProgressRow, SampleComparison, compare_sample, valid_request};

    fn sample(sequence: u64) -> ProgressRequest {
        ProgressRequest {
            lease_id: "lease".to_owned(),
            incarnation: "0123456789abcdef0123456789abcdef".to_owned(),
            fencing_token: 2,
            attempt: 2,
            sequence,
            wire_bytes_read: 10,
            wire_bytes_written: 9,
            useful_bytes_verified: 8,
            active_nanoseconds: 7,
            retry_count: 1,
            throttle_count: 0,
        }
    }

    fn current(sequence: u64) -> ProgressRow {
        ProgressRow {
            component_id: "component".to_owned(),
            attempt: 2,
            sequence,
            wire_bytes_read: 10,
            wire_bytes_written: 9,
            useful_bytes_verified: 8,
            active_nanoseconds: 7,
            retry_count: 1,
            throttle_count: 0,
        }
    }

    #[test]
    fn distinguishes_current_superseded_and_conflicting_samples() {
        assert!(matches!(
            compare_sample(&current(2), &sample(2)),
            SampleComparison::Current
        ));
        assert!(matches!(
            compare_sample(&current(3), &sample(2)),
            SampleComparison::Superseded
        ));

        let mut conflict = current(2);
        conflict.wire_bytes_read += 1;
        assert!(matches!(
            compare_sample(&conflict, &sample(2)),
            SampleComparison::Conflict
        ));
    }

    #[test]
    fn validates_fence_attempt_and_signed_counter_bounds() {
        assert!(valid_request("operation", &sample(1)));

        let mut invalid = sample(1);
        invalid.attempt += 1;
        assert!(!valid_request("operation", &invalid));
    }
}
