use worker::{Env, Result, wasm_bindgen::JsValue};

const DATABASE_BINDING: &str = "CARRACK_INDEX";
const MAXIMUM_EXPIRED_SESSIONS_PER_RUN: u64 = 500;
const MAXIMUM_EXPIRED_PUTS_PER_RUN: u64 = 250;

/// Performs bounded metadata hygiene without touching provider objects.
///
/// Expired sessions are ephemeral and can be deleted. Expired Put intents are
/// retained as durable evidence but leave the claimable `prepared` state. A
/// provider-object janitor remains responsible for any corresponding staging
/// object after the V2 reachability protocol proves it unreachable.
pub(crate) async fn run(env: &Env) -> Result<()> {
    let now = worker::Date::now().as_millis() / 1_000;
    let database = env.d1(DATABASE_BINDING)?;

    database
        .batch(vec![
            database
                .prepare(
                    "DELETE FROM admin_configuration_sessions
                     WHERE id IN (
                         SELECT id FROM admin_configuration_sessions
                         WHERE expires_at <= ?1
                         ORDER BY expires_at LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(&MAXIMUM_EXPIRED_SESSIONS_PER_RUN.to_string()),
                ])?,
            database
                .prepare(
                    "DELETE FROM admin_sessions
                     WHERE id IN (
                         SELECT id FROM admin_sessions
                         WHERE expires_at <= ?1
                         ORDER BY expires_at LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(&MAXIMUM_EXPIRED_SESSIONS_PER_RUN.to_string()),
                ])?,
            database
                .prepare(
                    "UPDATE vfs_put_intents
                     SET state = 'expired', revision = revision + 1
                     WHERE id IN (
                         SELECT id FROM vfs_put_intents
                         WHERE state = 'prepared' AND expires_at <= ?1
                         ORDER BY expires_at LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(&MAXIMUM_EXPIRED_PUTS_PER_RUN.to_string()),
                ])?,
        ])
        .await?;

    Ok(())
}
