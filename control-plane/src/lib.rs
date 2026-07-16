//! Carrack's Cloudflare control plane.
//!
//! The Worker serves metadata and the web console. Payload bytes always move
//! directly between Carrack agents and storage providers.

mod driver_authorization;
mod driver_configuration;
mod driver_credentials;
mod driver_inventory;
mod driver_lifecycle;
mod driver_registry;
mod environment_defaults;
mod maintenance;
mod management;
mod management_access;
mod management_configuration;
mod management_driver_configuration;
mod management_driver_credentials;
mod management_driver_registration;
mod management_quotas;
mod operator_sessions;
mod protocol_compatibility;
mod r2_signing;
mod transfer_metrics;
mod vfs_access;
mod vfs_authorization;
mod vfs_bootstrap;
mod vfs_catalog_delivery;
mod vfs_catalog_materialization;
mod vfs_directories;
mod vfs_directory_management;
mod vfs_download;
mod vfs_envelopes;
mod vfs_grants;
mod vfs_identifiers;
mod vfs_merkle;
mod vfs_namespace_mutation;
mod vfs_policy_management;
mod vfs_provider_inventory;
mod vfs_put;
mod vfs_put_commit;
mod vfs_put_deletion;
mod vfs_server_lifecycle;
mod vfs_token_management;
mod vfs_tokens;

use serde::{Deserialize, Serialize};
use worker::{
    Context, Env, Request, Response, Result, Router, ScheduleContext, ScheduledEvent, event,
};

#[derive(Serialize)]
struct HealthResponse {
    service: &'static str,
    environment: String,
    operator_account: String,
    transfer_mode: &'static str,
    mode: String,
    incarnation: String,
    revision: u64,
    external_maintenance: bool,
    mutations_allowed: bool,
}

#[derive(Deserialize, Serialize)]
struct ControlStateRow {
    incarnation: String,
    mode: String,
    revision: u64,
    recovered_at: Option<u64>,
}

/// Handles a Cloudflare Worker fetch event.
///
/// # Errors
///
/// Returns a Worker error when a binding, request body, cryptographic
/// operation, D1 query, or response serialization fails.
#[event(fetch)]
#[allow(
    clippy::too_many_lines,
    reason = "the fetch entrypoint keeps the complete HTTP route table visible"
)]
pub async fn main(request: Request, env: Env, context: Context) -> Result<Response> {
    if !request.path().starts_with("/api/") {
        return env
            .assets("ASSETS")?
            .fetch_request(request)
            .await
            .and_then(security_headers);
    }

    if (request.path().starts_with("/api/v2/") || request.path().starts_with("/api/admin/"))
        && let Some(response) = protocol_compatibility::enforce(&request)?
    {
        return Ok(response);
    }
    if request.path() == "/api/auth/login"
        && let Some(response) = protocol_compatibility::enforce_management_login(&request)?
    {
        return Ok(response);
    }

    Router::with_data(context)
        .get("/api/compatibility", |_, _| {
            protocol_compatibility::describe()
        })
        .get("/api/acceptance/wasm-sdk", |_, _| wasm_sdk_acceptance())
        .get_async("/api/health", |_, context| async move {
            health(&context.env).await
        })
        .post_async("/api/auth/login", |mut request, context| async move {
            operator_sessions::login(&mut request, &context.env).await
        })
        .get_async("/api/auth/session", |request, context| async move {
            operator_sessions::status(&request, &context.env).await
        })
        .post_async("/api/auth/logout", |request, context| async move {
            operator_sessions::logout(&request, &context.env).await
        })
        .get_async("/api/auth/configuration", |request, context| async move {
            operator_sessions::configuration_status(&request, &context.env).await
        })
        .post_async(
            "/api/auth/configuration/enable",
            |mut request, context| async move {
                operator_sessions::enable_configuration(&mut request, &context.env).await
            },
        )
        .post_async(
            "/api/auth/configuration/disable",
            |request, context| async move {
                operator_sessions::disable_configuration(&request, &context.env).await
            },
        )
        .post_async("/api/v2/bootstrap", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }
            if !operator_sessions::authorized(&request, &context.env).await? {
                return Response::error("operator authentication required", 401);
            }

            let response = vfs_bootstrap::bootstrap(
                &mut request,
                &context.env,
                operator_sessions::OPERATOR_SUBJECT,
            )
            .await;
            if let Err(error) = &response {
                worker::console_error!("VFS bootstrap failed: {error:?}");
            }
            response
        })
        .post_async(
            "/api/admin/vfs/authority/recover",
            |request, context| async move {
                if !operator_sessions::authorized(&request, &context.env).await?
                    || !operator_sessions::configuration_authorized(&request, &context.env).await?
                {
                    return Response::error("configuration authentication required", 401);
                }
                vfs_bootstrap::recover(&context.env, operator_sessions::OPERATOR_SUBJECT).await
            },
        )
        .get_async("/api/v2/session", |request, context| async move {
            let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                return Response::error("VFS token authentication required", 401);
            };
            vfs_tokens::session(&token)
        })
        .get_async(
            "/api/v2/catalog/checkpoint",
            |request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                vfs_catalog_delivery::checkpoint(&request, &context.env, &token).await
            },
        )
        .get_async(
            "/api/v2/directories/:id/entries",
            |request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(directory_id) = context.param("id") else {
                    return Response::error("VFS directory ID is required", 400);
                };

                vfs_directories::list(&request, &context.env, &token, directory_id).await
            },
        )
        .get_async(
            "/api/v2/versions/:id/download",
            |request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(version_id) = context.param("id") else {
                    return Response::error("VFS version ID is required", 400);
                };
                vfs_download::plan(&context.env, &token, version_id).await
            },
        )
        .post_async(
            "/api/v2/read-leases/:id/complete",
            |mut request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(lease_id) = context.param("id") else {
                    return Response::error("VFS read lease ID is required", 400);
                };
                vfs_download::complete(&mut request, &context.env, &context.data, &token, lease_id)
                    .await
            },
        )
        .post_async(
            "/api/v2/directories/:id/children",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(parent_directory_id) = context.param("id") else {
                    return Response::error("VFS parent directory ID is required", 400);
                };

                vfs_directory_management::create(
                    &mut request,
                    &context.env,
                    &token,
                    parent_directory_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v2/directories/:id/remove",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(directory_id) = context.param("id") else {
                    return Response::error("VFS directory ID is required", 400);
                };
                vfs_namespace_mutation::remove(&mut request, &context.env, &token, directory_id)
                    .await
            },
        )
        .post_async(
            "/api/v2/directories/:id/rename",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(source_directory_id) = context.param("id") else {
                    return Response::error("VFS source directory ID is required", 400);
                };
                vfs_namespace_mutation::rename(
                    &mut request,
                    &context.env,
                    &token,
                    source_directory_id,
                )
                .await
            },
        )
        .get_async("/api/v2/remove-receipts", |request, context| async move {
            let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                return Response::error("VFS token authentication required", 401);
            };
            vfs_namespace_mutation::remove_receipt(&request, &context.env, &token).await
        })
        .get_async("/api/v2/rename-receipts", |request, context| async move {
            let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                return Response::error("VFS token authentication required", 401);
            };
            vfs_namespace_mutation::rename_receipt(&request, &context.env, &token).await
        })
        .get_async(
            "/api/v2/directories/:id/acl",
            |request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(directory_id) = context.param("id") else {
                    return Response::error("VFS directory ID is required", 400);
                };
                vfs_policy_management::list_acl(&context.env, &token, directory_id).await
            },
        )
        .post_async(
            "/api/v2/directories/:id/acl/replace",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(directory_id) = context.param("id") else {
                    return Response::error("VFS directory ID is required", 400);
                };
                vfs_policy_management::replace_acl(&mut request, &context.env, &token, directory_id)
                    .await
            },
        )
        .get_async(
            "/api/v2/directories/:id/placements",
            |request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(directory_id) = context.param("id") else {
                    return Response::error("VFS directory ID is required", 400);
                };
                vfs_policy_management::list_placements(&context.env, &token, directory_id).await
            },
        )
        .post_async(
            "/api/v2/directories/:id/placements/replace",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(directory_id) = context.param("id") else {
                    return Response::error("VFS directory ID is required", 400);
                };
                vfs_policy_management::replace_placements(
                    &mut request,
                    &context.env,
                    &token,
                    directory_id,
                )
                .await
            },
        )
        .post_async("/api/v2/tokens", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }
            let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                return Response::error("VFS token authentication required", 401);
            };

            vfs_token_management::issue(&mut request, &context.env, &token).await
        })
        .post_async(
            "/api/v2/tokens/:id/revoke",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(target_token_id) = context.param("id") else {
                    return Response::error("VFS token ID is required", 400);
                };

                vfs_token_management::revoke(&mut request, &context.env, &token, target_token_id)
                    .await
            },
        )
        .post_async("/api/v2/puts/prepare", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                return Response::error("VFS token authentication required", 401);
            };

            vfs_put::prepare(&mut request, &context.env, &token).await
        })
        .post_async(
            "/api/v2/puts/:id/block-manifest",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(intent_id) = context.param("id") else {
                    return Response::error("VFS put intent ID is required", 400);
                };

                vfs_put_commit::stage_block_manifest(&mut request, &context.env, &token, intent_id)
                    .await
            },
        )
        .post_async(
            "/api/v2/puts/:id/commit",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(intent_id) = context.param("id") else {
                    return Response::error("VFS put intent ID is required", 400);
                };

                vfs_put_commit::commit(&mut request, &context.env, &context.data, &token, intent_id)
                    .await
            },
        )
        .post_async(
            "/api/v2/puts/:id/key-grant",
            |request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(intent_id) = context.param("id") else {
                    return Response::error("VFS put intent ID is required", 400);
                };

                vfs_grants::grant_put_key(&context.env, &token, intent_id).await
            },
        )
        .post_async(
            "/api/v2/puts/:id/driver-grant",
            |request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(intent_id) = context.param("id") else {
                    return Response::error("VFS put intent ID is required", 400);
                };

                vfs_grants::grant_put_driver(&context.env, &token, intent_id).await
            },
        )
        .post_async(
            "/api/v2/puts/:id/r2-multipart-grant",
            |mut request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(intent_id) = context.param("id") else {
                    return Response::error("VFS put intent ID is required", 400);
                };
                vfs_grants::grant_put_r2_multipart(&mut request, &context.env, &token, intent_id)
                    .await
            },
        )
        .post_async(
            "/api/v2/put-deletes/claim",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                vfs_put_deletion::claim(&mut request, &context.env, &token).await
            },
        )
        .post_async(
            "/api/v2/put-deletes/:id/driver-grant",
            |request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(task_id) = context.param("id") else {
                    return Response::error("VFS put-delete task ID is required", 400);
                };
                vfs_grants::grant_put_delete_driver(&context.env, &token, task_id).await
            },
        )
        .post_async(
            "/api/v2/put-deletes/:id/revalidate",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(task_id) = context.param("id") else {
                    return Response::error("VFS put-delete task ID is required", 400);
                };
                vfs_put_deletion::revalidate(&mut request, &context.env, &token, task_id).await
            },
        )
        .post_async(
            "/api/v2/put-deletes/:id/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(task_id) = context.param("id") else {
                    return Response::error("VFS put-delete task ID is required", 400);
                };
                vfs_put_deletion::complete(&mut request, &context.env, &token, task_id).await
            },
        )
        .post_async(
            "/api/v2/put-deletes/:id/fail",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(task_id) = context.param("id") else {
                    return Response::error("VFS put-delete task ID is required", 400);
                };
                vfs_put_deletion::fail(&mut request, &context.env, &token, task_id).await
            },
        )
        .get_async("/api/admin/snapshot", |request, context| async move {
            management::snapshot(&request, &context.env).await
        })
        .get_async("/api/admin/access", |request, context| async move {
            management_access::snapshot(request, &context.env).await
        })
        .get_async(
            "/api/admin/provider-inventory",
            |request, context| async move {
                vfs_provider_inventory::snapshot(request, &context.env).await
            },
        )
        .post_async(
            "/api/admin/provider-inventory/:driver_id/refresh",
            |request, context| async move {
                let Some(driver_id) = context.param("driver_id") else {
                    return Response::error("driver ID is required", 400);
                };
                vfs_provider_inventory::refresh(request, &context.env, driver_id).await
            },
        )
        .post_async(
            "/api/admin/access/validate",
            |mut request, context| async move {
                management_access::validate(&mut request, &context.env).await
            },
        )
        .post_async(
            "/api/admin/access/apply",
            |mut request, context| async move {
                management_access::apply(&mut request, &context.env).await
            },
        )
        .get_async("/api/admin/activity", |request, context| async move {
            management::activity(&request, &context.env).await
        })
        .get_async("/api/admin/events/cursor", |request, context| async move {
            management::event_cursor(&request, &context.env).await
        })
        .get_async("/api/admin/events", |request, context| async move {
            management::events(&request, &context.env).await
        })
        .get_async(
            "/api/admin/metrics/:scope/:id",
            |request, context| async move {
                transfer_metrics::management(
                    &request,
                    &context.env,
                    context.param("scope").map(String::as_str),
                    context.param("id").map(String::as_str),
                )
                .await
            },
        )
        .get_async(
            "/api/admin/directories/:id",
            |request, context| async move {
                let directory_id = context.param("id").cloned();
                management::directory(&request, &context.env, directory_id.as_deref()).await
            },
        )
        .post_async(
            "/api/admin/quotas/:scope/:id/validate",
            |mut request, context| async move {
                let scope = context.param("scope").cloned();
                let resource_id = context.param("id").cloned();
                management_quotas::validate(
                    &mut request,
                    &context.env,
                    scope.as_deref(),
                    resource_id.as_deref(),
                )
                .await
            },
        )
        .post_async(
            "/api/admin/quotas/:scope/:id/apply",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }
                let scope = context.param("scope").cloned();
                let resource_id = context.param("id").cloned();
                management_quotas::apply(
                    &mut request,
                    &context.env,
                    scope.as_deref(),
                    resource_id.as_deref(),
                )
                .await
            },
        )
        .post_async(
            "/api/admin/tokens/:id/annotation/validate",
            |mut request, context| async move {
                let token_id = context.param("id").cloned();
                management_configuration::validate_token_annotation(
                    &mut request,
                    &context.env,
                    token_id.as_deref(),
                )
                .await
            },
        )
        .post_async(
            "/api/admin/tokens/:id/annotation/apply",
            |mut request, context| async move {
                let token_id = context.param("id").cloned();
                management_configuration::apply_token_annotation(
                    &mut request,
                    &context.env,
                    token_id.as_deref(),
                )
                .await
            },
        )
        .post_async(
            "/api/admin/drivers/:id/state/validate",
            |mut request, context| async move {
                let driver_id = context.param("id").cloned();
                management_driver_configuration::validate(
                    &mut request,
                    &context.env,
                    driver_id.as_deref(),
                )
                .await
            },
        )
        .post_async(
            "/api/admin/drivers/:id/state/apply",
            |mut request, context| async move {
                let driver_id = context.param("id").cloned();
                management_driver_configuration::apply(
                    &mut request,
                    &context.env,
                    driver_id.as_deref(),
                )
                .await
            },
        )
        .post_async(
            "/api/admin/drivers/registration/validate",
            |mut request, context| async move {
                management_driver_registration::validate(&mut request, &context.env).await
            },
        )
        .post_async(
            "/api/admin/drivers/registration/apply",
            |mut request, context| async move {
                management_driver_registration::apply(&mut request, &context.env).await
            },
        )
        .post_async(
            "/api/admin/drivers/:id/credential/validate",
            |mut request, context| async move {
                let driver_id = context.param("id").cloned();
                management_driver_credentials::validate(
                    &mut request,
                    &context.env,
                    driver_id.as_deref(),
                )
                .await
            },
        )
        .post_async(
            "/api/admin/drivers/:id/credential/apply",
            |mut request, context| async move {
                let driver_id = context.param("id").cloned();
                management_driver_credentials::apply(
                    &mut request,
                    &context.env,
                    driver_id.as_deref(),
                )
                .await
            },
        )
        .run(request, env)
        .await
        .and_then(security_headers)
}

fn wasm_sdk_acceptance() -> Result<Response> {
    let proof = carrack_sdk_core::wasm_acceptance_proof(b"abc")
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    Response::from_json(&proof)
}

/// Runs bounded, idempotent D1 hygiene from the environment's Cron Trigger.
#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _context: ScheduleContext) {
    if let Err(error) = maintenance::run(&env).await {
        worker::console_error!("Carrack scheduled metadata maintenance failed: {error:?}");
    }
}

fn security_headers(mut response: Response) -> Result<Response> {
    let headers = response.headers_mut();
    headers.set(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; \
         form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; font-src 'self' data:; connect-src 'self'",
    )?;
    headers.set("Strict-Transport-Security", "max-age=31536000")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set("X-Frame-Options", "DENY")?;
    headers.set("Referrer-Policy", "no-referrer")?;
    headers.set(
        "Permissions-Policy",
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    )?;
    headers.set("Cross-Origin-Opener-Policy", "same-origin")?;
    headers.set("Cross-Origin-Resource-Policy", "same-origin")?;
    Ok(response)
}

async fn health(env: &Env) -> Result<Response> {
    let state = load_control_state(env).await?;
    let external_maintenance = external_maintenance(env);
    let environment = env.var("CARRACK_ENVIRONMENT")?.to_string();
    let operator_account = env.var("CARRACK_OPERATOR_ACCOUNT")?.to_string();

    Response::from_json(&HealthResponse {
        service: "carrack-control-plane",
        environment,
        operator_account,
        transfer_mode: "direct",
        mutations_allowed: state.mode == "active" && !external_maintenance,
        mode: state.mode,
        incarnation: state.incarnation,
        revision: state.revision,
        external_maintenance,
    })
}

async fn load_control_state(env: &Env) -> Result<ControlStateRow> {
    let database = env.d1("CARRACK_INDEX")?;
    let result = database
        .prepare(
            "SELECT incarnation, mode, revision, recovered_at \
             FROM control_plane_state WHERE singleton = 1",
        )
        .first::<ControlStateRow>(None)
        .await?;

    result.ok_or_else(|| worker::Error::RustError("control-plane state is missing".to_owned()))
}

fn external_maintenance(env: &Env) -> bool {
    let configured = env
        .var("CARRACK_MAINTENANCE")
        .map(|value| value.to_string())
        .or_else(|_| {
            env.secret("CARRACK_MAINTENANCE")
                .map(|value| value.to_string())
        });

    configured.is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "enabled"))
}
