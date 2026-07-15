//! Carrack's Cloudflare control plane.
//!
//! The Worker serves metadata and the web console. Payload bytes always move
//! directly between Carrack agents and storage providers.

mod clients;
mod compaction;
mod copying;
mod driver_credentials;
mod garbage_collection;
mod integrity;
mod inventory;
mod key_grants;
pub mod keys;
mod maintenance;
mod management;
mod management_configuration;
mod management_driver_configuration;
mod management_driver_credentials;
mod management_driver_registration;
mod management_quotas;
mod manifest_archive;
mod manifests;
mod move_deletion;
mod moving;
mod operations;
mod operator_sessions;
pub mod protocol;
mod protocol_compatibility;
mod publication;
mod quarantine;
mod quarantine_deletion;
mod r2_signing;
mod reconciliation;
mod repairing;
mod restoration;
mod telemetry;
mod verification;
mod vfs_access;
mod vfs_authorization;
mod vfs_bootstrap;
mod vfs_directories;
mod vfs_directory_management;
mod vfs_download;
mod vfs_envelopes;
mod vfs_grants;
mod vfs_identifiers;
mod vfs_merkle;
mod vfs_namespace_mutation;
mod vfs_policy_management;
mod vfs_put;
mod vfs_put_commit;
mod vfs_put_deletion;
mod vfs_server_lifecycle;
mod vfs_token_management;
mod vfs_tokens;

use serde::{Deserialize, Serialize};
use worker::{
    Context, D1Database, D1PreparedStatement, Date, Env, Request, Response, Result, Router,
    ScheduleContext, ScheduledEvent, event, wasm_bindgen::JsValue,
};

#[derive(Serialize)]
struct HealthResponse {
    service: &'static str,
    environment: String,
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

#[derive(Deserialize)]
struct RecoveryTransitionRequest {
    incarnation: String,
    expected_revision: u64,
}

#[derive(Deserialize, Serialize)]
struct SummaryRow {
    operations: u64,
    objects: u64,
    packs: u64,
    verified_locations: u64,
}

#[derive(Deserialize, Serialize)]
struct LiveComponentRow {
    component_id: String,
    operation_id: String,
    operation_kind: String,
    operation_phase: String,
    component_kind: String,
    component_state: String,
    client_name: Option<String>,
    useful_bytes_total: Option<u64>,
    useful_bytes_verified: u64,
    wire_bytes_read: u64,
    wire_bytes_written: u64,
    retry_count: u64,
    throttle_count: u64,
    last_sample_at: Option<u64>,
    rate_1m_bps: f64,
    rate_5m_bps: f64,
    rate_15m_bps: f64,
    lifetime_active_bps: f64,
}

#[derive(Serialize)]
struct LiveComponentsResponse {
    observed_at: u64,
    components: Vec<LiveComponentRow>,
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
pub async fn main(request: Request, env: Env, _context: Context) -> Result<Response> {
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

    Router::new()
        .get("/api/compatibility", |_, _| protocol_compatibility::describe())
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
        .post_async("/api/clients", |mut request, context| async move {
            if !operator_sessions::authorized(&request, &context.env).await? {
                return Response::error("authentication required", 401);
            }

            clients::create(&mut request, &context.env).await
        })
        .get_async("/api/client/session", |request, context| async move {
            match clients::authenticate(&request, &context.env).await? {
                Some(client) => Response::from_json(&client),
                None => Response::error("client authentication required", 401),
            }
        })
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
        .get_async("/api/v2/session", |request, context| async move {
            let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                return Response::error("VFS token authentication required", 401);
            };
            vfs_tokens::session(&token)
        })
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
            |request, context| async move {
                let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                    return Response::error("VFS token authentication required", 401);
                };
                let Some(lease_id) = context.param("id") else {
                    return Response::error("VFS read lease ID is required", 400);
                };
                vfs_download::complete(&context.env, &token, lease_id).await
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
                vfs_namespace_mutation::remove(
                    &mut request,
                    &context.env,
                    &token,
                    directory_id,
                )
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
                vfs_policy_management::replace_acl(
                    &mut request,
                    &context.env,
                    &token,
                    directory_id,
                )
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

                vfs_token_management::revoke(
                    &mut request,
                    &context.env,
                    &token,
                    target_token_id,
                )
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

                vfs_put_commit::stage_block_manifest(
                    &mut request,
                    &context.env,
                    &token,
                    intent_id,
                )
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

                vfs_put_commit::commit(&mut request, &context.env, &token, intent_id).await
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
                vfs_grants::grant_put_r2_multipart(
                    &mut request,
                    &context.env,
                    &token,
                    intent_id,
                )
                .await
            },
        )
        .post_async("/api/v2/put-deletes/claim", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }
            let Some(token) = vfs_tokens::authenticate(&request, &context.env).await? else {
                return Response::error("VFS token authentication required", 401);
            };
            vfs_put_deletion::claim(&mut request, &context.env, &token).await
        })
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
        .post_async(
            "/api/v1/recovery-manifests/stage",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                manifest_archive::stage(&mut request, &context.env, &client).await
            },
        )
        .post_async("/api/v1/operations", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            operations::create(&mut request, &context.env, &client).await
        })
        .post_async("/api/v1/gc/epochs", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            garbage_collection::create(&mut request, &context.env, &client).await
        })
        .post_async(
            "/api/v1/quarantine-actions",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                quarantine::create(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/quarantine-actions/:id/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                quarantine::complete(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/quarantine-actions/:id/deletes/claim",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                quarantine_deletion::claim(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/quarantine-deletes/revalidate",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                quarantine_deletion::revalidate(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/quarantine-deletes/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                quarantine_deletion::complete(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/quarantine-deletes/fail",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                quarantine_deletion::fail(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/gc/:id/mark",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                garbage_collection::mark(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/gc/:id/deletes/claim",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                garbage_collection::claim(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/gc/deletes/revalidate",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                garbage_collection::revalidate(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/gc/deletes/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                garbage_collection::complete(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/gc/deletes/fail",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                garbage_collection::fail(&mut request, &context.env, &client).await
            },
        )
        .post_async("/api/v1/compactions", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            compaction::create(&mut request, &context.env, &client).await
        })
        .post_async(
            "/api/v1/compactions/:id/manifest",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                compaction::fetch_manifest(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/compactions/:id/source-key",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                key_grants::grant_compact_source(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/compactions/:id/target-key",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                key_grants::grant_compact_target(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/compactions/publish",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                publication::publish(&mut request, &context.env, &client).await
            },
        )
        .post_async("/api/v1/reconciliations", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            reconciliation::create(&mut request, &context.env, &client).await
        })
        .post_async(
            "/api/v1/inventory-reconciliations",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                inventory::create(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/inventory-reconciliations/:id/pages",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                inventory::report_page(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/inventory-reconciliations/:id/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                inventory::complete(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/reconciliations/:id/snapshot",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                reconciliation::fetch_snapshot(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/reconciliations/:id/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                reconciliation::complete(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async("/api/v1/repairs", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            repairing::create(&mut request, &context.env, &client).await
        })
        .post_async(
            "/api/v1/repairs/:id/snapshot",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                repairing::fetch_snapshot(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/repairs/:id/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                repairing::complete(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async("/api/v1/verifications", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            verification::create(&mut request, &context.env, &client).await
        })
        .post_async(
            "/api/v1/verifications/:id/manifest",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                verification::fetch_manifest(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/verifications/:id/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                verification::complete(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async("/api/v1/copies", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            copying::create(&mut request, &context.env, &client).await
        })
        .post_async(
            "/api/v1/copies/:id/manifest",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                copying::fetch_manifest(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/copies/publish",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                copying::publish(&mut request, &context.env, &client).await
            },
        )
        .post_async("/api/v1/moves", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            moving::create(&mut request, &context.env, &client).await
        })
        .post_async(
            "/api/v1/moves/:id/manifest",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                copying::fetch_move_manifest(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/moves/publish-destination",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                copying::publish_move_destination(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/moves/tombstone-source",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                moving::tombstone(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/moves/:id/deletes/claim",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                move_deletion::claim(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/moves/deletes/revalidate",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                move_deletion::revalidate(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/moves/deletes/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                move_deletion::complete(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/moves/deletes/fail",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                move_deletion::fail(&mut request, &context.env, &client).await
            },
        )
        .post_async("/api/v1/restores", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            restoration::create(&mut request, &context.env, &client).await
        })
        .post_async(
            "/api/v1/restores/:id/claim",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                restoration::claim(&mut request, &context.env, &client, operation_id).await
            },
        )
        .post_async(
            "/api/v1/restores/:id/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                restoration::complete(&mut request, &context.env, &client, operation_id).await
            },
        )
        .post_async(
            "/api/v1/restores/:id/manifest",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                restoration::fetch_manifest(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/restores/:id/fail",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                restoration::fail(&mut request, &context.env, &client, operation_id).await
            },
        )
        .post_async(
            "/api/v1/restores/:id/key",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                key_grants::grant_restore(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/operations/:id/claim",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                operations::claim(&mut request, &context.env, &client, operation_id).await
            },
        )
        .post_async(
            "/api/v1/imports/:id/key",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                key_grants::grant_import(&mut request, &context.env, &client, operation_id).await
            },
        )
        .post_async(
            "/api/v1/imports/publish",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                publication::publish(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/operations/:id/progress",
            |mut request, context| async move {
                let operation_id = context.param("id").cloned();
                report_progress(&mut request, &context.env, operation_id.as_deref()).await
            },
        )
        .get_async("/api/summary", |request, context| async move {
            summary(&request, &context.env).await
        })
        .get_async("/api/admin/snapshot", |request, context| async move {
            management::snapshot(&request, &context.env).await
        })
        .get_async("/api/admin/events/cursor", |request, context| async move {
            management::event_cursor(&request, &context.env).await
        })
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
        .get_async("/api/components/live", |request, context| async move {
            live_components(&request, &context.env).await
        })
        .get_async("/api/integrity/findings", |request, context| async move {
            integrity::list(&request, &context.env).await
        })
        .post_async("/api/recovery/begin", |mut request, context| async move {
            begin_recovery(&mut request, &context.env).await
        })
        .post_async(
            "/api/recovery/complete",
            |mut request, context| async move {
                complete_recovery(&mut request, &context.env).await
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

async fn report_progress(
    request: &mut Request,
    env: &Env,
    operation_id: Option<&str>,
) -> Result<Response> {
    if external_maintenance(env) {
        return Response::error("control-plane mutations are disabled", 409);
    }

    let Some(client) = clients::authenticate(request, env).await? else {
        return Response::error("client authentication required", 401);
    };
    let Some(operation_id) = operation_id else {
        return Response::error("operation ID is required", 400);
    };

    telemetry::report(request, env, &client, operation_id).await
}

async fn health(env: &Env) -> Result<Response> {
    let state = load_control_state(env).await?;
    let external_maintenance = external_maintenance(env);
    let environment = env.var("CARRACK_ENVIRONMENT")?.to_string();

    Response::from_json(&HealthResponse {
        service: "carrack-control-plane",
        environment,
        transfer_mode: "direct",
        mutations_allowed: state.mode == "active" && !external_maintenance,
        mode: state.mode,
        incarnation: state.incarnation,
        revision: state.revision,
        external_maintenance,
    })
}

async fn summary(request: &Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let result = database
        .prepare(
            "SELECT \
             (SELECT COUNT(*) FROM operations) AS operations, \
             (SELECT COUNT(*) FROM objects) AS objects, \
             (SELECT COUNT(*) FROM packs) AS packs, \
             (SELECT COUNT(*) FROM locations WHERE state IN ('verified', 'available')) AS verified_locations",
        )
        .first::<SummaryRow>(None)
        .await?;

    match result {
        Some(value) => Response::from_json(&value),
        None => Response::error("summary query returned no row", 500),
    }
}

async fn live_components(request: &Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let query = database.prepare(
        "WITH recent_rates AS (\
             SELECT component_id, \
                    1.0e9 * SUM(CASE WHEN bucket_start >= unixepoch() - 60 \
                                     THEN useful_bytes_verified_delta ELSE 0 END) / \
                        NULLIF(SUM(CASE WHEN bucket_start >= unixepoch() - 60 \
                                        THEN active_nanoseconds_delta ELSE 0 END), 0) AS rate_1m_bps, \
                    1.0e9 * SUM(CASE WHEN bucket_start >= unixepoch() - 300 \
                                     THEN useful_bytes_verified_delta ELSE 0 END) / \
                        NULLIF(SUM(CASE WHEN bucket_start >= unixepoch() - 300 \
                                        THEN active_nanoseconds_delta ELSE 0 END), 0) AS rate_5m_bps, \
                    1.0e9 * SUM(useful_bytes_verified_delta) / \
                        NULLIF(SUM(active_nanoseconds_delta), 0) AS rate_15m_bps \
             FROM telemetry_minute_buckets \
             WHERE bucket_start >= unixepoch() - 900 \
             GROUP BY component_id\
         ) \
         SELECT component.id AS component_id, \
                operation.id AS operation_id, \
                operation.kind AS operation_kind, \
                operation.phase AS operation_phase, \
                component.component_kind AS component_kind, \
                component.state AS component_state, \
                client.name AS client_name, \
                component.useful_bytes_total AS useful_bytes_total, \
                component.useful_bytes_verified AS useful_bytes_verified, \
                component.wire_bytes_read AS wire_bytes_read, \
                component.wire_bytes_written AS wire_bytes_written, \
                component.retry_count AS retry_count, \
                component.throttle_count AS throttle_count, \
                component.last_sample_at AS last_sample_at, \
                COALESCE(recent_rates.rate_1m_bps, 0.0) AS rate_1m_bps, \
                COALESCE(recent_rates.rate_5m_bps, 0.0) AS rate_5m_bps, \
                COALESCE(recent_rates.rate_15m_bps, 0.0) AS rate_15m_bps, \
                COALESCE(1.0e9 * component.useful_bytes_verified / \
                         NULLIF(component.active_nanoseconds, 0), 0.0) AS lifetime_active_bps \
         FROM operation_components AS component \
         JOIN operations AS operation ON operation.id = component.operation_id \
         LEFT JOIN clients AS client ON client.id = component.client_id \
         LEFT JOIN recent_rates ON recent_rates.component_id = component.id \
         WHERE component.state IN ('pending', 'running', 'stalled', 'verifying') \
         ORDER BY component.updated_at DESC \
         LIMIT 200",
    );
    let result = query.all().await?;
    let components = result.results::<LiveComponentRow>()?;

    Response::from_json(&LiveComponentsResponse {
        observed_at: current_unix_seconds(),
        components,
    })
}

async fn begin_recovery(request: &mut Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }

    if !external_maintenance(env) {
        return Response::error("external maintenance mode is required", 409);
    }

    let transition = request.json::<RecoveryTransitionRequest>().await?;
    if protocol::validate_incarnation(&transition.incarnation).is_err() {
        return Response::error("invalid recovery incarnation", 400);
    }

    let expected_revision = d1_integer(transition.expected_revision)?;
    let now = d1_integer(current_unix_seconds())?;
    let database = env.d1("CARRACK_INDEX")?;
    let statements =
        recovery_statements(&database, &transition.incarnation, &expected_revision, &now)?;
    let results = database.batch(statements).await?;
    let state_changed = results
        .first()
        .and_then(|result| result.meta().ok().flatten())
        .and_then(|metadata| metadata.changes)
        == Some(1);
    let state = load_control_state(env).await?;

    if !state_changed && (state.incarnation != transition.incarnation || state.mode != "recovering")
    {
        return Response::error("recovery state changed concurrently", 409);
    }

    Response::from_json(&state)
}

fn recovery_statements(
    database: &D1Database,
    incarnation: &str,
    expected_revision: &str,
    now: &str,
) -> Result<Vec<D1PreparedStatement>> {
    let state_update = database
        .prepare(
            "UPDATE control_plane_state \
             SET incarnation = ?1, mode = 'recovering', revision = revision + 1, \
                 recovered_at = ?2, updated_at = ?2 \
             WHERE singleton = 1 AND revision = ?3 AND incarnation != ?1",
        )
        .bind(&[
            JsValue::from_str(incarnation),
            JsValue::from_str(now),
            JsValue::from_str(expected_revision),
        ])?;
    let fail_components = database
        .prepare(
            "UPDATE operation_components \
             SET state = 'failed', revision = revision + 1, finished_at = ?1, updated_at = ?1 \
             WHERE state IN ('pending', 'running', 'stalled', 'verifying') \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;
    let supersede_attempts = database
        .prepare(
            "UPDATE operation_attempts \
             SET state = 'superseded', finished_at = ?1 \
             WHERE state = 'running' AND incarnation != ?2 \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;
    let release_leases = database
        .prepare(
            "UPDATE leases SET released_at = ?1, updated_at = ?1 \
             WHERE released_at IS NULL AND incarnation != ?2 \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;
    let fail_gc = database
        .prepare(
            "UPDATE gc_epochs SET state = 'failed', updated_at = ?1 \
             WHERE state IN ('marking', 'grace', 'sweeping') AND incarnation != ?2 \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;
    let fail_operations = database
        .prepare(
            "UPDATE operations \
             SET state = CASE WHEN state = 'planned' THEN 'cancelled' ELSE 'failed' END, \
                 phase = 'control_plane_recovered', \
                 error_code = 'control_plane_recovered', \
                 error_message = 'operation invalidated by control-plane recovery', \
                 revision = revision + 1, finished_at = ?1, updated_at = ?1 \
             WHERE state IN ('planned', 'running', 'verifying', 'committing') \
               AND incarnation != ?2 \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;

    Ok(vec![
        state_update,
        fail_components,
        supersede_attempts,
        release_leases,
        fail_gc,
        fail_operations,
    ])
}

async fn complete_recovery(request: &mut Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }

    if !external_maintenance(env) {
        return Response::error("external maintenance mode is required", 409);
    }

    let transition = request.json::<RecoveryTransitionRequest>().await?;
    if protocol::validate_incarnation(&transition.incarnation).is_err() {
        return Response::error("invalid recovery incarnation", 400);
    }

    let expected_revision = d1_integer(transition.expected_revision)?;
    let now = d1_integer(current_unix_seconds())?;
    let database = env.d1("CARRACK_INDEX")?;
    let result = database
        .prepare(
            "UPDATE control_plane_state \
             SET mode = 'active', revision = revision + 1, updated_at = ?1 \
             WHERE singleton = 1 AND mode = 'recovering' \
               AND incarnation = ?2 AND revision = ?3",
        )
        .bind(&[
            JsValue::from_str(&now),
            JsValue::from_str(&transition.incarnation),
            JsValue::from_str(&expected_revision),
        ])?
        .run()
        .await?;
    let changed = result
        .meta()?
        .and_then(|metadata| metadata.changes)
        .unwrap_or_default();
    let state = load_control_state(env).await?;

    if changed != 1 && (state.incarnation != transition.incarnation || state.mode != "active") {
        return Response::error("recovery state changed concurrently", 409);
    }

    Response::from_json(&state)
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

fn d1_integer(value: u64) -> Result<String> {
    if value > i64::MAX as u64 {
        return Err(worker::Error::RustError(
            "integer exceeds D1's signed range".to_owned(),
        ));
    }

    Ok(value.to_string())
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}
