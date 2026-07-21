//! Optional authenticated catalog-change notifications over a hibernating
//! Durable Object WebSocket.
//!
//! This channel is an acceleration hint only. D1 and immutable catalog
//! artifacts remain authoritative, and clients must fetch and authenticate a
//! checkpoint, delta, or revision-pinned traversal after every notification.

use serde::Serialize;
use worker::{
    DurableObject, Env, Method, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair, durable_object,
};

use crate::{
    vfs_catalog_delivery::{CatalogWatchAuthorization, watch_authorization},
    vfs_tokens::AuthenticatedVfsToken,
};

const WATCH_BINDING: &str = "SKYDRIVER_CATALOG_WATCH";
const WATCH_PATH: &str = "/api/v2/catalog/watch";
const PUBLISHED_PATH: &str = "/internal/catalog-published";
const TOKEN_TAG: &str = "token:";
const PRINCIPAL_TAG: &str = "principal:";
const ROOT_TAG: &str = "root:";
const FILESYSTEM_HEADER: &str = "Skydriver-Watch-Filesystem";
const TOKEN_HEADER: &str = "Skydriver-Watch-Token";
const PRINCIPAL_HEADER: &str = "Skydriver-Watch-Principal";
const ROOT_HEADER: &str = "Skydriver-Watch-Root";

#[derive(Serialize)]
struct CatalogWatchEvent<'a> {
    schema: &'static str,
    kind: &'static str,
    filesystem_id: &'a str,
    revision_id: u64,
    root_directory_id: &'a str,
    root_data_root: &'a str,
    etag: &'a str,
}

/// Opens a token-authenticated watch socket through the filesystem-scoped
/// Durable Object. The edge authorization is repeated inside the object before
/// the socket is accepted, closing the ACL/revocation race between the two
/// requests.
pub(crate) async fn connect(
    request: &Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
) -> Result<Response> {
    if request
        .headers()
        .get("Upgrade")?
        .as_deref()
        .is_none_or(|value| !value.eq_ignore_ascii_case("websocket"))
    {
        return Response::error("WebSocket upgrade required", 426);
    }
    let Some(authorization) = watch_authorization(env, token).await? else {
        return Response::error("catalog watch is unavailable for this authority", 403);
    };
    let namespace = env.durable_object(WATCH_BINDING)?;
    let stub = namespace.get_by_name(&authorization.filesystem_id)?;
    let mut forwarded = Request::new("https://carrack.invalid/api/v2/catalog/watch", Method::Get)?;
    let headers = forwarded.headers_mut()?;
    headers.set("Upgrade", "websocket")?;
    headers.set(FILESYSTEM_HEADER, &authorization.filesystem_id)?;
    headers.set(TOKEN_HEADER, &token.id)?;
    headers.set(PRINCIPAL_HEADER, &token.principal_id)?;
    headers.set(ROOT_HEADER, &token.root_directory_id)?;
    stub.fetch_with_request(forwarded).await
}

/// Best-effort wake-up after a catalog head has been durably published.
///
/// The Durable Object reloads each subscriber's current authorization and
/// current head from D1; this call carries no catalog identity that a delayed
/// or reordered notification could accidentally make authoritative.
pub(crate) async fn notify_published(env: &Env, filesystem_id: &str) -> Result<()> {
    let namespace = env.durable_object(WATCH_BINDING)?;
    let stub = namespace.get_by_name(filesystem_id)?;
    let mut request = Request::new(
        "https://carrack.invalid/internal/catalog-published",
        Method::Post,
    )?;
    request
        .headers_mut()?
        .set(FILESYSTEM_HEADER, filesystem_id)?;
    let response = stub.fetch_with_request(request).await?;
    if response.status_code() != 204 {
        return Err(worker::Error::RustError(format!(
            "catalog watch notification returned HTTP {}",
            response.status_code()
        )));
    }
    Ok(())
}

/// One filesystem-scoped hibernating WebSocket hub.
///
/// The object stores no authoritative state. WebSocket tags contain only
/// server-authenticated non-secret identities needed to re-run the D1 proof
/// after hibernation.
#[durable_object]
pub struct CatalogWatchHub {
    state: State,
    env: Env,
}

impl DurableObject for CatalogWatchHub {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: Request) -> Result<Response> {
        match (request.method(), request.path().as_str()) {
            (Method::Get, WATCH_PATH) => self.accept(request).await,
            (Method::Post, PUBLISHED_PATH) => self.broadcast(request).await,
            _ => Response::error("catalog watch route not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        socket: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        match message {
            WebSocketIncomingMessage::String(value) if value == "refresh" => {
                self.refresh(&socket, None).await
            }
            WebSocketIncomingMessage::String(_) => {
                socket.close(Some(4002), Some("unsupported catalog watch message"))
            }
            WebSocketIncomingMessage::Binary(_) => socket.close(
                Some(4003),
                Some("binary catalog watch messages are unsupported"),
            ),
        }
    }

    async fn websocket_close(
        &self,
        _socket: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, socket: WebSocket, _error: worker::Error) -> Result<()> {
        let _ = socket.close(Some(1011), Some("catalog watch transport failed"));
        Ok(())
    }
}

impl CatalogWatchHub {
    async fn accept(&self, request: Request) -> Result<Response> {
        if request
            .headers()
            .get("Upgrade")?
            .as_deref()
            .is_none_or(|value| !value.eq_ignore_ascii_case("websocket"))
        {
            return Response::error("WebSocket upgrade required", 426);
        }
        let filesystem_id = required_header(&request, FILESYSTEM_HEADER)?;
        let token = token_from_headers(&request)?;
        let Some(authorization) = watch_authorization(&self.env, &token).await? else {
            return Response::error("catalog watch authority is no longer valid", 403);
        };
        if authorization.filesystem_id != filesystem_id {
            return Response::error("catalog watch filesystem differs", 403);
        }

        let pair = WebSocketPair::new()?;
        let tags = subscription_tags(&token);
        let tag_refs = tags.iter().map(String::as_str).collect::<Vec<_>>();
        self.state
            .accept_websocket_with_tags(&pair.server, &tag_refs);
        send_authorized(&pair.server, &authorization)?;
        Response::from_websocket(pair.client)
    }

    async fn broadcast(&self, request: Request) -> Result<Response> {
        let filesystem_id = required_header(&request, FILESYSTEM_HEADER)?;
        for socket in self.state.get_websockets() {
            if let Err(error) = self.refresh(&socket, Some(&filesystem_id)).await {
                worker::console_warn!("catalog watch subscriber refresh failed: {error:?}");
                let _ = socket.close(Some(1011), Some("catalog watch refresh failed"));
            }
        }
        Ok(Response::empty()?.with_status(204))
    }

    async fn refresh(&self, socket: &WebSocket, filesystem_id: Option<&str>) -> Result<()> {
        let token = token_from_tags(&self.state.get_tags(socket))?;
        let Some(authorization) = watch_authorization(&self.env, &token).await? else {
            socket.close(Some(4001), Some("catalog watch authority changed"))?;
            return Ok(());
        };
        if filesystem_id.is_some_and(|expected| expected != authorization.filesystem_id) {
            socket.close(Some(4001), Some("catalog watch filesystem changed"))?;
            return Ok(());
        }
        send_authorized(socket, &authorization)
    }
}

fn send_authorized(socket: &WebSocket, authorization: &CatalogWatchAuthorization) -> Result<()> {
    socket.send(&CatalogWatchEvent {
        schema: "carrack.vfs.catalog-watch.v1",
        kind: "catalog_head",
        filesystem_id: &authorization.filesystem_id,
        revision_id: authorization.revision_id,
        root_directory_id: &authorization.root_directory_id,
        root_data_root: &authorization.root_data_root,
        etag: &authorization.etag,
    })
}

fn required_header(request: &Request, name: &str) -> Result<String> {
    request.headers().get(name)?.ok_or_else(|| {
        worker::Error::RustError(format!("required catalog watch header {name} is missing"))
    })
}

fn token_from_headers(request: &Request) -> Result<AuthenticatedVfsToken> {
    Ok(AuthenticatedVfsToken {
        id: required_header(request, TOKEN_HEADER)?,
        principal_id: required_header(request, PRINCIPAL_HEADER)?,
        root_directory_id: required_header(request, ROOT_HEADER)?,
        expires_at: 0,
    })
}

fn subscription_tags(token: &AuthenticatedVfsToken) -> [String; 3] {
    [
        format!("{TOKEN_TAG}{}", token.id),
        format!("{PRINCIPAL_TAG}{}", token.principal_id),
        format!("{ROOT_TAG}{}", token.root_directory_id),
    ]
}

fn token_from_tags(tags: &[String]) -> Result<AuthenticatedVfsToken> {
    Ok(AuthenticatedVfsToken {
        id: unique_tag(tags, TOKEN_TAG)?,
        principal_id: unique_tag(tags, PRINCIPAL_TAG)?,
        root_directory_id: unique_tag(tags, ROOT_TAG)?,
        expires_at: 0,
    })
}

fn unique_tag(tags: &[String], prefix: &str) -> Result<String> {
    let mut values = tags.iter().filter_map(|tag| tag.strip_prefix(prefix));
    let value = values.next().filter(|value| !value.is_empty());
    if value.is_none() || values.next().is_some() {
        return Err(worker::Error::RustError(
            "catalog watch subscription tags are invalid".to_owned(),
        ));
    }
    Ok(value.expect("checked above").to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_tags_round_trip_without_bearer_material() {
        let token = AuthenticatedVfsToken {
            id: "019f0000000000000000000000000001".to_owned(),
            principal_id: "019f0000000000000000000000000002".to_owned(),
            root_directory_id: "019f0000000000000000000000000003".to_owned(),
            expires_at: 123,
        };
        let tags = subscription_tags(&token);
        let decoded = token_from_tags(&tags).expect("valid tags");

        assert_eq!(decoded.id, token.id);
        assert_eq!(decoded.principal_id, token.principal_id);
        assert_eq!(decoded.root_directory_id, token.root_directory_id);
        assert_eq!(decoded.expires_at, 0);
        assert!(tags.iter().all(|tag| !tag.contains("Bearer")));
    }

    #[test]
    fn subscription_tags_reject_missing_or_duplicate_identity() {
        assert!(token_from_tags(&[]).is_err());
        assert!(
            token_from_tags(&[
                "token:a".to_owned(),
                "token:b".to_owned(),
                "principal:p".to_owned(),
                "root:r".to_owned(),
            ])
            .is_err()
        );
    }
}
