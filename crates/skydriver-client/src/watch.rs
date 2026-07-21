//! Optional catalog-change notifications.
//!
//! The WebSocket carries only freshly authorized catalog-head receipts. It is
//! never a source of catalog truth: callers use an event to trigger the normal
//! authenticated checkpoint, delta, or revision-pinned traversal.

use futures_util::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{
        client::IntoClientRequest as _,
        http::{HeaderValue, StatusCode},
        protocol::{Message, WebSocketConfig},
    },
};

use crate::{Error, PROTOCOL_EPOCH, SDK_VERSION, VfsClient, VfsSession};

const MAXIMUM_WATCH_MESSAGE_BYTES: usize = 64 * 1024;
const WATCH_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

type WatchSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One freshly authorized catalog-head notification.
///
/// Receiving this value never authorizes payload work. It only tells the
/// caller that fetching the ordinary authenticated catalog may avoid polling.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogWatchEvent {
    /// Stable advisory protocol schema.
    pub schema: String,
    /// Event kind; currently always `catalog_head`.
    pub kind: String,
    /// Owning filesystem identity.
    pub filesystem_id: String,
    /// Current published catalog revision.
    pub revision_id: u64,
    /// Token-visible root directory identity.
    pub root_directory_id: String,
    /// Current authenticated root for that token-visible directory.
    pub root_data_root: String,
    /// Conditional checkpoint entity tag to use on the next HTTP fetch.
    pub etag: String,
}

/// One optional hibernating catalog-watch connection.
///
/// Disconnects, malformed events, and unsupported servers are acceleration
/// misses. Callers must fall back to the normal authenticated HTTP catalog
/// path rather than treating this stream as required for correctness.
pub struct CatalogWatch {
    socket: WatchSocket,
    root_directory_id: String,
    current: CatalogWatchEvent,
}

impl VfsClient {
    /// Opens an optional catalog-watch connection and waits for its initial
    /// freshly authorized head receipt.
    ///
    /// # Errors
    ///
    /// Returns a bounded, secret-free transport or protocol error. The bearer
    /// is sent only in the WebSocket authorization header and is never placed
    /// in the URL or an error message.
    pub async fn watch_catalog(&self) -> Result<CatalogWatch, Error> {
        let session = self.session().await?;
        self.watch_catalog_for_session(&session).await
    }

    pub(crate) async fn watch_catalog_for_session(
        &self,
        session: &VfsSession,
    ) -> Result<CatalogWatch, Error> {
        self.watch_catalog_for_session_with_timeout(session, WATCH_OPEN_TIMEOUT)
            .await
    }

    async fn watch_catalog_for_session_with_timeout(
        &self,
        session: &VfsSession,
        timeout: Duration,
    ) -> Result<CatalogWatch, Error> {
        tokio::time::timeout(timeout, self.open_catalog_watch(session))
            .await
            .map_err(|_| Error::CatalogWatch("open timed out".to_owned()))?
    }

    async fn open_catalog_watch(&self, session: &VfsSession) -> Result<CatalogWatch, Error> {
        let mut endpoint = self
            .control
            .endpoint
            .join("api/v2/catalog/watch")
            .map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        endpoint
            .set_scheme(match endpoint.scheme() {
                "https" => "wss",
                "http" => "ws",
                _ => {
                    return Err(Error::InvalidEndpoint(
                        "catalog watch endpoint scheme is invalid".to_owned(),
                    ));
                }
            })
            .map_err(|()| Error::InvalidEndpoint("catalog watch endpoint is invalid".to_owned()))?;
        let mut request = endpoint
            .as_str()
            .into_client_request()
            .map_err(|_| Error::CatalogWatch("construct WebSocket request".to_owned()))?;
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.token.encode()))
                .map_err(|_| Error::CatalogWatch("construct authorization header".to_owned()))?,
        );
        request.headers_mut().insert(
            "Skydriver-Protocol-Epoch",
            HeaderValue::from_str(&PROTOCOL_EPOCH.to_string())
                .map_err(|_| Error::CatalogWatch("construct protocol header".to_owned()))?,
        );
        request.headers_mut().insert(
            "Skydriver-SDK-Version",
            HeaderValue::from_static(SDK_VERSION),
        );
        let configuration = WebSocketConfig {
            write_buffer_size: 8 * 1024,
            max_write_buffer_size: MAXIMUM_WATCH_MESSAGE_BYTES,
            max_message_size: Some(MAXIMUM_WATCH_MESSAGE_BYTES),
            max_frame_size: Some(MAXIMUM_WATCH_MESSAGE_BYTES),
            ..WebSocketConfig::default()
        };
        let (mut socket, response) = connect_async_with_config(request, Some(configuration), false)
            .await
            .map_err(watch_transport)?;
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(Error::Rejected {
                status: response.status().as_u16(),
                message: "catalog watch upgrade rejected".to_owned(),
            });
        }
        let current = next_event(&mut socket, &session.root_directory_id, None).await?;
        Ok(CatalogWatch {
            socket,
            root_directory_id: session.root_directory_id.clone(),
            current,
        })
    }
}

impl CatalogWatch {
    /// Returns the most recent freshly authorized head receipt.
    #[must_use]
    pub const fn current(&self) -> &CatalogWatchEvent {
        &self.current
    }

    /// Waits for the next freshly authorized head receipt.
    ///
    /// Duplicate receipts are accepted, while a revision regression or a
    /// different identity at the same revision fails closed. Any error should
    /// make the caller discard this acceleration channel and use HTTP.
    ///
    /// # Errors
    ///
    /// Returns an error for a disconnect, bounded transport failure, malformed
    /// event, identity fork, or revision regression.
    pub async fn next_event(&mut self) -> Result<CatalogWatchEvent, Error> {
        let event = next_event(
            &mut self.socket,
            &self.root_directory_id,
            Some(&self.current),
        )
        .await?;
        self.current = event.clone();
        Ok(event)
    }

    /// Requests an immediate server-side reauthorization and current-head
    /// receipt without reconnecting the WebSocket.
    ///
    /// # Errors
    ///
    /// Returns an error when the refresh cannot be sent or the server closes,
    /// rejects, or returns an invalid current-head receipt.
    pub async fn refresh(&mut self) -> Result<CatalogWatchEvent, Error> {
        self.socket
            .send(Message::Text("refresh".to_owned()))
            .await
            .map_err(watch_transport)?;
        self.next_event().await
    }

    /// Closes the optional watch channel cleanly.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport cannot complete the close frame.
    pub async fn close(mut self) -> Result<(), Error> {
        self.socket.close(None).await.map_err(watch_transport)
    }
}

async fn next_event(
    socket: &mut WatchSocket,
    root_directory_id: &str,
    previous: Option<&CatalogWatchEvent>,
) -> Result<CatalogWatchEvent, Error> {
    loop {
        let message = socket
            .next()
            .await
            .ok_or_else(|| Error::CatalogWatch("connection closed".to_owned()))?
            .map_err(watch_transport)?;
        match message {
            Message::Text(text) => {
                if text.len() > MAXIMUM_WATCH_MESSAGE_BYTES {
                    return Err(Error::CatalogWatch("message exceeds byte bound".to_owned()));
                }
                let event: CatalogWatchEvent = serde_json::from_str(&text)
                    .map_err(|_| Error::CatalogWatch("decode catalog head event".to_owned()))?;
                validate_event(&event, root_directory_id, previous)?;
                return Ok(event);
            }
            Message::Ping(payload) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(watch_transport)?;
            }
            Message::Pong(_) | Message::Frame(_) => {}
            Message::Close(_) => {
                return Err(Error::CatalogWatch("connection closed".to_owned()));
            }
            Message::Binary(_) => {
                return Err(Error::CatalogWatch(
                    "binary catalog watch event is invalid".to_owned(),
                ));
            }
        }
    }
}

fn validate_event(
    event: &CatalogWatchEvent,
    root_directory_id: &str,
    previous: Option<&CatalogWatchEvent>,
) -> Result<(), Error> {
    if event.schema != "carrack.vfs.catalog-watch.v1"
        || event.kind != "catalog_head"
        || event.revision_id == 0
        || event.root_directory_id != root_directory_id
        || !valid_nonzero_hex::<16>(&event.filesystem_id)
        || !valid_nonzero_hex::<16>(&event.root_directory_id)
        || !valid_nonzero_hex::<32>(&event.root_data_root)
        || skydriver_sdk_core::validate_catalog_checkpoint_etag(&event.etag).is_err()
    {
        return Err(Error::CatalogWatch(
            "catalog head event identity is invalid".to_owned(),
        ));
    }
    if let Some(previous) = previous
        && (event.filesystem_id != previous.filesystem_id
            || event.revision_id < previous.revision_id
            || (event.revision_id == previous.revision_id && event != previous))
    {
        return Err(Error::CatalogWatch(
            "catalog head event regressed or forked".to_owned(),
        ));
    }
    Ok(())
}

fn valid_nonzero_hex<const N: usize>(value: &str) -> bool {
    skydriver_sdk_core::decode_lower_hex::<N>(value)
        .is_ok_and(|decoded| decoded.iter().any(|byte| *byte != 0))
}

fn watch_transport(error: tokio_tungstenite::tungstenite::Error) -> Error {
    if let tokio_tungstenite::tungstenite::Error::Http(response) = error {
        return Error::Rejected {
            status: response.status().as_u16(),
            message: "catalog watch upgrade rejected".to_owned(),
        };
    }
    Error::CatalogWatch("transport unavailable".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Request as ServerRequest, Response as ServerResponse},
    };

    use crate::{VfsSession, VfsToken};

    fn event(revision_id: u64) -> CatalogWatchEvent {
        CatalogWatchEvent {
            schema: "carrack.vfs.catalog-watch.v1".to_owned(),
            kind: "catalog_head".to_owned(),
            filesystem_id: "019f0000000000000000000000000001".to_owned(),
            revision_id,
            root_directory_id: "019f0000000000000000000000000002".to_owned(),
            root_data_root: "11".repeat(32),
            etag: skydriver_sdk_core::catalog_checkpoint_etag(&"22".repeat(32))
                .expect("valid etag"),
        }
    }

    #[test]
    fn watch_event_accepts_monotonic_duplicates_and_advances() {
        let first = event(7);
        validate_event(&first, &first.root_directory_id, None).expect("initial event");
        validate_event(&first, &first.root_directory_id, Some(&first)).expect("duplicate");
        validate_event(&event(8), &first.root_directory_id, Some(&first)).expect("advance");
    }

    #[test]
    fn watch_event_rejects_regression_and_same_revision_fork() {
        let first = event(7);
        assert!(validate_event(&event(6), &first.root_directory_id, Some(&first)).is_err());
        let mut fork = first.clone();
        fork.root_data_root = "33".repeat(32);
        assert!(validate_event(&fork, &first.root_directory_id, Some(&first)).is_err());
    }

    #[test]
    fn watch_event_rejects_wrong_authority_root_and_unknown_fields() {
        let first = event(7);
        assert!(validate_event(&first, "019f0000000000000000000000000003", None).is_err());
        let mut encoded = serde_json::to_value(&first).expect("encode event");
        encoded["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<CatalogWatchEvent>(encoded).is_err());
    }

    #[tokio::test]
    #[allow(
        clippy::result_large_err,
        reason = "the tungstenite handshake callback owns its fixed HTTP rejection type"
    )]
    async fn watch_transport_keeps_bearer_out_of_url_and_reauthorizes_on_refresh() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind watch server");
        let address = listener.local_addr().expect("watch server address");
        let encoded_token = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let token_not_in_url = encoded_token.clone();
        let expected_authorization = format!("Bearer {encoded_token}");
        let sent = event(7);
        let refreshed = event(8);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept watch client");
            let mut socket = accept_hdr_async(
                stream,
                move |request: &ServerRequest, response: ServerResponse| {
                    assert_eq!(request.uri().path(), "/api/v2/catalog/watch");
                    assert_eq!(
                        request
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok()),
                        Some(expected_authorization.as_str())
                    );
                    assert!(!request.uri().to_string().contains(&token_not_in_url));
                    assert_eq!(
                        request
                            .headers()
                            .get("skydriver-protocol-epoch")
                            .and_then(|v| v.to_str().ok()),
                        Some("2")
                    );
                    Ok(response)
                },
            )
            .await
            .expect("upgrade watch client");
            socket
                .send(Message::Text(
                    serde_json::to_string(&sent).expect("encode initial watch event"),
                ))
                .await
                .expect("send initial watch event");
            assert_eq!(
                socket
                    .next()
                    .await
                    .expect("refresh message")
                    .expect("valid refresh"),
                Message::Text("refresh".to_owned())
            );
            socket
                .send(Message::Text(
                    serde_json::to_string(&refreshed).expect("encode refreshed watch event"),
                ))
                .await
                .expect("send refreshed watch event");
        });

        let client = VfsClient::new(
            &format!("http://{address}"),
            VfsToken::parse(&encoded_token).expect("valid VFS token"),
        )
        .expect("watch client");
        let session = VfsSession {
            schema: "carrack.vfs.session.v1".to_owned(),
            token_id: "019f0000000000000000000000000003".to_owned(),
            principal_id: "019f0000000000000000000000000004".to_owned(),
            root_directory_id: "019f0000000000000000000000000002".to_owned(),
            expires_at: u64::MAX,
        };
        let mut watch = client
            .watch_catalog_for_session(&session)
            .await
            .expect("open catalog watch");
        assert_eq!(watch.current().revision_id, 7);
        assert_eq!(watch.refresh().await.expect("refresh watch").revision_id, 8);
        server.await.expect("watch server completes");
    }

    #[tokio::test]
    async fn watch_open_timeout_bounds_an_optional_acceleration_miss() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalled watch server");
        let address = listener.local_addr().expect("watch server address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept watch client");
            std::future::pending::<()>().await;
        });
        let client = VfsClient::new(
            &format!("http://{address}"),
            VfsToken::parse(&URL_SAFE_NO_PAD.encode([7_u8; 32])).expect("valid VFS token"),
        )
        .expect("watch client");
        let session = VfsSession {
            schema: "carrack.vfs.session.v1".to_owned(),
            token_id: "019f0000000000000000000000000003".to_owned(),
            principal_id: "019f0000000000000000000000000004".to_owned(),
            root_directory_id: "019f0000000000000000000000000002".to_owned(),
            expires_at: u64::MAX,
        };

        let Err(error) = client
            .watch_catalog_for_session_with_timeout(&session, Duration::from_millis(20))
            .await
        else {
            panic!("stalled optional watch must time out");
        };
        assert!(matches!(error, Error::CatalogWatch(message) if message == "open timed out"));
        server.abort();
    }
}
