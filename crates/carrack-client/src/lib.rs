//! Native Carrack control-plane client primitives.

pub use carrack_sdk_core::{
    EncryptionDescriptor, WasmAcceptanceProof, file_merkle_root,
    file_merkle_root_from_block_digests, open, seal, wasm_acceptance_proof,
};

use reqwest::{StatusCode, Url, header::HeaderMap};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Incompatible Carrack wire-protocol generation implemented by this client.
pub const PROTOCOL_EPOCH: u64 = 2;
/// Client implementation version sent on every control-plane request.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

const COMPATIBILITY_SCHEMA: &str = "carrack.protocol-compatibility.v1";
const ERROR_SCHEMA: &str = "carrack.protocol-error.v1";
const MAXIMUM_COMPATIBILITY_BODY_BYTES: usize = 64 * 1024;
const MAXIMUM_CONTROL_BODY_BYTES: usize = 64 * 1024 * 1024;

mod admin;
mod aliyun;
mod catalog;
mod crypto;
mod download;
mod driver;
mod integrity;
mod local;
mod private_fs;
mod publication;
mod r2;
mod sync;
mod transfer;
mod vfs;
mod watch;

pub use admin::{
    AccessMutationDesired, AccessMutationReceipt, AccessMutationValidation, AdminClient,
    BootstrapAuthority, BootstrapAuthorityRequest, DriverCredentialReceipt,
    DriverCredentialValidation, DriverRegistrationReceipt, DriverRegistrationValidation,
    DriverStateReceipt, DriverStateValidation, ManagementAccess, ManagementBreadcrumb,
    ManagementDirectory, ManagementDirectoryEntry, ManagementDirectoryIdentity, ManagementDriver,
    ManagementEvent, ManagementEventPage, ManagementFilesystem, ManagementGroup,
    ManagementMembership, ManagementPrincipal, ManagementSnapshot, ManagementToken,
    OperatorAccount, OperatorCredential, ProviderInventory, ProviderInventoryStatus, QuotaLimits,
    QuotaReceipt, QuotaValidation, TokenAnnotationReceipt, TokenAnnotationValidation,
    TransferAnalytics, TransferAnalyticsQuery, TransferAnalyticsRow, TransferMetricRow,
    TransferMetrics,
};

pub use download::{GetBytesResult, GetOptions, GetResult};
pub use sync::{SyncOptions, SyncResult};
pub use transfer::{
    BoundedRangeUploadSource, PutOptions, PutReceipt, PutResult, ReplayableUploadSource,
};
pub use vfs::{
    AclGrant, AclPolicy, Directory, DirectoryCreation, DirectoryEntry, DirectoryPage, EntryKind,
    IssuedToken, Placement, PlacementPolicy, PlacementView, PolicyMutationReceipt, RemoveReceipt,
    RenameReceipt, ResolvedEntry, RevokedToken, VfsClient, VfsSession, VfsToken,
};
pub use watch::{CatalogWatch, CatalogWatchEvent};

/// Public fail-fast compatibility contract returned by the control plane.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolCompatibility {
    /// Stable response schema.
    pub schema: String,
    /// Incompatible wire-protocol generation.
    pub protocol_epoch: u64,
    /// Oldest client SDK accepted by the server.
    pub minimum_sdk_version: String,
    /// Server implementation version.
    pub server_version: String,
    /// Compatibility enforcement mode.
    pub enforcement: String,
    /// Human-readable upgrade guidance.
    pub upgrade_command: String,
}

/// Machine-readable HTTP 426 response.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradeRequired {
    /// Stable error schema.
    pub schema: String,
    /// Stable machine-readable error code.
    pub code: String,
    /// Human-readable failure summary.
    pub message: String,
    /// Protocol epoch required by the server.
    pub protocol_epoch: u64,
    /// Oldest client SDK accepted by the server.
    pub minimum_sdk_version: String,
    /// Server implementation version.
    pub server_version: String,
    /// Human-readable upgrade guidance.
    pub upgrade_command: String,
}

/// Stable correctness and availability class for failures that callers must
/// handle without parsing human-readable messages.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The supplied bearer lacks authority for the requested operation.
    MissingAuthority,
    /// The file's declared cryptographic suite is not implemented safely.
    UnsupportedSuite,
    /// Encoded provider bytes or authenticated ciphertext are corrupt.
    CorruptCiphertext,
    /// Decrypted plaintext disagrees with its committed Merkle identity.
    CorruptPlaintext,
    /// The selected provider cannot currently complete the operation.
    ProviderUnavailable,
    /// Metadata names an immutable provider object that no longer exists.
    PermanentLoss,
}

impl fmt::Display for FailureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingAuthority => "missing authority",
            Self::UnsupportedSuite => "unsupported suite",
            Self::CorruptCiphertext => "corrupt ciphertext",
            Self::CorruptPlaintext => "corrupt plaintext",
            Self::ProviderUnavailable => "provider unavailable",
            Self::PermanentLoss => "permanent loss",
        })
    }
}

/// Native client construction and protocol errors.
#[derive(Debug, Error)]
pub enum Error {
    /// The endpoint is unsafe or malformed.
    #[error("invalid Carrack control-plane endpoint: {0}")]
    InvalidEndpoint(String),
    /// The control plane requires a different client version.
    #[error("Carrack client upgrade required: {0:?}")]
    UpgradeRequired(Box<UpgradeRequired>),
    /// The control plane returned a malformed or contradictory contract.
    #[error("invalid Carrack compatibility response: {0}")]
    InvalidCompatibility(String),
    /// A non-compatibility response was malformed or exceeded its bound.
    #[error("invalid Carrack control-plane response: {0}")]
    InvalidResponse(String),
    /// The control plane rejected an authenticated request.
    #[error("Carrack control plane rejected the request with HTTP {status}: {message}")]
    Rejected {
        /// HTTP response status.
        status: u16,
        /// Bounded, redacted server response text.
        message: String,
    },
    /// A stable correctness or provider failure that must not be inferred from text.
    #[error("Carrack {kind}: {message}")]
    Failure {
        /// Stable machine-readable failure class.
        kind: FailureKind,
        /// Bounded human-readable context with no credential material.
        message: String,
    },
    /// The request could not be completed.
    #[error("Carrack control-plane request failed: {0}")]
    Transport(#[from] reqwest::Error),
    /// The optional catalog-watch acceleration channel failed.
    #[error("Carrack catalog watch failed: {0}")]
    CatalogWatch(String),
}

impl Error {
    /// Returns the stable correctness or availability class when one applies.
    #[must_use]
    pub const fn failure_kind(&self) -> Option<FailureKind> {
        match self {
            Self::Rejected {
                status: 401 | 403, ..
            } => Some(FailureKind::MissingAuthority),
            Self::Failure { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    pub(crate) fn failure(kind: FailureKind, message: impl Into<String>) -> Self {
        Self::Failure {
            kind,
            message: message.into(),
        }
    }
}

/// HTTPS control-plane client. Payload bytes never pass through this client.
#[derive(Clone, Debug)]
pub struct Client {
    pub(crate) endpoint: Url,
    pub(crate) http: reqwest::Client,
}

pub(crate) struct BoundedResponse {
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

pub(crate) enum OptionalBytesResponse {
    Unavailable,
    NotModified,
    Body(BoundedResponse),
}

impl Client {
    /// Creates a client for an HTTPS endpoint. Plain HTTP is limited to loopback tests.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEndpoint`] for malformed or unsafe URLs, or a
    /// transport error when the native HTTP client cannot be constructed.
    pub fn new(endpoint: &str) -> Result<Self, Error> {
        let mut endpoint =
            Url::parse(endpoint).map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        validate_endpoint(&endpoint)?;
        if !endpoint.path().ends_with('/') {
            endpoint.set_path(&format!("{}/", endpoint.path()));
        }
        let http = reqwest::Client::builder()
            .https_only(endpoint.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(30))
            .read_timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self { endpoint, http })
    }

    /// Fetches and strictly validates compatibility before metadata or provider I/O.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UpgradeRequired`] for incompatible peers and a strict
    /// response or transport error for malformed and unavailable peers.
    pub async fn check_compatibility(&self) -> Result<ProtocolCompatibility, Error> {
        let endpoint = self
            .endpoint
            .join("api/compatibility")
            .map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        let response = self
            .http
            .get(endpoint)
            .header("Carrack-Protocol-Epoch", PROTOCOL_EPOCH)
            .header("Carrack-SDK-Version", SDK_VERSION)
            .send()
            .await?;
        if response.status() == StatusCode::UPGRADE_REQUIRED {
            return Err(decode_upgrade_required(response).await?);
        }
        let response = decode_json::<ProtocolCompatibility>(
            response.error_for_status()?,
            MAXIMUM_COMPATIBILITY_BODY_BYTES,
            true,
        )
        .await?;
        validate_compatibility(&response)?;
        Ok(response)
    }

    pub(crate) async fn send_json<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        query: &[(&str, String)],
        body: Option<&B>,
    ) -> Result<T, Error> {
        self.send_json_bounded(method, path, token, query, body, MAXIMUM_CONTROL_BODY_BYTES)
            .await
    }

    pub(crate) async fn send_json_bounded<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        query: &[(&str, String)],
        body: Option<&B>,
        maximum_response_bytes: usize,
    ) -> Result<T, Error> {
        if path.contains("..") || !path.starts_with("api/") {
            return Err(Error::InvalidEndpoint("invalid API path".to_owned()));
        }
        let endpoint = self
            .endpoint
            .join(path)
            .map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        let mut request = self
            .http
            .request(method, endpoint)
            .header("Accept", "application/json")
            .header("Carrack-Protocol-Epoch", PROTOCOL_EPOCH)
            .header("Carrack-SDK-Version", SDK_VERSION)
            .query(query);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await?;
        if response.status() == StatusCode::UPGRADE_REQUIRED {
            let failure =
                decode_json::<UpgradeRequired>(response, MAXIMUM_COMPATIBILITY_BODY_BYTES, true)
                    .await?;
            return Err(Error::UpgradeRequired(Box::new(failure)));
        }
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = read_bounded(response, 64 * 1024, false).await?;
            let message = String::from_utf8_lossy(&body).trim().to_owned();
            return Err(Error::Rejected { status, message });
        }
        decode_json(response, maximum_response_bytes, false).await
    }

    pub(crate) async fn send_optional_bytes(
        &self,
        path: &str,
        token: &str,
        maximum_bytes: usize,
        if_none_match: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<OptionalBytesResponse, Error> {
        if path.contains("..") || !path.starts_with("api/") {
            return Err(Error::InvalidEndpoint("invalid API path".to_owned()));
        }
        let endpoint = self
            .endpoint
            .join(path)
            .map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        let mut request = self
            .http
            .get(endpoint)
            .header("Accept", "application/json")
            .header("Carrack-Protocol-Epoch", PROTOCOL_EPOCH)
            .header("Carrack-SDK-Version", SDK_VERSION)
            .bearer_auth(token);
        if let Some(etag) = if_none_match {
            request = request.header("If-None-Match", etag);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await?;
        if response.status() == StatusCode::UPGRADE_REQUIRED {
            let failure =
                decode_json::<UpgradeRequired>(response, MAXIMUM_COMPATIBILITY_BODY_BYTES, true)
                    .await?;
            return Err(Error::UpgradeRequired(Box::new(failure)));
        }
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(OptionalBytesResponse::Unavailable);
        }
        if response.status() == StatusCode::NOT_MODIFIED {
            let Some(expected) = if_none_match else {
                return Err(Error::InvalidResponse(
                    "catalog checkpoint returned 304 without a condition".to_owned(),
                ));
            };
            if response
                .headers()
                .get("etag")
                .and_then(|value| value.to_str().ok())
                != Some(expected)
            {
                return Err(Error::InvalidResponse(
                    "catalog checkpoint 304 entity tag differs".to_owned(),
                ));
            }
            return Ok(OptionalBytesResponse::NotModified);
        }
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = read_bounded(response, 64 * 1024, false).await?;
            let message = String::from_utf8_lossy(&body).trim().to_owned();
            return Err(Error::Rejected { status, message });
        }
        let headers = response.headers().clone();
        let body = read_bounded(response, maximum_bytes, false).await?;
        Ok(OptionalBytesResponse::Body(BoundedResponse {
            headers,
            body,
        }))
    }
}

pub(crate) async fn decode_upgrade_required(response: reqwest::Response) -> Result<Error, Error> {
    let failure =
        decode_json::<UpgradeRequired>(response, MAXIMUM_COMPATIBILITY_BODY_BYTES, true).await?;
    if failure.schema != ERROR_SCHEMA
        || failure.code != "sdk_upgrade_required"
        || failure.protocol_epoch == 0
        || failure.minimum_sdk_version.is_empty()
        || failure.server_version.is_empty()
        || failure.upgrade_command.is_empty()
    {
        return Err(Error::InvalidCompatibility(
            "HTTP 426 did not contain the required error identity".to_owned(),
        ));
    }
    Ok(Error::UpgradeRequired(Box::new(failure)))
}

async fn decode_json<T: DeserializeOwned>(
    response: reqwest::Response,
    maximum_bytes: usize,
    compatibility: bool,
) -> Result<T, Error> {
    let body = read_bounded(response, maximum_bytes, compatibility).await?;
    serde_json::from_slice(&body).map_err(|error| {
        if compatibility {
            Error::InvalidCompatibility(format!("decode strict JSON: {error}"))
        } else {
            Error::InvalidResponse(format!("decode strict JSON: {error}"))
        }
    })
}

async fn read_bounded(
    mut response: reqwest::Response,
    maximum_bytes: usize,
    compatibility: bool,
) -> Result<Vec<u8>, Error> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(response_limit_error(compatibility));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(response_limit_error(compatibility));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn response_limit_error(compatibility: bool) -> Error {
    if compatibility {
        Error::InvalidCompatibility("response body exceeds the compatibility limit".to_owned())
    } else {
        Error::InvalidResponse("response body exceeds the control limit".to_owned())
    }
}

fn validate_endpoint(endpoint: &Url) -> Result<(), Error> {
    if endpoint.username() != ""
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(Error::InvalidEndpoint(
            "credentials, query, and fragment are forbidden".to_owned(),
        ));
    }
    if endpoint.scheme() == "https" {
        return Ok(());
    }
    let loopback = endpoint.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse()
                .is_ok_and(|ip: std::net::IpAddr| ip.is_loopback())
    });
    if endpoint.scheme() == "http" && loopback {
        return Ok(());
    }
    Err(Error::InvalidEndpoint(
        "HTTPS is required outside loopback".to_owned(),
    ))
}

fn validate_compatibility(response: &ProtocolCompatibility) -> Result<(), Error> {
    if response.schema != COMPATIBILITY_SCHEMA
        || response.protocol_epoch != PROTOCOL_EPOCH
        || response.enforcement != "required"
        || !version_at_least(SDK_VERSION, &response.minimum_sdk_version)
        || response.server_version.is_empty()
        || response.upgrade_command.is_empty()
    {
        return Err(Error::UpgradeRequired(Box::new(UpgradeRequired {
            schema: ERROR_SCHEMA.to_owned(),
            code: "sdk_upgrade_required".to_owned(),
            message: "Carrack protocol or SDK version is incompatible".to_owned(),
            protocol_epoch: response.protocol_epoch,
            minimum_sdk_version: response.minimum_sdk_version.clone(),
            server_version: response.server_version.clone(),
            upgrade_command: response.upgrade_command.clone(),
        })));
    }
    Ok(())
}

fn version_at_least(candidate: &str, minimum: &str) -> bool {
    fn parse(value: &str) -> Option<[u64; 3]> {
        if value.contains('+') {
            return None;
        }
        let core = value.split_once('-').map_or(value, |(core, _)| core);
        let fields = core.split('.').collect::<Vec<_>>();
        if fields.len() != 3
            || fields
                .iter()
                .any(|field| field.is_empty() || (field.len() > 1 && field.starts_with('0')))
        {
            return None;
        }
        Some([
            fields[0].parse().ok()?,
            fields[1].parse().ok()?,
            fields[2].parse().ok()?,
        ])
    }
    parse(candidate)
        .zip(parse(minimum))
        .is_some_and(|(candidate, minimum)| candidate >= minimum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn rejects_unsafe_endpoints() {
        for endpoint in [
            "http://example.com",
            "https://user@example.com",
            "https://example.com?token=secret",
            "https://example.com/#fragment",
        ] {
            assert!(matches!(
                Client::new(endpoint),
                Err(Error::InvalidEndpoint(_))
            ));
        }
    }

    #[test]
    fn exposes_failure_kinds_without_message_parsing() {
        let authority = Error::Rejected {
            status: 403,
            message: "forbidden".to_owned(),
        };
        assert_eq!(
            authority.failure_kind(),
            Some(FailureKind::MissingAuthority)
        );
        for kind in [
            FailureKind::UnsupportedSuite,
            FailureKind::CorruptCiphertext,
            FailureKind::CorruptPlaintext,
            FailureKind::ProviderUnavailable,
            FailureKind::PermanentLoss,
        ] {
            assert_eq!(
                Error::failure(kind, "classified failure").failure_kind(),
                Some(kind)
            );
        }
        assert_eq!(
            Error::InvalidResponse("schema".to_owned()).failure_kind(),
            None
        );
    }

    #[tokio::test]
    async fn sends_headers_and_accepts_the_strict_contract() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("read test address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = vec![0; 4096];
            let length = stream.read(&mut request).await.expect("read request");
            let request = String::from_utf8_lossy(&request[..length]).to_ascii_lowercase();
            assert!(request.starts_with("get /api/compatibility http/1.1"));
            assert!(request.contains("carrack-protocol-epoch: 2"));
            assert!(request.contains("carrack-sdk-version: 0.3.6"));
            let body = r#"{"schema":"carrack.protocol-compatibility.v1","protocol_epoch":2,"minimum_sdk_version":"0.3.0","server_version":"0.3.2","enforcement":"required","upgrade_command":"upgrade carrack"}"#;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("write response");
        });
        let client = Client::new(&format!("http://{address}")).expect("construct client");
        let compatibility = client
            .check_compatibility()
            .await
            .expect("check compatibility");
        assert_eq!(compatibility.protocol_epoch, PROTOCOL_EPOCH);
        server.await.expect("join test server");
    }

    #[tokio::test]
    async fn preserves_machine_readable_upgrade_failure() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("read test address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = vec![0; 4096];
            let length = stream.read(&mut request).await.expect("read request");
            assert!(length > 0);
            let body = r#"{"schema":"carrack.protocol-error.v1","code":"sdk_upgrade_required","message":"upgrade","protocol_epoch":3,"minimum_sdk_version":"2.0.0","server_version":"2.0.0","upgrade_command":"upgrade carrack"}"#;
            stream.write_all(format!("HTTP/1.1 426 Upgrade Required\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("write response");
        });
        let client = Client::new(&format!("http://{address}")).expect("construct client");
        let error = client
            .check_compatibility()
            .await
            .expect_err("reject incompatible server");
        let Error::UpgradeRequired(failure) = error else {
            panic!("unexpected failure: {error:?}");
        };
        assert_eq!(failure.protocol_epoch, 3);
        assert_eq!(failure.minimum_sdk_version, "2.0.0");
        server.await.expect("join test server");
    }
}
