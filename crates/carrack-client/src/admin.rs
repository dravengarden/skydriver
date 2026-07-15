//! Strict redacted management-plane reads.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Method, header::SET_COOKIE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Client, Error, MAXIMUM_CONTROL_BODY_BYTES, PROTOCOL_EPOCH, SDK_VERSION, decode_json};

const SNAPSHOT_SCHEMA: &str = "carrack.management.snapshot.v2";
const EVENTS_SCHEMA: &str = "carrack.management.events.v1";
const DIRECTORY_SCHEMA: &str = "carrack.management.directory.v1";
const TRANSFER_METRICS_SCHEMA: &str = "carrack.management.transfer-metrics.v1";
const TOKEN_ANNOTATION_VALIDATION_SCHEMA: &str =
    "carrack.management.token-annotation-validation.v1";
const TOKEN_ANNOTATION_RECEIPT_SCHEMA: &str = "carrack.management.token-annotation-receipt.v1";
const DRIVER_STATE_VALIDATION_SCHEMA: &str = "carrack.management.driver-state-validation.v1";
const DRIVER_STATE_RECEIPT_SCHEMA: &str = "carrack.management.driver-state-receipt.v1";
const DRIVER_REGISTRATION_VALIDATION_SCHEMA: &str =
    "carrack.management.driver-registration-validation.v1";
const DRIVER_REGISTRATION_RECEIPT_SCHEMA: &str =
    "carrack.management.driver-registration-receipt.v1";
const DRIVER_CREDENTIAL_VALIDATION_SCHEMA: &str =
    "carrack.management.driver-credential-validation.v1";
const DRIVER_CREDENTIAL_RECEIPT_SCHEMA: &str = "carrack.management.driver-credential-receipt.v1";
const QUOTA_VALIDATION_SCHEMA: &str = "carrack.management.quota-validation.v1";
const QUOTA_RECEIPT_SCHEMA: &str = "carrack.management.quota-receipt.v1";

/// Environment-scoped break-glass credential used only to mint short sessions.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OperatorCredential([u8; 32]);

impl OperatorCredential {
    /// Parses one canonical unpadded base64url credential.
    ///
    /// # Errors
    ///
    /// Rejects non-canonical, zero, or incorrectly sized credentials.
    pub fn parse(encoded: &str) -> Result<Self, Error> {
        let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            Error::InvalidResponse("invalid operator credential encoding".to_owned())
        })?;
        if decoded.len() != 32
            || URL_SAFE_NO_PAD.encode(&decoded) != encoded
            || decoded.iter().all(|byte| *byte == 0)
        {
            return Err(Error::InvalidResponse(
                "operator credential must canonically encode 32 nonzero bytes".to_owned(),
            ));
        }
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&decoded);
        Ok(Self(bytes))
    }

    fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

/// One redacted storage driver summary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementDriver {
    pub id: String,
    pub kind: String,
    pub lifecycle_owner: String,
    pub config: Value,
    pub enabled: bool,
    pub revision: u64,
    pub credential_present: bool,
    pub credential_rotated_at: Option<u64>,
    pub credential_expires_at: Option<u64>,
    pub credential_refresh_state: Option<String>,
    pub credential_refresh_after: Option<u64>,
    pub credential_refresh_last_succeeded_at: Option<u64>,
    pub credential_refresh_last_error_code: Option<String>,
    pub credential_refresh_token_expires_at: Option<u64>,
    pub placement_count: u64,
    pub location_count: u64,
    pub available_location_count: u64,
    pub encoded_bytes: u64,
    pub file_count: u64,
    pub quota_revision: u64,
    pub max_physical_bytes: Option<u64>,
    pub max_object_count: Option<u64>,
    pub reserved_physical_bytes: u64,
    pub reserved_object_count: u64,
    pub updated_at: u64,
}

/// One filesystem and recursive storage summary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementFilesystem {
    pub id: String,
    pub name: String,
    pub state: String,
    pub revision: u64,
    pub root_directory_id: String,
    pub directory_count: u64,
    pub file_count: u64,
    pub logical_bytes: u64,
    pub available_location_count: u64,
    pub encoded_bytes: u64,
    pub updated_at: u64,
}

/// Non-secret token authority and usage metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementToken {
    pub id: String,
    pub label: String,
    pub note: String,
    pub metadata_revision: u64,
    pub principal_id: String,
    pub principal_name: String,
    pub root_directory_id: String,
    pub root_directory_name: String,
    pub parent_token_id: Option<String>,
    pub snapshot_id: Option<String>,
    pub actions: Vec<String>,
    pub driver_ids: Vec<String>,
    pub expires_at: u64,
    pub sealed_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
}

/// Redacted operator overview with a monotonic audit cursor.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementSnapshot {
    pub schema: String,
    pub observed_at: u64,
    pub event_cursor: u64,
    pub drivers: Vec<ManagementDriver>,
    pub filesystems: Vec<ManagementFilesystem>,
    pub tokens: Vec<ManagementToken>,
}

/// One sampled daily transfer rollup.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct TransferMetricRow {
    pub day: u64,
    pub scope_kind: String,
    pub scope_id: String,
    pub direction: String,
    pub weighted_transfers: u64,
    pub weighted_bytes: u64,
    pub weighted_provider_ms: u64,
    pub weighted_total_ms: u64,
    pub weighted_retries: u64,
    pub speed_b0: u64,
    pub speed_b1: u64,
    pub speed_b2: u64,
    pub speed_b3: u64,
    pub speed_b4: u64,
    pub speed_b5: u64,
    pub speed_b6: u64,
    pub speed_b7: u64,
    pub speed_b8: u64,
    pub speed_b9: u64,
    pub speed_b10: u64,
    pub speed_b11: u64,
    pub updated_at: u64,
}

/// Bounded transfer-performance history for one management scope.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct TransferMetrics {
    pub schema: String,
    pub observed_at: u64,
    pub scope_kind: String,
    pub scope_id: String,
    pub retention_days: u64,
    pub window_days: u64,
    pub rows: Vec<TransferMetricRow>,
}

/// One redacted, durable management audit event.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementEvent {
    pub id: u64,
    pub filesystem_id: Option<String>,
    pub principal_id: Option<String>,
    pub token_id: Option<String>,
    pub event_kind: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub details: Value,
    pub created_at: u64,
}

/// One fixed-high-water, bounded management event page.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementEventPage {
    pub schema: String,
    pub observed_at: u64,
    pub after: u64,
    pub event_cursor: u64,
    pub next_after: u64,
    pub has_more: bool,
    pub events: Vec<ManagementEvent>,
}

/// Recursive collection identity and aggregate statistics.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementDirectoryIdentity {
    pub id: String,
    pub filesystem_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub data_root: String,
    pub crypto_suite: String,
    pub active_key_epoch: u64,
    pub acl_inherits: bool,
    pub revision: u64,
    pub acl_revision: u64,
    pub placement_revision: u64,
    pub child_directory_count: u64,
    pub recursive_directory_count: u64,
    pub recursive_file_count: u64,
    pub recursive_logical_bytes: u64,
    pub quota_revision: u64,
    pub max_file_bytes: Option<u64>,
    pub max_logical_bytes: Option<u64>,
    pub max_file_count: Option<u64>,
}

/// Hard quota limits; fields outside the selected scope must be absent.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct QuotaLimits {
    pub max_file_bytes: Option<u64>,
    pub max_logical_bytes: Option<u64>,
    pub max_file_count: Option<u64>,
    pub max_physical_bytes: Option<u64>,
    pub max_object_count: Option<u64>,
}

/// Server-bound quota mutation validation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct QuotaValidation {
    pub schema: String,
    pub scope: String,
    pub resource_id: String,
    pub current_limits: QuotaLimits,
    pub limits: QuotaLimits,
    pub expected_revision: u64,
    pub validation_expires_at: u64,
    pub validation_digest: String,
    pub warnings: Vec<String>,
}

/// Durable quota mutation receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct QuotaReceipt {
    pub schema: String,
    pub operation_id: String,
    pub scope: String,
    pub resource_id: String,
    #[serde(flatten)]
    pub limits: QuotaLimits,
    pub final_revision: u64,
    pub committed_at: u64,
    pub state: String,
}

/// One root-to-current path component.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementBreadcrumb {
    pub id: String,
    pub name: String,
    pub depth: u64,
}

/// One complete child entry in a management directory page.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementDirectoryEntry {
    pub name: String,
    pub kind: String,
    pub file_id: Option<String>,
    pub version_id: Option<String>,
    pub child_directory_id: Option<String>,
    pub size_bytes: u64,
    pub data_root: String,
    pub metadata_root: Option<String>,
    pub revision: u64,
    pub updated_at: u64,
    pub driver_ids: Vec<String>,
}

/// One bounded collection page and its recursive summary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct ManagementDirectory {
    pub schema: String,
    pub observed_at: u64,
    pub directory: ManagementDirectoryIdentity,
    pub breadcrumbs: Vec<ManagementBreadcrumb>,
    pub placements: Vec<String>,
    pub entries: Vec<ManagementDirectoryEntry>,
}

/// Server-normalized token annotation validation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct TokenAnnotationValidation {
    pub schema: String,
    pub token_id: String,
    pub current_label: String,
    pub current_note: String,
    pub label: String,
    pub note: String,
    pub expected_revision: u64,
    pub validation_expires_at: u64,
    pub validation_digest: String,
    pub warnings: Vec<String>,
}

/// Durable token annotation mutation receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct TokenAnnotationReceipt {
    pub schema: String,
    pub operation_id: String,
    pub token_id: String,
    pub label: String,
    pub note: String,
    pub final_revision: u64,
    pub committed_at: u64,
    pub state: String,
}

/// Server-normalized driver state validation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct DriverStateValidation {
    pub schema: String,
    pub driver_id: String,
    pub kind: String,
    pub current_enabled: bool,
    pub enabled: bool,
    pub expected_revision: u64,
    pub placement_count: u64,
    pub available_location_count: u64,
    pub validation_expires_at: u64,
    pub validation_digest: String,
    pub warnings: Vec<String>,
}

/// Durable driver state mutation receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct DriverStateReceipt {
    pub schema: String,
    pub operation_id: String,
    pub driver_id: String,
    pub enabled: bool,
    pub final_revision: u64,
    pub committed_at: u64,
    pub state: String,
}

/// Server-normalized typed driver registration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct DriverRegistrationValidation {
    pub schema: String,
    pub driver_id: String,
    pub kind: String,
    pub config: Value,
    pub enabled: bool,
    pub expected_revision: u64,
    pub requires_credential: bool,
    pub validation_expires_at: u64,
    pub validation_digest: String,
    pub warnings: Vec<String>,
}

/// Durable typed driver registration receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct DriverRegistrationReceipt {
    pub schema: String,
    pub operation_id: String,
    pub driver_id: String,
    pub kind: String,
    pub config: Value,
    pub enabled: bool,
    pub final_revision: u64,
    pub committed_at: u64,
    pub state: String,
}

/// Non-secret server validation for a write-only credential rotation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct DriverCredentialValidation {
    pub schema: String,
    pub driver_id: String,
    pub kind: String,
    pub current_credential_present: bool,
    pub credential_revision: u64,
    pub refresh_token_expires_at: u64,
    pub expected_revision: u64,
    pub validation_expires_at: u64,
    pub validation_digest: String,
    pub warnings: Vec<String>,
}

/// Durable non-secret credential rotation receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct DriverCredentialReceipt {
    pub schema: String,
    pub operation_id: String,
    pub driver_id: String,
    pub credential_id: String,
    pub credential_revision: u64,
    pub credential_expires_at: u64,
    pub refresh_token_expires_at: u64,
    pub final_revision: u64,
    pub rotated_at: u64,
    pub state: String,
}

/// Native operator client. It never exposes VFS payload access.
pub struct AdminClient {
    client: Client,
    credential: OperatorCredential,
}

impl AdminClient {
    /// Creates a strict management client.
    ///
    /// # Errors
    ///
    /// Returns an endpoint validation or HTTP-client construction error.
    pub fn new(endpoint: &str, credential: OperatorCredential) -> Result<Self, Error> {
        Ok(Self {
            client: Client::new(endpoint)?,
            credential,
        })
    }

    /// Fails fast when this binary cannot safely speak to the server.
    ///
    /// # Errors
    ///
    /// Returns the strict compatibility or transport error from the server.
    pub async fn check_compatibility(&self) -> Result<crate::ProtocolCompatibility, Error> {
        self.client.check_compatibility().await
    }

    /// Reads the redacted global management snapshot.
    ///
    /// # Errors
    ///
    /// Fails closed on authentication, transport, schema, or identity errors.
    pub async fn snapshot(&self) -> Result<ManagementSnapshot, Error> {
        let cookie = self.login().await?;
        let snapshot: ManagementSnapshot = self.request("api/admin/snapshot", &cookie).await?;
        if snapshot.schema != SNAPSHOT_SCHEMA || snapshot.observed_at == 0 {
            return Err(Error::InvalidResponse(
                "invalid management snapshot identity".to_owned(),
            ));
        }
        Ok(snapshot)
    }

    /// Reads sampled transfer performance for a global, driver, token, or directory scope.
    ///
    /// # Errors
    ///
    /// Fails closed on an unsafe scope, authentication, transport, or schema mismatch.
    pub async fn transfer_metrics(
        &self,
        scope: &str,
        scope_id: &str,
    ) -> Result<TransferMetrics, Error> {
        if !matches!(scope, "global" | "driver" | "token" | "directory")
            || scope_id.is_empty()
            || scope_id.len() > 128
            || !scope_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || (scope == "global" && scope_id != "all")
        {
            return Err(Error::InvalidResponse(
                "invalid transfer metrics scope".to_owned(),
            ));
        }
        let cookie = self.login().await?;
        let metrics: TransferMetrics = self
            .request(
                &format!("api/admin/metrics/{scope}/{scope_id}?days=400"),
                &cookie,
            )
            .await?;
        if metrics.schema != TRANSFER_METRICS_SCHEMA
            || metrics.scope_kind != scope
            || metrics.scope_id != scope_id
            || metrics.observed_at == 0
            || metrics.retention_days == 0
            || metrics.window_days != metrics.retention_days
        {
            return Err(Error::InvalidResponse(
                "invalid transfer metrics identity".to_owned(),
            ));
        }
        Ok(metrics)
    }

    /// Reads one ascending, bounded audit-event page after a monotonic cursor.
    ///
    /// Reinvoke this method with `next_after` while `has_more` is true. A page
    /// pins its server high-water mark, so concurrent appends are returned by a
    /// later call rather than extending the current response.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid bounds, authentication, transport, schema,
    /// ordering, cursor, or event identity errors.
    pub async fn events(&self, after: u64, limit: u64) -> Result<ManagementEventPage, Error> {
        if i64::try_from(after).is_err() || !(1..=250).contains(&limit) {
            return Err(Error::InvalidResponse(
                "invalid management event query".to_owned(),
            ));
        }
        let cookie = self.login().await?;
        let page: ManagementEventPage = self
            .request(
                &format!("api/admin/events?after={after}&limit={limit}"),
                &cookie,
            )
            .await?;
        validate_event_page(&page, after, limit)?;
        Ok(page)
    }

    /// Reads one directory with placements and recursive statistics.
    ///
    /// # Errors
    ///
    /// Fails closed on an unsafe identifier or invalid server response.
    pub async fn directory(&self, id: &str) -> Result<ManagementDirectory, Error> {
        if !valid_identifier(id) {
            return Err(Error::InvalidResponse(
                "invalid directory identifier".to_owned(),
            ));
        }
        let cookie = self.login().await?;
        let directory: ManagementDirectory = self
            .request(&format!("api/admin/directories/{id}"), &cookie)
            .await?;
        if directory.schema != DIRECTORY_SCHEMA || directory.directory.id != id {
            return Err(Error::InvalidResponse(
                "invalid management directory identity".to_owned(),
            ));
        }
        Ok(directory)
    }

    /// Validates a complete desired token label and note.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid input, authentication, transport, or schema errors.
    pub async fn validate_token_annotation(
        &self,
        token_id: &str,
        label: &str,
        note: &str,
        expected_revision: u64,
    ) -> Result<TokenAnnotationValidation, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            label: &'a str,
            note: &'a str,
            expected_revision: u64,
        }
        let response: TokenAnnotationValidation = self
            .post_authenticated(
                &format!("api/admin/tokens/{token_id}/annotation/validate"),
                &Request {
                    label,
                    note,
                    expected_revision,
                },
            )
            .await?;
        if response.schema != TOKEN_ANNOTATION_VALIDATION_SCHEMA
            || response.token_id != token_id
            || response.label != label.trim()
            || response.note != note.trim()
            || response.expected_revision != expected_revision
            || !valid_validation(&response.validation_digest, response.validation_expires_at)
        {
            return Err(Error::InvalidResponse(
                "invalid token annotation validation".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Applies an exact token annotation validation with an idempotency key.
    ///
    /// # Errors
    ///
    /// Fails closed when reauthentication, validation binding, or commit fails.
    pub async fn apply_token_annotation(
        &self,
        validation: &TokenAnnotationValidation,
        idempotency_key: &str,
    ) -> Result<TokenAnnotationReceipt, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            label: &'a str,
            note: &'a str,
            expected_revision: u64,
            validation_expires_at: u64,
            validation_digest: &'a str,
            idempotency_key: &'a str,
        }
        let response: TokenAnnotationReceipt = self
            .post_configured(
                &format!("api/admin/tokens/{}/annotation/apply", validation.token_id),
                &Request {
                    label: &validation.label,
                    note: &validation.note,
                    expected_revision: validation.expected_revision,
                    validation_expires_at: validation.validation_expires_at,
                    validation_digest: &validation.validation_digest,
                    idempotency_key,
                },
            )
            .await?;
        if response.schema != TOKEN_ANNOTATION_RECEIPT_SCHEMA
            || response.token_id != validation.token_id
            || response.final_revision != validation.expected_revision + 1
            || response.state != "committed"
        {
            return Err(Error::InvalidResponse(
                "invalid token annotation receipt".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Validates enabling or disabling one driver at an observed revision.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid input, authentication, transport, or schema errors.
    pub async fn validate_driver_state(
        &self,
        driver_id: &str,
        enabled: bool,
        expected_revision: u64,
    ) -> Result<DriverStateValidation, Error> {
        #[derive(Serialize)]
        struct Request {
            enabled: bool,
            expected_revision: u64,
        }
        let response: DriverStateValidation = self
            .post_authenticated(
                &format!("api/admin/drivers/{driver_id}/state/validate"),
                &Request {
                    enabled,
                    expected_revision,
                },
            )
            .await?;
        if response.schema != DRIVER_STATE_VALIDATION_SCHEMA
            || response.driver_id != driver_id
            || response.enabled != enabled
            || response.expected_revision != expected_revision
            || !valid_validation(&response.validation_digest, response.validation_expires_at)
        {
            return Err(Error::InvalidResponse(
                "invalid driver state validation".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Applies an exact driver state validation.
    ///
    /// # Errors
    ///
    /// Fails closed when reauthentication, validation binding, or commit fails.
    pub async fn apply_driver_state(
        &self,
        validation: &DriverStateValidation,
        idempotency_key: &str,
    ) -> Result<DriverStateReceipt, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            enabled: bool,
            expected_revision: u64,
            validation_expires_at: u64,
            validation_digest: &'a str,
            idempotency_key: &'a str,
        }
        let response: DriverStateReceipt = self
            .post_configured(
                &format!("api/admin/drivers/{}/state/apply", validation.driver_id),
                &Request {
                    enabled: validation.enabled,
                    expected_revision: validation.expected_revision,
                    validation_expires_at: validation.validation_expires_at,
                    validation_digest: &validation.validation_digest,
                    idempotency_key,
                },
            )
            .await?;
        if response.schema != DRIVER_STATE_RECEIPT_SCHEMA
            || response.driver_id != validation.driver_id
            || response.enabled != validation.enabled
            || response.final_revision != validation.expected_revision + 1
            || response.state != "committed"
        {
            return Err(Error::InvalidResponse(
                "invalid driver state receipt".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Validates one typed, disabled driver registration.
    ///
    /// # Errors
    ///
    /// Fails closed on an unsupported configuration or invalid response.
    pub async fn validate_driver_registration(
        &self,
        driver_id: &str,
        kind: &str,
        config: &Value,
    ) -> Result<DriverRegistrationValidation, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            driver_id: &'a str,
            kind: &'a str,
            config: &'a Value,
        }
        let response: DriverRegistrationValidation = self
            .post_authenticated(
                "api/admin/drivers/registration/validate",
                &Request {
                    driver_id,
                    kind,
                    config,
                },
            )
            .await?;
        if response.schema != DRIVER_REGISTRATION_VALIDATION_SCHEMA
            || response.driver_id != driver_id
            || response.kind != kind
            || response.enabled
            || response.expected_revision != 0
            || !valid_validation(&response.validation_digest, response.validation_expires_at)
        {
            return Err(Error::InvalidResponse(
                "invalid driver registration validation".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Applies an exact typed driver registration validation.
    ///
    /// # Errors
    ///
    /// Fails closed when reauthentication, validation binding, or commit fails.
    pub async fn apply_driver_registration(
        &self,
        validation: &DriverRegistrationValidation,
        idempotency_key: &str,
    ) -> Result<DriverRegistrationReceipt, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            driver_id: &'a str,
            kind: &'a str,
            config: &'a Value,
            validation_expires_at: u64,
            validation_digest: &'a str,
            idempotency_key: &'a str,
        }
        let response: DriverRegistrationReceipt = self
            .post_configured(
                "api/admin/drivers/registration/apply",
                &Request {
                    driver_id: &validation.driver_id,
                    kind: &validation.kind,
                    config: &validation.config,
                    validation_expires_at: validation.validation_expires_at,
                    validation_digest: &validation.validation_digest,
                    idempotency_key,
                },
            )
            .await?;
        if response.schema != DRIVER_REGISTRATION_RECEIPT_SCHEMA
            || response.driver_id != validation.driver_id
            || response.kind != validation.kind
            || response.enabled
            || response.final_revision != 1
            || response.state != "committed"
        {
            return Err(Error::InvalidResponse(
                "invalid driver registration receipt".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Validates a write-only typed driver credential.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid secret input or invalid server response.
    pub async fn validate_driver_credential(
        &self,
        driver_id: &str,
        credential: &Value,
        expected_revision: u64,
    ) -> Result<DriverCredentialValidation, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            credential: &'a Value,
            expected_revision: u64,
        }
        let response: DriverCredentialValidation = self
            .post_authenticated(
                &format!("api/admin/drivers/{driver_id}/credential/validate"),
                &Request {
                    credential,
                    expected_revision,
                },
            )
            .await?;
        if response.schema != DRIVER_CREDENTIAL_VALIDATION_SCHEMA
            || response.driver_id != driver_id
            || response.expected_revision != expected_revision
            || response.refresh_token_expires_at == 0
            || !valid_validation(&response.validation_digest, response.validation_expires_at)
        {
            return Err(Error::InvalidResponse(
                "invalid driver credential validation".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Applies a write-only credential bound to an exact validation.
    ///
    /// # Errors
    ///
    /// Fails closed when reauthentication, validation binding, or commit fails.
    pub async fn apply_driver_credential(
        &self,
        validation: &DriverCredentialValidation,
        credential: &Value,
        idempotency_key: &str,
    ) -> Result<DriverCredentialReceipt, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            credential: &'a Value,
            expected_revision: u64,
            validation_expires_at: u64,
            validation_digest: &'a str,
            idempotency_key: &'a str,
        }
        let response: DriverCredentialReceipt = self
            .post_configured(
                &format!(
                    "api/admin/drivers/{}/credential/apply",
                    validation.driver_id
                ),
                &Request {
                    credential,
                    expected_revision: validation.expected_revision,
                    validation_expires_at: validation.validation_expires_at,
                    validation_digest: &validation.validation_digest,
                    idempotency_key,
                },
            )
            .await?;
        if response.schema != DRIVER_CREDENTIAL_RECEIPT_SCHEMA
            || response.driver_id != validation.driver_id
            || response.credential_revision != validation.credential_revision
            || response.refresh_token_expires_at == 0
            || response.final_revision != validation.expected_revision + 1
            || response.state != "committed"
        {
            return Err(Error::InvalidResponse(
                "invalid driver credential receipt".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Validates one complete hard-quota policy for a directory or driver.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid scope, limits, revision, or server response.
    pub async fn validate_quota(
        &self,
        scope: &str,
        resource_id: &str,
        limits: &QuotaLimits,
        expected_revision: u64,
    ) -> Result<QuotaValidation, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            limits: &'a QuotaLimits,
            expected_revision: u64,
        }
        let response: QuotaValidation = self
            .post_authenticated(
                &format!("api/admin/quotas/{scope}/{resource_id}/validate"),
                &Request {
                    limits,
                    expected_revision,
                },
            )
            .await?;
        if response.schema != QUOTA_VALIDATION_SCHEMA
            || response.scope != scope
            || response.resource_id != resource_id
            || response.expected_revision != expected_revision
            || !valid_validation(&response.validation_digest, response.validation_expires_at)
        {
            return Err(Error::InvalidResponse(
                "invalid quota validation".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Applies one exact server-validated hard-quota policy.
    ///
    /// # Errors
    ///
    /// Fails closed when reauthentication, CAS, validation binding, or commit fails.
    pub async fn apply_quota(
        &self,
        validation: &QuotaValidation,
        idempotency_key: &str,
    ) -> Result<QuotaReceipt, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            limits: &'a QuotaLimits,
            expected_revision: u64,
            validation_expires_at: u64,
            validation_digest: &'a str,
            idempotency_key: &'a str,
        }
        let response: QuotaReceipt = self
            .post_configured(
                &format!(
                    "api/admin/quotas/{}/{}/apply",
                    validation.scope, validation.resource_id
                ),
                &Request {
                    limits: &validation.limits,
                    expected_revision: validation.expected_revision,
                    validation_expires_at: validation.validation_expires_at,
                    validation_digest: &validation.validation_digest,
                    idempotency_key,
                },
            )
            .await?;
        if response.schema != QUOTA_RECEIPT_SCHEMA
            || response.scope != validation.scope
            || response.resource_id != validation.resource_id
            || response.final_revision != validation.expected_revision + 1
            || response.state != "committed"
        {
            return Err(Error::InvalidResponse("invalid quota receipt".to_owned()));
        }
        Ok(response)
    }

    async fn login(&self) -> Result<String, Error> {
        #[derive(Serialize)]
        struct Login<'a> {
            password: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LoginResponse {
            authenticated: bool,
        }

        let mut encoded = self.credential.encoded();
        let endpoint = self
            .client
            .endpoint
            .join("api/auth/login")
            .map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        let response_result = self
            .client
            .http
            .request(Method::POST, endpoint)
            .header("Accept", "application/json")
            .header("Carrack-Protocol-Epoch", PROTOCOL_EPOCH)
            .header("Carrack-SDK-Version", SDK_VERSION)
            .json(&Login { password: &encoded })
            .send()
            .await;
        encoded.zeroize();
        let response = response_result?;
        if !response.status().is_success() {
            return Err(Error::Rejected {
                status: response.status().as_u16(),
                message: "operator authentication failed".to_owned(),
            });
        }
        let cookie = response
            .headers()
            .get(SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .filter(|value| value.starts_with("carrack_session="))
            .ok_or_else(|| {
                Error::InvalidResponse("operator login omitted session cookie".to_owned())
            })?
            .to_owned();
        let login: LoginResponse = decode_json(response, 64 * 1024, false).await?;
        if !login.authenticated {
            return Err(Error::InvalidResponse(
                "operator login was not authenticated".to_owned(),
            ));
        }
        Ok(cookie)
    }

    async fn post_authenticated<T: for<'de> Deserialize<'de>, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let cookie = self.login().await?;
        self.post(path, &cookie, body).await
    }

    async fn post_configured<T: for<'de> Deserialize<'de>, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let session = self.login().await?;
        let configuration = self.enable_configuration(&session).await?;
        self.post(path, &format!("{session}; {configuration}"), body)
            .await
    }

    async fn enable_configuration(&self, session: &str) -> Result<String, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            password: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response {
            enabled: bool,
            expires_at: Option<u64>,
        }

        let mut encoded = self.credential.encoded();
        let endpoint = self
            .client
            .endpoint
            .join("api/auth/configuration/enable")
            .map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        let response_result = self
            .client
            .http
            .post(endpoint)
            .header("Accept", "application/json")
            .header("Carrack-Protocol-Epoch", PROTOCOL_EPOCH)
            .header("Carrack-SDK-Version", SDK_VERSION)
            .header("Cookie", session)
            .json(&Request { password: &encoded })
            .send()
            .await;
        encoded.zeroize();
        let response = response_result?;
        if !response.status().is_success() {
            return Err(Error::Rejected {
                status: response.status().as_u16(),
                message: "configuration reauthentication failed".to_owned(),
            });
        }
        let cookie = response
            .headers()
            .get(SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .filter(|value| value.starts_with("carrack_configuration="))
            .ok_or_else(|| {
                Error::InvalidResponse("configuration login omitted session cookie".to_owned())
            })?
            .to_owned();
        let enabled: Response = decode_json(response, 64 * 1024, false).await?;
        if !enabled.enabled || enabled.expires_at.is_none_or(|expiry| expiry == 0) {
            return Err(Error::InvalidResponse(
                "configuration session was not enabled".to_owned(),
            ));
        }
        Ok(cookie)
    }

    async fn post<T: for<'de> Deserialize<'de>, B: Serialize + ?Sized>(
        &self,
        path: &str,
        cookie: &str,
        body: &B,
    ) -> Result<T, Error> {
        let endpoint = self
            .client
            .endpoint
            .join(path)
            .map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        let response = self
            .client
            .http
            .post(endpoint)
            .header("Accept", "application/json")
            .header("Carrack-Protocol-Epoch", PROTOCOL_EPOCH)
            .header("Carrack-SDK-Version", SDK_VERSION)
            .header("Cookie", cookie)
            .json(body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::Rejected {
                status: response.status().as_u16(),
                message: "management request rejected".to_owned(),
            });
        }
        decode_json(response, MAXIMUM_CONTROL_BODY_BYTES, false).await
    }

    async fn request<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        cookie: &str,
    ) -> Result<T, Error> {
        let endpoint = self
            .client
            .endpoint
            .join(path)
            .map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        let response = self
            .client
            .http
            .get(endpoint)
            .header("Accept", "application/json")
            .header("Carrack-Protocol-Epoch", PROTOCOL_EPOCH)
            .header("Carrack-SDK-Version", SDK_VERSION)
            .header("Cookie", cookie)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::Rejected {
                status: response.status().as_u16(),
                message: "management request rejected".to_owned(),
            });
        }
        decode_json(response, MAXIMUM_CONTROL_BODY_BYTES, false).await
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_event_page(page: &ManagementEventPage, after: u64, limit: u64) -> Result<(), Error> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    if page.schema != EVENTS_SCHEMA
        || page.observed_at == 0
        || page.after != after
        || page.event_cursor < after
        || page.next_after < after
        || page.next_after > page.event_cursor
        || page.events.len() > limit
    {
        return Err(Error::InvalidResponse(
            "invalid management event page identity".to_owned(),
        ));
    }
    let mut previous = after;
    for event in &page.events {
        if event.id <= previous
            || event.id > page.event_cursor
            || event.created_at == 0
            || event.event_kind.is_empty()
            || event.subject_kind.is_empty()
            || event.subject_id.is_empty()
        {
            return Err(Error::InvalidResponse(
                "invalid management event ordering or identity".to_owned(),
            ));
        }
        previous = event.id;
    }
    if page.next_after != previous
        || (page.has_more && (page.events.len() != limit || page.next_after >= page.event_cursor))
        || (!page.has_more && page.next_after != page.event_cursor)
    {
        return Err(Error::InvalidResponse(
            "invalid management event continuation".to_owned(),
        ));
    }
    Ok(())
}

fn valid_validation(digest: &str, expires_at: u64) -> bool {
    expires_at > 0
        && URL_SAFE_NO_PAD
            .decode(digest)
            .is_ok_and(|decoded| decoded.len() == 32 && URL_SAFE_NO_PAD.encode(decoded) == digest)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ManagementEvent, ManagementEventPage, OperatorCredential, validate_event_page};

    #[test]
    fn rejects_noncanonical_operator_credentials() {
        assert!(OperatorCredential::parse("secret").is_err());
        assert!(OperatorCredential::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
    }

    #[test]
    fn validates_strict_management_event_continuations() {
        let event = ManagementEvent {
            id: 4,
            filesystem_id: None,
            principal_id: None,
            token_id: None,
            event_kind: "driver.updated".to_owned(),
            subject_kind: "driver".to_owned(),
            subject_id: "driver-main".to_owned(),
            details: json!({"revision": 2}),
            created_at: 100,
        };
        let complete = ManagementEventPage {
            schema: "carrack.management.events.v1".to_owned(),
            observed_at: 100,
            after: 3,
            event_cursor: 4,
            next_after: 4,
            has_more: false,
            events: vec![event.clone()],
        };
        assert!(validate_event_page(&complete, 3, 100).is_ok());

        let mut invalid = complete.clone();
        invalid.next_after = 3;
        assert!(validate_event_page(&invalid, 3, 100).is_err());

        let paged = ManagementEventPage {
            schema: "carrack.management.events.v1".to_owned(),
            observed_at: 100,
            after: 3,
            event_cursor: 8,
            next_after: 4,
            has_more: true,
            events: vec![event],
        };
        assert!(validate_event_page(&paged, 3, 1).is_ok());
        assert!(validate_event_page(&paged, 3, 2).is_err());
    }
}
