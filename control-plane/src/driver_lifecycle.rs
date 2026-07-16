//! Provider deletion adapters behind one server-lifecycle boundary.
//!
//! D1 claims, reachability and revision fences, retries, and credential
//! envelope opening remain in `vfs_server_lifecycle`. This module performs
//! only an already-fenced provider delete or incomplete-upload cleanup.

use carrack_driver_contract::{AliyunDriveConfig, DriverKind, R2Config};
use serde::Deserialize;
use serde_json::json;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, Result, wasm_bindgen::JsValue};
use zeroize::Zeroize as _;

use crate::{driver_renewal::AliyunCredential, environment_defaults, r2_signing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteOutcome {
    Deleted,
    AlreadyAbsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteFailure {
    Retry(&'static str),
    Reauthenticate(&'static str),
    IdentityMismatch,
    Blocked(&'static str),
}

#[derive(Clone, Copy)]
pub(crate) struct ExpectedIdentity<'a> {
    pub(crate) native_id: Option<&'a str>,
    pub(crate) provider_version: Option<&'a str>,
    pub(crate) etag: Option<&'a str>,
    pub(crate) size_bytes: u64,
}

#[derive(Deserialize)]
#[allow(
    clippy::struct_field_names,
    reason = "fields match the Aliyun wire schema"
)]
struct DriveInfo {
    default_drive_id: String,
    resource_drive_id: String,
    backup_drive_id: String,
}

#[derive(Deserialize)]
struct AliyunFile {
    #[serde(default)]
    file_id: String,
    #[serde(default)]
    size: i64,
    #[serde(default)]
    content_hash: String,
}

pub(crate) async fn delete_object(
    env: &Env,
    kind: DriverKind,
    config_json: &str,
    storage_key: &str,
    expected: ExpectedIdentity<'_>,
    credential_plaintext: Option<&[u8]>,
) -> std::result::Result<DeleteOutcome, DeleteFailure> {
    match kind {
        DriverKind::AliyunDriveOpenV2 => {
            delete_aliyun(
                config_json,
                expected,
                credential_plaintext.ok_or(DeleteFailure::Blocked("credential_incomplete"))?,
            )
            .await
        }
        DriverKind::R2V1 => {
            delete_r2(
                env,
                config_json,
                storage_key,
                expected,
                credential_plaintext,
            )
            .await
        }
        DriverKind::LocalFilesystemV2 => {
            Err(DeleteFailure::Blocked("agent_host_driver_unreachable"))
        }
    }
}

pub(crate) async fn cleanup_r2_upload(
    env: &Env,
    config_json: &str,
    storage_key: &str,
    upload_id: Option<&str>,
    credential_plaintext: Option<&[u8]>,
) -> Result<()> {
    let config = serde_json::from_str::<R2Config>(config_json).map_err(|error| {
        worker::Error::RustError(format!("decode R2 cleanup configuration: {error}"))
    })?;
    let key = r2_signing::object_key(&config, storage_key)
        .ok_or_else(|| worker::Error::RustError("invalid R2 cleanup storage key".to_owned()))?;
    if environment_defaults::is_managed_r2_config(env, &config)? {
        let bucket = env.bucket("CARRACK_PAYLOAD")?;
        if let Some(upload_id) = upload_id {
            let upload = bucket.resume_multipart_upload(&key, upload_id)?;
            if let Err(error) = upload.abort().await {
                let rendered = format!("{error:?}");
                if !missing_multipart_upload(&rendered) {
                    return Err(error);
                }
            }
        }
        return Ok(());
    }

    let credential_plaintext = credential_plaintext.ok_or_else(|| {
        worker::Error::RustError("R2 cleanup credential is incomplete".to_owned())
    })?;
    r2_signing::cleanup_upload_from_plaintext(
        config_json,
        storage_key,
        upload_id,
        credential_plaintext,
    )
    .await
}

async fn delete_aliyun(
    config_json: &str,
    expected: ExpectedIdentity<'_>,
    credential_plaintext: &[u8],
) -> std::result::Result<DeleteOutcome, DeleteFailure> {
    let config: AliyunDriveConfig = serde_json::from_str(config_json)
        .map_err(|_| DeleteFailure::Blocked("configuration_invalid"))?;
    let _ = (&config.root_folder_id, config.upload_part_bytes);
    if !config.api_base_url.starts_with("https://") || config.api_base_url.ends_with('/') {
        return Err(DeleteFailure::Blocked("configuration_invalid"));
    }
    let mut credential = serde_json::from_slice::<AliyunCredential>(credential_plaintext)
        .map_err(|_| DeleteFailure::Blocked("credential_invalid"))?;
    let drive: DriveInfo = aliyun_post_optional(
        &config.api_base_url,
        "/adrive/v1.0/user/getDriveInfo",
        &credential.access_token,
        &json!({}),
    )
    .await?
    .ok_or(DeleteFailure::Retry("provider_identity_unavailable"))?;
    let drive_id = match config.drive_type.as_str() {
        "default" => drive.default_drive_id,
        "resource" => drive.resource_drive_id,
        "backup" => drive.backup_drive_id,
        _ => {
            return Err(DeleteFailure::Blocked("configuration_invalid"));
        }
    };
    let native_id = expected
        .native_id
        .filter(|value| !value.is_empty())
        .ok_or(DeleteFailure::Blocked("stable_identity_missing"))?;
    let stored = aliyun_post_optional::<AliyunFile>(
        &config.api_base_url,
        "/adrive/v1.0/openFile/get",
        &credential.access_token,
        &json!({"drive_id": drive_id, "file_id": native_id}),
    )
    .await?;
    let Some(stored) = stored else {
        credential.access_token.zeroize();
        return Ok(DeleteOutcome::AlreadyAbsent);
    };
    if stored.file_id != native_id
        || expected.provider_version != Some(native_id)
        || u64::try_from(stored.size).ok() != Some(expected.size_bytes)
        || expected
            .etag
            .is_none_or(|etag| etag.is_empty() || etag != stored.content_hash)
    {
        credential.access_token.zeroize();
        return Err(DeleteFailure::IdentityMismatch);
    }
    let result = aliyun_post_optional::<serde_json::Value>(
        &config.api_base_url,
        "/adrive/v1.0/openFile/delete",
        &credential.access_token,
        &json!({"drive_id": drive_id, "file_id": native_id}),
    )
    .await;
    credential.access_token.zeroize();
    result.map(|deleted| deleted.map_or(DeleteOutcome::AlreadyAbsent, |_| DeleteOutcome::Deleted))
}

async fn delete_r2(
    env: &Env,
    config_json: &str,
    storage_key: &str,
    expected: ExpectedIdentity<'_>,
    credential_plaintext: Option<&[u8]>,
) -> std::result::Result<DeleteOutcome, DeleteFailure> {
    let config = serde_json::from_str::<R2Config>(config_json)
        .map_err(|_| DeleteFailure::Blocked("configuration_invalid"))?;
    let key = r2_signing::object_key(&config, storage_key)
        .ok_or(DeleteFailure::Blocked("storage_key_invalid"))?;
    if environment_defaults::is_managed_r2_config(env, &config)
        .map_err(|_| DeleteFailure::Blocked("configuration_invalid"))?
    {
        let bucket = env
            .bucket("CARRACK_PAYLOAD")
            .map_err(|_| DeleteFailure::Retry("provider_binding_unavailable"))?;
        let object = bucket
            .head(&key)
            .await
            .map_err(|_| DeleteFailure::Retry("provider_stat_failed"))?;
        let Some(object) = object else {
            return Ok(DeleteOutcome::AlreadyAbsent);
        };
        if !r2_identity_matches(object.size(), &object.etag(), expected) {
            return Err(DeleteFailure::IdentityMismatch);
        }
        bucket
            .delete(key)
            .await
            .map_err(|_| DeleteFailure::Retry("provider_delete_failed"))?;
        return Ok(DeleteOutcome::Deleted);
    }
    let credential_plaintext =
        credential_plaintext.ok_or(DeleteFailure::Blocked("credential_incomplete"))?;
    let stat = r2_signing::stat_from_plaintext(config_json, storage_key, credential_plaintext)
        .await
        .map_err(map_r2_failure)?;
    let Some(stat) = stat else {
        return Ok(DeleteOutcome::AlreadyAbsent);
    };
    if !r2_identity_matches(stat.size_bytes, &stat.etag, expected) {
        return Err(DeleteFailure::IdentityMismatch);
    }
    r2_signing::delete_from_plaintext(config_json, storage_key, credential_plaintext)
        .await
        .map_err(map_r2_failure)?;
    Ok(DeleteOutcome::Deleted)
}

fn r2_identity_matches(size: u64, etag: &str, expected: ExpectedIdentity<'_>) -> bool {
    expected.size_bytes == size
        && expected.etag.is_some_and(|value| {
            !value.is_empty() && value.trim_matches('"') == etag.trim_matches('"')
        })
}

fn map_r2_failure(failure: r2_signing::OperationFailure) -> DeleteFailure {
    match failure {
        r2_signing::OperationFailure::Retry(code) => DeleteFailure::Retry(code),
        r2_signing::OperationFailure::Reauthenticate(code) => DeleteFailure::Reauthenticate(code),
        r2_signing::OperationFailure::Blocked(code) => DeleteFailure::Blocked(code),
    }
}

fn missing_multipart_upload(rendered_error: &str) -> bool {
    rendered_error.contains("NoSuchUpload")
        || (rendered_error.contains("multipart upload")
            && rendered_error.contains("does not exist"))
}

async fn aliyun_post_optional<T: for<'de> Deserialize<'de>>(
    base: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> std::result::Result<Option<T>, DeleteFailure> {
    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {token}"))
        .map_err(|_| DeleteFailure::Blocked("provider_request_invalid"))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|_| DeleteFailure::Blocked("provider_request_invalid"))?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body.to_string())));
    let request = Request::new_with_init(&format!("{base}{path}"), &init)
        .map_err(|_| DeleteFailure::Blocked("provider_request_invalid"))?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| DeleteFailure::Retry("provider_transport_failed"))?;
    if response.status_code() == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&response.status_code()) {
        return Err(classify_status(response.status_code()));
    }
    if response.status_code() == 204 {
        return serde_json::from_value(json!({}))
            .map(Some)
            .map_err(|_| DeleteFailure::Retry("provider_response_invalid"));
    }
    response
        .json::<T>()
        .await
        .map(Some)
        .map_err(|_| DeleteFailure::Retry("provider_response_invalid"))
}

fn classify_status(status: u16) -> DeleteFailure {
    match status {
        401 | 403 => DeleteFailure::Reauthenticate("provider_authorization_rejected"),
        408 | 425 | 429 | 500..=599 => DeleteFailure::Retry("provider_unavailable"),
        _ => DeleteFailure::Blocked("provider_request_rejected"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DeleteFailure, ExpectedIdentity, classify_status, missing_multipart_upload,
        r2_identity_matches,
    };

    #[test]
    fn recognizes_only_idempotent_missing_multipart_errors() {
        assert!(missing_multipart_upload("R2Error: NoSuchUpload"));
        assert!(missing_multipart_upload("multipart upload does not exist"));
        assert!(!missing_multipart_upload("R2Error: AccessDenied"));
    }

    #[test]
    fn exact_r2_identity_requires_size_and_opaque_etag() {
        let expected = ExpectedIdentity {
            native_id: None,
            provider_version: None,
            etag: Some("provider-etag"),
            size_bytes: 42,
        };
        assert!(r2_identity_matches(42, "\"provider-etag\"", expected));
        assert!(!r2_identity_matches(41, "provider-etag", expected));
        assert!(!r2_identity_matches(42, "other", expected));
        assert!(!r2_identity_matches(
            42,
            "provider-etag",
            ExpectedIdentity {
                etag: None,
                ..expected
            }
        ));
    }

    #[test]
    fn provider_status_has_stable_lifecycle_disposition() {
        assert_eq!(
            classify_status(401),
            DeleteFailure::Reauthenticate("provider_authorization_rejected")
        );
        assert_eq!(
            classify_status(429),
            DeleteFailure::Retry("provider_unavailable")
        );
        assert_eq!(
            classify_status(422),
            DeleteFailure::Blocked("provider_request_rejected")
        );
    }
}
