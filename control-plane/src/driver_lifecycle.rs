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

use crate::{driver_credentials::AliyunCredential, environment_defaults, r2_signing};

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

pub(crate) async fn delete_object(
    env: &Env,
    kind: DriverKind,
    config_json: &str,
    storage_key: &str,
    native_id: Option<&str>,
    credential_plaintext: Option<&[u8]>,
) -> Result<()> {
    match kind {
        DriverKind::AliyunDriveOpenV2 => {
            delete_aliyun(
                config_json,
                native_id.ok_or_else(|| {
                    worker::Error::RustError(
                        "Aliyun lifecycle task has no native file ID".to_owned(),
                    )
                })?,
                credential_plaintext.ok_or_else(|| {
                    worker::Error::RustError("Aliyun lifecycle credential is incomplete".to_owned())
                })?,
            )
            .await
        }
        DriverKind::R2V1 => delete_r2(env, config_json, storage_key, credential_plaintext).await,
        DriverKind::LocalFilesystemV2 => Err(worker::Error::RustError(
            "agent-host lifecycle reached hosted adapter".to_owned(),
        )),
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
        return bucket.delete(key).await;
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
    native_id: &str,
    credential_plaintext: &[u8],
) -> Result<()> {
    let config: AliyunDriveConfig = serde_json::from_str(config_json).map_err(|error| {
        worker::Error::RustError(format!("decode Aliyun lifecycle configuration: {error}"))
    })?;
    let _ = (&config.root_folder_id, config.upload_part_bytes);
    if !config.api_base_url.starts_with("https://") || config.api_base_url.ends_with('/') {
        return Err(worker::Error::RustError(
            "unsafe Aliyun API base URL".to_owned(),
        ));
    }
    let mut credential =
        serde_json::from_slice::<AliyunCredential>(credential_plaintext).map_err(|error| {
            worker::Error::RustError(format!("decode Aliyun lifecycle credential: {error}"))
        })?;
    let drive: DriveInfo = aliyun_post(
        &config.api_base_url,
        "/adrive/v1.0/user/getDriveInfo",
        &credential.access_token,
        &json!({}),
    )
    .await?;
    let drive_id = match config.drive_type.as_str() {
        "default" => drive.default_drive_id,
        "resource" => drive.resource_drive_id,
        "backup" => drive.backup_drive_id,
        _ => {
            return Err(worker::Error::RustError(
                "invalid Aliyun drive type".to_owned(),
            ));
        }
    };
    let result = aliyun_post::<serde_json::Value>(
        &config.api_base_url,
        "/adrive/v1.0/openFile/delete",
        &credential.access_token,
        &json!({"drive_id": drive_id, "file_id": native_id}),
    )
    .await;
    credential.access_token.zeroize();
    result.map(|_| ())
}

async fn delete_r2(
    env: &Env,
    config_json: &str,
    storage_key: &str,
    credential_plaintext: Option<&[u8]>,
) -> Result<()> {
    let config = serde_json::from_str::<R2Config>(config_json).map_err(|error| {
        worker::Error::RustError(format!("decode R2 lifecycle configuration: {error}"))
    })?;
    let key = r2_signing::object_key(&config, storage_key)
        .ok_or_else(|| worker::Error::RustError("invalid R2 lifecycle storage key".to_owned()))?;
    if environment_defaults::is_managed_r2_config(env, &config)? {
        return env.bucket("CARRACK_PAYLOAD")?.delete(key).await;
    }
    let credential_plaintext = credential_plaintext.ok_or_else(|| {
        worker::Error::RustError("R2 lifecycle credential is incomplete".to_owned())
    })?;
    r2_signing::delete_from_plaintext(config_json, storage_key, credential_plaintext).await
}

fn missing_multipart_upload(rendered_error: &str) -> bool {
    rendered_error.contains("NoSuchUpload")
        || (rendered_error.contains("multipart upload")
            && rendered_error.contains("does not exist"))
}

async fn aliyun_post<T: for<'de> Deserialize<'de>>(
    base: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<T> {
    let headers = Headers::new();
    headers.set("Authorization", &format!("Bearer {token}"))?;
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body.to_string())));
    let request = Request::new_with_init(&format!("{base}{path}"), &init)?;
    let mut response = Fetch::Request(request).send().await?;
    if response.status_code() == 404 {
        return serde_json::from_value(json!({}))
            .map_err(|error| worker::Error::RustError(error.to_string()));
    }
    if !(200..300).contains(&response.status_code()) {
        return Err(worker::Error::RustError(format!(
            "Aliyun delete API returned HTTP {}",
            response.status_code()
        )));
    }
    if response.status_code() == 204 {
        return serde_json::from_value(json!({}))
            .map_err(|error| worker::Error::RustError(error.to_string()));
    }
    response.json::<T>().await
}

#[cfg(test)]
mod tests {
    use super::missing_multipart_upload;

    #[test]
    fn recognizes_only_idempotent_missing_multipart_errors() {
        assert!(missing_multipart_upload("R2Error: NoSuchUpload"));
        assert!(missing_multipart_upload("multipart upload does not exist"));
        assert!(!missing_multipart_upload("R2Error: AccessDenied"));
    }
}
