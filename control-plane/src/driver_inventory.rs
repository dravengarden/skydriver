//! Provider inventory adapters behind one hosted-driver boundary.
//!
//! D1 scheduling, credential renewal and opening, quarantine, and generation
//! commits remain in `vfs_provider_inventory`. This module only performs one
//! bounded provider listing step using already-authorized authority.

use serde::{Deserialize, Serialize};
use serde_json::json;
use skydriver_driver_contract::{AliyunDriveConfig, DriverKind, R2Config};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, Result, wasm_bindgen::JsValue};

use crate::{aws_s3_signing, driver_renewal::AliyunCredential, environment_defaults, r2_signing};

const PAGE_SIZE: u32 = 100;
const MAXIMUM_ALIYUN_PAGES_PER_RUN: usize = 8;
const MAXIMUM_ALIYUN_CURSOR_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct ObservedObject {
    pub(crate) storage_key: String,
    pub(crate) provider_version: String,
    pub(crate) size_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct ProviderPage {
    pub(crate) objects: Vec<ObservedObject>,
    pub(crate) next_cursor: Option<String>,
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
struct AliyunListResponse {
    #[serde(default)]
    items: Vec<AliyunFile>,
    #[serde(default)]
    next_marker: String,
}

#[derive(Deserialize)]
struct AliyunFile {
    #[serde(default)]
    file_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    size: Option<i64>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AliyunCursor {
    stack: Vec<AliyunFrame>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AliyunFrame {
    folder_id: String,
    path: String,
    marker: String,
}

pub(crate) async fn list_page(
    env: &Env,
    kind: DriverKind,
    config_json: &str,
    cursor: Option<&str>,
    credential_plaintext: Option<&[u8]>,
) -> Result<ProviderPage> {
    match kind {
        DriverKind::R2V1 => list_r2_page(env, config_json, cursor).await,
        DriverKind::AliyunDriveOpenV2 => {
            let plaintext = credential_plaintext.ok_or_else(|| {
                worker::Error::RustError("Aliyun inventory authority is missing".to_owned())
            })?;
            let credential =
                serde_json::from_slice::<AliyunCredential>(plaintext).map_err(|error| {
                    worker::Error::RustError(format!("decode Aliyun inventory credential: {error}"))
                })?;
            list_aliyun_page(config_json, cursor, &credential).await
        }
        DriverKind::AwsS3V1 => {
            let plaintext = credential_plaintext.ok_or_else(|| {
                worker::Error::RustError("AWS S3 inventory authority is missing".to_owned())
            })?;
            if !aws_s3_signing::authority_healthy(config_json, plaintext).await {
                return Err(worker::Error::RustError(
                    "AWS S3 inventory requires an unversioned bucket".to_owned(),
                ));
            }
            let config = serde_json::from_str::<aws_s3_signing::Config>(config_json)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            let credential = serde_json::from_slice::<aws_s3_signing::Credential>(plaintext)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            let page = aws_s3_signing::list_page(&config, &credential, cursor, PAGE_SIZE)
                .await
                .map_err(|failure| {
                    worker::Error::RustError(format!("AWS S3 inventory failed: {failure:?}"))
                })?;
            Ok(ProviderPage {
                objects: page
                    .objects
                    .into_iter()
                    .map(|object| ObservedObject {
                        storage_key: object.storage_key,
                        provider_version: object.etag,
                        size_bytes: object.size_bytes,
                    })
                    .collect(),
                next_cursor: page.next_cursor,
            })
        }
        DriverKind::LocalFilesystemV2 => Err(worker::Error::RustError(
            "agent-host inventory reached hosted adapter".to_owned(),
        )),
    }
}

pub(crate) fn execution_available(env: &Env, kind: DriverKind, config_json: &str) -> Result<bool> {
    match kind {
        DriverKind::AliyunDriveOpenV2 | DriverKind::AwsS3V1 => Ok(true),
        DriverKind::R2V1 => {
            let config = serde_json::from_str::<R2Config>(config_json)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            environment_defaults::is_managed_r2_config(env, &config)
        }
        DriverKind::LocalFilesystemV2 => Ok(false),
    }
}

async fn list_r2_page(env: &Env, config_json: &str, cursor: Option<&str>) -> Result<ProviderPage> {
    let config = serde_json::from_str::<R2Config>(config_json)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    if !r2_signing::valid_config(&config) {
        return Err(worker::Error::RustError(
            "invalid R2 inventory configuration".to_owned(),
        ));
    }
    let bucket = env.bucket("SKYDRIVER_PAYLOAD")?;
    let mut list = bucket.list().limit(PAGE_SIZE).prefix(config.prefix.clone());
    if let Some(cursor) = cursor {
        list = list.cursor(cursor);
    }
    let listed = list.execute().await?;
    let objects = listed
        .objects()
        .into_iter()
        .filter_map(|object| {
            let key = object.key();
            let storage_key = key.strip_prefix(&config.prefix)?.to_owned();
            (!storage_key.is_empty()).then(|| ObservedObject {
                storage_key,
                provider_version: object.version(),
                size_bytes: object.size(),
            })
        })
        .collect();
    Ok(ProviderPage {
        objects,
        next_cursor: listed.truncated().then(|| listed.cursor()).flatten(),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "bounded recursive listing, cursor advancement, and object projection form one provider-page protocol"
)]
async fn list_aliyun_page(
    config_json: &str,
    cursor: Option<&str>,
    credential: &AliyunCredential,
) -> Result<ProviderPage> {
    let config = serde_json::from_str::<AliyunDriveConfig>(config_json)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let _ = config.upload_part_bytes;
    if !config.api_base_url.starts_with("https://") || config.api_base_url.ends_with('/') {
        return Err(worker::Error::RustError(
            "unsafe Aliyun inventory API base URL".to_owned(),
        ));
    }
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
    let mut traversal = match cursor {
        Some(encoded) => serde_json::from_str::<AliyunCursor>(encoded).map_err(|error| {
            worker::Error::RustError(format!("invalid Aliyun inventory cursor: {error}"))
        })?,
        None => AliyunCursor {
            stack: vec![AliyunFrame {
                folder_id: config.root_folder_id,
                path: String::new(),
                marker: String::new(),
            }],
        },
    };
    let mut objects = Vec::new();
    for _ in 0..MAXIMUM_ALIYUN_PAGES_PER_RUN {
        let Some(frame) = traversal.stack.pop() else {
            break;
        };
        let page: AliyunListResponse = aliyun_post(
            &config.api_base_url,
            "/adrive/v1.0/openFile/list",
            &credential.access_token,
            &json!({
                "drive_id": drive_id,
                "parent_file_id": frame.folder_id,
                "limit": PAGE_SIZE,
                "marker": frame.marker,
                "order_by": "name",
                "order_direction": "ASC"
            }),
        )
        .await?;
        if !page.next_marker.is_empty() {
            traversal.stack.push(AliyunFrame {
                folder_id: frame.folder_id,
                path: frame.path.clone(),
                marker: page.next_marker,
            });
        }
        let mut folders = Vec::new();
        for item in page.items {
            let Some(file_id) = item.file_id else {
                continue;
            };
            let Some(name) = item.name.filter(|name| !name.is_empty()).or(item.file_name) else {
                continue;
            };
            let path = if frame.path.is_empty() {
                name
            } else {
                format!("{}/{name}", frame.path)
            };
            match item.kind.as_deref() {
                Some("folder") if !file_id.is_empty() => folders.push(AliyunFrame {
                    folder_id: file_id,
                    path,
                    marker: String::new(),
                }),
                Some("file") if !file_id.is_empty() && item.size.is_some_and(|size| size >= 0) => {
                    objects.push(ObservedObject {
                        storage_key: path,
                        provider_version: file_id,
                        size_bytes: u64::try_from(item.size.unwrap_or_default())
                            .unwrap_or_default(),
                    });
                }
                _ => {}
            }
        }
        traversal.stack.extend(folders.into_iter().rev());
        if objects.len() >= usize::try_from(PAGE_SIZE).unwrap_or(usize::MAX) {
            break;
        }
    }
    let next_cursor = if traversal.stack.is_empty() {
        None
    } else {
        let encoded = serde_json::to_string(&traversal)
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
        if encoded.len() > MAXIMUM_ALIYUN_CURSOR_BYTES {
            return Err(worker::Error::RustError(
                "Aliyun inventory cursor exceeds the bounded state limit".to_owned(),
            ));
        }
        Some(encoded)
    };
    Ok(ProviderPage {
        objects,
        next_cursor,
    })
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
    if !(200..300).contains(&response.status_code()) {
        return Err(worker::Error::RustError(format!(
            "Aliyun inventory API returned HTTP {}",
            response.status_code()
        )));
    }
    response.json::<T>().await
}

#[cfg(test)]
mod tests {
    use skydriver_driver_contract::DriverKind;

    #[test]
    fn agent_host_driver_cannot_enter_hosted_inventory() {
        assert_eq!(
            DriverKind::LocalFilesystemV2.inventory_mode(),
            skydriver_driver_contract::InventoryMode::AgentHost
        );
    }
}
