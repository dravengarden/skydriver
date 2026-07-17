//! Native Aliyun Drive Open API complete-object transport.

use carrack_driver_contract::AliyunDriveConfig as Config;
use futures_util::StreamExt as _;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    io::{Read as _, Seek as _, Write as _},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, private_fs::ensure_private_directory};

const MAXIMUM_API_BODY: usize = 8 * 1024 * 1024;
const MAXIMUM_PARTS: u64 = 10_000;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Credential {
    access_token: String,
}

struct Client {
    http: reqwest::Client,
    base: Url,
    drive_id: String,
    root_folder_id: String,
    upload_part_bytes: u64,
    credential: Credential,
}

#[derive(Clone, Deserialize)]
struct FileRecord {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    file_id: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    file_name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    size: i64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    content_hash: String,
    #[serde(
        rename = "type",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    kind: String,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
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

#[derive(Serialize)]
struct ListRequest<'a> {
    drive_id: &'a str,
    parent_file_id: &'a str,
    limit: u16,
    marker: &'a str,
    order_by: &'static str,
    order_direction: &'static str,
}

#[derive(Deserialize)]
struct ListResponse {
    items: Vec<FileRecord>,
    next_marker: String,
}

#[derive(Serialize)]
struct CreateFolder<'a> {
    drive_id: &'a str,
    parent_file_id: &'a str,
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    check_name_mode: &'static str,
}

#[derive(Serialize)]
struct PartRequest {
    part_number: u64,
}

#[derive(Serialize)]
struct CreateFile<'a> {
    drive_id: &'a str,
    parent_file_id: &'a str,
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    check_name_mode: &'static str,
    part_info_list: Vec<PartRequest>,
}

#[derive(Deserialize)]
struct PartInformation {
    part_number: u64,
    upload_url: String,
}

#[derive(Deserialize)]
struct CreateFileResponse {
    file_id: String,
    upload_id: String,
    rapid_upload: bool,
    part_info_list: Vec<PartInformation>,
}

#[derive(Serialize)]
#[allow(
    clippy::struct_field_names,
    reason = "fields match the Aliyun wire schema"
)]
struct CompleteFile<'a> {
    drive_id: &'a str,
    file_id: &'a str,
    upload_id: &'a str,
}

#[derive(Serialize)]
struct DownloadUrlRequest<'a> {
    drive_id: &'a str,
    file_id: &'a str,
    expire_sec: u32,
}

#[derive(Deserialize)]
struct DownloadUrlResponse {
    url: String,
}

pub(crate) struct UploadedObject {
    pub(crate) native_id: String,
    pub(crate) provider_version: String,
    pub(crate) etag: String,
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the typed adapter binds one immutable grant to multipart publication and readback"
)]
pub(crate) async fn upload(
    http: &reqwest::Client,
    config: &Value,
    credential: Value,
    storage_key: &str,
    source: &Path,
    size_bytes: u64,
    encoded_sha256: &str,
) -> Result<UploadedObject, Error> {
    let client = Client::open(http, config, credential).await?;
    let (parent, name) = client.ensure_parent(storage_key).await?;
    let part_count = size_bytes.div_ceil(client.upload_part_bytes).max(1);
    if part_count > MAXIMUM_PARTS {
        return Err(Error::InvalidResponse(
            "Aliyun upload exceeds its part limit".to_owned(),
        ));
    }
    let request = CreateFile {
        drive_id: &client.drive_id,
        parent_file_id: &parent.file_id,
        name: &name,
        kind: "file",
        check_name_mode: "refuse",
        part_info_list: (1..=part_count)
            .map(|part_number| PartRequest { part_number })
            .collect(),
    };
    let created: CreateFileResponse = match client
        .api("/adrive/v1.0/openFile/create", &request)
        .await
    {
        Ok(created) => created,
        Err(create_error) => {
            let existing = client.resolve(storage_key).await?;
            if existing.kind == "folder" || u64::try_from(existing.size).ok() != Some(size_bytes) {
                return Err(create_error);
            }
            client
                .verify_readback(
                    storage_key,
                    &existing.file_id,
                    source.parent().unwrap_or(Path::new(".")),
                    size_bytes,
                    encoded_sha256,
                )
                .await?;
            return Ok(UploadedObject {
                native_id: existing.file_id.clone(),
                provider_version: existing.file_id,
                etag: existing.content_hash,
            });
        }
    };
    if created.file_id.is_empty()
        || created.upload_id.is_empty()
        || created.rapid_upload
        || created.part_info_list.len() as u64 != part_count
    {
        return Err(Error::InvalidResponse(
            "invalid Aliyun multipart plan".to_owned(),
        ));
    }
    let mut file = std::fs::File::open(source)
        .map_err(|error| Error::InvalidResponse(format!("open Aliyun upload source: {error}")))?;
    let mut remaining = size_bytes;
    for (index, part) in created.part_info_list.iter().enumerate() {
        if part.part_number != index as u64 + 1 {
            return Err(Error::InvalidResponse(
                "Aliyun part ordering changed".to_owned(),
            ));
        }
        let length = remaining.min(client.upload_part_bytes);
        let mut bytes = vec![
            0_u8;
            usize::try_from(length).map_err(|error| {
                Error::InvalidResponse(format!("Aliyun part length: {error}"))
            })?
        ];
        file.read_exact(&mut bytes)
            .map_err(|error| Error::InvalidResponse(format!("read Aliyun upload part: {error}")))?;
        let url = safe_service_url(&part.upload_url)?;
        let response = client.http.put(url).body(bytes).send().await?;
        if !matches!(response.status(), StatusCode::OK | StatusCode::CONFLICT) {
            return Err(Error::Rejected {
                status: response.status().as_u16(),
                message: "Aliyun upload URL rejected a part".to_owned(),
            });
        }
        remaining -= length;
    }
    if remaining != 0 {
        return Err(Error::InvalidResponse(
            "Aliyun multipart plan was short".to_owned(),
        ));
    }
    let completed: FileRecord = client
        .api(
            "/adrive/v1.0/openFile/complete",
            &CompleteFile {
                drive_id: &client.drive_id,
                file_id: &created.file_id,
                upload_id: &created.upload_id,
            },
        )
        .await?;
    let native_id = if completed.file_id.is_empty() {
        created.file_id
    } else {
        completed.file_id
    };
    client
        .verify_readback(
            storage_key,
            &native_id,
            source.parent().unwrap_or(Path::new(".")),
            size_bytes,
            encoded_sha256,
        )
        .await?;
    let stored = client.resolve(storage_key).await?;
    if stored.file_id != native_id || u64::try_from(stored.size).ok() != Some(size_bytes) {
        return Err(Error::InvalidResponse(
            "Aliyun object identity changed after readback".to_owned(),
        ));
    }
    Ok(UploadedObject {
        provider_version: native_id.clone(),
        native_id,
        etag: stored.content_hash,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the adapter validates every immutable download-plan identity"
)]
pub(crate) async fn download(
    http: &reqwest::Client,
    config: &Value,
    credential: Value,
    storage_key: &str,
    native_id: Option<&str>,
    staging_root: &Path,
    version_id: &str,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<PathBuf, Error> {
    let client = Client::open(http, config, credential).await?;
    let file_id = match native_id {
        Some(value) if !value.is_empty() => value.to_owned(),
        _ => client.resolve(storage_key).await?.file_id,
    };
    let path = client
        .download_to(storage_key, &file_id, staging_root, expected_bytes)
        .await?;
    let destination = staging_root.join(format!("{version_id}.download"));
    if path != destination {
        std::fs::rename(&path, &destination).map_err(|error| {
            Error::InvalidResponse(format!("publish Aliyun download staging: {error}"))
        })?;
    }
    if hash_file(&destination)? != expected_sha256 {
        let _ = std::fs::remove_file(&destination);
        return Err(Error::failure(
            crate::FailureKind::CorruptCiphertext,
            "Aliyun provider checksum differs",
        ));
    }
    Ok(destination)
}

impl Client {
    async fn open(
        http: &reqwest::Client,
        config: &Value,
        credential: Value,
    ) -> Result<Self, Error> {
        let config: Config = serde_json::from_value(config.clone()).map_err(|error| {
            Error::InvalidResponse(format!("decode Aliyun configuration: {error}"))
        })?;
        let credential: Credential = serde_json::from_value(credential).map_err(|error| {
            Error::InvalidResponse(format!("decode Aliyun credential: {error}"))
        })?;
        if credential.access_token.is_empty()
            || config.upload_part_bytes == 0
            || config.root_folder_id.is_empty()
        {
            return Err(Error::InvalidResponse("invalid Aliyun grant".to_owned()));
        }
        let base = safe_service_url(&config.api_base_url)?;
        let mut provisional = Self {
            http: http.clone(),
            base,
            drive_id: String::new(),
            root_folder_id: config.root_folder_id,
            upload_part_bytes: config.upload_part_bytes,
            credential,
        };
        let info: DriveInfo = provisional
            .api("/adrive/v1.0/user/getDriveInfo", &serde_json::json!({}))
            .await?;
        provisional.drive_id = match config.drive_type.as_str() {
            "default" => info.default_drive_id,
            "resource" => info.resource_drive_id,
            "backup" => info.backup_drive_id,
            _ => String::new(),
        };
        if provisional.drive_id.is_empty() {
            return Err(Error::InvalidResponse(
                "Aliyun drive identity is missing".to_owned(),
            ));
        }
        Ok(provisional)
    }

    async fn api<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        body: &impl Serialize,
    ) -> Result<T, Error> {
        let url = self
            .base
            .join(endpoint)
            .map_err(|error| Error::InvalidEndpoint(format!("Aliyun API endpoint: {error}")))?;
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.credential.access_token)
            .json(body)
            .send()
            .await
            .map_err(|error| provider_transport("call Aliyun Drive API", &error))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| provider_transport("read Aliyun Drive API response", &error))?;
        if bytes.len() > MAXIMUM_API_BODY {
            return Err(Error::InvalidResponse(
                "Aliyun API response is too large".to_owned(),
            ));
        }
        if !status.is_success() {
            if status == StatusCode::REQUEST_TIMEOUT
                || status == StatusCode::TOO_MANY_REQUESTS
                || status.is_server_error()
            {
                return Err(provider_status("Aliyun Drive API", status, false));
            }
            return Err(Error::Rejected {
                status: status.as_u16(),
                message: "Aliyun Drive API rejected the request".to_owned(),
            });
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| Error::InvalidResponse(format!("decode Aliyun API response: {error}")))
    }

    async fn resolve(&self, key: &str) -> Result<FileRecord, Error> {
        let segments = crate::driver::safe_storage_key(key)?;
        let mut current = FileRecord {
            file_id: self.root_folder_id.clone(),
            name: "root".to_owned(),
            file_name: String::new(),
            size: 0,
            content_hash: String::new(),
            kind: "folder".to_owned(),
        };
        for segment in &segments {
            let name = segment.to_str().ok_or_else(|| {
                Error::InvalidResponse("Aliyun object key is not UTF-8".to_owned())
            })?;
            current = self.find_child(&current.file_id, name).await?;
        }
        Ok(current)
    }

    async fn ensure_parent(&self, key: &str) -> Result<(FileRecord, String), Error> {
        let path = crate::driver::safe_storage_key(key)?;
        let segments = path.iter().collect::<Vec<_>>();
        let (name, parents) = segments
            .split_last()
            .ok_or_else(|| Error::InvalidResponse("Aliyun object key is empty".to_owned()))?;
        let mut current = FileRecord {
            file_id: self.root_folder_id.clone(),
            name: "root".to_owned(),
            file_name: String::new(),
            size: 0,
            content_hash: String::new(),
            kind: "folder".to_owned(),
        };
        for segment in parents {
            let component = segment.to_str().ok_or_else(|| {
                Error::InvalidResponse("Aliyun object key is not UTF-8".to_owned())
            })?;
            current = match self.find_child(&current.file_id, component).await {
                Ok(found) if found.kind == "folder" => found,
                Ok(_) => {
                    return Err(Error::InvalidResponse(
                        "Aliyun parent is not a folder".to_owned(),
                    ));
                }
                Err(Error::Failure {
                    kind: crate::FailureKind::PermanentLoss,
                    ..
                }) => {
                    self.api(
                        "/adrive/v1.0/openFile/create",
                        &CreateFolder {
                            drive_id: &self.drive_id,
                            parent_file_id: &current.file_id,
                            name: component,
                            kind: "folder",
                            check_name_mode: "refuse",
                        },
                    )
                    .await?
                }
                Err(error) => return Err(error),
            };
        }
        let name = name
            .to_str()
            .ok_or_else(|| Error::InvalidResponse("Aliyun object name is not UTF-8".to_owned()))?;
        Ok((current, name.to_owned()))
    }

    async fn find_child(&self, parent: &str, name: &str) -> Result<FileRecord, Error> {
        let mut marker = String::new();
        let mut found = None;
        loop {
            let page: ListResponse = self
                .api(
                    "/adrive/v1.0/openFile/list",
                    &ListRequest {
                        drive_id: &self.drive_id,
                        parent_file_id: parent,
                        limit: 200,
                        marker: &marker,
                        order_by: "name",
                        order_direction: "ASC",
                    },
                )
                .await?;
            for item in page.items {
                if item.name == name || item.file_name == name {
                    if found.is_some() {
                        return Err(Error::InvalidResponse(
                            "duplicate Aliyun object name".to_owned(),
                        ));
                    }
                    found = Some(item);
                }
            }
            if page.next_marker.is_empty() {
                break;
            }
            marker = page.next_marker;
        }
        found.ok_or_else(|| {
            Error::failure(
                crate::FailureKind::PermanentLoss,
                "Aliyun object was not found",
            )
        })
    }

    async fn download_to(
        &self,
        _key: &str,
        file_id: &str,
        staging_root: &Path,
        expected_bytes: u64,
    ) -> Result<PathBuf, Error> {
        ensure_private_directory(staging_root, "Aliyun download staging root")?;
        let grant: DownloadUrlResponse = self
            .api(
                "/adrive/v1.0/openFile/getDownloadUrl",
                &DownloadUrlRequest {
                    drive_id: &self.drive_id,
                    file_id,
                    expire_sec: 14_400,
                },
            )
            .await?;
        let url = safe_service_url(&grant.url)?;
        if expected_bytes == 0 {
            self.verify_empty_download(url.clone()).await?;
        }
        let (temporary, mut output) = create_download_staging_file(staging_root)?;
        let mut offset = 0_u64;
        let range_bytes = self.upload_part_bytes;
        while offset < expected_bytes {
            let length = range_bytes.min(expected_bytes - offset);
            let end = offset + length - 1;
            let response = self
                .http
                .get(url.clone())
                .header("Range", format!("bytes={offset}-{end}"))
                .header("Accept-Encoding", "identity")
                .send()
                .await
                .map_err(|error| provider_transport("download Aliyun range", &error))?;
            if response.status() != StatusCode::PARTIAL_CONTENT {
                return Err(provider_status(
                    "Aliyun range download",
                    response.status(),
                    true,
                ));
            }
            if response
                .content_length()
                .is_some_and(|bytes| bytes != length)
                || response
                    .headers()
                    .get("Content-Range")
                    .and_then(|value| value.to_str().ok())
                    != Some(format!("bytes {offset}-{end}/{expected_bytes}").as_str())
            {
                return Err(Error::failure(
                    crate::FailureKind::CorruptCiphertext,
                    "Aliyun range response identity differs",
                ));
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|error| provider_transport("read Aliyun range", &error))?;
            if bytes.len() as u64 != length {
                return Err(Error::failure(
                    crate::FailureKind::CorruptCiphertext,
                    "Aliyun range body was short",
                ));
            }
            output.write_all(&bytes).map_err(|error| {
                Error::InvalidResponse(format!("write Aliyun download: {error}"))
            })?;
            offset += length;
        }
        output
            .sync_all()
            .map_err(|error| Error::InvalidResponse(format!("sync Aliyun download: {error}")))?;
        Ok(temporary)
    }

    async fn verify_empty_download(&self, url: Url) -> Result<(), Error> {
        let response = self
            .http
            .get(url)
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .map_err(|error| provider_transport("download empty Aliyun object", &error))?;
        if response.status() != StatusCode::OK {
            return Err(provider_status(
                "Aliyun empty-object download",
                response.status(),
                true,
            ));
        }
        if response.content_length().is_some_and(|bytes| bytes != 0) {
            return Err(Error::failure(
                crate::FailureKind::CorruptCiphertext,
                "Aliyun zero-byte object returned a non-empty body",
            ));
        }
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk =
                chunk.map_err(|error| provider_transport("read empty Aliyun object", &error))?;
            if !chunk.is_empty() {
                return Err(Error::failure(
                    crate::FailureKind::CorruptCiphertext,
                    "Aliyun zero-byte object returned a non-empty body",
                ));
            }
        }
        Ok(())
    }

    async fn verify_readback(
        &self,
        key: &str,
        file_id: &str,
        staging_root: &Path,
        expected_bytes: u64,
        expected_sha256: &str,
    ) -> Result<(), Error> {
        let observed = self
            .download_to(key, file_id, staging_root, expected_bytes)
            .await?;
        let digest = hash_file(&observed);
        std::fs::remove_file(&observed)
            .map_err(|error| Error::InvalidResponse(format!("remove Aliyun readback: {error}")))?;
        if digest? != expected_sha256 {
            return Err(Error::failure(
                crate::FailureKind::CorruptCiphertext,
                "Aliyun complete readback differs",
            ));
        }
        Ok(())
    }
}

fn create_download_staging_file(staging_root: &Path) -> Result<(PathBuf, std::fs::File), Error> {
    loop {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|error| {
            Error::InvalidResponse(format!("generate Aliyun staging identity: {error}"))
        })?;
        let temporary =
            staging_root.join(format!(".carrack-aliyun-readback-{}", hex::encode(nonce)));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(output) => return Ok((temporary, output)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(Error::InvalidResponse(format!(
                    "create Aliyun download: {error}"
                )));
            }
        }
    }
}

fn provider_transport(operation: &str, error: &reqwest::Error) -> Error {
    Error::failure(
        crate::FailureKind::ProviderUnavailable,
        format!("{operation}: {error}"),
    )
}

fn provider_status(operation: &str, status: StatusCode, immutable_object_expected: bool) -> Error {
    let kind = if immutable_object_expected
        && matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE)
    {
        crate::FailureKind::PermanentLoss
    } else {
        crate::FailureKind::ProviderUnavailable
    };
    Error::failure(kind, format!("{operation} returned {status}"))
}

fn safe_service_url(value: &str) -> Result<Url, Error> {
    let url = Url::parse(value).map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
    let loopback_http = url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
    if (url.scheme() != "https" && !loopback_http)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::InvalidEndpoint(
            "unsafe Aliyun service URL".to_owned(),
        ));
    }
    Ok(url)
}

fn hash_file(path: &Path) -> Result<String, Error> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| Error::InvalidResponse(format!("open Aliyun readback: {error}")))?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| Error::InvalidResponse(format!("seek Aliyun readback: {error}")))?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)
        .map_err(|error| Error::InvalidResponse(format!("hash Aliyun readback: {error}")))?;
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use httpmock::{
        Method::{GET, POST, PUT},
        MockServer,
    };
    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::{FileRecord, create_download_staging_file, download, provider_status, upload};

    #[test]
    fn download_staging_identity_is_carrack_owned() {
        let staging = tempfile::tempdir().expect("temporary staging");
        let (path, file) =
            create_download_staging_file(staging.path()).expect("create staging file");
        drop(file);

        assert_eq!(path.parent(), Some(staging.path()));
        assert!(
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".carrack-aliyun-readback-"))
        );
        assert!(path.is_file());
    }

    #[test]
    fn normalizes_nullable_folder_metadata() {
        let folder: FileRecord = serde_json::from_value(json!({
            "file_id": "folder-1",
            "name": "objects",
            "file_name": null,
            "size": null,
            "content_hash": null,
            "type": "folder"
        }))
        .expect("decode Aliyun folder metadata");

        assert_eq!(folder.file_id, "folder-1");
        assert_eq!(folder.name, "objects");
        assert!(folder.file_name.is_empty());
        assert_eq!(folder.size, 0);
        assert!(folder.content_hash.is_empty());
        assert_eq!(folder.kind, "folder");
    }

    #[test]
    fn distinguishes_provider_outage_from_permanent_loss() {
        assert_eq!(
            provider_status("download", reqwest::StatusCode::NOT_FOUND, true).failure_kind(),
            Some(crate::FailureKind::PermanentLoss)
        );
        assert_eq!(
            provider_status("download", reqwest::StatusCode::SERVICE_UNAVAILABLE, true)
                .failure_kind(),
            Some(crate::FailureKind::ProviderUnavailable)
        );
    }

    #[tokio::test]
    async fn zero_byte_download_still_verifies_the_provider_body() {
        let server = MockServer::start();
        let drive_info = server.mock(|when, then| {
            when.method(POST).path("/adrive/v1.0/user/getDriveInfo");
            then.status(200).json_body(json!({
                "default_drive_id": "drive",
                "resource_drive_id": "drive",
                "backup_drive_id": "drive"
            }));
        });
        let download_url = server.url("/download");
        let grant = server.mock(|when, then| {
            when.method(POST)
                .path("/adrive/v1.0/openFile/getDownloadUrl");
            then.status(200).json_body(json!({"url": download_url}));
        });
        let provider = server.mock(|when, then| {
            when.method(GET)
                .path("/download")
                .header("Accept-Encoding", "identity");
            then.status(200).body("unexpected");
        });
        let staging = tempfile::tempdir().expect("temporary staging");
        let error = download(
            &reqwest::Client::new(),
            &json!({
                "api_base_url": server.base_url(),
                "drive_type": "resource",
                "root_folder_id": "root",
                "upload_part_bytes": 2
            }),
            json!({"access_token": "secret"}),
            "object",
            Some("file-1"),
            staging.path(),
            "version-1",
            0,
            &hex::encode(Sha256::digest([])),
        )
        .await
        .expect_err("non-empty provider body must not satisfy zero-byte identity");
        assert_eq!(
            error.failure_kind(),
            Some(crate::FailureKind::CorruptCiphertext)
        );
        drive_info.assert();
        grant.assert();
        provider.assert();
    }

    #[tokio::test]
    async fn malformed_partial_content_is_classified_as_corrupt_ciphertext() {
        let server = MockServer::start();
        let drive_info = server.mock(|when, then| {
            when.method(POST).path("/adrive/v1.0/user/getDriveInfo");
            then.status(200).json_body(json!({
                "default_drive_id": "drive",
                "resource_drive_id": "drive",
                "backup_drive_id": "drive"
            }));
        });
        let download_url = server.url("/download");
        let grant = server.mock(|when, then| {
            when.method(POST)
                .path("/adrive/v1.0/openFile/getDownloadUrl");
            then.status(200).json_body(json!({"url": download_url}));
        });
        let provider = server.mock(|when, then| {
            when.method(GET)
                .path("/download")
                .header("range", "bytes=0-2")
                .header("Accept-Encoding", "identity");
            then.status(206)
                .header("Content-Length", "3")
                .header("Content-Range", "bytes 0-2/4")
                .body("abc");
        });
        let staging = tempfile::tempdir().expect("temporary staging");
        let error = download(
            &reqwest::Client::new(),
            &json!({
                "api_base_url": server.base_url(),
                "drive_type": "resource",
                "root_folder_id": "root",
                "upload_part_bytes": 3
            }),
            json!({"access_token": "secret"}),
            "object",
            Some("file-1"),
            staging.path(),
            "version-1",
            3,
            &hex::encode(Sha256::digest(b"abc")),
        )
        .await
        .expect_err("wrong complete object length must fail closed");
        assert_eq!(
            error.failure_kind(),
            Some(crate::FailureKind::CorruptCiphertext)
        );
        drive_info.assert();
        grant.assert();
        provider.assert();
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one mock round trip keeps every signed URL and exact range assertion visible"
    )]
    async fn complete_object_round_trip_uses_exact_ranges() {
        let server = MockServer::start();
        let drive_info = server.mock(|when, then| {
            when.method(POST).path("/adrive/v1.0/user/getDriveInfo");
            then.status(200).json_body(json!({
                "default_drive_id": "drive",
                "resource_drive_id": "drive",
                "backup_drive_id": "drive"
            }));
        });
        let part_one_url = server.url("/upload/1");
        let part_two_url = server.url("/upload/2");
        let create = server.mock(|when, then| {
            when.method(POST).path("/adrive/v1.0/openFile/create");
            then.status(200).json_body(json!({
                "file_id": "file-1",
                "upload_id": "upload-1",
                "rapid_upload": false,
                "part_info_list": [
                    {"part_number": 1, "upload_url": part_one_url},
                    {"part_number": 2, "upload_url": part_two_url}
                ]
            }));
        });
        let part_one = server.mock(|when, then| {
            when.method(PUT).path("/upload/1").body("ab");
            then.status(200);
        });
        let part_two = server.mock(|when, then| {
            when.method(PUT).path("/upload/2").body("c");
            then.status(200);
        });
        let complete = server.mock(|when, then| {
            when.method(POST).path("/adrive/v1.0/openFile/complete");
            then.status(200).json_body(json!({"file_id": "file-1"}));
        });
        let list = server.mock(|when, then| {
            when.method(POST).path("/adrive/v1.0/openFile/list");
            then.status(200).json_body(json!({
                "items": [{
                    "file_id": "file-1", "name": "object", "size": 3,
                    "content_hash": "provider-hash", "type": "file"
                }],
                "next_marker": ""
            }));
        });
        let download_url = server.url("/download");
        let grant = server.mock(|when, then| {
            when.method(POST)
                .path("/adrive/v1.0/openFile/getDownloadUrl");
            then.status(200).json_body(json!({"url": download_url}));
        });
        let range_one = server.mock(|when, then| {
            when.method(GET)
                .path("/download")
                .header("range", "bytes=0-1");
            then.status(206)
                .header("Content-Length", "2")
                .header("Content-Range", "bytes 0-1/3")
                .body("ab");
        });
        let range_two = server.mock(|when, then| {
            when.method(GET)
                .path("/download")
                .header("range", "bytes=2-2");
            then.status(206)
                .header("Content-Length", "1")
                .header("Content-Range", "bytes 2-2/3")
                .body("c");
        });
        let state = tempfile::tempdir().expect("temporary state");
        let source = state.path().join("source");
        std::fs::write(&source, b"abc").expect("write source");
        let digest = hex::encode(Sha256::digest(b"abc"));
        let config = json!({
            "api_base_url": server.base_url(),
            "drive_type": "resource",
            "root_folder_id": "root",
            "upload_part_bytes": 2
        });
        let object = upload(
            &reqwest::Client::new(),
            &config,
            json!({"access_token": "secret"}),
            "object",
            &source,
            3,
            &digest,
        )
        .await
        .expect("upload complete object");
        assert_eq!(object.native_id, "file-1");
        assert_eq!(object.etag, "provider-hash");

        let restored = download(
            &reqwest::Client::new(),
            &config,
            json!({"access_token": "secret"}),
            "object",
            Some("file-1"),
            state.path(),
            "version-1",
            3,
            &digest,
        )
        .await
        .expect("download complete object");
        assert_eq!(std::fs::read(restored).expect("read restored"), b"abc");
        drive_info.assert_calls(2);
        create.assert();
        part_one.assert();
        part_two.assert();
        complete.assert();
        list.assert();
        grant.assert_calls(2);
        range_one.assert_calls(2);
        range_two.assert_calls(2);
    }
}
