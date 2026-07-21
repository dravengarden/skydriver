//! Official AWS S3 `SigV4` policy and object-scoped grant projection.
//!
//! The cryptographic canonicalization is shared with the R2 adapter, while
//! this module owns AWS-only endpoint, owner, and bucket-versioning rules.

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
pub(crate) use skydriver_driver_contract::AwsS3Config as Config;
use worker::{Date, Fetch, Headers, Method, Request, RequestInit, wasm_bindgen::JsValue};

pub(crate) use crate::r2_signing::Credential;
use crate::r2_signing::{SigningTarget, presign_target};

pub(crate) use crate::r2_signing::{ObjectStat, OperationFailure};

const MAXIMUM_PREFIX_BYTES: usize = 1_024;
const OWNER_HEADER: &str = "x-amz-expected-bucket-owner";

#[derive(Debug)]
pub(crate) struct ListedObject {
    pub(crate) storage_key: String,
    pub(crate) etag: String,
    pub(crate) size_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct ListedPage {
    pub(crate) objects: Vec<ListedObject>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "ListBucketResult", rename_all = "PascalCase")]
struct ListBucketResult {
    #[serde(default)]
    contents: Vec<ListedWireObject>,
    is_truncated: bool,
    next_continuation_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListedWireObject {
    key: String,
    #[serde(rename = "ETag")]
    etag: String,
    size: u64,
}

#[derive(Deserialize)]
#[serde(rename = "VersioningConfiguration", rename_all = "PascalCase")]
struct VersioningConfiguration {
    status: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "LocationConstraint")]
struct LocationConstraint {
    #[serde(rename = "$text")]
    region: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "InitiateMultipartUploadResult", rename_all = "PascalCase")]
struct InitiateMultipartUploadResult {
    upload_id: String,
}

pub(crate) fn valid_config(config: &Config) -> bool {
    valid_region(&config.region)
        && valid_bucket(&config.bucket)
        && config.expected_bucket_owner.len() == 12
        && config
            .expected_bucket_owner
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        && (config.prefix.is_empty()
            || (config.prefix.ends_with('/')
                && config.prefix.len() <= MAXIMUM_PREFIX_BYTES
                && !config.prefix.starts_with('/')
                && !config.prefix.contains("..")
                && !config.prefix.chars().any(char::is_control)))
}

pub(crate) fn valid_credential(credential: &Credential) -> bool {
    (16..=128).contains(&credential.access_key_id.len())
        && credential
            .access_key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
        && (16..=256).contains(&credential.secret_access_key.len())
        && credential
            .secret_access_key
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
}

pub(crate) fn object_key(config: &Config, storage_key: &str) -> Option<String> {
    if storage_key.is_empty()
        || storage_key.starts_with('/')
        || storage_key.contains("..")
        || storage_key.len() > 4_096
        || storage_key.chars().any(char::is_control)
    {
        return None;
    }
    Some(format!("{}{storage_key}", config.prefix))
}

fn endpoint(config: &Config) -> Option<String> {
    valid_config(config).then(|| {
        format!(
            "https://{}.s3.{}.amazonaws.com",
            config.bucket, config.region
        )
    })
}

fn target<'a>(endpoint: &'a str, config: &'a Config) -> SigningTarget<'a> {
    SigningTarget {
        endpoint,
        region: &config.region,
        bucket_path: None,
    }
}

fn sign(
    method: &str,
    config: &Config,
    credential: &Credential,
    key: &str,
    expires_seconds: u64,
    query: &[(&str, &str)],
    extra_headers: &[(&str, &str)],
) -> Option<String> {
    if !valid_credential(credential) {
        return None;
    }
    let endpoint = endpoint(config)?;
    let mut headers = vec![(OWNER_HEADER, config.expected_bucket_owner.as_str())];
    headers.extend_from_slice(extra_headers);
    presign_target(
        method,
        &target(&endpoint, config),
        credential,
        key,
        expires_seconds,
        query,
        &headers,
    )
}

pub(crate) fn access_grant_from_plaintext(
    method: &str,
    config_json: &str,
    storage_key: &str,
    plaintext: &[u8],
    maximum_expires_at: u64,
) -> Option<serde_json::Value> {
    let config = serde_json::from_str::<Config>(config_json).ok()?;
    let credential = serde_json::from_slice::<Credential>(plaintext).ok()?;
    let key = object_key(&config, storage_key)?;
    let now = Date::now().as_millis() / 1_000;
    let lifetime = maximum_expires_at.saturating_sub(now).min(900);
    let conditional = (method == "PUT").then_some(("if-none-match", "*"));
    let required = conditional.as_slice();
    let url = sign(method, &config, &credential, &key, lifetime, &[], required)?;
    let verify_url = (method == "PUT")
        .then(|| sign("GET", &config, &credential, &key, lifetime, &[], &[]))
        .flatten();
    let multipart_create_url = (method == "PUT")
        .then(|| {
            sign(
                "POST",
                &config,
                &credential,
                &key,
                lifetime,
                &[("uploads", "")],
                &[],
            )
        })
        .flatten();
    Some(json!({
        "method": method,
        "url": url,
        "verify_url": verify_url,
        "multipart_create_url": multipart_create_url,
        "multipart_create_requires_no_replace": false,
        "required_headers": {
            "x-amz-expected-bucket-owner": config.expected_bucket_owner,
        },
        "expires_at": now + lifetime,
    }))
}

#[allow(
    clippy::too_many_arguments,
    reason = "multipart authority is bounded by object, upload, part interval, and expiry"
)]
pub(crate) fn multipart_grant_from_plaintext(
    config_json: &str,
    storage_key: &str,
    plaintext: &[u8],
    upload_id: &str,
    first_part: u32,
    part_count: u32,
    maximum_expires_at: u64,
) -> Option<serde_json::Value> {
    if upload_id.is_empty()
        || upload_id.len() > 1_024
        || upload_id.contains(['\0', '\r', '\n'])
        || first_part == 0
        || part_count == 0
        || part_count > 64
        || first_part.checked_add(part_count)? > 10_001
    {
        return None;
    }
    let config = serde_json::from_str::<Config>(config_json).ok()?;
    let credential = serde_json::from_slice::<Credential>(plaintext).ok()?;
    let key = object_key(&config, storage_key)?;
    let now = Date::now().as_millis() / 1_000;
    let lifetime = maximum_expires_at.saturating_sub(now).min(900);
    let parts = (first_part..first_part + part_count)
        .map(|part_number| {
            let part = part_number.to_string();
            let url = sign(
                "PUT",
                &config,
                &credential,
                &key,
                lifetime,
                &[("partNumber", &part), ("uploadId", upload_id)],
                &[],
            )?;
            Some(json!({"part_number": part_number, "url": url}))
        })
        .collect::<Option<Vec<_>>>()?;
    let complete_url = sign(
        "POST",
        &config,
        &credential,
        &key,
        lifetime,
        &[("uploadId", upload_id)],
        &[("if-none-match", "*")],
    )?;
    let abort_url = sign(
        "DELETE",
        &config,
        &credential,
        &key,
        lifetime,
        &[("uploadId", upload_id)],
        &[],
    )?;
    let verify_url = sign("GET", &config, &credential, &key, lifetime, &[], &[])?;
    Some(json!({
        "schema": "skydriver.vfs.s3-multipart-grant.v1",
        "upload_id": upload_id,
        "parts": parts,
        "complete_url": complete_url,
        "abort_url": abort_url,
        "verify_url": verify_url,
        "required_headers": {
            "x-amz-expected-bucket-owner": config.expected_bucket_owner,
        },
        "expires_at": now + lifetime,
    }))
}

pub(crate) async fn verify(config: &Config, credential: &Credential) -> bool {
    if !valid_config(config) || !valid_credential(credential) {
        return false;
    }
    if !bucket_region_matches(config, credential).await {
        return false;
    }
    if !bucket_is_unversioned(config, credential).await {
        return false;
    }
    if list_page(config, credential, None, 1).await.is_err() {
        return false;
    }
    let Some(key) = verification_key(config, credential) else {
        return false;
    };
    let Some(put_url) = sign(
        "PUT",
        config,
        credential,
        &key,
        60,
        &[],
        &[("if-none-match", "*")],
    ) else {
        return false;
    };
    let headers = request_headers(config, Some(("If-None-Match", "*")));
    if headers.set("Content-Length", "0").is_err() {
        return false;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Put).with_headers(headers);
    let Ok(request) = Request::new_with_init(&put_url, &init) else {
        return false;
    };
    let Ok(response) = Fetch::Request(request).send().await else {
        return false;
    };
    if !(200..300).contains(&response.status_code()) {
        return false;
    }
    let Ok(Some(etag)) = response.headers().get("ETag") else {
        return false;
    };
    if !conditional_delete(config, credential, &key, &etag).await {
        return false;
    }
    let Some(multipart_key) = verification_key(config, credential) else {
        return false;
    };
    if !verify_multipart(config, credential, &multipart_key).await {
        return false;
    }
    let Some(abort_key) = verification_key(config, credential) else {
        return false;
    };
    verify_abort_capability(config, credential, &abort_key).await
}

pub(crate) async fn authority_healthy(config_json: &str, plaintext: &[u8]) -> bool {
    let Ok(config) = serde_json::from_str::<Config>(config_json) else {
        return false;
    };
    let Ok(credential) = serde_json::from_slice::<Credential>(plaintext) else {
        return false;
    };
    valid_config(&config)
        && valid_credential(&credential)
        && bucket_is_unversioned(&config, &credential).await
}

fn verification_key(config: &Config, credential: &Credential) -> Option<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).ok()?;
    let authority = hex(&Sha256::digest(credential.access_key_id.as_bytes()));
    object_key(
        config,
        &format!(".skydriver/credential-check/{authority}/{}", hex(&random)),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the one-time authorization canary proves multipart, exact range, readback, abort authority, and conditional cleanup as one provider capability transaction"
)]
async fn verify_multipart(config: &Config, credential: &Credential, key: &str) -> bool {
    let Some(create_url) = sign("POST", config, credential, key, 60, &[("uploads", "")], &[])
    else {
        return false;
    };
    let headers = request_headers(config, None);
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    let Ok(request) = Request::new_with_init(&create_url, &init) else {
        return false;
    };
    let Ok(mut response) = Fetch::Request(request).send().await else {
        return false;
    };
    if !(200..300).contains(&response.status_code()) {
        return false;
    }
    let Ok(body) = response.text().await else {
        return false;
    };
    let Ok(created) = quick_xml::de::from_str::<InitiateMultipartUploadResult>(&body) else {
        return false;
    };
    if created.upload_id.is_empty()
        || created.upload_id.len() > 1_024
        || created.upload_id.chars().any(char::is_control)
    {
        return false;
    }
    let upload_id = created.upload_id;
    let result = verify_multipart_after_create(config, credential, key, &upload_id).await;
    if !result {
        let _ = abort_multipart(config, credential, key, &upload_id).await;
    }
    result
}

async fn verify_multipart_after_create(
    config: &Config,
    credential: &Credential,
    key: &str,
    upload_id: &str,
) -> bool {
    let Some(part_url) = sign(
        "PUT",
        config,
        credential,
        key,
        60,
        &[("partNumber", "1"), ("uploadId", upload_id)],
        &[],
    ) else {
        return false;
    };
    let headers = request_headers(config, None);
    if headers.set("Content-Length", "1").is_err() {
        return false;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Put)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str("x")));
    let Ok(request) = Request::new_with_init(&part_url, &init) else {
        return false;
    };
    let Ok(response) = Fetch::Request(request).send().await else {
        return false;
    };
    if !(200..300).contains(&response.status_code()) {
        return false;
    }
    let Ok(Some(part_etag)) = response.headers().get("ETag") else {
        return false;
    };
    let normalized_etag = part_etag.trim_matches('"');
    if !valid_etag(normalized_etag) {
        return false;
    }
    let completion = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>&quot;{normalized_etag}&quot;</ETag></Part></CompleteMultipartUpload>"
    );
    let Some(complete_url) = sign(
        "POST",
        config,
        credential,
        key,
        60,
        &[("uploadId", upload_id)],
        &[("if-none-match", "*")],
    ) else {
        return false;
    };
    let headers = request_headers(config, Some(("If-None-Match", "*")));
    if headers.set("Content-Type", "application/xml").is_err() {
        return false;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&completion)));
    let Ok(request) = Request::new_with_init(&complete_url, &init) else {
        return false;
    };
    let Ok(response) = Fetch::Request(request).send().await else {
        return false;
    };
    if !(200..300).contains(&response.status_code()) {
        return false;
    }
    let Ok(Some(etag)) = response.headers().get("ETag") else {
        return false;
    };
    if !verify_exact_range(config, credential, key).await {
        let _ = conditional_delete(config, credential, key, &etag).await;
        return false;
    }
    conditional_delete(config, credential, key, &etag).await
}

async fn verify_exact_range(config: &Config, credential: &Credential, key: &str) -> bool {
    let Some(url) = sign("GET", config, credential, key, 60, &[], &[]) else {
        return false;
    };
    let headers = request_headers(config, Some(("Range", "bytes=0-0")));
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let Ok(request) = Request::new_with_init(&url, &init) else {
        return false;
    };
    let Ok(mut response) = Fetch::Request(request).send().await else {
        return false;
    };
    if response.status_code() != 206
        || response
            .headers()
            .get("Content-Range")
            .ok()
            .flatten()
            .as_deref()
            != Some("bytes 0-0/1")
    {
        return false;
    }
    response.bytes().await.is_ok_and(|body| body == b"x")
}

async fn abort_multipart(
    config: &Config,
    credential: &Credential,
    key: &str,
    upload_id: &str,
) -> bool {
    let Some(url) = sign(
        "DELETE",
        config,
        credential,
        key,
        60,
        &[("uploadId", upload_id)],
        &[],
    ) else {
        return false;
    };
    let headers = request_headers(config, None);
    let mut init = RequestInit::new();
    init.with_method(Method::Delete).with_headers(headers);
    let Ok(request) = Request::new_with_init(&url, &init) else {
        return false;
    };
    Fetch::Request(request)
        .send()
        .await
        .is_ok_and(|response| response.status_code() == 404 || response.status_code() == 204)
}

async fn verify_abort_capability(config: &Config, credential: &Credential, key: &str) -> bool {
    let Some(create_url) = sign("POST", config, credential, key, 60, &[("uploads", "")], &[])
    else {
        return false;
    };
    let headers = request_headers(config, None);
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    let Ok(request) = Request::new_with_init(&create_url, &init) else {
        return false;
    };
    let Ok(mut response) = Fetch::Request(request).send().await else {
        return false;
    };
    if !(200..300).contains(&response.status_code()) {
        return false;
    }
    let Ok(body) = response.text().await else {
        return false;
    };
    let Ok(created) = quick_xml::de::from_str::<InitiateMultipartUploadResult>(&body) else {
        return false;
    };
    if created.upload_id.is_empty()
        || created.upload_id.len() > 1_024
        || created.upload_id.chars().any(char::is_control)
    {
        return false;
    }
    abort_multipart(config, credential, key, &created.upload_id).await
}

pub(crate) async fn list_page(
    config: &Config,
    credential: &Credential,
    cursor: Option<&str>,
    maximum_keys: u32,
) -> Result<ListedPage, OperationFailure> {
    if !valid_config(config)
        || !valid_credential(credential)
        || maximum_keys == 0
        || maximum_keys > 1_000
        || cursor.is_some_and(|value| {
            value.is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control)
        })
    {
        return Err(OperationFailure::Blocked("provider_request_invalid"));
    }
    let maximum = maximum_keys.to_string();
    let mut query = vec![
        ("list-type", "2"),
        ("max-keys", maximum.as_str()),
        ("prefix", config.prefix.as_str()),
    ];
    if let Some(cursor) = cursor {
        query.push(("continuation-token", cursor));
    }
    let url = sign("GET", config, credential, "", 60, &query, &[])
        .ok_or(OperationFailure::Blocked("provider_request_invalid"))?;
    let headers = request_headers(config, None);
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let request = Request::new_with_init(&url, &init)
        .map_err(|_| OperationFailure::Blocked("provider_request_invalid"))?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| OperationFailure::Retry("provider_transport_failed"))?;
    if !(200..300).contains(&response.status_code()) {
        return Err(classify_status(response.status_code()));
    }
    let body = response
        .text()
        .await
        .map_err(|_| OperationFailure::Retry("provider_response_invalid"))?;
    if body.len() > 4 * 1024 * 1024 {
        return Err(OperationFailure::Retry("provider_response_invalid"));
    }
    parse_list_page(
        config,
        &body,
        usize::try_from(maximum_keys).unwrap_or(1_000),
    )
}

fn parse_list_page(
    config: &Config,
    body: &str,
    maximum_keys: usize,
) -> Result<ListedPage, OperationFailure> {
    let listed = quick_xml::de::from_str::<ListBucketResult>(body)
        .map_err(|_| OperationFailure::Retry("provider_response_invalid"))?;
    if listed.contents.len() > maximum_keys {
        return Err(OperationFailure::Retry("provider_response_invalid"));
    }
    let mut objects = Vec::with_capacity(listed.contents.len());
    for object in listed.contents {
        let storage_key = object
            .key
            .strip_prefix(&config.prefix)
            .filter(|value| !value.is_empty())
            .ok_or(OperationFailure::Retry("provider_response_invalid"))?;
        if storage_key.len() > 4_096
            || storage_key.starts_with('/')
            || storage_key.contains("..")
            || object.etag.is_empty()
            || object.etag.len() > 1_024
            || object.etag.chars().any(char::is_control)
        {
            return Err(OperationFailure::Retry("provider_response_invalid"));
        }
        objects.push(ListedObject {
            storage_key: storage_key.to_owned(),
            etag: object.etag,
            size_bytes: object.size,
        });
    }
    let next_cursor = if listed.is_truncated {
        Some(
            listed
                .next_continuation_token
                .filter(|value| !value.is_empty() && value.len() <= 16 * 1024)
                .filter(|value| !value.chars().any(char::is_control))
                .ok_or(OperationFailure::Retry("provider_response_invalid"))?,
        )
    } else {
        None
    };
    Ok(ListedPage {
        objects,
        next_cursor,
    })
}

pub(crate) async fn stat_from_plaintext(
    config_json: &str,
    storage_key: &str,
    plaintext: &[u8],
) -> Result<Option<ObjectStat>, OperationFailure> {
    let config = serde_json::from_str::<Config>(config_json)
        .map_err(|_| OperationFailure::Blocked("configuration_invalid"))?;
    let credential = serde_json::from_slice::<Credential>(plaintext)
        .map_err(|_| OperationFailure::Blocked("credential_invalid"))?;
    let key =
        object_key(&config, storage_key).ok_or(OperationFailure::Blocked("storage_key_invalid"))?;
    let url = sign("HEAD", &config, &credential, &key, 60, &[], &[])
        .ok_or(OperationFailure::Blocked("provider_request_invalid"))?;
    let headers = request_headers(&config, None);
    let mut init = RequestInit::new();
    init.with_method(Method::Head).with_headers(headers);
    let request = Request::new_with_init(&url, &init)
        .map_err(|_| OperationFailure::Blocked("provider_request_invalid"))?;
    let response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| OperationFailure::Retry("provider_transport_failed"))?;
    if response.status_code() == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&response.status_code()) {
        return Err(classify_status(response.status_code()));
    }
    let size_bytes = response
        .headers()
        .get("Content-Length")
        .map_err(|_| OperationFailure::Retry("provider_response_invalid"))?
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(OperationFailure::Retry("provider_response_invalid"))?;
    let etag = response
        .headers()
        .get("ETag")
        .map_err(|_| OperationFailure::Retry("provider_response_invalid"))?
        .filter(|value| !value.is_empty() && value.len() <= 1_024)
        .ok_or(OperationFailure::Retry("provider_response_invalid"))?;
    Ok(Some(ObjectStat { size_bytes, etag }))
}

pub(crate) async fn delete_from_plaintext(
    config_json: &str,
    storage_key: &str,
    expected_etag: &str,
    plaintext: &[u8],
) -> Result<(), OperationFailure> {
    let config = serde_json::from_str::<Config>(config_json)
        .map_err(|_| OperationFailure::Blocked("configuration_invalid"))?;
    let credential = serde_json::from_slice::<Credential>(plaintext)
        .map_err(|_| OperationFailure::Blocked("credential_invalid"))?;
    let key =
        object_key(&config, storage_key).ok_or(OperationFailure::Blocked("storage_key_invalid"))?;
    if conditional_delete_result(&config, &credential, &key, expected_etag).await? {
        Ok(())
    } else {
        Err(OperationFailure::Blocked("provider_identity_mismatch"))
    }
}

pub(crate) async fn cleanup_upload_from_plaintext(
    config_json: &str,
    storage_key: &str,
    upload_id: Option<&str>,
    plaintext: &[u8],
) -> Result<(), worker::Error> {
    let config = serde_json::from_str::<Config>(config_json)
        .map_err(|error| worker::Error::RustError(format!("decode AWS S3 config: {error}")))?;
    let credential = serde_json::from_slice::<Credential>(plaintext)
        .map_err(|error| worker::Error::RustError(format!("decode AWS S3 credential: {error}")))?;
    let key = object_key(&config, storage_key)
        .ok_or_else(|| worker::Error::RustError("invalid AWS S3 storage key".to_owned()))?;
    if let Some(upload_id) = upload_id {
        let url = sign(
            "DELETE",
            &config,
            &credential,
            &key,
            60,
            &[("uploadId", upload_id)],
            &[],
        )
        .ok_or_else(|| worker::Error::RustError("sign AWS S3 multipart abort".to_owned()))?;
        let headers = request_headers(&config, None);
        let mut init = RequestInit::new();
        init.with_method(Method::Delete).with_headers(headers);
        let request = Request::new_with_init(&url, &init)?;
        let response = Fetch::Request(request).send().await?;
        if response.status_code() != 404 && !(200..300).contains(&response.status_code()) {
            return Err(worker::Error::RustError(format!(
                "AWS S3 multipart abort returned {}",
                response.status_code()
            )));
        }
    }
    Ok(())
}

async fn bucket_is_unversioned(config: &Config, credential: &Credential) -> bool {
    let Some(url) = sign(
        "GET",
        config,
        credential,
        "",
        60,
        &[("versioning", "")],
        &[],
    ) else {
        return false;
    };
    let headers = request_headers(config, None);
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let Ok(request) = Request::new_with_init(&url, &init) else {
        return false;
    };
    let Ok(mut response) = Fetch::Request(request).send().await else {
        return false;
    };
    if !(200..300).contains(&response.status_code()) {
        return false;
    }
    let Ok(body) = response.text().await else {
        return false;
    };
    body.len() <= 64 * 1024
        && quick_xml::de::from_str::<VersioningConfiguration>(&body)
            .is_ok_and(|versioning| versioning.status.is_none())
}

async fn bucket_region_matches(config: &Config, credential: &Credential) -> bool {
    let Some(url) = sign("GET", config, credential, "", 60, &[("location", "")], &[]) else {
        return false;
    };
    let headers = request_headers(config, None);
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let Ok(request) = Request::new_with_init(&url, &init) else {
        return false;
    };
    let Ok(mut response) = Fetch::Request(request).send().await else {
        return false;
    };
    if !(200..300).contains(&response.status_code()) {
        return false;
    }
    let Ok(body) = response.text().await else {
        return false;
    };
    if body.len() > 64 * 1024 {
        return false;
    }
    location_matches(&config.region, &body)
}

fn location_matches(expected_region: &str, body: &str) -> bool {
    quick_xml::de::from_str::<LocationConstraint>(body).is_ok_and(|location| {
        let observed = match location.region.as_deref() {
            None | Some("") => "us-east-1",
            Some("EU") => "eu-west-1",
            Some(region) => region,
        };
        observed == expected_region
    })
}

async fn conditional_delete(
    config: &Config,
    credential: &Credential,
    key: &str,
    etag: &str,
) -> bool {
    conditional_delete_result(config, credential, key, etag)
        .await
        .unwrap_or(false)
}

async fn conditional_delete_result(
    config: &Config,
    credential: &Credential,
    key: &str,
    etag: &str,
) -> Result<bool, OperationFailure> {
    if etag.is_empty() || etag.len() > 1_024 || etag.chars().any(char::is_control) {
        return Err(OperationFailure::Blocked("provider_request_invalid"));
    }
    let Some(url) = sign(
        "DELETE",
        config,
        credential,
        key,
        60,
        &[],
        &[("if-match", etag)],
    ) else {
        return Err(OperationFailure::Blocked("provider_request_invalid"));
    };
    let headers = request_headers(config, Some(("If-Match", etag)));
    let mut init = RequestInit::new();
    init.with_method(Method::Delete).with_headers(headers);
    let request = Request::new_with_init(&url, &init)
        .map_err(|_| OperationFailure::Blocked("provider_request_invalid"))?;
    let response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| OperationFailure::Retry("provider_transport_failed"))?;
    match response.status_code() {
        404 | 200..=299 => Ok(true),
        409 | 412 => Ok(false),
        status => Err(classify_status(status)),
    }
}

fn classify_status(status: u16) -> OperationFailure {
    match status {
        401 | 403 => OperationFailure::Reauthenticate("provider_authorization_rejected"),
        408 | 425 | 429 | 500..=599 => OperationFailure::Retry("provider_unavailable"),
        _ => OperationFailure::Blocked("provider_request_rejected"),
    }
}

fn request_headers(config: &Config, extra: Option<(&str, &str)>) -> Headers {
    let headers = Headers::new();
    let _ = headers.set(OWNER_HEADER, &config.expected_bucket_owner);
    if let Some((name, value)) = extra {
        let _ = headers.set(name, value);
    }
    headers
}

fn valid_region(value: &str) -> bool {
    (6..=32).contains(&value.len())
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value.ends_with(|character: char| character.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.contains("--")
        && !value.starts_with("cn-")
        && !value.starts_with("us-iso-")
        && !value.starts_with("us-isob-")
        && !value.starts_with("us-isof-")
        && !value.starts_with("eu-isoe-")
}

fn valid_bucket(value: &str) -> bool {
    (3..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !value.starts_with("xn--")
        && !value.starts_with("sthree-")
        && !value.ends_with("-s3alias")
        && !value.ends_with("--ol-s3")
}

fn valid_etag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{
        Config, Credential, OWNER_HEADER, VersioningConfiguration, endpoint, location_matches,
        object_key, parse_list_page, target, valid_config, valid_credential,
    };
    use crate::r2_signing::presign_target_at;

    fn config() -> Config {
        Config {
            region: "us-east-1".to_owned(),
            bucket: "skydriver-payload-example".to_owned(),
            expected_bucket_owner: "123456789012".to_owned(),
            prefix: "objects/".to_owned(),
        }
    }

    #[test]
    fn configuration_pins_official_endpoint_owner_and_key_namespace() {
        let config = config();
        assert!(valid_config(&config));
        assert_eq!(
            object_key(&config, "v2/ab/value").as_deref(),
            Some("objects/v2/ab/value")
        );
        let mut invalid = config;
        invalid.expected_bucket_owner = "123".to_owned();
        assert!(!valid_config(&invalid));

        assert!(valid_credential(&Credential {
            access_key_id: "TESTACCESSKEY000001".to_owned(),
            secret_access_key: "test-secret-value-000000000000000000000001".to_owned(),
        }));
        assert!(!valid_credential(&Credential {
            access_key_id: "too-short".to_owned(),
            secret_access_key: "contains a space".to_owned(),
        }));
    }

    #[test]
    fn put_grant_binds_owner_and_no_replace_without_exposing_secret() {
        let config = config();
        let credential = Credential {
            access_key_id: "test-access".to_owned(),
            secret_access_key: "test-secret".to_owned(),
        };
        let endpoint = endpoint(&config).expect("endpoint");
        let url = presign_target_at(
            "PUT",
            &target(&endpoint, &config),
            &credential,
            "objects/v2/value",
            900,
            &[],
            &[
                ("if-none-match", "*"),
                (OWNER_HEADER, config.expected_bucket_owner.as_str()),
            ],
            "20260718T120000Z",
        )
        .expect("sign grant");
        assert!(url.starts_with("https://skydriver-payload-example.s3.us-east-1.amazonaws.com/"));
        assert!(
            url.contains("X-Amz-SignedHeaders=host%3Bif-none-match%3Bx-amz-expected-bucket-owner")
        );
        assert!(!url.contains("test-secret"));
    }

    #[test]
    fn versioning_and_inventory_parsers_fail_closed() {
        assert!(location_matches(
            "us-east-1",
            r#"<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>"#,
        ));
        assert!(location_matches(
            "eu-west-1",
            r"<LocationConstraint>EU</LocationConstraint>",
        ));
        assert!(!location_matches(
            "us-west-2",
            r"<LocationConstraint>eu-central-1</LocationConstraint>",
        ));
        assert!(!location_matches("us-east-1", "not XML"));

        let unversioned = quick_xml::de::from_str::<VersioningConfiguration>(
            r#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>"#,
        )
        .expect("unversioned response");
        assert!(unversioned.status.is_none());
        let enabled = quick_xml::de::from_str::<VersioningConfiguration>(
            r"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        )
        .expect("enabled response");
        assert_eq!(enabled.status.as_deref(), Some("Enabled"));

        let page = parse_list_page(
            &config(),
            r"<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>objects/v2/a&amp;b</Key><ETag>&quot;etag&quot;</ETag><Size>7</Size></Contents><NextContinuationToken>next&amp;token</NextContinuationToken></ListBucketResult>",
            100,
        )
        .expect("inventory page");
        assert_eq!(page.objects[0].storage_key, "v2/a&b");
        assert_eq!(page.objects[0].etag, "\"etag\"");
        assert_eq!(page.next_cursor.as_deref(), Some("next&token"));
        assert!(
            parse_list_page(
                &config(),
                r"<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
                100,
            )
            .is_err()
        );
    }
}
