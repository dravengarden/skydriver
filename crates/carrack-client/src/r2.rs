use futures_util::{StreamExt as _, stream};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    path::{Path, PathBuf},
};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio_util::io::ReaderStream;

use crate::Error;

const MAXIMUM_SINGLE_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const MULTIPART_THRESHOLD_BYTES: u64 = 100 * 1024 * 1024;
const MINIMUM_PART_BYTES: u64 = 5 * 1024 * 1024;
const MAXIMUM_PARTS: u64 = 10_000;
const NO_REPLACE_HEADER: &str = "*";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedGrant {
    method: String,
    url: String,
    #[serde(default)]
    verify_url: Option<String>,
    #[serde(default)]
    multipart_create_url: Option<String>,
    expires_at: u64,
}

#[derive(Serialize)]
struct MultipartGrantRequest<'a> {
    upload_id: &'a str,
    first_part: u32,
    part_count: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MultipartGrant {
    schema: String,
    upload_id: String,
    parts: Vec<PartGrant>,
    complete_url: String,
    abort_url: String,
    verify_url: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PartGrant {
    part_number: u32,
    url: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MultipartJournal {
    schema: String,
    intent_id: String,
    upload_id: String,
    encoded_bytes: u64,
    encoded_sha256: String,
    part_bytes: u64,
    etags: BTreeMap<u32, String>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the direct transfer binds control capability, immutable intent identity, staged object identity, and pipeline controls"
)]
pub(crate) async fn upload(
    control: &crate::Client,
    token: &str,
    intent_id: &str,
    credential: Value,
    path: &Path,
    bytes: u64,
    expected_sha256: &str,
    requested_part_bytes: u64,
    maximum_concurrency: usize,
) -> Result<(String, String, String), Error> {
    let grant = decode_grant(credential, "PUT")?;
    require_no_replace_signature(&grant.url)?;
    if bytes >= MULTIPART_THRESHOLD_BYTES || bytes > MAXIMUM_SINGLE_PUT_BYTES {
        return multipart_upload(
            control,
            token,
            intent_id,
            &grant,
            path,
            bytes,
            expected_sha256,
            requested_part_bytes,
            maximum_concurrency,
        )
        .await;
    }
    let http = &control.http;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|error| Error::InvalidResponse(format!("open R2 upload: {error}")))?;
    let response = http
        .put(&grant.url)
        .header(reqwest::header::IF_NONE_MATCH, NO_REPLACE_HEADER)
        .header(reqwest::header::CONTENT_LENGTH, bytes)
        .body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
        .send()
        .await
        .map_err(|error| provider_transport("upload R2 object", &error))?;
    if !response.status().is_success()
        && response.status() != reqwest::StatusCode::PRECONDITION_FAILED
    {
        return Err(provider_status("R2 upload", response.status(), false));
    }
    let verify_url = grant.verify_url.as_deref().ok_or_else(|| {
        Error::InvalidResponse("R2 upload grant omitted its readback URL".to_owned())
    })?;
    let etag = verify_readback(http, verify_url, bytes, expected_sha256).await?;
    Ok((expected_sha256.to_owned(), expected_sha256.to_owned(), etag))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "multipart resume identity, bounded grants, concurrent parts, completion, and readback form one upload transaction"
)]
async fn multipart_upload(
    control: &crate::Client,
    token: &str,
    intent_id: &str,
    initial: &SignedGrant,
    path: &Path,
    bytes: u64,
    expected_sha256: &str,
    requested_part_bytes: u64,
    maximum_concurrency: usize,
) -> Result<(String, String, String), Error> {
    let part_bytes = requested_part_bytes.clamp(MINIMUM_PART_BYTES, MAXIMUM_SINGLE_PUT_BYTES);
    let part_count = bytes.div_ceil(part_bytes);
    if part_count == 0 || part_count > MAXIMUM_PARTS || maximum_concurrency == 0 {
        return Err(Error::InvalidResponse(
            "R2 multipart parameters exceed provider bounds".to_owned(),
        ));
    }
    let journal_path = path.with_file_name(format!(".r2-multipart-{intent_id}.json"));
    let mut journal = match load_journal(&journal_path)? {
        Some(journal)
            if journal.intent_id == intent_id
                && journal.encoded_bytes == bytes
                && journal.encoded_sha256 == expected_sha256
                && journal.part_bytes == part_bytes =>
        {
            journal
        }
        Some(_) => {
            return Err(Error::InvalidResponse(
                "R2 multipart journal does not match the staged object".to_owned(),
            ));
        }
        None => {
            let create_url = initial.multipart_create_url.as_deref().ok_or_else(|| {
                Error::InvalidResponse("R2 grant omitted multipart initiation".to_owned())
            })?;
            require_no_replace_signature(create_url)?;
            let response = control
                .http
                .post(create_url)
                .header(reqwest::header::IF_NONE_MATCH, NO_REPLACE_HEADER)
                .header(reqwest::header::CONTENT_LENGTH, 0)
                .send()
                .await
                .map_err(|error| provider_transport("initiate R2 multipart upload", &error))?;
            if response.status() == reqwest::StatusCode::PRECONDITION_FAILED {
                let verify_url = initial.verify_url.as_deref().ok_or_else(|| {
                    Error::InvalidResponse("R2 grant omitted its readback URL".to_owned())
                })?;
                let etag =
                    verify_readback(&control.http, verify_url, bytes, expected_sha256).await?;
                return Ok((expected_sha256.to_owned(), expected_sha256.to_owned(), etag));
            }
            if !response.status().is_success() {
                return Err(provider_status(
                    "R2 multipart initiation",
                    response.status(),
                    false,
                ));
            }
            let body = response
                .text()
                .await
                .map_err(|error| provider_transport("read R2 multipart initiation", &error))?;
            let upload_id = xml_element(&body, "UploadId").ok_or_else(|| {
                Error::InvalidResponse("R2 multipart initiation omitted upload ID".to_owned())
            })?;
            let journal = MultipartJournal {
                schema: "carrack.r2-multipart-journal.v1".to_owned(),
                intent_id: intent_id.to_owned(),
                upload_id,
                encoded_bytes: bytes,
                encoded_sha256: expected_sha256.to_owned(),
                part_bytes,
                etags: BTreeMap::new(),
            };
            store_journal(&journal_path, &journal)?;
            journal
        }
    };

    let mut latest_grant = None;
    if journal.etags.len() as u64 == part_count
        && let Some(verify_url) = initial.verify_url.as_deref()
        && let Ok(etag) = verify_readback(&control.http, verify_url, bytes, expected_sha256).await
    {
        std::fs::remove_file(&journal_path).map_err(|error| {
            Error::InvalidResponse(format!("remove recovered R2 multipart journal: {error}"))
        })?;
        return Ok((expected_sha256.to_owned(), expected_sha256.to_owned(), etag));
    }
    for first in (1..=part_count).step_by(64) {
        let count = (part_count - first + 1).min(64);
        let grant: MultipartGrant = control
            .send_json(
                Method::POST,
                &format!("api/v2/puts/{intent_id}/r2-multipart-grant"),
                Some(token),
                &[],
                Some(&MultipartGrantRequest {
                    upload_id: &journal.upload_id,
                    first_part: u32::try_from(first).map_err(|_| {
                        Error::InvalidResponse("R2 part number overflow".to_owned())
                    })?,
                    part_count: u32::try_from(count)
                        .map_err(|_| Error::InvalidResponse("R2 part count overflow".to_owned()))?,
                }),
            )
            .await?;
        validate_multipart_grant(&grant, &journal.upload_id, first, count)?;
        let pending = grant
            .parts
            .iter()
            .filter(|part| !journal.etags.contains_key(&part.part_number))
            .collect::<Vec<_>>();
        let results = stream::iter(pending.into_iter().map(|part| {
            upload_part(
                &control.http,
                path,
                bytes,
                part_bytes,
                part.part_number,
                &part.url,
            )
        }))
        .buffer_unordered(maximum_concurrency.min(64))
        .collect::<Vec<_>>()
        .await;
        let mut first_error = None;
        for result in results {
            match result {
                Ok((part_number, etag)) => {
                    journal.etags.insert(part_number, etag);
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        store_journal(&journal_path, &journal)?;
        if let Some(error) = first_error {
            return Err(error);
        }
        latest_grant = Some(grant);
    }
    if journal.etags.len() as u64 != part_count {
        return Err(Error::InvalidResponse(
            "R2 multipart journal is incomplete after upload".to_owned(),
        ));
    }
    let grant = latest_grant.ok_or_else(|| {
        Error::InvalidResponse("R2 multipart completion grant is absent".to_owned())
    })?;
    let body = completion_xml(&journal.etags)?;
    require_no_replace_signature(&grant.complete_url)?;
    let response = control
        .http
        .post(&grant.complete_url)
        .header(reqwest::header::IF_NONE_MATCH, NO_REPLACE_HEADER)
        .header(reqwest::header::CONTENT_TYPE, "application/xml")
        .body(body)
        .send()
        .await
        .map_err(|error| provider_transport("complete R2 multipart", &error))?;
    if !response.status().is_success()
        && response.status() != reqwest::StatusCode::PRECONDITION_FAILED
    {
        return Err(provider_status(
            "R2 multipart completion",
            response.status(),
            false,
        ));
    }
    let etag = verify_readback(&control.http, &grant.verify_url, bytes, expected_sha256).await?;
    std::fs::remove_file(&journal_path).map_err(|error| {
        Error::InvalidResponse(format!("remove completed R2 multipart journal: {error}"))
    })?;
    Ok((expected_sha256.to_owned(), expected_sha256.to_owned(), etag))
}

async fn upload_part(
    http: &reqwest::Client,
    path: &Path,
    total_bytes: u64,
    part_bytes: u64,
    part_number: u32,
    url: &str,
) -> Result<(u32, String), Error> {
    let offset = u64::from(part_number.saturating_sub(1)).saturating_mul(part_bytes);
    let length = total_bytes.saturating_sub(offset).min(part_bytes);
    if length == 0 {
        return Err(Error::InvalidResponse(
            "R2 part lies beyond object".to_owned(),
        ));
    }
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| Error::InvalidResponse(format!("open R2 part source: {error}")))?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|error| Error::InvalidResponse(format!("seek R2 part source: {error}")))?;
    let response = http
        .put(url)
        .header(reqwest::header::CONTENT_LENGTH, length)
        .body(reqwest::Body::wrap_stream(ReaderStream::new(
            file.take(length),
        )))
        .send()
        .await
        .map_err(|error| provider_transport("upload R2 part", &error))?;
    if !response.status().is_success() {
        return Err(provider_status(
            &format!("R2 part {part_number}"),
            response.status(),
            false,
        ));
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(|value| value.trim_matches('"'))
        .filter(|value| valid_etag(value))
        .ok_or_else(|| Error::InvalidResponse("R2 part omitted a valid ETag".to_owned()))?;
    Ok((part_number, etag.to_owned()))
}

#[allow(
    clippy::too_many_arguments,
    reason = "direct download binds immutable object identity, staging, integrity, and range pipeline controls"
)]
pub(crate) async fn download(
    http: &reqwest::Client,
    credential: Value,
    staging_directory: &Path,
    version_id: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    part_bytes: u64,
    maximum_concurrency: usize,
) -> Result<PathBuf, Error> {
    let grant = decode_grant(credential, "GET")?;
    tokio::fs::create_dir_all(staging_directory)
        .await
        .map_err(|error| Error::InvalidResponse(format!("create R2 staging: {error}")))?;
    let path = staging_directory.join(format!("{version_id}.download"));
    if expected_bytes >= MULTIPART_THRESHOLD_BYTES && maximum_concurrency > 1 {
        return download_ranges(
            http,
            &grant.url,
            staging_directory,
            version_id,
            expected_bytes,
            expected_sha256,
            part_bytes.max(MINIMUM_PART_BYTES),
            maximum_concurrency,
        )
        .await;
    }
    let temporary = staging_directory.join(format!("{version_id}.download.partial"));
    let response = http
        .get(&grant.url)
        .send()
        .await
        .map_err(|error| provider_transport("download R2 object", &error))?;
    if !response.status().is_success() {
        return Err(provider_status("R2 download", response.status(), true));
    }
    let mut output = tokio::fs::File::create(&temporary)
        .await
        .map_err(|error| Error::InvalidResponse(format!("create R2 staging file: {error}")))?;
    let mut stream = response.bytes_stream();
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| provider_transport("read R2 response", &error))?;
        bytes = bytes.saturating_add(chunk.len() as u64);
        digest.update(&chunk);
        output
            .write_all(&chunk)
            .await
            .map_err(|error| Error::InvalidResponse(format!("write R2 staging: {error}")))?;
    }
    output
        .sync_all()
        .await
        .map_err(|error| Error::InvalidResponse(format!("sync R2 staging: {error}")))?;
    if bytes != expected_bytes || hex::encode(digest.finalize()) != expected_sha256 {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(Error::failure(
            crate::FailureKind::CorruptCiphertext,
            "R2 download failed encoded-byte verification",
        ));
    }
    tokio::fs::rename(&temporary, &path)
        .await
        .map_err(|error| Error::InvalidResponse(format!("publish R2 staging: {error}")))?;
    Ok(path)
}

#[allow(
    clippy::too_many_arguments,
    reason = "range planning binds one immutable signed object, staging identity, integrity, and concurrency controls"
)]
async fn download_ranges(
    http: &reqwest::Client,
    url: &str,
    staging_directory: &Path,
    version_id: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    part_bytes: u64,
    maximum_concurrency: usize,
) -> Result<PathBuf, Error> {
    let output_path = staging_directory.join(format!("{version_id}.download"));
    if output_path
        .metadata()
        .is_ok_and(|metadata| metadata.len() == expected_bytes)
        && hash_file(&output_path)? == expected_sha256
    {
        return Ok(output_path);
    }
    let part_root = staging_directory.join("parts").join(version_id);
    tokio::fs::create_dir_all(&part_root)
        .await
        .map_err(|error| Error::InvalidResponse(format!("create R2 range journal: {error}")))?;
    let part_count = expected_bytes.div_ceil(part_bytes);
    let pending = (0..part_count)
        .filter_map(|index| {
            let start = index.saturating_mul(part_bytes);
            let length = expected_bytes.saturating_sub(start).min(part_bytes);
            let path = part_root.join(format!("{index:08}.part"));
            (!path
                .metadata()
                .is_ok_and(|metadata| metadata.len() == length))
            .then_some((index, start, length, path))
        })
        .collect::<Vec<_>>();
    let results = stream::iter(pending.into_iter().map(|(_, start, length, path)| {
        download_range(http, url, start, length, expected_bytes, path)
    }))
    .buffer_unordered(maximum_concurrency.min(64))
    .collect::<Vec<_>>()
    .await;
    for result in results {
        result?;
    }
    let temporary = staging_directory.join(format!("{version_id}.download.partial"));
    let mut output = std::fs::File::create(&temporary)
        .map_err(|error| Error::InvalidResponse(format!("create R2 assembly: {error}")))?;
    let mut digest = Sha256::new();
    let mut assembled = 0_u64;
    for index in 0..part_count {
        let path = part_root.join(format!("{index:08}.part"));
        let bytes = std::fs::read(&path)
            .map_err(|error| Error::InvalidResponse(format!("read R2 range part: {error}")))?;
        assembled = assembled.saturating_add(
            u64::try_from(bytes.len())
                .map_err(|_| Error::InvalidResponse("R2 range part length overflow".to_owned()))?,
        );
        digest.update(&bytes);
        std::io::Write::write_all(&mut output, &bytes)
            .map_err(|error| Error::InvalidResponse(format!("assemble R2 ranges: {error}")))?;
    }
    std::io::Write::flush(&mut output)
        .map_err(|error| Error::InvalidResponse(format!("flush R2 assembly: {error}")))?;
    output
        .sync_all()
        .map_err(|error| Error::InvalidResponse(format!("sync R2 assembly: {error}")))?;
    if assembled != expected_bytes || hex::encode(digest.finalize()) != expected_sha256 {
        let _ = std::fs::remove_file(&temporary);
        let _ = std::fs::remove_dir_all(&part_root);
        return Err(Error::failure(
            crate::FailureKind::CorruptCiphertext,
            "R2 range assembly failed encoded-byte verification",
        ));
    }
    std::fs::rename(&temporary, &output_path)
        .map_err(|error| Error::InvalidResponse(format!("publish R2 assembly: {error}")))?;
    std::fs::remove_dir_all(&part_root)
        .map_err(|error| Error::InvalidResponse(format!("remove R2 range journal: {error}")))?;
    Ok(output_path)
}

async fn download_range(
    http: &reqwest::Client,
    url: &str,
    start: u64,
    length: u64,
    total_bytes: u64,
    path: PathBuf,
) -> Result<(), Error> {
    let end = start
        .checked_add(length)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| Error::InvalidResponse("R2 range overflow".to_owned()))?;
    let response = http
        .get(url)
        .header(reqwest::header::RANGE, format!("bytes={start}-{end}"))
        .send()
        .await
        .map_err(|error| provider_transport("download R2 range", &error))?;
    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        return Err(provider_status("R2 range", response.status(), true));
    }
    let expected_content_range = format!("bytes {start}-{end}/{total_bytes}");
    if response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        != Some(expected_content_range.as_str())
    {
        return Err(Error::failure(
            crate::FailureKind::CorruptCiphertext,
            "R2 range did not bind the exact provider object length",
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| provider_transport("read R2 range", &error))?;
    if bytes.len() as u64 != length {
        return Err(Error::failure(
            crate::FailureKind::CorruptCiphertext,
            "R2 range length does not match request",
        ));
    }
    let temporary = path.with_extension("part.tmp");
    tokio::fs::write(&temporary, &bytes)
        .await
        .map_err(|error| Error::InvalidResponse(format!("write R2 range: {error}")))?;
    tokio::fs::rename(&temporary, path)
        .await
        .map_err(|error| Error::InvalidResponse(format!("publish R2 range: {error}")))
}

fn hash_file(path: &Path) -> Result<String, Error> {
    let mut input = std::fs::File::open(path)
        .map_err(|error| Error::InvalidResponse(format!("open R2 assembly: {error}")))?;
    let mut digest = Sha256::new();
    std::io::copy(&mut input, &mut digest)
        .map_err(|error| Error::InvalidResponse(format!("hash R2 assembly: {error}")))?;
    Ok(hex::encode(digest.finalize()))
}

fn decode_grant(value: Value, expected_method: &str) -> Result<SignedGrant, Error> {
    let grant = serde_json::from_value::<SignedGrant>(value)
        .map_err(|error| Error::InvalidResponse(format!("decode R2 signed grant: {error}")))?;
    if grant.method != expected_method || !safe_signed_url(&grant.url) || grant.expires_at == 0 {
        return Err(Error::InvalidResponse("invalid R2 signed grant".to_owned()));
    }
    Ok(grant)
}

fn validate_multipart_grant(
    grant: &MultipartGrant,
    upload_id: &str,
    first_part: u64,
    part_count: u64,
) -> Result<(), Error> {
    if grant.schema != "carrack.vfs.r2-multipart-grant.v1"
        || grant.upload_id != upload_id
        || grant.parts.len() as u64 != part_count
        || grant.expires_at == 0
        || !safe_signed_url(&grant.complete_url)
        || !safe_signed_url(&grant.abort_url)
        || !safe_signed_url(&grant.verify_url)
        || grant.parts.iter().enumerate().any(|(index, part)| {
            u64::from(part.part_number) != first_part + index as u64 || !safe_signed_url(&part.url)
        })
    {
        return Err(Error::InvalidResponse(
            "invalid R2 multipart grant".to_owned(),
        ));
    }
    Ok(())
}

fn load_journal(path: &Path) -> Result<Option<MultipartJournal>, Error> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::InvalidResponse(format!(
                "read R2 multipart journal: {error}"
            )));
        }
    };
    let journal = serde_json::from_slice::<MultipartJournal>(&bytes)
        .map_err(|error| Error::InvalidResponse(format!("decode R2 journal: {error}")))?;
    if journal.schema != "carrack.r2-multipart-journal.v1"
        || journal.upload_id.is_empty()
        || journal.upload_id.len() > 1_024
        || journal.etags.keys().any(|part| *part == 0)
        || journal.etags.values().any(|etag| !valid_etag(etag))
    {
        return Err(Error::InvalidResponse(
            "invalid R2 multipart journal".to_owned(),
        ));
    }
    Ok(Some(journal))
}

fn store_journal(path: &Path, journal: &MultipartJournal) -> Result<(), Error> {
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| Error::InvalidResponse(format!("encode R2 journal: {error}")))?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, bytes)
        .map_err(|error| Error::InvalidResponse(format!("write R2 journal: {error}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| Error::InvalidResponse(format!("protect R2 journal: {error}")))?;
    }
    std::fs::rename(&temporary, path)
        .map_err(|error| Error::InvalidResponse(format!("publish R2 journal: {error}")))
}

fn completion_xml(etags: &BTreeMap<u32, String>) -> Result<String, Error> {
    if etags.is_empty() {
        return Err(Error::InvalidResponse(
            "cannot complete an empty R2 multipart upload".to_owned(),
        ));
    }
    let mut body = String::from("<CompleteMultipartUpload>");
    for (part_number, etag) in etags {
        if *part_number == 0 || !valid_etag(etag) {
            return Err(Error::InvalidResponse(
                "invalid R2 multipart completion identity".to_owned(),
            ));
        }
        write!(
            body,
            "<Part><PartNumber>{part_number}</PartNumber><ETag>&quot;{etag}&quot;</ETag></Part>"
        )
        .expect("writing to a String cannot fail");
    }
    body.push_str("</CompleteMultipartUpload>");
    Ok(body)
}

fn valid_etag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn xml_element(document: &str, element: &str) -> Option<String> {
    let start = format!("<{element}>");
    let end = format!("</{element}>");
    let value = document.split_once(&start)?.1.split_once(&end)?.0;
    let decoded = value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'");
    (!decoded.is_empty() && decoded.len() <= 1_024).then_some(decoded)
}

fn safe_signed_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            || (url.scheme() == "http"
                && url
                    .host_str()
                    .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1")))
    })
}

fn require_no_replace_signature(value: &str) -> Result<(), Error> {
    let url = url::Url::parse(value)
        .map_err(|error| Error::InvalidResponse(format!("parse R2 signed URL: {error}")))?;
    let signed_headers = url
        .query_pairs()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("X-Amz-SignedHeaders")
                .then_some(value)
        })
        .ok_or_else(|| {
            Error::InvalidResponse("R2 upload grant omitted signed headers".to_owned())
        })?;
    if !signed_headers
        .split(';')
        .any(|name| name.eq_ignore_ascii_case("if-none-match"))
    {
        return Err(Error::InvalidResponse(
            "R2 upload grant does not enforce atomic no-replace".to_owned(),
        ));
    }
    Ok(())
}

fn provider_transport(operation: &str, error: &reqwest::Error) -> Error {
    Error::failure(
        crate::FailureKind::ProviderUnavailable,
        format!("{operation}: {error}"),
    )
}

fn provider_status(
    operation: &str,
    status: reqwest::StatusCode,
    immutable_object_expected: bool,
) -> Error {
    let kind = if immutable_object_expected
        && matches!(
            status,
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE
        ) {
        crate::FailureKind::PermanentLoss
    } else {
        crate::FailureKind::ProviderUnavailable
    };
    Error::failure(kind, format!("{operation} returned {status}"))
}

async fn verify_readback(
    http: &reqwest::Client,
    url: &str,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<String, Error> {
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|error| provider_transport("read back R2 upload", &error))?;
    if !response.status().is_success() {
        return Err(provider_status(
            "R2 upload readback",
            response.status(),
            true,
        ));
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_matches('"').to_owned())
        .filter(|value| valid_etag(value))
        .ok_or_else(|| {
            Error::InvalidResponse("R2 upload readback omitted its exact ETag".to_owned())
        })?;
    let mut stream = response.bytes_stream();
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| provider_transport("read R2 verification", &error))?;
        bytes = bytes.saturating_add(chunk.len() as u64);
        digest.update(&chunk);
    }
    if bytes != expected_bytes || hex::encode(digest.finalize()) != expected_sha256 {
        return Err(Error::failure(
            crate::FailureKind::CorruptCiphertext,
            "R2 upload failed encoded-byte readback verification",
        ));
    }
    Ok(etag)
}

#[cfg(test)]
mod tests {
    use httpmock::{
        Method::{GET, POST, PUT},
        MockServer,
    };
    use sha2::{Digest as _, Sha256};

    use super::{
        SignedGrant, download_ranges, multipart_upload, provider_status,
        require_no_replace_signature, upload,
    };

    #[test]
    fn upload_grants_must_bind_the_no_replace_header() {
        assert!(
            require_no_replace_signature(
                "https://bucket.example/object?X-Amz-SignedHeaders=host%3Bif-none-match"
            )
            .is_ok()
        );
        assert!(
            require_no_replace_signature("https://bucket.example/object?X-Amz-SignedHeaders=host")
                .is_err()
        );
    }

    #[tokio::test]
    async fn multipart_round_trip_journals_parts_and_verifies_readback() {
        let server = MockServer::start_async().await;
        let payload = "x".repeat(5 * 1024 * 1024);
        let sha256 = hex::encode(Sha256::digest(payload.as_bytes()));
        let create = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/create")
                    .header("If-None-Match", "*");
                then.status(200)
                    .body("<InitiateMultipartUploadResult><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>");
            })
            .await;
        let part = server
            .mock_async(|when, then| {
                when.method(PUT).path("/part/1").body(payload.clone());
                then.status(200).header("ETag", "part-etag");
            })
            .await;
        let complete = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/complete")
                    .header("If-None-Match", "*");
                then.status(412);
            })
            .await;
        let verify = server
            .mock_async(|when, then| {
                when.method(GET).path("/verify");
                then.status(200)
                    .header("ETag", "verified-etag")
                    .body(payload.clone());
            })
            .await;
        let grant = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/api/v2/puts/intent/r2-multipart-grant");
                then.status(200).json_body(serde_json::json!({
                    "schema": "carrack.vfs.r2-multipart-grant.v1",
                    "upload_id": "upload-1",
                    "parts": [{"part_number": 1, "url": server.url("/part/1")}],
                    "complete_url": format!("{}?X-Amz-SignedHeaders=host%3Bif-none-match", server.url("/complete")),
                    "abort_url": server.url("/abort"),
                    "verify_url": server.url("/verify"),
                    "expires_at": 2_000_000_000,
                }));
            })
            .await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("encoded");
        std::fs::write(&path, payload.as_bytes()).expect("write staged object");
        let control = crate::Client::new(&format!("{}/", server.base_url())).expect("client");
        let initial = SignedGrant {
            method: "PUT".to_owned(),
            url: format!(
                "{}?X-Amz-SignedHeaders=host%3Bif-none-match",
                server.url("/single")
            ),
            verify_url: Some(server.url("/verify")),
            multipart_create_url: Some(format!(
                "{}?X-Amz-SignedHeaders=host%3Bif-none-match",
                server.url("/create")
            )),
            expires_at: 2_000_000_000,
        };
        let result = multipart_upload(
            &control,
            "token",
            "intent",
            &initial,
            &path,
            u64::try_from(payload.len()).expect("payload length"),
            &sha256,
            5 * 1024 * 1024,
            2,
        )
        .await
        .expect("multipart upload");
        assert_eq!(result.2, "verified-etag");
        assert!(!directory.path().join(".r2-multipart-intent.json").exists());
        create.assert_async().await;
        grant.assert_async().await;
        part.assert_async().await;
        complete.assert_async().await;
        verify.assert_async().await;
    }

    #[tokio::test]
    async fn single_put_adopts_only_an_identical_no_replace_collision() {
        let server = MockServer::start_async().await;
        let payload = b"already present";
        let sha256 = hex::encode(Sha256::digest(payload));
        let put = server
            .mock_async(|when, then| {
                when.method(PUT)
                    .path("/object")
                    .header("If-None-Match", "*");
                then.status(412);
            })
            .await;
        let verify = server
            .mock_async(|when, then| {
                when.method(GET).path("/verify");
                then.status(200)
                    .header("ETag", "existing-etag")
                    .body(payload.as_slice());
            })
            .await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("encoded");
        std::fs::write(&path, payload).expect("write staged object");
        let control = crate::Client::new(&format!("{}/", server.base_url())).expect("client");
        let credential = serde_json::json!({
            "method": "PUT",
            "url": format!("{}?X-Amz-SignedHeaders=host%3Bif-none-match", server.url("/object")),
            "verify_url": server.url("/verify"),
            "multipart_create_url": format!("{}?X-Amz-SignedHeaders=host%3Bif-none-match", server.url("/create")),
            "expires_at": 2_000_000_000_u64,
        });
        let result = upload(
            &control,
            "token",
            "intent",
            credential,
            &path,
            u64::try_from(payload.len()).expect("payload length"),
            &sha256,
            5 * 1024 * 1024,
            1,
        )
        .await
        .expect("adopt identical object");
        assert_eq!(result.2, "existing-etag");
        put.assert_async().await;
        verify.assert_async().await;
    }

    #[tokio::test]
    async fn single_put_rejects_a_different_no_replace_collision() {
        let server = MockServer::start_async().await;
        let payload = b"expected bytes";
        let sha256 = hex::encode(Sha256::digest(payload));
        let put = server
            .mock_async(|when, then| {
                when.method(PUT)
                    .path("/object")
                    .header("If-None-Match", "*");
                then.status(412);
            })
            .await;
        let verify = server
            .mock_async(|when, then| {
                when.method(GET).path("/verify");
                then.status(200)
                    .header("ETag", "different-etag")
                    .body("different bytes");
            })
            .await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("encoded");
        std::fs::write(&path, payload).expect("write staged object");
        let control = crate::Client::new(&format!("{}/", server.base_url())).expect("client");
        let error = upload(
            &control,
            "token",
            "intent",
            serde_json::json!({
                "method": "PUT",
                "url": format!("{}?X-Amz-SignedHeaders=host%3Bif-none-match", server.url("/object")),
                "verify_url": server.url("/verify"),
                "multipart_create_url": format!("{}?X-Amz-SignedHeaders=host%3Bif-none-match", server.url("/create")),
                "expires_at": 2_000_000_000_u64,
            }),
            &path,
            u64::try_from(payload.len()).expect("payload length"),
            &sha256,
            5 * 1024 * 1024,
            1,
        )
        .await
        .expect_err("different existing object must fail closed");
        assert_eq!(
            error.failure_kind(),
            Some(crate::FailureKind::CorruptCiphertext)
        );
        put.assert_async().await;
        verify.assert_async().await;
    }

    #[tokio::test]
    async fn concurrent_range_download_assembles_and_verifies() {
        let server = MockServer::start_async().await;
        let first = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/object")
                    .header("Range", "bytes=0-4");
                then.status(206)
                    .header("Content-Range", "bytes 0-4/10")
                    .body("abcde");
            })
            .await;
        let second = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/object")
                    .header("Range", "bytes=5-9");
                then.status(206)
                    .header("Content-Range", "bytes 5-9/10")
                    .body("fghij");
            })
            .await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let sha256 = hex::encode(Sha256::digest(b"abcdefghij"));
        let path = download_ranges(
            &reqwest::Client::new(),
            &server.url("/object"),
            directory.path(),
            "version",
            10,
            &sha256,
            5,
            2,
        )
        .await
        .expect("range download");
        assert_eq!(std::fs::read(path).expect("read assembly"), b"abcdefghij");
        first.assert_async().await;
        second.assert_async().await;
    }

    #[tokio::test]
    async fn range_download_rejects_a_correct_prefix_of_a_larger_object() {
        let server = MockServer::start_async().await;
        let range = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/object")
                    .header("Range", "bytes=0-4");
                then.status(206)
                    .header("Content-Range", "bytes 0-4/6")
                    .body("abcde");
            })
            .await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let error = download_ranges(
            &reqwest::Client::new(),
            &server.url("/object"),
            directory.path(),
            "larger-version",
            5,
            &hex::encode(Sha256::digest(b"abcde")),
            5,
            1,
        )
        .await
        .expect_err("a correct prefix must not hide extra provider bytes");
        assert_eq!(
            error.failure_kind(),
            Some(crate::FailureKind::CorruptCiphertext)
        );
        range.assert_async().await;
    }

    #[tokio::test]
    async fn classifies_corrupt_range_assembly_without_message_parsing() {
        let server = MockServer::start_async().await;
        let first = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/corrupt")
                    .header("Range", "bytes=0-4");
                then.status(206)
                    .header("Content-Range", "bytes 0-4/10")
                    .body("abcde");
            })
            .await;
        let second = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/corrupt")
                    .header("Range", "bytes=5-9");
                then.status(206)
                    .header("Content-Range", "bytes 5-9/10")
                    .body("xxxxx");
            })
            .await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let expected = hex::encode(Sha256::digest(b"abcdefghij"));
        let error = download_ranges(
            &reqwest::Client::new(),
            &server.url("/corrupt"),
            directory.path(),
            "corrupt-version",
            10,
            &expected,
            5,
            2,
        )
        .await
        .expect_err("reject corrupt provider object");
        assert_eq!(
            error.failure_kind(),
            Some(crate::FailureKind::CorruptCiphertext)
        );
        first.assert_async().await;
        second.assert_async().await;
    }

    #[test]
    fn classifies_provider_outage_and_permanent_loss() {
        assert_eq!(
            provider_status("download", reqwest::StatusCode::NOT_FOUND, true).failure_kind(),
            Some(crate::FailureKind::PermanentLoss)
        );
        assert_eq!(
            provider_status("download", reqwest::StatusCode::SERVICE_UNAVAILABLE, true)
                .failure_kind(),
            Some(crate::FailureKind::ProviderUnavailable)
        );
        assert_eq!(
            provider_status("upload", reqwest::StatusCode::NOT_FOUND, false).failure_kind(),
            Some(crate::FailureKind::ProviderUnavailable)
        );
    }
}
