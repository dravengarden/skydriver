use futures_util::StreamExt as _;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt as _;
use tokio_util::io::ReaderStream;

use crate::Error;

const MAXIMUM_SINGLE_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedGrant {
    method: String,
    url: String,
    #[serde(default)]
    verify_url: Option<String>,
    expires_at: u64,
}

pub(crate) async fn upload(
    http: &reqwest::Client,
    credential: Value,
    path: &Path,
    bytes: u64,
    expected_sha256: &str,
) -> Result<(String, String, String), Error> {
    if bytes > MAXIMUM_SINGLE_PUT_BYTES {
        return Err(Error::InvalidResponse(
            "R2 object exceeds the 5 GiB single-PUT limit; multipart upload is required".to_owned(),
        ));
    }
    let grant = decode_grant(credential, "PUT")?;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|error| Error::InvalidResponse(format!("open R2 upload: {error}")))?;
    let response = http
        .put(&grant.url)
        .header(reqwest::header::CONTENT_LENGTH, bytes)
        .body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
        .send()
        .await
        .map_err(|error| Error::InvalidResponse(format!("upload R2 object: {error}")))?;
    if !response.status().is_success() {
        return Err(Error::InvalidResponse(format!(
            "R2 upload returned {}",
            response.status()
        )));
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap_or(expected_sha256)
        .trim_matches('"')
        .to_owned();
    let verify_url = grant.verify_url.as_deref().ok_or_else(|| {
        Error::InvalidResponse("R2 upload grant omitted its readback URL".to_owned())
    })?;
    verify_readback(http, verify_url, bytes, expected_sha256).await?;
    Ok((expected_sha256.to_owned(), expected_sha256.to_owned(), etag))
}

pub(crate) async fn download(
    http: &reqwest::Client,
    credential: Value,
    staging_directory: &Path,
    version_id: &str,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<PathBuf, Error> {
    let grant = decode_grant(credential, "GET")?;
    tokio::fs::create_dir_all(staging_directory)
        .await
        .map_err(|error| Error::InvalidResponse(format!("create R2 staging: {error}")))?;
    let path = staging_directory.join(format!("{version_id}.download"));
    let temporary = staging_directory.join(format!("{version_id}.download.partial"));
    let response = http
        .get(&grant.url)
        .send()
        .await
        .map_err(|error| Error::InvalidResponse(format!("download R2 object: {error}")))?;
    if !response.status().is_success() {
        return Err(Error::InvalidResponse(format!(
            "R2 download returned {}",
            response.status()
        )));
    }
    let mut output = tokio::fs::File::create(&temporary)
        .await
        .map_err(|error| Error::InvalidResponse(format!("create R2 staging file: {error}")))?;
    let mut stream = response.bytes_stream();
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|error| Error::InvalidResponse(format!("read R2 response: {error}")))?;
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
        return Err(Error::InvalidResponse(
            "R2 download failed encoded-byte verification".to_owned(),
        ));
    }
    tokio::fs::rename(&temporary, &path)
        .await
        .map_err(|error| Error::InvalidResponse(format!("publish R2 staging: {error}")))?;
    Ok(path)
}

fn decode_grant(value: Value, expected_method: &str) -> Result<SignedGrant, Error> {
    let grant = serde_json::from_value::<SignedGrant>(value)
        .map_err(|error| Error::InvalidResponse(format!("decode R2 signed grant: {error}")))?;
    if grant.method != expected_method
        || !grant.url.starts_with("https://")
        || grant.expires_at == 0
    {
        return Err(Error::InvalidResponse("invalid R2 signed grant".to_owned()));
    }
    Ok(grant)
}

async fn verify_readback(
    http: &reqwest::Client,
    url: &str,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<(), Error> {
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|error| Error::InvalidResponse(format!("read back R2 upload: {error}")))?;
    if !response.status().is_success() {
        return Err(Error::InvalidResponse(format!(
            "R2 upload readback returned {}",
            response.status()
        )));
    }
    let mut stream = response.bytes_stream();
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|error| Error::InvalidResponse(format!("read R2 verification: {error}")))?;
        bytes = bytes.saturating_add(chunk.len() as u64);
        digest.update(&chunk);
    }
    if bytes != expected_bytes || hex::encode(digest.finalize()) != expected_sha256 {
        return Err(Error::InvalidResponse(
            "R2 upload failed encoded-byte readback verification".to_owned(),
        ));
    }
    Ok(())
}
