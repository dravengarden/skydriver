pub(crate) use carrack_driver_contract::R2Config as Config;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Fetch, Headers, Method, Request, RequestInit};
use zeroize::Zeroize as _;

type HmacSha256 = Hmac<Sha256>;

const SERVICE: &str = "s3";
const REGION: &str = "auto";
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credential {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
    }
}

pub(crate) fn valid_config(config: &Config) -> bool {
    let Some(authority) = config.endpoint.strip_prefix("https://") else {
        return false;
    };
    !authority.is_empty()
        && !authority.contains(['/', '?', '#', '@'])
        && (authority.ends_with(".r2.cloudflarestorage.com")
            || authority.ends_with(".eu.r2.cloudflarestorage.com")
            || authority.ends_with(".fedramp.r2.cloudflarestorage.com"))
        && valid_component(&config.bucket, 63)
        && (config.prefix.is_empty()
            || (config.prefix.ends_with('/')
                && config.prefix.len() <= 1_024
                && !config.prefix.starts_with('/')
                && !config.prefix.contains("..")))
}

pub(crate) fn valid_credential(credential: &Credential) -> bool {
    valid_secret(&credential.access_key_id, 256) && valid_secret(&credential.secret_access_key, 256)
}

pub(crate) fn object_key(config: &Config, storage_key: &str) -> Option<String> {
    if storage_key.is_empty()
        || storage_key.starts_with('/')
        || storage_key.contains("..")
        || storage_key.len() > 4_096
    {
        return None;
    }
    Some(format!("{}{storage_key}", config.prefix))
}

pub(crate) fn presign(
    method: &str,
    config: &Config,
    credential: &Credential,
    key: &str,
    expires_seconds: u64,
) -> Option<String> {
    presign_query_at(
        method,
        config,
        credential,
        key,
        expires_seconds,
        &[],
        &amz_timestamp()?,
    )
}

fn presign_query(
    method: &str,
    config: &Config,
    credential: &Credential,
    key: &str,
    expires_seconds: u64,
    query: &[(&str, &str)],
) -> Option<String> {
    presign_query_at(
        method,
        config,
        credential,
        key,
        expires_seconds,
        query,
        &amz_timestamp()?,
    )
}

fn presign_query_at(
    method: &str,
    config: &Config,
    credential: &Credential,
    key: &str,
    expires_seconds: u64,
    extra_query: &[(&str, &str)],
    timestamp: &str,
) -> Option<String> {
    if !matches!(method, "GET" | "PUT" | "POST" | "DELETE")
        || !valid_config(config)
        || !valid_credential(credential)
        || expires_seconds == 0
        || expires_seconds > 900
    {
        return None;
    }
    let host = config.endpoint.strip_prefix("https://")?;
    let date = timestamp.get(..8)?;
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let canonical_uri = format!(
        "/{}/{}",
        percent_encode(&config.bucket, true),
        percent_encode(key, false)
    );
    let mut query = vec![
        ("X-Amz-Algorithm".to_owned(), ALGORITHM.to_owned()),
        (
            "X-Amz-Credential".to_owned(),
            format!("{}/{}", credential.access_key_id, scope),
        ),
        ("X-Amz-Date".to_owned(), timestamp.to_owned()),
        ("X-Amz-Expires".to_owned(), expires_seconds.to_string()),
        ("X-Amz-SignedHeaders".to_owned(), "host".to_owned()),
    ];
    query.extend(
        extra_query
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    query.sort_by(|left, right| {
        percent_encode(&left.0, true)
            .cmp(&percent_encode(&right.0, true))
            .then_with(|| percent_encode(&left.1, true).cmp(&percent_encode(&right.1, true)))
    });
    let canonical_query = query
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                percent_encode(name, true),
                percent_encode(value, true)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
    );
    let string_to_sign = format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let signing_key = signing_key(&credential.secret_access_key, date)?;
    let signature = hex(&hmac(&signing_key, string_to_sign.as_bytes())?);
    Some(format!(
        "{}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}",
        config.endpoint
    ))
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
    let url = presign(method, &config, &credential, &key, lifetime)?;
    let verify_url = if method == "PUT" {
        Some(presign("GET", &config, &credential, &key, lifetime)?)
    } else {
        None
    };
    let multipart_create_url = if method == "PUT" {
        Some(presign_query(
            "POST",
            &config,
            &credential,
            &key,
            lifetime,
            &[("uploads", "")],
        )?)
    } else {
        None
    };
    Some(serde_json::json!({
        "method": method,
        "url": url,
        "verify_url": verify_url,
        "multipart_create_url": multipart_create_url,
        "expires_at": now + lifetime,
    }))
}

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
            let url = presign_query(
                "PUT",
                &config,
                &credential,
                &key,
                lifetime,
                &[("partNumber", &part), ("uploadId", upload_id)],
            )?;
            Some(serde_json::json!({"part_number": part_number, "url": url}))
        })
        .collect::<Option<Vec<_>>>()?;
    let complete_url = presign_query(
        "POST",
        &config,
        &credential,
        &key,
        lifetime,
        &[("uploadId", upload_id)],
    )?;
    let abort_url = presign_query(
        "DELETE",
        &config,
        &credential,
        &key,
        lifetime,
        &[("uploadId", upload_id)],
    )?;
    let verify_url = presign("GET", &config, &credential, &key, lifetime)?;
    Some(serde_json::json!({
        "schema": "carrack.vfs.r2-multipart-grant.v1",
        "upload_id": upload_id,
        "parts": parts,
        "complete_url": complete_url,
        "abort_url": abort_url,
        "verify_url": verify_url,
        "expires_at": now + lifetime,
    }))
}

pub(crate) async fn verify(config: &Config, credential: &Credential) -> bool {
    if !valid_config(config) || !valid_credential(credential) {
        return false;
    }
    let key = format!(
        ".carrack/credential-check/{}",
        hex(&Sha256::digest(credential.access_key_id.as_bytes()))
    );
    let Some(put_url) = presign("PUT", config, credential, &key, 60) else {
        return false;
    };
    let headers = Headers::new();
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
    let Some(delete_url) = presign("DELETE", config, credential, &key, 60) else {
        return false;
    };
    let Ok(request) = Request::new(&delete_url, Method::Delete) else {
        return false;
    };
    Fetch::Request(request).send().await.is_ok_and(|response| {
        response.status_code() == 404 || (200..300).contains(&response.status_code())
    })
}

pub(crate) async fn delete_from_plaintext(
    config_json: &str,
    storage_key: &str,
    plaintext: &[u8],
) -> Result<(), worker::Error> {
    let config = serde_json::from_str::<Config>(config_json)
        .map_err(|error| worker::Error::RustError(format!("decode R2 config: {error}")))?;
    let credential = serde_json::from_slice::<Credential>(plaintext)
        .map_err(|error| worker::Error::RustError(format!("decode R2 credential: {error}")))?;
    let key = object_key(&config, storage_key)
        .ok_or_else(|| worker::Error::RustError("invalid R2 storage key".to_owned()))?;
    let url = presign("DELETE", &config, &credential, &key, 60)
        .ok_or_else(|| worker::Error::RustError("sign R2 delete".to_owned()))?;
    let request = Request::new(&url, Method::Delete)?;
    let response = Fetch::Request(request).send().await?;
    if response.status_code() == 404 || (200..300).contains(&response.status_code()) {
        Ok(())
    } else {
        Err(worker::Error::RustError(format!(
            "R2 delete returned {}",
            response.status_code()
        )))
    }
}

pub(crate) async fn cleanup_upload_from_plaintext(
    config_json: &str,
    storage_key: &str,
    upload_id: Option<&str>,
    plaintext: &[u8],
) -> Result<(), worker::Error> {
    let config = serde_json::from_str::<Config>(config_json)
        .map_err(|error| worker::Error::RustError(format!("decode R2 config: {error}")))?;
    let credential = serde_json::from_slice::<Credential>(plaintext)
        .map_err(|error| worker::Error::RustError(format!("decode R2 credential: {error}")))?;
    let key = object_key(&config, storage_key)
        .ok_or_else(|| worker::Error::RustError("invalid R2 storage key".to_owned()))?;
    if let Some(upload_id) = upload_id {
        let url = presign_query(
            "DELETE",
            &config,
            &credential,
            &key,
            60,
            &[("uploadId", upload_id)],
        )
        .ok_or_else(|| worker::Error::RustError("sign R2 multipart abort".to_owned()))?;
        let request = Request::new(&url, Method::Delete)?;
        let response = Fetch::Request(request).send().await?;
        if response.status_code() != 404 && !(200..300).contains(&response.status_code()) {
            return Err(worker::Error::RustError(format!(
                "R2 multipart abort returned {}",
                response.status_code()
            )));
        }
    }
    let url = presign("DELETE", &config, &credential, &key, 60)
        .ok_or_else(|| worker::Error::RustError("sign R2 cleanup delete".to_owned()))?;
    let request = Request::new(&url, Method::Delete)?;
    let response = Fetch::Request(request).send().await?;
    if response.status_code() == 404 || (200..300).contains(&response.status_code()) {
        Ok(())
    } else {
        Err(worker::Error::RustError(format!(
            "R2 cleanup delete returned {}",
            response.status_code()
        )))
    }
}

fn signing_key(secret: &str, date: &str) -> Option<Vec<u8>> {
    let date_key = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
    let region_key = hmac(&date_key, REGION.as_bytes())?;
    let service_key = hmac(&region_key, SERVICE.as_bytes())?;
    hmac(&service_key, b"aws4_request")
}

fn hmac(key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(value);
    Some(mac.finalize().into_bytes().to_vec())
}

fn amz_timestamp() -> Option<String> {
    let iso = js_sys::Date::new_0().to_iso_string().as_string()?;
    if iso.len() < 19 {
        return None;
    }
    Some(format!(
        "{}{}{}T{}{}{}Z",
        &iso[0..4],
        &iso[5..7],
        &iso[8..10],
        &iso[11..13],
        &iso[14..16],
        &iso[17..19]
    ))
}

fn percent_encode(value: &str, encode_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (!encode_slash && byte == b'/')
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
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

fn valid_component(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_secret(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.trim() == value && !value.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::{Config, Credential, object_key, percent_encode, presign_query_at, valid_config};

    #[test]
    fn validates_r2_identity_and_canonical_keys() {
        let config = Config {
            endpoint: "https://0123456789abcdef.r2.cloudflarestorage.com".to_owned(),
            bucket: "payload-dev".to_owned(),
            prefix: "carrack/dev/".to_owned(),
            managed: false,
        };
        assert!(valid_config(&config));
        assert_eq!(
            object_key(&config, "objects/v2/ab/value").as_deref(),
            Some("carrack/dev/objects/v2/ab/value")
        );
        assert_eq!(percent_encode("a b/c", false), "a%20b/c");
    }

    #[test]
    fn grant_contains_only_a_short_lived_signed_url() {
        let config = Config {
            endpoint: "https://0123456789abcdef.r2.cloudflarestorage.com".to_owned(),
            bucket: "payload-dev".to_owned(),
            prefix: String::new(),
            managed: false,
        };
        let credential = Credential {
            access_key_id: "test-access".to_owned(),
            secret_access_key: "test-secret".to_owned(),
        };
        let grant = presign_query_at(
            "PUT",
            &config,
            &credential,
            "objects/v2/value",
            900,
            &[],
            "20260715T120000Z",
        )
        .expect("sign grant");
        assert!(grant.contains("X-Amz-Signature"));
        assert!(grant.contains("X-Amz-Expires"));
        assert!(!grant.contains("test-secret"));
    }

    #[test]
    fn multipart_query_is_canonical_and_provider_values_are_encoded() {
        let config = Config {
            endpoint: "https://0123456789abcdef.r2.cloudflarestorage.com".to_owned(),
            bucket: "payload-dev".to_owned(),
            prefix: String::new(),
            managed: false,
        };
        let credential = Credential {
            access_key_id: "test-access".to_owned(),
            secret_access_key: "test-secret".to_owned(),
        };
        let grant = presign_query_at(
            "PUT",
            &config,
            &credential,
            "objects/value",
            900,
            &[("uploadId", "id+/="), ("partNumber", "7")],
            "20260715T120000Z",
        )
        .expect("sign multipart part");
        assert!(grant.contains("partNumber=7"));
        assert!(grant.contains("uploadId=id%2B%2F%3D"));
        assert!(!grant.contains("test-secret"));
    }
}
