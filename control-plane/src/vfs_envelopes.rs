use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use sha2::Sha256;
use worker::{Env, Result, wasm_bindgen::JsValue};
use zeroize::Zeroize as _;

pub(crate) const ENCRYPTED_SUITE: &str = "carrack-vfs-aes256gcm-hkdfsha256-v1";
pub(crate) const PLAINTEXT_SUITE: &str = "plaintext/v1";
pub(crate) const ENVELOPE_ALGORITHM: &str = "aes-256-gcm/v1";
pub(crate) const MASTER_KEY_VERSION: &str = "v1";

const MASTER_KEY_BYTES: usize = 32;
const DIRECTORY_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const MAXIMUM_CREDENTIAL_BYTES: usize = 64 << 10;
const DIRECTORY_AAD_DOMAIN: &str = "carrack.vfs.directory-key-envelope.v1";
const CREDENTIAL_AAD_DOMAIN: &str = "carrack.vfs.driver-credential-envelope.v1";
const BOOTSTRAP_TOKEN_INFO: &str = "carrack.vfs.bootstrap-token.v1";
const CHILD_TOKEN_INFO: &str = "carrack.vfs.child-token.v1";

pub(crate) struct SealedEnvelope {
    pub(crate) nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
}

pub(crate) struct DirectoryEnvelopeRef<'a> {
    pub(crate) directory_id: &'a str,
    pub(crate) key_epoch: u64,
    pub(crate) crypto_suite: &'a str,
    pub(crate) algorithm: &'a str,
    pub(crate) master_key_version: &'a str,
    pub(crate) nonce: &'a [u8],
    pub(crate) ciphertext: &'a [u8],
}

pub(crate) fn seal_directory_key(
    env: &Env,
    directory_id: &str,
    key_epoch: u64,
    crypto_suite: &str,
    directory_key: &[u8; DIRECTORY_KEY_BYTES],
) -> Result<SealedEnvelope> {
    let mut master_key = load_master_key(env, MASTER_KEY_VERSION)?;
    let result = seal_directory_key_with_master(
        &master_key,
        directory_id,
        key_epoch,
        crypto_suite,
        directory_key,
    );
    master_key.zeroize();
    result
}

pub(crate) fn open_directory_key(
    env: &Env,
    envelope: &DirectoryEnvelopeRef<'_>,
) -> Result<[u8; DIRECTORY_KEY_BYTES]> {
    validate_envelope(
        envelope.algorithm,
        envelope.master_key_version,
        envelope.nonce,
        envelope.ciphertext,
    )?;

    let mut master_key = load_master_key(env, envelope.master_key_version)?;
    let aad = directory_aad(
        envelope.directory_id,
        envelope.key_epoch,
        envelope.crypto_suite,
    );
    let opened = open(
        &master_key,
        envelope.nonce,
        envelope.ciphertext,
        &aad,
        "directory key",
    );
    master_key.zeroize();

    let mut plaintext = opened?;
    let converted: Result<&[u8; DIRECTORY_KEY_BYTES]> =
        plaintext.as_slice().try_into().map_err(|_| {
            worker::Error::RustError("VFS directory key envelope has the wrong length".to_owned())
        });
    let key = converted.copied();
    plaintext.zeroize();
    let key = key?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(worker::Error::RustError(
            "VFS directory key envelope contains a zero key".to_owned(),
        ));
    }

    Ok(key)
}

pub(crate) fn open_driver_credential(
    env: &Env,
    credential_id: &str,
    revision: u64,
    envelope_algorithm: &str,
    master_key_version: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    validate_envelope(envelope_algorithm, master_key_version, nonce, ciphertext)?;
    if ciphertext.len() > MAXIMUM_CREDENTIAL_BYTES + 16 {
        return Err(worker::Error::RustError(
            "VFS driver credential envelope exceeds its limit".to_owned(),
        ));
    }

    let mut master_key = load_master_key(env, master_key_version)?;
    let aad = credential_aad(credential_id, revision);
    let opened = open(&master_key, nonce, ciphertext, &aad, "driver credential");
    master_key.zeroize();
    let plaintext = opened?;
    if plaintext.is_empty() || plaintext.len() > MAXIMUM_CREDENTIAL_BYTES {
        return Err(worker::Error::RustError(
            "VFS driver credential plaintext has an invalid length".to_owned(),
        ));
    }

    Ok(plaintext)
}

pub(crate) fn seal_driver_credential(
    env: &Env,
    credential_id: &str,
    revision: u64,
    plaintext: &[u8],
) -> Result<SealedEnvelope> {
    let mut master_key = load_master_key(env, MASTER_KEY_VERSION)?;
    let result =
        seal_driver_credential_with_master(&master_key, credential_id, revision, plaintext);
    master_key.zeroize();
    result
}

fn seal_driver_credential_with_master(
    master_key: &[u8; MASTER_KEY_BYTES],
    credential_id: &str,
    revision: u64,
    plaintext: &[u8],
) -> Result<SealedEnvelope> {
    if plaintext.is_empty() || plaintext.len() > MAXIMUM_CREDENTIAL_BYTES || revision == 0 {
        return Err(worker::Error::RustError(
            "VFS driver credential plaintext has an invalid length or revision".to_owned(),
        ));
    }

    let mut nonce = vec![0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|error| {
        worker::Error::RustError(format!(
            "generate VFS driver credential envelope nonce: {error}"
        ))
    })?;
    let aad = credential_aad(credential_id, revision);
    let ciphertext = cipher(master_key)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| worker::Error::RustError("seal VFS driver credential envelope".to_owned()))?;

    Ok(SealedEnvelope { nonce, ciphertext })
}

pub(crate) fn derive_bootstrap_token(
    env: &Env,
    request_sha256: &[u8; 32],
    idempotency_key: &str,
) -> Result<String> {
    let mut master_key = load_master_key(env, MASTER_KEY_VERSION)?;
    let hkdf = Hkdf::<Sha256>::new(Some(request_sha256), &master_key);
    let mut token = [0_u8; 32];
    let mut info = Vec::with_capacity(BOOTSTRAP_TOKEN_INFO.len() + 1 + idempotency_key.len());
    info.extend_from_slice(BOOTSTRAP_TOKEN_INFO.as_bytes());
    info.push(0);
    info.extend_from_slice(idempotency_key.as_bytes());
    let expanded = hkdf
        .expand(&info, &mut token)
        .map_err(|_| worker::Error::RustError("derive VFS bootstrap bearer token".to_owned()));
    master_key.zeroize();
    expanded?;

    let encoded = URL_SAFE_NO_PAD.encode(token);
    token.zeroize();
    Ok(encoded)
}

/// Derives a recoverable attenuated bearer without retaining it in D1.
///
/// The parent identity and caller-supplied idempotency key are domain-separated
/// inputs, while the canonical request digest is the HKDF salt. An exact retry
/// returns the same secret; any scope change returns a different secret and is
/// rejected by the immutable receipt.
pub(crate) fn derive_child_token(
    env: &Env,
    parent_token_id: &str,
    request_sha256: &[u8; 32],
    idempotency_key: &str,
) -> Result<String> {
    let mut master_key = load_master_key(env, MASTER_KEY_VERSION)?;
    let hkdf = Hkdf::<Sha256>::new(Some(request_sha256), &master_key);
    let mut token = [0_u8; 32];
    let mut info = Vec::with_capacity(
        CHILD_TOKEN_INFO.len() + parent_token_id.len() + idempotency_key.len() + 2,
    );
    info.extend_from_slice(CHILD_TOKEN_INFO.as_bytes());
    info.push(0);
    info.extend_from_slice(parent_token_id.as_bytes());
    info.push(0);
    info.extend_from_slice(idempotency_key.as_bytes());
    let expanded = hkdf
        .expand(&info, &mut token)
        .map_err(|_| worker::Error::RustError("derive VFS child bearer token".to_owned()));
    master_key.zeroize();
    expanded?;

    let encoded = URL_SAFE_NO_PAD.encode(token);
    token.zeroize();
    Ok(encoded)
}

pub(crate) fn blob_binding(bytes: &[u8]) -> JsValue {
    js_sys::Uint8Array::from(bytes).buffer().into()
}

fn seal_directory_key_with_master(
    master_key: &[u8; MASTER_KEY_BYTES],
    directory_id: &str,
    key_epoch: u64,
    crypto_suite: &str,
    directory_key: &[u8; DIRECTORY_KEY_BYTES],
) -> Result<SealedEnvelope> {
    if directory_key.iter().all(|byte| *byte == 0) {
        return Err(worker::Error::RustError(
            "VFS directory key must not be zero".to_owned(),
        ));
    }

    let mut nonce = vec![0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|error| {
        worker::Error::RustError(format!("generate VFS directory envelope nonce: {error}"))
    })?;
    let aad = directory_aad(directory_id, key_epoch, crypto_suite);
    let cipher = cipher(master_key)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: directory_key,
                aad: &aad,
            },
        )
        .map_err(|_| worker::Error::RustError("seal VFS directory key envelope".to_owned()))?;

    Ok(SealedEnvelope { nonce, ciphertext })
}

fn open(
    master_key: &[u8; MASTER_KEY_BYTES],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    purpose: &str,
) -> Result<Vec<u8>> {
    cipher(master_key)?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| worker::Error::RustError(format!("open VFS {purpose} envelope")))
}

fn cipher(master_key: &[u8; MASTER_KEY_BYTES]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(master_key)
        .map_err(|_| worker::Error::RustError("construct VFS envelope cipher".to_owned()))
}

fn validate_envelope(
    envelope_algorithm: &str,
    master_key_version: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<()> {
    if envelope_algorithm != ENVELOPE_ALGORITHM
        || master_key_version != MASTER_KEY_VERSION
        || nonce.len() != NONCE_BYTES
        || ciphertext.len() < 16
    {
        return Err(worker::Error::RustError(
            "unsupported or malformed VFS secret envelope".to_owned(),
        ));
    }

    Ok(())
}

fn load_master_key(env: &Env, version: &str) -> Result<[u8; MASTER_KEY_BYTES]> {
    if version != MASTER_KEY_VERSION {
        return Err(worker::Error::RustError(format!(
            "unsupported VFS master key version {version:?}"
        )));
    }

    let secret_name = "CARRACK_VFS_MASTER_KEY_V1";
    let mut encoded = env.secret(secret_name)?.to_string();
    let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes());
    encoded.zeroize();
    let mut decoded = decoded.map_err(|_| {
        worker::Error::RustError(format!("{secret_name} is not unpadded base64url"))
    })?;
    let converted: Result<&[u8; MASTER_KEY_BYTES]> = decoded.as_slice().try_into().map_err(|_| {
        worker::Error::RustError(format!("{secret_name} must encode exactly 32 bytes"))
    });
    let key = converted.copied();
    decoded.zeroize();
    let key = key?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(worker::Error::RustError(format!(
            "{secret_name} must not be zero"
        )));
    }

    Ok(key)
}

fn directory_aad(directory_id: &str, key_epoch: u64, crypto_suite: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        DIRECTORY_AAD_DOMAIN.len() + directory_id.len() + crypto_suite.len() + 18,
    );
    aad.extend_from_slice(DIRECTORY_AAD_DOMAIN.as_bytes());
    aad.push(0);
    aad.extend_from_slice(directory_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad.push(0);
    aad.extend_from_slice(crypto_suite.as_bytes());
    aad
}

fn credential_aad(credential_id: &str, revision: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CREDENTIAL_AAD_DOMAIN.len() + credential_id.len() + 10);
    aad.extend_from_slice(CREDENTIAL_AAD_DOMAIN.as_bytes());
    aad.push(0);
    aad.extend_from_slice(credential_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize as _;

    use super::{
        ENCRYPTED_SUITE, MASTER_KEY_BYTES, credential_aad, open, seal_directory_key_with_master,
        seal_driver_credential_with_master,
    };

    #[test]
    fn directory_envelope_authenticates_every_context_field() {
        let mut master = [7_u8; MASTER_KEY_BYTES];
        let mut directory_key = [9_u8; 32];
        let sealed = seal_directory_key_with_master(
            &master,
            "10000000000000000000000000000001",
            1,
            ENCRYPTED_SUITE,
            &directory_key,
        )
        .expect("seal directory key");
        let aad = super::directory_aad("10000000000000000000000000000001", 1, ENCRYPTED_SUITE);

        assert_eq!(
            open(&master, &sealed.nonce, &sealed.ciphertext, &aad, "test")
                .expect("open directory key"),
            directory_key
        );
        let wrong = super::directory_aad("10000000000000000000000000000002", 1, ENCRYPTED_SUITE);
        assert!(open(&master, &sealed.nonce, &sealed.ciphertext, &wrong, "test").is_err());

        master.zeroize();
        directory_key.zeroize();
    }

    #[test]
    fn credential_envelope_authenticates_identity_and_revision() {
        let mut master = [7_u8; MASTER_KEY_BYTES];
        let mut credential = br#"{"access_token":"private"}"#.to_vec();
        let sealed =
            seal_driver_credential_with_master(&master, "credential:aliyun-main", 2, &credential)
                .expect("seal driver credential");
        let aad = credential_aad("credential:aliyun-main", 2);

        assert_eq!(
            open(&master, &sealed.nonce, &sealed.ciphertext, &aad, "test")
                .expect("open driver credential"),
            credential
        );
        let wrong_revision = credential_aad("credential:aliyun-main", 3);
        assert!(
            open(
                &master,
                &sealed.nonce,
                &sealed.ciphertext,
                &wrong_revision,
                "test"
            )
            .is_err()
        );

        master.zeroize();
        credential.zeroize();
    }
}
