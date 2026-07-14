//! Complete-object AES-256-GCM framing compatible with Carrack VFS V1.

use aes_gcm::{
    Aes256Gcm, KeyInit as _, Nonce,
    aead::{AeadInPlace as _, generic_array::GenericArray},
};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const SUITE: &str = "carrack-vfs-aes256gcm-hkdfsha256-v1";
const FILE_KEY_INFO: &[u8] = b"carrack.vfs.file-key.v1";
const FRAME_AAD_DOMAIN: &[u8] = b"carrack.vfs.file-frame.v1\0";

pub(crate) struct Descriptor {
    pub directory_id: [u8; 16],
    pub version_id: [u8; 16],
    pub key_epoch: u64,
    pub frame_bytes: u64,
    pub plaintext_bytes: u64,
}

pub(crate) struct StagedObject {
    pub path: PathBuf,
    pub encoded_bytes: u64,
    pub encoded_sha256: String,
}

pub(crate) fn stage(
    source: &Path,
    staging_root: &Path,
    intent_id: &str,
    suite: &str,
    descriptor: &Descriptor,
    directory_key: Option<&[u8; 32]>,
) -> Result<StagedObject, crate::Error> {
    ensure_private_directory(staging_root)?;
    let final_path = staging_root.join(format!("{intent_id}.encoded"));
    let temporary_path = staging_root.join(format!(".{intent_id}-{}.partial", std::process::id()));
    let mut input = std::io::BufReader::new(std::fs::File::open(source).map_err(|error| {
        crate::Error::InvalidResponse(format!("open source for encoding: {error}"))
    })?);
    let temporary = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|error| {
            crate::Error::InvalidResponse(format!("create encoded staging: {error}"))
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                crate::Error::InvalidResponse(format!("protect encoded staging: {error}"))
            })?;
    }
    let mut output = std::io::BufWriter::new(temporary);
    let identity = if suite == "plaintext/v1" {
        if directory_key.is_some() {
            return cleanup_error(&temporary_path, "plaintext preparation exposed a key");
        }
        copy_plaintext(&mut input, &mut output, descriptor.plaintext_bytes)?
    } else if suite == SUITE {
        let key = directory_key.ok_or_else(|| {
            crate::Error::InvalidResponse("encrypted preparation omitted its key".to_owned())
        })?;
        seal_frames(&mut input, &mut output, descriptor, key)?
    } else {
        return cleanup_error(&temporary_path, "unsupported crypto suite");
    };
    output.flush().map_err(|error| {
        crate::Error::InvalidResponse(format!("flush encoded staging: {error}"))
    })?;
    output
        .get_ref()
        .sync_all()
        .map_err(|error| crate::Error::InvalidResponse(format!("sync encoded staging: {error}")))?;
    drop(output);
    if final_path.exists() {
        std::fs::remove_file(&final_path).map_err(|error| {
            crate::Error::InvalidResponse(format!("replace stale staging: {error}"))
        })?;
    }
    std::fs::rename(&temporary_path, &final_path).map_err(|error| {
        crate::Error::InvalidResponse(format!("publish encoded staging: {error}"))
    })?;
    Ok(StagedObject {
        path: final_path,
        encoded_bytes: identity.0,
        encoded_sha256: identity.1,
    })
}

pub(crate) fn restore(
    encoded: &Path,
    destination: &Path,
    suite: &str,
    descriptor: &Descriptor,
    directory_key: Option<&[u8; 32]>,
) -> Result<(), crate::Error> {
    let parent = destination.parent().ok_or_else(|| {
        crate::Error::InvalidResponse("download destination has no parent".to_owned())
    })?;
    std::fs::create_dir_all(parent).map_err(|error| {
        crate::Error::InvalidResponse(format!("create download parent: {error}"))
    })?;
    let temporary = parent.join(format!(".carrack-download-{}", std::process::id()));
    let mut input = std::io::BufReader::new(std::fs::File::open(encoded).map_err(|error| {
        crate::Error::InvalidResponse(format!("open encoded download: {error}"))
    })?);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            crate::Error::InvalidResponse(format!("create download temporary: {error}"))
        })?;
    let mut output = std::io::BufWriter::new(file);
    if suite == "plaintext/v1" {
        if directory_key.is_some() {
            return cleanup_error(&temporary, "plaintext download exposed a key");
        }
        copy_plaintext(&mut input, &mut output, descriptor.plaintext_bytes)?;
    } else if suite == SUITE {
        let key = directory_key.ok_or_else(|| {
            crate::Error::InvalidResponse("encrypted download omitted its key".to_owned())
        })?;
        open_frames(&mut input, &mut output, descriptor, key)?;
    } else {
        return cleanup_error(&temporary, "unsupported download crypto suite");
    }
    output.flush().map_err(|error| {
        crate::Error::InvalidResponse(format!("flush download temporary: {error}"))
    })?;
    output.get_ref().sync_all().map_err(|error| {
        crate::Error::InvalidResponse(format!("sync download temporary: {error}"))
    })?;
    drop(output);
    if destination.exists() {
        return cleanup_error(&temporary, "download destination already exists");
    }
    std::fs::rename(&temporary, destination).map_err(|error| {
        crate::Error::InvalidResponse(format!("publish downloaded file: {error}"))
    })?;
    Ok(())
}

fn seal_frames<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    descriptor: &Descriptor,
    directory_key: &[u8; 32],
) -> Result<(u64, String), crate::Error> {
    if descriptor.key_epoch == 0
        || descriptor.frame_bytes == 0
        || descriptor.frame_bytes > usize::MAX as u64
    {
        return Err(crate::Error::InvalidResponse(
            "invalid encryption descriptor".to_owned(),
        ));
    }
    let mut salt = [0_u8; 32];
    salt[..16].copy_from_slice(&descriptor.directory_id);
    salt[16..].copy_from_slice(&descriptor.version_id);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), directory_key);
    let mut file_key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(FILE_KEY_INFO, file_key.as_mut())
        .map_err(|_| crate::Error::InvalidResponse("derive file key".to_owned()))?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(file_key.as_ref()));
    let frame_capacity = usize::try_from(descriptor.frame_bytes)
        .map_err(|_| crate::Error::InvalidResponse("frame exceeds this platform".to_owned()))?;
    let mut frame = Zeroizing::new(vec![0_u8; frame_capacity]);
    let mut encoded_hasher = Sha256::new();
    let frame_count = if descriptor.plaintext_bytes == 0 {
        0
    } else {
        1 + (descriptor.plaintext_bytes - 1) / descriptor.frame_bytes
    };
    let mut encoded_bytes = 0_u64;
    for ordinal in 0..frame_count {
        let offset = ordinal * descriptor.frame_bytes;
        let plaintext_bytes = descriptor
            .frame_bytes
            .min(descriptor.plaintext_bytes - offset);
        let plaintext_length = usize::try_from(plaintext_bytes)
            .map_err(|_| crate::Error::InvalidResponse("frame exceeds this platform".to_owned()))?;
        input
            .read_exact(&mut frame[..plaintext_length])
            .map_err(|error| {
                crate::Error::InvalidResponse(format!("read encryption frame {ordinal}: {error}"))
            })?;
        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&ordinal.to_be_bytes());
        let aad = frame_aad(descriptor, ordinal, plaintext_bytes);
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad,
                &mut frame[..plaintext_length],
            )
            .map_err(|_| crate::Error::InvalidResponse(format!("encrypt frame {ordinal}")))?;
        output
            .write_all(&frame[..plaintext_length])
            .and_then(|()| output.write_all(&tag))
            .map_err(|error| {
                crate::Error::InvalidResponse(format!("write encrypted frame: {error}"))
            })?;
        encoded_hasher.update(&frame[..plaintext_length]);
        encoded_hasher.update(tag);
        encoded_bytes += plaintext_bytes + 16;
    }
    require_eof(input)?;
    frame.zeroize();
    Ok((encoded_bytes, hex::encode(encoded_hasher.finalize())))
}

fn open_frames<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    descriptor: &Descriptor,
    directory_key: &[u8; 32],
) -> Result<(), crate::Error> {
    let frame_capacity = usize::try_from(descriptor.frame_bytes)
        .map_err(|_| crate::Error::InvalidResponse("frame exceeds this platform".to_owned()))?;
    let mut salt = [0_u8; 32];
    salt[..16].copy_from_slice(&descriptor.directory_id);
    salt[16..].copy_from_slice(&descriptor.version_id);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), directory_key);
    let mut file_key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(FILE_KEY_INFO, file_key.as_mut())
        .map_err(|_| crate::Error::InvalidResponse("derive file key".to_owned()))?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(file_key.as_ref()));
    let mut frame = Zeroizing::new(vec![0_u8; frame_capacity + 16]);
    let frame_count = if descriptor.plaintext_bytes == 0 {
        0
    } else {
        1 + (descriptor.plaintext_bytes - 1) / descriptor.frame_bytes
    };
    for ordinal in 0..frame_count {
        let offset = ordinal * descriptor.frame_bytes;
        let plaintext_bytes = descriptor
            .frame_bytes
            .min(descriptor.plaintext_bytes - offset);
        let plaintext_length = usize::try_from(plaintext_bytes)
            .map_err(|_| crate::Error::InvalidResponse("frame exceeds this platform".to_owned()))?;
        input
            .read_exact(&mut frame[..plaintext_length + 16])
            .map_err(|error| {
                crate::Error::InvalidResponse(format!("read encrypted frame {ordinal}: {error}"))
            })?;
        let (ciphertext, tag) = frame[..plaintext_length + 16].split_at_mut(plaintext_length);
        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&ordinal.to_be_bytes());
        let aad = frame_aad(descriptor, ordinal, plaintext_bytes);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad,
                ciphertext,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| {
                crate::Error::InvalidResponse(format!("authenticate encrypted frame {ordinal}"))
            })?;
        output.write_all(ciphertext).map_err(|error| {
            crate::Error::InvalidResponse(format!("write plaintext frame: {error}"))
        })?;
    }
    require_eof(input)
}

fn copy_plaintext<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    length: u64,
) -> Result<(u64, String), crate::Error> {
    let mut hasher = Sha256::new();
    let mut remaining = length;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while remaining != 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            crate::Error::InvalidResponse("copy length exceeds this platform".to_owned())
        })?;
        input.read_exact(&mut buffer[..take]).map_err(|error| {
            crate::Error::InvalidResponse(format!("read plaintext staging: {error}"))
        })?;
        output.write_all(&buffer[..take]).map_err(|error| {
            crate::Error::InvalidResponse(format!("write plaintext staging: {error}"))
        })?;
        hasher.update(&buffer[..take]);
        remaining -= take as u64;
    }
    require_eof(input)?;
    buffer.zeroize();
    Ok((length, hex::encode(hasher.finalize())))
}

fn frame_aad(descriptor: &Descriptor, ordinal: u64, plaintext_bytes: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FRAME_AAD_DOMAIN.len() + 64);
    aad.extend_from_slice(FRAME_AAD_DOMAIN);
    aad.extend_from_slice(&descriptor.directory_id);
    aad.extend_from_slice(&descriptor.version_id);
    aad.extend_from_slice(&descriptor.key_epoch.to_be_bytes());
    aad.extend_from_slice(&descriptor.frame_bytes.to_be_bytes());
    aad.extend_from_slice(&descriptor.plaintext_bytes.to_be_bytes());
    aad.extend_from_slice(&ordinal.to_be_bytes());
    aad.extend_from_slice(&plaintext_bytes.to_be_bytes());
    aad
}

fn require_eof<R: Read>(input: &mut R) -> Result<(), crate::Error> {
    let mut extra = [0_u8; 1];
    if input
        .read(&mut extra)
        .map_err(|error| crate::Error::InvalidResponse(format!("read source EOF: {error}")))?
        != 0
    {
        return Err(crate::Error::InvalidResponse(
            "source contains trailing bytes".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), crate::Error> {
    if !path.is_absolute() {
        return Err(crate::Error::InvalidResponse(
            "staging directory must be absolute".to_owned(),
        ));
    }
    std::fs::create_dir_all(path).map_err(|error| {
        crate::Error::InvalidResponse(format!("create staging directory: {error}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| crate::Error::InvalidResponse(format!("protect staging directory: {error}")),
        )?;
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        crate::Error::InvalidResponse(format!("inspect staging directory: {error}"))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(crate::Error::InvalidResponse(
            "staging directory is unsafe".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(crate::Error::InvalidResponse(
                "staging directory must use mode 0700".to_owned(),
            ));
        }
    }
    Ok(())
}

fn cleanup_error<T>(path: &Path, message: &str) -> Result<T, crate::Error> {
    let _ = std::fs::remove_file(path);
    Err(crate::Error::InvalidResponse(message.to_owned()))
}
