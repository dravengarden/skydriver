//! Complete-object streaming I/O around the portable Carrack crypto core.

use carrack_sdk_core::{EncryptionDescriptor, FrameCipher};
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::{Zeroize, Zeroizing};

use crate::private_fs::ensure_private_directory;

const SUITE: &str = "carrack-vfs-aes256gcm-hkdfsha256-v1";
static DOWNLOAD_TEMPORARY_ORDINAL: AtomicU64 = AtomicU64::new(0);

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
    ensure_private_directory(staging_root, "staging directory")?;
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
        return cleanup_failure(
            &temporary_path,
            crate::FailureKind::UnsupportedSuite,
            format!("unsupported crypto suite {suite}"),
        );
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

pub(crate) fn restore_to_staging(
    encoded: &Path,
    parent: &Path,
    suite: &str,
    descriptor: &Descriptor,
    directory_key: Option<&[u8; 32]>,
) -> Result<PathBuf, crate::Error> {
    std::fs::create_dir_all(parent).map_err(|error| {
        crate::Error::InvalidResponse(format!("create download parent: {error}"))
    })?;
    let mut input = std::io::BufReader::new(std::fs::File::open(encoded).map_err(|error| {
        crate::Error::InvalidResponse(format!("open encoded download: {error}"))
    })?);
    let (temporary, file) = create_download_temporary(parent)?;
    let mut output = std::io::BufWriter::new(file);
    let restored = if suite == "plaintext/v1" {
        if directory_key.is_some() {
            Err(crate::Error::InvalidResponse(
                "plaintext download exposed a key".to_owned(),
            ))
        } else {
            copy_plaintext(&mut input, &mut output, descriptor.plaintext_bytes).map(|_| ())
        }
    } else if suite == SUITE {
        directory_key.map_or_else(
            || {
                Err(crate::Error::InvalidResponse(
                    "encrypted download omitted its key".to_owned(),
                ))
            },
            |key| open_frames(&mut input, &mut output, descriptor, key),
        )
    } else {
        Err(crate::Error::failure(
            crate::FailureKind::UnsupportedSuite,
            format!("unsupported download crypto suite {suite}"),
        ))
    };
    if let Err(error) = restored {
        drop(output);
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = output.flush() {
        drop(output);
        return cleanup_error(&temporary, &format!("flush download temporary: {error}"));
    }
    if let Err(error) = output.get_ref().sync_all() {
        drop(output);
        return cleanup_error(&temporary, &format!("sync download temporary: {error}"));
    }
    drop(output);
    Ok(temporary)
}

fn create_download_temporary(parent: &Path) -> Result<(PathBuf, std::fs::File), crate::Error> {
    loop {
        let ordinal = DOWNLOAD_TEMPORARY_ORDINAL.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".carrack-download-{}-{ordinal:016x}.tmp",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    {
                        drop(file);
                        let _ = std::fs::remove_file(&path);
                        return Err(crate::Error::InvalidResponse(format!(
                            "protect download temporary: {error}"
                        )));
                    }
                }
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(crate::Error::InvalidResponse(format!(
                    "create download temporary: {error}"
                )));
            }
        }
    }
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
    let mut cipher = FrameCipher::new(core_descriptor(descriptor), directory_key)
        .map_err(|error| crate::Error::InvalidResponse(error.to_string()))?;
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
        let tag = cipher
            .seal_frame(
                ordinal,
                descriptor.plaintext_bytes,
                &mut frame[..plaintext_length],
            )
            .map_err(|error| {
                crate::Error::InvalidResponse(format!("encrypt frame {ordinal}: {error}"))
            })?;
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
    let cipher = FrameCipher::new(core_descriptor(descriptor), directory_key)
        .map_err(|error| crate::Error::InvalidResponse(error.to_string()))?;
    let encoded_frame_capacity = frame_capacity
        .checked_add(16)
        .ok_or_else(|| crate::Error::InvalidResponse("encoded frame size overflows".to_owned()))?;
    let mut frame = Zeroizing::new(vec![0_u8; encoded_frame_capacity]);
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
                crate::Error::failure(
                    crate::FailureKind::CorruptCiphertext,
                    format!("read encrypted frame {ordinal}: {error}"),
                )
            })?;
        let (ciphertext, tag) = frame[..plaintext_length + 16].split_at_mut(plaintext_length);
        let tag: &[u8; 16] = (&*tag).try_into().map_err(|_| {
            crate::Error::failure(
                crate::FailureKind::CorruptCiphertext,
                format!("encrypted frame {ordinal} tag width differs"),
            )
        })?;
        cipher
            .open_frame(ordinal, descriptor.plaintext_bytes, ciphertext, tag)
            .map_err(|error| {
                crate::Error::failure(
                    crate::FailureKind::CorruptCiphertext,
                    format!("authenticate encrypted frame {ordinal}: {error}"),
                )
            })?;
        output.write_all(ciphertext).map_err(|error| {
            crate::Error::InvalidResponse(format!("write plaintext frame: {error}"))
        })?;
    }
    let mut extra = [0_u8; 1];
    if input.read(&mut extra).map_err(|error| {
        crate::Error::failure(
            crate::FailureKind::CorruptCiphertext,
            format!("read encrypted object EOF: {error}"),
        )
    })? != 0
    {
        return Err(crate::Error::failure(
            crate::FailureKind::CorruptCiphertext,
            "encrypted object contains trailing bytes",
        ));
    }
    Ok(())
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

fn core_descriptor(descriptor: &Descriptor) -> EncryptionDescriptor {
    EncryptionDescriptor {
        directory_id: descriptor.directory_id,
        version_id: descriptor.version_id,
        key_epoch: descriptor.key_epoch,
        frame_bytes: descriptor.frame_bytes,
    }
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

fn cleanup_error<T>(path: &Path, message: &str) -> Result<T, crate::Error> {
    let _ = std::fs::remove_file(path);
    Err(crate::Error::InvalidResponse(message.to_owned()))
}

fn cleanup_failure<T>(
    path: &Path,
    kind: crate::FailureKind,
    message: impl Into<String>,
) -> Result<T, crate::Error> {
    let _ = std::fs::remove_file(path);
    Err(crate::Error::failure(kind, message))
}

#[cfg(test)]
mod tests {
    use super::{Descriptor, restore_to_staging, stage};

    fn descriptor() -> Descriptor {
        Descriptor {
            directory_id: [1; 16],
            version_id: [2; 16],
            key_epoch: 1,
            frame_bytes: 2,
            plaintext_bytes: 3,
        }
    }

    #[test]
    fn distinguishes_unsupported_suite_and_authenticated_corruption() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("source");
        std::fs::write(&source, b"abc").expect("write source");
        let Err(unsupported) = stage(
            &source,
            directory.path(),
            "unsupported",
            "future-suite/v1",
            &descriptor(),
            None,
        ) else {
            panic!("accepted unsupported suite");
        };
        assert_eq!(
            unsupported.failure_kind(),
            Some(crate::FailureKind::UnsupportedSuite)
        );

        let key = [3; 32];
        let staged = stage(
            &source,
            directory.path(),
            "corrupt",
            "carrack-vfs-aes256gcm-hkdfsha256-v1",
            &descriptor(),
            Some(&key),
        )
        .expect("stage encrypted object");
        let mut encoded = std::fs::read(&staged.path).expect("read encoded object");
        encoded[0] ^= 1;
        std::fs::write(&staged.path, encoded).expect("tamper encoded object");
        let corrupt = restore_to_staging(
            &staged.path,
            directory.path(),
            "carrack-vfs-aes256gcm-hkdfsha256-v1",
            &descriptor(),
            Some(&key),
        )
        .expect_err("reject corrupt ciphertext");
        assert_eq!(
            corrupt.failure_kind(),
            Some(crate::FailureKind::CorruptCiphertext)
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("read temporary directory")
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".carrack-download-"))
                .count(),
            0
        );
    }

    #[test]
    fn plaintext_staging_is_unique_within_one_process() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let encoded = directory.path().join("encoded");
        std::fs::write(&encoded, b"abc").expect("write encoded plaintext");

        let first = restore_to_staging(
            &encoded,
            directory.path(),
            "plaintext/v1",
            &descriptor(),
            None,
        )
        .expect("restore first plaintext staging");
        let second = restore_to_staging(
            &encoded,
            directory.path(),
            "plaintext/v1",
            &descriptor(),
            None,
        )
        .expect("restore second plaintext staging");

        assert_ne!(first, second);
        assert_eq!(std::fs::read(first).expect("read first staging"), b"abc");
        assert_eq!(std::fs::read(second).expect("read second staging"), b"abc");
    }
}
