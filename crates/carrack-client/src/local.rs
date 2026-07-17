//! Root-confined local filesystem complete-object driver.

use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use sha2::{Digest as _, Sha256};
use std::{
    io::{Read, Seek as _, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{Error, FailureKind, driver::safe_storage_key, private_fs::ensure_private_directory};

pub(crate) struct UploadedObject {
    pub(crate) native_id: String,
    pub(crate) provider_version: String,
    pub(crate) etag: String,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the local adapter binds one rooted grant to an exact staged object and bounded pipeline"
)]
pub(crate) fn upload(
    root: &str,
    intent_id: &str,
    storage_key: &str,
    source: &Path,
    encoded_bytes: u64,
    encoded_sha256: &str,
    part_bytes: u64,
    maximum_concurrency: usize,
) -> Result<UploadedObject, Error> {
    let relative = safe_storage_key(storage_key)?;
    let directory = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|error| Error::InvalidResponse(format!("open local driver root: {error}")))?;
    if let Some(parent) = relative.parent() {
        directory
            .create_dir_all(parent)
            .map_err(|error| Error::InvalidResponse(format!("create object parent: {error}")))?;
    }
    let part_count = encoded_bytes.div_ceil(part_bytes);
    let part_root = PathBuf::from(format!(".carrack/uploads/{intent_id}"));
    directory
        .create_dir_all(&part_root)
        .map_err(|error| Error::InvalidResponse(format!("create upload journal: {error}")))?;
    upload_parts(
        &directory,
        source,
        &part_root,
        encoded_bytes,
        part_bytes,
        part_count,
        maximum_concurrency,
    )?;
    let temporary = PathBuf::from(format!("{}.carrack-upload-{intent_id}", relative.display()));
    if directory.metadata(&temporary).is_ok() {
        directory
            .remove_file(&temporary)
            .map_err(|error| Error::InvalidResponse(format!("reset upload assembly: {error}")))?;
    }
    let mut output = directory
        .open_with(&temporary, OpenOptions::new().write(true).create_new(true))
        .map_err(|error| Error::InvalidResponse(format!("create local upload: {error}")))?;
    for ordinal in 0..part_count {
        let mut part = directory
            .open(part_root.join(part_name(ordinal)))
            .map_err(|error| Error::InvalidResponse(format!("open upload part: {error}")))?;
        std::io::copy(&mut part, &mut output)
            .map_err(|error| Error::InvalidResponse(format!("assemble local upload: {error}")))?;
    }
    output
        .sync_all()
        .map_err(|error| Error::InvalidResponse(format!("sync local upload: {error}")))?;
    drop(output);
    match directory.hard_link(&temporary, &directory, &relative) {
        Ok(()) => directory.remove_file(&temporary).map_err(|error| {
            Error::InvalidResponse(format!("remove published local temporary: {error}"))
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            directory.remove_file(&temporary).map_err(|cleanup| {
                Error::InvalidResponse(format!("remove replay temporary: {cleanup}"))
            })?;
        }
        Err(error) => {
            return Err(Error::InvalidResponse(format!(
                "publish local object without replacement: {error}"
            )));
        }
    }
    let mut file = directory
        .open(&relative)
        .map_err(|error| Error::InvalidResponse(format!("read back local object: {error}")))?;
    let mut hash = Sha256::new();
    let bytes = std::io::copy(&mut file, &mut hash)
        .map_err(|error| Error::InvalidResponse(format!("verify local object: {error}")))?;
    if bytes != encoded_bytes || hex::encode(hash.finalize()) != encoded_sha256 {
        return Err(Error::failure(
            FailureKind::CorruptCiphertext,
            "local provider readback differs; the ambiguous object was retained",
        ));
    }
    for ordinal in 0..part_count {
        directory
            .remove_file(part_root.join(part_name(ordinal)))
            .map_err(|error| Error::InvalidResponse(format!("remove upload part: {error}")))?;
    }
    directory
        .remove_dir(&part_root)
        .map_err(|error| Error::InvalidResponse(format!("remove upload journal: {error}")))?;
    Ok(UploadedObject {
        native_id: format!("sha256:{encoded_sha256}"),
        provider_version: format!("sha256:{encoded_sha256}"),
        etag: encoded_sha256.to_owned(),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the local adapter validates one immutable object and bounded range pipeline"
)]
pub(crate) fn download(
    root: &str,
    storage_key: &str,
    staging_root: &Path,
    version_id: &str,
    encoded_bytes: u64,
    encoded_sha256: &str,
    part_bytes: u64,
    maximum_concurrency: usize,
) -> Result<PathBuf, Error> {
    ensure_private_directory(staging_root, "local download staging root")?;
    let relative = safe_storage_key(storage_key)?;
    let directory = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|error| Error::InvalidResponse(format!("open local driver root: {error}")))?;
    let path = staging_root.join(format!("{version_id}.download"));
    if path
        .metadata()
        .is_ok_and(|metadata| metadata.len() == encoded_bytes)
        && hash_file(&path)? == encoded_sha256
    {
        return Ok(path);
    }
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|error| Error::InvalidResponse(format!("reset download assembly: {error}")))?;
    }
    verify_provider_metadata(&directory, &relative, encoded_bytes)?;
    if encoded_bytes == 0 {
        verify_empty_provider_object(&directory, &relative)?;
    }
    let part_root = staging_root.join("parts").join(version_id);
    ensure_private_directory(&part_root, "local download part journal")?;
    download_parts(
        &directory,
        &relative,
        &part_root,
        encoded_bytes,
        part_bytes,
        maximum_concurrency,
    )?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| Error::InvalidResponse(format!("create download staging: {error}")))?;
    let part_count = encoded_bytes.div_ceil(part_bytes);
    for ordinal in 0..part_count {
        let mut part = std::fs::File::open(part_root.join(part_name(ordinal)))
            .map_err(|error| Error::InvalidResponse(format!("open download part: {error}")))?;
        std::io::copy(&mut part, &mut output).map_err(|error| {
            Error::InvalidResponse(format!("assemble download staging: {error}"))
        })?;
    }
    output
        .sync_all()
        .map_err(|error| Error::InvalidResponse(format!("sync download staging: {error}")))?;
    if path.metadata().map_or(0, |metadata| metadata.len()) != encoded_bytes
        || hash_file(&path)? != encoded_sha256
    {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&part_root);
        return Err(Error::failure(
            FailureKind::CorruptCiphertext,
            "provider object checksum differs",
        ));
    }
    verify_provider_metadata(&directory, &relative, encoded_bytes)?;
    std::fs::remove_dir_all(&part_root)
        .map_err(|error| Error::InvalidResponse(format!("remove download journal: {error}")))?;
    let _ = std::fs::remove_dir(staging_root.join("parts"));
    Ok(path)
}

fn verify_provider_metadata(
    directory: &Dir,
    source: &Path,
    expected_bytes: u64,
) -> Result<(), Error> {
    let metadata = directory
        .symlink_metadata(source)
        .map_err(|error| local_provider_error("stat provider object", &error))?;
    if !metadata.file_type().is_file() || metadata.len() != expected_bytes {
        return Err(Error::failure(
            FailureKind::CorruptCiphertext,
            "local provider object type or length differs",
        ));
    }
    Ok(())
}

fn verify_empty_provider_object(directory: &Dir, source: &Path) -> Result<(), Error> {
    let mut input = directory
        .open(source)
        .map_err(|error| local_provider_error("open empty provider object", &error))?;
    let mut byte = [0_u8; 1];
    let observed = input
        .read(&mut byte)
        .map_err(|error| local_provider_error("read empty provider object", &error))?;
    if observed != 0 {
        return Err(Error::failure(
            FailureKind::CorruptCiphertext,
            "local zero-byte provider object returned data",
        ));
    }
    Ok(())
}

fn upload_parts(
    directory: &Dir,
    source: &Path,
    part_root: &Path,
    total_bytes: u64,
    part_bytes: u64,
    part_count: u64,
    maximum_concurrency: usize,
) -> Result<(), Error> {
    parallel_parts(part_count, maximum_concurrency, |ordinal| {
        let offset = ordinal * part_bytes;
        let length = part_bytes.min(total_bytes - offset);
        let part_path = part_root.join(part_name(ordinal));
        if directory
            .metadata(&part_path)
            .is_ok_and(|metadata| metadata.len() == length)
        {
            return Ok(());
        }
        if directory.metadata(&part_path).is_ok() {
            directory
                .remove_file(&part_path)
                .map_err(|error| Error::InvalidResponse(format!("reset upload part: {error}")))?;
        }
        let mut input = std::fs::File::open(source)
            .map_err(|error| Error::InvalidResponse(format!("open encoded staging: {error}")))?;
        input
            .seek(std::io::SeekFrom::Start(offset))
            .map_err(|error| Error::InvalidResponse(format!("seek encoded staging: {error}")))?;
        let mut output = directory
            .open_with(&part_path, OpenOptions::new().write(true).create_new(true))
            .map_err(|error| Error::InvalidResponse(format!("create upload part: {error}")))?;
        copy_exact_bytes(&mut input, &mut output, length, "transfer")?;
        output
            .sync_all()
            .map_err(|error| Error::InvalidResponse(format!("sync upload part: {error}")))
    })
}

fn download_parts(
    directory: &Dir,
    source: &Path,
    part_root: &Path,
    total_bytes: u64,
    part_bytes: u64,
    maximum_concurrency: usize,
) -> Result<(), Error> {
    let part_count = total_bytes.div_ceil(part_bytes);
    parallel_parts(part_count, maximum_concurrency, |ordinal| {
        let offset = ordinal * part_bytes;
        let length = part_bytes.min(total_bytes - offset);
        let part_path = part_root.join(part_name(ordinal));
        if part_path
            .metadata()
            .is_ok_and(|metadata| metadata.len() == length)
        {
            return Ok(());
        }
        if part_path.exists() {
            std::fs::remove_file(&part_path)
                .map_err(|error| Error::InvalidResponse(format!("reset download part: {error}")))?;
        }
        let mut input = directory
            .open(source)
            .map_err(|error| local_provider_error("open provider object", &error))?;
        input
            .seek(std::io::SeekFrom::Start(offset))
            .map_err(|error| Error::InvalidResponse(format!("seek provider object: {error}")))?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part_path)
            .map_err(|error| Error::InvalidResponse(format!("create download part: {error}")))?;
        copy_exact_bytes(&mut input, &mut output, length, "download")?;
        output
            .sync_all()
            .map_err(|error| Error::InvalidResponse(format!("sync download part: {error}")))
    })
}

fn parallel_parts(
    part_count: u64,
    maximum_concurrency: usize,
    operation: impl Fn(u64) -> Result<(), Error> + Sync,
) -> Result<(), Error> {
    let next = AtomicU64::new(0);
    let worker_count =
        maximum_concurrency.min(usize::try_from(part_count.max(1)).unwrap_or(usize::MAX));
    std::thread::scope(|scope| {
        let workers = (0..worker_count)
            .map(|_| {
                let next = &next;
                let operation = &operation;
                scope.spawn(move || {
                    loop {
                        let ordinal = next.fetch_add(1, Ordering::Relaxed);
                        if ordinal >= part_count {
                            return Ok::<(), Error>(());
                        }
                        operation(ordinal)?;
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker
                .join()
                .map_err(|_| Error::InvalidResponse("local driver worker panicked".to_owned()))??;
        }
        Ok(())
    })
}

fn copy_exact_bytes(
    input: &mut impl Read,
    output: &mut impl Write,
    bytes: u64,
    context: &str,
) -> Result<(), Error> {
    let mut remaining = bytes;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        input
            .read_exact(&mut buffer[..wanted])
            .map_err(|error| Error::InvalidResponse(format!("read {context} part: {error}")))?;
        output
            .write_all(&buffer[..wanted])
            .map_err(|error| Error::InvalidResponse(format!("write {context} part: {error}")))?;
        remaining -= wanted as u64;
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, Error> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| Error::InvalidResponse(format!("open download assembly: {error}")))?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)
        .map_err(|error| Error::InvalidResponse(format!("hash download assembly: {error}")))?;
    Ok(hex::encode(hash.finalize()))
}

fn local_provider_error(operation: &str, error: &std::io::Error) -> Error {
    let kind = if error.kind() == std::io::ErrorKind::NotFound {
        FailureKind::PermanentLoss
    } else {
        FailureKind::ProviderUnavailable
    };
    Error::failure(kind, format!("{operation}: {error}"))
}

fn part_name(ordinal: u64) -> String {
    format!("{ordinal:016x}.part")
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};
    use std::path::Path;

    use crate::{FailureKind, driver::safe_storage_key};

    use super::{download, upload};

    #[test]
    fn storage_key_is_strictly_relative_and_normal() {
        assert!(safe_storage_key("objects/ab/cd").is_ok());
        for invalid in ["", "/absolute", "../escape", "a/../b", "a\\b"] {
            assert!(safe_storage_key(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn zero_byte_download_still_reads_the_provider_object() {
        let temporary = tempfile::tempdir().expect("temporary driver root");
        let root = temporary.path().join("provider");
        let object = root.join("objects/ab/object");
        std::fs::create_dir_all(object.parent().expect("object parent"))
            .expect("create provider root");
        std::fs::write(&object, b"unexpected").expect("write non-empty provider object");
        let empty_sha256 = hex::encode(Sha256::digest([]));

        let error = download(
            root.to_str().expect("UTF-8 provider root"),
            "objects/ab/object",
            &temporary.path().join("downloads"),
            "version-empty",
            0,
            &empty_sha256,
            4_096,
            1,
        )
        .expect_err("non-empty provider body must not satisfy zero-byte identity");
        assert_eq!(error.failure_kind(), Some(FailureKind::CorruptCiphertext));

        std::fs::remove_file(&object).expect("remove provider object");
        let missing = download(
            root.to_str().expect("UTF-8 provider root"),
            "objects/ab/object",
            &temporary.path().join("missing-download"),
            "version-missing",
            0,
            &empty_sha256,
            4_096,
            1,
        )
        .expect_err("missing provider object must not satisfy zero-byte identity");
        assert_eq!(missing.failure_kind(), Some(FailureKind::PermanentLoss));
    }

    #[test]
    fn download_rejects_a_provider_object_with_an_extra_suffix() {
        let temporary = tempfile::tempdir().expect("temporary driver root");
        let root = temporary.path().join("provider");
        let object = root.join("objects/ab/object");
        std::fs::create_dir_all(object.parent().expect("object parent"))
            .expect("create provider root");
        std::fs::write(&object, b"expected-extra").expect("write provider object");

        let error = download(
            root.to_str().expect("UTF-8 provider root"),
            "objects/ab/object",
            &temporary.path().join("downloads"),
            "version-prefix",
            8,
            &hex::encode(Sha256::digest(b"expected")),
            4,
            2,
        )
        .expect_err("a correct prefix must not hide extra provider bytes");
        assert_eq!(error.failure_kind(), Some(FailureKind::CorruptCiphertext));
    }

    #[test]
    fn parallel_complete_object_round_trip_and_corruption_fail_closed() {
        let temporary = tempfile::tempdir().expect("temporary driver root");
        let root = temporary.path().join("provider");
        let staging = temporary.path().join("staging");
        let downloads = temporary.path().join("downloads");
        std::fs::create_dir(&root).expect("create provider root");
        std::fs::create_dir(&staging).expect("create staging root");
        let plaintext = (0_u32..32_769)
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let source = staging.join("encoded");
        std::fs::write(&source, &plaintext).expect("write staged object");
        let sha256 = hex::encode(Sha256::digest(&plaintext));
        let root = root.to_str().expect("UTF-8 provider root");

        let uploaded = upload(
            root,
            "intent",
            "objects/ab/object",
            &source,
            plaintext.len() as u64,
            &sha256,
            8_191,
            4,
        )
        .expect("upload complete object");
        assert_eq!(uploaded.provider_version, format!("sha256:{sha256}"));
        let downloaded = download(
            root,
            "objects/ab/object",
            &downloads,
            "version-a",
            plaintext.len() as u64,
            &sha256,
            4_093,
            4,
        )
        .expect("download complete object");
        assert_eq!(std::fs::read(downloaded).expect("read download"), plaintext);

        std::fs::write(
            Path::new(root).join("objects/ab/object"),
            vec![0_u8; plaintext.len()],
        )
        .expect("corrupt provider object");
        let error = download(
            root,
            "objects/ab/object",
            &temporary.path().join("corrupt-download"),
            "version-b",
            plaintext.len() as u64,
            &sha256,
            4_093,
            4,
        )
        .expect_err("corrupt provider object must fail");
        assert_eq!(error.failure_kind(), Some(FailureKind::CorruptCiphertext));
    }

    #[test]
    fn upload_never_deletes_an_ambiguous_existing_provider_object() {
        let temporary = tempfile::tempdir().expect("temporary driver root");
        let root = temporary.path().join("provider");
        let staging = temporary.path().join("staging");
        std::fs::create_dir(&root).expect("create provider root");
        std::fs::create_dir(&staging).expect("create staging root");
        let source = staging.join("encoded");
        std::fs::write(&source, b"expected bytes").expect("write staging");
        let destination = root.join("objects/ab/object");
        std::fs::create_dir_all(destination.parent().expect("object parent"))
            .expect("create object parent");
        std::fs::write(&destination, b"preexisting provider bytes")
            .expect("write preexisting object");
        let expected_sha256 = hex::encode(Sha256::digest(b"expected bytes"));

        let result = upload(
            root.to_str().expect("UTF-8 root"),
            "other-intent",
            "objects/ab/object",
            &source,
            14,
            &expected_sha256,
            8,
            2,
        );
        let Err(error) = result else {
            panic!("ambiguous provider object must fail closed");
        };

        assert_eq!(error.failure_kind(), Some(FailureKind::CorruptCiphertext));
        assert_eq!(
            std::fs::read(&destination).expect("read retained provider object"),
            b"preexisting provider bytes"
        );
    }
}
