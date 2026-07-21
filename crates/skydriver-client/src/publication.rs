//! File-descriptor-bound verification and local publication.

use std::{
    ffi::OsStr,
    fs::File,
    io::{Seek as _, SeekFrom},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use rustix::fs::{AtFlags, CWD, linkat, renameat, unlinkat};
#[cfg(unix)]
use std::os::fd::AsRawFd as _;

use crate::{Error, integrity};

pub(crate) struct VerifiedPublication {
    file: File,
    source: Option<PathBuf>,
}

impl VerifiedPublication {
    pub(crate) fn open(
        source: &Path,
        verification_block_bytes: u64,
        plaintext_bytes: u64,
        file_root: &str,
    ) -> Result<Self, Error> {
        let file = match open_verified_file(
            source,
            verification_block_bytes,
            plaintext_bytes,
            file_root,
        ) {
            Ok(file) => file,
            Err(error) => {
                let _ = std::fs::remove_file(source);
                return Err(error);
            }
        };
        Ok(Self {
            file,
            source: Some(source.to_owned()),
        })
    }

    pub(crate) fn publish_no_replace(mut self, destination: &Path) -> Result<Vec<String>, Error> {
        let parent = destination.parent().ok_or_else(|| {
            Error::InvalidResponse("download destination has no parent".to_owned())
        })?;
        let name = destination.file_name().ok_or_else(|| {
            Error::InvalidResponse("download destination has no filename".to_owned())
        })?;
        let directory = File::open(parent).map_err(local_error("open publication directory"))?;
        link_open_file(&self.file, &directory, name).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::InvalidResponse("download destination already exists".to_owned())
            } else {
                Error::InvalidResponse(format!(
                    "publish downloaded file without replacement: {error}"
                ))
            }
        })?;
        let mut warnings = sync_and_cleanup(&directory, &mut self.source);
        if let Err(error) = directory.sync_all() {
            warnings.push(format!(
                "The verified file was published, but its directory sync failed: {error}"
            ));
        }
        Ok(warnings)
    }

    pub(crate) fn publish_replace(mut self, destination: &Path) -> Result<Vec<String>, Error> {
        let parent = destination
            .parent()
            .ok_or_else(|| Error::InvalidResponse("sync destination has no parent".to_owned()))?;
        let destination_name = destination
            .file_name()
            .ok_or_else(|| Error::InvalidResponse("sync destination has no filename".to_owned()))?;
        let directory =
            File::open(parent).map_err(local_error("open sync publication directory"))?;
        let temporary_name = loop {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce).map_err(|error| {
                Error::InvalidResponse(format!("generate publication identity: {error}"))
            })?;
            let name = format!(".skydriver-publish-{}", hex::encode(nonce));
            match link_open_file(&self.file, &directory, OsStr::new(&name)) {
                Ok(()) => break name,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(Error::InvalidResponse(format!(
                        "stage verified sync publication: {error}"
                    )));
                }
            }
        };
        if let Err(error) =
            rename_in_directory(&directory, OsStr::new(&temporary_name), destination_name)
        {
            let _ = unlink_in_directory(&directory, OsStr::new(&temporary_name));
            return Err(Error::InvalidResponse(format!(
                "publish synchronized file: {error}"
            )));
        }
        directory
            .sync_all()
            .map_err(local_error("sync local file publication directory"))?;
        Ok(sync_and_cleanup(&directory, &mut self.source))
    }
}

pub(crate) fn open_verified_file(
    source: &Path,
    verification_block_bytes: u64,
    plaintext_bytes: u64,
    file_root: &str,
) -> Result<File, Error> {
    let mut file = open_nofollow(source)?;
    if !integrity::matches_open_file(
        &mut file,
        verification_block_bytes,
        plaintext_bytes,
        file_root,
    )? {
        return Err(Error::failure(
            crate::FailureKind::CorruptPlaintext,
            "plaintext Merkle root differs",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(local_error("rewind verified plaintext"))?;
    Ok(file)
}

impl Drop for VerifiedPublication {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            let _ = std::fs::remove_file(source);
        }
    }
}

fn open_nofollow(path: &Path) -> Result<File, Error> {
    #[cfg(unix)]
    {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            Error::InvalidResponse(format!(
                "open plaintext staging without symlink traversal: {error}"
            ))
        })?;
        Ok(descriptor.into())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(Error::InvalidResponse(
            "fd-bound local publication is unavailable on this platform".to_owned(),
        ))
    }
}

#[cfg(unix)]
fn link_open_file(
    source: &File,
    destination_directory: &File,
    name: &OsStr,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    let source_path = format!("/proc/self/fd/{}", source.as_raw_fd());
    #[cfg(not(target_os = "linux"))]
    let source_path = format!("/dev/fd/{}", source.as_raw_fd());
    Ok(linkat(
        CWD,
        source_path.as_str(),
        destination_directory,
        name,
        AtFlags::SYMLINK_FOLLOW,
    )?)
}

#[cfg(not(unix))]
fn link_open_file(
    _source: &File,
    _destination_directory: &File,
    _name: &OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "fd-bound local publication is unavailable on this platform",
    ))
}

#[cfg(unix)]
fn rename_in_directory(directory: &File, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
    Ok(renameat(directory, from, directory, to)?)
}

#[cfg(not(unix))]
fn rename_in_directory(_directory: &File, _from: &OsStr, _to: &OsStr) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "fd-bound local publication is unavailable on this platform",
    ))
}

#[cfg(unix)]
fn unlink_in_directory(directory: &File, name: &OsStr) -> std::io::Result<()> {
    Ok(unlinkat(directory, name, AtFlags::empty())?)
}

#[cfg(not(unix))]
fn unlink_in_directory(_directory: &File, _name: &OsStr) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "fd-bound local publication is unavailable on this platform",
    ))
}

fn sync_and_cleanup(directory: &File, source: &mut Option<PathBuf>) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(path) = source.take()
        && let Err(error) = std::fs::remove_file(&path)
    {
        warnings.push(format!(
            "The verified file was published, but plaintext staging cleanup was deferred: {error}"
        ));
    }
    if let Err(error) = directory.sync_all() {
        warnings.push(format!(
            "The verified file was published, but staging cleanup directory sync failed: {error}"
        ));
    }
    warnings
}

fn local_error(context: &'static str) -> impl FnOnce(std::io::Error) -> Error {
    move |error| Error::InvalidResponse(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::VerifiedPublication;

    #[test]
    fn publication_is_bound_to_the_verified_open_file() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let staging = temporary.path().join("staging");
        let displaced = temporary.path().join("displaced");
        let destination = temporary.path().join("destination");
        std::fs::write(&staging, b"verified").expect("write staging");
        let root = hex::encode(
            skydriver_sdk_core::file_merkle_root(b"verified", 4).expect("plaintext root"),
        );
        let publication = VerifiedPublication::open(&staging, 4, 8, &root).expect("verify staging");
        std::fs::rename(&staging, &displaced).expect("replace staging path");
        std::fs::write(&staging, b"attacker").expect("write replacement path");

        publication
            .publish_no_replace(&destination)
            .expect("publish verified descriptor");
        assert_eq!(
            std::fs::read(destination).expect("read destination"),
            b"verified"
        );
    }

    #[test]
    fn replacement_publication_is_bound_to_the_verified_open_file() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let staging = temporary.path().join("staging");
        let displaced = temporary.path().join("displaced");
        let destination = temporary.path().join("destination");
        std::fs::write(&staging, b"verified").expect("write staging");
        std::fs::write(&destination, b"previous").expect("write previous destination");
        let root = hex::encode(
            skydriver_sdk_core::file_merkle_root(b"verified", 4).expect("plaintext root"),
        );
        let publication = VerifiedPublication::open(&staging, 4, 8, &root).expect("verify staging");
        std::fs::rename(&staging, &displaced).expect("replace staging path");
        std::fs::write(&staging, b"attacker").expect("write replacement path");

        publication
            .publish_replace(&destination)
            .expect("replace with verified descriptor");
        assert_eq!(
            std::fs::read(destination).expect("read destination"),
            b"verified"
        );
    }
}
