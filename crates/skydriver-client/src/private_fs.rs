//! Owner-private local directory validation for SDK staging and state roots.

use std::path::{Component, Path, PathBuf};

use crate::Error;

/// Creates a private directory without accepting relative paths or symlinked
/// path components. Existing public ancestors such as `/tmp` are permitted,
/// but the final directory must belong to this process owner and is normalized
/// to mode 0700 on Unix.
pub(crate) fn ensure_private_directory(path: &Path, context: &str) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::InvalidResponse(format!(
            "{context} must be an absolute path"
        )));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                match std::fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                            return Err(Error::InvalidResponse(format!(
                                "{context} contains a symlink or non-directory component"
                            )));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        std::fs::create_dir(&current).map_err(|error| {
                            Error::InvalidResponse(format!("create {context}: {error}"))
                        })?;
                        protect_directory(&current, context)?;
                    }
                    Err(error) => {
                        return Err(Error::InvalidResponse(format!(
                            "inspect {context}: {error}"
                        )));
                    }
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(Error::InvalidResponse(format!(
                    "{context} must be lexically normalized"
                )));
            }
        }
    }
    protect_directory(path, context)
}

fn protect_directory(path: &Path, context: &str) -> Result<(), Error> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| Error::InvalidResponse(format!("inspect {context}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(Error::InvalidResponse(format!(
            "{context} is not a real directory"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != effective_uid {
            return Err(Error::InvalidResponse(format!(
                "{context} is not owned by the current user"
            )));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| Error::InvalidResponse(format!("protect {context}: {error}")))?;
        let protected = std::fs::symlink_metadata(path)
            .map_err(|error| Error::InvalidResponse(format!("reinspect {context}: {error}")))?;
        if protected.file_type().is_symlink()
            || !protected.file_type().is_dir()
            || protected.uid() != effective_uid
            || protected.permissions().mode() & 0o077 != 0
        {
            return Err(Error::InvalidResponse(format!(
                "{context} did not remain owner-private"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_private_directory;
    use std::path::Path;

    #[test]
    fn requires_absolute_owner_private_real_directories() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let private = temporary.path().join("state/nested");
        ensure_private_directory(&private, "test state").expect("private directory");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};

            assert_eq!(
                std::fs::metadata(&private)
                    .expect("private metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            let real = temporary.path().join("real");
            std::fs::create_dir(&real).expect("real directory");
            let linked = temporary.path().join("linked");
            symlink(&real, &linked).expect("symlink ancestor");
            ensure_private_directory(&linked.join("escaped"), "test state")
                .expect_err("symlink ancestor must fail closed");
        }

        ensure_private_directory(Path::new("relative/state"), "test state")
            .expect_err("relative state must fail closed");
    }
}
