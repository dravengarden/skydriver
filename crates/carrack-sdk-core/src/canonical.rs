//! Canonical wire-value parsing independent of integrity and cryptography.

use crate::error::Error;

/// Complete stable VFS authorization-action vocabulary.
pub const VFS_ACTIONS: [&str; 12] = [
    "directory.list",
    "content.read",
    "content.write",
    "entry.delete",
    "snapshot.publish",
    "acl.manage",
    "token.issue",
    "driver.use",
    "driver.manage",
    "gc.run",
    "audit.read",
    "system.manage",
];

/// Sorts, deduplicates, and validates one nonempty VFS action set.
///
/// # Errors
///
/// Rejects empty sets and actions outside the stable protocol vocabulary.
pub fn canonicalize_vfs_actions(mut actions: Vec<String>) -> Result<Vec<String>, Error> {
    actions.sort();
    actions.dedup();
    if actions.is_empty()
        || actions.len() > VFS_ACTIONS.len()
        || !actions
            .iter()
            .all(|action| VFS_ACTIONS.contains(&action.as_str()))
    {
        return Err(Error::InvalidInput("VFS actions are invalid"));
    }
    Ok(actions)
}

/// Decodes one exact lowercase hexadecimal protocol identity.
///
/// # Errors
///
/// Rejects the wrong width, uppercase or non-hexadecimal input.
pub fn decode_lower_hex<const N: usize>(encoded: &str) -> Result<[u8; N], Error> {
    if encoded.len() != N * 2 {
        return Err(Error::InvalidInput("hexadecimal identity width differs"));
    }
    let decoded =
        hex::decode(encoded).map_err(|_| Error::InvalidInput("hexadecimal identity is invalid"))?;
    if hex::encode(&decoded) != encoded {
        return Err(Error::InvalidInput(
            "hexadecimal identity is not canonical lowercase",
        ));
    }
    decoded
        .try_into()
        .map_err(|_| Error::InvalidInput("hexadecimal identity width differs"))
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_vfs_actions, decode_lower_hex};

    #[test]
    fn rejects_uppercase_invalid_and_wrong_width() {
        assert_eq!(
            decode_lower_hex::<2>("00ff").expect("canonical hex"),
            [0, 255]
        );
        assert!(decode_lower_hex::<2>("00FF").is_err());
        assert!(decode_lower_hex::<2>("00fg").is_err());
        assert!(decode_lower_hex::<2>("00").is_err());
    }

    #[test]
    fn canonicalizes_only_known_nonempty_vfs_actions() {
        assert_eq!(
            canonicalize_vfs_actions(vec![
                "token.issue".to_owned(),
                "directory.list".to_owned(),
                "token.issue".to_owned(),
            ])
            .expect("canonical actions"),
            vec!["directory.list", "token.issue"]
        );
        assert!(canonicalize_vfs_actions(Vec::new()).is_err());
        assert!(canonicalize_vfs_actions(vec!["unknown".to_owned()]).is_err());
    }
}
