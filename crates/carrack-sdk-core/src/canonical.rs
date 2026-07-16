//! Canonical wire-value parsing independent of integrity and cryptography.

use crate::error::Error;

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
    use super::decode_lower_hex;

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
}
