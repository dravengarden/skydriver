use std::fmt::Write as _;

use worker::{Date, Result};

const IDENTIFIER_BYTES: usize = 16;
const STORAGE_NAME_BYTES: usize = 24;
const MAXIMUM_UUID_V7_TIMESTAMP: u64 = (1_u64 << 48) - 1;

/// Allocates a lowercase, hyphenless `UUIDv7` for a VFS metadata identity.
///
/// The 48-bit millisecond prefix improves D1 index locality. The remaining
/// random bits prevent content, path, user, and provider details from entering
/// the identifier. Provider storage names use a separate 192-bit namespace.
pub(crate) fn new_uuid_v7_hex() -> Result<String> {
    let timestamp_ms = Date::now().as_millis();
    let mut bytes = [0_u8; IDENTIFIER_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|error| worker::Error::RustError(format!("generate VFS identifier: {error}")))?;
    encode_uuid_v7(timestamp_ms, bytes)
}

/// Allocates a fresh opaque provider key with 192 random bits.
///
/// The sharding prefix is derived only from the random name. It never contains
/// a virtual path, filename, file identifier, user, directory, or media type.
pub(crate) fn new_storage_key() -> Result<String> {
    let mut random = [0_u8; STORAGE_NAME_BYTES];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate VFS storage key: {error}")))?;
    let encoded = lowercase_hex(&random)?;

    Ok(format!("objects/v2/{}/{}", &encoded[..2], encoded))
}

fn encode_uuid_v7(timestamp_ms: u64, mut bytes: [u8; IDENTIFIER_BYTES]) -> Result<String> {
    if timestamp_ms > MAXIMUM_UUID_V7_TIMESTAMP {
        return Err(worker::Error::RustError(
            "UUIDv7 timestamp exceeds 48 bits".to_owned(),
        ));
    }

    let timestamp = timestamp_ms.to_be_bytes();
    bytes[..6].copy_from_slice(&timestamp[2..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    lowercase_hex(&bytes)
}

fn lowercase_hex(bytes: &[u8]) -> Result<String> {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}")
            .map_err(|error| worker::Error::RustError(format!("encode VFS identity: {error}")))?;
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v7_is_canonical_and_time_ordered_by_prefix() {
        let encoded = encode_uuid_v7(
            0x0123_4567_89ab,
            [
                0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0xff, 0x88, 0xff, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00,
            ],
        )
        .expect("encode UUIDv7");

        assert_eq!(encoded.len(), 32);
        assert_eq!(&encoded[..12], "0123456789ab");
        assert_eq!(&encoded[12..13], "7");
        assert_eq!(&encoded[16..17], "b");
        assert!(encoded.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn storage_names_are_independent_192_bit_random_values() {
        let first = new_storage_key().expect("first storage key");
        let second = new_storage_key().expect("second storage key");

        assert_eq!(first.len(), 62);
        assert!(first.starts_with("objects/v2/"));
        assert_eq!(&first[11..13], &first[14..16]);
        assert!(
            first[11..13]
                .bytes()
                .chain(first[14..].bytes())
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_ne!(first, second);
    }

    #[test]
    fn rejects_timestamps_outside_uuid_v7() {
        assert!(encode_uuid_v7(MAXIMUM_UUID_V7_TIMESTAMP + 1, [0; IDENTIFIER_BYTES]).is_err());
    }
}
