use std::collections::{HashMap, HashSet};

use serde::Deserialize;

const MAXIMUM_RECOVERY_BYTES: usize = 16 << 20;
const FRAME_TAG_BYTES: u64 = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryManifest {
    pub(crate) schema_version: String,
    pub(crate) manifest_sha256: String,
    pub(crate) manifest: ContentManifest,
    pub(crate) locations: Vec<Location>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContentManifest {
    pub(crate) schema_version: String,
    pub(crate) namespace_id: String,
    pub(crate) object_id: String,
    pub(crate) generation: u64,
    pub(crate) plaintext_size: u64,
    pub(crate) plaintext_sha256: String,
    pub(crate) layout: Layout,
    pub(crate) crypto: Crypto,
    pub(crate) packs: Vec<Pack>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Layout {
    #[serde(rename = "physical_block_bytes")]
    pub(crate) physical_block: u64,
    #[serde(rename = "crypto_frame_bytes")]
    pub(crate) crypto_frame: u64,
    #[serde(rename = "logical_pack_bytes")]
    pub(crate) logical_pack: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Crypto {
    pub(crate) suite: String,
    pub(crate) root_version: u32,
    pub(crate) key_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pack {
    pub(crate) ordinal: u64,
    #[serde(rename = "pack_id")]
    pub(crate) id: String,
    pub(crate) plaintext_offset: u64,
    pub(crate) plaintext_size: u64,
    pub(crate) ciphertext_size: u64,
    pub(crate) ciphertext_sha256: String,
    pub(crate) extents: Vec<Extent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Extent {
    pub(crate) ordinal: u64,
    pub(crate) first_frame: u64,
    pub(crate) frame_count: u64,
    pub(crate) ciphertext_offset: u64,
    pub(crate) ciphertext_size: u64,
    pub(crate) ciphertext_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Location {
    pub(crate) extent_sha256: String,
    pub(crate) driver_id: String,
    pub(crate) storage_key: String,
    pub(crate) provider_version: Option<String>,
    pub(crate) offset: u64,
    pub(crate) length: u64,
}

pub(crate) struct ValidatedRecovery {
    pub(crate) manifest_sha256: String,
    pub(crate) namespace_id: String,
    pub(crate) object_id: String,
    pub(crate) generation: u64,
    pub(crate) recovery: RecoveryManifest,
}

pub(crate) fn validate(encoded: &[u8]) -> Result<ValidatedRecovery, String> {
    if encoded.is_empty() || encoded.len() > MAXIMUM_RECOVERY_BYTES {
        return Err("recovery manifest size is out of range".to_owned());
    }

    let recovery = serde_json::from_slice::<RecoveryManifest>(encoded)
        .map_err(|error| format!("decode recovery manifest: {error}"))?;
    validate_recovery(&recovery)?;

    Ok(ValidatedRecovery {
        manifest_sha256: recovery.manifest_sha256.clone(),
        namespace_id: recovery.manifest.namespace_id.clone(),
        object_id: recovery.manifest.object_id.clone(),
        generation: recovery.manifest.generation,
        recovery,
    })
}

fn validate_recovery(recovery: &RecoveryManifest) -> Result<(), String> {
    if recovery.schema_version != "carrack.recovery.v1" || !valid_sha256(&recovery.manifest_sha256)
    {
        return Err("invalid recovery schema or identity".to_owned());
    }

    validate_content(&recovery.manifest)?;

    let mut extent_sizes = HashMap::new();
    for pack in &recovery.manifest.packs {
        for extent in &pack.extents {
            if let Some(previous) =
                extent_sizes.insert(&extent.ciphertext_sha256, extent.ciphertext_size)
                && previous != extent.ciphertext_size
            {
                return Err("equal extent hashes have different sizes".to_owned());
            }
        }
    }

    let mut covered = HashSet::new();
    let mut unique_locations = HashSet::new();
    for location in &recovery.locations {
        let Some(expected_size) = extent_sizes.get(&location.extent_sha256) else {
            return Err("location references an unknown extent".to_owned());
        };

        if location.length != *expected_size
            || location.offset.checked_add(location.length).is_none()
            || !valid_string(&location.driver_id, 256)
            || !valid_string(&location.storage_key, 4_096)
            || location
                .provider_version
                .as_ref()
                .is_some_and(|value| value.len() > 1_024)
        {
            return Err("invalid recovery location".to_owned());
        }

        let identity = (
            &location.extent_sha256,
            &location.driver_id,
            &location.storage_key,
            location.offset,
            location.length,
        );
        if !unique_locations.insert(identity) {
            return Err("duplicate recovery location".to_owned());
        }

        covered.insert(&location.extent_sha256);
    }

    if extent_sizes.keys().any(|digest| !covered.contains(digest)) {
        return Err("an extent has no recovery location".to_owned());
    }

    Ok(())
}

fn validate_content(content: &ContentManifest) -> Result<(), String> {
    if content.schema_version != "carrack.manifest.v1"
        || !valid_identifier(&content.namespace_id)
        || !valid_string(&content.object_id, 2_048)
        || content.generation == 0
        || !valid_sha256(&content.plaintext_sha256)
    {
        return Err("invalid content manifest identity".to_owned());
    }

    validate_layout(&content.layout)?;
    if content.crypto.suite != "carrack-aes128gcm-hkdfsha256-v1"
        || content.crypto.root_version == 0
        || content.crypto.key_epoch == 0
    {
        return Err("invalid content crypto descriptor".to_owned());
    }

    let mut plaintext_offset = 0_u64;
    let mut pack_ids = HashSet::new();
    for (index, pack) in content.packs.iter().enumerate() {
        let ordinal = u64::try_from(index).map_err(|error| error.to_string())?;
        if pack.ordinal != ordinal
            || pack.plaintext_offset != plaintext_offset
            || pack.plaintext_size == 0
            || pack.plaintext_size > content.layout.logical_pack
            || !valid_identifier(&pack.id)
            || !valid_sha256(&pack.ciphertext_sha256)
            || !pack_ids.insert(&pack.id)
        {
            return Err("invalid content pack".to_owned());
        }

        validate_extents(pack, &content.layout)?;
        plaintext_offset = plaintext_offset
            .checked_add(pack.plaintext_size)
            .ok_or_else(|| "plaintext coverage overflow".to_owned())?;
    }

    if plaintext_offset != content.plaintext_size
        || (content.plaintext_size == 0 && !content.packs.is_empty())
    {
        return Err("content packs do not cover plaintext".to_owned());
    }

    Ok(())
}

fn validate_layout(layout: &Layout) -> Result<(), String> {
    if layout.physical_block == 0
        || layout.crypto_frame == 0
        || layout.logical_pack == 0
        || !layout.physical_block.is_multiple_of(layout.crypto_frame)
        || !layout.logical_pack.is_multiple_of(layout.physical_block)
    {
        return Err("invalid archive layout".to_owned());
    }

    Ok(())
}

fn validate_extents(pack: &Pack, layout: &Layout) -> Result<(), String> {
    let frame_count = 1 + (pack.plaintext_size - 1) / layout.crypto_frame;
    let expected_ciphertext = pack
        .plaintext_size
        .checked_add(
            frame_count
                .checked_mul(FRAME_TAG_BYTES)
                .ok_or_else(|| "ciphertext size overflow".to_owned())?,
        )
        .ok_or_else(|| "ciphertext size overflow".to_owned())?;
    if pack.ciphertext_size != expected_ciphertext || pack.extents.is_empty() {
        return Err("invalid pack ciphertext size".to_owned());
    }

    let mut first_frame = 0_u64;
    let mut ciphertext_offset = 0_u64;
    for (index, extent) in pack.extents.iter().enumerate() {
        let ordinal = u64::try_from(index).map_err(|error| error.to_string())?;
        if extent.ordinal != ordinal
            || extent.first_frame != first_frame
            || extent.frame_count == 0
            || !valid_sha256(&extent.ciphertext_sha256)
        {
            return Err("invalid ciphertext extent".to_owned());
        }

        let (expected_offset, expected_size) = ciphertext_span(
            pack.plaintext_size,
            layout.crypto_frame,
            extent.first_frame,
            extent.frame_count,
        )?;
        if extent.ciphertext_offset != ciphertext_offset
            || extent.ciphertext_offset != expected_offset
            || extent.ciphertext_size != expected_size
        {
            return Err("ciphertext extent coverage mismatch".to_owned());
        }

        first_frame = first_frame
            .checked_add(extent.frame_count)
            .ok_or_else(|| "frame coverage overflow".to_owned())?;
        ciphertext_offset = ciphertext_offset
            .checked_add(extent.ciphertext_size)
            .ok_or_else(|| "ciphertext coverage overflow".to_owned())?;
    }

    if first_frame != frame_count || ciphertext_offset != pack.ciphertext_size {
        return Err("extents do not cover pack ciphertext".to_owned());
    }

    Ok(())
}

fn ciphertext_span(
    plaintext_bytes: u64,
    frame_bytes: u64,
    first_frame: u64,
    selected_frames: u64,
) -> Result<(u64, u64), String> {
    let total_frames = 1 + (plaintext_bytes - 1) / frame_bytes;
    if selected_frames == 0
        || first_frame >= total_frames
        || selected_frames > total_frames - first_frame
    {
        return Err("frame span is out of range".to_owned());
    }

    let full_frame = frame_bytes
        .checked_add(FRAME_TAG_BYTES)
        .ok_or_else(|| "frame size overflow".to_owned())?;
    let offset = first_frame
        .checked_mul(full_frame)
        .ok_or_else(|| "frame offset overflow".to_owned())?;
    let mut length = selected_frames
        .checked_mul(full_frame)
        .ok_or_else(|| "frame length overflow".to_owned())?;

    if first_frame + selected_frames == total_frames {
        let final_plaintext = plaintext_bytes - (total_frames - 1) * frame_bytes;
        length -= frame_bytes - final_plaintext;
    }

    Ok((offset, length))
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32 && canonical_hex(value)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && canonical_hex(value)
}

fn canonical_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

#[cfg(test)]
mod tests {
    use super::validate;

    const VALID: &str = r#"{"schema_version":"carrack.recovery.v1","manifest_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","manifest":{"schema_version":"carrack.manifest.v1","namespace_id":"202122232425262728292a2b2c2d2e2f","object_id":"object-1","generation":1,"plaintext_size":2,"plaintext_sha256":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","layout":{"physical_block_bytes":2,"crypto_frame_bytes":2,"logical_pack_bytes":2},"crypto":{"suite":"carrack-aes128gcm-hkdfsha256-v1","root_version":1,"key_epoch":7},"packs":[{"ordinal":0,"pack_id":"404142434445464748494a4b4c4d4e4f","plaintext_offset":0,"plaintext_size":2,"ciphertext_size":18,"ciphertext_sha256":"1111111111111111111111111111111111111111111111111111111111111111","extents":[{"ordinal":0,"first_frame":0,"frame_count":1,"ciphertext_offset":0,"ciphertext_size":18,"ciphertext_sha256":"2222222222222222222222222222222222222222222222222222222222222222"}]}]},"locations":[{"extent_sha256":"2222222222222222222222222222222222222222222222222222222222222222","driver_id":"memory","storage_key":"extent","provider_version":"v1","offset":0,"length":18}]}"#;

    #[test]
    fn validates_portable_recovery_coverage() {
        let validated = validate(VALID.as_bytes()).expect("validate recovery manifest");

        assert_eq!(validated.object_id, "object-1");
        assert_eq!(validated.generation, 1);
    }

    #[test]
    fn rejects_unknown_fields_and_missing_locations() {
        let unknown = VALID.replacen(
            "\"manifest_sha256\"",
            "\"unknown\":true,\"manifest_sha256\"",
            1,
        );
        assert!(validate(unknown.as_bytes()).is_err());

        let missing = VALID.replace(
            "\"locations\":[{\"extent_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"driver_id\":\"memory\",\"storage_key\":\"extent\",\"provider_version\":\"v1\",\"offset\":0,\"length\":18}]",
            "\"locations\":[]",
        );
        assert!(validate(missing.as_bytes()).is_err());
    }
}
