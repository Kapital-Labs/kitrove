use std::fmt::{self, Debug, Formatter};

use kitrove_model::{AssetId, ContentHash};
use serde::{Deserialize, Serialize};

use crate::{InstructionError, InstructionLimits, hash_managed_region, inspect_managed_document};

const FORMAT: &str = "kitrove-native-instruction-region/v1";
const SCHEMA_VERSION: u32 = 1;
const MAX_STORED_REGION_BYTES: usize = 768 * 1024;

/// Lossless origin-native storage for one complete Kitrove-managed instruction region.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeInstructionRegion {
    asset_id: AssetId,
    exact_region: Vec<u8>,
    object_hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRegion {
    schema_version: u32,
    format: String,
    asset_id: AssetId,
    exact_region: String,
    object_hash: ContentHash,
}

impl NativeInstructionRegion {
    /// Validates and captures exactly one complete managed region.
    pub fn new(asset_id: AssetId, exact_region: Vec<u8>) -> Result<Self, InstructionError> {
        validate_exact_region(&asset_id, &exact_region)?;
        let object_hash = hash_native_region(&asset_id, &exact_region);
        let object = Self {
            asset_id,
            exact_region,
            object_hash,
        };
        object.to_json()?;
        Ok(object)
    }

    /// Parses and verifies one strict version-1 JSON envelope.
    pub fn from_json(input: &str) -> Result<Self, InstructionError> {
        if input.len() > MAX_STORED_REGION_BYTES {
            return Err(native_error(
                "instruction.native_storage_limit",
                "native instruction region exceeds the storage byte limit",
            ));
        }
        let persisted: PersistedRegion = serde_json::from_str(input).map_err(|_| {
            native_error(
                "instruction.native_storage_invalid",
                "native instruction region is not strict version-1 JSON",
            )
        })?;
        if persisted.schema_version != SCHEMA_VERSION || persisted.format != FORMAT {
            return Err(native_error(
                "instruction.native_storage_version",
                "native instruction region schema or format is unsupported",
            ));
        }
        let stored = Self::new(persisted.asset_id, persisted.exact_region.into_bytes())?;
        if stored.object_hash != persisted.object_hash {
            return Err(native_error(
                "instruction.native_storage_hash_mismatch",
                "native instruction identity does not match its exact region",
            ));
        }
        Ok(stored)
    }

    /// Serializes deterministic strict JSON with one final newline.
    pub fn to_json(&self) -> Result<String, InstructionError> {
        let exact_region = String::from_utf8(self.exact_region.clone()).map_err(|_| {
            native_error(
                "instruction.native_region_invalid",
                "native instruction region must be valid UTF-8",
            )
        })?;
        let persisted = PersistedRegion {
            schema_version: SCHEMA_VERSION,
            format: FORMAT.to_owned(),
            asset_id: self.asset_id.clone(),
            exact_region,
            object_hash: self.object_hash.clone(),
        };
        let mut encoded = serde_json::to_string_pretty(&persisted).map_err(|_| {
            native_error(
                "instruction.native_storage_serialize",
                "native instruction region could not be serialized",
            )
        })?;
        encoded.push('\n');
        if encoded.len() > MAX_STORED_REGION_BYTES {
            return Err(native_error(
                "instruction.native_storage_limit",
                "native instruction region exceeds the storage byte limit",
            ));
        }
        Ok(encoded)
    }

    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub fn exact_region(&self) -> &[u8] {
        &self.exact_region
    }

    #[must_use]
    pub const fn object_hash(&self) -> &ContentHash {
        &self.object_hash
    }

    #[must_use]
    pub const fn format() -> &'static str {
        FORMAT
    }
}

impl Debug for NativeInstructionRegion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeInstructionRegion")
            .field("asset_id", &self.asset_id)
            .field("region_byte_count", &self.exact_region.len())
            .field("object_hash", &self.object_hash)
            .finish()
    }
}

fn validate_exact_region(asset_id: &AssetId, exact_region: &[u8]) -> Result<(), InstructionError> {
    if exact_region.len() > MAX_STORED_REGION_BYTES {
        return Err(native_error(
            "instruction.native_region_limit",
            "native instruction region exceeds the storage byte limit",
        ));
    }
    let parsed = inspect_managed_document(
        exact_region,
        InstructionLimits {
            max_document_bytes: MAX_STORED_REGION_BYTES,
            max_body_bytes: MAX_STORED_REGION_BYTES,
            max_regions: 1,
        },
    )?;
    let mut regions = parsed.regions();
    let Some(region) = regions.next() else {
        return Err(native_error(
            "instruction.native_region_invalid",
            "native instruction object must contain one managed region",
        ));
    };
    if regions.next().is_some()
        || region.asset_id() != asset_id
        || region.range() != &(0..exact_region.len())
    {
        return Err(native_error(
            "instruction.native_region_invalid",
            "native instruction object must exactly match its managed asset region",
        ));
    }
    Ok(())
}

fn hash_native_region(asset_id: &AssetId, exact_region: &[u8]) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-instruction-region-v1\0");
    write_record(&mut hasher, asset_id.as_str());
    write_record(&mut hasher, hash_managed_region(exact_region).as_str());
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

fn write_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

const fn native_error(code: &'static str, message: &'static str) -> InstructionError {
    InstructionError::new(code, message)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn native() -> NativeInstructionRegion {
        NativeInstructionRegion::new(
            AssetId::parse("review").unwrap(),
            b"<!-- kitrove:instruction review begin -->\nReview carefully.  \n<!-- kitrove:instruction review end -->"
                .to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn exact_region_round_trips_without_normalizing_bytes() {
        let original = native();
        let encoded = original.to_json().unwrap();
        let decoded = NativeInstructionRegion::from_json(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert!(
            decoded
                .exact_region()
                .windows(3)
                .any(|bytes| bytes == b".  ")
        );
        assert_eq!(NativeInstructionRegion::format(), FORMAT);
    }

    #[test]
    fn rejects_wrong_identity_shape_and_hash() {
        let encoded = native().to_json().unwrap();
        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        value["asset_id"] = Value::from("other");
        assert_eq!(
            NativeInstructionRegion::from_json(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .code(),
            "instruction.native_region_invalid"
        );

        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        value["object_hash"] = Value::from(format!("blake3:{}", "0".repeat(64)));
        assert_eq!(
            NativeInstructionRegion::from_json(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .code(),
            "instruction.native_storage_hash_mismatch"
        );
    }

    #[test]
    fn debug_omits_authored_region() {
        assert!(!format!("{:?}", native()).contains("Review carefully"));
    }
}
