use std::{collections::BTreeSet, fmt};

use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use sigstore_types::{Bundle, MediaType, SignatureContent, bundle::VerificationMaterialContent};

use crate::ReleaseAttestationError;

pub(super) fn validate(bundle: &Bundle) -> Result<(), ReleaseAttestationError> {
    let exact_dsse_signature = match &bundle.content {
        SignatureContent::DsseEnvelope(envelope) => {
            envelope.signatures.len() == 1 && envelope.signatures[0].keyid.is_empty()
        }
        SignatureContent::MessageSignature(_) => false,
    };
    if bundle.version().ok() != Some(MediaType::Bundle0_3)
        || !matches!(
            bundle.verification_material.content,
            VerificationMaterialContent::Certificate(_)
        )
        || bundle.verification_material.tlog_entries.len() != 1
        || !exact_dsse_signature
    {
        return Err(ReleaseAttestationError::UnsupportedBundle);
    }
    Ok(())
}

pub(super) fn validate_json(value: &serde_json::Value) -> Result<(), ReleaseAttestationError> {
    let root = value
        .as_object()
        .filter(|object| {
            exact_keys(
                object,
                &["mediaType", "verificationMaterial", "dsseEnvelope"],
                &[],
            )
        })
        .ok_or(ReleaseAttestationError::InvalidBundle)?;
    root.get("verificationMaterial")
        .and_then(serde_json::Value::as_object)
        .filter(|object| {
            exact_keys(
                object,
                &["certificate", "tlogEntries", "timestampVerificationData"],
                &[],
            )
        })
        .ok_or(ReleaseAttestationError::InvalidBundle)?;
    let envelope = root
        .get("dsseEnvelope")
        .and_then(serde_json::Value::as_object)
        .filter(|object| exact_keys(object, &["payloadType", "payload", "signatures"], &[]))
        .ok_or(ReleaseAttestationError::InvalidBundle)?;
    let [signature] = envelope
        .get("signatures")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .ok_or(ReleaseAttestationError::InvalidBundle)?
    else {
        return Err(ReleaseAttestationError::UnsupportedBundle);
    };
    signature
        .as_object()
        .filter(|object| exact_keys(object, &["sig"], &["keyid"]))
        .ok_or(ReleaseAttestationError::InvalidBundle)?;
    Ok(())
}

fn exact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    required: &[&str],
    optional: &[&str],
) -> bool {
    object.len() >= required.len()
        && object.len() <= required.len() + optional.len()
        && required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

pub(super) fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<(), ReleaseAttestationError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    NoDuplicateKeys::deserialize(&mut deserializer)
        .and_then(|_| deserializer.end())
        .map_err(|_| ReleaseAttestationError::InvalidBundle)
}

struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateKeys::deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}
