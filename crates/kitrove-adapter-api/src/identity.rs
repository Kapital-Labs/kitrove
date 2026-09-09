use std::fmt::{self, Debug, Display, Formatter};

use kitrove_agent_skills::SkillSourceLayout;
use kitrove_model::{ContentHash, HarnessId, HarnessScope};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{AdapterError, RootTier};

fn validate_logical_id(value: &str, code: &'static str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b':' | b'_' | b'-')
        })
    {
        return Err(AdapterError::new(
            code,
            "logical identifiers must contain 1 to 128 bytes using lowercase ASCII letters, digits, '.', ':', '_', or '-'",
        ));
    }
    Ok(())
}

macro_rules! logical_id {
    ($name:ident, $label:literal, $code:literal) => {
        #[doc = concat!("A validated ", $label, ".")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Parses a ", $label, ".")]
            pub fn parse(value: impl Into<String>) -> Result<Self, AdapterError> {
                let value = value.into();
                validate_logical_id(&value, $code)?;
                Ok(Self(value))
            }

            #[doc = concat!("Returns the ", $label, " as a string slice.")]
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

logical_id!(
    EvidenceRef,
    "evidence reference",
    "adapter.evidence_ref_invalid"
);

/// A validated, forward-slash source path relative to an observed root.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SourceRelativePath(String);

impl SourceRelativePath {
    /// Parses a source-relative path without absolute, traversal, or control forms.
    pub fn parse(value: impl Into<String>) -> Result<Self, AdapterError> {
        let value = value.into();
        let has_windows_drive_prefix = value
            .as_bytes()
            .get(0..2)
            .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1] == b':');
        if value.is_empty()
            || value.starts_with('/')
            || value.contains('\\')
            || value.contains(':')
            || has_windows_drive_prefix
            || value.chars().any(char::is_control)
            || value
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(AdapterError::new(
                "adapter.source_relative_path_invalid",
                "source-relative paths must use non-empty forward-slash components without absolute, traversal, drive, backslash, colon, or control forms",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the validated source-relative path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SourceRelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for SourceRelativePath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Complete canonical evidence required to construct a stable observation identity.
#[derive(Clone, Copy)]
pub struct ObservationIdentity<'a> {
    pub harness: &'a HarnessId,
    pub scope: HarnessScope,
    pub root_tier: RootTier,
    pub policy_rank: u32,
    pub logical_root: &'a RootId,
    pub source_relative_path: &'a SourceRelativePath,
    pub layout: SkillSourceLayout,
    pub original_document_name: &'a str,
    pub native_id: Option<&'a str>,
    pub exact_source_hash: Option<&'a ContentHash>,
}

impl Debug for ObservationIdentity<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservationIdentity")
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("root_tier", &self.root_tier)
            .field("policy_rank", &self.policy_rank)
            .field("logical_root", &self.logical_root)
            .field("layout", &self.layout)
            .field("native_id_present", &self.native_id.is_some())
            .field(
                "exact_source_hash_present",
                &self.exact_source_hash.is_some(),
            )
            .finish()
    }
}
logical_id!(RootId, "logical root identifier", "adapter.root_id_invalid");
logical_id!(
    NativeRootKey,
    "native root descriptor key",
    "adapter.native_root_key_invalid"
);

/// Stable identity for one safely located observation.
///
/// Raw digest minting is intentionally unavailable to external consumers:
///
/// ```compile_fail
/// use kitrove_adapter_api::ObservationId;
///
/// let _ = ObservationId::from_digest([0_u8; 32]);
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ObservationId(String);

impl ObservationId {
    /// Hashes the complete canonical observation identity frame.
    #[must_use]
    pub fn from_identity(identity: &ObservationIdentity<'_>) -> Self {
        let mut frame = b"kitrove-observation-id-v1\0".to_vec();
        append_record(&mut frame, identity.harness.as_str());
        frame.push(match identity.scope {
            HarnessScope::User => 0,
            HarnessScope::Project => 1,
        });
        frame.push(match identity.root_tier {
            RootTier::User => 0,
            RootTier::Project => 1,
            RootTier::Admin => 2,
            RootTier::System => 3,
            RootTier::Compatibility => 4,
            RootTier::Explicit => 5,
        });
        frame.extend_from_slice(&identity.policy_rank.to_be_bytes());
        append_record(&mut frame, identity.logical_root.as_str());
        append_record(&mut frame, identity.source_relative_path.as_str());
        frame.push(match identity.layout {
            SkillSourceLayout::Directory => 0,
            SkillSourceLayout::Standalone => 1,
        });
        append_record(&mut frame, identity.original_document_name);
        append_optional_record(&mut frame, identity.native_id);
        append_optional_record(
            &mut frame,
            identity.exact_source_hash.map(ContentHash::as_str),
        );

        let digest = ContentHash::digest(&frame);
        let digest = digest
            .as_str()
            .strip_prefix("blake3:")
            .expect("ContentHash::digest always returns a BLAKE3 identity");
        Self(format!("observation-{digest}"))
    }

    /// Returns the stable observation identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn append_record(frame: &mut Vec<u8>, value: &str) {
    frame.extend_from_slice(&(value.len() as u64).to_be_bytes());
    frame.extend_from_slice(value.as_bytes());
}

fn append_optional_record(frame: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            frame.push(1);
            append_record(frame, value);
        }
        None => frame.push(0),
    }
}

impl Display for ObservationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_identity_debug_omits_native_identity() {
        const SECRET_NATIVE_ID: &str = "sk-ant-api03-KITROVE_SECRET_CANARY_42";
        let harness = HarnessId::Pi;
        let logical_root = RootId::parse("test.root").unwrap();
        let source_relative_path = SourceRelativePath::parse("fixture/SKILL.md").unwrap();
        let exact_source_hash = ContentHash::digest(b"fixture");
        let identity = ObservationIdentity {
            harness: &harness,
            scope: HarnessScope::User,
            root_tier: RootTier::User,
            policy_rank: 1,
            logical_root: &logical_root,
            source_relative_path: &source_relative_path,
            layout: SkillSourceLayout::Directory,
            original_document_name: "SKILL.md",
            native_id: Some(SECRET_NATIVE_ID),
            exact_source_hash: Some(&exact_source_hash),
        };

        let debug = format!("{identity:?}");
        assert!(!debug.contains(SECRET_NATIVE_ID));
        assert!(debug.contains("native_id_present"));
    }
}
