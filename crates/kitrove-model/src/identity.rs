use std::fmt::{self, Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::ValidationError;
use crate::content::PortablePath;

fn validate_identifier(value: &str, label: &str) -> Result<(), ValidationError> {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return Err(ValidationError::new(
            "identity.empty",
            format!("{label} is empty"),
        ));
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(ValidationError::new(
            "identity.invalid_start",
            format!("{label} must start with a lowercase ASCII letter or digit"),
        ));
    }
    if !characters.all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_' | '.')
    }) {
        return Err(ValidationError::new(
            "identity.invalid_character",
            format!("{label} may contain only lowercase ASCII letters, digits, '-', '_', and '.'"),
        ));
    }
    Ok(())
}

macro_rules! validated_identifier {
    ($name:ident, $label:literal) => {
        #[doc = concat!("A validated ", $label, ".")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Parses a ", $label, ".")]
            pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
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

validated_identifier!(AssetId, "asset identifier");
validated_identifier!(BindingName, "binding name");
validated_identifier!(ProfileId, "profile identifier");
validated_identifier!(MachineId, "machine identifier");
validated_identifier!(ReceiptId, "receipt identifier");
validated_identifier!(PackApplicationId, "pack application identifier");

/// A versioned content identity for one immutable component provenance record.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProvenanceId(String);

impl ProvenanceId {
    /// Parses `provenance:blake3:` followed by 64 lowercase hexadecimal digits.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let Some(digest) = value.strip_prefix("provenance:blake3:") else {
            return Err(ValidationError::new(
                "provenance_id.unsupported_format",
                "provenance ID must use the 'provenance:blake3:' format",
            ));
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ValidationError::new(
                "provenance_id.invalid_digest",
                "provenance BLAKE3 digest must contain exactly 64 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the versioned provenance identity as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ProvenanceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for ProvenanceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The logical scope to which a harness destination belongs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessScope {
    User,
    Project,
}

impl HarnessScope {
    /// Returns the stable scope tag used in persisted state and receipt identity.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
        }
    }
}

/// A canonical absolute destination for machine-local harness materialization.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NormalizedDestination(String);

impl NormalizedDestination {
    /// Parses and normalizes an absolute Unix or drive-letter Windows destination.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty() || value.contains('\0') {
            return Err(ValidationError::new(
                "destination.invalid",
                "destination must be a non-empty path without NUL bytes",
            ));
        }
        if value.starts_with("//") || value.starts_with(r"\\") {
            return Err(ValidationError::new(
                "destination.invalid",
                "destination must not use a UNC, verbatim, or device path form",
            ));
        }

        let (normalized, is_windows) = if let Some(drive) = value
            .as_bytes()
            .get(0..2)
            .filter(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1] == b':')
        {
            let suffix = &value[2..];
            if !suffix.starts_with(['/', '\\']) {
                return Err(ValidationError::new(
                    "destination.invalid",
                    "Windows destinations must be drive-letter absolute paths",
                ));
            }
            (
                format!("{}:{}", char::from(drive[0]).to_ascii_uppercase(), suffix)
                    .replace('\\', "/"),
                true,
            )
        } else if value.starts_with('/') {
            (value, false)
        } else {
            return Err(ValidationError::new(
                "destination.invalid",
                "destination must be an absolute Unix or drive-letter Windows path",
            ));
        };

        let (prefix, components) = if is_windows {
            (&normalized[..3], &normalized[3..])
        } else {
            ("/", &normalized[1..])
        };
        let mut canonical_components = Vec::new();
        for component in components.split('/') {
            if component.is_empty() {
                continue;
            }
            if component == "." || component == ".." {
                return Err(ValidationError::new(
                    "destination.invalid",
                    "destination must not contain '.' or '..' components",
                ));
            }
            if is_windows && !kitrove_windows_names::is_lossless_windows_component(component) {
                return Err(ValidationError::new(
                    "destination.invalid",
                    "Windows destination components must be lossless in the ordinary Win32 namespace",
                ));
            }
            canonical_components.push(component);
        }
        let canonical = if canonical_components.is_empty() {
            prefix.to_owned()
        } else {
            format!("{prefix}{}", canonical_components.join("/"))
        };
        Ok(Self(canonical))
    }

    /// Returns the canonical destination string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Joins one validated portable relative path without host filesystem semantics.
    pub fn join_portable(&self, relative: &PortablePath) -> Result<Self, ValidationError> {
        let separator = if self.0.ends_with('/') { "" } else { "/" };
        Self::parse(format!("{}{separator}{}", self.0, relative.as_str()))
    }

    /// Recovers the canonical root whose portable child is this destination.
    pub fn anchor_for(&self, relative: &PortablePath) -> Result<Self, ValidationError> {
        let Some(prefix) = self.0.strip_suffix(relative.as_str()) else {
            return Err(destination_invalid());
        };
        if !prefix.ends_with('/') {
            return Err(destination_invalid());
        }
        let anchor = if prefix == "/" || prefix.ends_with(":/") {
            prefix
        } else {
            prefix.strip_suffix('/').ok_or_else(destination_invalid)?
        };
        Self::parse(anchor.to_owned())
    }

    /// Iterates canonical identities for every strict ancestor from root to parent.
    ///
    /// This is host-independent: Windows destinations retain drive-letter semantics even when
    /// Kitrove is running on Unix, and Unix destinations retain Unix semantics on Windows.
    pub fn strict_ancestor_strings(&self) -> impl Iterator<Item = &str> {
        let root_length = if self.0.starts_with('/') { 1 } else { 3 };
        let root = (self.0.len() > root_length).then_some(&self.0[..root_length]);
        root.into_iter().chain(
            self.0
                .match_indices('/')
                .filter(move |(separator, _)| *separator > root_length)
                .map(|(separator, _)| &self.0[..separator]),
        )
    }

    /// Returns whether this destination is a strict ancestor of `other`.
    #[must_use]
    pub fn is_ancestor_of(&self, other: &Self) -> bool {
        other
            .strict_ancestor_strings()
            .any(|ancestor| ancestor == self.as_str())
    }
}

fn destination_invalid() -> ValidationError {
    ValidationError::new(
        "destination.invalid",
        "destination does not contain the portable relative path at a component boundary",
    )
}

impl<'de> Deserialize<'de> for NormalizedDestination {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for NormalizedDestination {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated environment-variable reference, never its resolved value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EnvironmentVariableName(String);

impl EnvironmentVariableName {
    /// Parses a portable environment-variable name.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let mut bytes = value.bytes();
        let Some(first) = bytes.next() else {
            return Err(ValidationError::new(
                "binding.environment_variable",
                "environment-variable name is empty",
            ));
        };
        if !(first.is_ascii_alphabetic() || first == b'_')
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ValidationError::new(
                "binding.environment_variable",
                "environment-variable name must use ASCII letters, digits, and underscores and cannot start with a digit",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the unresolved environment-variable name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for EnvironmentVariableName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for EnvironmentVariableName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An immutable source revision or harness observation identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(String);

impl Revision {
    /// Parses a non-empty, single-line immutable revision identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.trim().is_empty() || value.contains(['\r', '\n']) {
            return Err(ValidationError::new(
                "revision.invalid",
                "revision must be a non-empty single-line identifier",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the revision identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for Revision {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Backward-compatible name for asset identifier validation failures.
pub type InvalidAssetId = ValidationError;

/// A validated namespaced identifier for a community harness adapter.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommunityHarnessId(String);

impl CommunityHarnessId {
    /// Parses a namespaced community harness identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let segments = value.split('/').collect::<Vec<_>>();
        if segments.len() < 2
            || segments
                .iter()
                .any(|segment| validate_identifier(segment, "harness namespace segment").is_err())
        {
            return Err(ValidationError::new(
                "harness.invalid_id",
                "community harness identifiers must contain at least two lowercase namespace segments separated by '/'",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the validated namespaced identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CommunityHarnessId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for CommunityHarnessId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A harness recognized by the domain model.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(into = "String")]
pub enum HarnessId {
    Claude,
    Codex,
    Pi,
    OpenCode,
    Other(CommunityHarnessId),
}

impl HarnessId {
    /// Parses a tier-one or namespaced community harness identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        match value.as_str() {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "pi" => Ok(Self::Pi),
            "opencode" => Ok(Self::OpenCode),
            _ => CommunityHarnessId::parse(value).map(Self::Other),
        }
    }

    /// Returns the stable identifier used in plans and persisted state.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Pi => "pi",
            Self::OpenCode => "opencode",
            Self::Other(value) => value.as_str(),
        }
    }
}

impl From<HarnessId> for String {
    fn from(value: HarnessId) -> Self {
        value.as_str().to_owned()
    }
}

impl<'de> Deserialize<'de> for HarnessId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for HarnessId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_join_and_anchor_are_host_independent_inverses() {
        let relative = PortablePath::parse("skills/example").unwrap();
        for anchor in ["/", "/targets", "C:/", "D:/harness"] {
            let anchor = NormalizedDestination::parse(anchor).unwrap();
            let destination = anchor.join_portable(&relative).unwrap();

            assert_eq!(destination.anchor_for(&relative).unwrap(), anchor);
        }
    }

    #[test]
    fn anchor_requires_a_complete_component_suffix() {
        let destination = NormalizedDestination::parse("/targets/not-skills/example").unwrap();
        let relative = PortablePath::parse("skills/example").unwrap();

        assert_eq!(
            destination.anchor_for(&relative).unwrap_err().code(),
            "destination.invalid"
        );
    }
}
