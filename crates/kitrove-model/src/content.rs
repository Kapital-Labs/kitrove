use std::fmt::{self, Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::ValidationError;

/// A platform-neutral path relative to the portable environment root.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PortablePath(String);

impl PortablePath {
    /// Parses a portable relative path.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty()
            || value.starts_with('/')
            || value.contains('\\')
            || value.contains(':')
            || value
                .split('/')
                .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        {
            return Err(ValidationError::new(
                "path.not_portable",
                format!("{value:?} is not a portable relative path"),
            ));
        }
        Ok(Self(value))
    }

    /// Returns the normalized forward-slash path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PortablePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for PortablePath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An algorithm-qualified BLAKE3 content identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ContentHash(String);

impl ContentHash {
    /// Parses `blake3:` followed by exactly 64 lowercase hexadecimal digits.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let Some(digest) = value.strip_prefix("blake3:") else {
            return Err(ValidationError::new(
                "hash.unsupported_algorithm",
                "content hash must use the 'blake3:' algorithm qualifier",
            ));
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ValidationError::new(
                "hash.invalid_digest",
                "BLAKE3 digest must contain exactly 64 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value))
    }

    /// Hashes bytes into Kitrove's algorithm-qualified representation.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        Self(format!("blake3:{}", blake3::hash(bytes).to_hex()))
    }

    /// Returns the qualified hash as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for ContentHash {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A portable Git repository URL without embedded credentials or mutable query data.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RepositoryUrl(String);

impl RepositoryUrl {
    /// Parses an HTTPS or SSH repository URL suitable for portable state.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.contains(['?', '#', '\r', '\n']) || value.chars().any(char::is_whitespace) {
            return Err(ValidationError::new(
                "source.repository_url",
                "repository URL cannot contain query parameters, fragments, controls, or whitespace",
            ));
        }

        let authority_and_path = if let Some(rest) = value.strip_prefix("https://") {
            if rest
                .split('/')
                .next()
                .is_some_and(|authority| authority.contains('@'))
            {
                return Err(ValidationError::new(
                    "source.repository_credentials",
                    "HTTPS repository URLs cannot contain user information",
                ));
            }
            rest
        } else if let Some(rest) = value.strip_prefix("ssh://") {
            let authority = rest.split('/').next().unwrap_or_default();
            if authority.split('@').count() > 2
                || authority
                    .split_once('@')
                    .is_some_and(|(user, _)| user.is_empty() || user.contains(':'))
            {
                return Err(ValidationError::new(
                    "source.repository_credentials",
                    "SSH repository URLs may contain a username but not a password",
                ));
            }
            rest
        } else {
            return Err(ValidationError::new(
                "source.repository_scheme",
                "repository URL must use https:// or ssh://",
            ));
        };

        let Some((authority, path)) = authority_and_path.split_once('/') else {
            return Err(ValidationError::new(
                "source.repository_url",
                "repository URL must include a host and repository path",
            ));
        };
        if authority.is_empty() || path.is_empty() {
            return Err(ValidationError::new(
                "source.repository_url",
                "repository URL must include a host and repository path",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the credential-free repository URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RepositoryUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for RepositoryUrl {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Content risk classification, not a claim of safety.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentClass {
    DataOnly,
    AgentActive,
    Executable,
}
