use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ContentHash, RemoteKey, SyncLimits, ValidationError};

/// Canonical version-1 selector for one machine-local retained sync generation.
///
/// This validates bytes only. It does not establish filesystem or object authority.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct SyncBasePointer {
    schema_version: u32,
    remote_key: RemoteKey,
    generation: ContentHash,
}

impl SyncBasePointer {
    #[must_use]
    pub const fn new(remote_key: RemoteKey, generation: ContentHash) -> Self {
        Self {
            schema_version: 1,
            remote_key,
            generation,
        }
    }

    /// Parses the existing exact canonical selector format with a caller's control budget.
    pub fn from_json(input: &str, limits: SyncLimits) -> Result<Self, ValidationError> {
        if input.len() as u64 > limits.max_control_bytes() {
            return Err(invalid());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: u32,
            remote_key: RemoteKey,
            generation: ContentHash,
        }
        let wire: Wire = serde_json::from_str(input).map_err(|_| invalid())?;
        if wire.schema_version != 1 {
            return Err(invalid());
        }
        let pointer = Self::new(wire.remote_key, wire.generation);
        if pointer.to_json()? != input {
            return Err(invalid());
        }
        Ok(pointer)
    }

    /// Preserves the original pretty-printed JSON and trailing newline exactly.
    pub fn to_json(&self) -> Result<String, ValidationError> {
        let mut text = serde_json::to_string_pretty(self).map_err(|_| invalid())?;
        text.push('\n');
        Ok(text)
    }

    #[must_use]
    pub const fn remote_key(&self) -> &RemoteKey {
        &self.remote_key
    }

    #[must_use]
    pub const fn generation(&self) -> &ContentHash {
        &self.generation
    }
}

impl fmt::Debug for SyncBasePointer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncBasePointer")
            .field("schema_version", &self.schema_version)
            .finish_non_exhaustive()
    }
}

fn invalid() -> ValidationError {
    ValidationError::new(
        "sync_base_pointer.invalid",
        "sync base selector is not valid bounded canonical version-1 JSON",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pointer() -> SyncBasePointer {
        SyncBasePointer::new(
            RemoteKey::parse(format!("remote:blake3:{}", "1".repeat(64))).unwrap(),
            ContentHash::digest(b"generation"),
        )
    }

    #[test]
    fn preserves_the_existing_wire_format_exactly() {
        let pointer = pointer();
        let text = pointer.to_json().unwrap();
        assert_eq!(
            text,
            format!(
                "{{\n  \"schema_version\": 1,\n  \"remote_key\": \"{}\",\n  \"generation\": \"{}\"\n}}\n",
                pointer.remote_key().as_str(),
                pointer.generation().as_str()
            )
        );
        assert_eq!(
            SyncBasePointer::from_json(&text, SyncLimits::default()).unwrap(),
            pointer
        );
        assert!(!format!("{pointer:?}").contains(pointer.remote_key().as_str()));
        assert!(!format!("{pointer:?}").contains(pointer.generation().as_str()));
    }

    #[test]
    fn rejects_unknown_duplicate_noncanonical_and_unsupported_input() {
        let text = pointer().to_json().unwrap();
        for changed in [
            text.replace("\"schema_version\": 1", "\"schema_version\": 2"),
            text.replace(
                "\"schema_version\": 1",
                "\"schema_version\": 1,\n  \"foreign\": \"PRIVATE-CANARY\"",
            ),
            text.replace(
                "\"schema_version\": 1",
                "\"schema_version\": 1,\n  \"schema_version\": 1",
            ),
            text.trim_end().to_owned(),
            serde_json::to_string(&pointer()).unwrap(),
        ] {
            let error = SyncBasePointer::from_json(&changed, SyncLimits::default()).unwrap_err();
            assert!(!error.to_string().contains("PRIVATE-CANARY"));
        }
        let oversized = " ".repeat(SyncLimits::default().max_control_bytes() as usize + 1);
        assert!(SyncBasePointer::from_json(&oversized, SyncLimits::default()).is_err());
    }
}
