use kitrove_release_policy::ParsedReleaseManifest;
use serde::{Deserialize, Serialize};

/// Caller-selected intent; a saved value must match, never select, that intent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReplacementDirection {
    Upgrade,
    Rollback,
}

impl ReplacementDirection {
    pub(crate) fn permits(
        self,
        candidate: &ParsedReleaseManifest,
        installed: &ParsedReleaseManifest,
    ) -> bool {
        match self {
            Self::Upgrade => candidate.declares_rollback_compatibility_to(installed),
            Self::Rollback => installed.declares_rollback_compatibility_to(candidate),
        }
    }
}
