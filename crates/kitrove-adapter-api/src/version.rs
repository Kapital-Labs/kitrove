use std::fmt::{self, Display, Formatter};

use kitrove_model::HarnessId;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{AdapterError, EvidenceRef};

/// A bounded, printable harness version observation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct HarnessVersion(String);

impl HarnessVersion {
    /// Parses 1 to 128 printable ASCII bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self, AdapterError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| (b' '..=b'~').contains(&byte))
        {
            return Err(AdapterError::new(
                "adapter.harness_version_invalid",
                "harness version must contain 1 to 128 printable ASCII bytes",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the observed version text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for HarnessVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Display for HarnessVersion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A compiled, evidence-backed harness policy line.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLine {
    ClaudeCurrent,
    CodexCurrent,
    PiLatest,
    OpenCodeCurrent,
    OpenCodeV2,
}

impl PolicyLine {
    /// Returns the harness that owns this compiled policy line.
    #[must_use]
    pub fn harness(self) -> HarnessId {
        match self {
            Self::ClaudeCurrent => HarnessId::Claude,
            Self::CodexCurrent => HarnessId::Codex,
            Self::PiLatest => HarnessId::Pi,
            Self::OpenCodeCurrent | Self::OpenCodeV2 => HarnessId::OpenCode,
        }
    }

    /// Returns the stable canonical policy-line tag used in plan authority.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCurrent => "claude_current",
            Self::CodexCurrent => "codex_current",
            Self::PiLatest => "pi_latest",
            Self::OpenCodeCurrent => "open_code_current",
            Self::OpenCodeV2 => "open_code_v2",
        }
    }
}

/// Verified evidence selecting one compiled version policy line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedVersionEvidence {
    harness: HarnessId,
    observed: HarnessVersion,
    policy_line: PolicyLine,
    evidence: EvidenceRef,
}

impl VerifiedVersionEvidence {
    /// Creates verified version evidence when the line belongs to the supplied harness.
    pub fn new(
        harness: HarnessId,
        observed: HarnessVersion,
        policy_line: PolicyLine,
        evidence: EvidenceRef,
    ) -> Result<Self, AdapterError> {
        if policy_line.harness() != harness {
            return Err(AdapterError::new(
                "adapter.version_policy_mismatch",
                "verified version evidence must use a policy line owned by its harness",
            ));
        }
        Ok(Self {
            harness,
            observed,
            policy_line,
            evidence,
        })
    }

    #[must_use]
    pub fn harness(&self) -> &HarnessId {
        &self.harness
    }

    #[must_use]
    pub fn observed(&self) -> &HarnessVersion {
        &self.observed
    }

    #[must_use]
    pub const fn policy_line(&self) -> PolicyLine {
        self.policy_line
    }

    #[must_use]
    pub fn evidence(&self) -> &EvidenceRef {
        &self.evidence
    }

    /// Derives the canonical plan-authority reference for this complete observation.
    ///
    /// The digest includes the harness, exact observed version, compiled policy line, and
    /// executable-bound evidence. This keeps confirmation authority sensitive to every field that
    /// selected the policy, even when an executable reports versions from external state.
    pub fn plan_authority(&self) -> Result<EvidenceRef, AdapterError> {
        let mut hasher = blake3::Hasher::new();
        hash_record(&mut hasher, self.harness.as_str());
        hash_record(&mut hasher, self.observed.as_str());
        hash_record(&mut hasher, self.policy_line.as_str());
        hash_record(&mut hasher, self.evidence.as_str());
        EvidenceRef::parse(format!(
            "local.version_probe.authority.blake3.{}",
            hasher.finalize().to_hex()
        ))
    }
}

fn hash_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

/// Borrowed version evidence supplied to an observation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionObservation<'a> {
    Verified(&'a VerifiedVersionEvidence),
    Unknown,
}

/// Owned version evidence retained in a selected policy profile and scan report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VersionObservationOwned {
    Verified {
        observed: HarnessVersion,
        policy_line: PolicyLine,
        evidence: EvidenceRef,
    },
    Unknown,
}

impl From<VersionObservation<'_>> for VersionObservationOwned {
    fn from(value: VersionObservation<'_>) -> Self {
        match value {
            VersionObservation::Verified(evidence) => Self::Verified {
                observed: evidence.observed.clone(),
                policy_line: evidence.policy_line,
                evidence: evidence.evidence.clone(),
            },
            VersionObservation::Unknown => Self::Unknown,
        }
    }
}

/// Selects reviewed version-policy evidence for a destructive target.
///
/// A target may explicitly name one conservative compiled line for unknown versions when that
/// line documents the common destination and format. Version-specific targets pass `None` and
/// fail closed until the caller supplies verified evidence.
pub fn select_materialization_policy(
    harness: HarnessId,
    version: VersionObservation<'_>,
    supported_lines: &[PolicyLine],
    unknown_line: Option<PolicyLine>,
) -> Result<PolicyLine, AdapterError> {
    let selected = match version {
        VersionObservation::Verified(evidence) => {
            if evidence.harness() != &harness {
                return Err(AdapterError::new(
                    "apply.harness_policy_unsupported",
                    "the verified harness version does not select a reviewed materialization policy",
                ));
            }
            evidence.policy_line()
        }
        VersionObservation::Unknown => unknown_line.ok_or_else(|| {
            AdapterError::new(
                "apply.harness_version_unverified",
                "materialization requires verified harness version and policy evidence",
            )
        })?,
    };
    if !supported_lines.contains(&selected) || selected.harness() != harness {
        return Err(AdapterError::new(
            "apply.harness_policy_unsupported",
            "the selected harness version does not have a reviewed materialization policy",
        ));
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(observed: &str, executable: &str) -> VerifiedVersionEvidence {
        VerifiedVersionEvidence::new(
            HarnessId::OpenCode,
            HarnessVersion::parse(observed).unwrap(),
            PolicyLine::OpenCodeV2,
            EvidenceRef::parse(executable).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn plan_authority_binds_observed_version_and_executable_evidence() {
        let first = evidence("opencode2 v2.0.0", "local.probe.first");
        let changed_version = evidence("opencode2 v2.0.1", "local.probe.first");
        let changed_executable = evidence("opencode2 v2.0.0", "local.probe.second");

        assert_ne!(
            first.plan_authority().unwrap(),
            changed_version.plan_authority().unwrap()
        );
        assert_ne!(
            first.plan_authority().unwrap(),
            changed_executable.plan_authority().unwrap()
        );
        assert_eq!(first.plan_authority(), first.plan_authority());
    }
}
