use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{BindingName, ValidationError};

/// A portable name for local authority required before a target can be applied.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BlockedRequirement {
    /// A symbolic binding must be resolved by machine-local configuration.
    Binding { name: BindingName },
    /// Exact executable content requires a machine-local trust decision.
    ExecutableTrust,
}

impl BlockedRequirement {
    /// Creates a blocked requirement for one symbolic local binding.
    #[must_use]
    pub const fn binding(name: BindingName) -> Self {
        Self::Binding { name }
    }

    /// Returns the binding name only for binding requirements.
    #[must_use]
    pub const fn binding_name(&self) -> Option<&BindingName> {
        match self {
            Self::Binding { name } => Some(name),
            Self::ExecutableTrust => None,
        }
    }
}

/// The categorical fidelity of one asset on one target harness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fidelity {
    Native,
    Portable,
    Adapted,
    Partial,
    Unsupported,
    Blocked,
}

/// A structured explanation attached to a fidelity result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FidelityReason {
    pub code: String,
    pub message: String,
}

impl FidelityReason {
    /// Creates a structured loss or blocking reason.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Evidence supporting a fidelity classification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FidelityEvidence {
    pub kind: String,
    pub detail: String,
}

impl FidelityEvidence {
    /// Creates a fidelity evidence record.
    #[must_use]
    pub fn new(kind: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            detail: detail.into(),
        }
    }
}

/// The complete compatibility result for an asset-target pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FidelityResult {
    fidelity: Fidelity,
    reasons: Vec<FidelityReason>,
    evidence: Vec<FidelityEvidence>,
    blocked_requirements: Vec<BlockedRequirement>,
    adapter_version: String,
    harness_version: Option<String>,
}

impl FidelityResult {
    /// Creates and validates a complete fidelity result.
    pub fn new(
        fidelity: Fidelity,
        reasons: Vec<FidelityReason>,
        evidence: Vec<FidelityEvidence>,
        blocked_requirements: Vec<BlockedRequirement>,
        adapter_version: impl Into<String>,
        harness_version: Option<String>,
    ) -> Result<Self, ValidationError> {
        if matches!(
            fidelity,
            Fidelity::Partial | Fidelity::Unsupported | Fidelity::Blocked
        ) && reasons.is_empty()
        {
            return Err(ValidationError::new(
                "fidelity.reason_required",
                format!("{fidelity:?} fidelity requires at least one structured reason"),
            ));
        }
        if reasons
            .iter()
            .any(|reason| reason.code.trim().is_empty() || reason.message.trim().is_empty())
        {
            return Err(ValidationError::new(
                "fidelity.invalid_reason",
                "fidelity reason codes and messages must be non-empty",
            ));
        }
        if fidelity == Fidelity::Blocked && blocked_requirements.is_empty() {
            return Err(ValidationError::new(
                "fidelity.blocked_requirement_required",
                "blocked fidelity requires at least one symbolic local requirement",
            ));
        }
        if fidelity != Fidelity::Blocked && !blocked_requirements.is_empty() {
            return Err(ValidationError::new(
                "fidelity.unexpected_blocked_requirement",
                "only blocked fidelity may include blocked requirements",
            ));
        }
        if evidence.is_empty() {
            return Err(ValidationError::new(
                "fidelity.evidence_required",
                "every fidelity claim requires at least one evidence record",
            ));
        }
        if evidence
            .iter()
            .any(|item| item.kind.trim().is_empty() || item.detail.trim().is_empty())
        {
            return Err(ValidationError::new(
                "fidelity.invalid_evidence",
                "fidelity evidence kinds and details must be non-empty",
            ));
        }
        let adapter_version = adapter_version.into();
        if adapter_version.trim().is_empty() {
            return Err(ValidationError::new(
                "fidelity.adapter_version_required",
                "fidelity results require an adapter version",
            ));
        }
        Ok(Self {
            fidelity,
            reasons,
            evidence,
            blocked_requirements,
            adapter_version,
            harness_version,
        })
    }

    /// Creates an evidence-backed exact fidelity result.
    pub fn exact(
        fidelity: Fidelity,
        evidence: Vec<FidelityEvidence>,
        adapter_version: impl Into<String>,
        harness_version: Option<String>,
    ) -> Result<Self, ValidationError> {
        if !matches!(
            fidelity,
            Fidelity::Native | Fidelity::Portable | Fidelity::Adapted
        ) {
            return Err(ValidationError::new(
                "fidelity.not_exact",
                "exact fidelity accepts only native, portable, or adapted categories",
            ));
        }
        Self::new(
            fidelity,
            vec![],
            evidence,
            vec![],
            adapter_version,
            harness_version,
        )
    }

    /// Returns the categorical fidelity.
    #[must_use]
    pub const fn fidelity(&self) -> Fidelity {
        self.fidelity
    }

    /// Returns structured loss or blocking explanations.
    #[must_use]
    pub fn reasons(&self) -> &[FidelityReason] {
        &self.reasons
    }

    /// Returns the evidence supporting this claim.
    #[must_use]
    pub fn evidence(&self) -> &[FidelityEvidence] {
        &self.evidence
    }

    /// Returns symbolic requirements that block local application.
    #[must_use]
    pub fn blocked_requirements(&self) -> &[BlockedRequirement] {
        &self.blocked_requirements
    }

    /// Returns the adapter implementation version.
    #[must_use]
    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }

    /// Returns the observed harness version, when known.
    #[must_use]
    pub fn harness_version(&self) -> Option<&str> {
        self.harness_version.as_deref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFidelityResult {
    fidelity: Fidelity,
    #[serde(default)]
    reasons: Vec<FidelityReason>,
    #[serde(default)]
    evidence: Vec<FidelityEvidence>,
    #[serde(default)]
    blocked_requirements: Vec<BlockedRequirement>,
    adapter_version: String,
    harness_version: Option<String>,
}

impl<'de> Deserialize<'de> for FidelityResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFidelityResult::deserialize(deserializer)?;
        Self::new(
            raw.fidelity,
            raw.reasons,
            raw.evidence,
            raw.blocked_requirements,
            raw.adapter_version,
            raw.harness_version,
        )
        .map_err(D::Error::custom)
    }
}
