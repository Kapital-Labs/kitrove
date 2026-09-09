use kitrove_model::{HarnessId, HarnessScope, NormalizedDestination, ReceiptId};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::{EvidenceRef, ObservationId, RootId, SourceRelativePath};

/// Whether a scan finding is informational or requires attention.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Informational,
    Attention,
}

/// Logical, redacted subject of a scan finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindingSubject {
    Report,
    Harness(HarnessId),
    Root(RootId),
    Observation(ObservationId),
    Receipt(ReceiptId),
    Destination {
        harness: HarnessId,
        scope: HarnessScope,
        normalized_destination: NormalizedDestination,
    },
    Related {
        logical_root: RootId,
        source_relative_path: SourceRelativePath,
    },
}

impl Serialize for FindingSubject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = match self {
            Self::Report => 1,
            Self::Harness(_) | Self::Root(_) | Self::Observation(_) | Self::Receipt(_) => 2,
            Self::Destination { .. } => 4,
            Self::Related { .. } => 3,
        };
        let mut map = serializer.serialize_map(Some(field_count))?;
        match self {
            Self::Report => map.serialize_entry("type", "report")?,
            Self::Harness(harness) => {
                map.serialize_entry("type", "harness")?;
                map.serialize_entry("harness", harness)?;
            }
            Self::Root(root) => {
                map.serialize_entry("type", "root")?;
                map.serialize_entry("logical_root", root)?;
            }
            Self::Observation(observation_id) => {
                map.serialize_entry("type", "observation")?;
                map.serialize_entry("observation_id", observation_id)?;
            }
            Self::Receipt(receipt_id) => {
                map.serialize_entry("type", "receipt")?;
                map.serialize_entry("receipt_id", receipt_id)?;
            }
            Self::Destination {
                harness,
                scope,
                normalized_destination,
            } => {
                map.serialize_entry("type", "destination")?;
                map.serialize_entry("harness", harness)?;
                map.serialize_entry("scope", scope)?;
                map.serialize_entry("normalized_destination", normalized_destination)?;
            }
            Self::Related {
                logical_root,
                source_relative_path,
            } => {
                map.serialize_entry("type", "related")?;
                map.serialize_entry("logical_root", logical_root)?;
                map.serialize_entry("source_relative_path", source_relative_path)?;
            }
        }
        map.end()
    }
}

/// Redacted, stable scan diagnostic.
///
/// Diagnostic prose is restricted to compiled catalog text. Runtime candidate bodies,
/// paths, and adapter-provided strings therefore cannot be accepted at this boundary.
///
/// ```compile_fail
/// use kitrove_adapter_api::{FindingSeverity, FindingSubject, ScanFinding};
///
/// let runtime_text = String::from("candidate-controlled detail");
/// let _ = ScanFinding::new(
///     "scan.invalid",
///     FindingSeverity::Attention,
///     FindingSubject::Report,
///     vec![],
///     runtime_text,
/// );
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScanFinding {
    pub code: &'static str,
    pub severity: FindingSeverity,
    pub subject: FindingSubject,
    pub evidence: Vec<EvidenceRef>,
    pub action: &'static str,
}

impl ScanFinding {
    /// Creates a finding from compiled catalog text and validated logical evidence.
    #[must_use]
    pub fn new(
        code: &'static str,
        severity: FindingSeverity,
        subject: FindingSubject,
        evidence: Vec<EvidenceRef>,
        action: &'static str,
    ) -> Self {
        Self {
            code,
            severity,
            subject,
            evidence,
            action,
        }
    }
}
