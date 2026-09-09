use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use kitrove_agent_skills::SkillSourceLayout;
use kitrove_model::{AssetKind, HarnessScope};

use crate::{
    EvidenceRef, NativeRootKey, ObservedRoot, PolicyLine, ReceiptAnchor, RelatedDocumentPattern,
    RelatedRoot, RootId, RootTier,
};

/// Closed logical-ID matcher compiled into a policy's runtime authority catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootIdAuthority {
    Exact(RootId),
    Prefix(String),
    IndexedPrefix(String),
    IndexedPrefixWithSuffixes {
        prefix: String,
        suffixes: BTreeSet<String>,
    },
    IndexedPrefixWithEncodedFile(String),
}

/// Request-derived containment rule for one compiled root or receipt claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootPathAuthority {
    Exact(PathBuf),
    HomeRelative(PathBuf),
    WorkingRelative(PathBuf),
    ProjectAncestorRelative {
        relative: PathBuf,
        root_to_current: bool,
        ascend_without_repository: bool,
    },
    WorkingDescendant {
        suffix: PathBuf,
        include_working_root: bool,
    },
    SuppliedNative(NativeRootKey),
    ExplicitDirectory,
    /// One exact explicit standalone-file request.
    ///
    /// Candidate-root authority must pair this with
    /// [`RootIdAuthority::IndexedPrefixWithEncodedFile`]. The shared engine resolves the closed
    /// request index only when both the returned root parent and the indexed exact file name
    /// agree with the same request item.
    ExplicitFileRequest,
}

/// Exact or request-owned evidence permitted for a compiled root claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootEvidenceAuthority {
    Exact(EvidenceRef),
    ProjectTrust { fallback: EvidenceRef },
}

/// Rank claim for an exact root or a request-order/project-anchor indexed root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootRankAuthority {
    Exact(u32),
    Indexed { base: u32 },
}

/// Complete enumerable authority for one family of candidate roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootAuthority {
    pub logical_id: RootIdAuthority,
    pub path: RootPathAuthority,
    pub scopes: BTreeSet<HarnessScope>,
    pub tier: RootTier,
    pub rank: RootRankAuthority,
    pub layouts: BTreeMap<PolicyLine, BTreeSet<SkillSourceLayout>>,
    pub evidence: RootEvidenceAuthority,
}

/// Complete enumerable authority for one family of body-unread related roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedRootAuthority {
    pub root: RootAuthority,
    pub kind: AssetKind,
    pub pattern: RelatedDocumentPattern,
}

/// Closed destination authority for one receipt-anchor family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptAuthority {
    pub path: RootPathAuthority,
    pub scope: HarnessScope,
    pub evidence: EvidenceRef,
}

/// Runtime catalogs retained by the shared engine and registry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyRuntimeAuthority {
    pub roots: Vec<RootAuthority>,
    pub related_roots: Vec<RelatedRootAuthority>,
    pub receipt_anchors: Vec<ReceiptAuthority>,
}

impl PolicyRuntimeAuthority {
    /// Builds a closed catalog from exact, already-validated claims.
    ///
    /// This is useful for fixed synthetic policies. Tier-one policies use request-derived path
    /// rules so their catalogs remain enumerable before a request supplies local paths.
    #[must_use]
    pub fn exact(
        line: PolicyLine,
        roots: &[ObservedRoot],
        related_roots: &[RelatedRoot],
        receipt_anchors: &[ReceiptAnchor],
    ) -> Self {
        Self {
            roots: roots
                .iter()
                .map(|root| RootAuthority {
                    logical_id: RootIdAuthority::Exact(root.logical_id.clone()),
                    path: RootPathAuthority::Exact(root.path.clone()),
                    scopes: BTreeSet::from([root.scope]),
                    tier: root.tier,
                    rank: RootRankAuthority::Exact(root.policy_rank),
                    layouts: BTreeMap::from([(line, root.enabled_layouts.clone())]),
                    evidence: RootEvidenceAuthority::Exact(root.evidence.clone()),
                })
                .collect(),
            related_roots: related_roots
                .iter()
                .map(|root| RelatedRootAuthority {
                    root: RootAuthority {
                        logical_id: RootIdAuthority::Exact(root.logical_id.clone()),
                        path: RootPathAuthority::Exact(root.path.clone()),
                        scopes: BTreeSet::from([root.scope]),
                        tier: root.tier,
                        rank: RootRankAuthority::Exact(root.policy_rank),
                        layouts: BTreeMap::new(),
                        evidence: RootEvidenceAuthority::Exact(root.evidence.clone()),
                    },
                    kind: root.kind,
                    pattern: root.pattern,
                })
                .collect(),
            receipt_anchors: receipt_anchors
                .iter()
                .map(|anchor| ReceiptAuthority {
                    path: RootPathAuthority::Exact(anchor.path.clone()),
                    scope: anchor.scope,
                    evidence: anchor.evidence.clone(),
                })
                .collect(),
        }
    }
}
