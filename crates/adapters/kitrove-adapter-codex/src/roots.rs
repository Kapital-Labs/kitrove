use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use kitrove_adapter_api::{
    AdapterResult, EvidenceRef, FindingSeverity, FindingSubject, NativeRootKey, ObservedRoot,
    PolicyLine, PolicyRuntimeAuthority, ProjectBoundary, ReceiptAnchor, ReceiptAuthority,
    RelatedDocumentPattern, RelatedRoot, RelatedRootAuthority, RootAuthority, RootContext,
    RootEvidenceAuthority, RootHookMeter, RootHookReport, RootId, RootIdAuthority,
    RootPathAuthority, RootRankAuthority, RootTier, ScanFinding,
};
use kitrove_agent_skills::SkillSourceLayout;
use kitrove_model::{AssetKind, HarnessId, HarnessScope};

#[cfg(unix)]
pub(crate) const ADMIN_RANK: u32 = 10;
pub(crate) const USER_RANK: u32 = 20;
pub(crate) const PROJECT_RANK: u32 = 30;
pub(crate) const BUNDLED_RANK: u32 = 40;
pub(crate) const EXPLICIT_RANK: u32 = 50;

pub(crate) const PROFILE_EVIDENCE: &str = "codex.docs.skills.current";
#[cfg(unix)]
pub(crate) const ADMIN_EVIDENCE: &str = "codex.docs.skills.admin";
pub(crate) const USER_EVIDENCE: &str = "codex.docs.skills.user";
pub(crate) const PROJECT_EVIDENCE: &str = "codex.docs.skills.project";
pub(crate) const BUNDLED_EVIDENCE: &str = "codex.docs.skills.bundled";
pub(crate) const AGENT_EVIDENCE: &str = "codex.docs.agents.current";

const BUNDLED_KEY: &str = "codex.bundled";
const BUNDLED_SCOPE_FINDING: &str = "codex.bundled_scope_unsupported";

#[derive(Clone, Copy)]
struct NativeRootDescriptor {
    key: &'static str,
    tier: RootTier,
    policy_rank: u32,
    allowed_scopes: &'static [HarnessScope],
    evidence: &'static str,
    scope_finding: &'static str,
}

const BUNDLED_DESCRIPTOR: NativeRootDescriptor = NativeRootDescriptor {
    key: BUNDLED_KEY,
    tier: RootTier::System,
    policy_rank: BUNDLED_RANK,
    allowed_scopes: &[HarnessScope::User],
    evidence: BUNDLED_EVIDENCE,
    scope_finding: BUNDLED_SCOPE_FINDING,
};

pub(crate) fn runtime_authority() -> PolicyRuntimeAuthority {
    let layouts = BTreeMap::from([(
        PolicyLine::CodexCurrent,
        BTreeSet::from([SkillSourceLayout::Directory]),
    )]);
    let roots = vec![
        RootAuthority {
            logical_id: RootIdAuthority::Exact(RootId::parse("codex.user.skills").unwrap()),
            path: RootPathAuthority::HomeRelative(PathBuf::from(".agents/skills")),
            scopes: BTreeSet::from([HarnessScope::User]),
            tier: RootTier::User,
            rank: RootRankAuthority::Exact(USER_RANK),
            layouts: layouts.clone(),
            evidence: RootEvidenceAuthority::Exact(evidence(USER_EVIDENCE)),
        },
        RootAuthority {
            logical_id: RootIdAuthority::IndexedPrefix("codex.project.skills.".to_owned()),
            path: RootPathAuthority::ProjectAncestorRelative {
                relative: PathBuf::from(".agents/skills"),
                root_to_current: false,
                ascend_without_repository: false,
            },
            scopes: BTreeSet::from([HarnessScope::Project]),
            tier: RootTier::Project,
            rank: RootRankAuthority::Exact(PROJECT_RANK),
            layouts: layouts.clone(),
            evidence: RootEvidenceAuthority::Exact(evidence(PROJECT_EVIDENCE)),
        },
        RootAuthority {
            logical_id: RootIdAuthority::IndexedPrefix("codex.system.bundled.".to_owned()),
            path: RootPathAuthority::SuppliedNative(NativeRootKey::parse(BUNDLED_KEY).unwrap()),
            scopes: BTreeSet::from([HarnessScope::User]),
            tier: RootTier::System,
            rank: RootRankAuthority::Exact(BUNDLED_RANK),
            layouts: layouts.clone(),
            evidence: RootEvidenceAuthority::Exact(evidence(BUNDLED_EVIDENCE)),
        },
        RootAuthority {
            logical_id: RootIdAuthority::IndexedPrefix("codex.explicit.".to_owned()),
            path: RootPathAuthority::ExplicitDirectory,
            scopes: BTreeSet::from([HarnessScope::User, HarnessScope::Project]),
            tier: RootTier::Explicit,
            rank: RootRankAuthority::Indexed {
                base: EXPLICIT_RANK,
            },
            layouts: layouts.clone(),
            evidence: RootEvidenceAuthority::Exact(evidence(PROFILE_EVIDENCE)),
        },
    ];
    #[cfg(unix)]
    let roots = {
        let mut roots = roots;
        roots.insert(
            0,
            RootAuthority {
                logical_id: RootIdAuthority::Exact(RootId::parse("codex.admin.skills").unwrap()),
                path: RootPathAuthority::Exact(PathBuf::from("/etc/codex/skills")),
                scopes: BTreeSet::from([HarnessScope::User]),
                tier: RootTier::Admin,
                rank: RootRankAuthority::Exact(ADMIN_RANK),
                layouts: layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(ADMIN_EVIDENCE)),
            },
        );
        roots
    };
    PolicyRuntimeAuthority {
        roots,
        related_roots: vec![
            RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::Exact(RootId::parse("codex.user.agents").unwrap()),
                    path: RootPathAuthority::HomeRelative(PathBuf::from(".codex/agents")),
                    scopes: BTreeSet::from([HarnessScope::User]),
                    tier: RootTier::User,
                    rank: RootRankAuthority::Exact(USER_RANK),
                    layouts: BTreeMap::new(),
                    evidence: RootEvidenceAuthority::Exact(evidence(AGENT_EVIDENCE)),
                },
                kind: AssetKind::Agent,
                pattern: RelatedDocumentPattern::TomlDirectChildren,
            },
            RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::IndexedPrefix("codex.project.agents.".to_owned()),
                    path: RootPathAuthority::ProjectAncestorRelative {
                        relative: PathBuf::from(".codex/agents"),
                        root_to_current: false,
                        ascend_without_repository: false,
                    },
                    scopes: BTreeSet::from([HarnessScope::Project]),
                    tier: RootTier::Project,
                    rank: RootRankAuthority::Exact(PROJECT_RANK),
                    layouts: BTreeMap::new(),
                    evidence: RootEvidenceAuthority::Exact(evidence(AGENT_EVIDENCE)),
                },
                kind: AssetKind::Agent,
                pattern: RelatedDocumentPattern::TomlDirectChildren,
            },
        ],
        receipt_anchors: vec![
            ReceiptAuthority {
                path: RootPathAuthority::HomeRelative(PathBuf::from(".agents/skills")),
                scope: HarnessScope::User,
                evidence: evidence(USER_EVIDENCE),
            },
            ReceiptAuthority {
                path: RootPathAuthority::ProjectAncestorRelative {
                    relative: PathBuf::from(".agents/skills"),
                    root_to_current: true,
                    ascend_without_repository: false,
                },
                scope: HarnessScope::Project,
                evidence: evidence(PROJECT_EVIDENCE),
            },
        ],
    }
}

pub(crate) fn agent_roots(context: &RootContext<'_>) -> Vec<RelatedRoot> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            roots.push(RelatedRoot {
                logical_id: RootId::parse("codex.user.agents").unwrap(),
                path: home.join(".codex/agents"),
                scope: HarnessScope::User,
                tier: RootTier::User,
                policy_rank: USER_RANK,
                kind: AssetKind::Agent,
                pattern: RelatedDocumentPattern::TomlDirectChildren,
                evidence: evidence(AGENT_EVIDENCE),
            });
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        for (index, anchor) in project_anchors(context).into_iter().enumerate() {
            roots.push(RelatedRoot {
                logical_id: RootId::parse(format!("codex.project.agents.{index:04}")).unwrap(),
                path: anchor.join(".codex/agents"),
                scope: HarnessScope::Project,
                tier: RootTier::Project,
                policy_rank: PROJECT_RANK,
                kind: AssetKind::Agent,
                pattern: RelatedDocumentPattern::TomlDirectChildren,
                evidence: evidence(AGENT_EVIDENCE),
            });
        }
    }
    roots
}

pub(crate) fn standard_roots(context: &RootContext<'_>) -> AdapterResult<Vec<ObservedRoot>> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        #[cfg(unix)]
        roots.push(observed_root(
            "codex.admin.skills",
            PathBuf::from("/etc/codex/skills"),
            HarnessScope::User,
            RootTier::Admin,
            ADMIN_RANK,
            ADMIN_EVIDENCE,
        ));
        if let Some(home) = context.home {
            roots.push(observed_root(
                "codex.user.skills",
                home.join(".agents/skills"),
                HarnessScope::User,
                RootTier::User,
                USER_RANK,
                USER_EVIDENCE,
            ));
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        for (index, anchor) in project_anchors(context).into_iter().enumerate() {
            roots.push(observed_root(
                &format!("codex.project.skills.{index:04}"),
                anchor.join(".agents/skills"),
                HarnessScope::Project,
                RootTier::Project,
                PROJECT_RANK,
                PROJECT_EVIDENCE,
            ));
        }
    }
    Ok(roots)
}

pub(crate) fn unusual_roots(
    context: &RootContext<'_>,
    unknown: bool,
    meter: &mut dyn RootHookMeter,
) -> RootHookReport {
    let mut report = RootHookReport::default();
    if unknown {
        report.findings.push(ScanFinding::new(
            "codex.version_unknown",
            FindingSeverity::Informational,
            FindingSubject::Harness(HarnessId::Codex),
            vec![evidence(PROFILE_EVIDENCE)],
            "use the conservative current Codex directory policy",
        ));
    }
    if scope_selected(context, HarnessScope::User) {
        let resolved = append_supplied_roots(context, &mut report, meter);
        if !resolved {
            report.findings.push(ScanFinding::new(
                "scan.root_unresolved",
                FindingSeverity::Informational,
                FindingSubject::Root(
                    RootId::parse("codex.system.skills")
                        .expect("compiled Codex system root ID is valid"),
                ),
                vec![evidence(BUNDLED_EVIDENCE)],
                "supply the Codex bundled skills provider through codex.bundled",
            ));
        }
    }
    append_explicit_roots(context, &mut report, meter);
    report.roots.sort_by(|left, right| {
        left.policy_rank
            .cmp(&right.policy_rank)
            .then_with(|| left.logical_id.cmp(&right.logical_id))
            .then_with(|| left.scope.cmp(&right.scope))
    });
    report.findings.sort_by(|left, right| {
        left.code
            .cmp(right.code)
            .then_with(|| format!("{:?}", left.subject).cmp(&format!("{:?}", right.subject)))
    });
    report
}

fn append_explicit_roots(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    meter: &mut dyn RootHookMeter,
) {
    for (index, explicit) in context.explicit_roots.iter().enumerate() {
        if explicit.harness != HarnessId::Codex || !scope_selected(context, explicit.scope) {
            continue;
        }
        if !meter.try_root_input() || report.roots.len() >= context.limits.max_roots {
            if !report
                .findings
                .iter()
                .any(|finding| finding.code == "scan.root_budget_exhausted")
            {
                report.findings.push(supplied_finding(
                    "scan.root_budget_exhausted",
                    "reduce explicit Codex roots or increase the request root limit",
                ));
            }
            break;
        }
        report.roots.push(observed_root(
            &format!("codex.explicit.{index:04}"),
            explicit.path.clone(),
            explicit.scope,
            RootTier::Explicit,
            indexed_rank(EXPLICIT_RANK, index),
            PROFILE_EVIDENCE,
        ));
    }
}

fn indexed_rank(base: u32, index: usize) -> u32 {
    base.saturating_add(u32::try_from(index).unwrap_or(u32::MAX))
}

pub(crate) fn standard_receipt_anchors(context: &RootContext<'_>) -> Vec<ReceiptAnchor> {
    let mut anchors = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            anchors.push(ReceiptAnchor {
                scope: HarnessScope::User,
                path: home.join(".agents/skills"),
                evidence: evidence(USER_EVIDENCE),
            });
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        if let Some(anchor) = project_anchors(context).into_iter().last() {
            anchors.push(ReceiptAnchor {
                scope: HarnessScope::Project,
                path: anchor.join(".agents/skills"),
                evidence: evidence(PROJECT_EVIDENCE),
            });
        }
    }
    anchors
}

fn append_supplied_roots(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    meter: &mut dyn RootHookMeter,
) -> bool {
    let mut resolved = false;
    for (index, supplied) in context.supplied_native_roots.iter().enumerate() {
        if supplied.harness() != &HarnessId::Codex {
            continue;
        }
        if !meter.try_root_input() {
            if !report
                .findings
                .iter()
                .any(|finding| finding.code == "scan.root_budget_exhausted")
            {
                report.findings.push(supplied_finding(
                    "scan.root_budget_exhausted",
                    "reduce supplied Codex roots or increase the request root limit",
                ));
            }
            break;
        }
        let Some(descriptor) = descriptor(supplied.source_key()) else {
            report.findings.push(supplied_finding(
                "codex.native_root_unknown",
                "select the compiled codex.bundled native-root descriptor",
            ));
            continue;
        };
        if !descriptor.allowed_scopes.contains(&supplied.scope()) {
            report.findings.push(supplied_finding(
                descriptor.scope_finding,
                "select user scope for the Codex bundled skills provider",
            ));
            continue;
        }
        if !scope_selected(context, supplied.scope()) {
            continue;
        }
        resolved = true;
        if report.roots.len() >= context.limits.max_roots {
            report.findings.push(supplied_finding(
                "scan.root_budget_exhausted",
                "reduce supplied Codex roots or increase the request root limit",
            ));
            break;
        }
        report.roots.push(observed_root(
            &format!("codex.system.bundled.{index:04}"),
            supplied.path().to_path_buf(),
            supplied.scope(),
            descriptor.tier,
            descriptor.policy_rank,
            descriptor.evidence,
        ));
    }
    resolved
}

pub(crate) fn project_anchors(context: &RootContext<'_>) -> Vec<PathBuf> {
    match context.project_boundary {
        ProjectBoundary::NoRepository | ProjectBoundary::UnsafeStop => {
            vec![context.working_directory.to_path_buf()]
        }
        ProjectBoundary::Repository { root } => {
            if !context.working_directory.starts_with(root) {
                return vec![];
            }
            let mut anchors = Vec::new();
            let mut current = context.working_directory;
            loop {
                anchors.push(current.to_path_buf());
                if current == root {
                    break;
                }
                let Some(parent) = current.parent() else {
                    break;
                };
                current = parent;
            }
            anchors
        }
    }
}

fn observed_root(
    logical_id: &str,
    path: PathBuf,
    scope: HarnessScope,
    tier: RootTier,
    policy_rank: u32,
    evidence_ref: &str,
) -> ObservedRoot {
    ObservedRoot {
        logical_id: RootId::parse(logical_id).expect("compiled Codex root IDs are valid"),
        path,
        scope,
        tier,
        policy_rank,
        enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
        evidence: evidence(evidence_ref),
    }
}

fn descriptor(key: &NativeRootKey) -> Option<NativeRootDescriptor> {
    (key.as_str() == BUNDLED_DESCRIPTOR.key).then_some(BUNDLED_DESCRIPTOR)
}

fn scope_selected(context: &RootContext<'_>, scope: HarnessScope) -> bool {
    matches!(
        (context.scopes, scope),
        (kitrove_adapter_api::ScopeSelection::All, _)
            | (
                kitrove_adapter_api::ScopeSelection::User,
                HarnessScope::User
            )
            | (
                kitrove_adapter_api::ScopeSelection::Project,
                HarnessScope::Project
            )
    )
}

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).expect("compiled Codex evidence references are valid")
}

fn supplied_finding(code: &'static str, action: &'static str) -> ScanFinding {
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Harness(HarnessId::Codex),
        vec![evidence(BUNDLED_EVIDENCE)],
        action,
    )
}
