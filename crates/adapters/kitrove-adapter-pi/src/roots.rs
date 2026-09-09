use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use kitrove_adapter_api::{
    AdapterResult, EvidenceRef, FindingSeverity, FindingSubject, ObservedRoot, PolicyLine,
    PolicyRuntimeAuthority, ProjectBoundary, ProjectTrustKey, ProjectTrustObservation,
    ReceiptAnchor, ReceiptAuthority, RelatedDocumentPattern, RelatedRoot, RelatedRootAuthority,
    RootAuthority, RootContext, RootEvidenceAuthority, RootHookMeter, RootHookReport, RootId,
    RootIdAuthority, RootPathAuthority, RootRankAuthority, RootTier, ScanFinding,
};
use kitrove_agent_skills::SkillSourceLayout;
use kitrove_model::{AssetKind, HarnessId, HarnessScope};

pub(crate) const USER_NATIVE_RANK: u32 = 10;
pub(crate) const USER_COMPATIBILITY_RANK: u32 = 20;
pub(crate) const PROJECT_NATIVE_RANK: u32 = 30;
pub(crate) const PROJECT_COMPATIBILITY_RANK: u32 = 40;
pub(crate) const USER_EXTENSION_RANK: u32 = 15;
pub(crate) const PROJECT_EXTENSION_RANK: u32 = 35;
pub(crate) const USER_COMMAND_RANK: u32 = 12;
pub(crate) const PROJECT_COMMAND_RANK: u32 = 32;
pub(crate) const EXPLICIT_RANK: u32 = 50;

pub(crate) const PROFILE_EVIDENCE: &str = "pi.docs.skills.latest";
pub(crate) const USER_NATIVE_EVIDENCE: &str = "pi.docs.skills.user-native";
pub(crate) const USER_COMPATIBILITY_EVIDENCE: &str = "pi.docs.skills.user-compatibility";
pub(crate) const PROJECT_NATIVE_EVIDENCE: &str = "pi.docs.skills.project-native";
pub(crate) const PROJECT_COMPATIBILITY_EVIDENCE: &str = "pi.docs.skills.project-compatibility";
pub(crate) const PROJECT_TRUST_UNKNOWN_EVIDENCE: &str = "pi.docs.skills.project-trust-unknown";
pub(crate) const EXPLICIT_EVIDENCE: &str = "pi.docs.skills.explicit-local";
pub(crate) const DUPLICATE_EVIDENCE: &str = "pi.docs.skills.first-found";
pub(crate) const USER_EXTENSION_EVIDENCE: &str = "pi.docs.extensions.user-native";
pub(crate) const COMMAND_EVIDENCE: &str = "pi.docs.prompt-templates";

const DIRECTORY_LAYOUTS: [SkillSourceLayout; 1] = [SkillSourceLayout::Directory];
const STANDALONE_LAYOUTS: [SkillSourceLayout; 1] = [SkillSourceLayout::Standalone];
const BOTH_LAYOUTS: [SkillSourceLayout; 2] =
    [SkillSourceLayout::Directory, SkillSourceLayout::Standalone];

pub(crate) fn runtime_authority() -> PolicyRuntimeAuthority {
    let line = PolicyLine::PiLatest;
    let directory = BTreeMap::from([(line, BTreeSet::from([SkillSourceLayout::Directory]))]);
    let standalone = BTreeMap::from([(line, BTreeSet::from([SkillSourceLayout::Standalone]))]);
    let both = BTreeMap::from([(line, BOTH_LAYOUTS.into_iter().collect())]);
    let trust = RootEvidenceAuthority::ProjectTrust {
        fallback: evidence(PROJECT_TRUST_UNKNOWN_EVIDENCE),
    };
    PolicyRuntimeAuthority {
        roots: vec![
            RootAuthority {
                logical_id: RootIdAuthority::Exact(RootId::parse("pi.user.native.skills").unwrap()),
                path: RootPathAuthority::HomeRelative(PathBuf::from(".pi/agent/skills")),
                scopes: BTreeSet::from([HarnessScope::User]),
                tier: RootTier::User,
                rank: RootRankAuthority::Exact(USER_NATIVE_RANK),
                layouts: both.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(USER_NATIVE_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::Exact(
                    RootId::parse("pi.user.compatibility.skills").unwrap(),
                ),
                path: RootPathAuthority::HomeRelative(PathBuf::from(".agents/skills")),
                scopes: BTreeSet::from([HarnessScope::User]),
                tier: RootTier::Compatibility,
                rank: RootRankAuthority::Exact(USER_COMPATIBILITY_RANK),
                layouts: both.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(USER_COMPATIBILITY_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::Prefix("pi.project.native.skills.".to_owned()),
                path: RootPathAuthority::ProjectAncestorRelative {
                    relative: PathBuf::from(".pi/skills"),
                    root_to_current: true,
                    ascend_without_repository: false,
                },
                scopes: BTreeSet::from([HarnessScope::Project]),
                tier: RootTier::Project,
                rank: RootRankAuthority::Exact(PROJECT_NATIVE_RANK),
                layouts: both.clone(),
                evidence: trust.clone(),
            },
            RootAuthority {
                logical_id: RootIdAuthority::IndexedPrefixWithSuffixes {
                    prefix: "pi.project.compatibility.skills.".to_owned(),
                    suffixes: ["trusted", "declined", "unknown"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                },
                path: RootPathAuthority::ProjectAncestorRelative {
                    relative: PathBuf::from(".agents/skills"),
                    root_to_current: false,
                    ascend_without_repository: true,
                },
                scopes: BTreeSet::from([HarnessScope::Project]),
                tier: RootTier::Compatibility,
                rank: RootRankAuthority::Exact(PROJECT_COMPATIBILITY_RANK),
                layouts: both,
                evidence: trust.clone(),
            },
            RootAuthority {
                logical_id: RootIdAuthority::IndexedPrefix("pi.explicit.directory.".to_owned()),
                path: RootPathAuthority::ExplicitDirectory,
                scopes: BTreeSet::from([HarnessScope::User, HarnessScope::Project]),
                tier: RootTier::Explicit,
                rank: RootRankAuthority::Exact(EXPLICIT_RANK),
                layouts: directory,
                evidence: RootEvidenceAuthority::Exact(evidence(EXPLICIT_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::IndexedPrefixWithEncodedFile(
                    "pi.explicit.file.".to_owned(),
                ),
                path: RootPathAuthority::ExplicitFileRequest,
                scopes: BTreeSet::from([HarnessScope::User, HarnessScope::Project]),
                tier: RootTier::Explicit,
                rank: RootRankAuthority::Exact(EXPLICIT_RANK),
                layouts: standalone,
                evidence: RootEvidenceAuthority::Exact(evidence(EXPLICIT_EVIDENCE)),
            },
        ],
        related_roots: vec![
            RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::Exact(
                        RootId::parse("pi.user.native.commands").unwrap(),
                    ),
                    path: RootPathAuthority::HomeRelative(PathBuf::from(".pi/agent/prompts")),
                    scopes: BTreeSet::from([HarnessScope::User]),
                    tier: RootTier::User,
                    rank: RootRankAuthority::Exact(USER_COMMAND_RANK),
                    layouts: BTreeMap::new(),
                    evidence: RootEvidenceAuthority::Exact(evidence(COMMAND_EVIDENCE)),
                },
                kind: AssetKind::Command,
                pattern: RelatedDocumentPattern::MarkdownDirectChildren,
            },
            RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::Exact(
                        RootId::parse("pi.project.native.commands").unwrap(),
                    ),
                    path: RootPathAuthority::ProjectAncestorRelative {
                        relative: PathBuf::from(".pi/prompts"),
                        root_to_current: true,
                        ascend_without_repository: false,
                    },
                    scopes: BTreeSet::from([HarnessScope::Project]),
                    tier: RootTier::Project,
                    rank: RootRankAuthority::Exact(PROJECT_COMMAND_RANK),
                    layouts: BTreeMap::new(),
                    evidence: trust.clone(),
                },
                kind: AssetKind::Command,
                pattern: RelatedDocumentPattern::MarkdownDirectChildren,
            },
            kitrove_adapter_api::RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::Exact(
                        RootId::parse("pi.user.native.extensions").unwrap(),
                    ),
                    path: RootPathAuthority::HomeRelative(PathBuf::from(".pi/agent/extensions")),
                    scopes: BTreeSet::from([HarnessScope::User]),
                    tier: RootTier::User,
                    rank: RootRankAuthority::Exact(USER_EXTENSION_RANK),
                    layouts: BTreeMap::new(),
                    evidence: RootEvidenceAuthority::Exact(evidence(USER_EXTENSION_EVIDENCE)),
                },
                kind: kitrove_model::AssetKind::Extension,
                pattern: kitrove_adapter_api::RelatedDocumentPattern::NativeExtensionAtRoot,
            },
            kitrove_adapter_api::RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::Exact(
                        RootId::parse("pi.project.native.extensions").unwrap(),
                    ),
                    path: RootPathAuthority::ProjectAncestorRelative {
                        relative: PathBuf::from(".pi/extensions"),
                        root_to_current: true,
                        ascend_without_repository: false,
                    },
                    scopes: BTreeSet::from([HarnessScope::Project]),
                    tier: RootTier::Project,
                    rank: RootRankAuthority::Exact(PROJECT_EXTENSION_RANK),
                    layouts: BTreeMap::new(),
                    evidence: trust.clone(),
                },
                kind: kitrove_model::AssetKind::Extension,
                pattern: kitrove_adapter_api::RelatedDocumentPattern::NativeExtensionAtRoot,
            },
        ],
        receipt_anchors: vec![
            ReceiptAuthority {
                path: RootPathAuthority::HomeRelative(PathBuf::from(".pi/agent/skills")),
                scope: HarnessScope::User,
                evidence: evidence(USER_NATIVE_EVIDENCE),
            },
            ReceiptAuthority {
                path: RootPathAuthority::ProjectAncestorRelative {
                    relative: PathBuf::from(".pi/skills"),
                    root_to_current: true,
                    ascend_without_repository: false,
                },
                scope: HarnessScope::Project,
                evidence: evidence(PROJECT_NATIVE_EVIDENCE),
            },
        ],
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectTrustState {
    Trusted,
    Declined,
    Unknown,
}

struct ProjectSelection {
    anchor: PathBuf,
    trust_state: ProjectTrustState,
    trust_evidence: EvidenceRef,
}

pub(crate) fn standard_roots(context: &RootContext<'_>) -> AdapterResult<Vec<ObservedRoot>> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            roots.push(observed_root(
                "pi.user.native.skills",
                home.join(".pi/agent/skills"),
                HarnessScope::User,
                RootTier::User,
                USER_NATIVE_RANK,
                &BOTH_LAYOUTS,
                evidence(USER_NATIVE_EVIDENCE),
            ));
            roots.push(observed_root(
                "pi.user.compatibility.skills",
                home.join(".agents/skills"),
                HarnessScope::User,
                RootTier::Compatibility,
                USER_COMPATIBILITY_RANK,
                &BOTH_LAYOUTS,
                evidence(USER_COMPATIBILITY_EVIDENCE),
            ));
        }
    }

    if scope_selected(context, HarnessScope::Project) {
        if let Some(selection) = project_selection(context) {
            let state = trust_tag(selection.trust_state);
            roots.push(observed_root(
                &format!("pi.project.native.skills.{state}"),
                selection.anchor.join(".pi/skills"),
                HarnessScope::Project,
                RootTier::Project,
                PROJECT_NATIVE_RANK,
                &BOTH_LAYOUTS,
                selection.trust_evidence.clone(),
            ));
            for (index, anchor) in ancestor_anchors(context, &selection.anchor)
                .into_iter()
                .enumerate()
            {
                roots.push(observed_root(
                    &format!("pi.project.compatibility.skills.{index:04}.{state}"),
                    anchor.join(".agents/skills"),
                    HarnessScope::Project,
                    RootTier::Compatibility,
                    PROJECT_COMPATIBILITY_RANK,
                    &BOTH_LAYOUTS,
                    selection.trust_evidence.clone(),
                ));
            }
        }
    }

    // Standard roots are assembled in increasing policy rank. Retaining the first
    // no-follow path identity gives a coincident user root deterministic precedence
    // over the same path reached later through project ancestor compatibility.
    let mut seen_paths = BTreeSet::new();
    roots.retain(|root| seen_paths.insert(no_follow_path_key(&root.path)));
    Ok(roots)
}

pub(crate) fn extension_roots(context: &RootContext<'_>) -> Vec<kitrove_adapter_api::RelatedRoot> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            roots.push(kitrove_adapter_api::RelatedRoot {
                logical_id: RootId::parse("pi.user.native.extensions").unwrap(),
                path: home.join(".pi/agent/extensions"),
                scope: HarnessScope::User,
                tier: RootTier::User,
                policy_rank: USER_EXTENSION_RANK,
                kind: kitrove_model::AssetKind::Extension,
                pattern: kitrove_adapter_api::RelatedDocumentPattern::NativeExtensionAtRoot,
                evidence: evidence(USER_EXTENSION_EVIDENCE),
            });
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        if let Some(selection) = project_selection(context) {
            roots.push(kitrove_adapter_api::RelatedRoot {
                // Project trust stays in local evidence and never enters portable provenance.
                logical_id: RootId::parse("pi.project.native.extensions").unwrap(),
                path: selection.anchor.join(".pi/extensions"),
                scope: HarnessScope::Project,
                tier: RootTier::Project,
                policy_rank: PROJECT_EXTENSION_RANK,
                kind: kitrove_model::AssetKind::Extension,
                pattern: kitrove_adapter_api::RelatedDocumentPattern::NativeExtensionAtRoot,
                evidence: selection.trust_evidence,
            });
        }
    }
    roots
}

pub(crate) fn command_roots(context: &RootContext<'_>) -> Vec<RelatedRoot> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            roots.push(RelatedRoot {
                logical_id: RootId::parse("pi.user.native.commands").unwrap(),
                path: home.join(".pi/agent/prompts"),
                scope: HarnessScope::User,
                tier: RootTier::User,
                policy_rank: USER_COMMAND_RANK,
                kind: AssetKind::Command,
                pattern: RelatedDocumentPattern::MarkdownDirectChildren,
                evidence: evidence(COMMAND_EVIDENCE),
            });
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        if let Some(selection) = project_selection(context) {
            if selection.trust_state == ProjectTrustState::Trusted {
                roots.push(RelatedRoot {
                    logical_id: RootId::parse("pi.project.native.commands").unwrap(),
                    path: selection.anchor.join(".pi/prompts"),
                    scope: HarnessScope::Project,
                    tier: RootTier::Project,
                    policy_rank: PROJECT_COMMAND_RANK,
                    kind: AssetKind::Command,
                    pattern: RelatedDocumentPattern::MarkdownDirectChildren,
                    evidence: selection.trust_evidence,
                });
            }
        }
    }
    roots
}

pub(crate) fn unusual_roots(
    context: &RootContext<'_>,
    unknown: bool,
    meter: &mut dyn RootHookMeter,
) -> RootHookReport {
    let mut report = RootHookReport::default();
    if unknown {
        report.findings.push(ScanFinding::new(
            "pi.version_unknown",
            FindingSeverity::Informational,
            FindingSubject::Harness(HarnessId::Pi),
            vec![evidence(PROFILE_EVIDENCE)],
            "use the Pi Latest read-only inventory policy without making a materialization claim",
        ));
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

pub(crate) fn standard_receipt_anchors(context: &RootContext<'_>) -> Vec<ReceiptAnchor> {
    let mut anchors = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            anchors.push(ReceiptAnchor {
                scope: HarnessScope::User,
                path: home.join(".pi/agent/skills"),
                evidence: evidence(USER_NATIVE_EVIDENCE),
            });
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        if let Some(selection) = project_selection(context) {
            anchors.push(ReceiptAnchor {
                scope: HarnessScope::Project,
                path: selection.anchor.join(".pi/skills"),
                evidence: evidence(PROJECT_NATIVE_EVIDENCE),
            });
        }
    }
    anchors
}

pub(crate) fn project_trust_state(root: &ObservedRoot) -> Option<ProjectTrustState> {
    let logical = root.logical_id.as_str();
    if !logical.starts_with("pi.project.") {
        return None;
    }
    if logical.ends_with(".trusted") {
        Some(ProjectTrustState::Trusted)
    } else if logical.ends_with(".declined") {
        Some(ProjectTrustState::Declined)
    } else if logical.ends_with(".unknown") {
        Some(ProjectTrustState::Unknown)
    } else {
        None
    }
}

pub(crate) fn source_evidence(root: &ObservedRoot) -> EvidenceRef {
    match (root.scope, root.tier) {
        (HarnessScope::User, RootTier::User) => evidence(USER_NATIVE_EVIDENCE),
        (HarnessScope::User, RootTier::Compatibility) => evidence(USER_COMPATIBILITY_EVIDENCE),
        (HarnessScope::Project, RootTier::Project) => evidence(PROJECT_NATIVE_EVIDENCE),
        (HarnessScope::Project, RootTier::Compatibility) => {
            evidence(PROJECT_COMPATIBILITY_EVIDENCE)
        }
        (_, RootTier::Explicit) => evidence(EXPLICIT_EVIDENCE),
        _ => root.evidence.clone(),
    }
}

pub(crate) fn is_explicit_file_root(root: &ObservedRoot) -> bool {
    root.logical_id.as_str().starts_with("pi.explicit.file.")
}

pub(crate) fn is_explicit_directory_root(root: &ObservedRoot) -> bool {
    root.logical_id
        .as_str()
        .starts_with("pi.explicit.directory.")
}

pub(crate) fn explicit_file_name(root: &ObservedRoot) -> Option<String> {
    let encoded = root
        .logical_id
        .as_str()
        .strip_prefix("pi.explicit.file.")?
        .split_once('.')?
        .1;
    decode_hex(encoded).and_then(|bytes| String::from_utf8(bytes).ok())
}

fn append_explicit_roots(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    meter: &mut dyn RootHookMeter,
) {
    let mut matching_inputs = context
        .explicit_roots
        .iter()
        .enumerate()
        .filter(|(_, explicit)| {
            explicit.harness == HarnessId::Pi && scope_selected(context, explicit.scope)
        })
        .peekable();
    while let Some((index, explicit)) = matching_inputs.next() {
        let has_tail = matching_inputs.peek().is_some();
        if !meter.try_root_input() {
            append_explicit_exhaustion(report, context.limits.max_findings);
            break;
        }
        if !safe_absolute_path(&explicit.path) {
            if !append_explicit_issue(
                report,
                context.limits.max_findings,
                has_tail,
                "scan.discovery_unsafe_path",
                "supply an absolute local Pi source path without traversal components",
            ) {
                break;
            }
            continue;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&explicit.path) else {
            if !append_explicit_issue(
                report,
                context.limits.max_findings,
                has_tail,
                "scan.discovery_unsafe_path",
                "supply a readable regular Pi skill directory or Markdown file",
            ) {
                break;
            }
            continue;
        };
        if metadata.file_type().is_symlink() {
            if !append_explicit_issue(
                report,
                context.limits.max_findings,
                has_tail,
                "scan.discovery_unsafe_path",
                "replace the explicit Pi source link with a regular local path",
            ) {
                break;
            }
            continue;
        }
        if metadata.is_dir() {
            report.roots.push(observed_root(
                &format!("pi.explicit.directory.{index:04}"),
                explicit.path.clone(),
                explicit.scope,
                RootTier::Explicit,
                EXPLICIT_RANK,
                &DIRECTORY_LAYOUTS,
                evidence(EXPLICIT_EVIDENCE),
            ));
            continue;
        }
        if !metadata.is_file() {
            if !append_explicit_issue(
                report,
                context.limits.max_findings,
                has_tail,
                "scan.discovery_unsafe_path",
                "supply a regular Pi skill directory or Markdown file",
            ) {
                break;
            }
            continue;
        }
        let Some(file_name) = explicit.path.file_name().and_then(|name| name.to_str()) else {
            if !append_explicit_issue(
                report,
                context.limits.max_findings,
                has_tail,
                "scan.discovery_unsafe_path",
                "rename the explicit Pi standalone source using valid UTF-8",
            ) {
                break;
            }
            continue;
        };
        if !file_name.ends_with(".md") {
            if !append_explicit_issue(
                report,
                context.limits.max_findings,
                has_tail,
                "scan.layout_unsupported",
                "supply a Pi standalone skill as a Markdown file",
            ) {
                break;
            }
            continue;
        }
        let encoded = encode_hex(file_name.as_bytes());
        let logical = format!("pi.explicit.file.{index:04}.{encoded}");
        let Ok(logical_id) = RootId::parse(logical) else {
            if !append_explicit_issue(
                report,
                context.limits.max_findings,
                has_tail,
                "pi.explicit_identity_too_long",
                "shorten the explicit Pi standalone file name",
            ) {
                break;
            }
            continue;
        };
        let Some(parent) = explicit.path.parent() else {
            if !append_explicit_issue(
                report,
                context.limits.max_findings,
                has_tail,
                "scan.discovery_unsafe_path",
                "supply a Pi standalone source with a regular parent directory",
            ) {
                break;
            }
            continue;
        };
        report.roots.push(ObservedRoot {
            logical_id,
            path: parent.to_path_buf(),
            scope: explicit.scope,
            tier: RootTier::Explicit,
            policy_rank: EXPLICIT_RANK,
            enabled_layouts: BTreeSet::from(STANDALONE_LAYOUTS),
            evidence: evidence(EXPLICIT_EVIDENCE),
        });
    }
}

fn append_explicit_issue(
    report: &mut RootHookReport,
    max_findings: usize,
    has_tail: bool,
    code: &'static str,
    action: &'static str,
) -> bool {
    let remaining = max_findings.saturating_sub(report.findings.len());
    if remaining == 0 || (has_tail && remaining == 1) {
        append_explicit_exhaustion(report, max_findings);
        return false;
    }
    report.findings.push(explicit_finding(code, action));
    true
}

fn append_explicit_exhaustion(report: &mut RootHookReport, max_findings: usize) {
    if report.findings.len() < max_findings
        && !report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.root_budget_exhausted")
    {
        report.findings.push(explicit_finding(
            "scan.root_budget_exhausted",
            "reduce supplied Pi explicit roots or increase the request root or finding limit",
        ));
    }
}

fn project_selection(context: &RootContext<'_>) -> Option<ProjectSelection> {
    let anchor = match context.project_boundary {
        ProjectBoundary::Repository { root } if context.working_directory.starts_with(root) => {
            root.clone()
        }
        ProjectBoundary::Repository { .. } => return None,
        ProjectBoundary::NoRepository | ProjectBoundary::UnsafeStop => {
            context.working_directory.to_path_buf()
        }
    };
    let key = ProjectTrustKey {
        harness: HarnessId::Pi,
        project_anchor: anchor.clone(),
    };
    let (trust_state, trust_evidence) = match context.project_trust.get(&key) {
        Some(ProjectTrustObservation::Trusted { evidence }) => {
            (ProjectTrustState::Trusted, evidence.clone())
        }
        Some(ProjectTrustObservation::Declined { evidence }) => {
            (ProjectTrustState::Declined, evidence.clone())
        }
        Some(ProjectTrustObservation::Unknown) | None => (
            ProjectTrustState::Unknown,
            evidence(PROJECT_TRUST_UNKNOWN_EVIDENCE),
        ),
    };
    Some(ProjectSelection {
        anchor,
        trust_state,
        trust_evidence,
    })
}

fn ancestor_anchors(context: &RootContext<'_>, project_anchor: &Path) -> Vec<PathBuf> {
    let stop = match context.project_boundary {
        ProjectBoundary::Repository { .. } => project_anchor,
        ProjectBoundary::NoRepository => context
            .working_directory
            .ancestors()
            .last()
            .unwrap_or(project_anchor),
        ProjectBoundary::UnsafeStop => project_anchor,
    };
    let mut anchors = Vec::new();
    let mut current = context.working_directory;
    loop {
        anchors.push(current.to_path_buf());
        if current == stop {
            break;
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    anchors
}

fn observed_root(
    logical_id: &str,
    path: PathBuf,
    scope: HarnessScope,
    tier: RootTier,
    policy_rank: u32,
    layouts: &[SkillSourceLayout],
    evidence_ref: EvidenceRef,
) -> ObservedRoot {
    ObservedRoot {
        logical_id: RootId::parse(logical_id).expect("compiled Pi root IDs are valid"),
        path,
        scope,
        tier,
        policy_rank,
        enabled_layouts: layouts.iter().copied().collect(),
        evidence: evidence_ref,
    }
}

fn trust_tag(state: ProjectTrustState) -> &'static str {
    match state {
        ProjectTrustState::Trusted => "trusted",
        ProjectTrustState::Declined => "declined",
        ProjectTrustState::Unknown => "unknown",
    }
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

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !raw_parent_component(path)
        && !path
            .components()
            .any(|component| {
                matches!(component, Component::ParentDir | Component::CurDir)
                    || matches!(component, Component::Normal(value) if value == OsStr::new(".") || value == OsStr::new(".."))
            })
}

#[cfg(windows)]
fn raw_parent_component(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|segment| segment == "..")
}

#[cfg(not(windows))]
const fn raw_parent_component(_path: &Path) -> bool {
    false
}

fn no_follow_path_key(path: &Path) -> PathBuf {
    let mut key = PathBuf::new();
    for component in path.components() {
        key.push(component.as_os_str());
    }
    key
}

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).expect("compiled Pi evidence references are valid")
}

fn explicit_finding(code: &'static str, action: &'static str) -> ScanFinding {
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Harness(HarnessId::Pi),
        vec![evidence(EXPLICIT_EVIDENCE)],
        action,
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
