use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use kitrove_adapter_api::{
    AdapterResult, EvidenceRef, FindingSeverity, FindingSubject, NativeRootKey, ObservedRoot,
    PolicyLine, PolicyRuntimeAuthority, ProjectBoundary, ReceiptAnchor, ReceiptAuthority,
    RelatedDocumentPattern, RelatedRoot, RelatedRootAuthority, RootAuthority, RootContext,
    RootEvidenceAuthority, RootHookMeter, RootHookReport, RootId, RootIdAuthority,
    RootPathAuthority, RootRankAuthority, RootTier, ScanFinding,
};
use kitrove_agent_skills::SkillSourceLayout;
use kitrove_model::{AssetKind, HarnessId, HarnessScope};

pub(crate) const CURRENT_PROFILE_EVIDENCE: &str = "opencode.docs.skills.current";
pub(crate) const V2_PROFILE_EVIDENCE: &str = "opencode.v2.docs.skills";
pub(crate) const USER_NATIVE_EVIDENCE: &str = "opencode.docs.skills.user-native";
pub(crate) const PROJECT_NATIVE_EVIDENCE: &str = "opencode.docs.skills.project-native";
pub(crate) const CLAUDE_COMPATIBILITY_EVIDENCE: &str = "opencode.docs.skills.claude-compatibility";
pub(crate) const AGENT_COMPATIBILITY_EVIDENCE: &str = "opencode.docs.skills.agent-compatibility";
pub(crate) const BUILT_IN_EVIDENCE: &str = "opencode.v2.docs.skills.built-in";
pub(crate) const EXPLICIT_EVIDENCE: &str = "opencode.v2.docs.skills.explicit";
pub(crate) const CURRENT_DUPLICATE_EVIDENCE: &str = "opencode.docs.skills.unique-names";
pub(crate) const V2_PRECEDENCE_EVIDENCE: &str = "opencode.v2.docs.skills.precedence";
pub(crate) const COMMAND_EVIDENCE: &str = "opencode.v2.docs.commands.markdown";
pub(crate) const AGENT_EVIDENCE: &str = "opencode.docs.agents.current";

pub(crate) const BUILT_IN_RANK: u32 = 10;
const CLAUDE_GLOBAL_RANK: u32 = 100_000;
const CLAUDE_PROJECT_RANK: u32 = 110_000;
const AGENT_GLOBAL_RANK: u32 = 200_000;
const AGENT_PROJECT_RANK: u32 = 210_000;
const USER_NATIVE_RANK: u32 = 300_000;
const PROJECT_NATIVE_RANK: u32 = 400_000;
pub(crate) const EXPLICIT_RANK: u32 = 500_000;

const BUILT_IN_KEY: &str = "opencode-v2.built-in";
const BUILT_IN_SCOPE_FINDING: &str = "opencode.built_in_scope_unsupported";
const DIRECTORY_LAYOUTS: [SkillSourceLayout; 1] = [SkillSourceLayout::Directory];
const BOTH_LAYOUTS: [SkillSourceLayout; 2] =
    [SkillSourceLayout::Directory, SkillSourceLayout::Standalone];

#[derive(Clone, Copy)]
struct NativeRootDescriptor {
    key: &'static str,
    tier: RootTier,
    policy_rank: u32,
    allowed_scopes: &'static [HarnessScope],
    evidence: &'static str,
    scope_finding: &'static str,
}

const BUILT_IN_DESCRIPTOR: NativeRootDescriptor = NativeRootDescriptor {
    key: BUILT_IN_KEY,
    tier: RootTier::System,
    policy_rank: BUILT_IN_RANK,
    allowed_scopes: &[HarnessScope::User],
    evidence: BUILT_IN_EVIDENCE,
    scope_finding: BUILT_IN_SCOPE_FINDING,
};

pub(crate) fn runtime_authority() -> PolicyRuntimeAuthority {
    let standard_layouts = BTreeMap::from([
        (
            PolicyLine::OpenCodeCurrent,
            BTreeSet::from([SkillSourceLayout::Directory]),
        ),
        (PolicyLine::OpenCodeV2, BOTH_LAYOUTS.into_iter().collect()),
    ]);
    let v2_layouts = BTreeMap::from([(PolicyLine::OpenCodeV2, BOTH_LAYOUTS.into_iter().collect())]);
    let explicit_layouts = BTreeMap::from([
        (
            PolicyLine::OpenCodeCurrent,
            DIRECTORY_LAYOUTS.into_iter().collect(),
        ),
        (PolicyLine::OpenCodeV2, BOTH_LAYOUTS.into_iter().collect()),
    ]);
    let project_rule = |relative: &str| RootPathAuthority::ProjectAncestorRelative {
        relative: PathBuf::from(relative),
        root_to_current: true,
        ascend_without_repository: false,
    };
    PolicyRuntimeAuthority {
        roots: vec![
            RootAuthority {
                logical_id: RootIdAuthority::Exact(
                    RootId::parse("opencode.user.claude.skills").unwrap(),
                ),
                path: RootPathAuthority::HomeRelative(PathBuf::from(".claude/skills")),
                scopes: BTreeSet::from([HarnessScope::User]),
                tier: RootTier::Compatibility,
                rank: RootRankAuthority::Exact(CLAUDE_GLOBAL_RANK),
                layouts: standard_layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(CLAUDE_COMPATIBILITY_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::IndexedPrefix(
                    "opencode.project.claude.skills.".to_owned(),
                ),
                path: project_rule(".claude/skills"),
                scopes: BTreeSet::from([HarnessScope::Project]),
                tier: RootTier::Compatibility,
                rank: RootRankAuthority::Indexed {
                    base: CLAUDE_PROJECT_RANK,
                },
                layouts: standard_layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(CLAUDE_COMPATIBILITY_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::Exact(
                    RootId::parse("opencode.user.agents.skills").unwrap(),
                ),
                path: RootPathAuthority::HomeRelative(PathBuf::from(".agents/skills")),
                scopes: BTreeSet::from([HarnessScope::User]),
                tier: RootTier::Compatibility,
                rank: RootRankAuthority::Exact(AGENT_GLOBAL_RANK),
                layouts: standard_layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(AGENT_COMPATIBILITY_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::IndexedPrefix(
                    "opencode.project.agents.skills.".to_owned(),
                ),
                path: project_rule(".agents/skills"),
                scopes: BTreeSet::from([HarnessScope::Project]),
                tier: RootTier::Compatibility,
                rank: RootRankAuthority::Indexed {
                    base: AGENT_PROJECT_RANK,
                },
                layouts: standard_layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(AGENT_COMPATIBILITY_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::Exact(
                    RootId::parse("opencode.user.native.skills").unwrap(),
                ),
                path: RootPathAuthority::HomeRelative(PathBuf::from(".config/opencode/skills")),
                scopes: BTreeSet::from([HarnessScope::User]),
                tier: RootTier::User,
                rank: RootRankAuthority::Exact(USER_NATIVE_RANK),
                layouts: standard_layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(USER_NATIVE_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::IndexedPrefix(
                    "opencode.project.native.skills.".to_owned(),
                ),
                path: project_rule(".opencode/skills"),
                scopes: BTreeSet::from([HarnessScope::Project]),
                tier: RootTier::Project,
                rank: RootRankAuthority::Indexed {
                    base: PROJECT_NATIVE_RANK,
                },
                layouts: standard_layouts,
                evidence: RootEvidenceAuthority::Exact(evidence(PROJECT_NATIVE_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::Exact(
                    RootId::parse("opencode.system.built-in").unwrap(),
                ),
                path: RootPathAuthority::SuppliedNative(
                    NativeRootKey::parse(BUILT_IN_KEY).unwrap(),
                ),
                scopes: BTreeSet::from([HarnessScope::User]),
                tier: RootTier::System,
                rank: RootRankAuthority::Exact(BUILT_IN_RANK),
                layouts: v2_layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(BUILT_IN_EVIDENCE)),
            },
            RootAuthority {
                logical_id: RootIdAuthority::IndexedPrefix("opencode.explicit.".to_owned()),
                path: RootPathAuthority::ExplicitDirectory,
                scopes: BTreeSet::from([HarnessScope::User, HarnessScope::Project]),
                tier: RootTier::Explicit,
                rank: RootRankAuthority::Indexed {
                    base: EXPLICIT_RANK,
                },
                layouts: explicit_layouts,
                evidence: RootEvidenceAuthority::Exact(evidence(EXPLICIT_EVIDENCE)),
            },
        ],
        related_roots: vec![
            RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::Exact(
                        RootId::parse("opencode.user.native.agents").unwrap(),
                    ),
                    path: RootPathAuthority::HomeRelative(PathBuf::from(".config/opencode/agents")),
                    scopes: BTreeSet::from([HarnessScope::User]),
                    tier: RootTier::User,
                    rank: RootRankAuthority::Exact(USER_NATIVE_RANK),
                    layouts: BTreeMap::new(),
                    evidence: RootEvidenceAuthority::Exact(evidence(AGENT_EVIDENCE)),
                },
                kind: AssetKind::Agent,
                pattern: RelatedDocumentPattern::MarkdownDirectChildren,
            },
            RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::IndexedPrefix(
                        "opencode.project.native.agents.".to_owned(),
                    ),
                    path: project_rule(".opencode/agents"),
                    scopes: BTreeSet::from([HarnessScope::Project]),
                    tier: RootTier::Project,
                    rank: RootRankAuthority::Indexed {
                        base: PROJECT_NATIVE_RANK,
                    },
                    layouts: BTreeMap::new(),
                    evidence: RootEvidenceAuthority::Exact(evidence(AGENT_EVIDENCE)),
                },
                kind: AssetKind::Agent,
                pattern: RelatedDocumentPattern::MarkdownDirectChildren,
            },
            RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::Exact(
                        RootId::parse("opencode.user.native.commands").unwrap(),
                    ),
                    path: RootPathAuthority::HomeRelative(PathBuf::from(
                        ".config/opencode/commands",
                    )),
                    scopes: BTreeSet::from([HarnessScope::User]),
                    tier: RootTier::User,
                    rank: RootRankAuthority::Exact(USER_NATIVE_RANK),
                    layouts: BTreeMap::new(),
                    evidence: RootEvidenceAuthority::Exact(evidence(COMMAND_EVIDENCE)),
                },
                kind: AssetKind::Command,
                pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
            },
            RelatedRootAuthority {
                root: RootAuthority {
                    logical_id: RootIdAuthority::IndexedPrefix(
                        "opencode.project.native.commands.".to_owned(),
                    ),
                    path: project_rule(".opencode/commands"),
                    scopes: BTreeSet::from([HarnessScope::Project]),
                    tier: RootTier::Project,
                    rank: RootRankAuthority::Indexed {
                        base: PROJECT_NATIVE_RANK,
                    },
                    layouts: BTreeMap::new(),
                    evidence: RootEvidenceAuthority::Exact(evidence(COMMAND_EVIDENCE)),
                },
                kind: AssetKind::Command,
                pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
            },
        ],
        receipt_anchors: vec![
            ReceiptAuthority {
                path: RootPathAuthority::HomeRelative(PathBuf::from(".config/opencode/skills")),
                scope: HarnessScope::User,
                evidence: evidence(USER_NATIVE_EVIDENCE),
            },
            ReceiptAuthority {
                path: RootPathAuthority::ProjectAncestorRelative {
                    relative: PathBuf::from(".opencode/skills"),
                    root_to_current: true,
                    ascend_without_repository: false,
                },
                scope: HarnessScope::Project,
                evidence: evidence(PROJECT_NATIVE_EVIDENCE),
            },
        ],
    }
}

pub(crate) fn command_roots(context: &RootContext<'_>) -> Vec<RelatedRoot> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            roots.push(RelatedRoot {
                logical_id: RootId::parse("opencode.user.native.commands").unwrap(),
                path: home.join(".config/opencode/commands"),
                scope: HarnessScope::User,
                tier: RootTier::User,
                policy_rank: USER_NATIVE_RANK,
                kind: AssetKind::Command,
                pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
                evidence: evidence(COMMAND_EVIDENCE),
            });
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        for (index, anchor) in project_anchors_root_to_current(context)
            .into_iter()
            .enumerate()
        {
            roots.push(RelatedRoot {
                logical_id: RootId::parse(format!("opencode.project.native.commands.{index:04}"))
                    .unwrap(),
                path: anchor.join(".opencode/commands"),
                scope: HarnessScope::Project,
                tier: RootTier::Project,
                policy_rank: indexed_rank(PROJECT_NATIVE_RANK, index),
                kind: AssetKind::Command,
                pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
                evidence: evidence(COMMAND_EVIDENCE),
            });
        }
    }
    roots
}

pub(crate) fn agent_roots(context: &RootContext<'_>) -> Vec<RelatedRoot> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            roots.push(RelatedRoot {
                logical_id: RootId::parse("opencode.user.native.agents").unwrap(),
                path: home.join(".config/opencode/agents"),
                scope: HarnessScope::User,
                tier: RootTier::User,
                policy_rank: USER_NATIVE_RANK,
                kind: AssetKind::Agent,
                pattern: RelatedDocumentPattern::MarkdownDirectChildren,
                evidence: evidence(AGENT_EVIDENCE),
            });
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        for (index, anchor) in project_anchors_root_to_current(context)
            .into_iter()
            .enumerate()
        {
            roots.push(RelatedRoot {
                logical_id: RootId::parse(format!("opencode.project.native.agents.{index:04}"))
                    .unwrap(),
                path: anchor.join(".opencode/agents"),
                scope: HarnessScope::Project,
                tier: RootTier::Project,
                policy_rank: indexed_rank(PROJECT_NATIVE_RANK, index),
                kind: AssetKind::Agent,
                pattern: RelatedDocumentPattern::MarkdownDirectChildren,
                evidence: evidence(AGENT_EVIDENCE),
            });
        }
    }
    roots
}

pub(crate) fn standard_roots(
    context: &RootContext<'_>,
    profile_line: PolicyLine,
) -> AdapterResult<Vec<ObservedRoot>> {
    let layouts = layouts(profile_line);
    let mut roots = Vec::new();
    let mut seen_paths = BTreeSet::new();
    let project_anchors = project_anchors_root_to_current(context);

    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            push_unique(
                &mut roots,
                &mut seen_paths,
                observed_root(
                    "opencode.user.claude.skills",
                    home.join(".claude/skills"),
                    HarnessScope::User,
                    RootTier::Compatibility,
                    CLAUDE_GLOBAL_RANK,
                    layouts,
                    CLAUDE_COMPATIBILITY_EVIDENCE,
                ),
            );
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        for (index, anchor) in project_anchors.iter().enumerate() {
            push_unique(
                &mut roots,
                &mut seen_paths,
                observed_root(
                    &format!("opencode.project.claude.skills.{index:04}"),
                    anchor.join(".claude/skills"),
                    HarnessScope::Project,
                    RootTier::Compatibility,
                    indexed_rank(CLAUDE_PROJECT_RANK, index),
                    layouts,
                    CLAUDE_COMPATIBILITY_EVIDENCE,
                ),
            );
        }
    }

    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            push_unique(
                &mut roots,
                &mut seen_paths,
                observed_root(
                    "opencode.user.agents.skills",
                    home.join(".agents/skills"),
                    HarnessScope::User,
                    RootTier::Compatibility,
                    AGENT_GLOBAL_RANK,
                    layouts,
                    AGENT_COMPATIBILITY_EVIDENCE,
                ),
            );
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        for (index, anchor) in project_anchors.iter().enumerate() {
            push_unique(
                &mut roots,
                &mut seen_paths,
                observed_root(
                    &format!("opencode.project.agents.skills.{index:04}"),
                    anchor.join(".agents/skills"),
                    HarnessScope::Project,
                    RootTier::Compatibility,
                    indexed_rank(AGENT_PROJECT_RANK, index),
                    layouts,
                    AGENT_COMPATIBILITY_EVIDENCE,
                ),
            );
        }
    }

    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            push_unique(
                &mut roots,
                &mut seen_paths,
                observed_root(
                    "opencode.user.native.skills",
                    home.join(".config/opencode/skills"),
                    HarnessScope::User,
                    RootTier::User,
                    USER_NATIVE_RANK,
                    layouts,
                    USER_NATIVE_EVIDENCE,
                ),
            );
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        for (index, anchor) in project_anchors.iter().enumerate() {
            push_unique(
                &mut roots,
                &mut seen_paths,
                observed_root(
                    &format!("opencode.project.native.skills.{index:04}"),
                    anchor.join(".opencode/skills"),
                    HarnessScope::Project,
                    RootTier::Project,
                    indexed_rank(PROJECT_NATIVE_RANK, index),
                    layouts,
                    PROJECT_NATIVE_EVIDENCE,
                ),
            );
        }
    }
    if profile_line == PolicyLine::OpenCodeV2 {
        promote_coincident_explicit_roots(context, &mut roots);
    }
    Ok(roots)
}

pub(crate) fn unusual_roots(
    context: &RootContext<'_>,
    profile_line: PolicyLine,
    unknown: bool,
    meter: &mut dyn RootHookMeter,
) -> RootHookReport {
    let mut report = RootHookReport::default();
    if unknown {
        push_finding(
            &mut report,
            context.limits.max_findings,
            harness_finding(
                "opencode.version_unknown",
                FindingSeverity::Informational,
                CURRENT_PROFILE_EVIDENCE,
                "use the conservative current OpenCode directory policy without accepting V2-only layouts",
            ),
        );
    }

    let mut seen_paths = standard_roots(context, profile_line)
        .unwrap_or_default()
        .into_iter()
        .map(|root| no_follow_path_key(&root.path))
        .collect::<BTreeSet<_>>();
    let mut remaining_inputs = context.limits.max_roots.saturating_sub(seen_paths.len());
    let continue_inputs = if profile_line == PolicyLine::OpenCodeV2 {
        append_built_in_roots(
            context,
            &mut report,
            &mut seen_paths,
            &mut remaining_inputs,
            meter,
        )
    } else {
        let mut matching = context
            .supplied_native_roots
            .iter()
            .filter(|supplied| supplied.harness() == &HarnessId::OpenCode)
            .peekable();
        let mut continue_inputs = true;
        while let Some(_supplied) = matching.next() {
            if remaining_inputs == 0 || !meter.try_root_input() {
                push_root_exhaustion(context, &mut report, CURRENT_PROFILE_EVIDENCE);
                continue_inputs = false;
                break;
            }
            remaining_inputs = remaining_inputs.saturating_sub(1);
            if !append_input_issue(
                context,
                &mut report,
                matching.peek().is_some(),
                CURRENT_PROFILE_EVIDENCE,
                harness_finding(
                    "opencode.native_root_profile_unsupported",
                    FindingSeverity::Attention,
                    CURRENT_PROFILE_EVIDENCE,
                    "select verified OpenCode V2 evidence before using supplied native roots",
                ),
            ) {
                continue_inputs = false;
                break;
            }
        }
        continue_inputs
    };
    if continue_inputs {
        append_explicit_roots(
            context,
            &mut report,
            &mut seen_paths,
            &mut remaining_inputs,
            profile_line,
            meter,
        );
    }

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
                path: home.join(".config/opencode/skills"),
                evidence: evidence(USER_NATIVE_EVIDENCE),
            });
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        if let Some(anchor) = project_anchors_root_to_current(context).first() {
            anchors.push(ReceiptAnchor {
                scope: HarnessScope::Project,
                path: anchor.join(".opencode/skills"),
                evidence: evidence(PROJECT_NATIVE_EVIDENCE),
            });
        }
    }
    anchors
}

fn append_built_in_roots(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    seen_paths: &mut BTreeSet<PathBuf>,
    remaining_inputs: &mut usize,
    meter: &mut dyn RootHookMeter,
) -> bool {
    if !scope_selected(context, HarnessScope::User) {
        return true;
    }
    let mut providers = BTreeMap::new();
    let explicit_tail = context.explicit_roots.iter().any(|explicit| {
        explicit.harness == HarnessId::OpenCode && scope_selected(context, explicit.scope)
    });
    let mut matching = context
        .supplied_native_roots
        .iter()
        .filter(|supplied| supplied.harness() == &HarnessId::OpenCode)
        .peekable();
    let mut continue_inputs = true;
    while let Some(supplied) = matching.next() {
        let has_tail = matching.peek().is_some() || explicit_tail;
        if *remaining_inputs == 0 || !meter.try_root_input() {
            push_root_exhaustion(context, report, V2_PROFILE_EVIDENCE);
            continue_inputs = false;
            break;
        }
        *remaining_inputs = remaining_inputs.saturating_sub(1);
        let Some(descriptor) = descriptor(supplied.source_key()) else {
            if !append_input_issue(
                context,
                report,
                has_tail,
                V2_PROFILE_EVIDENCE,
                harness_finding(
                    "opencode.native_root_unknown",
                    FindingSeverity::Attention,
                    BUILT_IN_EVIDENCE,
                    "select the compiled opencode-v2.built-in native-root descriptor",
                ),
            ) {
                continue_inputs = false;
                break;
            }
            continue;
        };
        if !descriptor.allowed_scopes.contains(&supplied.scope()) {
            if !append_input_issue(
                context,
                report,
                has_tail,
                V2_PROFILE_EVIDENCE,
                harness_finding(
                    descriptor.scope_finding,
                    FindingSeverity::Attention,
                    descriptor.evidence,
                    "select user scope for the OpenCode V2 built-in provider",
                ),
            ) {
                continue_inputs = false;
                break;
            }
            continue;
        }
        if !safe_local_directory(supplied.path()) {
            if !append_input_issue(
                context,
                report,
                has_tail,
                V2_PROFILE_EVIDENCE,
                harness_finding(
                    "scan.discovery_unsafe_path",
                    FindingSeverity::Attention,
                    descriptor.evidence,
                    "supply an absolute regular local directory for the OpenCode V2 built-in provider",
                ),
            ) {
                continue_inputs = false;
                break;
            }
            continue;
        }
        let key = no_follow_path_key(supplied.path());
        providers
            .entry(key)
            .or_insert_with(|| (supplied.path().to_path_buf(), supplied.scope()));
        if providers.len() > 1 {
            push_finding(
                report,
                context.limits.max_findings,
                harness_finding(
                    "opencode.built_in_provider_ambiguous",
                    FindingSeverity::Attention,
                    BUILT_IN_EVIDENCE,
                    "supply exactly one physical OpenCode V2 built-in skills provider",
                ),
            );
            break;
        }
    }
    if providers.len() == 1 {
        let (key, (path, scope)) = providers
            .into_iter()
            .next()
            .expect("a single built-in provider has one member");
        if seen_paths.insert(key) {
            report.roots.push(observed_root(
                "opencode.system.built-in",
                path,
                scope,
                BUILT_IN_DESCRIPTOR.tier,
                BUILT_IN_DESCRIPTOR.policy_rank,
                &BOTH_LAYOUTS,
                BUILT_IN_DESCRIPTOR.evidence,
            ));
        }
    } else if providers.is_empty() {
        push_finding(
            report,
            context.limits.max_findings,
            ScanFinding::new(
                "scan.root_unresolved",
                FindingSeverity::Informational,
                FindingSubject::Root(
                    RootId::parse("opencode.system.built-in")
                        .expect("compiled OpenCode built-in root ID is valid"),
                ),
                vec![evidence(BUILT_IN_EVIDENCE)],
                "supply the OpenCode V2 built-in skills provider through opencode-v2.built-in",
            ),
        );
    }
    continue_inputs
}

fn append_explicit_roots(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    seen_paths: &mut BTreeSet<PathBuf>,
    remaining_inputs: &mut usize,
    profile_line: PolicyLine,
    meter: &mut dyn RootHookMeter,
) {
    let profile_evidence = match profile_line {
        PolicyLine::OpenCodeCurrent => CURRENT_PROFILE_EVIDENCE,
        PolicyLine::OpenCodeV2 => V2_PROFILE_EVIDENCE,
        _ => CURRENT_PROFILE_EVIDENCE,
    };
    let mut matching = context
        .explicit_roots
        .iter()
        .enumerate()
        .filter(|(_, explicit)| {
            explicit.harness == HarnessId::OpenCode && scope_selected(context, explicit.scope)
        })
        .peekable();
    while let Some((index, explicit)) = matching.next() {
        let has_tail = matching.peek().is_some();
        if *remaining_inputs == 0 || !meter.try_root_input() {
            push_root_exhaustion(context, report, profile_evidence);
            break;
        }
        *remaining_inputs = remaining_inputs.saturating_sub(1);
        if !safe_local_directory(&explicit.path) {
            if !append_input_issue(
                context,
                report,
                has_tail,
                profile_evidence,
                harness_finding(
                    "scan.discovery_unsafe_path",
                    FindingSeverity::Attention,
                    EXPLICIT_EVIDENCE,
                    "supply an absolute regular local directory instead of a file or remote catalog",
                ),
            ) {
                break;
            }
            continue;
        }
        let key = no_follow_path_key(&explicit.path);
        if !seen_paths.insert(key.clone()) {
            if let Some(root) = report
                .roots
                .iter_mut()
                .find(|root| no_follow_path_key(&root.path) == key)
            {
                *root = observed_root(
                    &format!("opencode.explicit.{index:04}"),
                    explicit.path.clone(),
                    explicit.scope,
                    RootTier::Explicit,
                    indexed_rank(EXPLICIT_RANK, index),
                    layouts(profile_line),
                    EXPLICIT_EVIDENCE,
                );
            }
            continue;
        }
        report.roots.push(observed_root(
            &format!("opencode.explicit.{index:04}"),
            explicit.path.clone(),
            explicit.scope,
            RootTier::Explicit,
            indexed_rank(EXPLICIT_RANK, index),
            layouts(profile_line),
            EXPLICIT_EVIDENCE,
        ));
    }
}

fn promote_coincident_explicit_roots(context: &RootContext<'_>, roots: &mut [ObservedRoot]) {
    let mut remaining_inputs = context.limits.max_roots.saturating_sub(roots.len());
    if scope_selected(context, HarnessScope::User) {
        let mut providers = BTreeSet::new();
        for supplied in context
            .supplied_native_roots
            .iter()
            .filter(|supplied| supplied.harness() == &HarnessId::OpenCode)
        {
            if remaining_inputs == 0 {
                return;
            }
            remaining_inputs = remaining_inputs.saturating_sub(1);
            if descriptor(supplied.source_key()).is_some_and(|descriptor| {
                descriptor.allowed_scopes.contains(&supplied.scope())
                    && supplied.path().is_absolute()
            }) {
                providers.insert(no_follow_path_key(supplied.path()));
                if providers.len() > 1 {
                    break;
                }
            }
        }
    }
    for (index, explicit) in context
        .explicit_roots
        .iter()
        .enumerate()
        .filter(|(_, explicit)| {
            explicit.harness == HarnessId::OpenCode && scope_selected(context, explicit.scope)
        })
    {
        if remaining_inputs == 0 {
            break;
        }
        remaining_inputs = remaining_inputs.saturating_sub(1);
        let key = no_follow_path_key(&explicit.path);
        let Some(root) = roots
            .iter_mut()
            .find(|root| no_follow_path_key(&root.path) == key)
        else {
            continue;
        };
        *root = observed_root(
            &format!("opencode.explicit.{index:04}"),
            explicit.path.clone(),
            explicit.scope,
            RootTier::Explicit,
            indexed_rank(EXPLICIT_RANK, index),
            &BOTH_LAYOUTS,
            EXPLICIT_EVIDENCE,
        );
    }
}

fn append_input_issue(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    has_tail: bool,
    exhaustion_evidence: &str,
    finding: ScanFinding,
) -> bool {
    let remaining_findings = context
        .limits
        .max_findings
        .saturating_sub(report.findings.len());
    if remaining_findings == 0 {
        if has_tail {
            push_root_exhaustion(context, report, exhaustion_evidence);
        }
        return false;
    }
    if has_tail && remaining_findings == 1 {
        push_root_exhaustion(context, report, exhaustion_evidence);
        return false;
    }
    report.findings.push(finding);
    true
}

fn project_anchors_root_to_current(context: &RootContext<'_>) -> Vec<PathBuf> {
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
                    return vec![];
                };
                current = parent;
            }
            anchors.reverse();
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
    layouts: &[SkillSourceLayout],
    evidence_ref: &str,
) -> ObservedRoot {
    ObservedRoot {
        logical_id: RootId::parse(logical_id).expect("compiled OpenCode root IDs are valid"),
        path,
        scope,
        tier,
        policy_rank,
        enabled_layouts: layouts.iter().copied().collect(),
        evidence: evidence(evidence_ref),
    }
}

fn push_unique(
    roots: &mut Vec<ObservedRoot>,
    seen_paths: &mut BTreeSet<PathBuf>,
    root: ObservedRoot,
) {
    if seen_paths.insert(no_follow_path_key(&root.path)) {
        roots.push(root);
    }
}

fn layouts(line: PolicyLine) -> &'static [SkillSourceLayout] {
    match line {
        PolicyLine::OpenCodeV2 => &BOTH_LAYOUTS,
        PolicyLine::OpenCodeCurrent => &DIRECTORY_LAYOUTS,
        _ => unreachable!("OpenCode policy only selects OpenCode lines"),
    }
}

fn descriptor(key: &NativeRootKey) -> Option<NativeRootDescriptor> {
    (key.as_str() == BUILT_IN_DESCRIPTOR.key).then_some(BUILT_IN_DESCRIPTOR)
}

fn indexed_rank(base: u32, index: usize) -> u32 {
    base.saturating_add(u32::try_from(index).unwrap_or(u32::MAX))
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

fn safe_local_directory(path: &Path) -> bool {
    if !path.is_absolute()
        || raw_parent_component(path)
        || path
            .components()
            .any(|component| {
                matches!(component, Component::ParentDir | Component::CurDir)
                    || matches!(component, Component::Normal(value) if value == OsStr::new(".") || value == OsStr::new(".."))
            })
    {
        return false;
    }
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && !metadata_is_windows_reparse(&metadata)
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

#[cfg(windows)]
fn metadata_is_windows_reparse(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn metadata_is_windows_reparse(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn push_root_exhaustion(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    evidence_ref: &str,
) {
    if !report
        .findings
        .iter()
        .any(|finding| finding.code == "scan.root_budget_exhausted")
    {
        let finding = harness_finding(
            "scan.root_budget_exhausted",
            FindingSeverity::Attention,
            evidence_ref,
            "reduce supplied OpenCode roots or increase the request root limit",
        );
        if report.findings.len() < context.limits.max_findings {
            report.findings.push(finding);
        } else if context.limits.max_findings > 0 {
            *report
                .findings
                .last_mut()
                .expect("a full positive finding budget has a retained finding") = finding;
        }
    }
}

fn push_finding(report: &mut RootHookReport, max_findings: usize, finding: ScanFinding) {
    if report.findings.len() < max_findings {
        report.findings.push(finding);
    }
}

fn harness_finding(
    code: &'static str,
    severity: FindingSeverity,
    evidence_ref: &str,
    action: &'static str,
) -> ScanFinding {
    ScanFinding::new(
        code,
        severity,
        FindingSubject::Harness(HarnessId::OpenCode),
        vec![evidence(evidence_ref)],
        action,
    )
}

pub(crate) fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).expect("compiled OpenCode evidence references are valid")
}
