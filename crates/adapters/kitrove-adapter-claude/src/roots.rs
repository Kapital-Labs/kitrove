use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use kitrove_adapter_api::{
    AdapterResult, EvidenceRef, FindingSeverity, FindingSubject, NativeRootKey, ObservedRoot,
    PolicyLine, PolicyRuntimeAuthority, ProjectBoundary, ReceiptAuthority, RelatedDocumentPattern,
    RelatedRoot, RelatedRootAuthority, RootAuthority, RootContext, RootEvidenceAuthority,
    RootHookMeter, RootHookReport, RootId, RootIdAuthority, RootPathAuthority, RootRankAuthority,
    RootTier, ScanFinding,
};
use kitrove_agent_skills::{
    DirectoryWalkControl, DirectoryWalkMeter, SkillSourceLayout, walk_directories_nofollow,
};
use kitrove_model::{AssetKind, HarnessId, HarnessScope};

pub(crate) const ENTERPRISE_RANK: u32 = 10;
pub(crate) const USER_RANK: u32 = 20;
pub(crate) const PROJECT_RANK: u32 = 30;
pub(crate) const NESTED_RANK: u32 = 31;
pub(crate) const BUNDLED_RANK: u32 = 40;
pub(crate) const PLUGIN_RANK: u32 = 50;
pub(crate) const ADDITIONAL_RANK: u32 = 60;
pub(crate) const EXPLICIT_RANK: u32 = 70;

pub(crate) const PROFILE_EVIDENCE: &str = "claude.docs.skills.current";
pub(crate) const ENTERPRISE_EVIDENCE: &str = "claude.docs.skills.enterprise";
pub(crate) const USER_EVIDENCE: &str = "claude.docs.skills.user";
pub(crate) const PROJECT_EVIDENCE: &str = "claude.docs.skills.project";
pub(crate) const NESTED_EVIDENCE: &str = "claude.docs.skills.nested";
pub(crate) const PLUGIN_EVIDENCE: &str = "claude.docs.skills.plugin";
pub(crate) const ADDITIONAL_EVIDENCE: &str = "claude.docs.skills.additional";
pub(crate) const BUNDLED_EVIDENCE: &str = "claude.docs.skills.bundled";
pub(crate) const COMMAND_EVIDENCE: &str = "claude.docs.commands";
pub(crate) const AGENT_EVIDENCE: &str = "claude.docs.agents.current";
pub(crate) const PRECEDENCE_EVIDENCE: &str = "claude.docs.skills.precedence";

const ENTERPRISE_KEY: &str = "claude.enterprise";
const PLUGIN_KEY: &str = "claude.plugin";
const ADDITIONAL_KEY: &str = "claude.additional";
const BUNDLED_KEY: &str = "claude.bundled";

#[derive(Clone, Copy)]
struct NativeRootDescriptor {
    key: &'static str,
    tier: RootTier,
    policy_rank: u32,
    allowed_scopes: &'static [HarnessScope],
    evidence: &'static str,
    scope_finding: &'static str,
}

const NATIVE_ROOTS: [NativeRootDescriptor; 4] = [
    NativeRootDescriptor {
        key: ENTERPRISE_KEY,
        tier: RootTier::Admin,
        policy_rank: ENTERPRISE_RANK,
        allowed_scopes: &[HarnessScope::User],
        evidence: ENTERPRISE_EVIDENCE,
        scope_finding: "claude.enterprise_scope_unsupported",
    },
    NativeRootDescriptor {
        key: PLUGIN_KEY,
        tier: RootTier::Explicit,
        policy_rank: PLUGIN_RANK,
        allowed_scopes: &[HarnessScope::User, HarnessScope::Project],
        evidence: PLUGIN_EVIDENCE,
        scope_finding: "claude.plugin_scope_unsupported",
    },
    NativeRootDescriptor {
        key: ADDITIONAL_KEY,
        tier: RootTier::Explicit,
        policy_rank: ADDITIONAL_RANK,
        allowed_scopes: &[HarnessScope::User, HarnessScope::Project],
        evidence: ADDITIONAL_EVIDENCE,
        scope_finding: "claude.additional_scope_unsupported",
    },
    NativeRootDescriptor {
        key: BUNDLED_KEY,
        tier: RootTier::System,
        policy_rank: BUNDLED_RANK,
        allowed_scopes: &[HarnessScope::User],
        evidence: BUNDLED_EVIDENCE,
        scope_finding: "claude.bundled_scope_unsupported",
    },
];

pub(crate) fn runtime_authority() -> PolicyRuntimeAuthority {
    let line = PolicyLine::ClaudeCurrent;
    let directory_layouts =
        BTreeMap::from([(line, BTreeSet::from([SkillSourceLayout::Directory]))]);
    let mut roots = vec![
        RootAuthority {
            logical_id: RootIdAuthority::Exact(RootId::parse("claude.user.skills").unwrap()),
            path: RootPathAuthority::HomeRelative(PathBuf::from(".claude/skills")),
            scopes: BTreeSet::from([HarnessScope::User]),
            tier: RootTier::User,
            rank: RootRankAuthority::Exact(USER_RANK),
            layouts: directory_layouts.clone(),
            evidence: RootEvidenceAuthority::Exact(evidence(USER_EVIDENCE)),
        },
        RootAuthority {
            logical_id: RootIdAuthority::IndexedPrefix("claude.project.skills.".to_owned()),
            path: RootPathAuthority::ProjectAncestorRelative {
                relative: PathBuf::from(".claude/skills"),
                root_to_current: false,
                ascend_without_repository: false,
            },
            scopes: BTreeSet::from([HarnessScope::Project]),
            tier: RootTier::Project,
            rank: RootRankAuthority::Exact(PROJECT_RANK),
            layouts: directory_layouts.clone(),
            evidence: RootEvidenceAuthority::Exact(evidence(PROJECT_EVIDENCE)),
        },
        RootAuthority {
            logical_id: RootIdAuthority::Prefix("claude.project.nested.".to_owned()),
            path: RootPathAuthority::WorkingDescendant {
                suffix: PathBuf::from(".claude/skills"),
                include_working_root: false,
            },
            scopes: BTreeSet::from([HarnessScope::Project]),
            tier: RootTier::Project,
            rank: RootRankAuthority::Exact(NESTED_RANK),
            layouts: directory_layouts.clone(),
            evidence: RootEvidenceAuthority::Exact(evidence(NESTED_EVIDENCE)),
        },
        RootAuthority {
            logical_id: RootIdAuthority::IndexedPrefix("claude.explicit.".to_owned()),
            path: RootPathAuthority::ExplicitDirectory,
            scopes: BTreeSet::from([HarnessScope::User, HarnessScope::Project]),
            tier: RootTier::Explicit,
            rank: RootRankAuthority::Indexed {
                base: EXPLICIT_RANK,
            },
            layouts: directory_layouts.clone(),
            evidence: RootEvidenceAuthority::Exact(evidence(PROFILE_EVIDENCE)),
        },
    ];
    for descriptor in NATIVE_ROOTS {
        let kind = descriptor
            .key
            .strip_prefix("claude.")
            .unwrap_or(descriptor.key);
        roots.push(RootAuthority {
            logical_id: RootIdAuthority::IndexedPrefix(format!("claude.{kind}.")),
            path: RootPathAuthority::SuppliedNative(NativeRootKey::parse(descriptor.key).unwrap()),
            scopes: descriptor.allowed_scopes.iter().copied().collect(),
            tier: descriptor.tier,
            rank: RootRankAuthority::Exact(descriptor.policy_rank),
            layouts: directory_layouts.clone(),
            evidence: RootEvidenceAuthority::Exact(evidence(descriptor.evidence)),
        });
    }
    let related_layouts = BTreeMap::new();
    let related_roots = vec![
        RelatedRootAuthority {
            root: RootAuthority {
                logical_id: RootIdAuthority::Exact(RootId::parse("claude.user.commands").unwrap()),
                path: RootPathAuthority::HomeRelative(PathBuf::from(".claude/commands")),
                scopes: BTreeSet::from([HarnessScope::User]),
                tier: RootTier::User,
                rank: RootRankAuthority::Exact(USER_RANK),
                layouts: related_layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(COMMAND_EVIDENCE)),
            },
            kind: AssetKind::Command,
            pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
        },
        RelatedRootAuthority {
            root: RootAuthority {
                logical_id: RootIdAuthority::Exact(RootId::parse("claude.user.agents").unwrap()),
                path: RootPathAuthority::HomeRelative(PathBuf::from(".claude/agents")),
                scopes: BTreeSet::from([HarnessScope::User]),
                tier: RootTier::User,
                rank: RootRankAuthority::Exact(USER_RANK),
                layouts: related_layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(AGENT_EVIDENCE)),
            },
            kind: AssetKind::Agent,
            pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
        },
        RelatedRootAuthority {
            root: RootAuthority {
                logical_id: RootIdAuthority::IndexedPrefix("claude.project.agents.".to_owned()),
                path: RootPathAuthority::ProjectAncestorRelative {
                    relative: PathBuf::from(".claude/agents"),
                    root_to_current: false,
                    ascend_without_repository: false,
                },
                scopes: BTreeSet::from([HarnessScope::Project]),
                tier: RootTier::Project,
                rank: RootRankAuthority::Exact(PROJECT_RANK),
                layouts: related_layouts.clone(),
                evidence: RootEvidenceAuthority::Exact(evidence(AGENT_EVIDENCE)),
            },
            kind: AssetKind::Agent,
            pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
        },
        RelatedRootAuthority {
            root: RootAuthority {
                logical_id: RootIdAuthority::IndexedPrefix("claude.project.commands.".to_owned()),
                path: RootPathAuthority::ProjectAncestorRelative {
                    relative: PathBuf::from(".claude/commands"),
                    root_to_current: false,
                    ascend_without_repository: false,
                },
                scopes: BTreeSet::from([HarnessScope::Project]),
                tier: RootTier::Project,
                rank: RootRankAuthority::Exact(PROJECT_RANK),
                layouts: related_layouts,
                evidence: RootEvidenceAuthority::Exact(evidence(COMMAND_EVIDENCE)),
            },
            kind: AssetKind::Command,
            pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
        },
    ];
    let receipt_anchors = vec![
        ReceiptAuthority {
            path: RootPathAuthority::HomeRelative(PathBuf::from(".claude/skills")),
            scope: HarnessScope::User,
            evidence: evidence(USER_EVIDENCE),
        },
        ReceiptAuthority {
            path: RootPathAuthority::ProjectAncestorRelative {
                relative: PathBuf::from(".claude/skills"),
                root_to_current: true,
                ascend_without_repository: false,
            },
            scope: HarnessScope::Project,
            evidence: evidence(PROJECT_EVIDENCE),
        },
    ];
    PolicyRuntimeAuthority {
        roots,
        related_roots,
        receipt_anchors,
    }
}

pub(crate) fn standard_roots(context: &RootContext<'_>) -> AdapterResult<Vec<ObservedRoot>> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            roots.push(observed_root(
                "claude.user.skills",
                home.join(".claude/skills"),
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
                &format!("claude.project.skills.{index:04}"),
                anchor.join(".claude/skills"),
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
            "claude.version_unknown",
            FindingSeverity::Informational,
            FindingSubject::Harness(HarnessId::Claude),
            vec![evidence(PROFILE_EVIDENCE)],
            "use the conservative current Claude directory policy",
        ));
    }
    append_supplied_roots(context, &mut report, meter);
    append_explicit_roots(context, &mut report, meter);
    if scope_selected(context, HarnessScope::Project) {
        append_nested_roots(context, &mut report, meter);
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

fn append_explicit_roots(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    meter: &mut dyn RootHookMeter,
) {
    for (index, explicit) in context.explicit_roots.iter().enumerate() {
        if explicit.harness != HarnessId::Claude || !scope_selected(context, explicit.scope) {
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
                    "reduce explicit Claude roots or increase the request root limit",
                ));
            }
            break;
        }
        report.roots.push(observed_root(
            &format!("claude.explicit.{index:04}"),
            explicit.path.clone(),
            explicit.scope,
            RootTier::Explicit,
            indexed_rank(EXPLICIT_RANK, index),
            PROFILE_EVIDENCE,
        ));
    }
}

pub(crate) fn command_roots(context: &RootContext<'_>) -> Vec<RelatedRoot> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            roots.push(related_root(
                "claude.user.commands",
                home.join(".claude/commands"),
                HarnessScope::User,
                RootTier::User,
                USER_RANK,
                RelatedCapability::Command,
            ));
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        for (index, anchor) in project_anchors(context).into_iter().enumerate() {
            roots.push(related_root(
                &format!("claude.project.commands.{index:04}"),
                anchor.join(".claude/commands"),
                HarnessScope::Project,
                RootTier::Project,
                PROJECT_RANK,
                RelatedCapability::Command,
            ));
        }
    }
    roots
}

pub(crate) fn agent_roots(context: &RootContext<'_>) -> Vec<RelatedRoot> {
    let mut roots = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            roots.push(related_root(
                "claude.user.agents",
                home.join(".claude/agents"),
                HarnessScope::User,
                RootTier::User,
                USER_RANK,
                RelatedCapability::Agent,
            ));
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        for (index, anchor) in project_anchors(context).into_iter().enumerate() {
            roots.push(related_root(
                &format!("claude.project.agents.{index:04}"),
                anchor.join(".claude/agents"),
                HarnessScope::Project,
                RootTier::Project,
                PROJECT_RANK,
                RelatedCapability::Agent,
            ));
        }
    }
    roots
}

pub(crate) fn standard_receipt_anchors(
    context: &RootContext<'_>,
) -> Vec<kitrove_adapter_api::ReceiptAnchor> {
    let mut anchors = Vec::new();
    if scope_selected(context, HarnessScope::User) {
        if let Some(home) = context.home {
            anchors.push(kitrove_adapter_api::ReceiptAnchor {
                scope: HarnessScope::User,
                path: home.join(".claude/skills"),
                evidence: evidence(USER_EVIDENCE),
            });
        }
    }
    if scope_selected(context, HarnessScope::Project) {
        if let Some(anchor) = project_anchors(context).into_iter().last() {
            anchors.push(kitrove_adapter_api::ReceiptAnchor {
                scope: HarnessScope::Project,
                path: anchor.join(".claude/skills"),
                evidence: evidence(PROJECT_EVIDENCE),
            });
        }
    }
    anchors
}

pub(crate) fn nested_qualifier(root: &RootId) -> Option<String> {
    let encoded = root.as_str().strip_prefix("claude.project.nested.")?;
    decode_hex(encoded).and_then(|bytes| String::from_utf8(bytes).ok())
}

pub(crate) fn is_plugin_root(root: &RootId) -> bool {
    root.as_str().starts_with("claude.plugin.")
}

pub(crate) fn is_additional_root(root: &RootId) -> bool {
    root.as_str().starts_with("claude.additional.")
}

fn append_supplied_roots(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    meter: &mut dyn RootHookMeter,
) {
    for (index, supplied) in context.supplied_native_roots.iter().enumerate() {
        if supplied.harness() != &HarnessId::Claude {
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
                    "reduce supplied Claude roots or increase the request root limit",
                ));
            }
            break;
        }
        if report.roots.len() >= context.limits.max_roots {
            report.findings.push(supplied_finding(
                "scan.root_budget_exhausted",
                "reduce supplied Claude roots or increase the request root limit",
            ));
            break;
        }
        let Some(descriptor) = descriptor(supplied.source_key()) else {
            report.findings.push(supplied_finding(
                "claude.native_root_unknown",
                "select a compiled Claude native-root descriptor key",
            ));
            continue;
        };
        if !descriptor.allowed_scopes.contains(&supplied.scope()) {
            report.findings.push(supplied_finding(
                descriptor.scope_finding,
                "select a scope permitted by the compiled native-root descriptor",
            ));
            continue;
        }
        if !scope_selected(context, supplied.scope()) {
            continue;
        }
        let kind = descriptor
            .key
            .strip_prefix("claude.")
            .unwrap_or(descriptor.key);
        report.roots.push(observed_root(
            &format!("claude.{kind}.{index:04}"),
            supplied.path().to_path_buf(),
            supplied.scope(),
            descriptor.tier,
            descriptor.policy_rank,
            descriptor.evidence,
        ));
    }
}

fn append_nested_roots(
    context: &RootContext<'_>,
    report: &mut RootHookReport,
    meter: &mut dyn RootHookMeter,
) {
    let boundary = match context.project_boundary {
        ProjectBoundary::Repository { root } if context.working_directory.starts_with(root) => {
            context.working_directory
        }
        ProjectBoundary::Repository { .. } => return,
        ProjectBoundary::NoRepository | ProjectBoundary::UnsafeStop => context.working_directory,
    };
    let mut found = Vec::new();
    let mut root_exhausted = false;
    let mut directory_meter = RootDirectoryWalkMeter { inner: meter };
    let walk = walk_directories_nofollow(
        boundary,
        context.limits.max_discovery_depth,
        &mut directory_meter,
        &mut |path, relative| {
            if relative.file_name().is_some_and(|name| name == ".git") {
                return DirectoryWalkControl::Skip;
            }
            if !nested_skills_root(relative) {
                return DirectoryWalkControl::Continue;
            }
            if relative != Path::new(".claude/skills") {
                if report.roots.len().saturating_add(found.len()) >= context.limits.max_roots {
                    root_exhausted = true;
                    return DirectoryWalkControl::Stop;
                }
                found.push((path.to_path_buf(), nested_project_prefix(relative)));
            }
            DirectoryWalkControl::Skip
        },
    );

    found.sort_by_key(|item| path_key(&item.1));
    found.dedup_by(|left, right| left.0 == right.0);
    for (path, qualifier) in found {
        let Some(qualifier_text) = portable_relative_text(&qualifier) else {
            report.findings.push(nested_finding(
                "scan.discovery_unsafe_path",
                "rename nested project paths using valid UTF-8",
            ));
            continue;
        };
        let encoded = encode_hex(qualifier_text.as_bytes());
        let logical = format!("claude.project.nested.{encoded}");
        if logical.len() > 128 {
            report.findings.push(nested_finding(
                "claude.nested_identity_too_long",
                "shorten the nested project path before adopting its skills",
            ));
            continue;
        }
        report.roots.push(observed_root(
            &logical,
            path,
            HarnessScope::Project,
            RootTier::Project,
            NESTED_RANK,
            NESTED_EVIDENCE,
        ));
    }
    if report.roots.iter().any(|root| {
        root.logical_id
            .as_str()
            .starts_with("claude.project.nested.")
    }) {
        report.findings.push(nested_finding(
            "claude.nested_activation_context_unknown",
            "treat nested roots as potential skills until Claude has accessed their subtree",
        ));
    }
    if walk.unsafe_path || walk.unreadable {
        report.findings.push(nested_finding(
            "scan.discovery_unsafe_path",
            "use readable regular nested project directories with no links or reparse points",
        ));
    }
    if walk.depth_exhausted {
        report.findings.push(nested_finding(
            "scan.discovery_depth_exhausted",
            "reduce nested project depth or increase the request depth limit",
        ));
    }
    if walk.budget_exhausted {
        report.findings.push(nested_finding(
            "scan.discovery_budget_exhausted",
            "reduce nested project entries or increase the request discovery limit",
        ));
    }
    if root_exhausted {
        report.findings.push(nested_finding(
            "scan.root_budget_exhausted",
            "reduce nested Claude roots or increase the request root limit",
        ));
    }
}

struct RootDirectoryWalkMeter<'a> {
    inner: &'a mut dyn RootHookMeter,
}

impl DirectoryWalkMeter for RootDirectoryWalkMeter<'_> {
    fn try_discovery_entry(&mut self) -> bool {
        self.inner.try_discovery_entry()
    }

    fn remaining_discovery_entries(&self) -> usize {
        self.inner.remaining_discovery_entries()
    }
}

fn project_anchors(context: &RootContext<'_>) -> Vec<PathBuf> {
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
        logical_id: RootId::parse(logical_id).expect("compiled Claude root IDs are valid"),
        path,
        scope,
        tier,
        policy_rank,
        enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
        evidence: evidence(evidence_ref),
    }
}

#[derive(Clone, Copy)]
enum RelatedCapability {
    Command,
    Agent,
}

fn related_root(
    logical_id: &str,
    path: PathBuf,
    scope: HarnessScope,
    tier: RootTier,
    policy_rank: u32,
    capability: RelatedCapability,
) -> RelatedRoot {
    let (kind, evidence_ref) = match capability {
        RelatedCapability::Command => (AssetKind::Command, COMMAND_EVIDENCE),
        RelatedCapability::Agent => (AssetKind::Agent, AGENT_EVIDENCE),
    };
    RelatedRoot {
        logical_id: RootId::parse(logical_id).expect("compiled Claude command root IDs are valid"),
        path,
        scope,
        tier,
        policy_rank,
        kind,
        pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
        evidence: evidence(evidence_ref),
    }
}

fn descriptor(key: &NativeRootKey) -> Option<NativeRootDescriptor> {
    NATIVE_ROOTS
        .iter()
        .copied()
        .find(|descriptor| descriptor.key == key.as_str())
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

fn nested_skills_root(path: &Path) -> bool {
    let components = path.components().collect::<Vec<_>>();
    components.len() >= 2
        && matches!(components[components.len() - 2], Component::Normal(value) if value == ".claude")
        && matches!(components[components.len() - 1], Component::Normal(value) if value == "skills")
}

fn nested_project_prefix(path: &Path) -> PathBuf {
    let count = path.components().count().saturating_sub(2);
    path.components().take(count).collect()
}

fn portable_relative_text(path: &Path) -> Option<String> {
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (!components.is_empty()).then(|| components.join("/"))
}

fn path_key(path: &Path) -> Vec<u8> {
    path.as_os_str().as_encoded_bytes().to_vec()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn indexed_rank(base: u32, index: usize) -> u32 {
    base.saturating_add(u32::try_from(index).unwrap_or(u32::MAX))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).expect("compiled Claude evidence references are valid")
}

fn nested_finding(code: &'static str, action: &'static str) -> ScanFinding {
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Root(
            RootId::parse("claude.project.nested").expect("compiled Claude root ID is valid"),
        ),
        vec![evidence(NESTED_EVIDENCE)],
        action,
    )
}

fn supplied_finding(code: &'static str, action: &'static str) -> ScanFinding {
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Harness(HarnessId::Claude),
        vec![evidence(PROFILE_EVIDENCE)],
        action,
    )
}
