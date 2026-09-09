use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cap_fs_ext::{
    DirEntryExt as _, DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _,
    OpenOptionsSyncExt as _,
};
use cap_std::fs::{Dir, DirEntry, Metadata, OpenOptions};
use kitrove_adapter_api::{
    CandidateLocator, FindingSeverity, FindingSubject, HarnessObservationPolicy, LocatorDecision,
    ObservedRoot, PolicyProfile, RelatedRoot, ScanFinding, SourceRelativePath,
};
use kitrove_agent_skills::{
    BoundedDirectoryEntries, SkillSourceLayout, collect_bounded_sorted_directory_entries,
};

use crate::limits::ScanBudget;
use crate::read_only_fs::{
    ReadOnlyRootOpen as RootOpen, open_root_nofollow, safe_metadata, same_file,
};

/// A safe candidate locator together with the policy root that supplied it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredLocator {
    pub locator: CandidateLocator,
    pub root: ObservedRoot,
}

/// A located candidate that was deliberately not sent to generic capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedLocator {
    pub locator: CandidateLocator,
    pub root: ObservedRoot,
    pub finding: ScanFinding,
}

/// A selected root that existed but could not be opened safely without following links.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedRoot {
    pub root: ObservedRoot,
    pub finding: ScanFinding,
}

/// Deterministic, localized output from the pre-capture locator walk.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryReport {
    pub locators: Vec<DiscoveredLocator>,
    pub failed_locators: Vec<FailedLocator>,
    pub failed_roots: Vec<FailedRoot>,
    pub findings: Vec<ScanFinding>,
    pub roots_scanned: usize,
}

/// A safe, body-unread native related document kept separate from Agent Skill locators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedDocumentLocator {
    pub absolute_path: PathBuf,
    pub source_relative_path: String,
    pub layout: SkillSourceLayout,
    pub root: RelatedRoot,
}

/// Localized output from walking documented native-capability roots.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelatedDiscoveryReport {
    pub locators: Vec<RelatedDocumentLocator>,
    pub findings: Vec<ScanFinding>,
    pub roots_scanned: usize,
}

struct PendingEntry {
    entry: DirEntry,
    parent: Arc<Dir>,
    parent_relative: String,
    parent_key: Vec<u8>,
    file_name: OsString,
    display_path: PathBuf,
    depth: usize,
}

/// Discovers policy-classified candidate locators without opening candidate content.
///
/// The only content read is the up-to-five-byte frontmatter discriminator authorized by
/// [`LocatorDecision::CaptureIfFrontmatterPrefix`]: `---\n` or `---\r\n`. Every counter is
/// charged to the supplied request-global budget, so overlapping roots cannot reset capacity.
#[must_use]
pub fn discover_locators(
    policy: &dyn HarnessObservationPolicy,
    roots: &[ObservedRoot],
    profile: &PolicyProfile,
    budget: &mut ScanBudget,
) -> DiscoveryReport {
    let mut report = DiscoveryReport::default();

    for (index, root) in roots.iter().enumerate() {
        if !budget.reserve_root() {
            report.findings.push(root_finding(
                root,
                "scan.root_budget_exhausted",
                "reduce selected roots",
            ));
            break;
        }

        let directory = match open_root_nofollow(&root.path) {
            RootOpen::Open(directory) => directory,
            RootOpen::Missing => continue,
            RootOpen::Unsafe => {
                report.failed_roots.push(FailedRoot {
                    root: root.clone(),
                    finding: root_finding(
                        root,
                        "scan.root_unreadable",
                        "replace the root with a readable regular directory that has no link or reparse-point ancestor",
                    ),
                });
                continue;
            }
        };
        report.roots_scanned += 1;
        walk_root(policy, root, profile, budget, directory, &mut report);
        if budget.discovery_exhausted() {
            if index + 1 < roots.len()
                && !report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "scan.discovery_budget_exhausted")
            {
                report.findings.push(root_finding(
                    root,
                    "scan.discovery_budget_exhausted",
                    "reduce discovered entries or increase the request discovery limit",
                ));
            }
            break;
        }
    }

    report.locators.sort_by(locator_order);
    report.failed_locators.sort_by(failed_locator_order);
    report.findings.sort_by(finding_order);
    report
}

/// Discovers regular Markdown related documents without reading their bodies or treating them as
/// Agent Skills.
#[must_use]
pub fn discover_related_documents(
    roots: &[RelatedRoot],
    budget: &mut ScanBudget,
) -> RelatedDiscoveryReport {
    let mut report = RelatedDiscoveryReport::default();
    for (index, root) in roots.iter().enumerate() {
        let pseudo_root = ObservedRoot {
            logical_id: root.logical_id.clone(),
            path: root.path.clone(),
            scope: root.scope,
            tier: root.tier,
            policy_rank: root.policy_rank,
            enabled_layouts: Default::default(),
            evidence: root.evidence.clone(),
        };
        if !budget.reserve_root() {
            report.findings.push(root_finding(
                &pseudo_root,
                "scan.root_budget_exhausted",
                "reduce selected roots",
            ));
            break;
        }
        let directory = match open_root_nofollow(&root.path) {
            RootOpen::Open(directory) => directory,
            RootOpen::Missing => continue,
            RootOpen::Unsafe => {
                report.findings.push(root_finding(
                    &pseudo_root,
                    "scan.root_unreadable",
                    "replace the root with a readable regular directory that has no link or reparse-point ancestor",
                ));
                continue;
            }
        };
        report.roots_scanned += 1;
        let mut pending = BTreeMap::new();
        let mut local_discovery = DiscoveryReport::default();
        if !enqueue_entries(
            Arc::new(directory),
            "",
            Vec::new(),
            &root.path,
            0,
            budget,
            &pseudo_root,
            &mut local_discovery,
            &mut pending,
        ) {
            report.findings.extend(local_discovery.findings);
            report.findings.push(root_finding(
                &pseudo_root,
                "scan.discovery_budget_exhausted",
                "reduce discovered entries or increase the request discovery limit",
            ));
            continue;
        }
        report.findings.extend(local_discovery.findings);
        while let Some((_key, entry)) = pending.pop_first() {
            let Some(name) = entry.file_name.to_str() else {
                report.findings.push(root_finding(
                    &pseudo_root,
                    "scan.discovery_unsafe_path",
                    "rename the discovered path using valid UTF-8",
                ));
                continue;
            };
            let relative = join_relative(&entry.parent_relative, name);
            let metadata = match entry.entry.full_metadata() {
                Ok(metadata) if safe_metadata(&metadata) => metadata,
                _ => {
                    report.findings.push(related_finding(
                        root,
                        &relative,
                        "scan.discovery_unsafe_path",
                        "replace the discovered link, reparse point, or special file with a regular file or directory",
                    ));
                    continue;
                }
            };
            if metadata.is_dir() {
                if matches!(
                    root.pattern,
                    kitrove_adapter_api::RelatedDocumentPattern::MarkdownDirectChildren
                        | kitrove_adapter_api::RelatedDocumentPattern::TomlDirectChildren
                ) {
                    continue;
                }
                if root.pattern
                    == kitrove_adapter_api::RelatedDocumentPattern::NativeExtensionAtRoot
                {
                    let Ok(child) = entry.parent.open_dir_nofollow(&entry.file_name) else {
                        report.findings.push(related_finding(
                            root,
                            &relative,
                            "scan.discovery_unsafe_path",
                            "replace the changing or unsafe extension directory",
                        ));
                        continue;
                    };
                    let Ok(entrypoint) = child.symlink_metadata("index.ts") else {
                        continue;
                    };
                    if !safe_metadata(&entrypoint) || !entrypoint.is_file() {
                        report.findings.push(related_finding(
                            root,
                            &relative,
                            "scan.discovery_unsafe_path",
                            "replace the unsafe extension entrypoint with a regular index.ts file",
                        ));
                        continue;
                    }
                    if !budget.reserve_candidate() {
                        report.findings.push(related_finding(
                            root,
                            &relative,
                            "scan.candidate_budget_exhausted",
                            "reduce extension candidates or increase the request candidate limit",
                        ));
                        break;
                    }
                    report.locators.push(RelatedDocumentLocator {
                        absolute_path: entry.display_path,
                        source_relative_path: relative,
                        layout: SkillSourceLayout::Directory,
                        root: root.clone(),
                    });
                    continue;
                }
                let depth = entry.depth.saturating_add(1);
                if depth > budget.limits().max_discovery_depth {
                    report.findings.push(related_finding(
                        root,
                        &relative,
                        "scan.discovery_depth_exhausted",
                        "reduce directory nesting or increase the request discovery depth",
                    ));
                    continue;
                }
                let Ok(child) = entry.parent.open_dir_nofollow(&entry.file_name) else {
                    report.findings.push(related_finding(
                        root,
                        &relative,
                        "scan.discovery_unsafe_path",
                        "replace the changing or unsafe directory entry with a regular directory",
                    ));
                    continue;
                };
                let Ok(opened) = child.dir_metadata() else {
                    report.findings.push(related_finding(
                        root,
                        &relative,
                        "scan.discovery_unsafe_path",
                        "make the discovered directory readable without links or reparse points",
                    ));
                    continue;
                };
                if !safe_metadata(&opened) || !opened.is_dir() || !same_file(&metadata, &opened) {
                    report.findings.push(related_finding(
                        root,
                        &relative,
                        "scan.discovery_unsafe_path",
                        "replace the changing or unsafe directory entry with a regular directory",
                    ));
                    continue;
                }
                let mut child_key = entry.parent_key;
                if !child_key.is_empty() {
                    child_key.push(b'/');
                }
                child_key.extend_from_slice(entry.file_name.as_encoded_bytes());
                let mut discarded = DiscoveryReport::default();
                if !enqueue_entries(
                    Arc::new(child),
                    &relative,
                    child_key,
                    &entry.display_path,
                    depth,
                    budget,
                    &pseudo_root,
                    &mut discarded,
                    &mut pending,
                ) {
                    report.findings.extend(discarded.findings);
                    report.findings.push(related_finding(
                        root,
                        &relative,
                        "scan.discovery_budget_exhausted",
                        "reduce discovered entries or increase the request discovery limit",
                    ));
                    break;
                }
                report.findings.extend(discarded.findings);
            } else if metadata.is_file()
                && match root.pattern {
                    kitrove_adapter_api::RelatedDocumentPattern::MarkdownDirectChildren => {
                        entry.depth == 0 && name.ends_with(".md")
                    }
                    kitrove_adapter_api::RelatedDocumentPattern::MarkdownAtAnyDepth => {
                        name.ends_with(".md")
                    }
                    kitrove_adapter_api::RelatedDocumentPattern::TomlDirectChildren => {
                        entry.depth == 0 && name.ends_with(".toml")
                    }
                    kitrove_adapter_api::RelatedDocumentPattern::NativeExtensionAtRoot => {
                        entry.depth == 0 && name.ends_with(".ts") && !name.ends_with(".d.ts")
                    }
                }
            {
                if !budget.reserve_candidate() {
                    report.findings.push(related_finding(
                        root,
                        &relative,
                        "scan.candidate_budget_exhausted",
                        "reduce candidates or increase the request candidate limit",
                    ));
                    break;
                }
                report.locators.push(RelatedDocumentLocator {
                    absolute_path: entry.display_path,
                    source_relative_path: relative,
                    layout: SkillSourceLayout::Standalone,
                    root: root.clone(),
                });
            } else if !metadata.is_file() {
                report.findings.push(related_finding(
                    root,
                    &relative,
                    "scan.discovery_unsafe_path",
                    "replace the discovered special file with a regular file or directory",
                ));
            }
        }
        if budget.discovery_exhausted() && index + 1 < roots.len() {
            if !report
                .findings
                .iter()
                .any(|finding| finding.code == "scan.discovery_budget_exhausted")
            {
                report.findings.push(root_finding(
                    &pseudo_root,
                    "scan.discovery_budget_exhausted",
                    "reduce discovered entries or increase the request discovery limit",
                ));
            }
            break;
        }
    }
    report.locators.sort_by(|left, right| {
        (
            left.root.policy_rank,
            left.root.logical_id.as_str(),
            left.source_relative_path.as_bytes(),
        )
            .cmp(&(
                right.root.policy_rank,
                right.root.logical_id.as_str(),
                right.source_relative_path.as_bytes(),
            ))
    });
    report.findings.sort_by(finding_order);
    report
}

fn walk_root(
    policy: &dyn HarnessObservationPolicy,
    root: &ObservedRoot,
    profile: &PolicyProfile,
    budget: &mut ScanBudget,
    directory: Dir,
    report: &mut DiscoveryReport,
) {
    let mut pending = BTreeMap::new();
    if !enqueue_entries(
        Arc::new(directory),
        "",
        Vec::new(),
        &root.path,
        0,
        budget,
        root,
        report,
        &mut pending,
    ) {
        report.findings.push(root_finding(
            root,
            "scan.discovery_budget_exhausted",
            "reduce discovered entries or increase the request discovery limit",
        ));
        return;
    }

    while let Some((_key, pending_entry)) = pending.pop_first() {
        let Some(name) = pending_entry.file_name.to_str() else {
            report.findings.push(root_finding(
                root,
                "scan.discovery_unsafe_path",
                "rename the discovered path using valid UTF-8",
            ));
            continue;
        };
        let relative = join_relative(&pending_entry.parent_relative, name);
        let metadata = match pending_entry.entry.full_metadata() {
            Ok(metadata) if safe_metadata(&metadata) => metadata,
            _ => {
                report.findings.push(root_finding(
                    root,
                    "scan.discovery_unsafe_path",
                    "replace the discovered link, reparse point, or special file with a regular file or directory",
                ));
                continue;
            }
        };

        if metadata.is_dir() {
            let depth = pending_entry.depth.saturating_add(1);
            if depth > budget.limits().max_discovery_depth {
                report.findings.push(root_finding(
                    root,
                    "scan.discovery_depth_exhausted",
                    "reduce directory nesting or increase the request discovery depth",
                ));
                continue;
            }

            let child = match pending_entry
                .parent
                .open_dir_nofollow(&pending_entry.file_name)
            {
                Ok(child) => child,
                Err(_) => {
                    report.findings.push(root_finding(
                        root,
                        "scan.discovery_unsafe_path",
                        "replace the changing or unsafe directory entry with a regular directory",
                    ));
                    continue;
                }
            };
            let Ok(opened_metadata) = child.dir_metadata() else {
                report.findings.push(root_finding(
                    root,
                    "scan.discovery_unsafe_path",
                    "make the discovered directory readable without links or reparse points",
                ));
                continue;
            };
            if !safe_metadata(&opened_metadata)
                || !opened_metadata.is_dir()
                || !same_file(&metadata, &opened_metadata)
            {
                report.findings.push(root_finding(
                    root,
                    "scan.discovery_unsafe_path",
                    "replace the changing or unsafe directory entry with a regular directory",
                ));
                continue;
            }

            if has_direct_regular_skill_document(&child) {
                let locator = CandidateLocator {
                    absolute_path: pending_entry.display_path.clone(),
                    source_relative_path: relative.clone(),
                    layout: SkillSourceLayout::Directory,
                    original_document_name: "SKILL.md".to_owned(),
                };
                classify_locator(policy, root, profile, budget, locator, None, report);
            }

            let mut child_key = pending_entry.parent_key;
            if !child_key.is_empty() {
                child_key.push(b'/');
            }
            child_key.extend_from_slice(pending_entry.file_name.as_encoded_bytes());
            if !enqueue_entries(
                Arc::new(child),
                &relative,
                child_key,
                &pending_entry.display_path,
                depth,
                budget,
                root,
                report,
                &mut pending,
            ) {
                report.findings.push(root_finding(
                    root,
                    "scan.discovery_budget_exhausted",
                    "reduce discovered entries or increase the request discovery limit",
                ));
                return;
            }
        } else if metadata.is_file() {
            let locator = CandidateLocator {
                absolute_path: pending_entry.display_path.clone(),
                source_relative_path: relative,
                layout: SkillSourceLayout::Standalone,
                original_document_name: name.to_owned(),
            };
            classify_locator(
                policy,
                root,
                profile,
                budget,
                locator,
                Some((&pending_entry.parent, &pending_entry.file_name, &metadata)),
                report,
            );
        } else {
            report.findings.push(root_finding(
                root,
                "scan.discovery_unsafe_path",
                "replace the discovered special file with a regular file or directory",
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn enqueue_entries(
    directory: Arc<Dir>,
    relative: &str,
    directory_key: Vec<u8>,
    display_path: &Path,
    depth: usize,
    budget: &mut ScanBudget,
    root: &ObservedRoot,
    report: &mut DiscoveryReport,
    pending: &mut BTreeMap<Vec<u8>, PendingEntry>,
) -> bool {
    let read_dir = match directory.entries() {
        Ok(entries) => entries,
        Err(_) => {
            report.findings.push(root_finding(
                root,
                "scan.discovery_unsafe_path",
                "make the root directory readable without following links",
            ));
            return true;
        }
    };
    let allowance = budget.remaining_discovery_entries();
    if allowance == 0 {
        return false;
    }
    let bounded = match collect_bounded_sorted_directory_entries(read_dir, allowance) {
        Ok(entries) => entries,
        Err(_) => {
            report.findings.push(root_finding(
                root,
                "scan.discovery_unsafe_path",
                "make the root directory readable without following links",
            ));
            return true;
        }
    };
    let entries = match bounded {
        BoundedDirectoryEntries::Complete(entries) => entries,
        BoundedDirectoryEntries::Overflow => {
            budget.exhaust_discovery();
            return false;
        }
    };
    for entry in entries {
        let reserved = budget.reserve_discovery_entry();
        debug_assert!(
            reserved,
            "directory enumeration cannot exceed reserved capacity"
        );
        if !reserved {
            return false;
        }
        let file_name = entry.file_name();
        let mut key = directory_key.clone();
        if !key.is_empty() {
            key.push(b'/');
        }
        key.extend_from_slice(file_name.as_encoded_bytes());
        pending.insert(
            key,
            PendingEntry {
                display_path: display_path.join(&file_name),
                entry,
                parent: Arc::clone(&directory),
                parent_relative: relative.to_owned(),
                parent_key: directory_key.clone(),
                file_name,
                depth,
            },
        );
    }
    true
}

#[allow(clippy::type_complexity)]
fn classify_locator(
    policy: &dyn HarnessObservationPolicy,
    root: &ObservedRoot,
    profile: &PolicyProfile,
    budget: &mut ScanBudget,
    locator: CandidateLocator,
    prefix_handle: Option<(&Arc<Dir>, &OsString, &Metadata)>,
    report: &mut DiscoveryReport,
) {
    match policy.classify_locator(&locator, root, profile) {
        LocatorDecision::Ignore => {}
        LocatorDecision::Capture => retain_locator(budget, locator, root, report),
        LocatorDecision::CaptureIfFrontmatterPrefix => {
            let Some((parent, name, metadata)) = prefix_handle else {
                return;
            };
            match has_frontmatter_prefix(parent, name, &locator.absolute_path, metadata, budget) {
                PrefixResult::Present => retain_locator(budget, locator, root, report),
                PrefixResult::Missing => {}
                PrefixResult::BudgetExhausted => {
                    if !budget.reserve_candidate() {
                        report.findings.push(root_finding(
                            root,
                            "scan.candidate_budget_exhausted",
                            "reduce candidates or increase the request candidate limit",
                        ));
                        return;
                    }
                    let finding = locator_finding(
                        root,
                        "scan.capture_budget_exhausted",
                        "reduce capture work or increase request capture capacity",
                    );
                    retain_failed(locator, root, finding, report);
                }
                PrefixResult::Unsafe => {
                    if !budget.reserve_candidate() {
                        report.findings.push(root_finding(
                            root,
                            "scan.candidate_budget_exhausted",
                            "reduce candidates or increase the request candidate limit",
                        ));
                        return;
                    }
                    let finding = locator_finding(
                        root,
                        "scan.discovery_unsafe_path",
                        "replace the changing or unsafe candidate with a regular file",
                    );
                    retain_failed(locator, root, finding, report);
                }
            }
        }
        LocatorDecision::Unsupported { finding } => {
            if !budget.reserve_candidate() {
                report.findings.push(root_finding(
                    root,
                    "scan.candidate_budget_exhausted",
                    "reduce candidates or increase the request candidate limit",
                ));
                return;
            }
            retain_failed(locator, root, finding, report);
        }
    }
}

fn retain_locator(
    budget: &mut ScanBudget,
    locator: CandidateLocator,
    root: &ObservedRoot,
    report: &mut DiscoveryReport,
) {
    if !budget.reserve_candidate() {
        report.findings.push(root_finding(
            root,
            "scan.candidate_budget_exhausted",
            "reduce candidates or increase the request candidate limit",
        ));
        return;
    }
    report.locators.push(DiscoveredLocator {
        locator,
        root: root.clone(),
    });
}

fn retain_failed(
    locator: CandidateLocator,
    root: &ObservedRoot,
    finding: ScanFinding,
    report: &mut DiscoveryReport,
) {
    report.failed_locators.push(FailedLocator {
        locator,
        root: root.clone(),
        finding,
    });
}

enum PrefixResult {
    Present,
    Missing,
    BudgetExhausted,
    Unsafe,
}

fn has_frontmatter_prefix(
    parent: &Dir,
    name: &OsString,
    _path: &Path,
    entry_metadata: &Metadata,
    budget: &mut ScanBudget,
) -> PrefixResult {
    if !budget.begin_capture_file() {
        return PrefixResult::BudgetExhausted;
    }
    let remaining = budget.remaining_capture_bytes();
    if remaining == 0 {
        return PrefixResult::BudgetExhausted;
    }
    let read_len = usize::try_from(remaining.min(5)).unwrap_or(5);
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let Ok(mut file) = parent.open_with(name, &options) else {
        return PrefixResult::Unsafe;
    };
    let Ok(before) = file.metadata() else {
        return PrefixResult::Unsafe;
    };
    if !safe_metadata(&before) || !before.is_file() || !same_file(entry_metadata, &before) {
        return PrefixResult::Unsafe;
    }
    let mut prefix = vec![0_u8; read_len];
    let bytes_read = match file.read(&mut prefix) {
        Ok(bytes_read) => bytes_read,
        Err(_) => return PrefixResult::Unsafe,
    };
    prefix.truncate(bytes_read);
    budget.charge_capture_bytes(u64::try_from(bytes_read).unwrap_or(u64::MAX));
    let Ok(after) = file.metadata() else {
        return PrefixResult::Unsafe;
    };
    if !safe_metadata(&after) || !after.is_file() || !same_file(&before, &after) {
        return PrefixResult::Unsafe;
    }
    if prefix.starts_with(b"---\n") || prefix == b"---\r\n" {
        return PrefixResult::Present;
    }
    if prefix == b"---\r" && budget.remaining_capture_bytes() == 0 {
        return PrefixResult::BudgetExhausted;
    }
    PrefixResult::Missing
}

fn has_direct_regular_skill_document(directory: &Dir) -> bool {
    directory
        .symlink_metadata("SKILL.md")
        .is_ok_and(|metadata| safe_metadata(&metadata) && metadata.is_file())
}

fn join_relative(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn root_finding(root: &ObservedRoot, code: &'static str, action: &'static str) -> ScanFinding {
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Root(root.logical_id.clone()),
        vec![root.evidence.clone()],
        action,
    )
}

fn locator_finding(root: &ObservedRoot, code: &'static str, action: &'static str) -> ScanFinding {
    root_finding(root, code, action)
}

fn related_finding(
    root: &RelatedRoot,
    relative: &str,
    code: &'static str,
    action: &'static str,
) -> ScanFinding {
    let subject = SourceRelativePath::parse(relative).map_or_else(
        |_| FindingSubject::Root(root.logical_id.clone()),
        |source_relative_path| FindingSubject::Related {
            logical_root: root.logical_id.clone(),
            source_relative_path,
        },
    );
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        subject,
        vec![root.evidence.clone()],
        action,
    )
}

fn locator_order(left: &DiscoveredLocator, right: &DiscoveredLocator) -> std::cmp::Ordering {
    locator_key(&left.locator, &left.root).cmp(&locator_key(&right.locator, &right.root))
}

fn failed_locator_order(left: &FailedLocator, right: &FailedLocator) -> std::cmp::Ordering {
    locator_key(&left.locator, &left.root)
        .cmp(&locator_key(&right.locator, &right.root))
        .then_with(|| left.finding.code.cmp(right.finding.code))
}

fn locator_key<'a>(
    locator: &'a CandidateLocator,
    root: &'a ObservedRoot,
) -> (u32, &'a str, &'a [u8], u8) {
    (
        root.policy_rank,
        root.logical_id.as_str(),
        locator.source_relative_path.as_bytes(),
        match locator.layout {
            SkillSourceLayout::Directory => 0,
            SkillSourceLayout::Standalone => 1,
        },
    )
}

fn finding_order(left: &ScanFinding, right: &ScanFinding) -> std::cmp::Ordering {
    left.code
        .cmp(right.code)
        .then_with(|| format!("{:?}", left.subject).cmp(&format!("{:?}", right.subject)))
}
