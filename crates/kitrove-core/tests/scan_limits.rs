use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    EvidenceRef, FindingSeverity, FindingSubject, HarnessObservationPolicy, LocatorDecision,
    ObservedRoot, PolicyLine, PolicyProfile, ReceiptAnchor, RootContext, RootId, RootTier,
    ScanFinding, ScanLimits, VersionObservation, VersionObservationOwned,
};
use kitrove_agent_skills::{CapturedSkillSource, SkillSourceLayout};
use kitrove_core::{ScanBudget, discover_locators, discover_related_documents};
use kitrove_model::{HarnessId, HarnessScope};

static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let id = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kitrove-core-scan-limits-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestPolicy;

impl HarnessObservationPolicy for TestPolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Claude
    }

    fn profile(&self, _version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        Ok(profile())
    }

    fn roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        Ok(vec![])
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        if locator.layout == SkillSourceLayout::Directory
            && locator.source_relative_path.ends_with("package")
        {
            LocatorDecision::Capture
        } else if locator.layout == SkillSourceLayout::Directory
            || locator.original_document_name == "SKILL.md"
            || locator.source_relative_path.ends_with("ignored.md")
        {
            LocatorDecision::Ignore
        } else if locator.source_relative_path.ends_with("unsupported.md") {
            LocatorDecision::Unsupported {
                finding: ScanFinding::new(
                    "scan.unsupported_locator",
                    FindingSeverity::Attention,
                    FindingSubject::Report,
                    vec![],
                    "use a supported layout",
                ),
            }
        } else if locator.source_relative_path.contains("prefix") {
            LocatorDecision::CaptureIfFrontmatterPrefix
        } else {
            LocatorDecision::Capture
        }
    }

    fn decide_candidate(
        &self,
        _candidate: &CapturedSkillSource,
        _locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        unreachable!("locator discovery never captures candidates")
    }

    fn resolve_duplicates(
        &self,
        _group: &[CandidateSummary],
        _profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision> {
        Ok(DuplicateDecision::Coexist)
    }

    fn receipt_anchors(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>> {
        Ok(vec![])
    }
}

fn profile() -> PolicyProfile {
    PolicyProfile::new(
        HarnessId::Claude,
        PolicyLine::ClaudeCurrent,
        VersionObservationOwned::Unknown,
        EvidenceRef::parse("test.profile").unwrap(),
    )
    .unwrap()
}

fn root(path: &Path, id: usize) -> ObservedRoot {
    ObservedRoot {
        logical_id: RootId::parse(format!("test.root.{id}")).unwrap(),
        path: path.to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: id as u32,
        enabled_layouts: BTreeSet::from([
            SkillSourceLayout::Directory,
            SkillSourceLayout::Standalone,
        ]),
        evidence: EvidenceRef::parse("test.root").unwrap(),
    }
}

fn discover(roots: &[ObservedRoot], limits: ScanLimits) -> kitrove_core::DiscoveryReport {
    let mut budget = ScanBudget::new(limits);
    discover_locators(&TestPolicy, roots, &profile(), &mut budget)
}

fn write_markdown(path: &Path) {
    fs::write(path, b"---\nname: test\ndescription: test\n---\n").unwrap();
}

#[test]
fn overlapping_roots_share_one_discovery_budget() {
    let fixture = TestRoot::new();
    for name in ["a.md", "b.md", "c.md"] {
        write_markdown(&fixture.path().join(name));
    }
    let roots = [root(fixture.path(), 0), root(fixture.path(), 1)];

    let result = discover(
        &roots,
        ScanLimits {
            max_discovery_entries: 3,
            max_candidates: 2,
            ..ScanLimits::default()
        },
    );

    assert_eq!(result.locators.len(), 2);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.code == "scan.discovery_budget_exhausted")
    );
}

#[test]
fn missing_optional_root_is_silently_skipped() {
    let fixture = TestRoot::new();
    let missing = fixture.path().join("missing");

    let result = discover(&[root(&missing, 0)], ScanLimits::default());

    assert_eq!(result.roots_scanned, 0);
    assert!(result.locators.is_empty());
    assert!(result.failed_roots.is_empty());
    assert!(result.findings.is_empty());
}

#[cfg(unix)]
#[test]
fn unsafe_root_is_retained_as_one_redacted_root_failure() {
    use std::os::unix::fs::symlink;

    let fixture = TestRoot::new();
    let external = TestRoot::new();
    symlink(external.path(), fixture.path().join("unsafe-root")).unwrap();

    let result = discover(
        &[root(&fixture.path().join("unsafe-root"), 0)],
        ScanLimits::default(),
    );

    assert_eq!(result.roots_scanned, 0);
    assert!(result.locators.is_empty());
    assert!(result.findings.is_empty());
    assert_eq!(result.failed_roots.len(), 1);
    assert_eq!(result.failed_roots[0].finding.code, "scan.root_unreadable");
}

#[test]
fn flat_root_overflow_is_detected_with_one_extra_entry_and_fails_closed() {
    let fixture = TestRoot::new();
    for name in ["a.md", "b.md", "c.md"] {
        write_markdown(&fixture.path().join(name));
    }

    let result = discover(
        &[root(fixture.path(), 0), root(fixture.path(), 1)],
        ScanLimits {
            max_discovery_entries: 2,
            ..ScanLimits::default()
        },
    );

    assert!(result.locators.is_empty());
    assert_eq!(result.roots_scanned, 1);
    assert_eq!(
        result
            .findings
            .iter()
            .filter(|finding| finding.code == "scan.discovery_budget_exhausted")
            .count(),
        1
    );
}

#[test]
fn grouping_and_support_directories_are_not_directory_candidates() {
    let fixture = TestRoot::new();
    fs::create_dir_all(fixture.path().join("group/package")).unwrap();
    fs::create_dir_all(fixture.path().join("group/support")).unwrap();
    write_markdown(&fixture.path().join("group/package/SKILL.md"));
    write_markdown(&fixture.path().join("group/support/readme.md"));

    let result = discover(&[root(fixture.path(), 0)], ScanLimits::default());

    assert_eq!(
        result
            .locators
            .iter()
            .filter(|located| located.locator.layout == SkillSourceLayout::Directory)
            .map(|located| located.locator.source_relative_path.as_str())
            .collect::<Vec<_>>(),
        ["group/package"]
    );
}

#[test]
fn policy_is_the_only_layout_gate_and_preserves_unsupported_locators() {
    let fixture = TestRoot::new();
    for name in ["captured.md", "ignored.md", "unsupported.md"] {
        write_markdown(&fixture.path().join(name));
    }

    let result = discover(&[root(fixture.path(), 0)], ScanLimits::default());

    assert_eq!(
        result
            .locators
            .iter()
            .map(|located| located.locator.source_relative_path.as_str())
            .collect::<Vec<_>>(),
        ["captured.md"]
    );
    assert_eq!(result.failed_locators.len(), 1);
    assert_eq!(
        result.failed_locators[0].finding.code,
        "scan.unsupported_locator"
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.code != "scan.unsupported_locator")
    );
}

#[test]
fn prefix_gate_accepts_complete_lf_with_four_byte_capacity() {
    let fixture = TestRoot::new();
    fs::write(
        fixture.path().join("prefix-lf.md"),
        b"---\nnot a full capture\n",
    )
    .unwrap();
    let mut budget = ScanBudget::new(ScanLimits {
        max_capture_files: 1,
        max_capture_bytes: 4,
        ..ScanLimits::default()
    });

    let result = discover_locators(
        &TestPolicy,
        &[root(fixture.path(), 0)],
        &profile(),
        &mut budget,
    );

    assert_eq!(result.locators.len(), 1);
    assert_eq!(budget.capture_usage().file_attempts, 1);
    assert_eq!(budget.capture_usage().bytes_read, 4);
}

#[test]
fn prefix_gate_accepts_crlf_with_one_bounded_read() {
    let fixture = TestRoot::new();
    fs::write(fixture.path().join("prefix-crlf.md"), b"---\r\n").unwrap();
    let mut budget = ScanBudget::new(ScanLimits {
        max_capture_files: 1,
        max_capture_bytes: 5,
        ..ScanLimits::default()
    });

    let result = discover_locators(
        &TestPolicy,
        &[root(fixture.path(), 0)],
        &profile(),
        &mut budget,
    );

    assert_eq!(result.locators.len(), 1);
    assert_eq!(budget.capture_usage().file_attempts, 1);
    assert_eq!(budget.capture_usage().bytes_read, 5);
}

#[test]
fn prefix_gate_charges_short_and_budget_limited_reads_exactly() {
    let fixture = TestRoot::new();
    fs::write(fixture.path().join("prefix-short.md"), b"---").unwrap();
    let mut short_budget = ScanBudget::new(ScanLimits {
        max_capture_files: 1,
        max_capture_bytes: 5,
        ..ScanLimits::default()
    });
    let short = discover_locators(
        &TestPolicy,
        &[root(fixture.path(), 0)],
        &profile(),
        &mut short_budget,
    );
    assert!(short.locators.is_empty());
    assert!(short.failed_locators.is_empty());
    assert!(short.findings.is_empty());
    assert_eq!(short_budget.capture_usage().file_attempts, 1);
    assert_eq!(short_budget.capture_usage().bytes_read, 3);

    fs::remove_file(fixture.path().join("prefix-short.md")).unwrap();
    fs::write(fixture.path().join("prefix-budget.md"), b"---\r").unwrap();
    let mut limited_budget = ScanBudget::new(ScanLimits {
        max_capture_files: 1,
        max_capture_bytes: 4,
        ..ScanLimits::default()
    });
    let limited = discover_locators(
        &TestPolicy,
        &[root(fixture.path(), 1)],
        &profile(),
        &mut limited_budget,
    );
    assert!(limited.locators.is_empty());
    assert_eq!(limited.failed_locators.len(), 1);
    assert_eq!(
        limited.failed_locators[0].finding.code,
        "scan.capture_budget_exhausted"
    );
    assert!(limited.findings.is_empty());
    assert_eq!(limited_budget.capture_usage().file_attempts, 1);
    assert_eq!(limited_budget.capture_usage().bytes_read, 4);
}

#[test]
fn prefix_nonmatch_is_ignored_without_consuming_candidate_capacity() {
    let fixture = TestRoot::new();
    fs::write(fixture.path().join("a-prefix.md"), b"plain markdown").unwrap();
    write_markdown(&fixture.path().join("z-captured.md"));

    let result = discover(
        &[root(fixture.path(), 0)],
        ScanLimits {
            max_candidates: 1,
            ..ScanLimits::default()
        },
    );

    assert_eq!(result.locators.len(), 1);
    assert_eq!(
        result.locators[0].locator.source_relative_path,
        "z-captured.md"
    );
    assert!(result.failed_locators.is_empty());
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.code != "scan.frontmatter_prefix_missing")
    );
}

#[test]
fn depth_limit_accepts_64_and_rejects_65() {
    let accepted = TestRoot::new();
    let mut accepted_path = accepted.path().to_path_buf();
    for _ in 0..64 {
        accepted_path.push("d");
        fs::create_dir(&accepted_path).unwrap();
    }
    write_markdown(&accepted_path.join("accepted.md"));

    let rejected = TestRoot::new();
    let mut rejected_path = rejected.path().to_path_buf();
    for _ in 0..65 {
        rejected_path.push("d");
        fs::create_dir(&rejected_path).unwrap();
    }
    write_markdown(&rejected_path.join("rejected.md"));

    let accepted_report = discover(&[root(accepted.path(), 0)], ScanLimits::default());
    assert_eq!(accepted_report.locators.len(), 1);

    let rejected_report = discover(&[root(rejected.path(), 0)], ScanLimits::default());
    assert!(rejected_report.locators.is_empty());
    assert!(
        rejected_report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.discovery_depth_exhausted")
    );
}

#[test]
fn root_limit_accepts_256_and_rejects_257() {
    let fixture = TestRoot::new();
    let roots = (0..257)
        .map(|id| root(fixture.path(), id))
        .collect::<Vec<_>>();
    let result = discover(
        &roots,
        ScanLimits {
            max_roots: 256,
            ..ScanLimits::default()
        },
    );

    assert_eq!(result.roots_scanned, 256);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.code == "scan.root_budget_exhausted")
    );
}

#[test]
fn candidate_limit_accepts_4096_and_rejects_4097() {
    let fixture = TestRoot::new();
    for id in 0..4097 {
        write_markdown(&fixture.path().join(format!("candidate-{id:04}.md")));
    }
    let result = discover(&[root(fixture.path(), 0)], ScanLimits::default());

    assert_eq!(result.locators.len(), 4096);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.code == "scan.candidate_budget_exhausted")
    );
}

#[test]
fn locator_order_is_stable_across_creation_orders() {
    let first = TestRoot::new();
    let second = TestRoot::new();
    for name in ["z.md", "a.md", "m.md"] {
        write_markdown(&first.path().join(name));
    }
    for name in ["m.md", "z.md", "a.md"] {
        write_markdown(&second.path().join(name));
    }

    let first_paths = discover(&[root(first.path(), 0)], ScanLimits::default())
        .locators
        .into_iter()
        .map(|located| located.locator.source_relative_path)
        .collect::<Vec<_>>();
    let second_paths = discover(&[root(second.path(), 0)], ScanLimits::default())
        .locators
        .into_iter()
        .map(|located| located.locator.source_relative_path)
        .collect::<Vec<_>>();

    assert_eq!(first_paths, ["a.md", "m.md", "z.md"]);
    assert_eq!(first_paths, second_paths);
}

#[test]
fn queued_discovery_entries_never_exceed_the_global_budget() {
    let fixture = TestRoot::new();
    let nested = fixture.path().join("a").join("00");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir(fixture.path().join("a/01")).unwrap();
    write_markdown(&nested.join("leaf.md"));
    let mut budget = ScanBudget::new(ScanLimits {
        max_discovery_entries: 3,
        ..ScanLimits::default()
    });

    let report = discover_locators(
        &TestPolicy,
        &[root(fixture.path(), 0)],
        &profile(),
        &mut budget,
    );

    assert_eq!(budget.discovery_entries(), 3);
    assert!(report.locators.is_empty());
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.discovery_budget_exhausted")
    );
}

#[cfg(unix)]
#[test]
fn symlinked_roots_and_candidates_are_localized_without_following_targets() {
    use std::os::unix::fs::symlink;

    let fixture = TestRoot::new();
    let external = TestRoot::new();
    let target = external.path().join("target");
    fs::create_dir(&target).unwrap();
    write_markdown(&target.join("outside.md"));
    symlink(&target, fixture.path().join("root-link")).unwrap();
    symlink(
        target.join("outside.md"),
        fixture.path().join("candidate-link.md"),
    )
    .unwrap();

    let root_link = discover(
        &[root(&fixture.path().join("root-link"), 0)],
        ScanLimits::default(),
    );
    assert!(root_link.locators.is_empty());
    assert_eq!(root_link.failed_roots.len(), 1);
    assert_eq!(
        root_link.failed_roots[0].finding.code,
        "scan.root_unreadable"
    );

    let candidate_link = discover(&[root(fixture.path(), 1)], ScanLimits::default());
    assert!(candidate_link.locators.is_empty());
    assert!(
        candidate_link
            .findings
            .iter()
            .any(|finding| finding.code == "scan.discovery_unsafe_path")
    );
}

#[cfg(unix)]
#[test]
fn special_files_are_localized_without_becoming_locators() {
    use std::os::unix::net::UnixListener;

    let fixture = TestRoot::new();
    let _socket = UnixListener::bind(fixture.path().join("socket.md")).unwrap();

    let result = discover(&[root(fixture.path(), 0)], ScanLimits::default());

    assert!(result.locators.is_empty());
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.code == "scan.discovery_unsafe_path")
    );
}

#[test]
fn related_documents_are_markdown_only_and_share_the_candidate_budget() {
    let fixture = TestRoot::new();
    write_markdown(&fixture.path().join("command.md"));
    fs::write(fixture.path().join("ignored.txt"), b"not a command").unwrap();
    let related = kitrove_adapter_api::RelatedRoot {
        logical_id: RootId::parse("test.commands").unwrap(),
        path: fixture.path().to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: 0,
        kind: kitrove_model::AssetKind::Command,
        pattern: kitrove_adapter_api::RelatedDocumentPattern::MarkdownAtAnyDepth,
        evidence: EvidenceRef::parse("test.commands").unwrap(),
    };
    let mut budget = ScanBudget::new(ScanLimits {
        max_candidates: 1,
        ..ScanLimits::default()
    });

    let report = discover_related_documents(&[related], &mut budget);

    assert_eq!(report.locators.len(), 1);
    assert_eq!(report.locators[0].source_relative_path, "command.md");
}

#[test]
fn direct_related_markdown_does_not_traverse_nested_directories() {
    let fixture = TestRoot::new();
    write_markdown(&fixture.path().join("direct.md"));
    fs::create_dir_all(fixture.path().join("nested")).unwrap();
    write_markdown(&fixture.path().join("nested/ignored.md"));
    let related = kitrove_adapter_api::RelatedRoot {
        logical_id: RootId::parse("test.direct.commands").unwrap(),
        path: fixture.path().to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: 0,
        kind: kitrove_model::AssetKind::Command,
        pattern: kitrove_adapter_api::RelatedDocumentPattern::MarkdownDirectChildren,
        evidence: EvidenceRef::parse("test.commands").unwrap(),
    };
    let mut budget = ScanBudget::new(ScanLimits::default());

    let report = discover_related_documents(&[related], &mut budget);

    assert_eq!(report.locators.len(), 1);
    assert_eq!(report.locators[0].source_relative_path, "direct.md");
    assert!(report.findings.is_empty());
}

#[test]
fn related_flat_root_overflow_fails_closed_with_one_terminal_finding() {
    let fixture = TestRoot::new();
    for name in ["a.md", "b.md", "c.md"] {
        write_markdown(&fixture.path().join(name));
    }
    let related = kitrove_adapter_api::RelatedRoot {
        logical_id: RootId::parse("test.commands.overflow").unwrap(),
        path: fixture.path().to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: 0,
        kind: kitrove_model::AssetKind::Command,
        pattern: kitrove_adapter_api::RelatedDocumentPattern::MarkdownAtAnyDepth,
        evidence: EvidenceRef::parse("test.commands").unwrap(),
    };
    let mut budget = ScanBudget::new(ScanLimits {
        max_discovery_entries: 2,
        ..ScanLimits::default()
    });

    let report = discover_related_documents(&[related], &mut budget);

    assert!(report.locators.is_empty());
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "scan.discovery_budget_exhausted")
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn related_sibling_failures_retain_distinct_relative_subjects() {
    use std::os::unix::net::UnixListener;

    let fixture = TestRoot::new();
    let _first = UnixListener::bind(fixture.path().join("first.md")).unwrap();
    let _second = UnixListener::bind(fixture.path().join("second.md")).unwrap();
    let related = kitrove_adapter_api::RelatedRoot {
        logical_id: RootId::parse("test.related").unwrap(),
        path: fixture.path().to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: 0,
        kind: kitrove_model::AssetKind::Command,
        pattern: kitrove_adapter_api::RelatedDocumentPattern::MarkdownAtAnyDepth,
        evidence: EvidenceRef::parse("test.related").unwrap(),
    };
    let mut budget = ScanBudget::new(ScanLimits::default());

    let report = discover_related_documents(&[related], &mut budget);

    let paths = report
        .findings
        .iter()
        .filter_map(|finding| match &finding.subject {
            FindingSubject::Related {
                source_relative_path,
                ..
            } => Some(source_relative_path.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(paths, ["first.md", "second.md"]);
}
