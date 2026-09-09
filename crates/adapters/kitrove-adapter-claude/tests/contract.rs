use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use kitrove_adapter_api::{
    CandidateDecision, CandidateLocator, EvidenceRef, HarnessObservationPolicy, NativeAcceptance,
    NativeRootKey, ObservedRoot, PolicyLine, PortablePolicyDecision, ProjectBoundary,
    ProjectTrustKey, ProjectTrustObservation, RootContext, RootId, RootTier, ScanLimits,
    ScanRequest, ScopeSelection, SuppliedNativeRoot, VersionObservation,
};
use kitrove_adapter_claude::ClaudeObservationPolicy;
use kitrove_agent_skills::{CaptureLimits, SkillSource, SkillSourceLayout, capture_skill_source};
use kitrove_core::{ObservedCandidate, ScanClassification, render_scan_json};
use kitrove_model::{ContentClass, HarnessId, HarnessScope};
#[cfg(unix)]
use kitrove_testkit::FilesystemSnapshot;
use kitrove_testkit::{
    FixtureBuilder, LocatorExpectation, LocatorProbe, NativeRootExpectation, PolicyContractCase,
    ReceiptAnchorExpectation, assert_policy_contract, test_engine,
};
use tempfile::TempDir;

const DIRECTORY_LAYOUT: [SkillSourceLayout; 1] = [SkillSourceLayout::Directory];

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).unwrap()
}

fn tempdir() -> TempDir {
    let canonical_temp = std::env::temp_dir().canonicalize().unwrap();
    tempfile::tempdir_in(canonical_temp).unwrap()
}

fn native_root(scope: HarnessScope, key: &str, path: impl Into<PathBuf>) -> SuppliedNativeRoot {
    SuppliedNativeRoot::new(
        HarnessId::Claude,
        scope,
        NativeRootKey::parse(key).unwrap(),
        path.into(),
    )
}

fn write_skill(root: &Path, name: &str, document: &str) -> PathBuf {
    let directory = root.join(name);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("SKILL.md"), document).unwrap();
    directory
}

fn valid_skill(name: &str, description: &str) -> String {
    format!("---\nname: {name}\ndescription: {description}\n---\nInert body.\n")
}

fn decide_document(
    temp: &TempDir,
    directory_id: &str,
    document: &str,
    logical_root: &str,
    root_path: PathBuf,
) -> CandidateDecision {
    let source = write_skill(&temp.path().join("captured"), directory_id, document);
    let captured = capture_skill_source(
        &SkillSource::Directory {
            path: source.clone(),
        },
        CaptureLimits::default(),
    )
    .unwrap();
    let root = ObservedRoot {
        logical_id: RootId::parse(logical_root).unwrap(),
        path: root_path,
        scope: HarnessScope::User,
        tier: RootTier::Explicit,
        policy_rank: 50,
        enabled_layouts: BTreeSet::from(DIRECTORY_LAYOUT),
        evidence: evidence("claude.docs.skills.plugin"),
    };
    let locator = CandidateLocator {
        absolute_path: source,
        source_relative_path: directory_id.to_owned(),
        layout: SkillSourceLayout::Directory,
        original_document_name: "SKILL.md".to_owned(),
    };
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    policy
        .decide_candidate(&captured, &locator, &root, &profile)
        .unwrap()
}

fn request(
    temp: &TempDir,
    working_directory: PathBuf,
    repository_root: PathBuf,
    supplied_native_roots: Vec<SuppliedNativeRoot>,
) -> ScanRequest<'static> {
    ScanRequest {
        home: Some(temp.path().join("home")),
        working_directory,
        project_boundary: ProjectBoundary::Repository {
            root: repository_root,
        },
        harnesses: BTreeSet::from([HarnessId::Claude]),
        scopes: ScopeSelection::All,
        explicit_roots: vec![],
        supplied_native_roots,
        versions: BTreeMap::new(),
        project_trust: BTreeMap::new(),
        environment: None,
        local_state: None,
        limits: ScanLimits::default(),
    }
}

fn root_context<'a>(
    home: &'a Path,
    working_directory: &'a Path,
    boundary: &'a ProjectBoundary,
    supplied_native_roots: &'a [SuppliedNativeRoot],
    project_trust: &'a BTreeMap<ProjectTrustKey, ProjectTrustObservation>,
    limits: &'a ScanLimits,
) -> RootContext<'a> {
    RootContext {
        home: Some(home),
        working_directory,
        project_boundary: boundary,
        scopes: ScopeSelection::All,
        explicit_roots: &[],
        supplied_native_roots,
        project_trust,
        limits,
    }
}

#[test]
fn shared_policy_contract_covers_compiled_roots_layouts_and_receipt_authority() {
    let fixture = FixtureBuilder::new()
        .repository()
        .user_root(".claude/skills")
        .directory_skill("review", valid_skill("review", "Review changes."))
        .build()
        .unwrap();
    let enterprise = fixture.root().join("enterprise");
    let plugin = fixture.root().join("plugins/example/skills");
    let additional = fixture.root().join("additional/.claude/skills");
    let bundled = fixture.root().join("bundled/skills");
    for path in [&enterprise, &plugin, &additional, &bundled] {
        fs::create_dir_all(path).unwrap();
    }

    let user_anchor = fixture.home().join(".claude/skills");
    let project_anchor = fixture
        .repository_root()
        .expect("repository fixture")
        .join(".claude/skills");
    let directory_layouts = BTreeSet::from(DIRECTORY_LAYOUT);
    let case = PolicyContractCase::new(ClaudeObservationPolicy::new())
        .with_fixture(fixture)
        .expect_native_root(NativeRootExpectation {
            supplied: native_root(HarnessScope::User, "claude.enterprise", &enterprise),
            allowed_scopes: BTreeSet::from([HarnessScope::User]),
            unsupported_scope_finding: "claude.enterprise_scope_unsupported".to_owned(),
            tier: RootTier::Admin,
            policy_rank: 10,
            enabled_layouts: directory_layouts.clone(),
            evidence: evidence("claude.docs.skills.enterprise"),
        })
        .expect_native_root(NativeRootExpectation {
            supplied: native_root(HarnessScope::Project, "claude.plugin", &plugin),
            allowed_scopes: BTreeSet::from([HarnessScope::User, HarnessScope::Project]),
            unsupported_scope_finding: "claude.plugin_scope_unsupported".to_owned(),
            tier: RootTier::Explicit,
            policy_rank: 50,
            enabled_layouts: directory_layouts.clone(),
            evidence: evidence("claude.docs.skills.plugin"),
        })
        .expect_native_root(NativeRootExpectation {
            supplied: native_root(HarnessScope::User, "claude.additional", &additional),
            allowed_scopes: BTreeSet::from([HarnessScope::User, HarnessScope::Project]),
            unsupported_scope_finding: "claude.additional_scope_unsupported".to_owned(),
            tier: RootTier::Explicit,
            policy_rank: 60,
            enabled_layouts: directory_layouts.clone(),
            evidence: evidence("claude.docs.skills.additional"),
        })
        .expect_native_root(NativeRootExpectation {
            supplied: native_root(HarnessScope::User, "claude.bundled", &bundled),
            allowed_scopes: BTreeSet::from([HarnessScope::User]),
            unsupported_scope_finding: "claude.bundled_scope_unsupported".to_owned(),
            tier: RootTier::System,
            policy_rank: 40,
            enabled_layouts: directory_layouts,
            evidence: evidence("claude.docs.skills.bundled"),
        })
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::User,
            user_anchor,
            evidence("claude.docs.skills.user"),
        ))
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::Project,
            project_anchor,
            evidence("claude.docs.skills.project"),
        ))
        .expect_locator(LocatorProbe::new(
            "review",
            SkillSourceLayout::Directory,
            "SKILL.md",
            LocatorExpectation::Supported,
        ))
        .expect_locator(LocatorProbe::new(
            "flat.md",
            SkillSourceLayout::Standalone,
            "flat.md",
            LocatorExpectation::Unsupported,
        ));

    assert_policy_contract(case).unwrap();
}

#[test]
fn enterprise_and_bundled_reject_project_scope_with_stable_findings() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    fs::create_dir_all(&working).unwrap();
    let supplied = vec![
        native_root(
            HarnessScope::Project,
            "claude.enterprise",
            temp.path().join("enterprise"),
        ),
        native_root(
            HarnessScope::Project,
            "claude.bundled",
            temp.path().join("bundled"),
        ),
    ];
    let boundary = ProjectBoundary::Repository { root: repository };
    let limits = ScanLimits::default();
    let project_trust = BTreeMap::new();
    let context = root_context(
        &home,
        &working,
        &boundary,
        &supplied,
        &project_trust,
        &limits,
    );
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert!(!report.roots.iter().any(|root| {
        matches!(root.tier, RootTier::Admin | RootTier::System)
            && root.scope == HarnessScope::Project
    }));
    let codes = report
        .findings
        .iter()
        .map(|finding| finding.code)
        .collect::<BTreeSet<_>>();
    assert!(codes.contains("claude.enterprise_scope_unsupported"));
    assert!(codes.contains("claude.bundled_scope_unsupported"));
}

#[test]
fn inconsistent_repository_boundary_grants_no_project_root_or_receipt_anchor() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = temp.path().join("outside/work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(&working).unwrap();
    let boundary = ProjectBoundary::Repository { root: repository };
    let limits = ScanLimits::default();
    let project_trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &[], &project_trust, &limits);
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let roots = policy.roots(&context, &profile).unwrap();
    let anchors = policy.receipt_anchors(&context, &profile).unwrap();

    assert!(roots.iter().all(|root| root.scope != HarnessScope::Project));
    assert!(
        anchors
            .iter()
            .all(|anchor| anchor.scope != HarnessScope::Project)
    );
}

#[test]
fn nested_working_directory_uses_repository_root_for_project_receipts() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("packages/app");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let boundary = ProjectBoundary::Repository {
        root: repository.clone(),
    };
    let limits = ScanLimits::default();
    let project_trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &[], &project_trust, &limits);
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let anchors = policy.receipt_anchors(&context, &profile).unwrap();

    assert!(anchors.iter().any(|anchor| {
        anchor.scope == HarnessScope::Project && anchor.path == repository.join(".claude/skills")
    }));
    assert!(!anchors.iter().any(|anchor| {
        anchor.scope == HarnessScope::Project && anchor.path == working.join(".claude/skills")
    }));
}

#[test]
fn no_repository_and_unsafe_stop_keep_claude_project_roots_at_working_directory() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("outside/deep/work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let limits = ScanLimits::default();
    let project_trust = BTreeMap::new();
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    for boundary in [ProjectBoundary::NoRepository, ProjectBoundary::UnsafeStop] {
        let context = root_context(&home, &working, &boundary, &[], &project_trust, &limits);
        let project_paths = policy
            .roots(&context, &profile)
            .unwrap()
            .into_iter()
            .filter(|root| root.scope == HarnessScope::Project)
            .map(|root| root.path)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            project_paths,
            BTreeSet::from([working.join(".claude/skills")])
        );
    }
}

#[test]
fn roots_include_user_ancestors_and_bounded_nested_projects() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("packages/app");
    fs::create_dir_all(home.join(".claude/skills")).unwrap();
    for directory in [
        repository.join(".claude/skills"),
        repository.join("packages/.claude/skills"),
        working.join(".claude/skills"),
        working.join("feature/.claude/skills"),
    ] {
        fs::create_dir_all(directory).unwrap();
    }
    fs::create_dir_all(temp.path().join("outside/.claude/skills")).unwrap();
    let boundary = ProjectBoundary::Repository {
        root: repository.clone(),
    };
    let limits = ScanLimits::default();
    let project_trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &[], &project_trust, &limits);
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let roots = policy.roots(&context, &profile).unwrap();
    let unusual = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(profile.line(), PolicyLine::ClaudeCurrent);
    assert!(
        roots
            .iter()
            .any(|root| root.path == home.join(".claude/skills"))
    );
    for expected in [
        repository.join(".claude/skills"),
        repository.join("packages/.claude/skills"),
        working.join(".claude/skills"),
    ] {
        assert!(roots.iter().any(|root| root.path == expected));
    }
    assert!(
        unusual
            .roots
            .iter()
            .any(|root| root.path == working.join("feature/.claude/skills"))
    );
    assert!(
        unusual
            .roots
            .iter()
            .all(|root| root.path.starts_with(&working))
    );
    assert!(
        unusual
            .findings
            .iter()
            .any(|finding| { finding.code == "claude.nested_activation_context_unknown" })
    );
}

#[test]
fn nested_hook_respects_the_request_root_limit() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(working.join("a/.claude/skills")).unwrap();
    fs::create_dir_all(working.join("b/.claude/skills")).unwrap();
    let boundary = ProjectBoundary::Repository { root: repository };
    let limits = ScanLimits {
        max_roots: 1,
        ..ScanLimits::default()
    };
    let project_trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &[], &project_trust, &limits);
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(report.roots.len(), 1);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.root_budget_exhausted")
    );
}

#[test]
fn nested_hook_and_generic_discovery_share_one_refusing_entry_budget() {
    let temp = tempdir();
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    let nested = working.join("nested/.claude/skills/review");
    fs::create_dir_all(&nested).unwrap();
    fs::write(
        nested.join("SKILL.md"),
        valid_skill("review", "Review nested changes."),
    )
    .unwrap();
    let mut request = request(&temp, working, repository, vec![]);
    request.scopes = ScopeSelection::Project;
    request.limits.max_discovery_entries = 3;

    let report = test_engine(&ClaudeObservationPolicy::new())
        .scan(&request)
        .unwrap();

    assert!(report.entries.is_empty());
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "scan.discovery_budget_exhausted")
            .count(),
        1
    );
}

#[test]
fn supplied_root_budget_counts_invalid_inputs_and_stops_before_the_tail() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let boundary = ProjectBoundary::NoRepository;
    let supplied = vec![
        native_root(
            HarnessScope::User,
            "claude.unknown",
            temp.path().join("one"),
        ),
        native_root(
            HarnessScope::User,
            "claude.unknown",
            temp.path().join("two"),
        ),
    ];
    let limits = ScanLimits {
        max_roots: 1,
        ..ScanLimits::default()
    };
    let trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &supplied, &trust, &limits);
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "claude.native_root_unknown")
            .count(),
        1
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "scan.root_budget_exhausted")
            .count(),
        1
    );
}

#[test]
fn native_id_and_portable_fallback_are_loss_aware() {
    let temp = tempdir();
    let source = write_skill(
        temp.path(),
        "portable-name",
        "---\nname: Display Name\n---\n# Display heading\r\n\r\nFallback paragraph stays\r\nunchanged.\r\n\r\nLater text.\r\n",
    );
    let captured = capture_skill_source(
        &SkillSource::Directory {
            path: source.clone(),
        },
        CaptureLimits::default(),
    )
    .unwrap();
    let root = ObservedRoot {
        logical_id: RootId::parse("claude.user.skills").unwrap(),
        path: temp.path().to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: 20,
        enabled_layouts: BTreeSet::from(DIRECTORY_LAYOUT),
        evidence: evidence("claude.docs.skills.user"),
    };
    let locator = CandidateLocator {
        absolute_path: source,
        source_relative_path: "portable-name".to_owned(),
        layout: SkillSourceLayout::Directory,
        original_document_name: "SKILL.md".to_owned(),
    };
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let decision = policy
        .decide_candidate(&captured, &locator, &root, &profile)
        .unwrap();

    assert_eq!(decision.native_id(), Some("portable-name"));
    let PortablePolicyDecision::Project {
        name,
        description,
        reasons,
    } = decision.portable()
    else {
        panic!("standard directory ID and fallback paragraph must project")
    };
    assert_eq!(name.as_str(), "portable-name");
    assert_eq!(description, "Fallback paragraph stays\r\nunchanged.");
    assert_eq!(
        reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "claude.description_first_paragraph",
            "claude.display_name_differs",
        ])
    );
}

#[test]
fn portable_fallback_skips_markdown_block_constructs_without_modifying_the_paragraph() {
    let temp = tempdir();
    let cases = [
        (
            "thematic-dashes",
            "---\n\nActual paragraph.\n",
            "Actual paragraph.",
        ),
        (
            "thematic-stars",
            "***\r\n\r\nExact first line.\r\nsecond line.\r\n",
            "Exact first line.\r\nsecond line.",
        ),
        (
            "thematic-underscores",
            "___\n\nActual paragraph.\n",
            "Actual paragraph.",
        ),
        (
            "indented-code",
            "\tcode block\n\nActual paragraph.\n",
            "Actual paragraph.",
        ),
        (
            "tabbed-list",
            "-\tlist item\n\nActual paragraph.\n",
            "Actual paragraph.",
        ),
        (
            "tabbed-ordered-list",
            "1)\tlist item\n\nActual paragraph.\n",
            "Actual paragraph.",
        ),
        (
            "html-block",
            "<div>\nblock content\n</div>\n\nActual paragraph.\n",
            "Actual paragraph.",
        ),
        (
            "link-definition",
            "[reference]: https://example.invalid\n\nActual paragraph.\n",
            "Actual paragraph.",
        ),
        (
            "custom-html-block",
            "<custom-element>\n\nActual paragraph.\n",
            "Actual paragraph.",
        ),
        (
            "table-block",
            "Header | Other\n--- | ---\ncell | cell\n\nActual paragraph.\n",
            "Actual paragraph.",
        ),
    ];

    for (directory_id, body, expected) in cases {
        let document = format!("---\nname: {directory_id}\n---\n{body}");
        let decision = decide_document(
            &temp,
            directory_id,
            &document,
            "claude.user.skills",
            temp.path().join("user-skills"),
        );
        let PortablePolicyDecision::Project { description, .. } = decision.portable() else {
            panic!("{directory_id} should fall through to its real first paragraph")
        };
        assert_eq!(description, expected, "case {directory_id}");
    }
}

#[test]
fn portable_fallback_is_unavailable_when_the_body_has_only_non_paragraph_blocks() {
    let temp = tempdir();
    let decision = decide_document(
        &temp,
        "non-paragraphs",
        "---\nname: non-paragraphs\n---\n---\n\n***\n\n___\n\n\tcode block\n",
        "claude.user.skills",
        temp.path().join("user-skills"),
    );

    let PortablePolicyDecision::Unavailable { reasons } = decision.portable() else {
        panic!("block constructs must not become an invented portable description")
    };
    assert!(
        reasons
            .iter()
            .any(|reason| reason.code == "claude.portable_description_unavailable")
    );
}

#[test]
fn plugin_identity_is_rejected_when_an_exact_namespace_is_unavailable() {
    let temp = tempdir();
    let decisions = [
        decide_document(
            &temp,
            "review",
            &valid_skill("review", "Review changes."),
            "claude.plugin.0000",
            PathBuf::from("skills"),
        ),
        decide_document(
            &temp,
            "review",
            &valid_skill("review", "Review changes."),
            "claude.plugin.0001",
            PathBuf::from(std::path::MAIN_SEPARATOR.to_string()),
        ),
    ];

    for decision in decisions {
        assert_eq!(decision.acceptance(), NativeAcceptance::Rejected);
        assert_eq!(decision.native_id(), None);
        let PortablePolicyDecision::Unavailable { reasons } = decision.portable() else {
            panic!("a rejected plugin identity cannot project portably")
        };
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, "claude.plugin_namespace_unavailable");
        assert!(
            decision
                .findings()
                .iter()
                .any(|finding| finding.code == "claude.plugin_namespace_unavailable")
        );
    }
}

#[cfg(unix)]
#[test]
fn plugin_identity_rejects_a_non_utf8_namespace() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let temp = tempdir();
    let namespace = OsString::from_vec(vec![0xff]);
    let root_path = temp.path().join("plugins").join(namespace).join("skills");
    let decision = decide_document(
        &temp,
        "review",
        &valid_skill("review", "Review changes."),
        "claude.plugin.0000",
        root_path,
    );

    assert_eq!(decision.acceptance(), NativeAcceptance::Rejected);
    assert_eq!(decision.native_id(), None);
    let PortablePolicyDecision::Unavailable { reasons } = decision.portable() else {
        panic!("a non-UTF-8 namespace cannot project portably")
    };
    assert_eq!(reasons[0].code, "claude.plugin_namespace_unavailable");
}

#[test]
fn invalid_directory_id_or_overlong_fallback_keeps_native_candidate_without_portable_projection() {
    let temp = tempdir();
    let paragraph = "x".repeat(1_025);
    let source = write_skill(temp.path(), "Not Portable", &format!("{paragraph}\n"));
    let captured = capture_skill_source(
        &SkillSource::Directory {
            path: source.clone(),
        },
        CaptureLimits::default(),
    )
    .unwrap();
    let root = ObservedRoot {
        logical_id: RootId::parse("claude.user.skills").unwrap(),
        path: temp.path().to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: 20,
        enabled_layouts: BTreeSet::from(DIRECTORY_LAYOUT),
        evidence: evidence("claude.docs.skills.user"),
    };
    let locator = CandidateLocator {
        absolute_path: source,
        source_relative_path: "Not Portable".to_owned(),
        layout: SkillSourceLayout::Directory,
        original_document_name: "SKILL.md".to_owned(),
    };
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let decision = policy
        .decide_candidate(&captured, &locator, &root, &profile)
        .unwrap();

    assert_eq!(decision.native_id(), Some("Not Portable"));
    let PortablePolicyDecision::Unavailable { reasons } = decision.portable() else {
        panic!("invalid standard name and description must not be invented")
    };
    assert_eq!(
        reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "claude.portable_description_unavailable",
            "claude.portable_name_unavailable",
        ])
    );
}

#[test]
fn commands_are_typed_observations_and_flat_markdown_is_never_a_skill() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    fs::create_dir_all(home.join(".claude/skills/review")).unwrap();
    fs::create_dir_all(home.join(".claude/commands")).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        home.join(".claude/skills/review/SKILL.md"),
        valid_skill("review", "Review changes."),
    )
    .unwrap();
    fs::write(home.join(".claude/skills/flat.md"), "Not a package.\n").unwrap();
    fs::write(
        home.join(".claude/commands/review.md"),
        "Related command.\n",
    )
    .unwrap();
    let request = request(&temp, working, repository, vec![]);

    let report = test_engine(&ClaudeObservationPolicy::new())
        .scan(&request)
        .unwrap();

    assert!(report.related.is_empty());
    assert_eq!(report.prompt_commands.len(), 1);
    assert_eq!(report.prompt_commands[0].source_relative_path, "review.md");
    assert_eq!(report.prompt_commands[0].name.as_str(), "review");
    assert!(report.prompt_commands[0].portable_hash.is_some());
    assert_eq!(
        report
            .entries
            .iter()
            .filter(|entry| entry.classification == ScanClassification::Unmanaged)
            .count(),
        1
    );
    let flat = report
        .entries
        .iter()
        .find(|entry| entry.source_relative_path.as_deref() == Some("flat.md"))
        .unwrap();
    assert_eq!(flat.classification, ScanClassification::Unknown);
    assert!(
        flat.findings
            .iter()
            .any(|finding| finding.code == "scan.layout_unsupported")
    );
}

#[test]
fn executable_command_scan_is_redacted_and_not_portable() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("working");
    let commands = home.join(".claude/commands");
    fs::create_dir_all(&commands).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        commands.join("private.md"),
        "Inspect !`printf PRIVATE_COMMAND_SECRET`.\n",
    )
    .unwrap();

    let report = test_engine(&ClaudeObservationPolicy::new())
        .scan(&request(&temp, working, repository, vec![]))
        .unwrap();
    let command = &report.prompt_commands[0];

    assert_eq!(command.content_class, ContentClass::Executable);
    assert!(command.portable_hash.is_none());
    assert!(command.blocked_reason.is_some());
    assert_eq!(report.prompt_command_observations().len(), 1);
    let rendered = render_scan_json(&report).unwrap();
    assert!(!rendered.contains("PRIVATE_COMMAND_SECRET"));
    assert!(rendered.contains("scan.prompt_command_executable"));
}

#[test]
fn agents_are_recursive_typed_and_same_name_ambiguity_is_local_to_one_root() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("working");
    let agents = home.join(".claude/agents");
    fs::create_dir_all(agents.join("team")).unwrap();
    fs::create_dir_all(agents.join("other")).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        agents.join("team/review.md"),
        "---\nname: review\ndescription: Review changes.\n---\nReview carefully.\n",
    )
    .unwrap();
    fs::write(
        agents.join("other/duplicate.md"),
        "---\nname: review\ndescription: Review another way.\n---\nReview independently.\n",
    )
    .unwrap();
    fs::write(
        agents.join("authority.md"),
        "---\nname: authority\ndescription: Retain native authority.\nhooks:\n  Stop: unresolved\n---\nStay native.\n",
    )
    .unwrap();

    let report = test_engine(&ClaudeObservationPolicy::new())
        .scan(&request(&temp, working, repository, vec![]))
        .unwrap();

    assert_eq!(report.agents.len(), 3);
    assert_eq!(report.agent_observations().len(), 1);
    let duplicate = report
        .agents
        .iter()
        .filter(|agent| agent.name.as_str() == "review")
        .collect::<Vec<_>>();
    assert_eq!(duplicate.len(), 2);
    assert!(duplicate.iter().all(|agent| {
        agent.classification == ScanClassification::ConflictingDuplicate
            && agent
                .findings
                .iter()
                .any(|finding| finding.code == "scan.agent_name_ambiguous")
    }));
    let authority = report
        .agents
        .iter()
        .find(|agent| agent.name.as_str() == "authority")
        .unwrap();
    assert!(authority.portable_hash.is_none());
    assert!(authority.blocked_reason.is_some());
}

#[test]
fn standard_precedence_retains_every_shadow_and_additional_collisions_are_ambiguous() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    let enterprise = temp.path().join("enterprise");
    let bundled = temp.path().join("bundled");
    let additional = temp.path().join("additional");
    for root in [
        home.join(".claude/skills"),
        working.join(".claude/skills"),
        enterprise.clone(),
        bundled.clone(),
        additional.clone(),
    ] {
        fs::create_dir_all(&root).unwrap();
        write_skill(&root, "review", &valid_skill("review", "Review changes."));
    }
    let standard_request = request(
        &temp,
        working.clone(),
        repository.clone(),
        vec![
            native_root(HarnessScope::User, "claude.enterprise", &enterprise),
            native_root(HarnessScope::User, "claude.bundled", &bundled),
        ],
    );
    let policy = ClaudeObservationPolicy::new();

    let standard = test_engine(&policy).scan(&standard_request).unwrap();

    assert_eq!(standard.entries.len(), 4);
    let winner = standard
        .entries
        .iter()
        .find(|entry| entry.root_tier == Some(RootTier::Admin))
        .unwrap();
    assert_eq!(winner.shadowed_by, None);
    for shadow in standard
        .entries
        .iter()
        .filter(|entry| entry.root_tier != Some(RootTier::Admin))
    {
        assert_eq!(shadow.shadowed_by.as_ref(), winner.observation_id.as_ref());
        assert!(
            shadow
                .findings
                .iter()
                .any(|finding| finding.code == "scan.candidate_shadowed")
        );
    }

    let ambiguous_request = request(
        &temp,
        working,
        repository,
        vec![native_root(
            HarnessScope::User,
            "claude.additional",
            &additional,
        )],
    );
    let ambiguous = test_engine(&policy).scan(&ambiguous_request).unwrap();
    let collision = ambiguous
        .entries
        .iter()
        .filter(|entry| entry.native_id.as_deref() == Some("review"))
        .collect::<Vec<_>>();
    assert!(collision.len() >= 2);
    assert!(collision.iter().all(|entry| entry.shadowed_by.is_none()));
    assert!(collision.iter().all(|entry| {
        entry
            .findings
            .iter()
            .any(|finding| finding.code == "scan.duplicate_ambiguous")
    }));
}

#[test]
fn nested_and_plugin_namespaces_coexist_with_unqualified_sources() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    let nested = working.join("feature/.claude/skills");
    let plugin = temp.path().join("plugins/example-plugin/skills");
    for root in [home.join(".claude/skills"), nested, plugin.clone()] {
        fs::create_dir_all(&root).unwrap();
        write_skill(&root, "review", &valid_skill("review", "Review changes."));
    }
    let request = request(
        &temp,
        working,
        repository,
        vec![native_root(HarnessScope::User, "claude.plugin", plugin)],
    );

    let report = test_engine(&ClaudeObservationPolicy::new())
        .scan(&request)
        .unwrap();
    let ids = report
        .entries
        .iter()
        .filter_map(|entry| entry.native_id.as_deref())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        ids,
        BTreeSet::from(["example-plugin:review", "feature/review", "review"])
    );
    assert!(
        report
            .entries
            .iter()
            .all(|entry| entry.shadowed_by.is_none())
    );
}

#[cfg(unix)]
#[test]
fn symlinked_skill_is_refused_without_reading_or_writing_and_valid_sibling_survives() {
    use std::os::unix::fs::symlink;

    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    let skills = home.join(".claude/skills");
    let target = temp.path().join("outside/secret-skill");
    fs::create_dir_all(&skills).unwrap();
    fs::create_dir_all(&working).unwrap();
    write_skill(&skills, "valid", &valid_skill("valid", "Valid sibling."));
    write_skill(
        &temp.path().join("outside"),
        "secret-skill",
        &valid_skill("secret", "Do not read."),
    );
    symlink(&target, skills.join("linked")).unwrap();
    let before = FilesystemSnapshot::capture(temp.path()).unwrap();
    let request = request(&temp, working, repository, vec![]);

    let report = test_engine(&ClaudeObservationPolicy::new())
        .scan(&request)
        .unwrap();

    assert_eq!(FilesystemSnapshot::capture(temp.path()).unwrap(), before);
    assert!(report.entries.iter().any(|entry| {
        entry.native_id.as_deref() == Some("valid")
            && entry.classification == ScanClassification::Unmanaged
    }));
    assert!(
        !report
            .entries
            .iter()
            .any(|entry| entry.native_id.as_deref() == Some("secret"))
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.discovery_unsafe_path")
    );
}

#[cfg(unix)]
#[test]
fn nested_hook_does_not_follow_a_symlinked_working_directory() {
    use std::os::unix::fs::symlink;

    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let actual_working = temp.path().join("actual-working");
    let linked_working = repository.join("working");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(actual_working.join("feature/.claude/skills")).unwrap();
    symlink(&actual_working, &linked_working).unwrap();
    let boundary = ProjectBoundary::Repository { root: repository };
    let limits = ScanLimits::default();
    let project_trust = BTreeMap::new();
    let context = root_context(
        &home,
        &linked_working,
        &boundary,
        &[],
        &project_trust,
        &limits,
    );
    let policy = ClaudeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert!(report.roots.is_empty());
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.discovery_unsafe_path")
    );
}

#[test]
fn one_malformed_skill_does_not_hide_sibling_and_report_order_is_stable() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    let skills = home.join(".claude/skills");
    fs::create_dir_all(&skills).unwrap();
    fs::create_dir_all(&working).unwrap();
    write_skill(
        &skills,
        "z-valid",
        &valid_skill("z-valid", "Valid sibling."),
    );
    write_skill(&skills, "a-malformed", "---\nname: [unterminated\n---\n");
    let request = request(&temp, working, repository, vec![]);
    let policy = ClaudeObservationPolicy::new();

    let first = test_engine(&policy).scan(&request).unwrap();
    let second = test_engine(&policy).scan(&request).unwrap();

    assert_eq!(first, second);
    assert_eq!(
        first
            .entries
            .iter()
            .map(|entry| (
                entry.source_relative_path.as_deref().unwrap(),
                entry.classification,
            ))
            .collect::<Vec<_>>(),
        [
            ("a-malformed", ScanClassification::Unknown),
            ("z-valid", ScanClassification::Unmanaged),
        ]
    );
    assert!(matches!(
        first.observations()[0],
        ObservedCandidate::Failed(_)
    ));
    assert!(matches!(
        first.observations()[1],
        ObservedCandidate::Accepted(_)
    ));
}
