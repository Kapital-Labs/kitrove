use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use kitrove_adapter_api::{
    CandidateDecision, CandidateLocator, EvidenceRef, HarnessObservationPolicy, NativeAcceptance,
    NativeRootKey, ObservedRoot, PolicyLine, PortablePolicyDecision, ProjectBoundary,
    ProjectTrustKey, ProjectTrustObservation, RootContext, RootId, RootTier, ScanLimits,
    ScanRequest, ScopeSelection, SuppliedNativeRoot, VersionObservation,
};
use kitrove_adapter_codex::CodexObservationPolicy;
use kitrove_agent_skills::{CaptureLimits, SkillSource, SkillSourceLayout, capture_skill_source};
use kitrove_core::ScanClassification;
use kitrove_model::{HarnessId, HarnessScope};
use kitrove_testkit::{
    FilesystemSnapshot, FixtureBuilder, LocatorExpectation, LocatorProbe, NativeRootExpectation,
    PolicyContractCase, ReceiptAnchorExpectation, assert_policy_contract, test_engine,
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

fn native_root(scope: HarnessScope, path: impl Into<PathBuf>) -> SuppliedNativeRoot {
    SuppliedNativeRoot::new(
        HarnessId::Codex,
        scope,
        NativeRootKey::parse("codex.bundled").unwrap(),
        path.into(),
    )
}

fn write_skill(root: &Path, directory: &str, name: Option<&str>, description: Option<&str>) {
    let package = root.join(directory);
    fs::create_dir_all(&package).unwrap();
    let mut document = String::from("---\n");
    if let Some(name) = name {
        document.push_str(&format!("name: {name}\n"));
    }
    if let Some(description) = description {
        document.push_str(&format!("description: {description}\n"));
    }
    document.push_str("---\nInert body.\n");
    fs::write(package.join("SKILL.md"), document).unwrap();
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
        harnesses: BTreeSet::from([HarnessId::Codex]),
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

fn decide_document(
    directory: &str,
    name: Option<&str>,
    description: Option<&str>,
) -> CandidateDecision {
    let temp = tempdir();
    let root_path = temp.path().join("skills");
    write_skill(&root_path, directory, name, description);
    let source = root_path.join(directory);
    let captured = capture_skill_source(
        &SkillSource::Directory {
            path: source.clone(),
        },
        CaptureLimits::default(),
    )
    .unwrap();
    let root = ObservedRoot {
        logical_id: RootId::parse("codex.user.skills").unwrap(),
        path: root_path,
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: 20,
        enabled_layouts: BTreeSet::from(DIRECTORY_LAYOUT),
        evidence: evidence("codex.docs.skills.user"),
    };
    let locator = CandidateLocator {
        absolute_path: source,
        source_relative_path: directory.to_owned(),
        layout: SkillSourceLayout::Directory,
        original_document_name: "SKILL.md".to_owned(),
    };
    let policy = CodexObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();
    policy
        .decide_candidate(&captured, &locator, &root, &profile)
        .unwrap()
}

#[test]
fn shared_contract_covers_bundled_catalog_layouts_and_receipt_authority() {
    let fixture = FixtureBuilder::new()
        .repository()
        .user_root(".agents/skills")
        .directory_skill(
            "review",
            "---\nname: review\ndescription: Review changes.\n---\nInert body.\n",
        )
        .build()
        .unwrap();
    let bundled = fixture.root().join("bundled/skills");
    fs::create_dir_all(&bundled).unwrap();
    let user_anchor = fixture.home().join(".agents/skills");
    let project_anchor = fixture
        .repository_root()
        .expect("repository fixture")
        .join(".agents/skills");
    let directory_layouts = BTreeSet::from(DIRECTORY_LAYOUT);
    let case = PolicyContractCase::new(CodexObservationPolicy::new())
        .with_fixture(fixture)
        .expect_native_root(NativeRootExpectation {
            supplied: native_root(HarnessScope::User, &bundled),
            allowed_scopes: BTreeSet::from([HarnessScope::User]),
            unsupported_scope_finding: "codex.bundled_scope_unsupported".to_owned(),
            tier: RootTier::System,
            policy_rank: 40,
            enabled_layouts: directory_layouts,
            evidence: evidence("codex.docs.skills.bundled"),
        })
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::User,
            user_anchor,
            evidence("codex.docs.skills.user"),
        ))
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::Project,
            project_anchor,
            evidence("codex.docs.skills.project"),
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
    #[cfg(unix)]
    let case = case.allow_anchor("/etc/codex/skills");

    assert_policy_contract(case).unwrap();
}

#[test]
fn all_codex_tiers_are_observed_or_explicitly_unresolved() {
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
    let trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &[], &trust, &limits);
    let policy = CodexObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let roots = policy.roots(&context, &profile).unwrap();
    let unusual = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(profile.line(), PolicyLine::CodexCurrent);
    assert!(roots.iter().any(|root| root.tier == RootTier::Project));
    assert!(roots.iter().any(|root| root.tier == RootTier::User));
    #[cfg(unix)]
    {
        let admin = roots
            .iter()
            .find(|root| root.tier == RootTier::Admin)
            .unwrap();
        assert_eq!(admin.scope, HarnessScope::User);
        assert_eq!(admin.path, Path::new("/etc/codex/skills"));
    }
    #[cfg(windows)]
    assert!(roots.iter().all(|root| root.tier != RootTier::Admin));
    assert!(
        unusual
            .roots
            .iter()
            .all(|root| root.tier != RootTier::System)
    );
    assert_eq!(
        unusual
            .findings
            .iter()
            .filter(|finding| finding.code == "scan.root_unresolved")
            .count(),
        1
    );
    assert!(
        unusual
            .findings
            .iter()
            .any(|finding| finding.code == "codex.version_unknown")
    );
}

#[test]
fn supplied_bundled_root_is_system_user_scope_and_suppresses_unresolved_finding() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    let bundled = temp.path().join("bundled/skills");
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&bundled).unwrap();
    let supplied = vec![native_root(HarnessScope::User, &bundled)];
    let boundary = ProjectBoundary::Repository { root: repository };
    let limits = ScanLimits::default();
    let trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &supplied, &trust, &limits);
    let policy = CodexObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    let system = report
        .roots
        .iter()
        .find(|root| root.tier == RootTier::System)
        .unwrap();
    assert_eq!(system.scope, HarnessScope::User);
    assert_eq!(system.path, bundled);
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.root_unresolved")
    );
}

#[test]
fn bundled_provider_overflow_emits_one_budget_finding_and_stops_processing_the_tail() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let supplied = (0..128)
        .map(|index| {
            native_root(
                if index < 2 {
                    HarnessScope::User
                } else {
                    HarnessScope::Project
                },
                temp.path().join(format!("bundled-{index:03}/skills")),
            )
        })
        .collect::<Vec<_>>();
    let boundary = ProjectBoundary::Repository { root: repository };
    let limits = ScanLimits {
        max_roots: 1,
        max_findings: 2,
        ..ScanLimits::default()
    };
    let trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &supplied, &trust, &limits);
    let policy = CodexObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();
    let before = FilesystemSnapshot::capture(temp.path()).unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(FilesystemSnapshot::capture(temp.path()).unwrap(), before);
    assert_eq!(report.roots.len(), 1);
    assert_eq!(report.findings.len(), 2);
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "scan.root_budget_exhausted")
            .count(),
        1
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.code != "codex.bundled_scope_unsupported")
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.code != "scan.root_unresolved")
    );
}

#[test]
fn strict_standard_metadata_and_directory_match_gate_native_acceptance() {
    let valid = decide_document("review", Some("review"), Some("Review changes."));
    assert_eq!(valid.acceptance(), NativeAcceptance::Accepted);
    assert_eq!(valid.native_id(), Some("review"));
    assert!(matches!(
        valid.portable(),
        PortablePolicyDecision::Project { .. }
    ));

    for (decision, expected_code) in [
        (
            decide_document("review", Some("other"), Some("Review changes.")),
            "skill.directory_name_mismatch",
        ),
        (
            decide_document("review", None, Some("Review changes.")),
            "skill.name_invalid",
        ),
        (
            decide_document("review", Some("review"), None),
            "skill.description_invalid",
        ),
        (
            decide_document("Bad Name", Some("Bad Name"), Some("Review changes.")),
            "skill.name_invalid",
        ),
    ] {
        assert_eq!(decision.acceptance(), NativeAcceptance::Rejected);
        assert!(matches!(
            decision.portable(),
            PortablePolicyDecision::Unavailable { .. }
        ));
        assert!(
            decision
                .findings()
                .iter()
                .any(|finding| finding.code == expected_code)
        );
    }
}

#[test]
fn same_name_packages_across_tiers_coexist_without_shadow_or_conflict() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    let bundled = temp.path().join("bundled/skills");
    for root in [
        home.join(".agents/skills"),
        working.join(".agents/skills"),
        bundled.clone(),
    ] {
        write_skill(&root, "review", Some("review"), Some("Review changes."));
    }
    let request = request(
        &temp,
        working,
        repository,
        vec![native_root(HarnessScope::User, bundled)],
    );

    let report = test_engine(&CodexObservationPolicy::new())
        .scan(&request)
        .unwrap();
    let same_name = report
        .entries
        .iter()
        .filter(|entry| entry.native_id.as_deref() == Some("review"))
        .collect::<Vec<_>>();

    assert_eq!(same_name.len(), 3);
    assert!(
        same_name
            .iter()
            .all(|entry| entry.classification == ScanClassification::Unmanaged)
    );
    assert!(same_name.iter().all(|entry| entry.shadowed_by.is_none()));
    assert!(same_name.iter().all(|entry| {
        entry.findings.iter().all(|finding| {
            finding.code != "scan.candidate_shadowed" && finding.code != "scan.duplicate_ambiguous"
        })
    }));
}

#[test]
fn flat_markdown_stays_visible_as_unsupported() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    let skills = home.join(".agents/skills");
    fs::create_dir_all(&skills).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(skills.join("flat.md"), "Not a directory package.\n").unwrap();
    let request = request(&temp, working, repository, vec![]);

    let report = test_engine(&CodexObservationPolicy::new())
        .scan(&request)
        .unwrap();
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
fn agents_are_direct_toml_only_and_unknown_authority_blocks_projection() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("working");
    let agents = home.join(".codex/agents");
    fs::create_dir_all(agents.join("nested")).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        agents.join("review.toml"),
        "name = \"review\"\ndescription = \"Review changes.\"\ndeveloper_instructions = \"Review carefully.\\n\"\n",
    )
    .unwrap();
    fs::write(
        agents.join("authority.toml"),
        "name = \"authority\"\ndescription = \"Retain native authority.\"\ndeveloper_instructions = \"Stay native.\"\nmodel = \"powerful\"\n",
    )
    .unwrap();
    fs::write(
        agents.join("nested/hidden.toml"),
        "name = \"hidden\"\ndescription = \"Hidden.\"\ndeveloper_instructions = \"Ignore.\"\n",
    )
    .unwrap();

    let report = test_engine(&CodexObservationPolicy::new())
        .scan(&request(&temp, working, repository, vec![]))
        .unwrap();

    assert_eq!(report.agents.len(), 2);
    assert_eq!(report.agent_observations().len(), 2);
    assert!(report.agents.iter().all(|agent| {
        agent
            .source_relative_path
            .as_deref()
            .is_some_and(|path| !path.contains('/'))
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
fn receipt_anchors_are_only_standard_user_and_selected_valid_project_root() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("packages/app");
    let bundled = temp.path().join("bundled/skills");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&bundled).unwrap();
    let supplied = vec![native_root(HarnessScope::User, &bundled)];
    let boundary = ProjectBoundary::Repository {
        root: repository.clone(),
    };
    let limits = ScanLimits::default();
    let trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &supplied, &trust, &limits);
    let policy = CodexObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let anchors = policy.receipt_anchors(&context, &profile).unwrap();

    assert_eq!(anchors.len(), 2);
    assert!(anchors.iter().any(|anchor| {
        anchor.scope == HarnessScope::User && anchor.path == home.join(".agents/skills")
    }));
    assert!(anchors.iter().any(|anchor| {
        anchor.scope == HarnessScope::Project && anchor.path == repository.join(".agents/skills")
    }));
    assert!(
        anchors.iter().all(|anchor| {
            anchor.path != Path::new("/etc/codex/skills") && anchor.path != bundled
        })
    );
}

#[test]
fn invalid_repository_boundary_grants_no_project_root_or_receipt_anchor() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = temp.path().join("outside/work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(&working).unwrap();
    let boundary = ProjectBoundary::Repository { root: repository };
    let limits = ScanLimits::default();
    let trust = BTreeMap::new();
    let context = root_context(&home, &working, &boundary, &[], &trust, &limits);
    let policy = CodexObservationPolicy::new();
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
fn no_repository_and_unsafe_stop_keep_codex_project_roots_at_working_directory() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("outside/deep/work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let limits = ScanLimits::default();
    let trust = BTreeMap::new();
    let policy = CodexObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    for boundary in [ProjectBoundary::NoRepository, ProjectBoundary::UnsafeStop] {
        let context = root_context(&home, &working, &boundary, &[], &trust, &limits);
        let project_paths = policy
            .roots(&context, &profile)
            .unwrap()
            .into_iter()
            .filter(|root| root.scope == HarnessScope::Project)
            .map(|root| root.path)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            project_paths,
            BTreeSet::from([working.join(".agents/skills")])
        );
    }
}
