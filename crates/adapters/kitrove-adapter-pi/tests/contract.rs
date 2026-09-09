use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use kitrove_adapter_api::{
    EvidenceRef, ExplicitRoot, HarnessObservationPolicy, PolicyLine, ProjectBoundary,
    ProjectTrustKey, ProjectTrustObservation, RootContext, RootId, RootTier, ScanLimits,
    ScanRequest, ScopeSelection, VersionObservation,
};
use kitrove_adapter_pi::PiObservationPolicy;
use kitrove_agent_skills::SkillSourceLayout;
use kitrove_core::{ScanClassification, ScanEntry, ScanReport};
use kitrove_model::{HarnessId, HarnessScope};
use kitrove_testkit::{
    FilesystemSnapshot, FixtureBuilder, LocatorExpectation, LocatorProbe, PolicyContractCase,
    ReceiptAnchorExpectation, assert_policy_contract, test_engine,
};
use tempfile::TempDir;

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).unwrap()
}

fn tempdir() -> TempDir {
    let canonical_temp = std::env::temp_dir().canonicalize().unwrap();
    tempfile::tempdir_in(canonical_temp).unwrap()
}

fn valid_skill(name: &str, description: &str) -> String {
    format!("---\nname: {name}\ndescription: {description}\n---\nInert body.\n")
}

fn write_directory_skill(root: &Path, directory: &str, document: &str) -> PathBuf {
    let package = root.join(directory);
    fs::create_dir_all(&package).unwrap();
    fs::write(package.join("SKILL.md"), document).unwrap();
    package
}

fn request(
    temp: &TempDir,
    working_directory: PathBuf,
    project_boundary: ProjectBoundary,
    scopes: ScopeSelection,
    explicit_roots: Vec<ExplicitRoot>,
    project_trust: BTreeMap<ProjectTrustKey, ProjectTrustObservation>,
) -> ScanRequest<'static> {
    ScanRequest {
        home: Some(temp.path().join("home")),
        working_directory,
        project_boundary,
        harnesses: BTreeSet::from([HarnessId::Pi]),
        scopes,
        explicit_roots,
        supplied_native_roots: vec![],
        versions: BTreeMap::new(),
        project_trust,
        environment: None,
        local_state: None,
        limits: ScanLimits::default(),
    }
}

fn entry_has_finding(entry: &ScanEntry, code: &str) -> bool {
    entry.findings.iter().any(|finding| finding.code == code)
}

fn entry_for_native_id<'a>(report: &'a ScanReport, native_id: &str) -> &'a ScanEntry {
    report
        .entries
        .iter()
        .find(|entry| entry.native_id.as_deref() == Some(native_id))
        .unwrap_or_else(|| panic!("missing Pi entry for native ID {native_id}"))
}

#[test]
fn shared_policy_contract_covers_root_specific_layouts_and_receipt_authority() {
    let fixture = FixtureBuilder::new()
        .repository()
        .user_root(".pi/agent/skills")
        .directory_skill("review", valid_skill("review", "Review changes."))
        .build()
        .unwrap();
    fs::create_dir_all(fixture.home().join(".agents/skills")).unwrap();

    let native_user = RootId::parse("pi.user.native.skills").unwrap();
    let compatibility_user = RootId::parse("pi.user.compatibility.skills").unwrap();
    let user_anchor = fixture.home().join(".pi/agent/skills");
    let project_anchor = fixture
        .repository_root()
        .expect("repository fixture")
        .join(".pi/skills");
    let case = PolicyContractCase::new(PiObservationPolicy::new())
        .with_fixture(fixture)
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::User,
            user_anchor,
            evidence("pi.docs.skills.user-native"),
        ))
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::Project,
            project_anchor,
            evidence("pi.docs.skills.project-native"),
        ))
        .expect_locator(
            LocatorProbe::new(
                "quick.md",
                SkillSourceLayout::Standalone,
                "quick.md",
                LocatorExpectation::Supported,
            )
            .for_root(native_user.clone()),
        )
        .expect_locator(
            LocatorProbe::new(
                "group/quick.md",
                SkillSourceLayout::Standalone,
                "quick.md",
                LocatorExpectation::Unsupported,
            )
            .for_root(native_user),
        )
        .expect_locator(
            LocatorProbe::new(
                "flat.md",
                SkillSourceLayout::Standalone,
                "flat.md",
                LocatorExpectation::Unsupported,
            )
            .for_root(compatibility_user.clone()),
        )
        .expect_locator(
            LocatorProbe::new(
                "group/compat.md",
                SkillSourceLayout::Standalone,
                "compat.md",
                LocatorExpectation::Supported,
            )
            .for_root(compatibility_user),
        );

    assert_policy_contract(case).unwrap();
}

#[test]
fn native_and_compatibility_roots_enforce_direct_and_grouping_positions() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let native = home.join(".pi/agent/skills");
    let compatibility = home.join(".agents/skills");
    fs::create_dir_all(compatibility.join("group")).unwrap();
    fs::create_dir_all(&native).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        native.join("native.md"),
        valid_skill("native", "Native skill."),
    )
    .unwrap();
    fs::write(
        native.join("nested.md.ignore"),
        valid_skill("not-markdown", "Not Markdown."),
    )
    .unwrap();
    fs::write(
        compatibility.join("flat.md"),
        valid_skill("flat", "Unsupported direct compatibility skill."),
    )
    .unwrap();
    fs::write(
        compatibility.join("group/compat.md"),
        valid_skill("compat", "Grouped compatibility skill."),
    )
    .unwrap();
    write_directory_skill(
        &compatibility,
        "group/package",
        &valid_skill("nested-pi", "Nested Pi directory package."),
    );
    fs::write(
        native.join("plain.md"),
        "# ordinary Markdown\nNo frontmatter.\n",
    )
    .unwrap();

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            vec![],
            BTreeMap::new(),
        ))
        .unwrap();

    let native = entry_for_native_id(&report, "native");
    let compat = entry_for_native_id(&report, "compat");
    assert_eq!(native.classification, ScanClassification::Unmanaged);
    assert_eq!(native.layout, Some(SkillSourceLayout::Standalone));
    assert_eq!(compat.classification, ScanClassification::Unmanaged);
    assert_eq!(
        compat.source_relative_path.as_deref(),
        Some("group/compat.md")
    );
    assert_eq!(
        entry_for_native_id(&report, "nested-pi")
            .source_relative_path
            .as_deref(),
        Some("group/package")
    );
    assert!(
        !report
            .entries
            .iter()
            .any(|entry| entry.source_relative_path.as_deref() == Some("group"))
    );

    let flat = report
        .entries
        .iter()
        .find(|entry| entry.source_relative_path.as_deref() == Some("flat.md"))
        .unwrap();
    assert_eq!(flat.classification, ScanClassification::Unknown);
    assert!(entry_has_finding(flat, "scan.layout_unsupported"));
    assert!(
        !report
            .entries
            .iter()
            .any(|entry| entry.source_relative_path.as_deref() == Some("plain.md"))
    );
}

#[test]
fn standalone_hint_accepts_only_exact_lf_or_crlf_opening_delimiters() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let native = home.join(".pi/agent/skills");
    let working = temp.path().join("working");
    fs::create_dir_all(&native).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        native.join("crlf.md"),
        "---\r\nname: crlf\r\ndescription: CRLF skill.\r\n---\r\nInert.\r\n",
    )
    .unwrap();
    fs::write(
        native.join("indented.md"),
        " ---\nname: indented\ndescription: Not hinted.\n---\nInert.\n",
    )
    .unwrap();

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            vec![],
            BTreeMap::new(),
        ))
        .unwrap();

    assert_eq!(
        entry_for_native_id(&report, "crlf").classification,
        ScanClassification::Unmanaged
    );
    assert!(
        !report
            .entries
            .iter()
            .any(|entry| entry.source_relative_path.as_deref() == Some("indented.md"))
    );
}

#[test]
fn repository_project_roots_stop_compatibility_ascent_at_the_repository_boundary() {
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
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::Project,
        explicit_roots: &[],
        supplied_native_roots: &[],
        project_trust: &trust,
        limits: &limits,
    };
    let policy = PiObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let roots = policy.roots(&context, &profile).unwrap();

    assert_eq!(profile.line(), PolicyLine::PiLatest);
    assert!(roots.iter().any(|root| {
        root.tier == RootTier::Project && root.path == repository.join(".pi/skills")
    }));
    let compatibility_paths = roots
        .iter()
        .filter(|root| root.tier == RootTier::Compatibility)
        .map(|root| root.path.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        compatibility_paths,
        BTreeSet::from([
            working.join(".agents/skills"),
            repository.join("packages/.agents/skills"),
            repository.join(".agents/skills"),
        ])
    );
    assert!(!compatibility_paths.contains(&temp.path().join(".agents/skills")));
}

#[test]
fn no_repository_project_compatibility_roots_ascend_to_the_filesystem_root() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("outside/deep/work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let boundary = ProjectBoundary::NoRepository;
    let limits = ScanLimits::default();
    let trust = BTreeMap::new();
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::Project,
        explicit_roots: &[],
        supplied_native_roots: &[],
        project_trust: &trust,
        limits: &limits,
    };
    let policy = PiObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let roots = policy.roots(&context, &profile).unwrap();
    let compatibility = roots
        .iter()
        .filter(|root| root.tier == RootTier::Compatibility)
        .collect::<Vec<_>>();

    assert!(
        compatibility
            .iter()
            .any(|root| root.path == working.join(".agents/skills"))
    );
    let filesystem_root = working.ancestors().last().unwrap().join(".agents/skills");
    assert!(
        compatibility
            .iter()
            .any(|root| root.path == filesystem_root)
    );
    assert!(compatibility.len() <= limits.max_roots.saturating_sub(1));
}

#[test]
fn unsafe_stop_project_compatibility_roots_do_not_ascend() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("outside/deep/work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let boundary = ProjectBoundary::UnsafeStop;
    let limits = ScanLimits::default();
    let trust = BTreeMap::new();
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::Project,
        explicit_roots: &[],
        supplied_native_roots: &[],
        project_trust: &trust,
        limits: &limits,
    };
    let policy = PiObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let roots = policy.roots(&context, &profile).unwrap();
    let compatibility_paths = roots
        .iter()
        .filter(|root| root.tier == RootTier::Compatibility)
        .map(|root| root.path.clone())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        compatibility_paths,
        BTreeSet::from([working.join(".agents/skills")])
    );
}

#[test]
fn all_scope_deduplicates_user_compatibility_root_reached_by_project_ascent() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = home.join("projects/app");
    let compatibility = home.join(".agents/skills");
    fs::create_dir_all(compatibility.join("group")).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        compatibility.join("group/shared.md"),
        valid_skill("shared", "One physical compatibility skill."),
    )
    .unwrap();

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::All,
            vec![],
            BTreeMap::new(),
        ))
        .unwrap();
    let shared = report
        .entries
        .iter()
        .filter(|entry| entry.native_id.as_deref() == Some("shared"))
        .collect::<Vec<_>>();

    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].scope, HarnessScope::User);
    assert_eq!(shared[0].root_tier, Some(RootTier::Compatibility));
    assert_eq!(
        shared[0].logical_root.as_ref().map(RootId::as_str),
        Some("pi.user.compatibility.skills")
    );
    assert!(!entry_has_finding(shared[0], "scan.duplicate_ambiguous"));
}

#[test]
fn explicit_directory_and_single_file_roots_capture_only_the_supplied_sources() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let directory_root = temp.path().join("explicit-directory");
    let file_parent = temp.path().join("explicit-files");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&directory_root).unwrap();
    fs::create_dir_all(&file_parent).unwrap();
    write_directory_skill(
        &directory_root,
        "directory-skill",
        &valid_skill("directory-skill", "Explicit directory skill."),
    );
    fs::write(
        directory_root.join("flat.md"),
        valid_skill("flat", "A directory root does not enable flat files."),
    )
    .unwrap();
    let selected_file = file_parent.join("selected.md");
    fs::write(
        &selected_file,
        valid_skill("selected", "Explicit standalone skill."),
    )
    .unwrap();
    fs::write(
        file_parent.join("sibling.md"),
        valid_skill("sibling", "Must not be captured."),
    )
    .unwrap();
    let explicit_roots = vec![
        ExplicitRoot::new(HarnessId::Pi, HarnessScope::User, directory_root),
        ExplicitRoot::new(HarnessId::Pi, HarnessScope::User, selected_file),
    ];

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            explicit_roots,
            BTreeMap::new(),
        ))
        .unwrap();

    assert_eq!(
        entry_for_native_id(&report, "directory-skill").classification,
        ScanClassification::Unmanaged
    );
    assert_eq!(
        entry_for_native_id(&report, "selected").classification,
        ScanClassification::Unmanaged
    );
    assert!(!report.entries.iter().any(|entry| {
        entry.native_id.as_deref() == Some("sibling")
            || entry.source_relative_path.as_deref() == Some("sibling.md")
    }));
    let flat = report
        .entries
        .iter()
        .find(|entry| entry.source_relative_path.as_deref() == Some("flat.md"))
        .unwrap();
    assert!(entry_has_finding(flat, "scan.layout_unsupported"));
}

#[test]
fn reversed_sibling_explicit_files_are_both_authorized_and_reported_canonically() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let file_parent = temp.path().join("explicit-files");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&file_parent).unwrap();
    let alpha = file_parent.join("alpha.md");
    let beta = file_parent.join("beta.md");
    fs::write(&alpha, valid_skill("alpha", "First explicit skill.")).unwrap();
    fs::write(&beta, valid_skill("beta", "Second explicit skill.")).unwrap();

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            vec![
                ExplicitRoot::new(HarnessId::Pi, HarnessScope::User, beta),
                ExplicitRoot::new(HarnessId::Pi, HarnessScope::User, alpha),
            ],
            BTreeMap::new(),
        ))
        .unwrap();

    assert_eq!(
        report
            .entries
            .iter()
            .map(|entry| entry.native_id.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["beta", "alpha"]
    );
    assert_eq!(
        report
            .entries
            .iter()
            .map(|entry| entry.logical_root.as_ref().unwrap().as_str())
            .collect::<Vec<_>>(),
        [
            "pi.explicit.file.0000.626574612e6d64",
            "pi.explicit.file.0001.616c7068612e6d64",
        ]
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.code != "scan.policy_root_conflict")
    );
}

#[test]
fn explicit_skill_document_file_takes_precedence_over_directory_principal_suppression() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let explicit_parent = temp.path().join("explicit");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&explicit_parent).unwrap();
    let selected = explicit_parent.join("SKILL.md");
    fs::write(
        &selected,
        valid_skill("explicit-skill", "Explicit principal document."),
    )
    .unwrap();

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            vec![ExplicitRoot::new(
                HarnessId::Pi,
                HarnessScope::User,
                selected,
            )],
            BTreeMap::new(),
        ))
        .unwrap();
    let entry = entry_for_native_id(&report, "explicit-skill");

    assert_eq!(entry.classification, ScanClassification::Unmanaged);
    assert_eq!(entry.root_tier, Some(RootTier::Explicit));
    assert_eq!(entry.layout, Some(SkillSourceLayout::Standalone));
    assert_eq!(entry.source_relative_path.as_deref(), Some("SKILL.md"));
}

#[test]
fn explicit_root_and_finding_budgets_count_invalid_inputs_and_stop_before_the_tail() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let tail = temp.path().join("tail");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&tail).unwrap();
    let mut explicit_roots = vec![ExplicitRoot::new(
        HarnessId::Pi,
        HarnessScope::User,
        temp.path().join("missing-first.md"),
    )];
    for index in 0..127 {
        let unsupported = tail.join(format!("unsupported-{index:03}.txt"));
        fs::write(&unsupported, b"ordinary file\n").unwrap();
        explicit_roots.push(ExplicitRoot::new(
            HarnessId::Pi,
            HarnessScope::User,
            unsupported,
        ));
    }
    let boundary = ProjectBoundary::NoRepository;
    let trust = BTreeMap::new();
    let policy = PiObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();
    let before = FilesystemSnapshot::capture(temp.path()).unwrap();
    let limits = [
        ScanLimits {
            max_roots: 1,
            ..ScanLimits::default()
        },
        ScanLimits {
            max_roots: 128,
            max_findings: 3,
            ..ScanLimits::default()
        },
    ];

    for limits in &limits {
        let context = RootContext {
            home: Some(&home),
            working_directory: &working,
            project_boundary: &boundary,
            scopes: ScopeSelection::User,
            explicit_roots: &explicit_roots,
            supplied_native_roots: &[],
            project_trust: &trust,
            limits,
        };
        let report = policy.discover_unusual_roots(&context, &profile).unwrap();

        assert_eq!(FilesystemSnapshot::capture(temp.path()).unwrap(), before);
        assert!(report.roots.is_empty());
        assert_eq!(report.findings.len(), 3);
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.code == "scan.discovery_unsafe_path")
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
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.code != "scan.layout_unsupported")
        );
    }
}

fn scan_project_with_trust(trust: Option<ProjectTrustObservation>) -> ScanReport {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    write_directory_skill(
        &repository.join(".pi/skills"),
        "review",
        &valid_skill("review", "Review project changes."),
    );
    fs::create_dir_all(repository.join(".pi/extensions")).unwrap();
    fs::write(
        repository.join(".pi/extensions/review.ts"),
        b"export default {};\n",
    )
    .unwrap();
    let key = ProjectTrustKey {
        harness: HarnessId::Pi,
        project_anchor: repository.clone(),
    };
    let project_trust = trust
        .map(|observation| BTreeMap::from([(key, observation)]))
        .unwrap_or_default();
    test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::Repository { root: repository },
            ScopeSelection::Project,
            vec![],
            project_trust,
        ))
        .unwrap()
}

#[test]
fn trusted_project_candidate_needs_no_trust_finding() {
    let report = scan_project_with_trust(Some(ProjectTrustObservation::Trusted {
        evidence: evidence("fixture.pi.trust-trusted"),
    }));
    let entry = entry_for_native_id(&report, "review");

    assert_eq!(entry.classification, ScanClassification::Unmanaged);
    assert!(!entry_has_finding(entry, "pi.project_trust_unknown"));
    assert!(!entry_has_finding(entry, "pi.project_trust_declined"));
}

#[test]
fn declined_project_trust_keeps_the_candidate_but_requires_attention() {
    let report = scan_project_with_trust(Some(ProjectTrustObservation::Declined {
        evidence: evidence("fixture.pi.trust-declined"),
    }));
    let entry = entry_for_native_id(&report, "review");

    assert_eq!(entry.classification, ScanClassification::Unmanaged);
    assert!(entry_has_finding(entry, "pi.project_trust_declined"));
}

#[test]
fn absent_and_explicit_unknown_project_trust_are_equally_conservative() {
    let absent = scan_project_with_trust(None);
    let unknown = scan_project_with_trust(Some(ProjectTrustObservation::Unknown));

    for report in [&absent, &unknown] {
        let entry = entry_for_native_id(report, "review");
        assert_eq!(entry.classification, ScanClassification::Unmanaged);
        assert!(entry_has_finding(entry, "pi.project_trust_unknown"));
        assert!(!entry_has_finding(entry, "pi.project_trust_declined"));
    }
}

#[test]
fn project_extension_portable_identity_excludes_local_trust_state() {
    let trusted = scan_project_with_trust(Some(ProjectTrustObservation::Trusted {
        evidence: evidence("fixture.pi.trust-trusted"),
    }));
    let declined = scan_project_with_trust(Some(ProjectTrustObservation::Declined {
        evidence: evidence("fixture.pi.trust-declined"),
    }));
    let unknown = scan_project_with_trust(Some(ProjectTrustObservation::Unknown));

    let extensions = [&trusted, &declined, &unknown].map(|report| {
        report
            .native_extensions
            .iter()
            .find(|extension| extension.native_id == "review")
            .unwrap()
    });
    for extension in extensions {
        assert_eq!(
            extension.logical_root.as_str(),
            "pi.project.native.extensions"
        );
    }
    assert_eq!(
        trusted.native_extensions[0].observation_identity,
        declined.native_extensions[0].observation_identity
    );
    assert_eq!(
        trusted.native_extensions[0].observation_identity,
        unknown.native_extensions[0].observation_identity
    );
}

#[test]
fn declared_name_is_native_identity_and_container_mismatch_is_preserved() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let native = home.join(".pi/agent/skills");
    fs::create_dir_all(&working).unwrap();
    write_directory_skill(
        &native,
        "container",
        &valid_skill("declared", "Declared Pi identity."),
    );

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            vec![],
            BTreeMap::new(),
        ))
        .unwrap();
    let entry = entry_for_native_id(&report, "declared");

    assert_eq!(entry.classification, ScanClassification::Unmanaged);
    assert!(entry.portable_hash.is_some());
    assert!(entry_has_finding(entry, "skill.native_name_differs"));
}

#[test]
fn missing_declared_name_or_description_is_rejected_with_stable_findings() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let native = home.join(".pi/agent/skills");
    fs::create_dir_all(&working).unwrap();
    write_directory_skill(
        &native,
        "missing-name",
        "---\ndescription: Missing name.\n---\nInert.\n",
    );
    write_directory_skill(
        &native,
        "missing-description",
        "---\nname: missing-description\n---\nInert.\n",
    );

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            vec![],
            BTreeMap::new(),
        ))
        .unwrap();

    assert!(report.entries.iter().any(|entry| {
        entry.classification == ScanClassification::Unknown
            && entry.source_relative_path.as_deref() == Some("missing-name")
            && entry_has_finding(entry, "skill.name_invalid")
    }));
    assert!(report.entries.iter().any(|entry| {
        entry.classification == ScanClassification::Unknown
            && entry.source_relative_path.as_deref() == Some("missing-description")
            && entry_has_finding(entry, "skill.description_invalid")
    }));
}

#[test]
fn duplicate_declared_names_remain_visible_and_ambiguous() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let native = home.join(".pi/agent/skills");
    fs::create_dir_all(&working).unwrap();
    write_directory_skill(&native, "first", &valid_skill("shared", "First copy."));
    write_directory_skill(&native, "second", &valid_skill("shared", "Second copy."));

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            vec![],
            BTreeMap::new(),
        ))
        .unwrap();
    let duplicates = report
        .entries
        .iter()
        .filter(|entry| entry.native_id.as_deref() == Some("shared"))
        .collect::<Vec<_>>();

    assert_eq!(duplicates.len(), 2);
    assert!(
        duplicates
            .iter()
            .all(|entry| entry.classification == ScanClassification::Unmanaged)
    );
    assert!(
        duplicates
            .iter()
            .all(|entry| entry_has_finding(entry, "scan.duplicate_ambiguous"))
    );
    assert!(duplicates.iter().all(|entry| entry.shadowed_by.is_none()));
}

#[test]
fn receipt_anchors_exclude_compatibility_and_explicit_roots() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("packages/app");
    let explicit = temp.path().join("explicit");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&explicit).unwrap();
    let boundary = ProjectBoundary::Repository {
        root: repository.clone(),
    };
    let explicit_roots = [ExplicitRoot::new(
        HarnessId::Pi,
        HarnessScope::Project,
        explicit.clone(),
    )];
    let limits = ScanLimits::default();
    let trust = BTreeMap::new();
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::All,
        explicit_roots: &explicit_roots,
        supplied_native_roots: &[],
        project_trust: &trust,
        limits: &limits,
    };
    let policy = PiObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let anchors = policy.receipt_anchors(&context, &profile).unwrap();

    assert_eq!(anchors.len(), 2);
    assert!(anchors.iter().any(|anchor| {
        anchor.scope == HarnessScope::User && anchor.path == home.join(".pi/agent/skills")
    }));
    assert!(anchors.iter().any(|anchor| {
        anchor.scope == HarnessScope::Project && anchor.path == repository.join(".pi/skills")
    }));
    assert!(anchors.iter().all(|anchor| {
        anchor.path != home.join(".agents/skills")
            && anchor.path != repository.join(".agents/skills")
            && anchor.path != explicit
    }));
}

#[test]
fn user_prompt_discovery_is_limited_to_direct_markdown_children() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let prompts = home.join(".pi/agent/prompts");
    fs::create_dir_all(prompts.join("nested")).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(prompts.join("direct.md"), "Direct prompt.\n").unwrap();
    fs::write(prompts.join("nested/ignored.md"), "Nested prompt.\n").unwrap();

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            vec![],
            BTreeMap::new(),
        ))
        .unwrap();
    let commands = &report.prompt_commands;

    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].source_relative_path, "direct.md");
    assert_eq!(commands[0].scope, HarnessScope::User);
    assert_eq!(commands[0].logical_root.as_str(), "pi.user.native.commands");
    assert!(commands[0].portable_hash.is_some());
}

#[test]
fn plain_agent_files_do_not_imply_the_optional_executable_registry() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let agents = home.join(".pi/agent/agents");
    fs::create_dir_all(&agents).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        agents.join("review.md"),
        "---\nname: review\ndescription: Review changes.\n---\nReview carefully.\n",
    )
    .unwrap();

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            vec![],
            BTreeMap::new(),
        ))
        .unwrap();

    assert!(report.agents.is_empty());
    assert!(report.agent_observations().is_empty());
}

#[test]
fn prompt_capture_obeys_the_request_wide_byte_limit() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let prompts = home.join(".pi/agent/prompts");
    fs::create_dir_all(&prompts).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(prompts.join("review.md"), "Review this prompt.\n").unwrap();
    let mut request = request(
        &temp,
        working,
        ProjectBoundary::NoRepository,
        ScopeSelection::User,
        vec![],
        BTreeMap::new(),
    );
    request.limits.capture.max_total_bytes = 4;

    let report = test_engine(&PiObservationPolicy::new())
        .scan(&request)
        .unwrap();

    assert!(report.prompt_commands.is_empty());
    assert_eq!(report.related.len(), 1);
    assert!(
        report.related[0]
            .findings
            .iter()
            .any(|finding| finding.code == "scan.prompt_command_capture_limit")
    );
    assert_eq!(report.capture_usage().file_attempts, 1);
    assert_eq!(report.capture_usage().bytes_read, 0);
}

#[test]
fn project_prompt_capture_requires_verified_project_trust() {
    for (trust, expected_commands) in [
        (
            Some(ProjectTrustObservation::Trusted {
                evidence: evidence("fixture.pi.command-trusted"),
            }),
            1,
        ),
        (
            Some(ProjectTrustObservation::Declined {
                evidence: evidence("fixture.pi.command-declined"),
            }),
            0,
        ),
        (None, 0),
    ] {
        let temp = tempdir();
        let repository = temp.path().join("repo");
        let working = repository.join("packages/app");
        let prompts = repository.join(".pi/prompts");
        fs::create_dir_all(&prompts).unwrap();
        fs::create_dir_all(&working).unwrap();
        fs::write(prompts.join("review.md"), "Review $ARGUMENTS.\n").unwrap();
        let project_trust = trust
            .map(|observation| {
                BTreeMap::from([(
                    ProjectTrustKey {
                        harness: HarnessId::Pi,
                        project_anchor: repository.clone(),
                    },
                    observation,
                )])
            })
            .unwrap_or_default();

        let report = test_engine(&PiObservationPolicy::new())
            .scan(&request(
                &temp,
                working,
                ProjectBoundary::Repository { root: repository },
                ScopeSelection::Project,
                vec![],
                project_trust,
            ))
            .unwrap();

        assert_eq!(report.prompt_commands.len(), expected_commands);
    }
}
