use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use kitrove_adapter_api::{
    EvidenceRef, ExplicitRoot, HarnessObservationPolicy, HarnessVersion, NativeRootKey, PolicyLine,
    ProjectBoundary, RootContext, RootId, RootTier, ScanLimits, ScanRequest, ScopeSelection,
    SuppliedNativeRoot, VerifiedVersionEvidence, VersionObservation, VersionObservationOwned,
};
use kitrove_adapter_opencode::OpenCodeObservationPolicy;
use kitrove_agent_skills::SkillSourceLayout;
use kitrove_core::{ScanClassification, ScanEntry, ScanReport};
use kitrove_model::{AssetKind, HarnessId, HarnessScope};
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

fn v2_skill(display_name: Option<&str>, description: Option<&str>) -> String {
    let mut document = String::from("---\n");
    if let Some(name) = display_name {
        document.push_str(&format!("name: {name}\n"));
    }
    if let Some(description) = description {
        document.push_str(&format!("description: {description}\n"));
    }
    document.push_str("---\nInert body.\n");
    document
}

fn write_directory_skill(root: &Path, relative: &str, document: &str) -> PathBuf {
    let package = root.join(relative);
    fs::create_dir_all(&package).unwrap();
    fs::write(package.join("SKILL.md"), document).unwrap();
    package
}

fn verified(line: PolicyLine) -> VerifiedVersionEvidence {
    VerifiedVersionEvidence::new(
        HarnessId::OpenCode,
        HarnessVersion::parse(match line {
            PolicyLine::OpenCodeCurrent => "current-fixture",
            PolicyLine::OpenCodeV2 => "v2-fixture",
            _ => unreachable!(),
        })
        .unwrap(),
        line,
        evidence(match line {
            PolicyLine::OpenCodeCurrent => "fixture.opencode.current",
            PolicyLine::OpenCodeV2 => "fixture.opencode.v2",
            _ => unreachable!(),
        }),
    )
    .unwrap()
}

fn native_root(scope: HarnessScope, key: &str, path: impl Into<PathBuf>) -> SuppliedNativeRoot {
    SuppliedNativeRoot::new(
        HarnessId::OpenCode,
        scope,
        NativeRootKey::parse(key).unwrap(),
        path.into(),
    )
}

fn request(
    temp: &TempDir,
    working_directory: PathBuf,
    project_boundary: ProjectBoundary,
    scopes: ScopeSelection,
    version: Option<VerifiedVersionEvidence>,
    explicit_roots: Vec<ExplicitRoot>,
    supplied_native_roots: Vec<SuppliedNativeRoot>,
) -> ScanRequest<'static> {
    let versions = version
        .map(|version| BTreeMap::from([(HarnessId::OpenCode, version)]))
        .unwrap_or_default();
    ScanRequest {
        home: Some(temp.path().join("home")),
        working_directory,
        project_boundary,
        harnesses: BTreeSet::from([HarnessId::OpenCode]),
        scopes,
        explicit_roots,
        supplied_native_roots,
        versions,
        project_trust: BTreeMap::new(),
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
        .unwrap_or_else(|| panic!("missing OpenCode entry for native ID {native_id}"))
}

#[test]
fn profiles_require_typed_evidence_and_unknown_stays_current() {
    let policy = OpenCodeObservationPolicy::new();
    let unknown = policy.profile(VersionObservation::Unknown).unwrap();
    let current_evidence = verified(PolicyLine::OpenCodeCurrent);
    let current = policy
        .profile(VersionObservation::Verified(&current_evidence))
        .unwrap();
    let v2_evidence = verified(PolicyLine::OpenCodeV2);
    let v2 = policy
        .profile(VersionObservation::Verified(&v2_evidence))
        .unwrap();

    assert_eq!(unknown.line(), PolicyLine::OpenCodeCurrent);
    assert!(matches!(
        unknown.version(),
        VersionObservationOwned::Unknown
    ));
    assert_eq!(current.line(), PolicyLine::OpenCodeCurrent);
    assert_eq!(v2.line(), PolicyLine::OpenCodeV2);
    assert!(
        VerifiedVersionEvidence::new(
            HarnessId::OpenCode,
            HarnessVersion::parse("mismatch").unwrap(),
            PolicyLine::ClaudeCurrent,
            evidence("fixture.mismatch"),
        )
        .is_err()
    );
}

#[test]
fn shared_unknown_policy_contract_covers_common_roots_and_native_receipt_authority() {
    let fixture = FixtureBuilder::new()
        .repository()
        .user_root(".config/opencode/skills")
        .directory_skill("review", valid_skill("review", "Review changes."))
        .build()
        .unwrap();
    for path in [
        fixture.home().join(".claude/skills"),
        fixture.home().join(".agents/skills"),
    ] {
        fs::create_dir_all(path).unwrap();
    }
    let user_anchor = fixture.home().join(".config/opencode/skills");
    let project_anchor = fixture
        .repository_root()
        .expect("repository fixture")
        .join(".opencode/skills");
    let native_user = RootId::parse("opencode.user.native.skills").unwrap();
    let case = PolicyContractCase::new(OpenCodeObservationPolicy::new())
        .with_fixture(fixture)
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::User,
            user_anchor,
            evidence("opencode.docs.skills.user-native"),
        ))
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::Project,
            project_anchor,
            evidence("opencode.docs.skills.project-native"),
        ))
        .expect_locator(
            LocatorProbe::new(
                "review",
                SkillSourceLayout::Directory,
                "SKILL.md",
                LocatorExpectation::Supported,
            )
            .for_root(native_user.clone()),
        )
        .expect_locator(
            LocatorProbe::new(
                "review.md",
                SkillSourceLayout::Standalone,
                "review.md",
                LocatorExpectation::Unsupported,
            )
            .for_root(native_user),
        );

    assert_policy_contract(case).unwrap();
}

#[test]
fn unknown_profile_reports_v2_flat_file_without_accepting_it() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let native = home.join(".config/opencode/skills");
    fs::create_dir_all(&native).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        native.join("v2-flat.md"),
        v2_skill(Some("v2-flat"), Some("V2-only flat skill.")),
    )
    .unwrap();

    let report = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            None,
            vec![],
            vec![],
        ))
        .unwrap();
    let entry = report
        .entries
        .iter()
        .find(|entry| entry.source_relative_path.as_deref() == Some("v2-flat.md"))
        .unwrap();

    assert_eq!(entry.classification, ScanClassification::Unknown);
    assert!(entry.native_id.is_none());
    assert!(entry_has_finding(entry, "scan.layout_unsupported"));
}

#[test]
fn current_requires_standard_matching_directory_identity_and_reports_ambiguity() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let native = home.join(".config/opencode/skills");
    let compatibility = home.join(".claude/skills");
    fs::create_dir_all(&working).unwrap();
    write_directory_skill(
        &native,
        "shared",
        &valid_skill("shared", "Native current copy."),
    );
    write_directory_skill(
        &compatibility,
        "shared",
        &valid_skill("shared", "Compatibility current copy."),
    );
    write_directory_skill(
        &native,
        "container",
        &valid_skill("declared", "Mismatched current copy."),
    );

    let report = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            Some(verified(PolicyLine::OpenCodeCurrent)),
            vec![],
            vec![],
        ))
        .unwrap();
    let shared = report
        .entries
        .iter()
        .filter(|entry| entry.native_id.as_deref() == Some("shared"))
        .collect::<Vec<_>>();

    assert_eq!(shared.len(), 2);
    assert!(shared.iter().all(|entry| entry.shadowed_by.is_none()));
    assert!(
        shared
            .iter()
            .all(|entry| entry_has_finding(entry, "scan.duplicate_ambiguous"))
    );
    let mismatch = report
        .entries
        .iter()
        .find(|entry| entry.source_relative_path.as_deref() == Some("container"))
        .unwrap();
    assert_eq!(mismatch.classification, ScanClassification::Unknown);
    assert!(entry_has_finding(mismatch, "skill.directory_name_mismatch"));
}

#[test]
fn verified_v2_accepts_root_markdown_nested_skill_documents_and_exact_case_ids() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let native = home.join(".config/opencode/skills");
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&native).unwrap();
    fs::write(
        native.join("Release.md"),
        v2_skill(Some("display-name"), Some("Standalone release.")),
    )
    .unwrap();
    write_directory_skill(
        &native,
        "teams/release",
        &v2_skill(None, Some("Nested release.")),
    );
    write_directory_skill(
        &native,
        "teams/Review",
        &v2_skill(None, Some("Uppercase nested review.")),
    );
    fs::create_dir_all(native.join("teams/support")).unwrap();

    let report = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            Some(verified(PolicyLine::OpenCodeV2)),
            vec![],
            vec![],
        ))
        .unwrap();

    assert_eq!(
        entry_for_native_id(&report, "Release").classification,
        ScanClassification::Unmanaged
    );
    assert_eq!(
        entry_for_native_id(&report, "release").classification,
        ScanClassification::Unmanaged
    );
    assert!(!report.entries.iter().any(|entry| {
        matches!(
            entry.source_relative_path.as_deref(),
            Some("teams") | Some("teams/support")
        )
    }));
    assert_eq!(
        entry_for_native_id(&report, "Review").classification,
        ScanClassification::Unmanaged
    );
    assert!(report.findings.iter().any(|finding| {
        finding.code == "scan.root_unresolved"
            && matches!(
                finding.subject,
                kitrove_adapter_api::FindingSubject::Root(_)
            )
    }));
}

#[test]
fn v2_native_candidate_without_description_is_retained_without_inventing_portable_content() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let native = home.join(".config/opencode/skills");
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&native).unwrap();
    fs::write(native.join("native-only.md"), "# Native-only\n").unwrap();

    let report = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            Some(verified(PolicyLine::OpenCodeV2)),
            vec![],
            vec![],
        ))
        .unwrap();
    let entry = entry_for_native_id(&report, "native-only");

    assert_eq!(entry.classification, ScanClassification::Unmanaged);
    assert!(entry.exact_source_hash.is_some());
    assert!(entry.portable_hash.is_none());
    assert!(entry_has_finding(
        entry,
        "opencode.portable_projection_unavailable"
    ));
}

#[test]
fn verified_v2_uses_later_source_winner_and_retains_every_shadow() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("packages/app");
    fs::create_dir_all(&working).unwrap();
    write_directory_skill(
        &home.join(".claude/skills"),
        "duplicate-release",
        &v2_skill(None, Some("Claude global.")),
    );
    write_directory_skill(
        &home.join(".config/opencode/skills"),
        "duplicate-release",
        &v2_skill(None, Some("OpenCode global.")),
    );
    write_directory_skill(
        &working.join(".opencode/skills"),
        "duplicate-release",
        &v2_skill(None, Some("Nearest OpenCode project.")),
    );

    let report = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::Repository { root: repository },
            ScopeSelection::All,
            Some(verified(PolicyLine::OpenCodeV2)),
            vec![],
            vec![],
        ))
        .unwrap();
    let duplicates = report
        .entries
        .iter()
        .filter(|entry| entry.native_id.as_deref() == Some("duplicate-release"))
        .collect::<Vec<_>>();
    let winner = duplicates
        .iter()
        .find(|entry| entry.shadowed_by.is_none())
        .unwrap();

    assert_eq!(duplicates.len(), 3);
    assert_eq!(winner.scope, HarnessScope::Project);
    assert_eq!(winner.root_tier, Some(RootTier::Project));
    assert!(
        duplicates
            .iter()
            .filter(|entry| entry.shadowed_by.is_some())
            .count()
            == 2
    );
    assert!(
        duplicates
            .iter()
            .filter(|entry| entry.shadowed_by.is_some())
            .all(|entry| {
                entry.shadowed_by.as_ref() == winner.observation_id.as_ref()
                    && entry_has_finding(entry, "scan.candidate_shadowed")
            })
    );
}

#[test]
fn v2_coincident_explicit_root_is_scanned_once_and_keeps_later_precedence() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let user_native = home.join(".config/opencode/skills");
    let project_native = working.join(".opencode/skills");
    fs::create_dir_all(&working).unwrap();
    let built_in_providers = (0..3)
        .map(|index| {
            let path = temp.path().join(format!("built-in-{index}"));
            fs::create_dir_all(&path).unwrap();
            native_root(HarnessScope::User, "opencode-v2.built-in", path)
        })
        .collect::<Vec<_>>();
    write_directory_skill(
        &user_native,
        "coincident",
        &v2_skill(None, Some("Explicit copy coincident with the user root.")),
    );
    write_directory_skill(
        &project_native,
        "coincident",
        &v2_skill(None, Some("Project OpenCode copy.")),
    );

    let mut scan_request = request(
        &temp,
        working,
        ProjectBoundary::NoRepository,
        ScopeSelection::All,
        Some(verified(PolicyLine::OpenCodeV2)),
        vec![ExplicitRoot::new(
            HarnessId::OpenCode,
            HarnessScope::User,
            user_native,
        )],
        built_in_providers,
    );
    // Six standard roots plus the two providers needed to establish stable
    // ambiguity leave exactly one input slot for the coincident explicit root.
    scan_request.limits.max_roots = 9;
    let report = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&scan_request)
        .unwrap();
    let duplicates = report
        .entries
        .iter()
        .filter(|entry| entry.native_id.as_deref() == Some("coincident"))
        .collect::<Vec<_>>();
    let winner = duplicates
        .iter()
        .find(|entry| entry.shadowed_by.is_none())
        .unwrap();

    assert_eq!(duplicates.len(), 2);
    assert_eq!(winner.root_tier, Some(RootTier::Explicit));
    assert_eq!(winner.scope, HarnessScope::User);
    assert_eq!(
        winner.logical_root.as_ref().map(RootId::as_str),
        Some("opencode.explicit.0000")
    );
    assert_eq!(winner.policy_rank, Some(500_000));
    assert!(
        duplicates
            .iter()
            .filter(|entry| entry.shadowed_by.is_some())
            .all(|entry| entry.shadowed_by.as_ref() == winner.observation_id.as_ref())
    );
}

#[test]
fn v2_built_in_provider_is_typed_user_system_evidence_or_one_unresolved_finding() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let built_in = temp.path().join("built-in");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    write_directory_skill(
        &built_in,
        "built-in-review",
        &v2_skill(None, Some("Built-in review.")),
    );

    let unresolved = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&request(
            &temp,
            working.clone(),
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            Some(verified(PolicyLine::OpenCodeV2)),
            vec![],
            vec![],
        ))
        .unwrap();
    assert_eq!(
        unresolved
            .findings
            .iter()
            .filter(|finding| finding.code == "scan.root_unresolved")
            .count(),
        1
    );
    assert!(
        !unresolved
            .entries
            .iter()
            .any(|entry| entry.root_tier == Some(RootTier::System))
    );

    let supplied = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::NoRepository,
            ScopeSelection::User,
            Some(verified(PolicyLine::OpenCodeV2)),
            vec![],
            vec![native_root(
                HarnessScope::User,
                "opencode-v2.built-in",
                built_in,
            )],
        ))
        .unwrap();
    let entry = entry_for_native_id(&supplied, "built-in-review");
    assert_eq!(entry.scope, HarnessScope::User);
    assert_eq!(entry.root_tier, Some(RootTier::System));
    assert!(
        !supplied
            .findings
            .iter()
            .any(|finding| finding.code == "scan.root_unresolved")
    );
}

#[test]
fn v2_multiple_built_in_providers_are_stably_ambiguous_in_either_input_order() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let first = temp.path().join("built-in-a");
    let second = temp.path().join("built-in-b");
    for path in [&home, &working, &first, &second] {
        fs::create_dir_all(path).unwrap();
    }
    let forward = vec![
        native_root(HarnessScope::User, "opencode-v2.built-in", first.clone()),
        native_root(HarnessScope::User, "opencode-v2.built-in", second.clone()),
    ];
    let reversed = vec![
        native_root(HarnessScope::User, "opencode-v2.built-in", second),
        native_root(HarnessScope::User, "opencode-v2.built-in", first),
    ];
    let boundary = ProjectBoundary::NoRepository;
    let trust = BTreeMap::new();
    let limits = ScanLimits::default();
    let policy = OpenCodeObservationPolicy::new();
    let version = verified(PolicyLine::OpenCodeV2);
    let profile = policy
        .profile(VersionObservation::Verified(&version))
        .unwrap();
    let discover = |supplied_native_roots: &[SuppliedNativeRoot]| {
        let context = RootContext {
            home: Some(&home),
            working_directory: &working,
            project_boundary: &boundary,
            scopes: ScopeSelection::User,
            explicit_roots: &[],
            supplied_native_roots,
            project_trust: &trust,
            limits: &limits,
        };
        policy.discover_unusual_roots(&context, &profile).unwrap()
    };

    let forward_report = discover(&forward);
    let reversed_report = discover(&reversed);

    assert_eq!(forward_report, reversed_report);
    assert!(forward_report.roots.is_empty());
    assert_eq!(
        forward_report
            .findings
            .iter()
            .filter(|finding| finding.code == "opencode.built_in_provider_ambiguous")
            .count(),
        1
    );
    assert!(
        !forward_report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.root_unresolved")
    );
}

#[test]
fn receipt_anchors_exclude_compatibility_built_in_and_explicit_roots() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("packages/app");
    let explicit = temp.path().join("explicit");
    let built_in = temp.path().join("built-in");
    for path in [&home, &working, &explicit, &built_in] {
        fs::create_dir_all(path).unwrap();
    }
    let boundary = ProjectBoundary::Repository {
        root: repository.clone(),
    };
    let explicit_roots = [ExplicitRoot::new(
        HarnessId::OpenCode,
        HarnessScope::Project,
        explicit.clone(),
    )];
    let supplied = [native_root(
        HarnessScope::User,
        "opencode-v2.built-in",
        built_in.clone(),
    )];
    let limits = ScanLimits::default();
    let trust = BTreeMap::new();
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::All,
        explicit_roots: &explicit_roots,
        supplied_native_roots: &supplied,
        project_trust: &trust,
        limits: &limits,
    };
    let policy = OpenCodeObservationPolicy::new();
    let version = verified(PolicyLine::OpenCodeV2);
    let profile = policy
        .profile(VersionObservation::Verified(&version))
        .unwrap();

    let anchors = policy.receipt_anchors(&context, &profile).unwrap();

    assert_eq!(anchors.len(), 2);
    assert!(anchors.iter().any(|anchor| {
        anchor.scope == HarnessScope::User && anchor.path == home.join(".config/opencode/skills")
    }));
    assert!(anchors.iter().any(|anchor| {
        anchor.scope == HarnessScope::Project && anchor.path == repository.join(".opencode/skills")
    }));
    assert!(anchors.iter().all(|anchor| {
        anchor.path != home.join(".claude/skills")
            && anchor.path != home.join(".agents/skills")
            && anchor.path != explicit
            && anchor.path != built_in
    }));
}

#[test]
fn no_repository_and_unsafe_stop_keep_opencode_project_roots_at_working_directory() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("outside/deep/work");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let limits = ScanLimits::default();
    let trust = BTreeMap::new();
    let policy = OpenCodeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    for boundary in [ProjectBoundary::NoRepository, ProjectBoundary::UnsafeStop] {
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
        let project_paths = policy
            .roots(&context, &profile)
            .unwrap()
            .into_iter()
            .filter(|root| root.scope == HarnessScope::Project)
            .map(|root| root.path)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            project_paths,
            BTreeSet::from([
                working.join(".agents/skills"),
                working.join(".claude/skills"),
                working.join(".opencode/skills"),
            ])
        );
    }
}

#[test]
fn unusual_root_budget_counts_invalid_inputs_and_stops_before_the_tail() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let tail = temp.path().join("tail");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&tail).unwrap();
    let mut explicit_roots = vec![ExplicitRoot::new(
        HarnessId::OpenCode,
        HarnessScope::Project,
        temp.path().join("missing-first"),
    )];
    for index in 0..8 {
        let invalid_file = tail.join(format!("invalid-{index:02}.txt"));
        fs::write(&invalid_file, b"not a local directory\n").unwrap();
        explicit_roots.push(ExplicitRoot::new(
            HarnessId::OpenCode,
            HarnessScope::Project,
            invalid_file,
        ));
    }
    let boundary = ProjectBoundary::NoRepository;
    let trust = BTreeMap::new();
    let limits = ScanLimits {
        // The three common project roots leave capacity to inspect exactly one
        // caller-supplied input, even when that input is invalid.
        max_roots: 4,
        max_findings: 4,
        ..ScanLimits::default()
    };
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::Project,
        explicit_roots: &explicit_roots,
        supplied_native_roots: &[],
        project_trust: &trust,
        limits: &limits,
    };
    let policy = OpenCodeObservationPolicy::new();
    let version = verified(PolicyLine::OpenCodeV2);
    let profile = policy
        .profile(VersionObservation::Verified(&version))
        .unwrap();
    let before = FilesystemSnapshot::capture(temp.path()).unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(FilesystemSnapshot::capture(temp.path()).unwrap(), before);
    assert!(report.roots.is_empty());
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
}

#[test]
fn current_and_unknown_native_inputs_stop_at_the_root_budget() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let supplied = (0..8)
        .map(|index| {
            let key = if index == 0 {
                "opencode-v2.built-in".to_owned()
            } else {
                format!("opencode-v2.adversarial-tail-{index:02}")
            };
            native_root(
                HarnessScope::User,
                &key,
                temp.path().join(format!("uninspected-tail-{index:02}")),
            )
        })
        .collect::<Vec<_>>();
    let boundary = ProjectBoundary::NoRepository;
    let trust = BTreeMap::new();
    let limits = ScanLimits {
        // The three common project roots leave capacity for exactly one
        // caller-supplied input. The remaining tail must not be visited.
        max_roots: 4,
        max_findings: 8,
        ..ScanLimits::default()
    };
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::Project,
        explicit_roots: &[],
        supplied_native_roots: &supplied,
        project_trust: &trust,
        limits: &limits,
    };
    let policy = OpenCodeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "opencode.native_root_profile_unsupported")
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
            .all(|finding| !finding.action.contains("adversarial-tail"))
    );
}

#[test]
fn verified_current_full_finding_budget_retains_exhaustion_with_current_evidence() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let supplied = [
        native_root(
            HarnessScope::User,
            "opencode-v2.built-in",
            temp.path().join("first"),
        ),
        native_root(
            HarnessScope::User,
            "opencode-v2.extra",
            temp.path().join("uninspected-tail"),
        ),
    ];
    let boundary = ProjectBoundary::NoRepository;
    let trust = BTreeMap::new();
    let limits = ScanLimits {
        max_roots: 4,
        max_findings: 1,
        ..ScanLimits::default()
    };
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::Project,
        explicit_roots: &[],
        supplied_native_roots: &supplied,
        project_trust: &trust,
        limits: &limits,
    };
    let policy = OpenCodeObservationPolicy::new();
    let version = verified(PolicyLine::OpenCodeCurrent);
    let profile = policy
        .profile(VersionObservation::Verified(&version))
        .unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].code, "scan.root_budget_exhausted");
    assert_eq!(
        report.findings[0].evidence,
        vec![evidence("opencode.docs.skills.current")]
    );
}

#[test]
fn unknown_exhaustion_replaces_version_notice_with_current_evidence() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    let supplied = [
        native_root(
            HarnessScope::User,
            "opencode-v2.built-in",
            temp.path().join("first"),
        ),
        native_root(
            HarnessScope::User,
            "opencode-v2.extra",
            temp.path().join("uninspected-tail"),
        ),
    ];
    let boundary = ProjectBoundary::NoRepository;
    let trust = BTreeMap::new();
    let limits = ScanLimits {
        max_roots: 4,
        max_findings: 1,
        ..ScanLimits::default()
    };
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::Project,
        explicit_roots: &[],
        supplied_native_roots: &supplied,
        project_trust: &trust,
        limits: &limits,
    };
    let policy = OpenCodeObservationPolicy::new();
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].code, "scan.root_budget_exhausted");
    assert_eq!(
        report.findings[0].evidence,
        vec![evidence("opencode.docs.skills.current")]
    );
}

#[test]
fn unusual_finding_budget_reserves_one_terminal_exhaustion_signal() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let tail = temp.path().join("tail");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::create_dir_all(&tail).unwrap();
    let explicit_roots = (0..8)
        .map(|index| {
            let invalid_file = tail.join(format!("invalid-{index:02}.txt"));
            fs::write(&invalid_file, b"not a local directory\n").unwrap();
            ExplicitRoot::new(HarnessId::OpenCode, HarnessScope::Project, invalid_file)
        })
        .collect::<Vec<_>>();
    let boundary = ProjectBoundary::NoRepository;
    let trust = BTreeMap::new();
    let limits = ScanLimits {
        max_findings: 2,
        ..ScanLimits::default()
    };
    let context = RootContext {
        home: Some(&home),
        working_directory: &working,
        project_boundary: &boundary,
        scopes: ScopeSelection::Project,
        explicit_roots: &explicit_roots,
        supplied_native_roots: &[],
        project_trust: &trust,
        limits: &limits,
    };
    let policy = OpenCodeObservationPolicy::new();
    let version = verified(PolicyLine::OpenCodeV2);
    let profile = policy
        .profile(VersionObservation::Verified(&version))
        .unwrap();

    let report = policy.discover_unusual_roots(&context, &profile).unwrap();

    assert_eq!(report.findings.len(), 2);
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
    let exhaustion = report
        .findings
        .iter()
        .find(|finding| finding.code == "scan.root_budget_exhausted")
        .unwrap();
    assert_eq!(
        exhaustion.evidence,
        vec![evidence("opencode.v2.docs.skills")]
    );
}

#[test]
fn command_discovery_preserves_user_and_nested_project_paths() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("packages/app");
    let user_commands = home.join(".config/opencode/commands");
    let project_commands = repository.join(".opencode/commands/team");
    fs::create_dir_all(&user_commands).unwrap();
    fs::create_dir_all(&project_commands).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(user_commands.join("review.md"), "Review $ARGUMENTS.\n").unwrap();
    fs::write(project_commands.join("release.md"), "Release $ARGUMENTS.\n").unwrap();

    let report = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&request(
            &temp,
            working,
            ProjectBoundary::Repository { root: repository },
            ScopeSelection::All,
            Some(verified(PolicyLine::OpenCodeV2)),
            vec![],
            vec![],
        ))
        .unwrap();
    let commands = &report.prompt_commands;

    assert_eq!(commands.len(), 2);
    assert!(commands.iter().any(|entry| {
        entry.scope == HarnessScope::User
            && entry.logical_root.as_str() == "opencode.user.native.commands"
            && entry.source_relative_path == "review.md"
            && entry.portable_hash.is_some()
    }));
    assert!(commands.iter().any(|entry| {
        entry.scope == HarnessScope::Project
            && entry.logical_root.as_str() == "opencode.project.native.commands.0000"
            && entry.source_relative_path == "team/release.md"
            && entry.blocked_reason.is_some()
    }));
}

#[test]
fn command_discovery_requires_verified_v2_policy() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let working = temp.path().join("working");
    let commands = home.join(".config/opencode/commands");
    fs::create_dir_all(&commands).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(commands.join("review.md"), "Review prompt.\n").unwrap();

    for version in [None, Some(verified(PolicyLine::OpenCodeCurrent))] {
        let report = test_engine(&OpenCodeObservationPolicy::new())
            .scan(&request(
                &temp,
                working.clone(),
                ProjectBoundary::NoRepository,
                ScopeSelection::User,
                version,
                vec![],
                vec![],
            ))
            .unwrap();

        assert!(report.prompt_commands.is_empty());
        assert!(
            report
                .related
                .iter()
                .all(|entry| entry.kind != AssetKind::Command)
        );
    }
}

#[test]
fn agents_are_current_direct_markdown_and_primary_mode_stays_native() {
    let temp = tempdir();
    let home = temp.path().join("home");
    let repository = temp.path().join("repo");
    let working = repository.join("working");
    let agents = home.join(".config/opencode/agents");
    fs::create_dir_all(agents.join("nested")).unwrap();
    fs::create_dir_all(&working).unwrap();
    fs::write(
        agents.join("review.md"),
        "---\ndescription: Review changes.\nmode: subagent\n---\nReview carefully.\n",
    )
    .unwrap();
    fs::write(
        agents.join("primary.md"),
        "---\ndescription: Primary authority.\nmode: primary\n---\nStay native.\n",
    )
    .unwrap();
    fs::write(
        agents.join("nested/hidden.md"),
        "---\ndescription: Hidden.\nmode: subagent\n---\nIgnore.\n",
    )
    .unwrap();
    let request = request(
        &temp,
        working,
        ProjectBoundary::Repository { root: repository },
        ScopeSelection::All,
        Some(verified(PolicyLine::OpenCodeCurrent)),
        vec![],
        vec![],
    );

    let report = test_engine(&OpenCodeObservationPolicy::new())
        .scan(&request)
        .unwrap();

    assert_eq!(report.agents.len(), 2);
    assert_eq!(report.agent_observations().len(), 2);
    assert!(report.agents.iter().all(|agent| {
        agent
            .source_relative_path
            .as_deref()
            .is_some_and(|path| !path.contains('/'))
    }));
    let primary = report
        .agents
        .iter()
        .find(|agent| agent.name.as_str() == "primary")
        .unwrap();
    assert!(primary.portable_hash.is_none());
    assert!(primary.blocked_reason.is_some());
}
