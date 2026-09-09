use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use kitrove_adapter_api::{
    AdapterResult, AgentDiscovery, AgentTargetPolicy, CandidateDecision, CandidateLocator,
    CandidateSummary, DuplicateDecision, EnvironmentInput, EvidenceRef, ExplicitRoot,
    ExtensionTargetPolicy, FindingSeverity, FindingSubject, HarnessObservationPolicy,
    HarnessVersion, InstructionTargetAnchor, InstructionTargetPolicy, LocalStateInput,
    LocatorDecision, NativeAcceptance, NativeRootKey, ObservationId, ObservationIdentity,
    ObservedRoot, PolicyLine, PolicyProfile, PortablePolicyDecision, ProjectBoundary,
    PromptCommandTargetPolicy, ReceiptAnchor, RelatedDocumentPattern, RelatedRoot, RootContext,
    RootHookReport, RootId, RootTier, ScanFinding, ScanLimits, ScanRequest, ScopeSelection,
    SourceRelativePath, SuppliedNativeRoot, TargetAnchor, VerifiedVersionEvidence,
    VersionObservation, VersionObservationOwned, select_materialization_policy,
};
use kitrove_agent_skills::{CapturedSkillSource, SkillSourceLayout};
use kitrove_agents::NativeAgentDialect;
use kitrove_model::{
    AssetId, ContentHash, FidelityReason, HarnessId, HarnessScope, NormalizedDestination, ReceiptId,
};
use serde_json::json;

#[test]
fn project_boundary_preserves_ordinary_absence_and_unsafe_termination() {
    assert_ne!(ProjectBoundary::NoRepository, ProjectBoundary::UnsafeStop);
    assert_eq!(
        format!("{:?}", ProjectBoundary::NoRepository),
        "NoRepository"
    );
    assert_eq!(format!("{:?}", ProjectBoundary::UnsafeStop), "UnsafeStop");
}

#[test]
fn pi_extension_policy_has_one_revalidated_identity() {
    let canonical = ExtensionTargetPolicy::pi_native_extensions(
        HarnessScope::Project,
        VersionObservationOwned::Unknown,
    );
    canonical.validate_pi_native_extensions().unwrap();

    let mut drifted = canonical;
    drifted.adapter_version = "pi-native-extensions/drift";
    assert_eq!(
        drifted.validate_pi_native_extensions().unwrap_err().code,
        "apply.extension_policy_invalid"
    );
}

#[test]
fn prompt_command_target_policy_rejects_cross_harness_and_project_config_anchors() {
    assert_eq!(
        PromptCommandTargetPolicy::new(
            HarnessId::Pi,
            HarnessScope::User,
            PolicyLine::ClaudeCurrent,
            TargetAnchor::Scope,
            ".pi/agent/prompts",
            "test/1",
            "test.prompt_commands",
        )
        .unwrap_err()
        .code,
        "adapter.prompt_command_target_invalid"
    );
    assert_eq!(
        PromptCommandTargetPolicy::new(
            HarnessId::OpenCode,
            HarnessScope::Project,
            PolicyLine::OpenCodeV2,
            TargetAnchor::HarnessConfiguration,
            "commands",
            "test/1",
            "test.prompt_commands",
        )
        .unwrap_err()
        .code,
        "adapter.prompt_command_target_invalid"
    );
}

#[test]
fn agent_target_policy_derives_native_identity_and_revalidates_public_mutation() {
    assert_eq!(
        AgentTargetPolicy::new(
            HarnessScope::User,
            PolicyLine::CodexCurrent,
            TargetAnchor::Scope,
            ".claude/agents",
            NativeAgentDialect::ClaudeCurrent,
            "test/1",
            "test.agents",
        )
        .unwrap_err()
        .code,
        "adapter.agent_target_invalid"
    );

    let mut policy = AgentTargetPolicy::new(
        HarnessScope::Project,
        PolicyLine::ClaudeCurrent,
        TargetAnchor::Scope,
        ".claude/agents",
        NativeAgentDialect::ClaudeCurrent,
        "test/1",
        "test.agents",
    )
    .unwrap();
    assert_eq!(policy.harness, HarnessId::Claude);
    assert_eq!(policy.discovery, AgentDiscovery::Recursive);
    policy.discovery = AgentDiscovery::DirectFiles;
    assert_eq!(
        policy.validate().unwrap_err().code,
        "adapter.agent_target_invalid"
    );
}

#[test]
fn verified_version_rejects_cross_harness_policy_lines() {
    let result = VerifiedVersionEvidence::new(
        HarnessId::Claude,
        HarnessVersion::parse("2.1.0").unwrap(),
        PolicyLine::OpenCodeV2,
        EvidenceRef::parse("fixture.claude.2-1-0").unwrap(),
    );

    assert_eq!(result.unwrap_err().code, "adapter.version_policy_mismatch");
}

#[test]
fn instruction_target_policy_rejects_cross_harness_and_project_config_anchors() {
    assert_eq!(
        InstructionTargetPolicy::new(
            HarnessId::Claude,
            HarnessScope::User,
            PolicyLine::CodexCurrent,
            InstructionTargetAnchor::Scope,
            "CLAUDE.md",
            "test/1",
            "test.instructions",
        )
        .unwrap_err()
        .code,
        "adapter.instruction_target_invalid"
    );
    assert_eq!(
        InstructionTargetPolicy::new(
            HarnessId::OpenCode,
            HarnessScope::Project,
            PolicyLine::OpenCodeV2,
            InstructionTargetAnchor::HarnessConfiguration,
            "AGENTS.md",
            "test/1",
            "test.instructions",
        )
        .unwrap_err()
        .code,
        "adapter.instruction_target_invalid"
    );
}

#[test]
fn verified_version_retains_only_validated_matching_evidence() {
    let evidence = VerifiedVersionEvidence::new(
        HarnessId::OpenCode,
        HarnessVersion::parse("2.0 beta").unwrap(),
        PolicyLine::OpenCodeV2,
        EvidenceRef::parse("fixture:opencode_v2-beta").unwrap(),
    )
    .unwrap();

    assert_eq!(evidence.harness(), &HarnessId::OpenCode);
    assert_eq!(evidence.observed().as_str(), "2.0 beta");
    assert_eq!(evidence.policy_line(), PolicyLine::OpenCodeV2);
    assert_eq!(evidence.evidence().as_str(), "fixture:opencode_v2-beta");
}

#[test]
fn materialization_policy_selection_is_explicit_for_unknown_and_verified_versions() {
    assert_eq!(
        select_materialization_policy(
            HarnessId::OpenCode,
            VersionObservation::Unknown,
            &[PolicyLine::OpenCodeCurrent, PolicyLine::OpenCodeV2],
            Some(PolicyLine::OpenCodeCurrent),
        )
        .unwrap(),
        PolicyLine::OpenCodeCurrent,
    );
    assert_eq!(
        select_materialization_policy(
            HarnessId::Pi,
            VersionObservation::Unknown,
            &[PolicyLine::PiLatest],
            None,
        )
        .unwrap_err()
        .code,
        "apply.harness_version_unverified",
    );

    let v2 = VerifiedVersionEvidence::new(
        HarnessId::OpenCode,
        HarnessVersion::parse("reviewed v2").unwrap(),
        PolicyLine::OpenCodeV2,
        EvidenceRef::parse("fixture.opencode.v2").unwrap(),
    )
    .unwrap();
    assert_eq!(
        select_materialization_policy(
            HarnessId::OpenCode,
            VersionObservation::Verified(&v2),
            &[PolicyLine::OpenCodeCurrent, PolicyLine::OpenCodeV2],
            Some(PolicyLine::OpenCodeCurrent),
        )
        .unwrap(),
        PolicyLine::OpenCodeV2,
    );
}

#[test]
fn logical_evidence_uses_the_exact_bounded_ascii_grammar() {
    let maximum = "a".repeat(128);
    assert_eq!(EvidenceRef::parse(&maximum).unwrap().as_str(), maximum);
    assert!(EvidenceRef::parse("a.b:c_d-e0").is_ok());

    for invalid in [
        "",
        "Uppercase",
        "contains/path",
        "contains space",
        "évidence",
    ] {
        assert!(EvidenceRef::parse(invalid).is_err(), "accepted {invalid:?}");
        assert!(RootId::parse(invalid).is_err(), "accepted {invalid:?}");
        assert!(
            NativeRootKey::parse(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
    assert!(EvidenceRef::parse("a".repeat(129)).is_err());
}

#[test]
fn harness_versions_are_bounded_printable_ascii() {
    assert!(HarnessVersion::parse(" ").is_ok());
    assert!(HarnessVersion::parse("~".repeat(128)).is_ok());

    for invalid in [
        String::new(),
        "1\t2".to_owned(),
        "vérsion".to_owned(),
        "v".repeat(129),
    ] {
        assert!(HarnessVersion::parse(invalid).is_err());
    }
}

#[test]
fn supplied_native_root_does_not_accept_caller_provenance() {
    let root = SuppliedNativeRoot::new(
        HarnessId::Codex,
        HarnessScope::User,
        NativeRootKey::parse("codex.bundled").unwrap(),
        PathBuf::from("/opt/codex/skills"),
    );

    assert_eq!(root.harness(), &HarnessId::Codex);
    assert_eq!(root.scope(), HarnessScope::User);
    assert_eq!(root.source_key().as_str(), "codex.bundled");
    assert_eq!(root.path(), PathBuf::from("/opt/codex/skills"));
}

#[test]
fn scan_limits_default_to_the_approved_request_and_capture_bounds() {
    let limits = ScanLimits::default();

    assert_eq!(limits.max_input_bytes, 32 * 1024 * 1024);
    assert_eq!(limits.max_roots, 256);
    assert_eq!(limits.max_discovery_entries, 65_536);
    assert_eq!(limits.max_candidates, 4_096);
    assert_eq!(limits.max_discovery_depth, 64);
    assert_eq!(limits.max_receipts, 4_096);
    assert_eq!(limits.max_findings, 32_768);
    assert_eq!(limits.max_report_entries, 8_192);
    assert_eq!(limits.max_capture_files, 16_384);
    assert_eq!(limits.max_capture_bytes, 256 * 1024 * 1024);
    assert_eq!(limits.capture.max_files, 512);
    assert_eq!(limits.capture.max_file_bytes, 4 * 1024 * 1024);
    assert_eq!(limits.capture.max_total_bytes, 32 * 1024 * 1024);
}

#[test]
fn policy_profile_rejects_harness_or_owned_version_mismatches() {
    let version = VersionObservationOwned::Verified {
        observed: HarnessVersion::parse("2.0").unwrap(),
        policy_line: PolicyLine::OpenCodeV2,
        evidence: EvidenceRef::parse("fixture.opencode.v2").unwrap(),
    };
    let result = PolicyProfile::new(
        HarnessId::Claude,
        PolicyLine::ClaudeCurrent,
        version,
        EvidenceRef::parse("catalog.claude.current").unwrap(),
    );

    assert_eq!(result.unwrap_err().code, "adapter.version_policy_mismatch");
}

#[test]
fn candidate_decisions_enforce_native_identity_and_projection_invariants() {
    let accepted = CandidateDecision::new(
        NativeAcceptance::Accepted,
        Some("native-skill".to_owned()),
        PortablePolicyDecision::Project {
            name: AssetId::parse("portable-skill").unwrap(),
            description: "A portable skill".to_owned(),
            reasons: vec![],
        },
        vec![],
    )
    .unwrap();
    assert_eq!(accepted.native_id(), Some("native-skill"));

    let missing_native = CandidateDecision::new(
        NativeAcceptance::Accepted,
        None,
        PortablePolicyDecision::Unavailable {
            reasons: vec![FidelityReason::new("skill.name_missing", "name is missing")],
        },
        vec![],
    );
    assert_eq!(
        missing_native.unwrap_err().code,
        "adapter.native_id_required"
    );

    let rejected_projection = CandidateDecision::new(
        NativeAcceptance::Rejected,
        Some("native-skill".to_owned()),
        PortablePolicyDecision::Project {
            name: AssetId::parse("portable-skill").unwrap(),
            description: "A portable skill".to_owned(),
            reasons: vec![],
        },
        vec![],
    );
    assert_eq!(
        rejected_projection.unwrap_err().code,
        "adapter.rejected_candidate_portable"
    );

    let empty_loss = CandidateDecision::new(
        NativeAcceptance::Rejected,
        None,
        PortablePolicyDecision::Unavailable { reasons: vec![] },
        vec![],
    );
    assert_eq!(
        empty_loss.unwrap_err().code,
        "adapter.fidelity_reason_required"
    );
}

#[test]
fn finding_serialization_contains_only_catalog_and_typed_logical_evidence() {
    let secret_body = "SECRET-CAPTURED-BODY";
    let raw_path = "/Users/alice/private/SKILL.md";
    assert!(EvidenceRef::parse(secret_body).is_err());
    assert!(EvidenceRef::parse(raw_path).is_err());
    assert!(NormalizedDestination::parse("relative/private/SKILL.md").is_err());

    let finding = ScanFinding::new(
        "scan.version_unknown",
        FindingSeverity::Informational,
        FindingSubject::Harness(HarnessId::Pi),
        vec![EvidenceRef::parse("catalog.pi.latest").unwrap()],
        "verify the harness version before materialization",
    );
    let serialized = serde_json::to_value(&finding).unwrap();

    assert_eq!(
        serialized,
        json!({
            "code": "scan.version_unknown",
            "severity": "informational",
            "subject": { "type": "harness", "harness": "pi" },
            "evidence": ["catalog.pi.latest"],
            "action": "verify the harness version before materialization"
        })
    );
    let text = serde_json::to_string(&finding).unwrap();
    assert!(!text.contains(secret_body));
    assert!(!text.contains(raw_path));
}

#[test]
fn finding_subject_paths_require_validated_relative_or_normalized_evidence() {
    assert!(HarnessId::parse("/absolute-harness").is_err());
    assert!(RootId::parse("/absolute-root").is_err());
    assert!(ReceiptId::parse("/absolute-receipt").is_err());

    assert_eq!(
        serde_json::to_value(FindingSubject::Root(
            RootId::parse("claude.project.skills").unwrap()
        ))
        .unwrap(),
        json!({ "type": "root", "logical_root": "claude.project.skills" })
    );
    assert_eq!(
        serde_json::to_value(FindingSubject::Receipt(
            ReceiptId::parse("receipt-safe").unwrap()
        ))
        .unwrap(),
        json!({ "type": "receipt", "receipt_id": "receipt-safe" })
    );

    for invalid in [
        "/absolute/review.md",
        "../review.md",
        "commands/../review.md",
        "commands//review.md",
        "C:/private/review.md",
        "commands\\review.md",
        "captured\nsecret body",
        "captured\0secret body",
    ] {
        assert!(
            SourceRelativePath::parse(invalid).is_err(),
            "accepted unsafe relative path {invalid:?}"
        );
    }

    let related = FindingSubject::Related {
        logical_root: RootId::parse("claude.project.commands").unwrap(),
        source_relative_path: SourceRelativePath::parse("commands/review.md").unwrap(),
    };
    assert_eq!(
        serde_json::to_value(related).unwrap(),
        json!({
            "type": "related",
            "logical_root": "claude.project.commands",
            "source_relative_path": "commands/review.md"
        })
    );

    for invalid in [
        "relative/review.md",
        "/safe/../private/review.md",
        "/private/review\0.md",
    ] {
        assert!(
            NormalizedDestination::parse(invalid).is_err(),
            "accepted unsafe destination {invalid:?}"
        );
    }
    let destination = FindingSubject::Destination {
        harness: HarnessId::Claude,
        scope: HarnessScope::Project,
        normalized_destination: NormalizedDestination::parse("/workspace/.claude/skills/review")
            .unwrap(),
    };
    assert_eq!(
        serde_json::to_value(destination).unwrap(),
        json!({
            "type": "destination",
            "harness": "claude",
            "scope": "project",
            "normalized_destination": "/workspace/.claude/skills/review"
        })
    );
}

#[test]
fn scan_findings_retain_only_compiled_catalog_text() {
    let finding = ScanFinding::new(
        "scan.layout_unsupported",
        FindingSeverity::Attention,
        FindingSubject::Harness(HarnessId::OpenCode),
        vec![EvidenceRef::parse("catalog.opencode.current").unwrap()],
        "move the source into a policy-supported layout",
    );

    fn assert_compiled_catalog_text(_: &'static str) {}
    assert_compiled_catalog_text(finding.code);
    assert_compiled_catalog_text(finding.action);
}

#[test]
fn request_debug_is_structural_and_redacts_paths_and_input_bytes() {
    let path_canary = "/Users/alice/PRIVATE-PATH-CANARY";
    let environment_canary = b"ENVIRONMENT-BODY-CANARY";
    let state_canary = b"LOCAL-STATE-BODY-CANARY";
    let environment = EnvironmentInput {
        source_path: PathBuf::from(format!("{path_canary}/kitrove.toml")),
        toml_bytes: environment_canary,
    };
    let local_state = LocalStateInput::Bytes {
        source_path: PathBuf::from(format!("{path_canary}/state.json")),
        json_bytes: state_canary,
    };
    let explicit = ExplicitRoot::new(
        HarnessId::Claude,
        HarnessScope::Project,
        PathBuf::from(format!("{path_canary}/explicit")),
    );
    let supplied = SuppliedNativeRoot::new(
        HarnessId::Codex,
        HarnessScope::User,
        NativeRootKey::parse("codex.bundled").unwrap(),
        PathBuf::from(format!("{path_canary}/native")),
    );
    let request = ScanRequest {
        home: Some(PathBuf::from(format!("{path_canary}/home"))),
        working_directory: PathBuf::from(format!("{path_canary}/workspace")),
        project_boundary: ProjectBoundary::Repository {
            root: PathBuf::from(format!("{path_canary}/repository")),
        },
        harnesses: BTreeSet::from([HarnessId::Claude, HarnessId::Codex]),
        scopes: ScopeSelection::All,
        explicit_roots: vec![explicit.clone()],
        supplied_native_roots: vec![supplied.clone()],
        versions: BTreeMap::new(),
        project_trust: BTreeMap::new(),
        environment: Some(environment.clone()),
        local_state: Some(local_state.clone()),
        limits: ScanLimits::default(),
    };

    for rendered in [
        format!("{explicit:?}"),
        format!("{supplied:?}"),
        format!("{environment:?}"),
        format!("{local_state:?}"),
        format!("{request:?}"),
    ] {
        assert!(!rendered.contains(path_canary), "leaked path: {rendered}");
        assert!(
            !rendered.contains(std::str::from_utf8(environment_canary).unwrap()),
            "leaked environment bytes: {rendered}"
        );
        assert!(
            !rendered.contains(std::str::from_utf8(state_canary).unwrap()),
            "leaked local-state bytes: {rendered}"
        );
    }

    let request_debug = format!("{request:?}");
    assert!(request_debug.contains("explicit_roots: 1"));
    assert!(request_debug.contains("supplied_native_roots: 1"));
    assert!(request_debug.contains("toml_bytes: 23"));
    assert!(request_debug.contains("json_bytes: 23"));
}

#[test]
fn enum_tags_are_snake_case_and_fieldless_values_are_strings() {
    assert_eq!(
        serde_json::to_value(PolicyLine::OpenCodeV2).unwrap(),
        json!("open_code_v2")
    );
    assert_eq!(
        serde_json::to_value(RootTier::Compatibility).unwrap(),
        json!("compatibility")
    );
    assert_eq!(
        serde_json::to_value(NativeAcceptance::Accepted).unwrap(),
        json!("accepted")
    );
    assert_eq!(
        serde_json::to_value(DuplicateDecision::Coexist).unwrap(),
        json!("coexist")
    );
    assert_eq!(
        serde_json::to_value(RelatedDocumentPattern::MarkdownDirectChildren).unwrap(),
        json!("markdown_direct_children")
    );
}

#[test]
fn owned_version_serialization_uses_an_explicit_status_object() {
    assert_eq!(
        serde_json::to_value(VersionObservationOwned::Unknown).unwrap(),
        json!({ "status": "unknown" })
    );
    assert_eq!(
        serde_json::to_value(VersionObservationOwned::Verified {
            observed: HarnessVersion::parse("2.0.0").unwrap(),
            policy_line: PolicyLine::OpenCodeV2,
            evidence: EvidenceRef::parse("fixture.opencode.v2").unwrap(),
        })
        .unwrap(),
        json!({
            "status": "verified",
            "observed": "2.0.0",
            "policy_line": "open_code_v2",
            "evidence": "fixture.opencode.v2"
        })
    );
}

struct DefaultHookPolicy;

impl HarnessObservationPolicy for DefaultHookPolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Claude
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        PolicyProfile::new(
            HarnessId::Claude,
            PolicyLine::ClaudeCurrent,
            VersionObservationOwned::from(version),
            EvidenceRef::parse("catalog.claude.current").unwrap(),
        )
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
        _locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        LocatorDecision::Capture
    }

    fn decide_candidate(
        &self,
        _candidate: &CapturedSkillSource,
        _locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        unreachable!("contract-only policy does not capture candidates")
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

#[test]
fn policy_hooks_default_to_bounded_empty_reports() {
    let policy = DefaultHookPolicy;
    let limits = ScanLimits::default();
    let explicit_roots = [ExplicitRoot::new(
        HarnessId::Claude,
        HarnessScope::Project,
        PathBuf::from("/workspace/.extra-skills"),
    )];
    let supplied_native_roots = [];
    let project_trust = BTreeMap::new();
    let boundary = ProjectBoundary::Repository {
        root: PathBuf::from("/workspace"),
    };
    let home = PathBuf::from("/home/alice");
    let working_directory = PathBuf::from("/workspace");
    let context = RootContext {
        home: Some(&home),
        working_directory: &working_directory,
        project_boundary: &boundary,
        scopes: ScopeSelection::All,
        explicit_roots: &explicit_roots,
        supplied_native_roots: &supplied_native_roots,
        project_trust: &project_trust,
        limits: &limits,
    };
    let profile = policy.profile(VersionObservation::Unknown).unwrap();

    assert_eq!(
        policy.discover_unusual_roots(&context, &profile).unwrap(),
        RootHookReport {
            roots: vec![],
            findings: vec![]
        }
    );
    assert_eq!(
        policy.related_roots(&context, &profile).unwrap(),
        Vec::<RelatedRoot>::new()
    );
}

#[test]
fn observed_roots_use_policy_owned_layout_rank_and_evidence() {
    let root = ObservedRoot {
        logical_id: RootId::parse("codex.user.agents-skills").unwrap(),
        path: PathBuf::from("/home/alice/.agents/skills"),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: 10,
        enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
        evidence: EvidenceRef::parse("catalog.codex.skills").unwrap(),
    };

    assert_eq!(
        root.enabled_layouts,
        BTreeSet::from([SkillSourceLayout::Directory])
    );
}

#[test]
fn observation_ids_are_deterministic_over_complete_canonical_identity_evidence() {
    let harness = HarnessId::Codex;
    let logical_root = RootId::parse("codex.project.agents-skills").unwrap();
    let source_relative_path = SourceRelativePath::parse("nested/review").unwrap();
    let exact_source_hash = ContentHash::parse(
        "blake3:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .unwrap();
    let identity = ObservationIdentity {
        harness: &harness,
        scope: HarnessScope::Project,
        root_tier: RootTier::Compatibility,
        policy_rank: 42,
        logical_root: &logical_root,
        source_relative_path: &source_relative_path,
        layout: SkillSourceLayout::Directory,
        original_document_name: "SKILL.md",
        native_id: Some("review"),
        exact_source_hash: Some(&exact_source_hash),
    };

    let id = ObservationId::from_identity(&identity);
    assert_eq!(
        id.as_str(),
        "observation-f043d25157d61a155ee2a280d1efe1a9607392e77946b90de16dcf24c5ee1e24"
    );
    assert_eq!(
        serde_json::to_value(FindingSubject::Observation(id.clone())).unwrap(),
        json!({ "type": "observation", "observation_id": id.as_str() })
    );

    let changed_identity = ObservationIdentity {
        policy_rank: 43,
        ..identity
    };
    assert_ne!(id, ObservationId::from_identity(&changed_identity));
}
