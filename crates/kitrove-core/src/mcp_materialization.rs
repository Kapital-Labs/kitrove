use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_adapter_api::McpTargetPolicy;
use kitrove_mcp::{
    McpDocumentMutation, McpParseLimits, ObservedMcpDocument, ObservedMcpServer, RenderedMcpEntry,
    StoredMcpServer, edit_native_mcp_document, render_native_mcp_entry,
};
use kitrove_model::{
    AssetId, AssetKind, BindingResolver, ContentClass, ContentHash, DeploymentReceipt,
    EnvironmentManifest, Fidelity, LocalState, NormalizedDestination, ProfileId, ReceiptTarget,
    Revision,
};

use crate::materialization::write_digest_record;
use crate::read_only_fs::RegularFileMode;
use crate::{ApplyDisposition, McpDocumentObservation, ReceiptIndex, derive_manifest_revision};

const MAX_MCP_PROJECTIONS: usize = 4096;

/// One portable MCP asset selected for one compiled native target.
#[derive(Clone, Eq, PartialEq)]
pub struct McpProjection {
    asset_id: AssetId,
    object: StoredMcpServer,
    policy: McpTargetPolicy,
    observation: McpDocumentObservation,
}

/// One receipt-backed MCP projection selected for reference-aware pack removal.
#[derive(Clone, Eq, PartialEq)]
pub struct McpRemovalSelection {
    projection: McpProjection,
    retained: bool,
}

impl McpRemovalSelection {
    #[must_use]
    pub const fn remove(projection: McpProjection) -> Self {
        Self {
            projection,
            retained: false,
        }
    }

    #[must_use]
    pub const fn retain(projection: McpProjection) -> Self {
        Self {
            projection,
            retained: true,
        }
    }
}

impl McpProjection {
    #[must_use]
    pub fn new(
        asset_id: AssetId,
        object: StoredMcpServer,
        policy: McpTargetPolicy,
        observation: McpDocumentObservation,
    ) -> Self {
        Self {
            asset_id,
            object,
            policy,
            observation,
        }
    }

    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn policy(&self) -> &McpTargetPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn observation(&self) -> &McpDocumentObservation {
        &self.observation
    }
}

impl Debug for McpProjection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpProjection")
            .field("asset_id", &self.asset_id)
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("destination", self.observation.destination())
            .finish()
    }
}

/// One receipt-backed logical entry within a coalesced MCP document plan.
#[derive(Clone, Eq, PartialEq)]
pub struct CoalescedMcpEntry {
    asset_id: AssetId,
    native_name: String,
    disposition: ApplyDisposition,
    observed_receipt: Option<DeploymentReceipt>,
    proposed_receipt: Option<DeploymentReceipt>,
    policy: McpTargetPolicy,
}

impl CoalescedMcpEntry {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub fn native_name(&self) -> &str {
        &self.native_name
    }

    #[must_use]
    pub const fn disposition(&self) -> ApplyDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn observed_receipt(&self) -> Option<&DeploymentReceipt> {
        self.observed_receipt.as_ref()
    }

    #[must_use]
    pub const fn proposed_receipt(&self) -> Option<&DeploymentReceipt> {
        self.proposed_receipt.as_ref()
    }

    #[must_use]
    pub const fn policy(&self) -> &McpTargetPolicy {
        &self.policy
    }
}

impl Debug for CoalescedMcpEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoalescedMcpEntry")
            .field("asset_id", &self.asset_id)
            .field("native_name", &self.native_name)
            .field("disposition", &self.disposition)
            .finish()
    }
}

/// Exact complete output for one shared MCP configuration document.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedCoalescedMcpDocument {
    bytes: Vec<u8>,
    document_hash: ContentHash,
    mode: RegularFileMode,
}

impl RenderedCoalescedMcpDocument {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn document_hash(&self) -> &ContentHash {
        &self.document_hash
    }

    #[allow(dead_code)]
    pub(crate) const fn mode(&self) -> RegularFileMode {
        self.mode
    }
}

impl Debug for RenderedCoalescedMcpDocument {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedCoalescedMcpDocument")
            .field("byte_count", &self.bytes.len())
            .field("document_hash", &self.document_hash)
            .finish()
    }
}

/// One physical MCP document staged exactly once by the atomic coordinator.
#[derive(Clone, Eq, PartialEq)]
pub struct CoalescedMcpDocument {
    destination: NormalizedDestination,
    target_anchor: NormalizedDestination,
    relative_destination: kitrove_model::PortablePath,
    observation: McpDocumentObservation,
    rendered: RenderedCoalescedMcpDocument,
    disposition: ApplyDisposition,
    entries: Vec<CoalescedMcpEntry>,
    digest: ContentHash,
}

impl CoalescedMcpDocument {
    #[must_use]
    pub const fn destination(&self) -> &NormalizedDestination {
        &self.destination
    }

    #[must_use]
    pub const fn target_anchor(&self) -> &NormalizedDestination {
        &self.target_anchor
    }

    #[must_use]
    pub const fn relative_destination(&self) -> &kitrove_model::PortablePath {
        &self.relative_destination
    }

    #[must_use]
    pub const fn observation(&self) -> &McpDocumentObservation {
        &self.observation
    }

    #[must_use]
    pub const fn rendered(&self) -> &RenderedCoalescedMcpDocument {
        &self.rendered
    }

    #[must_use]
    pub const fn disposition(&self) -> ApplyDisposition {
        self.disposition
    }

    #[must_use]
    pub fn entries(&self) -> &[CoalescedMcpEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

impl Debug for CoalescedMcpDocument {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoalescedMcpDocument")
            .field("destination", &self.destination)
            .field("disposition", &self.disposition)
            .field("entry_count", &self.entries.len())
            .field("rendered", &self.rendered)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Complete pure plan for all selected MCP projections and final receipt state.
#[derive(Clone, Eq, PartialEq)]
pub struct CoalescedMcpApplyPlan {
    documents: Vec<CoalescedMcpDocument>,
    target_anchors: Vec<NormalizedDestination>,
    manifest_revision: Revision,
    observed_local_state_text: String,
    proposed_local_state: LocalState,
    proposed_local_state_text: String,
    active_profile: Option<ProfileId>,
    digest: ContentHash,
}

impl CoalescedMcpApplyPlan {
    #[must_use]
    pub fn documents(&self) -> &[CoalescedMcpDocument] {
        &self.documents
    }

    #[must_use]
    pub fn target_anchors(&self) -> &[NormalizedDestination] {
        &self.target_anchors
    }

    #[must_use]
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    #[must_use]
    pub fn observed_local_state_text(&self) -> &str {
        &self.observed_local_state_text
    }

    #[must_use]
    pub const fn proposed_local_state(&self) -> &LocalState {
        &self.proposed_local_state
    }

    #[must_use]
    pub fn proposed_local_state_text(&self) -> &str {
        &self.proposed_local_state_text
    }

    #[must_use]
    pub const fn active_profile(&self) -> Option<&ProfileId> {
        self.active_profile.as_ref()
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

impl Debug for CoalescedMcpApplyPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoalescedMcpApplyPlan")
            .field("document_count", &self.documents.len())
            .field("target_anchor_count", &self.target_anchors.len())
            .field("manifest_revision", &self.manifest_revision)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Stable, path- and authored-value-redacted MCP planning failure.
#[derive(Clone, Eq, PartialEq)]
pub struct McpMaterializationError {
    code: &'static str,
    message: &'static str,
}

impl McpMaterializationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

#[cfg(test)]
pub(crate) use tests::AtomicMcpFixture;

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use kitrove_adapter_api::{McpTargetPolicy, PolicyLine, TargetAnchor};
    use kitrove_mcp::NativeMcpDialect;
    use kitrove_model::{
        BindingName, EnvironmentVariableName, HarnessScope, MachineConfig, MachineId, PortablePath,
        SchemaVersion,
    };
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::mcp_adoption::tests::{capabilities, empty_manifest};
    use crate::{McpAdoptionOutcome, observe_mcp_document, plan_mcp_adoption};

    fn policy() -> McpTargetPolicy {
        McpTargetPolicy::new(
            HarnessScope::User,
            PolicyLine::ClaudeCurrent,
            TargetAnchor::Scope,
            "claude.json",
            NativeMcpDialect::ClaudeCurrent,
            "claude-mcp/1",
            "fixture.claude.mcp",
        )
        .unwrap()
    }

    fn observe(source: &str) -> (TempDir, McpDocumentObservation) {
        let directory = tempdir().unwrap();
        let anchor = directory.path().canonicalize().unwrap();
        fs::write(anchor.join("claude.json"), source).unwrap();
        let observation =
            observe_mcp_document(&anchor, &policy(), McpParseLimits::default()).unwrap();
        (directory, observation)
    }

    fn state(bindings: BTreeMap<BindingName, BindingResolver>) -> LocalState {
        LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("mcp-materialization-test").unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::new(),
                harness_roots: BTreeMap::new(),
            },
            bindings,
            receipts: BTreeMap::new(),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: Vec::new(),
        }
    }

    fn adopt(
        manifest: &EnvironmentManifest,
        asset: &str,
        name: &str,
        binding: Option<&BindingName>,
    ) -> (EnvironmentManifest, AssetId, StoredMcpServer) {
        let header = if binding.is_some() {
            ",\"headers\":{\"Authorization\":\"Bearer ${NATIVE_TOKEN}\"}"
        } else {
            ""
        };
        let source = format!(
            r#"{{"mcpServers":{{"{name}":{{"type":"http","url":"https://{name}.example.com/mcp"{header}}}}}}}"#
        );
        let (_, observation) = observe(&source);
        let selected = observation.parsed().unwrap().entries()[0]
            .exact_entry_hash()
            .clone();
        let asset_id = AssetId::parse(asset).unwrap();
        let McpAdoptionOutcome::Ready(plan) = plan_mcp_adoption(
            &observation,
            &selected,
            &asset_id,
            binding,
            manifest,
            &capabilities(),
        )
        .unwrap() else {
            panic!("portable fixture must be adoptable")
        };
        (
            plan.proposed_manifest().clone(),
            asset_id,
            plan.portable_object().clone(),
        )
    }

    pub(crate) struct AtomicMcpFixture {
        _root: TempDir,
        pub(crate) environment: std::path::PathBuf,
        pub(crate) state: std::path::PathBuf,
        pub(crate) target: std::path::PathBuf,
        pub(crate) batch: crate::AtomicApplyBatchPlan,
        pub(crate) original_document: Vec<u8>,
        manifest: EnvironmentManifest,
        object: StoredMcpServer,
        asset_id: AssetId,
        policy: McpTargetPolicy,
    }

    impl AtomicMcpFixture {
        pub(crate) fn new() -> Self {
            let root = tempdir().unwrap();
            let canonical = root.path().canonicalize().unwrap();
            let environment = canonical.join("environment");
            let state_root = canonical.join("state");
            let target = canonical.join("target");
            for directory in [&environment, &target] {
                fs::create_dir(directory).unwrap();
            }
            let (manifest, asset_id, object) =
                adopt(&empty_manifest(), "docs", "company-docs", None);
            fs::write(
                environment.join("kitrove.toml"),
                manifest.to_toml().unwrap(),
            )
            .unwrap();
            let portable = manifest.assets[&asset_id].portable.as_ref().unwrap();
            let store = crate::ObjectStore::open(&environment).unwrap();
            let environment_lock = store.try_lock_environment().unwrap();
            let staging = PortablePath::parse(".kitrove/test-mcp").unwrap();
            store
                .stage_portable_mcp(
                    &staging,
                    &object,
                    kitrove_agent_skills::CaptureLimits::default(),
                )
                .unwrap();
            store
                .install_portable_mcp(
                    &staging,
                    &portable.root,
                    &portable.object_hash,
                    kitrove_agent_skills::CaptureLimits::default(),
                )
                .unwrap();
            drop(environment_lock);
            let local = state(BTreeMap::new());
            let initial_state = local.to_json().unwrap();
            crate::test_authority::initialize_private_state(&state_root, &local).unwrap();
            let original_document = br#"{"theme":"KEEP","mcpServers":{}}"#.to_vec();
            crate::test_authority::write_owned_fixture_file(
                target.join("claude.json"),
                &original_document,
            )
            .unwrap();
            let policy = policy();
            let observation =
                observe_mcp_document(&target, &policy, McpParseLimits::default()).unwrap();
            let mcp = plan_coalesced_mcp_apply(
                &manifest,
                vec![McpProjection::new(
                    asset_id.clone(),
                    object.clone(),
                    policy.clone(),
                    observation,
                )],
                &initial_state,
                None,
                McpParseLimits::default(),
            )
            .unwrap();
            let batch = crate::AtomicApplyBatchPlan::with_mcp(Vec::new(), mcp).unwrap();
            Self {
                _root: root,
                environment,
                state: state_root,
                target,
                batch,
                original_document,
                manifest,
                object,
                asset_id,
                policy,
            }
        }

        pub(crate) fn removal_batch(&self) -> crate::AtomicApplyBatchPlan {
            let state_text = fs::read_to_string(self.state.join("state.json")).unwrap();
            let observation =
                observe_mcp_document(&self.target, &self.policy, McpParseLimits::default())
                    .unwrap();
            let removal = plan_coalesced_mcp_removal(
                &self.manifest,
                vec![McpProjection::new(
                    self.asset_id.clone(),
                    self.object.clone(),
                    self.policy.clone(),
                    observation,
                )],
                &state_text,
                McpParseLimits::default(),
            )
            .unwrap();
            crate::AtomicApplyBatchPlan::with_mcp(Vec::new(), removal).unwrap()
        }
    }

    #[test]
    fn coalesces_entries_deterministically_and_preserves_unrelated_content() {
        let (manifest, docs_id, docs) = adopt(&empty_manifest(), "docs", "company-docs", None);
        let (manifest, search_id, search) = adopt(&manifest, "search", "company-search", None);
        let (_target, observation) = observe(r#"{"theme":"KEEP-ME","mcpServers":{}}"#);
        let projections = vec![
            McpProjection::new(docs_id, docs, policy(), observation.clone()),
            McpProjection::new(search_id, search, policy(), observation),
        ];
        let state = state(BTreeMap::new()).to_json().unwrap();
        let forward = plan_coalesced_mcp_apply(
            &manifest,
            projections.clone(),
            &state,
            None,
            McpParseLimits::default(),
        )
        .unwrap();
        let reverse = plan_coalesced_mcp_apply(
            &manifest,
            projections.into_iter().rev().collect(),
            &state,
            None,
            McpParseLimits::default(),
        )
        .unwrap();
        assert_eq!(forward.digest(), reverse.digest());
        assert_eq!(forward.documents().len(), 1);
        assert_eq!(forward.documents()[0].entries().len(), 2);
        let output = std::str::from_utf8(forward.documents()[0].rendered().bytes()).unwrap();
        assert!(output.contains("KEEP-ME"));
        assert!(output.contains("company-docs"));
        assert!(output.contains("company-search"));
        assert_eq!(forward.proposed_local_state().receipts.len(), 2);
        assert!(!format!("{forward:?}").contains("example.com"));
    }

    #[test]
    fn refuses_unmanaged_entries_and_requires_environment_binding_authority() {
        let binding = BindingName::parse("company_mcp_token").unwrap();
        let (manifest, asset_id, object) =
            adopt(&empty_manifest(), "docs", "company-docs", Some(&binding));
        let (_target, occupied) = observe(
            r#"{"mcpServers":{"company-docs":{"type":"http","url":"https://other.example.com/mcp"}}}"#,
        );
        let projection = McpProjection::new(asset_id.clone(), object.clone(), policy(), occupied);
        let empty_state = state(BTreeMap::new()).to_json().unwrap();
        assert_eq!(
            plan_coalesced_mcp_apply(
                &manifest,
                vec![projection],
                &empty_state,
                None,
                McpParseLimits::default(),
            )
            .unwrap_err()
            .code(),
            "mcp_apply.entry_unmanaged"
        );

        let (_target, empty) = observe(r#"{"mcpServers":{}}"#);
        let projection = McpProjection::new(asset_id, object, policy(), empty);
        assert_eq!(
            plan_coalesced_mcp_apply(
                &manifest,
                vec![projection.clone()],
                &empty_state,
                None,
                McpParseLimits::default(),
            )
            .unwrap_err()
            .code(),
            "mcp_apply.binding_missing"
        );
        let command_state = state(BTreeMap::from([(
            binding.clone(),
            BindingResolver::Command {
                program: "SECRET-PROGRAM".to_owned(),
                arguments: vec!["SECRET-ARGUMENT".to_owned()],
            },
        )]))
        .to_json()
        .unwrap();
        let error = plan_coalesced_mcp_apply(
            &manifest,
            vec![projection.clone()],
            &command_state,
            None,
            McpParseLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "mcp_apply.binding_command_unsupported");
        assert!(!format!("{error:?} {error}").contains("SECRET"));

        let environment_state = state(BTreeMap::from([(
            binding,
            BindingResolver::Environment {
                variable: EnvironmentVariableName::parse("KITROVE_MCP_TOKEN").unwrap(),
            },
        )]))
        .to_json()
        .unwrap();
        let plan = plan_coalesced_mcp_apply(
            &manifest,
            vec![projection],
            &environment_state,
            None,
            McpParseLimits::default(),
        )
        .unwrap();
        let output = std::str::from_utf8(plan.documents()[0].rendered().bytes()).unwrap();
        assert!(output.contains("KITROVE_MCP_TOKEN"));
        assert!(!output.contains("NATIVE_TOKEN"));
    }

    #[test]
    fn unchanged_receipt_backed_projection_is_a_true_no_op_and_modification_refuses() {
        let (manifest, asset_id, object) = adopt(&empty_manifest(), "docs", "company-docs", None);
        let (target, empty) = observe(r#"{"mcpServers":{}}"#);
        let projection = McpProjection::new(asset_id.clone(), object.clone(), policy(), empty);
        let initial_state = state(BTreeMap::new()).to_json().unwrap();
        let installed = plan_coalesced_mcp_apply(
            &manifest,
            vec![projection],
            &initial_state,
            None,
            McpParseLimits::default(),
        )
        .unwrap();
        fs::write(
            target.path().join("claude.json"),
            installed.documents()[0].rendered().bytes(),
        )
        .unwrap();
        let current = observe_mcp_document(
            &target.path().canonicalize().unwrap(),
            &policy(),
            McpParseLimits::default(),
        )
        .unwrap();
        let current_projection =
            McpProjection::new(asset_id.clone(), object.clone(), policy(), current);
        let repeated = plan_coalesced_mcp_apply(
            &manifest,
            vec![current_projection],
            installed.proposed_local_state_text(),
            None,
            McpParseLimits::default(),
        )
        .unwrap();
        assert_eq!(
            repeated.documents()[0].disposition(),
            ApplyDisposition::NoOp
        );
        assert_eq!(
            repeated.proposed_local_state_text(),
            installed.proposed_local_state_text()
        );

        fs::write(
            target.path().join("claude.json"),
            r#"{"theme":"KEEP","mcpServers":{}}"#,
        )
        .unwrap();
        let missing_entry = observe_mcp_document(
            &target.path().canonicalize().unwrap(),
            &policy(),
            McpParseLimits::default(),
        )
        .unwrap();
        let restored = plan_coalesced_mcp_apply(
            &manifest,
            vec![McpProjection::new(
                asset_id.clone(),
                object.clone(),
                policy(),
                missing_entry,
            )],
            installed.proposed_local_state_text(),
            None,
            McpParseLimits::default(),
        )
        .unwrap();
        assert_eq!(
            restored.documents()[0].entries()[0].disposition(),
            ApplyDisposition::Restore
        );
        assert!(
            std::str::from_utf8(restored.documents()[0].rendered().bytes())
                .unwrap()
                .contains("KEEP")
        );

        fs::write(
            target.path().join("claude.json"),
            r#"{"mcpServers":{"company-docs":{"type":"http","url":"https://changed.example.com/mcp"}}}"#,
        )
        .unwrap();
        let modified = observe_mcp_document(
            &target.path().canonicalize().unwrap(),
            &policy(),
            McpParseLimits::default(),
        )
        .unwrap();
        let error = plan_coalesced_mcp_apply(
            &manifest,
            vec![McpProjection::new(asset_id, object, policy(), modified)],
            installed.proposed_local_state_text(),
            None,
            McpParseLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "mcp_apply.entry_modified");
    }

    #[test]
    fn atomic_coordinator_commits_shared_document_and_receipt_together() {
        let fixture = AtomicMcpFixture::new();
        let crate::AtomicApplyItem::Mcp(item) = &fixture.batch.items()[0] else {
            panic!("fixture must contain an MCP participant");
        };
        let expected = item.document().rendered().bytes().to_vec();
        assert_eq!(
            crate::commit_atomic_apply_batch(
                &fixture.batch,
                &fixture.environment,
                &fixture.state,
                kitrove_agent_skills::CaptureLimits::default(),
            )
            .unwrap(),
            crate::AtomicApplyBatchCommitOutcome::Committed
        );
        assert_eq!(
            fs::read(fixture.target.join("claude.json")).unwrap(),
            expected
        );
        let committed =
            LocalState::from_json(&fs::read_to_string(fixture.state.join("state.json")).unwrap())
                .unwrap();
        assert_eq!(committed.receipts.len(), 1);
        assert!(std::str::from_utf8(&expected).unwrap().contains("KEEP"));
    }

    #[test]
    fn atomic_removal_preserves_co_owned_content_and_clears_receipt() {
        let fixture = AtomicMcpFixture::new();
        crate::commit_atomic_apply_batch(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            kitrove_agent_skills::CaptureLimits::default(),
        )
        .unwrap();
        let removal = fixture.removal_batch();

        crate::commit_atomic_apply_batch(
            &removal,
            &fixture.environment,
            &fixture.state,
            kitrove_agent_skills::CaptureLimits::default(),
        )
        .unwrap();

        let document = fs::read_to_string(fixture.target.join("claude.json")).unwrap();
        assert!(document.contains("KEEP"));
        assert!(!document.contains("company-docs"));
        let state =
            LocalState::from_json(&fs::read_to_string(fixture.state.join("state.json")).unwrap())
                .unwrap();
        assert!(state.receipts.is_empty());
    }

    #[test]
    fn removal_refuses_a_modified_managed_entry() {
        let fixture = AtomicMcpFixture::new();
        crate::commit_atomic_apply_batch(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            kitrove_agent_skills::CaptureLimits::default(),
        )
        .unwrap();
        let path = fixture.target.join("claude.json");
        let modified = fs::read_to_string(&path).unwrap().replace(
            "https://company-docs.example.com/mcp",
            "https://changed.example.com/mcp",
        );
        fs::write(&path, modified).unwrap();
        let observation =
            observe_mcp_document(&fixture.target, &fixture.policy, McpParseLimits::default())
                .unwrap();
        let error = plan_coalesced_mcp_removal(
            &fixture.manifest,
            vec![McpProjection::new(
                fixture.asset_id.clone(),
                fixture.object.clone(),
                fixture.policy.clone(),
                observation,
            )],
            &fs::read_to_string(fixture.state.join("state.json")).unwrap(),
            McpParseLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "mcp_remove.entry_modified");
    }
}

impl Debug for McpMaterializationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpMaterializationError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for McpMaterializationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for McpMaterializationError {}

/// Coalesces one or more logical MCP projections into one mutation per physical document.
pub fn plan_coalesced_mcp_apply(
    manifest: &EnvironmentManifest,
    projections: Vec<McpProjection>,
    local_state_text: &str,
    active_profile: Option<ProfileId>,
    limits: McpParseLimits,
) -> Result<CoalescedMcpApplyPlan, McpMaterializationError> {
    plan_coalesced_mcp(
        manifest,
        projections
            .into_iter()
            .map(|projection| McpPlannedProjection {
                projection,
                operation: McpPlanOperation::Apply,
            })
            .collect(),
        local_state_text,
        active_profile,
        limits,
    )
}

/// Plans removal of exact receipt-backed logical MCP entries without deleting portable authority.
pub fn plan_coalesced_mcp_removal(
    manifest: &EnvironmentManifest,
    projections: Vec<McpProjection>,
    local_state_text: &str,
    limits: McpParseLimits,
) -> Result<CoalescedMcpApplyPlan, McpMaterializationError> {
    plan_coalesced_mcp(
        manifest,
        projections
            .into_iter()
            .map(|projection| McpPlannedProjection {
                projection,
                operation: McpPlanOperation::Remove,
            })
            .collect(),
        local_state_text,
        None,
        limits,
    )
}

/// Coalesces mixed retained and removed MCP entries into one mutation per document.
pub fn plan_coalesced_mcp_removal_selection(
    manifest: &EnvironmentManifest,
    selections: Vec<McpRemovalSelection>,
    local_state_text: &str,
    limits: McpParseLimits,
) -> Result<CoalescedMcpApplyPlan, McpMaterializationError> {
    let active_profile = LocalState::from_json(local_state_text)
        .map_err(|_| state_invalid())?
        .machine
        .active_profile;
    plan_coalesced_mcp(
        manifest,
        selections
            .into_iter()
            .map(|selection| McpPlannedProjection {
                projection: selection.projection,
                operation: if selection.retained {
                    McpPlanOperation::Retain
                } else {
                    McpPlanOperation::Remove
                },
            })
            .collect(),
        local_state_text,
        active_profile,
        limits,
    )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum McpPlanOperation {
    Apply,
    Retain,
    Remove,
}

struct McpPlannedProjection {
    projection: McpProjection,
    operation: McpPlanOperation,
}

fn plan_coalesced_mcp(
    manifest: &EnvironmentManifest,
    projections: Vec<McpPlannedProjection>,
    local_state_text: &str,
    active_profile: Option<ProfileId>,
    limits: McpParseLimits,
) -> Result<CoalescedMcpApplyPlan, McpMaterializationError> {
    if projections.is_empty() {
        return Err(error("mcp_apply.empty"));
    }
    if projections.len() > MAX_MCP_PROJECTIONS {
        return Err(error("mcp_apply.limit"));
    }
    let inspection = ReceiptIndex::inspect_json(local_state_text).map_err(|_| state_invalid())?;
    if !inspection.invalid.is_empty() {
        return Err(state_invalid());
    }
    let initial_state = LocalState::from_json(local_state_text).map_err(|_| state_invalid())?;
    let manifest_revision = derive_manifest_revision(manifest).map_err(|_| source_invalid())?;
    let mut groups = BTreeMap::<NormalizedDestination, Vec<McpPlannedProjection>>::new();
    for projection in projections {
        validate_source(manifest, &projection.projection)?;
        groups
            .entry(projection.projection.observation.destination().clone())
            .or_default()
            .push(projection);
    }
    let mut state = initial_state.clone();
    let mut documents = Vec::with_capacity(groups.len());
    for projections in groups.into_values() {
        documents.push(plan_document(
            manifest,
            &initial_state,
            &mut state,
            &manifest_revision,
            projections,
            limits,
        )?);
    }
    state.machine.active_profile = active_profile.clone();
    let proposed_local_state_text = state.to_json().map_err(|_| state_invalid())?;
    let target_anchors = documents
        .iter()
        .map(|document| document.target_anchor.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let digest = plan_digest(
        &documents,
        &manifest_revision,
        local_state_text,
        &proposed_local_state_text,
        active_profile.as_ref(),
    );
    Ok(CoalescedMcpApplyPlan {
        documents,
        target_anchors,
        manifest_revision,
        observed_local_state_text: local_state_text.to_owned(),
        proposed_local_state: state,
        proposed_local_state_text,
        active_profile,
        digest,
    })
}

fn validate_source(
    manifest: &EnvironmentManifest,
    projection: &McpProjection,
) -> Result<(), McpMaterializationError> {
    manifest.validate().map_err(|_| source_invalid())?;
    projection.policy.validate().map_err(|_| source_invalid())?;
    if projection.observation.policy() != &projection.policy {
        return Err(source_invalid());
    }
    let asset = manifest
        .assets
        .get(&projection.asset_id)
        .ok_or_else(source_invalid)?;
    let portable = asset.portable.as_ref().ok_or_else(source_invalid)?;
    let expected_bindings = projection
        .object
        .server()
        .bearer_token_binding()
        .cloned()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let compatibility = asset
        .compatibility
        .get(&projection.policy.harness)
        .ok_or_else(source_invalid)?;
    if asset.kind != AssetKind::Mcp
        || asset.content_class != ContentClass::AgentActive
        || asset.required_bindings != expected_bindings
        || !matches!(
            compatibility.fidelity(),
            Fidelity::Native | Fidelity::Portable | Fidelity::Adapted
        )
        || compatibility.adapter_version() != projection.policy.adapter_version
        || portable.format != StoredMcpServer::format()
        || portable.object_hash != *projection.object.object_hash()
    {
        return Err(source_invalid());
    }
    Ok(())
}

fn plan_document(
    manifest: &EnvironmentManifest,
    initial_state: &LocalState,
    state: &mut LocalState,
    manifest_revision: &Revision,
    mut projections: Vec<McpPlannedProjection>,
    limits: McpParseLimits,
) -> Result<CoalescedMcpDocument, McpMaterializationError> {
    projections.sort_by(|left, right| left.projection.asset_id.cmp(&right.projection.asset_id));
    let mut native_names = BTreeSet::new();
    if projections.iter().any(|projection| {
        !native_names.insert(
            projection
                .projection
                .object
                .server()
                .name()
                .as_str()
                .to_owned(),
        )
    }) {
        return Err(error("mcp_apply.entry_duplicate"));
    }
    let first = &projections[0].projection;
    if projections.iter().any(|projection| {
        projection.projection.policy != first.policy
            || !projection
                .projection
                .observation
                .has_same_physical_authority(&first.observation)
    }) {
        return Err(error("mcp_apply.document_authority_mismatch"));
    }
    let document_policy = first.policy.clone();
    let document_observation = first.observation.clone();
    if initial_state.receipts.values().any(|receipt| {
        receipt.destination == *document_observation.destination()
            && receipt.target != ReceiptTarget::ManagedMcpEntry
    }) {
        return Err(error("mcp_apply.destination_owned_other"));
    }
    let target_anchor = document_observation
        .destination()
        .anchor_for(&document_policy.relative_document)
        .map_err(|_| source_invalid())?;
    let input = match document_observation.document_bytes() {
        Some(bytes) => std::str::from_utf8(bytes).map_err(|_| source_invalid())?,
        None => empty_document(document_policy.dialect),
    };
    let parsed = document_observation.parsed();
    let mut planned = Vec::with_capacity(projections.len());
    let mut mutations = Vec::with_capacity(projections.len());
    for planned_projection in projections {
        let projection = planned_projection.projection;
        let operation = planned_projection.operation;
        let name = projection.object.server().name().as_str().to_owned();
        let observed_entry = parsed.and_then(|document| {
            document
                .entries()
                .iter()
                .find(|entry| entry.native_name() == name)
        });
        let existing = matching_receipt(
            initial_state,
            &projection.asset_id,
            &projection.policy,
            projection.observation.destination(),
            &name,
        )?;
        let expected_existing = exact_managed_entry(existing, observed_entry, operation)?;
        let asset = manifest
            .assets
            .get(&projection.asset_id)
            .ok_or_else(source_invalid)?;
        let mutation = match operation {
            McpPlanOperation::Apply => McpDocumentMutation::Upsert {
                rendered: render_projection(&projection, initial_state)?,
                expected_existing,
            },
            McpPlanOperation::Retain => {
                planned.push((
                    projection,
                    existing.cloned(),
                    observed_entry.is_some(),
                    asset.content_hash.clone(),
                    operation,
                ));
                continue;
            }
            McpPlanOperation::Remove => McpDocumentMutation::Remove {
                native_name: name,
                expected_existing: expected_existing
                    .ok_or_else(|| error("mcp_remove.entry_missing"))?,
            },
        };
        planned.push((
            projection,
            existing.cloned(),
            observed_entry.is_some(),
            asset.content_hash.clone(),
            operation,
        ));
        mutations.push(mutation);
    }
    let edited = edit_native_mcp_document(input, document_policy.dialect, &mutations, limits)
        .map_err(|error| McpMaterializationError::new(error.code(), error.message()))?;
    let final_document =
        kitrove_mcp::parse_native_mcp_document(edited.text(), document_policy.dialect, limits)
            .map_err(|_| source_invalid())?;
    let prior_document_hash = parsed.map(|document| document.exact_document_hash().clone());
    let mut entries = Vec::with_capacity(planned.len());
    for (projection, existing, entry_was_present, source_hash, operation) in planned {
        let name = projection.object.server().name().as_str();
        let (disposition, proposed) = planned_entry_transition(McpEntryTransitionAuthority {
            operation,
            projection: &projection,
            existing: existing.as_ref(),
            entry_was_present,
            source_hash,
            final_document: &final_document,
            final_document_hash: edited.exact_document_hash(),
            prior_document_hash: prior_document_hash.as_ref(),
            manifest_revision,
        })?;
        if let Some(old) = &existing {
            state
                .receipts
                .remove(&old.receipt_id().map_err(|_| state_invalid())?);
        }
        if let Some(proposed) = &proposed {
            let receipt_id = proposed.receipt_id().map_err(|_| state_invalid())?;
            if state
                .receipts
                .insert(receipt_id, proposed.clone())
                .is_some()
            {
                return Err(state_invalid());
            }
        }
        entries.push(CoalescedMcpEntry {
            asset_id: projection.asset_id,
            native_name: name.to_owned(),
            disposition,
            observed_receipt: existing,
            proposed_receipt: proposed,
            policy: projection.policy,
        });
    }
    let rendered = RenderedCoalescedMcpDocument {
        bytes: edited.text().as_bytes().to_vec(),
        document_hash: edited.exact_document_hash().clone(),
        mode: document_observation.mode(),
    };
    let disposition = if document_observation.document_bytes() == Some(rendered.bytes()) {
        ApplyDisposition::NoOp
    } else if document_observation.is_present() {
        ApplyDisposition::ManagedUpdate
    } else {
        ApplyDisposition::Install
    };
    let relative_destination = document_policy.relative_document;
    let observation = document_observation;
    let mut document = CoalescedMcpDocument {
        destination: observation.destination().clone(),
        target_anchor,
        relative_destination,
        observation,
        rendered,
        disposition,
        entries,
        digest: ContentHash::digest(b"pending"),
    };
    document.digest = document_digest(&document);
    Ok(document)
}

fn exact_managed_entry(
    receipt: Option<&DeploymentReceipt>,
    observed: Option<&ObservedMcpServer>,
    operation: McpPlanOperation,
) -> Result<Option<ContentHash>, McpMaterializationError> {
    match (operation, receipt, observed) {
        (McpPlanOperation::Apply, None, None) => Ok(None),
        (McpPlanOperation::Apply, None, Some(_)) => Err(error("mcp_apply.entry_unmanaged")),
        (McpPlanOperation::Apply, Some(_), None) => Ok(None),
        (_, Some(receipt), Some(entry)) if entry.exact_entry_hash() == &receipt.rendered_hash => {
            Ok(Some(entry.exact_entry_hash().clone()))
        }
        (McpPlanOperation::Apply, Some(_), Some(_)) => Err(error("mcp_apply.entry_modified")),
        (McpPlanOperation::Retain, None, _) => Err(error("mcp_remove.receipt_missing")),
        (McpPlanOperation::Retain, Some(_), None) => Err(error("mcp_remove.entry_missing")),
        (McpPlanOperation::Retain, Some(_), Some(_)) => Err(error("mcp_remove.entry_modified")),
        (McpPlanOperation::Remove, None, _) => Err(error("mcp_remove.receipt_missing")),
        (McpPlanOperation::Remove, Some(_), None) => Err(error("mcp_remove.entry_missing")),
        (McpPlanOperation::Remove, Some(_), Some(_)) => Err(error("mcp_remove.entry_modified")),
    }
}

fn render_projection(
    projection: &McpProjection,
    state: &LocalState,
) -> Result<RenderedMcpEntry, McpMaterializationError> {
    let environment = match projection.object.server().bearer_token_binding() {
        Some(binding) => match state.bindings.get(binding) {
            Some(BindingResolver::Environment { variable }) => Some(variable),
            Some(BindingResolver::Command { .. }) => {
                return Err(error("mcp_apply.binding_command_unsupported"));
            }
            None => return Err(error("mcp_apply.binding_missing")),
        },
        None => None,
    };
    render_native_mcp_entry(
        projection.object.server(),
        projection.policy.dialect,
        environment,
    )
    .map_err(|_| source_invalid())
}

struct McpEntryTransitionAuthority<'a> {
    operation: McpPlanOperation,
    projection: &'a McpProjection,
    existing: Option<&'a DeploymentReceipt>,
    entry_was_present: bool,
    source_hash: ContentHash,
    final_document: &'a ObservedMcpDocument,
    final_document_hash: &'a ContentHash,
    prior_document_hash: Option<&'a ContentHash>,
    manifest_revision: &'a Revision,
}

fn planned_entry_transition(
    authority: McpEntryTransitionAuthority<'_>,
) -> Result<(ApplyDisposition, Option<DeploymentReceipt>), McpMaterializationError> {
    let McpEntryTransitionAuthority {
        operation,
        projection,
        existing,
        entry_was_present,
        source_hash,
        final_document,
        final_document_hash,
        prior_document_hash,
        manifest_revision,
    } = authority;
    let name = projection.object.server().name().as_str();
    if operation == McpPlanOperation::Retain {
        let mut proposed = existing.cloned().ok_or_else(source_invalid)?;
        let retained = final_document
            .entries()
            .iter()
            .find(|entry| entry.native_name() == name)
            .ok_or_else(source_invalid)?;
        if retained.exact_entry_hash() != &proposed.rendered_hash {
            return Err(source_invalid());
        }
        proposed.document_hash = Some(final_document_hash.clone());
        return Ok((ApplyDisposition::NoOp, Some(proposed)));
    }
    if operation == McpPlanOperation::Remove {
        if final_document
            .entries()
            .iter()
            .any(|entry| entry.native_name() == name)
        {
            return Err(source_invalid());
        }
        return Ok((ApplyDisposition::Remove, None));
    }
    let installed = final_document
        .entries()
        .iter()
        .find(|entry| entry.native_name() == name)
        .ok_or_else(source_invalid)?;
    let disposition = match existing {
        None => ApplyDisposition::Install,
        Some(receipt)
            if receipt.source_hash == source_hash
                && receipt.rendered_hash == *installed.exact_entry_hash()
                && receipt.document_hash.as_ref() == Some(final_document_hash)
                && receipt.environment_revision == *manifest_revision
                && receipt.adapter_version == projection.policy.adapter_version =>
        {
            ApplyDisposition::NoOp
        }
        Some(_) if entry_was_present => ApplyDisposition::ManagedUpdate,
        Some(_) => ApplyDisposition::Restore,
    };
    let proposed = match (existing, disposition) {
        (Some(receipt), ApplyDisposition::NoOp) => receipt.clone(),
        _ => DeploymentReceipt {
            asset_id: projection.asset_id.clone(),
            harness: projection.policy.harness.clone(),
            scope: projection.policy.scope,
            destination: projection.observation.destination().clone(),
            target: ReceiptTarget::ManagedMcpEntry,
            logical_key: Some(name.to_owned()),
            shared_with: Default::default(),
            shared_adapter_versions: Default::default(),
            source_hash,
            rendered_hash: installed.exact_entry_hash().clone(),
            document_hash: Some(final_document_hash.clone()),
            prior_hash: prior_document_hash.cloned(),
            adapter_version: projection.policy.adapter_version.to_owned(),
            environment_revision: manifest_revision.clone(),
        },
    };
    Ok((disposition, Some(proposed)))
}

fn matching_receipt<'a>(
    state: &'a LocalState,
    asset_id: &AssetId,
    policy: &McpTargetPolicy,
    destination: &NormalizedDestination,
    native_name: &str,
) -> Result<Option<&'a DeploymentReceipt>, McpMaterializationError> {
    let mut matching = state.receipts.values().filter(|receipt| {
        receipt.asset_id == *asset_id
            && receipt.harness == policy.harness
            && receipt.scope == policy.scope
            && receipt.destination == *destination
            && receipt.target == ReceiptTarget::ManagedMcpEntry
    });
    let first = matching.next();
    if matching.next().is_some()
        || first.is_some_and(|receipt| receipt.logical_key.as_deref() != Some(native_name))
    {
        return Err(state_invalid());
    }
    Ok(first)
}

const fn empty_document(dialect: kitrove_mcp::NativeMcpDialect) -> &'static str {
    match dialect {
        kitrove_mcp::NativeMcpDialect::ClaudeCurrent
        | kitrove_mcp::NativeMcpDialect::OpenCodeV2 => "{}",
        kitrove_mcp::NativeMcpDialect::CodexCurrent => "",
    }
}

fn document_digest(document: &CoalescedMcpDocument) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-coalesced-mcp-document-v2\0");
    write_digest_record(&mut hasher, document.destination.as_str());
    write_digest_record(&mut hasher, document.target_anchor.as_str());
    write_digest_record(&mut hasher, document.relative_destination.as_str());
    write_digest_record(&mut hasher, document.rendered.document_hash.as_str());
    write_digest_record(
        &mut hasher,
        match document.disposition {
            ApplyDisposition::Install => "install",
            ApplyDisposition::NoOp => "no_op",
            ApplyDisposition::Restore => "restore",
            ApplyDisposition::ManagedUpdate => "managed_update",
            ApplyDisposition::Remove => "remove",
        },
    );
    if let Some(parsed) = document.observation.parsed() {
        write_digest_record(&mut hasher, parsed.exact_document_hash().as_str());
    } else {
        write_digest_record(&mut hasher, "absent");
    }
    for entry in &document.entries {
        write_digest_record(&mut hasher, entry.asset_id.as_str());
        write_digest_record(&mut hasher, &entry.native_name);
        write_digest_record(
            &mut hasher,
            match entry.disposition {
                ApplyDisposition::Install => "install",
                ApplyDisposition::NoOp => "no_op",
                ApplyDisposition::Restore => "restore",
                ApplyDisposition::ManagedUpdate => "managed_update",
                ApplyDisposition::Remove => "remove",
            },
        );
        let receipt = entry
            .proposed_receipt
            .as_ref()
            .or(entry.observed_receipt.as_ref())
            .expect("an MCP entry transition has receipt authority");
        write_digest_record(&mut hasher, receipt.rendered_hash.as_str());
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("BLAKE3 produces a valid content hash")
}

fn plan_digest(
    documents: &[CoalescedMcpDocument],
    manifest_revision: &Revision,
    observed_state: &str,
    proposed_state: &str,
    active_profile: Option<&ProfileId>,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-coalesced-mcp-plan-v1\0");
    write_digest_record(&mut hasher, manifest_revision.as_str());
    write_digest_record(&mut hasher, observed_state);
    write_digest_record(&mut hasher, proposed_state);
    write_digest_record(
        &mut hasher,
        active_profile.map_or("none", ProfileId::as_str),
    );
    for document in documents {
        write_digest_record(&mut hasher, document.digest.as_str());
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("BLAKE3 produces a valid content hash")
}

const fn error(code: &'static str) -> McpMaterializationError {
    McpMaterializationError::new(
        code,
        "MCP materialization authority was missing, stale, ambiguous, or unsupported",
    )
}

const fn source_invalid() -> McpMaterializationError {
    error("mcp_apply.source_invalid")
}

const fn state_invalid() -> McpMaterializationError {
    error("mcp_apply.local_state_invalid")
}

impl McpMaterializationError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}
