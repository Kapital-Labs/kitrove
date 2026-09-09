#![forbid(unsafe_code)]
//! Harness-neutral planning helpers.

mod adoption;
mod agent_adoption;
mod agent_materialization;
mod agent_observation;
mod agent_removal;
mod agent_update;
mod apply_batch;
mod apply_batch_journal;
mod apply_batch_transaction;
mod apply_target;
mod authority;
mod classification;
mod discovery;
mod engine;
mod executable_trust;
mod executable_trust_transaction;
mod extension_materialization;
mod filesystem_identity;
mod filesystem_sync_backend;
mod git_remote;
mod git_sync_backend;
mod guarded_control;
mod guarded_journal;
mod instruction_adoption;
mod instruction_apply_batch;
mod instruction_apply_transaction;
mod instruction_materialization;
mod instruction_observation;
mod instruction_removal;
mod instruction_risk;
mod instruction_update;
mod limits;
mod local_state_authority;
mod materialization;
mod mcp_adoption;
mod mcp_materialization;
mod mcp_observation;
mod mcp_update;
mod merge;
mod native_extension;
mod native_extension_adoption;
mod native_extension_transaction;
mod object_mutation;
mod object_store;
mod observation_identity;
mod pack_creation;
mod pack_distribution;
mod pack_distribution_plan;
mod pack_inspection;
mod pack_rollback;
mod pack_rollback_plan;
mod pi_project_trust;
mod portable_transaction;
mod profile_resolution;
mod prompt_command_adoption;
mod prompt_command_materialization;
mod prompt_command_observation;
mod prompt_command_removal;
mod prompt_command_update;
mod quarantine_cleanup;
mod quarantine_name;
mod read_only_fs;
mod receipt;
mod registry;
mod render;
mod report;
mod snapshot;
mod ssh_git_transport;
mod ssh_known_hosts;
mod sync_backend;
mod sync_base_store;
mod sync_journal;
mod sync_plan;
mod sync_portable_transaction;
mod sync_transaction;
#[cfg(test)]
mod test_authority;
mod update;
mod whole_file_adoption;

#[cfg(test)]
mod d3_canary_matrix;

pub use adoption::{
    AdoptionBlock, AdoptionBlockReason, AdoptionDisposition, AdoptionError, AdoptionIdChoice,
    AdoptionPlan, AdoptionPlanOutcome, AdoptionRecoveryAction, TierOneCapabilities, plan_adoption,
};
pub use agent_adoption::{
    AgentAdoptionBlock, AgentAdoptionBlockReason, AgentAdoptionError, AgentAdoptionOutcome,
    AgentAdoptionPlan, TierOneAgentCapabilities, plan_agent_adoption,
};
pub use agent_materialization::{
    AgentApplyPlan, AgentDestinationObservation, RenderedAgent, observe_agent_destination,
    plan_agent_apply, resolve_agent_destination,
};
pub use agent_observation::{AgentObservation, AgentObservationError, observe_agent_file_metered};
pub use agent_removal::{AgentRemovalPlan, observe_agent_receipt_destination, plan_agent_removal};
pub use agent_update::{AgentUpdateError, AgentUpdatePlan, plan_agent_update};
pub use apply_batch::{
    AtomicApplyBatchError, AtomicApplyBatchPlan, AtomicApplyItem, AtomicInstructionApplyPlan,
    AtomicMcpApplyPlan, PackApplicationSelection,
};
pub use apply_batch_journal::{
    AtomicApplyBatchJournalError, AtomicApplyBatchJournalStatus, AtomicApplyBatchPhase,
    inspect_atomic_apply_batch_journal,
};
pub use apply_batch_transaction::{
    AtomicApplyBatchCommitOutcome, AtomicApplyBatchRecoveryOutcome,
    AtomicApplyBatchTransactionError, commit_atomic_apply_batch, recover_atomic_apply_batch,
    validate_atomic_apply_batch_authority,
};
pub use authority::{
    LockComparison, LockStatus, compare_lockfile, derive_lockfile, derive_manifest_revision,
};
pub use discovery::{
    DiscoveredLocator, DiscoveryReport, FailedLocator, FailedRoot, RelatedDiscoveryReport,
    RelatedDocumentLocator, discover_locators, discover_related_documents,
};
pub use engine::{
    AcceptedObservedCandidate, FailedObservedCandidate, ObservationLocation, ObservedCandidate,
    ScanEngine,
};
pub use executable_trust::{
    ExecutableTrustDecision, ExecutableTrustDisposition, ExecutableTrustError,
    ExecutableTrustInspection, ExecutableTrustPlan, ExecutableTrustStatus,
    inspect_executable_trust, plan_executable_trust,
};
pub use executable_trust_transaction::{
    ExecutableTrustCommitOutcome, ExecutableTrustRecoveryOutcome, ExecutableTrustTransactionError,
    commit_executable_trust, recover_executable_trust,
};
pub use extension_materialization::{
    ExtensionApplyAuthority, ExtensionApplyPlan, ExtensionDestinationObservation,
    RenderedExtension, authorize_extension_apply, observe_extension_destination,
    pi_extension_removal_policy, plan_extension_apply, plan_extension_removal,
    plan_extension_retention, render_native_extension, resolve_extension_destination,
};
pub use filesystem_sync_backend::{
    FilesystemApplySession, FilesystemReadSession, FilesystemSyncBackend,
};
pub use git_remote::{GitRemoteUrl, SshGitRemoteUrl};
pub use git_sync_backend::{
    GitApplySession, GitBasicCredential, GitCredentialProvider, GitReadSession, GitSyncBackend,
    SshGitApplySession, SshGitReadSession, SshGitSyncBackend,
};
pub use instruction_adoption::{
    InstructionAdoptionBlock, InstructionAdoptionBlockReason, InstructionAdoptionError,
    InstructionAdoptionOutcome, InstructionAdoptionPlan, TierOneInstructionCapabilities,
    plan_instruction_adoption,
};
pub use instruction_apply_batch::{
    CoalescedInstructionApplyError, CoalescedInstructionApplyPlan, CoalescedInstructionDocument,
    CoalescedInstructionRegion, InstructionProjection, RenderedCoalescedInstructionDocument,
    plan_coalesced_instruction_apply,
};
pub use instruction_apply_transaction::{
    InstructionApplyCommitOutcome, InstructionApplyRecoveryOutcome,
    InstructionApplyTransactionError, commit_instruction_apply, recover_instruction_apply,
};
pub use instruction_materialization::{
    InstructionApplyPlan, InstructionMaterializationError, RenderedInstructionDocument,
    plan_instruction_apply,
};
pub use instruction_observation::{
    InstructionDocumentObservation, InstructionObservationError, ObservedInstructionRegion,
    classify_instruction_region, observe_instruction_document,
    observe_instruction_document_metered,
};
pub use instruction_removal::{
    InstructionRemovalProjection, InstructionRemovalSelection, plan_coalesced_instruction_removal,
    plan_coalesced_instruction_removal_selection,
};
pub use instruction_update::{
    InstructionUpdateError, InstructionUpdatePlan, InstructionUpdateSource, plan_instruction_update,
};
pub use limits::ScanBudget;
pub use materialization::{
    ApplyDisposition, ApplyPlan, DestinationObservation, MaterializationError, RenderedSkill,
    guard_asset_materialization, observe_skill_destination, plan_skill_apply, plan_skill_removal,
    render_portable_skill, resolve_target_destination,
};
pub use mcp_adoption::{
    McpAdoptionBlock, McpAdoptionBlockReason, McpAdoptionError, McpAdoptionOutcome,
    McpAdoptionPlan, TierOneMcpCapabilities, plan_mcp_adoption,
};
pub use mcp_materialization::{
    CoalescedMcpApplyPlan, CoalescedMcpDocument, CoalescedMcpEntry, McpMaterializationError,
    McpProjection, McpRemovalSelection, RenderedCoalescedMcpDocument, plan_coalesced_mcp_apply,
    plan_coalesced_mcp_removal, plan_coalesced_mcp_removal_selection,
};
pub use mcp_observation::{
    McpDocumentObservation, McpObservationError, observe_mcp_document, observe_mcp_document_metered,
};
pub use mcp_update::{McpUpdateError, McpUpdatePlan, plan_mcp_update};
pub use merge::{
    SemanticMergeError, SemanticMergeResult, VerifiedSkillObjectCatalog, merge_manifests,
};
pub use native_extension::{
    CapturedNativeExtension, NativeExtensionLayout, NativeExtensionObject, NativeExtensionSource,
    capture_pi_extension, capture_pi_extension_metered,
};
pub use native_extension_adoption::{
    NativeExtensionDisposition, NativeExtensionObservation, NativeExtensionPlan,
    NativeExtensionPlanningError, plan_native_extension_adoption, plan_native_extension_update,
};
pub use native_extension_transaction::{NativeExtensionCommitError, commit_native_extension_plan};
pub use object_mutation::{
    ObjectInstallOutcome, ObjectMutationError, ObjectStageOutcome, ObjectStore,
    initialize_empty_authority, preflight_empty_authority_initialization,
};
pub use object_store::{
    ObjectFinding, ObjectKind, ObjectState, ObjectVerification, load_native_agent_object,
    load_native_extension_object, load_native_extension_object_bounded,
    load_native_instruction_object, load_native_instruction_object_bounded, load_native_mcp_object,
    load_native_prompt_command_object, load_native_skill_object, load_native_skill_object_bounded,
    load_portable_agent_object, load_portable_instruction_object,
    load_portable_instruction_object_bounded, load_portable_mcp_object,
    load_portable_prompt_command_object, load_portable_skill_object,
    load_portable_skill_object_bounded, verify_referenced_objects,
};
pub use pack_creation::{
    PackCreationError, PackCreationPlan, PackMutationError, PackMutationKind, PackMutationPlan,
    PackRevisionChange, PackUpdateError, PackUpdatePlan, plan_pack_creation, plan_pack_update,
};
pub use pack_distribution::{
    PackDistributionError, PackDistributionSelection, select_pack_distribution,
};
pub use pack_distribution_plan::{PackDistributionPlan, plan_pack_distribution_adoption};
pub use pack_inspection::{
    PackComponent, PackComponentKind, PackInspection, PackInspectionError, inspect_pack,
    resolve_pack_asset_memberships, resolve_pack_assets,
};
pub use pack_rollback::{
    PackRollbackError, PackRollbackSelection, VerifiedHistoricalSnapshot, VerifiedRemoteHistory,
    select_pack_rollback_snapshot,
};
pub use pack_rollback_plan::{PackRollbackPlan, plan_pack_rollback};
pub use pi_project_trust::{
    PiProjectTrustError, PiProjectTrustEvidence, PiProjectTrustStatus, inspect_pi_project_trust,
};
pub use portable_transaction::{
    AdoptionCommitOutcome, LockRepairOutcome, LockRepairPlan, PortableJournalStatus,
    PortableManifestCommitOutcome, PortableRecoveryOutcome, PortableStatus,
    PortableTransactionError, UpdateCommitOutcome, UpdateRecoveryOutcome, commit_adoption,
    commit_agent_adoption, commit_agent_update, commit_instruction_adoption,
    commit_instruction_update, commit_lock_repair, commit_mcp_adoption, commit_mcp_update,
    commit_pack_creation, commit_pack_distribution_adoption, commit_pack_rollback,
    commit_pack_update, commit_prompt_command_adoption, commit_prompt_command_update,
    commit_update_adoption, inspect_portable_environment, inspect_portable_journal,
    plan_lock_repair, recover_portable_environment, recover_update_adoption,
};
pub use profile_resolution::{ProfileResolutionError, ResolvedProfile, resolve_profile};
pub use prompt_command_adoption::{
    PromptCommandAdoptionBlock, PromptCommandAdoptionBlockReason, PromptCommandAdoptionError,
    PromptCommandAdoptionOutcome, PromptCommandAdoptionPlan, TierOnePromptCommandCapabilities,
    plan_prompt_command_adoption,
};
pub use prompt_command_materialization::{
    PromptCommandApplyPlan, PromptCommandDestinationObservation, RenderedPromptCommand,
    observe_prompt_command_destination, plan_prompt_command_apply,
    resolve_prompt_command_destination,
};
pub use prompt_command_observation::PromptCommandObservation;
pub use prompt_command_removal::{
    PromptCommandRemovalPlan, observe_prompt_command_receipt_destination,
    plan_prompt_command_removal,
};
pub use prompt_command_update::{
    PromptCommandUpdateError, PromptCommandUpdatePlan, plan_prompt_command_update,
};
pub use receipt::{
    InspectedReceipt, InvalidReceipt, ReceiptIndex, ReceiptInspection, ReceiptInvalidityScope,
};
pub use registry::{PolicyCatalog, PolicyRegistration, PolicyRegistry};
pub use render::{render_scan_json, render_scan_text};
pub use report::{
    AgentScanEntry, InstructionScanEntry, McpPrecedence, McpScanEntry, NativeExtensionScanEntry,
    PromptCommandScanEntry, RelatedCapabilityObservation, ScanClassification, ScanEntry, ScanMode,
    ScanReport,
};
pub use snapshot::{
    PortableSnapshotV1, SnapshotError, native_snapshot_object_kind, portable_snapshot_object_kind,
};
pub use sync_backend::{
    BackendError, PublicationIntent, PublicationStatus, RemoteSnapshot, SyncBackend,
    SyncBackendApply, SyncBackendRead, VerifiedDocumentObject, VerifiedObjectEnvelope,
};
pub use sync_base_store::{RetainedSyncBase, SyncBaseStore, SyncBaseStoreError};
pub use sync_journal::{SyncJournal, SyncJournalError, SyncJournalPhase};
pub use sync_plan::{
    SyncBaseInput, SyncDisposition, SyncPlan, SyncPlanOutcome, SyncPlanningError, plan_sync,
};
pub use sync_portable_transaction::{
    SyncPortableCommitOutcome, SyncPortableRecoveryOutcome, SyncPortableTransactionError,
    commit_sync_portable_snapshot, recover_sync_portable_snapshot,
};
pub use sync_transaction::{
    SyncCommitOutcome, SyncRecoveryOutcome, SyncTransactionError, commit_sync_transaction,
    recover_sync_transaction, sync_transaction_journal_path,
};
pub use update::{
    UpdatePlan, UpdatePlanningError, UpdateSelectionError, UpdateSource, UpdateSourceAuthority,
    plan_update_adoption,
};

use std::collections::BTreeMap;

use kitrove_model::{Fidelity, FidelityResult, HarnessId};

/// Counts categorical outcomes without hiding their reasons.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FidelitySummary {
    /// Number of target-native results.
    pub native: usize,
    /// Number of shared portable results.
    pub portable: usize,
    /// Number of reviewed adaptations.
    pub adapted: usize,
    /// Number of partial results.
    pub partial: usize,
    /// Number of unsupported results.
    pub unsupported: usize,
    /// Number of locally blocked results.
    pub blocked: usize,
}

impl FidelitySummary {
    /// Summarizes categories while callers retain the original detailed map.
    #[must_use]
    pub fn from_results(results: &BTreeMap<HarnessId, FidelityResult>) -> Self {
        let mut summary = Self::default();
        for result in results.values() {
            match result.fidelity() {
                Fidelity::Native => summary.native += 1,
                Fidelity::Portable => summary.portable += 1,
                Fidelity::Adapted => summary.adapted += 1,
                Fidelity::Partial => summary.partial += 1,
                Fidelity::Unsupported => summary.unsupported += 1,
                Fidelity::Blocked => summary.blocked += 1,
            }
        }
        summary
    }

    /// Returns true when at least one result needs explicit user attention.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        self.partial > 0 || self.unsupported > 0 || self.blocked > 0
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use kitrove_model::{Fidelity, FidelityEvidence, FidelityReason, FidelityResult, HarnessId};

    use super::FidelitySummary;

    #[test]
    fn attention_is_preserved_in_summary() {
        let mut results = BTreeMap::new();
        results.insert(
            HarnessId::Claude,
            FidelityResult::exact(
                Fidelity::Native,
                vec![FidelityEvidence::new(
                    "test.native",
                    "native representation is used unchanged",
                )],
                "test-adapter/1",
                None,
            )
            .expect("native fidelity is exact"),
        );
        results.insert(
            HarnessId::Pi,
            FidelityResult::new(
                Fidelity::Partial,
                vec![FidelityReason::new(
                    "hook.unsupported",
                    "one lifecycle hook cannot be represented",
                )],
                vec![FidelityEvidence::new(
                    "test.matrix",
                    "target capability matrix omits lifecycle hooks",
                )],
                vec![],
                "test-adapter/1",
                None,
            )
            .expect("partial fidelity has a reason and evidence"),
        );

        let summary = FidelitySummary::from_results(&results);
        assert_eq!(summary.native, 1);
        assert_eq!(summary.partial, 1);
        assert!(summary.needs_attention());
    }
}
