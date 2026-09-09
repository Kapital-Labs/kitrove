use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_agent_skills::{CaptureLimits, NativeSkillObject, StoredSkillTree};
use kitrove_agents::{StoredAgent, StoredNativeAgent};
use kitrove_instructions::{InstructionLimits, NativeInstructionRegion, StoredInstruction};
use kitrove_mcp::{StoredMcpServer, StoredNativeMcpEntry};
use kitrove_model::{
    Asset, ContentHash, EnvironmentManifest, HarnessId, Lockfile, NativeVariant, PortableContent,
    PortablePath, ReceiptId, ReceiptTarget, Revision,
};
use kitrove_prompt_commands::{StoredNativePromptCommand, StoredPromptCommand};
use serde::{Deserialize, Serialize};

use crate::instruction_observation::observe_instruction_region_hash;
use crate::local_state_authority;
use crate::object_mutation::guarded_backup_path;
use crate::pack_creation::PackMutationKind;
use crate::quarantine_cleanup::coordinator::{
    MutationCleanupError, MutationWork, cleanup_locked_stores,
};
use crate::{
    AcceptedObservedCandidate, AdoptionDisposition, AdoptionPlan, AgentAdoptionPlan,
    AgentObservation, AgentUpdatePlan, DestinationObservation, InstructionAdoptionPlan,
    InstructionDocumentObservation, InstructionUpdatePlan, LockStatus, McpAdoptionPlan,
    McpDocumentObservation, McpUpdatePlan, ObjectInstallOutcome, ObjectStore, ObjectVerification,
    PackCreationPlan, PackDistributionPlan, PackRollbackPlan, PackUpdatePlan,
    PromptCommandAdoptionPlan, PromptCommandObservation, PromptCommandUpdatePlan, UpdatePlan,
    VerifiedObjectEnvelope, compare_lockfile, derive_lockfile, derive_manifest_revision,
    observe_skill_destination, verify_referenced_objects,
};

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 64 * 1024;
const MANIFEST_PATH: &str = "kitrove.toml";
const LOCK_PATH: &str = "kitrove.lock.json";
const JOURNAL_PATH: &str = ".kitrove/adoption-journal.json";
const JOURNAL_PENDING_PATH: &str = ".kitrove/adoption-journal.pending";
const RECOVERY_LOCK_STAGE_PATH: &str = ".kitrove/recovery-lock.pending";

mod cleanup_inventory;
mod recovery_control;

use cleanup_inventory::{
    ORPHAN_PENDING_CLEANUP_TOMBSTONES, PortableMutationKind, PortableRecoveryDirection,
};
use recovery_control::{
    PortableJournalControlState, effective_guarded_control_text, journal_status_with_store,
    portable_journal_control_state, reconcile_guarded_control, restore_interrupted_journal_control,
};

/// Successful authority result of an adoption transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionCommitOutcome {
    Committed,
    Repaired,
    Recovered,
}

/// Result of inspecting and resolving an existing portable journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortableRecoveryOutcome {
    NoJournal,
    DiscardedUncommitted,
    CompletedCommitted,
}

/// Successful result of an exact-prior update transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateCommitOutcome {
    Committed,
    CommittedWithReceipt,
    CommittedWithoutReceipt,
    Recovered,
    RecoveredWithReceipt,
    RecoveredWithoutReceipt,
}

/// Result of resolving an interrupted exact-prior update transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateRecoveryOutcome {
    NoJournal,
    DiscardedUncommitted,
    Completed,
    CompletedWithReceipt,
    CompletedWithoutReceipt,
}

/// Read-only status of the recovery journal that blocks later portable mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortableJournalStatus {
    Absent,
    Pending,
    Invalid,
}

/// Complete read-only status of portable desired state and generated state.
#[derive(Clone, Eq, PartialEq)]
pub struct PortableStatus {
    manifest_revision: Revision,
    lock_status: LockStatus,
    objects: ObjectVerification,
    journal_status: PortableJournalStatus,
}

/// Result of a generated-lock-only transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockRepairOutcome {
    AlreadyInSync,
    Repaired,
    Recovered,
}

/// Result of atomically committing a metadata-only portable manifest mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortableManifestCommitOutcome {
    Committed,
    Recovered,
}

/// Deterministic plan to replace only generated lock state.
#[derive(Clone, Eq, PartialEq)]
pub struct LockRepairPlan {
    manifest_revision: Revision,
    expected_lock: Lockfile,
    observed_status: LockStatus,
    observed_lock: Option<String>,
    digest: ContentHash,
}

impl LockRepairPlan {
    #[must_use]
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    #[must_use]
    pub const fn expected_lock(&self) -> &Lockfile {
        &self.expected_lock
    }

    #[must_use]
    pub const fn observed_status(&self) -> LockStatus {
        self.observed_status
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

impl Debug for LockRepairPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockRepairPlan")
            .field("manifest_revision", &self.manifest_revision)
            .field("observed_status", &self.observed_status)
            .field(
                "observed_lock_hash",
                &self
                    .observed_lock
                    .as_deref()
                    .map(|text| ContentHash::digest(text.as_bytes())),
            )
            .field("digest", &self.digest)
            .finish()
    }
}

impl PortableStatus {
    #[must_use]
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    #[must_use]
    pub const fn lock_status(&self) -> LockStatus {
        self.lock_status
    }

    #[must_use]
    pub const fn objects(&self) -> &ObjectVerification {
        &self.objects
    }

    #[must_use]
    pub const fn journal_status(&self) -> PortableJournalStatus {
        self.journal_status
    }

    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.lock_status == LockStatus::InSync
            && self.objects.is_clean()
            && self.journal_status == PortableJournalStatus::Absent
    }
}

impl Debug for PortableStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableStatus")
            .field("manifest_revision", &self.manifest_revision)
            .field("lock_status", &self.lock_status)
            .field("objects", &self.objects)
            .field("journal_status", &self.journal_status)
            .finish()
    }
}

/// A stable, content- and path-redacted portable transaction failure.
#[derive(Clone, Eq, PartialEq)]
pub struct PortableTransactionError {
    code: &'static str,
    message: &'static str,
}

impl PortableTransactionError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for PortableTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableTransactionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for PortableTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for PortableTransactionError {}

impl From<crate::ObjectMutationError> for PortableTransactionError {
    fn from(error: crate::ObjectMutationError) -> Self {
        store_error(error)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Prepared,
    ObjectsInstalled,
    ManifestCommitted,
    LockCommitted,
    StateCommitted,
    Verified,
    Complete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JournalOperation {
    Adopt,
    Lock,
    Manifest,
    Update,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PortableJournal {
    schema_version: u32,
    operation: JournalOperation,
    phase: JournalPhase,
    plan_digest: ContentHash,
    old_manifest_revision: Revision,
    new_manifest_revision: Revision,
    old_manifest_hash: ContentHash,
    new_manifest_hash: ContentHash,
    staging_manifest: Option<PortablePath>,
    staging_lock: PortablePath,
    old_lock_hash: Option<ContentHash>,
    new_lock_hash: ContentHash,
    portable_root: Option<PortablePath>,
    portable_hash: Option<ContentHash>,
    native_root: Option<PortablePath>,
    native_hash: Option<ContentHash>,
    portable_preexisting: Option<bool>,
    native_preexisting: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    portable_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_format: Option<String>,
    staging_state: Option<PortablePath>,
    old_state_hash: Option<ContentHash>,
    new_state_hash: Option<ContentHash>,
    receipt_id: Option<ReceiptId>,
    reviewed_target_hash: Option<ContentHash>,
    expected_prior: Option<ContentHash>,
}

#[derive(Clone, Copy)]
enum AdoptionPlanRef<'a> {
    Skill(&'a AdoptionPlan),
    Instruction(&'a InstructionAdoptionPlan),
    PromptCommand(&'a PromptCommandAdoptionPlan),
    PromptCommandUpdate(&'a PromptCommandUpdatePlan),
    Agent(&'a AgentAdoptionPlan),
    AgentUpdate(&'a AgentUpdatePlan),
    Mcp(&'a McpAdoptionPlan),
    McpUpdate(&'a McpUpdatePlan),
}

#[derive(Clone, Copy)]
enum AdoptionObservationRef<'a> {
    Skill(&'a AcceptedObservedCandidate),
    Instruction(&'a InstructionDocumentObservation),
    PromptCommand(&'a PromptCommandObservation),
    Agent(&'a AgentObservation),
    Mcp(&'a McpDocumentObservation),
}

#[derive(Clone, Copy)]
enum UpdatePlanRef<'a> {
    Skill(&'a UpdatePlan),
    Instruction(&'a InstructionUpdatePlan),
}

#[derive(Clone, Copy)]
enum UpdateObservationRef<'a> {
    Skill(&'a AcceptedObservedCandidate),
    Instruction(&'a InstructionDocumentObservation),
}

#[derive(Clone, Copy)]
enum ObjectPlanRef<'a> {
    Skill {
        portable: &'a StoredSkillTree,
        native: &'a NativeSkillObject,
    },
    Instruction {
        portable: &'a StoredInstruction,
        native: &'a NativeInstructionRegion,
    },
    PromptCommand {
        portable: &'a StoredPromptCommand,
        native: &'a StoredNativePromptCommand,
    },
    Agent {
        portable: &'a StoredAgent,
        native: &'a StoredNativeAgent,
    },
    Mcp {
        portable: &'a StoredMcpServer,
        native: &'a StoredNativeMcpEntry,
    },
}

impl ObjectPlanRef<'_> {
    fn journal_formats(self) -> (Option<String>, Option<String>) {
        match self {
            Self::Skill { .. } => (None, None),
            Self::Instruction { .. } => (
                Some(StoredInstruction::format().to_owned()),
                Some(NativeInstructionRegion::format().to_owned()),
            ),
            Self::PromptCommand { .. } => (
                Some(StoredPromptCommand::format().to_owned()),
                Some(StoredNativePromptCommand::format().to_owned()),
            ),
            Self::Agent { .. } => (
                Some(StoredAgent::format().to_owned()),
                Some(StoredNativeAgent::format().to_owned()),
            ),
            Self::Mcp { .. } => (
                Some(StoredMcpServer::format().to_owned()),
                Some(StoredNativeMcpEntry::format().to_owned()),
            ),
        }
    }

    fn portable_preexisting(
        self,
        store: &ObjectStore,
        portable: &PortableContent,
        limits: CaptureLimits,
    ) -> bool {
        match self {
            Self::Skill { .. } => {
                store.portable_is_verified(&portable.root, &portable.object_hash, limits)
            }
            Self::Instruction { .. } => store.portable_instruction_is_verified(
                &portable.root,
                &portable.object_hash,
                limits,
            ),
            Self::PromptCommand { .. } => store.portable_prompt_command_is_verified(
                &portable.root,
                &portable.object_hash,
                limits,
            ),
            Self::Agent { .. } => {
                store.portable_agent_is_verified(&portable.root, &portable.object_hash, limits)
            }
            Self::Mcp { .. } => {
                store.portable_mcp_is_verified(&portable.root, &portable.object_hash, limits)
            }
        }
    }

    fn native_preexisting(
        self,
        store: &ObjectStore,
        native: &NativeVariant,
        limits: CaptureLimits,
    ) -> bool {
        match self {
            Self::Skill { .. } => {
                store.native_is_verified(&native.root, &native.object_hash, limits)
            }
            Self::Instruction { .. } => {
                store.native_instruction_is_verified(&native.root, &native.object_hash, limits)
            }
            Self::PromptCommand { .. } => {
                store.native_prompt_command_is_verified(&native.root, &native.object_hash, limits)
            }
            Self::Agent { .. } => {
                store.native_agent_is_verified(&native.root, &native.object_hash, limits)
            }
            Self::Mcp { .. } => store.native_mcp_is_verified(
                &native.root,
                &native.object_hash,
                &native.harness,
                limits,
            ),
        }
    }

    fn prepare_portable(
        self,
        store: &ObjectStore,
        staging: &PortablePath,
        portable: &PortableContent,
        preexisting: bool,
        limits: CaptureLimits,
    ) -> Result<(), PortableTransactionError> {
        match (self, preexisting) {
            (Self::Skill { .. }, true) => {
                store.clear_portable_staging(staging, &portable.object_hash, limits)
            }
            (
                Self::Skill {
                    portable: object, ..
                },
                false,
            ) => {
                store.reset_incomplete_portable_staging(staging, &portable.object_hash, limits)?;
                store.stage_portable(staging, object, limits).map(|_| ())
            }
            (Self::Instruction { .. }, true) => {
                store.clear_portable_instruction_staging(staging, &portable.object_hash, limits)
            }
            (
                Self::Instruction {
                    portable: object, ..
                },
                false,
            ) => {
                store.reset_incomplete_portable_instruction_staging(
                    staging,
                    &portable.object_hash,
                    limits,
                )?;
                store
                    .stage_portable_instruction(staging, object, limits)
                    .map(|_| ())
            }
            (Self::PromptCommand { .. }, true) => {
                store.clear_portable_prompt_command_staging(staging, &portable.object_hash, limits)
            }
            (
                Self::PromptCommand {
                    portable: object, ..
                },
                false,
            ) => {
                store.reset_incomplete_portable_prompt_command_staging(
                    staging,
                    &portable.object_hash,
                    limits,
                )?;
                store
                    .stage_portable_prompt_command(staging, object, limits)
                    .map(|_| ())
            }
            (Self::Agent { .. }, true) => {
                store.clear_portable_agent_staging(staging, &portable.object_hash, limits)
            }
            (
                Self::Agent {
                    portable: object, ..
                },
                false,
            ) => {
                store.reset_incomplete_portable_agent_staging(
                    staging,
                    &portable.object_hash,
                    limits,
                )?;
                store
                    .stage_portable_agent(staging, object, limits)
                    .map(|_| ())
            }
            (Self::Mcp { .. }, true) => {
                store.clear_portable_mcp_staging(staging, &portable.object_hash, limits)
            }
            (
                Self::Mcp {
                    portable: object, ..
                },
                false,
            ) => {
                store.reset_incomplete_portable_mcp_staging(
                    staging,
                    &portable.object_hash,
                    limits,
                )?;
                store
                    .stage_portable_mcp(staging, object, limits)
                    .map(|_| ())
            }
        }
        .map_err(store_error)
    }

    fn prepare_native(
        self,
        store: &ObjectStore,
        staging: &PortablePath,
        native: &NativeVariant,
        preexisting: bool,
        limits: CaptureLimits,
    ) -> Result<(), PortableTransactionError> {
        match (self, preexisting) {
            (Self::Skill { .. }, true) => {
                store.clear_native_staging(staging, &native.object_hash, limits)
            }
            (Self::Skill { native: object, .. }, false) => {
                store.reset_incomplete_native_staging(staging, &native.object_hash, limits)?;
                store.stage_native(staging, object, limits).map(|_| ())
            }
            (Self::Instruction { .. }, true) => {
                store.clear_native_instruction_staging(staging, &native.object_hash, limits)
            }
            (Self::Instruction { native: object, .. }, false) => {
                store.reset_incomplete_native_instruction_staging(
                    staging,
                    &native.object_hash,
                    limits,
                )?;
                store
                    .stage_native_instruction(staging, object, limits)
                    .map(|_| ())
            }
            (Self::PromptCommand { .. }, true) => {
                store.clear_native_prompt_command_staging(staging, &native.object_hash, limits)
            }
            (Self::PromptCommand { native: object, .. }, false) => {
                store.reset_incomplete_native_prompt_command_staging(
                    staging,
                    &native.object_hash,
                    limits,
                )?;
                store
                    .stage_native_prompt_command(staging, object, limits)
                    .map(|_| ())
            }
            (Self::Agent { .. }, true) => {
                store.clear_native_agent_staging(staging, &native.object_hash, limits)
            }
            (Self::Agent { native: object, .. }, false) => {
                store.reset_incomplete_native_agent_staging(
                    staging,
                    &native.object_hash,
                    limits,
                )?;
                store
                    .stage_native_agent(staging, object, limits)
                    .map(|_| ())
            }
            (Self::Mcp { .. }, true) => {
                store.clear_native_mcp_staging(staging, &native.object_hash, limits)
            }
            (Self::Mcp { native: object, .. }, false) => {
                store.reset_incomplete_native_mcp_staging(staging, &native.object_hash, limits)?;
                store.stage_native_mcp(staging, object, limits).map(|_| ())
            }
        }
        .map_err(store_error)
    }

    fn install(
        self,
        store: &ObjectStore,
        paths: &TransactionPaths,
        portable: &PortableContent,
        native: &NativeVariant,
        limits: CaptureLimits,
    ) -> Result<(), PortableTransactionError> {
        match self {
            Self::Skill { .. } => {
                store.install_portable(
                    &paths.portable,
                    &portable.root,
                    &portable.object_hash,
                    limits,
                )?;
                store.install_native(&paths.native, &native.root, &native.object_hash, limits)?;
            }
            Self::Instruction { .. } => {
                store.install_portable_instruction(
                    &paths.portable,
                    &portable.root,
                    &portable.object_hash,
                    limits,
                )?;
                store.install_native_instruction(
                    &paths.native,
                    &native.root,
                    &native.object_hash,
                    limits,
                )?;
            }
            Self::PromptCommand { .. } => {
                store.install_portable_prompt_command(
                    &paths.portable,
                    &portable.root,
                    &portable.object_hash,
                    limits,
                )?;
                store.install_native_prompt_command(
                    &paths.native,
                    &native.root,
                    &native.object_hash,
                    limits,
                )?;
            }
            Self::Agent { .. } => {
                store.install_portable_agent(
                    &paths.portable,
                    &portable.root,
                    &portable.object_hash,
                    limits,
                )?;
                store.install_native_agent(
                    &paths.native,
                    &native.root,
                    &native.object_hash,
                    limits,
                )?;
            }
            Self::Mcp { .. } => {
                store.install_portable_mcp(
                    &paths.portable,
                    &portable.root,
                    &portable.object_hash,
                    limits,
                )?;
                store.install_native_mcp(
                    &paths.native,
                    &native.root,
                    &native.object_hash,
                    limits,
                )?;
            }
        }
        Ok(())
    }
}

impl<'a> UpdatePlanRef<'a> {
    fn ensure_observation_fresh(
        self,
        reread: UpdateObservationRef<'_>,
    ) -> Result<(), PortableTransactionError> {
        match (self, reread) {
            (Self::Skill(plan), UpdateObservationRef::Skill(observation)) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            (Self::Instruction(plan), UpdateObservationRef::Instruction(observation)) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            _ => Err(observation_stale()),
        }
    }

    fn ensure_portable_authority_fresh(
        self,
        manifest_text: &str,
        manifest: &EnvironmentManifest,
        lock_text: Option<&str>,
    ) -> Result<(), PortableTransactionError> {
        match self {
            Self::Skill(plan) => plan
                .ensure_portable_authority_fresh(manifest_text, manifest, lock_text)
                .map_err(|_| manifest_stale()),
            Self::Instruction(plan) => plan
                .ensure_portable_authority_fresh(manifest_text, manifest, lock_text)
                .map_err(|_| manifest_stale()),
        }
    }

    fn ensure_local_state_fresh(
        self,
        state_text: Option<&str>,
    ) -> Result<(), PortableTransactionError> {
        match self {
            Self::Skill(plan) => plan
                .ensure_local_state_fresh(state_text)
                .map_err(|_| local_state_stale()),
            Self::Instruction(plan) => plan
                .ensure_local_state_fresh(state_text)
                .map_err(|_| local_state_stale()),
        }
    }

    fn asset(self) -> &'a Asset {
        match self {
            Self::Skill(plan) => plan.asset(),
            Self::Instruction(plan) => plan.asset(),
        }
    }

    fn origin_harness(self) -> &'a HarnessId {
        match self {
            Self::Skill(plan) => &plan.source().selected().location().harness,
            Self::Instruction(plan) => plan.source().observation().harness(),
        }
    }

    fn proposed_manifest(self) -> &'a EnvironmentManifest {
        match self {
            Self::Skill(plan) => plan.proposed_manifest(),
            Self::Instruction(plan) => plan.proposed_manifest(),
        }
    }

    fn proposed_lock(self) -> &'a Lockfile {
        match self {
            Self::Skill(plan) => plan.proposed_lock(),
            Self::Instruction(plan) => plan.proposed_lock(),
        }
    }

    fn base_manifest_hash(self) -> &'a ContentHash {
        match self {
            Self::Skill(plan) => plan.base_manifest_hash(),
            Self::Instruction(plan) => plan.base_manifest_hash(),
        }
    }

    fn base_manifest_revision(self) -> &'a Revision {
        match self {
            Self::Skill(plan) => plan.base_manifest_revision(),
            Self::Instruction(plan) => plan.base_manifest_revision(),
        }
    }

    fn proposed_manifest_revision(self) -> &'a Revision {
        match self {
            Self::Skill(plan) => plan.proposed_manifest_revision(),
            Self::Instruction(plan) => plan.proposed_manifest_revision(),
        }
    }

    fn proposed_local_state_text(self) -> Option<&'a str> {
        match self {
            Self::Skill(plan) => plan.proposed_local_state_text(),
            Self::Instruction(plan) => Some(plan.proposed_local_state_text()),
        }
    }

    fn expected_prior(self) -> &'a ContentHash {
        match self {
            Self::Skill(plan) => plan.expected_prior(),
            Self::Instruction(plan) => plan.expected_prior(),
        }
    }

    fn digest(self) -> &'a ContentHash {
        match self {
            Self::Skill(plan) => plan.digest(),
            Self::Instruction(plan) => plan.digest(),
        }
    }

    fn receipt(self) -> Option<&'a kitrove_model::DeploymentReceipt> {
        match self {
            Self::Skill(plan) => plan.source().receipt(),
            Self::Instruction(plan) => Some(plan.source().receipt()),
        }
    }

    fn reviewed_target_hash(self) -> Option<&'a ContentHash> {
        match self {
            Self::Skill(plan) => Some(&plan.source().selected().captured().exact_source_hash),
            Self::Instruction(plan) => plan
                .source()
                .observation()
                .region(plan.source().asset_id())
                .map(|region| region.exact_region_hash()),
        }
    }

    const fn journal_schema(self) -> u32 {
        match self {
            Self::Skill(_) => 3,
            Self::Instruction(_) => 5,
        }
    }

    fn objects(self) -> ObjectPlanRef<'a> {
        match self {
            Self::Skill(plan) => ObjectPlanRef::Skill {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
            Self::Instruction(plan) => ObjectPlanRef::Instruction {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
        }
    }
}

impl<'a> AdoptionPlanRef<'a> {
    fn ensure_observation_fresh(
        self,
        reread: AdoptionObservationRef<'_>,
    ) -> Result<(), PortableTransactionError> {
        match (self, reread) {
            (Self::Skill(plan), AdoptionObservationRef::Skill(observation)) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            (Self::Instruction(plan), AdoptionObservationRef::Instruction(observation)) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            (Self::PromptCommand(plan), AdoptionObservationRef::PromptCommand(observation)) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            (
                Self::PromptCommandUpdate(plan),
                AdoptionObservationRef::PromptCommand(observation),
            ) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            (Self::Agent(plan), AdoptionObservationRef::Agent(observation)) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            (Self::AgentUpdate(plan), AdoptionObservationRef::Agent(observation)) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            (Self::Mcp(plan), AdoptionObservationRef::Mcp(observation)) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            (Self::McpUpdate(plan), AdoptionObservationRef::Mcp(observation)) => plan
                .ensure_observation_fresh(observation)
                .map_err(|_| observation_stale()),
            _ => Err(observation_stale()),
        }
    }

    fn ensure_portable_authority_fresh(
        self,
        manifest_text: &str,
        manifest: &EnvironmentManifest,
        lock_text: Option<&str>,
    ) -> Result<(), PortableTransactionError> {
        match self {
            Self::Skill(plan) => plan
                .ensure_manifest_fresh(manifest)
                .map_err(|_| manifest_stale()),
            Self::Instruction(plan) => plan
                .ensure_manifest_fresh(manifest)
                .map_err(|_| manifest_stale()),
            Self::PromptCommand(plan) => plan
                .ensure_manifest_fresh(manifest)
                .map_err(|_| manifest_stale()),
            Self::PromptCommandUpdate(plan) => plan
                .ensure_portable_authority_fresh(manifest_text, manifest, lock_text)
                .map_err(|_| manifest_stale()),
            Self::Agent(plan) => plan
                .ensure_manifest_fresh(manifest)
                .map_err(|_| manifest_stale()),
            Self::AgentUpdate(plan) => plan
                .ensure_portable_authority_fresh(manifest_text, manifest, lock_text)
                .map_err(|_| manifest_stale()),
            Self::Mcp(plan) => plan
                .ensure_manifest_fresh(manifest)
                .map_err(|_| manifest_stale()),
            Self::McpUpdate(plan) => plan
                .ensure_portable_authority_fresh(manifest_text, manifest, lock_text)
                .map_err(|_| manifest_stale()),
        }
    }

    fn asset(self) -> &'a Asset {
        match self {
            Self::Skill(plan) => plan.asset(),
            Self::Instruction(plan) => plan.asset(),
            Self::PromptCommand(plan) => plan.asset(),
            Self::PromptCommandUpdate(plan) => plan.asset(),
            Self::Agent(plan) => plan.asset(),
            Self::AgentUpdate(plan) => plan.asset(),
            Self::Mcp(plan) => plan.asset(),
            Self::McpUpdate(plan) => plan.asset(),
        }
    }

    fn origin_harness(self) -> &'a HarnessId {
        match self {
            Self::Skill(plan) => plan.origin_harness(),
            Self::Instruction(plan) => plan.origin_harness(),
            Self::PromptCommand(plan) => plan.observation().harness(),
            Self::PromptCommandUpdate(plan) => plan.observation().harness(),
            Self::Agent(plan) => plan.observation().harness(),
            Self::AgentUpdate(plan) => plan.observation().harness(),
            Self::Mcp(plan) => plan.observation().harness(),
            Self::McpUpdate(plan) => plan.observation().harness(),
        }
    }

    fn proposed_manifest(self) -> &'a EnvironmentManifest {
        match self {
            Self::Skill(plan) => plan.proposed_manifest(),
            Self::Instruction(plan) => plan.proposed_manifest(),
            Self::PromptCommand(plan) => plan.proposed_manifest(),
            Self::PromptCommandUpdate(plan) => plan.proposed_manifest(),
            Self::Agent(plan) => plan.proposed_manifest(),
            Self::AgentUpdate(plan) => plan.proposed_manifest(),
            Self::Mcp(plan) => plan.proposed_manifest(),
            Self::McpUpdate(plan) => plan.proposed_manifest(),
        }
    }

    fn proposed_lock(self) -> &'a Lockfile {
        match self {
            Self::Skill(plan) => plan.proposed_lock(),
            Self::Instruction(plan) => plan.proposed_lock(),
            Self::PromptCommand(plan) => plan.proposed_lock(),
            Self::PromptCommandUpdate(plan) => plan.proposed_lock(),
            Self::Agent(plan) => plan.proposed_lock(),
            Self::AgentUpdate(plan) => plan.proposed_lock(),
            Self::Mcp(plan) => plan.proposed_lock(),
            Self::McpUpdate(plan) => plan.proposed_lock(),
        }
    }

    fn base_manifest_revision(self) -> &'a Revision {
        match self {
            Self::Skill(plan) => plan.base_manifest_revision(),
            Self::Instruction(plan) => plan.base_manifest_revision(),
            Self::PromptCommand(plan) => plan.base_manifest_revision(),
            Self::PromptCommandUpdate(plan) => plan.base_manifest_revision(),
            Self::Agent(plan) => plan.base_manifest_revision(),
            Self::AgentUpdate(plan) => plan.base_manifest_revision(),
            Self::Mcp(plan) => plan.base_manifest_revision(),
            Self::McpUpdate(plan) => plan.base_manifest_revision(),
        }
    }

    fn proposed_manifest_revision(self) -> &'a Revision {
        match self {
            Self::Skill(plan) => plan.proposed_manifest_revision(),
            Self::Instruction(plan) => plan.proposed_manifest_revision(),
            Self::PromptCommand(plan) => plan.proposed_manifest_revision(),
            Self::PromptCommandUpdate(plan) => plan.proposed_manifest_revision(),
            Self::Agent(plan) => plan.proposed_manifest_revision(),
            Self::AgentUpdate(plan) => plan.proposed_manifest_revision(),
            Self::Mcp(plan) => plan.proposed_manifest_revision(),
            Self::McpUpdate(plan) => plan.proposed_manifest_revision(),
        }
    }

    fn digest(self) -> &'a ContentHash {
        match self {
            Self::Skill(plan) => plan.digest(),
            Self::Instruction(plan) => plan.digest(),
            Self::PromptCommand(plan) => plan.digest(),
            Self::PromptCommandUpdate(plan) => plan.digest(),
            Self::Agent(plan) => plan.digest(),
            Self::AgentUpdate(plan) => plan.digest(),
            Self::Mcp(plan) => plan.digest(),
            Self::McpUpdate(plan) => plan.digest(),
        }
    }

    fn disposition(self) -> AdoptionDisposition {
        match self {
            Self::Skill(plan) => plan.disposition(),
            Self::Instruction(plan) => plan.disposition(),
            Self::PromptCommand(plan) => plan.disposition(),
            Self::PromptCommandUpdate(_) => AdoptionDisposition::First,
            Self::Agent(plan) => plan.disposition(),
            Self::AgentUpdate(_) => AdoptionDisposition::First,
            Self::Mcp(plan) => plan.disposition(),
            Self::McpUpdate(_) => AdoptionDisposition::First,
        }
    }

    const fn journal_schema(self) -> u32 {
        match self {
            Self::Skill(_) => 2,
            Self::Instruction(_) => 4,
            Self::PromptCommand(_) => 6,
            Self::PromptCommandUpdate(_) => 6,
            Self::Agent(_) | Self::AgentUpdate(_) => 7,
            Self::Mcp(_) | Self::McpUpdate(_) => 8,
        }
    }

    fn objects(self) -> ObjectPlanRef<'a> {
        match self {
            Self::Skill(plan) => ObjectPlanRef::Skill {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
            Self::Instruction(plan) => ObjectPlanRef::Instruction {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
            Self::PromptCommand(plan) => ObjectPlanRef::PromptCommand {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
            Self::PromptCommandUpdate(plan) => ObjectPlanRef::PromptCommand {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
            Self::Agent(plan) => ObjectPlanRef::Agent {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
            Self::AgentUpdate(plan) => ObjectPlanRef::Agent {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
            Self::Mcp(plan) => ObjectPlanRef::Mcp {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
            Self::McpUpdate(plan) => ObjectPlanRef::Mcp {
                portable: plan.portable_object(),
                native: plan.native_object(),
            },
        }
    }
}

/// Commits one confirmed adoption plan under the environment lock.
pub fn commit_adoption(
    plan: &AdoptionPlan,
    reread_candidate: &AcceptedObservedCandidate,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_adoption_inner(plan, reread_candidate, environment_root, limits, None)
}

/// Commits one confirmed standing-instruction adoption under the environment lock.
pub fn commit_instruction_adoption(
    plan: &InstructionAdoptionPlan,
    reread_observation: &InstructionDocumentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_instruction_adoption_inner(plan, reread_observation, environment_root, limits, None)
}

/// Commits one confirmed prompt-command adoption under the environment lock.
pub fn commit_prompt_command_adoption(
    plan: &PromptCommandAdoptionPlan,
    reread_observation: &PromptCommandObservation,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_prompt_command_adoption_inner(plan, reread_observation, environment_root, limits, None)
}

/// Commits one confirmed agent adoption under the environment lock.
pub fn commit_agent_adoption(
    plan: &AgentAdoptionPlan,
    reread_observation: &AgentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_agent_adoption_inner(plan, reread_observation, environment_root, limits, None)
}

/// Commits one confirmed MCP adoption under the environment lock.
pub fn commit_mcp_adoption(
    plan: &McpAdoptionPlan,
    reread_observation: &McpDocumentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_mcp_adoption_inner(plan, reread_observation, environment_root, limits, None)
}

/// Commits one confirmed exact-prior MCP replacement without touching local receipts.
pub fn commit_mcp_update(
    plan: &McpUpdatePlan,
    reread_observation: &McpDocumentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    commit_mcp_update_inner(plan, reread_observation, environment_root, limits, None)
}

/// Commits one confirmed exact-prior update under environment-then-local-state locks.
pub fn commit_update_adoption(
    plan: &UpdatePlan,
    reread_candidate: &AcceptedObservedCandidate,
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    commit_update_adoption_inner(
        plan,
        reread_candidate,
        environment_root,
        state_root,
        limits,
        None,
    )
}

/// Commits one confirmed explicit prompt-command replacement without touching local receipts.
pub fn commit_prompt_command_update(
    plan: &PromptCommandUpdatePlan,
    reread_observation: &PromptCommandObservation,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    commit_prompt_command_update_inner(plan, reread_observation, environment_root, limits, None)
}

/// Commits one confirmed explicit agent replacement without touching local receipts.
pub fn commit_agent_update(
    plan: &AgentUpdatePlan,
    reread_observation: &AgentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    commit_agent_update_inner(plan, reread_observation, environment_root, limits, None)
}

/// Commits one confirmed exact-prior instruction update under the shared update transaction.
pub fn commit_instruction_update(
    plan: &InstructionUpdatePlan,
    reread_observation: &InstructionDocumentObservation,
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    commit_update_authority(
        UpdatePlanRef::Instruction(plan),
        UpdateObservationRef::Instruction(reread_observation),
        environment_root,
        state_root,
        limits,
        None,
    )
}

/// Recovers an interrupted exact-prior update under the same lock order.
pub fn recover_update_adoption(
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
) -> Result<UpdateRecoveryOutcome, PortableTransactionError> {
    let environment = ObjectStore::open(environment_root).map_err(store_error)?;
    let state = ObjectStore::open_private_state_for_mutation(state_root).map_err(store_error)?;
    environment
        .require_non_overlapping_root(&state)
        .map_err(store_error)?;
    let _root_locks =
        ObjectStore::try_lock_distinct_roots(&[&environment, &state]).map_err(store_error)?;
    ensure_no_foreign_environment_journal(&environment)?;
    ensure_no_foreign_local_state_journal(&state)?;
    recover_update_with_stores(&environment, environment_root, &state, limits)
}

fn ensure_no_foreign_local_state_journal(
    state: &ObjectStore,
) -> Result<(), PortableTransactionError> {
    if local_state_authority::any_journal_present(
        state,
        local_state_authority::ALL_LOCAL_STATE_RECOVERY,
        MAX_JOURNAL_BYTES,
    )
    .map_err(store_error)?
    {
        return Err(PortableTransactionError::new(
            "transaction.local_state_recovery_required",
            "another local-state transaction must recover before update adoption can continue",
        ));
    }
    Ok(())
}

fn ensure_no_foreign_environment_journal(
    environment: &ObjectStore,
) -> Result<(), PortableTransactionError> {
    if local_state_authority::any_journal_present(
        environment,
        local_state_authority::FOREIGN_TO_ADOPTION,
        MAX_JOURNAL_BYTES,
    )
    .map_err(store_error)?
    {
        return Err(PortableTransactionError::new(
            "transaction.foreign_recovery_required",
            "another portable transaction must recover before mutation can continue",
        ));
    }
    Ok(())
}

/// Recovers any existing portable journal under the environment lock.
pub fn recover_portable_environment(
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableRecoveryOutcome, PortableTransactionError> {
    let store = ObjectStore::open(environment_root).map_err(store_error)?;
    let _lock = store.try_lock_environment().map_err(store_error)?;
    ensure_no_foreign_environment_journal(&store)?;
    recover_with_store(&store, environment_root, limits)
}

/// Plans deterministic generated-lock repair without changing manifest authority.
pub fn plan_lock_repair(
    manifest: &EnvironmentManifest,
    stored_lock: Option<&str>,
) -> Result<LockRepairPlan, PortableTransactionError> {
    if stored_lock.is_some_and(|value| value.len() > MAX_CONTROL_BYTES) {
        return Err(PortableTransactionError::new(
            "transaction.lock_too_large",
            "the generated lock exceeds the portable control-file limit",
        ));
    }
    let comparison = compare_lockfile(manifest, stored_lock).map_err(|_| manifest_invalid())?;
    let manifest_revision = derive_manifest_revision(manifest).map_err(|_| manifest_invalid())?;
    let expected_lock = comparison.expected().clone();
    let expected_encoded = expected_lock.to_json().map_err(|_| proposed_invalid())?;
    let observed_status = comparison.status();
    let observed_hash = stored_lock.map(|text| ContentHash::digest(text.as_bytes()));
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-lock-repair-plan-v1\0");
    write_record(&mut hasher, manifest_revision.as_str());
    hasher.update(&[lock_status_tag(observed_status)]);
    write_optional_hash(&mut hasher, observed_hash.as_ref());
    write_record(
        &mut hasher,
        ContentHash::digest(expected_encoded.as_bytes()).as_str(),
    );
    let digest = ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .map_err(|_| proposed_invalid())?;
    Ok(LockRepairPlan {
        manifest_revision,
        expected_lock,
        observed_status,
        observed_lock: stored_lock.map(str::to_owned),
        digest,
    })
}

/// Commits only the manifest-derived generated lock under the portable transaction lock.
pub fn commit_lock_repair(
    plan: &LockRepairPlan,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<LockRepairOutcome, PortableTransactionError> {
    commit_lock_repair_inner(plan, environment_root, limits, None)
}

/// Commits a confirmed pack-creation plan without writing or replacing immutable objects.
pub fn commit_pack_creation(
    plan: &PackCreationPlan,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    commit_pack_mutation_inner(
        plan,
        PackMutationKind::Create,
        environment_root,
        limits,
        None,
    )
}

/// Commits a confirmed pack-update plan without writing or replacing immutable objects.
pub fn commit_pack_update(
    plan: &PackUpdatePlan,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    commit_pack_mutation_inner(
        plan,
        PackMutationKind::Update,
        environment_root,
        limits,
        None,
    )
}

/// Commits a confirmed selective pack rollback after all required immutable objects are present.
pub fn commit_pack_rollback(
    plan: &PackRollbackPlan,
    objects: &[VerifiedObjectEnvelope],
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    let supplied: BTreeSet<_> = objects
        .iter()
        .map(|object| object.descriptor().clone())
        .collect();
    if supplied.len() != objects.len() || supplied != *plan.required_objects() {
        return Err(pack_rollback_objects_invalid());
    }
    commit_manifest_plan_inner(
        plan,
        ManifestCommitKind::Rollback,
        Some(objects),
        environment_root,
        limits,
        None,
    )
}

/// Commits one confirmed pack distribution adoption and its exact immutable object closure.
pub fn commit_pack_distribution_adoption(
    plan: &PackDistributionPlan,
    objects: &[VerifiedObjectEnvelope],
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    let supplied: BTreeSet<_> = objects
        .iter()
        .map(|object| object.descriptor().clone())
        .collect();
    if supplied.len() != objects.len() || supplied != *plan.required_objects() {
        return Err(pack_adoption_objects_invalid());
    }
    commit_manifest_plan_inner(
        plan,
        ManifestCommitKind::Adopt,
        Some(objects),
        environment_root,
        limits,
        None,
    )
}

/// Inspects journal presence and structure without taking a lock or mutating state.
pub fn inspect_portable_journal(
    environment_root: &Path,
) -> Result<PortableJournalStatus, PortableTransactionError> {
    let store = ObjectStore::open(environment_root).map_err(store_error)?;
    journal_status_with_store(&store)
}

/// Inspects manifest authority, generated lock, referenced objects, and journal independently.
pub fn inspect_portable_environment(
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableStatus, PortableTransactionError> {
    let store = ObjectStore::open(environment_root).map_err(store_error)?;
    let manifest_text = required_text(&store, MANIFEST_PATH)?;
    let manifest =
        EnvironmentManifest::from_toml(&manifest_text).map_err(|_| manifest_invalid())?;
    let manifest_revision = derive_manifest_revision(&manifest).map_err(|_| manifest_invalid())?;
    let lock_text = store
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(store_error)?;
    let lock_status = compare_lockfile(&manifest, lock_text.as_deref())
        .map_err(|_| manifest_invalid())?
        .status();
    let objects = verify_referenced_objects(&manifest, environment_root, limits)
        .map_err(|_| verification_failed())?;
    let journal_status = journal_status_with_store(&store)?;
    Ok(PortableStatus {
        manifest_revision,
        lock_status,
        objects,
        journal_status,
    })
}

fn commit_adoption_inner(
    plan: &AdoptionPlan,
    reread_candidate: &AcceptedObservedCandidate,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_adoption_authority(
        AdoptionPlanRef::Skill(plan),
        AdoptionObservationRef::Skill(reread_candidate),
        environment_root,
        limits,
        interrupt_after,
    )
}

fn commit_instruction_adoption_inner(
    plan: &InstructionAdoptionPlan,
    reread_observation: &InstructionDocumentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_adoption_authority(
        AdoptionPlanRef::Instruction(plan),
        AdoptionObservationRef::Instruction(reread_observation),
        environment_root,
        limits,
        interrupt_after,
    )
}

fn commit_prompt_command_adoption_inner(
    plan: &PromptCommandAdoptionPlan,
    reread_observation: &PromptCommandObservation,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_adoption_authority(
        AdoptionPlanRef::PromptCommand(plan),
        AdoptionObservationRef::PromptCommand(reread_observation),
        environment_root,
        limits,
        interrupt_after,
    )
}

fn commit_agent_adoption_inner(
    plan: &AgentAdoptionPlan,
    reread_observation: &AgentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_adoption_authority(
        AdoptionPlanRef::Agent(plan),
        AdoptionObservationRef::Agent(reread_observation),
        environment_root,
        limits,
        interrupt_after,
    )
}

fn commit_mcp_adoption_inner(
    plan: &McpAdoptionPlan,
    reread_observation: &McpDocumentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    commit_adoption_authority(
        AdoptionPlanRef::Mcp(plan),
        AdoptionObservationRef::Mcp(reread_observation),
        environment_root,
        limits,
        interrupt_after,
    )
}

fn commit_mcp_update_inner(
    plan: &McpUpdatePlan,
    reread_observation: &McpDocumentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    let outcome = commit_adoption_authority(
        AdoptionPlanRef::McpUpdate(plan),
        AdoptionObservationRef::Mcp(reread_observation),
        environment_root,
        limits,
        interrupt_after,
    )?;
    Ok(match outcome {
        AdoptionCommitOutcome::Committed | AdoptionCommitOutcome::Repaired => {
            UpdateCommitOutcome::CommittedWithoutReceipt
        }
        AdoptionCommitOutcome::Recovered => UpdateCommitOutcome::RecoveredWithoutReceipt,
    })
}

fn commit_prompt_command_update_inner(
    plan: &PromptCommandUpdatePlan,
    reread_observation: &PromptCommandObservation,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    let outcome = commit_adoption_authority(
        AdoptionPlanRef::PromptCommandUpdate(plan),
        AdoptionObservationRef::PromptCommand(reread_observation),
        environment_root,
        limits,
        interrupt_after,
    )?;
    Ok(match outcome {
        AdoptionCommitOutcome::Committed | AdoptionCommitOutcome::Repaired => {
            UpdateCommitOutcome::CommittedWithoutReceipt
        }
        AdoptionCommitOutcome::Recovered => UpdateCommitOutcome::RecoveredWithoutReceipt,
    })
}

fn commit_agent_update_inner(
    plan: &AgentUpdatePlan,
    reread_observation: &AgentObservation,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    let outcome = commit_adoption_authority(
        AdoptionPlanRef::AgentUpdate(plan),
        AdoptionObservationRef::Agent(reread_observation),
        environment_root,
        limits,
        interrupt_after,
    )?;
    Ok(match outcome {
        AdoptionCommitOutcome::Committed | AdoptionCommitOutcome::Repaired => {
            UpdateCommitOutcome::CommittedWithoutReceipt
        }
        AdoptionCommitOutcome::Recovered => UpdateCommitOutcome::RecoveredWithoutReceipt,
    })
}

fn commit_adoption_authority(
    plan: AdoptionPlanRef<'_>,
    reread_observation: AdoptionObservationRef<'_>,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
    let (forward_work, rollback_work) = PortableMutationKind::Adoption.commit_work(limits)?;
    let store = ObjectStore::open(environment_root)
        .map_err(|error| store_error_at(error, "transaction.environment_open_io"))?;
    let _lock = store
        .try_lock_environment()
        .map_err(|error| store_error_at(error, "transaction.environment_lock_io"))?;
    ensure_no_foreign_environment_journal(&store)?;
    let recovery = recover_with_store(&store, environment_root, limits)
        .map_err(|error| transaction_error_at(error, "transaction.recovery_io"))?;
    let cleanup_budget =
        cleanup_locked_stores(&[&store], forward_work, rollback_work).map_err(cleanup_error)?;
    let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;

    plan.ensure_observation_fresh(reread_observation)?;
    let manifest_text = required_text(&store, MANIFEST_PATH)
        .map_err(|error| transaction_error_at(error, "transaction.manifest_read_io"))?;
    let current_lock_text = store
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(|error| store_error_at(error, "transaction.lock_read_io"))?;
    let current = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| manifest_invalid())?;
    let current_revision = derive_manifest_revision(&current).map_err(|_| manifest_invalid())?;
    if recovery == PortableRecoveryOutcome::CompletedCommitted
        && current_revision == *plan.proposed_manifest_revision()
        && current == *plan.proposed_manifest()
    {
        return Ok(AdoptionCommitOutcome::Recovered);
    }
    plan.ensure_portable_authority_fresh(&manifest_text, &current, current_lock_text.as_deref())?;

    let manifest_encoded = plan
        .proposed_manifest()
        .to_toml()
        .map_err(|_| proposed_invalid())?;
    let lock_encoded = plan
        .proposed_lock()
        .to_json()
        .map_err(|_| proposed_invalid())?;
    let paths = transaction_paths(plan.digest())?;
    let portable = plan
        .asset()
        .portable
        .as_ref()
        .ok_or_else(proposed_invalid)?;
    let native = plan
        .asset()
        .native_variants
        .get(plan.origin_harness())
        .ok_or_else(proposed_invalid)?;

    let objects = plan.objects();
    let portable_preexisting = objects.portable_preexisting(&store, portable, limits);
    let native_preexisting = objects.native_preexisting(&store, native, limits);
    objects.prepare_portable(
        &store,
        &paths.portable,
        portable,
        portable_preexisting,
        limits,
    )?;
    objects.prepare_native(&store, &paths.native, native, native_preexisting, limits)?;
    stage_authority_controls(
        &store,
        &paths,
        &manifest_encoded,
        &lock_encoded,
        plan.proposed_manifest(),
        plan.proposed_lock(),
    )?;

    let (portable_format, native_format) = objects.journal_formats();
    let mut journal = PortableJournal {
        schema_version: plan.journal_schema(),
        operation: JournalOperation::Adopt,
        phase: JournalPhase::Prepared,
        plan_digest: plan.digest().clone(),
        old_manifest_revision: plan.base_manifest_revision().clone(),
        new_manifest_revision: plan.proposed_manifest_revision().clone(),
        old_manifest_hash: ContentHash::digest(manifest_text.as_bytes()),
        new_manifest_hash: ContentHash::digest(manifest_encoded.as_bytes()),
        staging_manifest: Some(paths.manifest.clone()),
        staging_lock: paths.lock.clone(),
        old_lock_hash: current_lock_text
            .as_deref()
            .map(|text| ContentHash::digest(text.as_bytes())),
        new_lock_hash: ContentHash::digest(lock_encoded.as_bytes()),
        portable_root: Some(portable.root.clone()),
        portable_hash: Some(portable.object_hash.clone()),
        native_root: Some(native.root.clone()),
        native_hash: Some(native.object_hash.clone()),
        portable_preexisting: Some(portable_preexisting),
        native_preexisting: Some(native_preexisting),
        portable_format,
        native_format,
        staging_state: None,
        old_state_hash: None,
        new_state_hash: None,
        receipt_id: None,
        reviewed_target_hash: None,
        expected_prior: None,
    };
    let mut journal_encoded = write_journal(&store, &journal)?;
    interrupt(JournalPhase::Prepared, interrupt_after)?;

    objects.install(&store, &paths, portable, native, limits)?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::ObjectsInstalled,
    )?;
    interrupt(JournalPhase::ObjectsInstalled, interrupt_after)?;

    store
        .install_staged_text_guarded(
            &paths.manifest,
            &portable_path(MANIFEST_PATH)?,
            Some(&manifest_text),
            &manifest_encoded,
            MAX_CONTROL_BYTES,
        )
        .map_err(|error| store_error_at(error, "transaction.manifest_install_io"))?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::ManifestCommitted,
    )?;
    interrupt(JournalPhase::ManifestCommitted, interrupt_after)?;

    store
        .install_staged_text_guarded(
            &paths.lock,
            &portable_path(LOCK_PATH)?,
            current_lock_text.as_deref(),
            &lock_encoded,
            MAX_CONTROL_BYTES,
        )
        .map_err(|error| store_error_at(error, "transaction.lock_install_io"))?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::LockCommitted,
    )?;
    interrupt(JournalPhase::LockCommitted, interrupt_after)?;

    verify_committed(&store, environment_root, limits, plan.proposed_manifest())
        .map_err(|error| transaction_error_at(error, "transaction.verification_io"))?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::Verified,
    )?;
    interrupt(JournalPhase::Verified, interrupt_after)?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::Complete,
    )?;
    interrupt(JournalPhase::Complete, interrupt_after)?;
    store
        .remove_regular_file_if_present(&portable_path(JOURNAL_PATH)?)
        .map_err(|error| store_error_at(error, "transaction.journal_cleanup_io"))?;
    cleanup_empty_staging(&store, &paths.base)
        .map_err(|error| transaction_error_at(error, "transaction.staging_cleanup_io"))?;

    Ok(match plan.disposition() {
        AdoptionDisposition::First => AdoptionCommitOutcome::Committed,
        AdoptionDisposition::Idempotent => AdoptionCommitOutcome::Repaired,
    })
}

fn commit_update_adoption_inner(
    plan: &UpdatePlan,
    reread_candidate: &AcceptedObservedCandidate,
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    commit_update_authority(
        UpdatePlanRef::Skill(plan),
        UpdateObservationRef::Skill(reread_candidate),
        environment_root,
        state_root,
        limits,
        interrupt_after,
    )
}

fn commit_update_authority(
    plan: UpdatePlanRef<'_>,
    reread_observation: UpdateObservationRef<'_>,
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<UpdateCommitOutcome, PortableTransactionError> {
    let local_state = plan.proposed_local_state_text().is_some();
    let (forward_work, rollback_work) =
        PortableMutationKind::Update { local_state }.commit_work(limits)?;
    let environment = ObjectStore::open(environment_root)
        .map_err(|error| store_error_at(error, "transaction.environment_open_io"))?;
    let state = ObjectStore::open_or_create_private_state(state_root)
        .map_err(|error| store_error_at(error, "transaction.local_state_open_io"))?;
    environment
        .require_non_overlapping_root(&state)
        .map_err(|error| store_error_at(error, "transaction.local_state_open_io"))?;
    let _root_locks = ObjectStore::try_lock_distinct_roots(&[&environment, &state])
        .map_err(|error| store_error_at(error, "transaction.local_state_lock_io"))?;
    ensure_no_foreign_environment_journal(&environment)?;
    ensure_no_foreign_local_state_journal(&state)?;
    let recovery = recover_update_with_stores(&environment, environment_root, &state, limits)?;
    if recovery == UpdateRecoveryOutcome::CompletedWithReceipt {
        return Ok(UpdateCommitOutcome::RecoveredWithReceipt);
    }
    if recovery == UpdateRecoveryOutcome::CompletedWithoutReceipt {
        return Ok(UpdateCommitOutcome::RecoveredWithoutReceipt);
    }
    if recovery == UpdateRecoveryOutcome::Completed {
        return Ok(UpdateCommitOutcome::Recovered);
    }
    let cleanup_budget =
        cleanup_locked_stores(&[&environment, &state], forward_work, rollback_work)
            .map_err(cleanup_error)?;
    let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;

    plan.ensure_observation_fresh(reread_observation)?;
    let manifest_text = required_text(&environment, MANIFEST_PATH)?;
    let current_manifest =
        EnvironmentManifest::from_toml(&manifest_text).map_err(|_| manifest_invalid())?;
    let current_lock = environment
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(store_error)?;
    plan.ensure_portable_authority_fresh(
        &manifest_text,
        &current_manifest,
        current_lock.as_deref(),
    )?;

    let UpdateLocalPreconditions {
        old_state_text,
        new_state_text,
        receipt_id,
        reviewed_target_hash,
    } = update_local_preconditions(plan, &state, limits)?;
    let manifest_encoded = plan
        .proposed_manifest()
        .to_toml()
        .map_err(|_| proposed_invalid())?;
    let lock_encoded = plan
        .proposed_lock()
        .to_json()
        .map_err(|_| proposed_invalid())?;
    let paths = transaction_paths(plan.digest())?;
    let portable = plan
        .asset()
        .portable
        .as_ref()
        .ok_or_else(proposed_invalid)?;
    let native = plan
        .asset()
        .native_variants
        .get(plan.origin_harness())
        .ok_or_else(proposed_invalid)?;

    let objects = plan.objects();
    let portable_preexisting = objects.portable_preexisting(&environment, portable, limits);
    let native_preexisting = objects.native_preexisting(&environment, native, limits);
    objects.prepare_portable(
        &environment,
        &paths.portable,
        portable,
        portable_preexisting,
        limits,
    )?;
    objects.prepare_native(
        &environment,
        &paths.native,
        native,
        native_preexisting,
        limits,
    )?;
    for (path, text) in [
        (&paths.manifest, manifest_encoded.as_str()),
        (&paths.lock, lock_encoded.as_str()),
    ] {
        environment
            .reset_incomplete_staged_text(path, text, MAX_CONTROL_BYTES)
            .map_err(store_error)?;
        environment
            .stage_text(path, text, MAX_CONTROL_BYTES)
            .map_err(store_error)?;
    }
    let staging_state = if let Some(new_state_text) = new_state_text.as_deref() {
        let path = update_state_staging_path(plan.digest())?;
        state
            .reset_incomplete_staged_text(&path, new_state_text, MAX_CONTROL_BYTES)
            .map_err(store_error)?;
        state
            .stage_text(&path, new_state_text, MAX_CONTROL_BYTES)
            .map_err(store_error)?;
        Some(path)
    } else {
        None
    };

    verify_update_staging(&environment, &state, &paths, staging_state.as_ref(), plan)?;
    let (portable_format, native_format) = objects.journal_formats();
    let mut journal = PortableJournal {
        schema_version: plan.journal_schema(),
        operation: JournalOperation::Update,
        phase: JournalPhase::Prepared,
        plan_digest: plan.digest().clone(),
        old_manifest_revision: plan.base_manifest_revision().clone(),
        new_manifest_revision: plan.proposed_manifest_revision().clone(),
        old_manifest_hash: plan.base_manifest_hash().clone(),
        new_manifest_hash: ContentHash::digest(manifest_encoded.as_bytes()),
        staging_manifest: Some(paths.manifest.clone()),
        staging_lock: paths.lock.clone(),
        old_lock_hash: current_lock
            .as_deref()
            .map(|text| ContentHash::digest(text.as_bytes())),
        new_lock_hash: ContentHash::digest(lock_encoded.as_bytes()),
        portable_root: Some(portable.root.clone()),
        portable_hash: Some(portable.object_hash.clone()),
        native_root: Some(native.root.clone()),
        native_hash: Some(native.object_hash.clone()),
        portable_preexisting: Some(portable_preexisting),
        native_preexisting: Some(native_preexisting),
        portable_format,
        native_format,
        staging_state,
        old_state_hash: old_state_text
            .as_deref()
            .map(|text| ContentHash::digest(text.as_bytes())),
        new_state_hash: new_state_text
            .as_deref()
            .map(|text| ContentHash::digest(text.as_bytes())),
        receipt_id,
        reviewed_target_hash,
        expected_prior: Some(plan.expected_prior().clone()),
    };
    let mut journal_encoded = write_journal(&environment, &journal)?;
    interrupt(JournalPhase::Prepared, interrupt_after)?;

    revalidate_update_preconditions(plan, reread_observation, &environment, &state, limits)?;
    objects.install(&environment, &paths, portable, native, limits)?;
    update_phase(
        &environment,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::ObjectsInstalled,
    )?;
    interrupt(JournalPhase::ObjectsInstalled, interrupt_after)?;

    revalidate_update_preconditions(plan, reread_observation, &environment, &state, limits)?;
    environment
        .install_staged_text_guarded(
            &paths.manifest,
            &portable_path(MANIFEST_PATH)?,
            Some(&manifest_text),
            &manifest_encoded,
            MAX_CONTROL_BYTES,
        )
        .map_err(store_error)?;
    update_phase(
        &environment,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::ManifestCommitted,
    )?;
    interrupt(JournalPhase::ManifestCommitted, interrupt_after)?;

    environment
        .install_staged_text_guarded(
            &paths.lock,
            &portable_path(LOCK_PATH)?,
            current_lock.as_deref(),
            &lock_encoded,
            MAX_CONTROL_BYTES,
        )
        .map_err(store_error)?;
    update_phase(
        &environment,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::LockCommitted,
    )?;
    interrupt(JournalPhase::LockCommitted, interrupt_after)?;

    let receipt_committed =
        if let (Some(staging_state), Some(old_state_text), Some(new_state_text)) = (
            journal.staging_state.as_ref(),
            old_state_text.as_deref(),
            new_state_text.as_deref(),
        ) {
            if reviewed_target_is_current(plan, limits) {
                state
                    .install_staged_text_guarded(
                        staging_state,
                        &portable_path("state.json")?,
                        Some(old_state_text),
                        new_state_text,
                        MAX_CONTROL_BYTES,
                    )
                    .map_err(store_error)?;
                update_phase(
                    &environment,
                    &mut journal,
                    &mut journal_encoded,
                    JournalPhase::StateCommitted,
                )?;
                interrupt(JournalPhase::StateCommitted, interrupt_after)?;
                true
            } else {
                false
            }
        } else {
            false
        };

    verify_committed(
        &environment,
        environment_root,
        limits,
        plan.proposed_manifest(),
    )?;
    if receipt_committed
        && state
            .read_text(&portable_path("state.json")?, MAX_CONTROL_BYTES)
            .map_err(store_error)?
            .as_deref()
            != new_state_text.as_deref()
    {
        return Err(verification_failed());
    }
    update_phase(
        &environment,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::Verified,
    )?;
    interrupt(JournalPhase::Verified, interrupt_after)?;
    update_phase(
        &environment,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::Complete,
    )?;
    interrupt(JournalPhase::Complete, interrupt_after)?;
    cleanup_completed_update(&environment, &state, &journal)?;

    Ok(if plan.proposed_local_state_text().is_none() {
        UpdateCommitOutcome::Committed
    } else if receipt_committed {
        UpdateCommitOutcome::CommittedWithReceipt
    } else {
        UpdateCommitOutcome::CommittedWithoutReceipt
    })
}

fn stage_authority_controls(
    store: &ObjectStore,
    paths: &TransactionPaths,
    manifest_encoded: &str,
    lock_encoded: &str,
    expected_manifest: &EnvironmentManifest,
    expected_lock: &Lockfile,
) -> Result<(), PortableTransactionError> {
    for (path, encoded, reset_code, stage_code) in [
        (
            &paths.manifest,
            manifest_encoded,
            "transaction.manifest_reset_io",
            "transaction.manifest_stage_io",
        ),
        (
            &paths.lock,
            lock_encoded,
            "transaction.lock_reset_io",
            "transaction.lock_stage_io",
        ),
    ] {
        store
            .reset_incomplete_staged_text(path, encoded, MAX_CONTROL_BYTES)
            .map_err(|error| store_error_at(error, reset_code))?;
        store
            .stage_text(path, encoded, MAX_CONTROL_BYTES)
            .map_err(|error| store_error_at(error, stage_code))?;
    }
    let staged_manifest = store
        .read_text(&paths.manifest, MAX_CONTROL_BYTES)
        .map_err(|error| store_error_at(error, "transaction.manifest_verify_read_io"))?
        .ok_or_else(proposed_invalid)?;
    let staged_lock = store
        .read_text(&paths.lock, MAX_CONTROL_BYTES)
        .map_err(|error| store_error_at(error, "transaction.lock_verify_read_io"))?
        .ok_or_else(proposed_invalid)?;
    if EnvironmentManifest::from_toml(&staged_manifest).map_err(|_| proposed_invalid())?
        != *expected_manifest
        || Lockfile::from_json(&staged_lock).map_err(|_| proposed_invalid())? != *expected_lock
    {
        return Err(proposed_invalid());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ManifestCommitKind {
    Create,
    Update,
    Adopt,
    Rollback,
}

trait ManifestCommitPlan {
    fn digest(&self) -> &ContentHash;
    fn proposed_manifest(&self) -> &EnvironmentManifest;
    fn proposed_lock(&self) -> &Lockfile;
    fn base_manifest_revision(&self) -> &Revision;
    fn proposed_manifest_revision(&self) -> &Revision;
}

impl ManifestCommitPlan for crate::PackMutationPlan {
    fn digest(&self) -> &ContentHash {
        self.digest()
    }

    fn proposed_manifest(&self) -> &EnvironmentManifest {
        self.proposed_manifest()
    }

    fn proposed_lock(&self) -> &Lockfile {
        self.proposed_lock()
    }

    fn base_manifest_revision(&self) -> &Revision {
        self.base_manifest_revision()
    }

    fn proposed_manifest_revision(&self) -> &Revision {
        self.proposed_manifest_revision()
    }
}

impl ManifestCommitPlan for PackRollbackPlan {
    fn digest(&self) -> &ContentHash {
        self.digest()
    }

    fn proposed_manifest(&self) -> &EnvironmentManifest {
        self.proposed_manifest()
    }

    fn proposed_lock(&self) -> &Lockfile {
        self.proposed_lock()
    }

    fn base_manifest_revision(&self) -> &Revision {
        self.base_manifest_revision()
    }

    fn proposed_manifest_revision(&self) -> &Revision {
        self.proposed_manifest_revision()
    }
}

impl ManifestCommitPlan for PackDistributionPlan {
    fn digest(&self) -> &ContentHash {
        self.digest()
    }

    fn proposed_manifest(&self) -> &EnvironmentManifest {
        self.proposed_manifest()
    }

    fn proposed_lock(&self) -> &Lockfile {
        self.proposed_lock()
    }

    fn base_manifest_revision(&self) -> &Revision {
        self.base_manifest_revision()
    }

    fn proposed_manifest_revision(&self) -> &Revision {
        self.proposed_manifest_revision()
    }
}

fn commit_pack_mutation_inner(
    plan: &PackCreationPlan,
    expected_operation: PackMutationKind,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    if plan.operation() != expected_operation {
        return Err(PortableTransactionError::new(
            "pack.operation_mismatch",
            "the pack plan does not match the requested mutation",
        ));
    }
    let kind = match expected_operation {
        PackMutationKind::Create => ManifestCommitKind::Create,
        PackMutationKind::Update => ManifestCommitKind::Update,
    };
    commit_manifest_plan_inner(plan, kind, None, environment_root, limits, interrupt_after)
}

fn commit_manifest_plan_inner(
    plan: &impl ManifestCommitPlan,
    kind: ManifestCommitKind,
    objects: Option<&[VerifiedObjectEnvelope]>,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    let (forward_work, rollback_work) = PortableMutationKind::Manifest {
        rollback_objects: objects.map_or(0, <[VerifiedObjectEnvelope]>::len),
    }
    .commit_work(limits)?;
    let store = ObjectStore::open(environment_root)
        .map_err(|error| store_error_at(error, "transaction.environment_open_io"))?;
    let _lock = store
        .try_lock_environment()
        .map_err(|error| store_error_at(error, "transaction.environment_lock_io"))?;
    ensure_no_foreign_environment_journal(&store)?;
    let recovery = recover_with_store(&store, environment_root, limits)
        .map_err(|error| transaction_error_at(error, "transaction.recovery_io"))?;
    let cleanup_budget =
        cleanup_locked_stores(&[&store], forward_work, rollback_work).map_err(cleanup_error)?;
    let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;
    let manifest_text = required_text(&store, MANIFEST_PATH)
        .map_err(|error| transaction_error_at(error, "transaction.manifest_read_io"))?;
    let current = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| manifest_invalid())?;
    let current_revision = derive_manifest_revision(&current).map_err(|_| manifest_invalid())?;
    if recovery == PortableRecoveryOutcome::CompletedCommitted
        && current_revision == *plan.proposed_manifest_revision()
        && current == *plan.proposed_manifest()
    {
        return Ok(PortableManifestCommitOutcome::Recovered);
    }
    if current_revision != *plan.base_manifest_revision() {
        return Err(manifest_plan_stale(kind));
    }

    let current_lock = store
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(|error| store_error_at(error, "transaction.lock_read_io"))?;
    let expected_current_lock = derive_lockfile(&current)
        .and_then(|lock| lock.to_json())
        .map_err(|_| manifest_invalid())?;
    if current_lock.as_deref() != Some(expected_current_lock.as_str()) {
        return Err(manifest_plan_lock_stale(kind));
    }

    if let Some(objects) = objects {
        prepare_pack_rollback_objects(&store, plan.digest(), objects, limits)?;
    }

    if !verify_referenced_objects(plan.proposed_manifest(), environment_root, limits)
        .map_err(|_| verification_failed())?
        .is_clean()
    {
        return Err(verification_failed());
    }

    let manifest_encoded = plan
        .proposed_manifest()
        .to_toml()
        .map_err(|_| proposed_invalid())?;
    let lock_encoded = plan
        .proposed_lock()
        .to_json()
        .map_err(|_| proposed_invalid())?;
    let paths = transaction_paths(plan.digest())?;
    stage_authority_controls(
        &store,
        &paths,
        &manifest_encoded,
        &lock_encoded,
        plan.proposed_manifest(),
        plan.proposed_lock(),
    )?;

    let mut journal = PortableJournal {
        schema_version: 9,
        operation: JournalOperation::Manifest,
        phase: JournalPhase::Prepared,
        plan_digest: plan.digest().clone(),
        old_manifest_revision: plan.base_manifest_revision().clone(),
        new_manifest_revision: plan.proposed_manifest_revision().clone(),
        old_manifest_hash: ContentHash::digest(manifest_text.as_bytes()),
        new_manifest_hash: ContentHash::digest(manifest_encoded.as_bytes()),
        staging_manifest: Some(paths.manifest.clone()),
        staging_lock: paths.lock.clone(),
        old_lock_hash: Some(ContentHash::digest(expected_current_lock.as_bytes())),
        new_lock_hash: ContentHash::digest(lock_encoded.as_bytes()),
        portable_root: None,
        portable_hash: None,
        native_root: None,
        native_hash: None,
        portable_preexisting: None,
        native_preexisting: None,
        portable_format: None,
        native_format: None,
        staging_state: None,
        old_state_hash: None,
        new_state_hash: None,
        receipt_id: None,
        reviewed_target_hash: None,
        expected_prior: None,
    };
    let mut journal_encoded = write_journal(&store, &journal)?;
    interrupt(JournalPhase::Prepared, interrupt_after)?;

    store
        .install_staged_text_guarded(
            &paths.manifest,
            &portable_path(MANIFEST_PATH)?,
            Some(&manifest_text),
            &manifest_encoded,
            MAX_CONTROL_BYTES,
        )
        .map_err(|error| store_error_at(error, "transaction.manifest_install_io"))?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::ManifestCommitted,
    )?;
    interrupt(JournalPhase::ManifestCommitted, interrupt_after)?;

    store
        .install_staged_text_guarded(
            &paths.lock,
            &portable_path(LOCK_PATH)?,
            Some(&expected_current_lock),
            &lock_encoded,
            MAX_CONTROL_BYTES,
        )
        .map_err(|error| store_error_at(error, "transaction.lock_install_io"))?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::LockCommitted,
    )?;
    interrupt(JournalPhase::LockCommitted, interrupt_after)?;

    verify_committed(&store, environment_root, limits, plan.proposed_manifest())
        .map_err(|error| transaction_error_at(error, "transaction.verification_io"))?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::Verified,
    )?;
    interrupt(JournalPhase::Verified, interrupt_after)?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::Complete,
    )?;
    interrupt(JournalPhase::Complete, interrupt_after)?;
    cleanup_manifest_transaction(&store, &journal)?;
    Ok(PortableManifestCommitOutcome::Committed)
}

fn prepare_pack_rollback_objects(
    store: &ObjectStore,
    digest: &ContentHash,
    objects: &[VerifiedObjectEnvelope],
    limits: CaptureLimits,
) -> Result<(), PortableTransactionError> {
    let paths = transaction_paths(digest)?;
    let mut ordered = objects.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.descriptor().cmp(right.descriptor()));
    for (index, object) in ordered.into_iter().enumerate() {
        let staging = portable_path(&format!("{}/rollback-{index:08}", paths.base.as_str()))?;
        let descriptor = object.descriptor();
        if crate::sync_portable_transaction::verified_object_matches(
            store,
            descriptor.root(),
            descriptor,
            limits,
        ) {
            object
                .clear_staging(store, &staging, limits)
                .map_err(store_error)?;
            continue;
        }
        if !crate::sync_portable_transaction::verified_object_matches(
            store, &staging, descriptor, limits,
        ) {
            object
                .reset_incomplete_staging(store, &staging, limits)
                .map_err(store_error)?;
            object
                .stage_to(store, &staging, limits)
                .map_err(store_error)?;
        }
        if !crate::sync_portable_transaction::verified_object_matches(
            store, &staging, descriptor, limits,
        ) {
            return Err(verification_failed());
        }
        let outcome = object
            .install_from(store, &staging, limits)
            .map_err(store_error)?;
        if outcome == ObjectInstallOutcome::AlreadyPresent {
            object
                .clear_staging(store, &staging, limits)
                .map_err(store_error)?;
        }
        if !crate::sync_portable_transaction::verified_object_matches(
            store,
            descriptor.root(),
            descriptor,
            limits,
        ) {
            return Err(verification_failed());
        }
    }
    cleanup_empty_staging(store, &paths.base)
}

const fn manifest_plan_stale(kind: ManifestCommitKind) -> PortableTransactionError {
    match kind {
        ManifestCommitKind::Create => PortableTransactionError::new(
            "pack_create.manifest_stale",
            "manifest authority changed after pack creation was planned",
        ),
        ManifestCommitKind::Update => PortableTransactionError::new(
            "pack_update.manifest_stale",
            "manifest authority changed after pack update was planned",
        ),
        ManifestCommitKind::Adopt => PortableTransactionError::new(
            "pack_adopt.manifest_stale",
            "manifest authority changed after pack adoption was planned",
        ),
        ManifestCommitKind::Rollback => PortableTransactionError::new(
            "pack_rollback.manifest_stale",
            "manifest authority changed after pack rollback was planned",
        ),
    }
}

const fn manifest_plan_lock_stale(kind: ManifestCommitKind) -> PortableTransactionError {
    match kind {
        ManifestCommitKind::Create => PortableTransactionError::new(
            "transaction.lock_stale",
            "the generated lock must match manifest authority before pack creation",
        ),
        ManifestCommitKind::Update => PortableTransactionError::new(
            "transaction.lock_stale",
            "the generated lock must match manifest authority before pack update",
        ),
        ManifestCommitKind::Adopt => PortableTransactionError::new(
            "transaction.lock_stale",
            "the generated lock must match manifest authority before pack adoption",
        ),
        ManifestCommitKind::Rollback => PortableTransactionError::new(
            "transaction.lock_stale",
            "the generated lock must match manifest authority before pack rollback",
        ),
    }
}

const fn pack_rollback_objects_invalid() -> PortableTransactionError {
    PortableTransactionError::new(
        "pack_rollback.objects_invalid",
        "pack rollback requires the exact complete verified historical object set",
    )
}

const fn pack_adoption_objects_invalid() -> PortableTransactionError {
    PortableTransactionError::new(
        "pack_adopt.objects_invalid",
        "pack adoption requires the exact complete verified distribution object set",
    )
}

fn commit_lock_repair_inner(
    plan: &LockRepairPlan,
    environment_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<JournalPhase>,
) -> Result<LockRepairOutcome, PortableTransactionError> {
    let (forward_work, rollback_work) = PortableMutationKind::Lock.commit_work(limits)?;
    let store = ObjectStore::open(environment_root)
        .map_err(|error| store_error_at(error, "transaction.environment_open_io"))?;
    let _lock = store
        .try_lock_environment()
        .map_err(|error| store_error_at(error, "transaction.environment_lock_io"))?;
    ensure_no_foreign_environment_journal(&store)?;
    let recovery = recover_with_store(&store, environment_root, limits)
        .map_err(|error| transaction_error_at(error, "transaction.recovery_io"))?;
    let cleanup_budget =
        cleanup_locked_stores(&[&store], forward_work, rollback_work).map_err(cleanup_error)?;
    let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;
    let manifest_text = required_text(&store, MANIFEST_PATH)
        .map_err(|error| transaction_error_at(error, "transaction.manifest_read_io"))?;
    let manifest =
        EnvironmentManifest::from_toml(&manifest_text).map_err(|_| manifest_invalid())?;
    let manifest_revision = derive_manifest_revision(&manifest).map_err(|_| manifest_invalid())?;
    if manifest_revision != plan.manifest_revision {
        return Err(manifest_stale());
    }
    let current_lock = store
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(|error| store_error_at(error, "transaction.lock_read_io"))?;
    let current_comparison =
        compare_lockfile(&manifest, current_lock.as_deref()).map_err(|_| manifest_invalid())?;
    if current_comparison.status() == LockStatus::InSync {
        return Ok(if recovery == PortableRecoveryOutcome::CompletedCommitted {
            LockRepairOutcome::Recovered
        } else {
            LockRepairOutcome::AlreadyInSync
        });
    }
    if current_lock != plan.observed_lock {
        return Err(PortableTransactionError::new(
            "transaction.lock_stale",
            "the generated lock changed after repair planning",
        ));
    }

    let expected_encoded = plan
        .expected_lock
        .to_json()
        .map_err(|_| proposed_invalid())?;
    let paths = transaction_paths(plan.digest())?;
    store
        .reset_incomplete_staged_text(&paths.lock, &expected_encoded, MAX_CONTROL_BYTES)
        .map_err(|error| store_error_at(error, "transaction.lock_reset_io"))?;
    store
        .stage_text(&paths.lock, &expected_encoded, MAX_CONTROL_BYTES)
        .map_err(|error| store_error_at(error, "transaction.lock_stage_io"))?;
    let staged = store
        .read_text(&paths.lock, MAX_CONTROL_BYTES)
        .map_err(|error| store_error_at(error, "transaction.lock_verify_read_io"))?
        .ok_or_else(proposed_invalid)?;
    if Lockfile::from_json(&staged).map_err(|_| proposed_invalid())? != plan.expected_lock {
        return Err(proposed_invalid());
    }

    let mut journal = PortableJournal {
        schema_version: 2,
        operation: JournalOperation::Lock,
        phase: JournalPhase::Prepared,
        plan_digest: plan.digest.clone(),
        old_manifest_revision: plan.manifest_revision.clone(),
        new_manifest_revision: plan.manifest_revision.clone(),
        old_manifest_hash: ContentHash::digest(manifest_text.as_bytes()),
        new_manifest_hash: ContentHash::digest(manifest_text.as_bytes()),
        staging_manifest: None,
        staging_lock: paths.lock.clone(),
        old_lock_hash: current_lock
            .as_deref()
            .map(|text| ContentHash::digest(text.as_bytes())),
        new_lock_hash: ContentHash::digest(expected_encoded.as_bytes()),
        portable_root: None,
        portable_hash: None,
        native_root: None,
        native_hash: None,
        portable_preexisting: None,
        native_preexisting: None,
        portable_format: None,
        native_format: None,
        staging_state: None,
        old_state_hash: None,
        new_state_hash: None,
        receipt_id: None,
        reviewed_target_hash: None,
        expected_prior: None,
    };
    let mut journal_encoded = write_journal(&store, &journal)?;
    interrupt(JournalPhase::Prepared, interrupt_after)?;

    store
        .install_staged_text_guarded(
            &paths.lock,
            &portable_path(LOCK_PATH)?,
            current_lock.as_deref(),
            &expected_encoded,
            MAX_CONTROL_BYTES,
        )
        .map_err(|error| store_error_at(error, "transaction.lock_install_io"))?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::LockCommitted,
    )?;
    interrupt(JournalPhase::LockCommitted, interrupt_after)?;
    verify_lock_committed(&store, &manifest)
        .map_err(|error| transaction_error_at(error, "transaction.verification_io"))?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::Verified,
    )?;
    interrupt(JournalPhase::Verified, interrupt_after)?;
    update_phase(
        &store,
        &mut journal,
        &mut journal_encoded,
        JournalPhase::Complete,
    )?;
    interrupt(JournalPhase::Complete, interrupt_after)?;
    store
        .remove_regular_file_if_present(&portable_path(JOURNAL_PATH)?)
        .map_err(|error| store_error_at(error, "transaction.journal_cleanup_io"))?;
    cleanup_empty_staging(&store, &paths.base)
        .map_err(|error| transaction_error_at(error, "transaction.staging_cleanup_io"))?;
    Ok(LockRepairOutcome::Repaired)
}

fn parse_valid_journal(encoded: &str) -> Option<PortableJournal> {
    serde_json::from_str(encoded)
        .ok()
        .filter(|journal| validate_journal(journal).is_ok())
}

fn valid_journal_transition(old: &PortableJournal, next: &PortableJournal) -> bool {
    let mut normalized = old.clone();
    normalized.phase = next.phase;
    next.phase >= old.phase && normalized == *next
}

fn reconcile_interrupted_authority_controls(
    store: &ObjectStore,
    journal: &PortableJournal,
) -> Result<(), PortableTransactionError> {
    if let Some(staging_manifest) = &journal.staging_manifest {
        reconcile_guarded_control(
            store,
            staging_manifest,
            &portable_path(MANIFEST_PATH)?,
            Some(&journal.old_manifest_hash),
            &journal.new_manifest_hash,
            MAX_CONTROL_BYTES,
        )?;
    }
    reconcile_guarded_control(
        store,
        &journal.staging_lock,
        &portable_path(LOCK_PATH)?,
        journal.old_lock_hash.as_ref(),
        &journal.new_lock_hash,
        MAX_CONTROL_BYTES,
    )
}

fn recover_update_with_stores(
    environment: &ObjectStore,
    environment_root: &Path,
    state: &ObjectStore,
    limits: CaptureLimits,
) -> Result<UpdateRecoveryOutcome, PortableTransactionError> {
    let control_state = portable_journal_control_state(environment)?;
    if matches!(control_state, PortableJournalControlState::Invalid) {
        return Err(journal_invalid());
    }
    let Some(journal) = control_state.selected_journal().cloned() else {
        if !control_state.requires_reconciliation() {
            return Ok(UpdateRecoveryOutcome::NoJournal);
        }
        let work = MutationWork::try_from_counts(ORPHAN_PENDING_CLEANUP_TOMBSTONES, 0, limits)
            .map_err(cleanup_error)?;
        let cleanup_budget =
            cleanup_locked_stores(&[environment, state], work, MutationWork::none())
                .map_err(cleanup_error)?;
        let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;
        return recover_update_with_stores_inner(
            environment,
            environment_root,
            state,
            limits,
            None,
        );
    };
    if journal.operation != JournalOperation::Update {
        recover_with_store(environment, environment_root, limits)?;
        return Ok(UpdateRecoveryOutcome::NoJournal);
    }
    let direction = portable_recovery_direction(environment, &journal)?;
    let local_state = validate_update_recovery_control(state, &journal, direction)?;
    let (forward_work, rollback_work) =
        PortableMutationKind::Update { local_state }.recovery_work(direction, limits)?;
    let cleanup_budget = cleanup_locked_stores(&[environment, state], forward_work, rollback_work)
        .map_err(cleanup_error)?;
    let _mutation_budget = match direction {
        PortableRecoveryDirection::Forward => cleanup_budget.begin_forward(),
        PortableRecoveryDirection::Rollback => cleanup_budget.begin_rollback(),
    }
    .map_err(cleanup_error)?;
    recover_update_with_stores_inner(environment, environment_root, state, limits, Some(&journal))
}

fn validate_update_recovery_control(
    state: &ObjectStore,
    journal: &PortableJournal,
    direction: PortableRecoveryDirection,
) -> Result<bool, PortableTransactionError> {
    let (staging, old, new) = match (
        journal.staging_state.as_ref(),
        journal.old_state_hash.as_ref(),
        journal.new_state_hash.as_ref(),
    ) {
        (None, None, None) => return Ok(false),
        (Some(staging), Some(old), Some(new)) => (staging, old, new),
        _ => return Err(journal_invalid()),
    };
    let effective = effective_guarded_control_text(
        state,
        staging,
        &portable_path("state.json")?,
        Some(old),
        new,
        MAX_CONTROL_BYTES,
    )?
    .ok_or_else(recovery_blocked)?;
    if direction == PortableRecoveryDirection::Rollback
        && ContentHash::digest(effective.as_bytes()) != *old
    {
        return Err(recovery_blocked());
    }
    Ok(true)
}

fn recover_update_with_stores_inner(
    environment: &ObjectStore,
    environment_root: &Path,
    state: &ObjectStore,
    limits: CaptureLimits,
    expected_journal: Option<&PortableJournal>,
) -> Result<UpdateRecoveryOutcome, PortableTransactionError> {
    restore_interrupted_journal_control(environment)?;
    let Some(encoded) = environment
        .read_text(&portable_path(JOURNAL_PATH)?, MAX_JOURNAL_BYTES)
        .map_err(store_error)?
    else {
        return if expected_journal.is_none() {
            Ok(UpdateRecoveryOutcome::NoJournal)
        } else {
            Err(recovery_blocked())
        };
    };
    let journal: PortableJournal = serde_json::from_str(&encoded).map_err(|_| journal_invalid())?;
    validate_journal(&journal)?;
    if expected_journal != Some(&journal) {
        return Err(recovery_blocked());
    }
    if journal.operation != JournalOperation::Update {
        return Err(journal_invalid());
    }
    reconcile_interrupted_authority_controls(environment, &journal)?;
    if let (Some(staging), Some(old), Some(new)) = (
        journal.staging_state.as_ref(),
        journal.old_state_hash.as_ref(),
        journal.new_state_hash.as_ref(),
    ) {
        reconcile_guarded_control(
            state,
            staging,
            &portable_path("state.json")?,
            Some(old),
            new,
            MAX_CONTROL_BYTES,
        )?;
    }

    let manifest_text = required_text(environment, MANIFEST_PATH)?;
    let manifest =
        EnvironmentManifest::from_toml(&manifest_text).map_err(|_| recovery_blocked())?;
    let revision = derive_manifest_revision(&manifest).map_err(|_| recovery_blocked())?;
    if revision == journal.old_manifest_revision {
        cleanup_abandoned_adoption(environment, &journal, &manifest, limits)?;
        cleanup_update_state_staging(state, &journal)?;
        remove_update_journal(environment)?;
        return Ok(UpdateRecoveryOutcome::DiscardedUncommitted);
    }
    if revision != journal.new_manifest_revision {
        return Err(recovery_blocked());
    }
    validate_recovered_update_binding(state, &journal, &manifest)?;
    complete_recovered_lock(environment, &journal, &manifest)?;
    verify_committed(environment, environment_root, limits, &manifest)?;

    let has_receipt = journal.staging_state.is_some();
    let receipt_committed = match (
        journal.staging_state.as_ref(),
        journal.old_state_hash.as_ref(),
        journal.new_state_hash.as_ref(),
        journal.receipt_id.as_ref(),
        journal.reviewed_target_hash.as_ref(),
    ) {
        (None, None, None, None, None) => false,
        (Some(staging), Some(old), Some(new), Some(receipt_id), Some(target_hash)) => {
            let current = state
                .read_text(&portable_path("state.json")?, MAX_CONTROL_BYTES)
                .map_err(store_error)?
                .ok_or_else(recovery_blocked)?;
            let current_hash = ContentHash::digest(current.as_bytes());
            if &current_hash == new {
                true
            } else if &current_hash == old {
                if recovered_target_is_current(&current, receipt_id, target_hash, limits)? {
                    let proposed = state
                        .read_text(staging, MAX_CONTROL_BYTES)
                        .map_err(store_error)?
                        .ok_or_else(recovery_blocked)?;
                    if ContentHash::digest(proposed.as_bytes()) != *new {
                        return Err(recovery_blocked());
                    }
                    state
                        .install_staged_text_guarded(
                            staging,
                            &portable_path("state.json")?,
                            Some(&current),
                            &proposed,
                            MAX_CONTROL_BYTES,
                        )
                        .map_err(store_error)?;
                    true
                } else {
                    false
                }
            } else {
                return Err(recovery_blocked());
            }
        }
        _ => return Err(journal_invalid()),
    };
    cleanup_completed_update(environment, state, &journal)?;
    Ok(if !has_receipt {
        UpdateRecoveryOutcome::Completed
    } else if receipt_committed {
        UpdateRecoveryOutcome::CompletedWithReceipt
    } else {
        UpdateRecoveryOutcome::CompletedWithoutReceipt
    })
}

fn validate_recovered_update_binding(
    state_store: &ObjectStore,
    journal: &PortableJournal,
    manifest: &EnvironmentManifest,
) -> Result<(), PortableTransactionError> {
    let Some(staging_path) = journal.staging_state.as_ref() else {
        return Ok(());
    };
    let (Some(old_hash), Some(new_hash), Some(receipt_id), Some(reviewed_target_hash)) = (
        journal.old_state_hash.as_ref(),
        journal.new_state_hash.as_ref(),
        journal.receipt_id.as_ref(),
        journal.reviewed_target_hash.as_ref(),
    ) else {
        return Err(journal_invalid());
    };
    let expected_prior = journal
        .expected_prior
        .as_ref()
        .ok_or_else(journal_invalid)?;
    let current_text = state_store
        .read_text(&portable_path("state.json")?, MAX_CONTROL_BYTES)
        .map_err(store_error)?
        .ok_or_else(recovery_blocked)?;
    let current_hash = ContentHash::digest(current_text.as_bytes());
    if &current_hash != old_hash && &current_hash != new_hash {
        return Err(recovery_blocked());
    }
    let new_text = if &current_hash == new_hash {
        current_text.clone()
    } else {
        state_store
            .read_text(staging_path, MAX_CONTROL_BYTES)
            .map_err(store_error)?
            .ok_or_else(recovery_blocked)?
    };
    if ContentHash::digest(new_text.as_bytes()) != *new_hash {
        return Err(recovery_blocked());
    }
    let new_state =
        kitrove_model::LocalState::from_json(&new_text).map_err(|_| recovery_blocked())?;
    if new_state.to_json().ok().as_deref() != Some(new_text.as_str()) {
        return Err(recovery_blocked());
    }
    let new_receipt = new_state
        .receipts
        .get(receipt_id)
        .ok_or_else(recovery_blocked)?;
    let new_asset = manifest
        .assets
        .get(&new_receipt.asset_id)
        .ok_or_else(recovery_blocked)?;
    if new_receipt.receipt_id().ok().as_ref() != Some(receipt_id)
        || new_receipt.source_hash != new_asset.content_hash
        || new_receipt.environment_revision != journal.new_manifest_revision
        || &new_receipt.rendered_hash != reviewed_target_hash
        || new_receipt.prior_hash.is_none()
    {
        return Err(recovery_blocked());
    }
    if &current_hash == old_hash {
        let mut old_state =
            kitrove_model::LocalState::from_json(&current_text).map_err(|_| recovery_blocked())?;
        if old_state.to_json().ok().as_deref() != Some(current_text.as_str()) {
            return Err(recovery_blocked());
        }
        let old_receipt = old_state
            .receipts
            .get(receipt_id)
            .cloned()
            .ok_or_else(recovery_blocked)?;
        if old_receipt.receipt_id().ok().as_ref() != Some(receipt_id)
            || &old_receipt.source_hash != expected_prior
            || old_receipt.environment_revision != journal.old_manifest_revision
            || new_receipt.prior_hash.as_ref() != Some(&old_receipt.rendered_hash)
            || old_receipt.asset_id != new_receipt.asset_id
            || old_receipt.harness != new_receipt.harness
            || old_receipt.scope != new_receipt.scope
            || old_receipt.destination != new_receipt.destination
            || old_receipt.target != new_receipt.target
            || old_receipt.shared_with != new_receipt.shared_with
        {
            return Err(recovery_blocked());
        }
        old_state
            .receipts
            .insert(receipt_id.clone(), new_receipt.clone());
        if old_state.to_json().ok().as_deref() != Some(new_text.as_str()) {
            return Err(recovery_blocked());
        }
    }
    Ok(())
}

fn complete_recovered_lock(
    environment: &ObjectStore,
    journal: &PortableJournal,
    manifest: &EnvironmentManifest,
) -> Result<(), PortableTransactionError> {
    let expected = derive_lockfile(manifest).map_err(|_| recovery_blocked())?;
    let expected_text = expected.to_json().map_err(|_| recovery_blocked())?;
    if ContentHash::digest(expected_text.as_bytes()) != journal.new_lock_hash {
        return Err(recovery_blocked());
    }
    let current = environment
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(store_error)?;
    let current_hash = current
        .as_deref()
        .map(|text| ContentHash::digest(text.as_bytes()));
    if current_hash.as_ref() == Some(&journal.new_lock_hash) {
        return Ok(());
    }
    if current_hash != journal.old_lock_hash {
        return Err(recovery_blocked());
    }
    environment
        .replace_text_atomically_guarded(
            &portable_path(RECOVERY_LOCK_STAGE_PATH)?,
            &portable_path(LOCK_PATH)?,
            current.as_deref(),
            &expected_text,
            MAX_CONTROL_BYTES,
        )
        .map_err(store_error)
}

struct UpdateLocalPreconditions {
    old_state_text: Option<String>,
    new_state_text: Option<String>,
    receipt_id: Option<ReceiptId>,
    reviewed_target_hash: Option<ContentHash>,
}

fn update_local_preconditions(
    plan: UpdatePlanRef<'_>,
    state: &ObjectStore,
    limits: CaptureLimits,
) -> Result<UpdateLocalPreconditions, PortableTransactionError> {
    let Some(new_state) = plan.proposed_local_state_text() else {
        plan.ensure_local_state_fresh(None)?;
        return Ok(UpdateLocalPreconditions {
            old_state_text: None,
            new_state_text: None,
            receipt_id: None,
            reviewed_target_hash: None,
        });
    };
    let old_state = state
        .read_text(&portable_path("state.json")?, MAX_CONTROL_BYTES)
        .map_err(store_error)?
        .ok_or_else(local_state_stale)?;
    plan.ensure_local_state_fresh(Some(&old_state))?;
    if !reviewed_target_is_current(plan, limits) {
        return Err(target_stale());
    }
    let receipt = plan.receipt().ok_or_else(proposed_invalid)?;
    Ok(UpdateLocalPreconditions {
        old_state_text: Some(old_state),
        new_state_text: Some(new_state.to_owned()),
        receipt_id: Some(receipt.receipt_id().map_err(|_| proposed_invalid())?),
        reviewed_target_hash: Some(
            plan.reviewed_target_hash()
                .ok_or_else(proposed_invalid)?
                .clone(),
        ),
    })
}

fn revalidate_update_preconditions(
    plan: UpdatePlanRef<'_>,
    reread_observation: UpdateObservationRef<'_>,
    environment: &ObjectStore,
    state: &ObjectStore,
    limits: CaptureLimits,
) -> Result<(), PortableTransactionError> {
    plan.ensure_observation_fresh(reread_observation)?;
    let manifest_text = required_text(environment, MANIFEST_PATH)?;
    let manifest =
        EnvironmentManifest::from_toml(&manifest_text).map_err(|_| manifest_invalid())?;
    let lock = environment
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(store_error)?;
    plan.ensure_portable_authority_fresh(&manifest_text, &manifest, lock.as_deref())?;
    if plan.proposed_local_state_text().is_some() {
        let current = state
            .read_text(&portable_path("state.json")?, MAX_CONTROL_BYTES)
            .map_err(store_error)?;
        plan.ensure_local_state_fresh(current.as_deref())?;
        if !reviewed_target_is_current(plan, limits) {
            return Err(target_stale());
        }
    }
    Ok(())
}

fn reviewed_target_is_current(plan: UpdatePlanRef<'_>, limits: CaptureLimits) -> bool {
    let Some(receipt) = plan.receipt() else {
        return true;
    };
    let Some(expected) = plan.reviewed_target_hash() else {
        return false;
    };
    match receipt.target {
        ReceiptTarget::WholeTarget => matches!(
            observe_skill_destination(Path::new(receipt.destination.as_str()), limits),
            DestinationObservation::Present { rendered_hash, .. } if &rendered_hash == expected
        ),
        ReceiptTarget::ManagedInstructionRegion => {
            observe_instruction_region_hash(
                &receipt.destination,
                &receipt.asset_id,
                InstructionLimits::default(),
            )
            .as_ref()
                == Some(expected)
        }
        ReceiptTarget::ManagedMcpEntry => false,
    }
}

fn recovered_target_is_current(
    state_text: &str,
    receipt_id: &ReceiptId,
    reviewed_hash: &ContentHash,
    limits: CaptureLimits,
) -> Result<bool, PortableTransactionError> {
    let state = kitrove_model::LocalState::from_json(state_text).map_err(|_| recovery_blocked())?;
    let receipt = state
        .receipts
        .get(receipt_id)
        .ok_or_else(recovery_blocked)?;
    if receipt.receipt_id().ok().as_ref() != Some(receipt_id) {
        return Err(recovery_blocked());
    }
    Ok(match receipt.target {
        ReceiptTarget::WholeTarget => matches!(
            observe_skill_destination(Path::new(receipt.destination.as_str()), limits),
            DestinationObservation::Present { rendered_hash, .. } if &rendered_hash == reviewed_hash
        ),
        ReceiptTarget::ManagedInstructionRegion => {
            observe_instruction_region_hash(
                &receipt.destination,
                &receipt.asset_id,
                InstructionLimits::default(),
            )
            .as_ref()
                == Some(reviewed_hash)
        }
        ReceiptTarget::ManagedMcpEntry => false,
    })
}

fn verify_update_staging(
    environment: &ObjectStore,
    state: &ObjectStore,
    paths: &TransactionPaths,
    staging_state: Option<&PortablePath>,
    plan: UpdatePlanRef<'_>,
) -> Result<(), PortableTransactionError> {
    let manifest = environment
        .read_text(&paths.manifest, MAX_CONTROL_BYTES)
        .map_err(store_error)?
        .ok_or_else(proposed_invalid)?;
    let lock = environment
        .read_text(&paths.lock, MAX_CONTROL_BYTES)
        .map_err(store_error)?
        .ok_or_else(proposed_invalid)?;
    if EnvironmentManifest::from_toml(&manifest).map_err(|_| proposed_invalid())?
        != *plan.proposed_manifest()
        || Lockfile::from_json(&lock).map_err(|_| proposed_invalid())? != *plan.proposed_lock()
    {
        return Err(proposed_invalid());
    }
    if let Some(path) = staging_state {
        let staged = state
            .read_text(path, MAX_CONTROL_BYTES)
            .map_err(store_error)?;
        if staged.as_deref() != plan.proposed_local_state_text() {
            return Err(proposed_invalid());
        }
        kitrove_model::LocalState::from_json(staged.as_deref().expect("checked present"))
            .map_err(|_| proposed_invalid())?;
    }
    Ok(())
}

fn cleanup_update_state_staging(
    state: &ObjectStore,
    journal: &PortableJournal,
) -> Result<(), PortableTransactionError> {
    if let Some(path) = &journal.staging_state {
        state
            .remove_regular_file_if_present(path)
            .map_err(store_error)?;
        state
            .remove_regular_file_if_present(&guarded_backup_path(path).map_err(store_error)?)
            .map_err(store_error)?;
        if let Some((base, _)) = path.as_str().rsplit_once('/') {
            state
                .remove_empty_directory_if_present(&portable_path(base)?)
                .map_err(store_error)?;
        }
        state
            .remove_empty_directory_if_present(&portable_path(".kitrove/update-staging")?)
            .map_err(store_error)?;
    }
    Ok(())
}

fn cleanup_completed_update(
    environment: &ObjectStore,
    state: &ObjectStore,
    journal: &PortableJournal,
) -> Result<(), PortableTransactionError> {
    cleanup_update_state_staging(state, journal)?;
    for path in [
        journal.staging_manifest.as_ref(),
        Some(&journal.staging_lock),
    ]
    .into_iter()
    .flatten()
    {
        environment
            .remove_regular_file_if_present(path)
            .map_err(store_error)?;
        environment
            .remove_regular_file_if_present(&guarded_backup_path(path).map_err(store_error)?)
            .map_err(store_error)?;
    }
    let paths = transaction_paths(&journal.plan_digest)?;
    cleanup_empty_staging(environment, &paths.base)?;
    remove_update_journal(environment)
}

fn remove_update_journal(environment: &ObjectStore) -> Result<(), PortableTransactionError> {
    environment
        .remove_regular_file_if_present(&portable_path(JOURNAL_PATH)?)
        .map_err(store_error)?;
    environment
        .remove_regular_file_if_present(&portable_path(JOURNAL_PENDING_PATH)?)
        .map_err(store_error)
}

fn portable_recovery_direction(
    store: &ObjectStore,
    journal: &PortableJournal,
) -> Result<PortableRecoveryDirection, PortableTransactionError> {
    let manifest_text = if let Some(staging_manifest) = &journal.staging_manifest {
        effective_guarded_control_text(
            store,
            staging_manifest,
            &portable_path(MANIFEST_PATH)?,
            Some(&journal.old_manifest_hash),
            &journal.new_manifest_hash,
            MAX_CONTROL_BYTES,
        )?
        .ok_or_else(recovery_blocked)?
    } else {
        let manifest = required_text(store, MANIFEST_PATH)?;
        let manifest_hash = ContentHash::digest(manifest.as_bytes());
        if manifest_hash != journal.old_manifest_hash || manifest_hash != journal.new_manifest_hash
        {
            return Err(recovery_blocked());
        }
        manifest
    };
    let manifest =
        EnvironmentManifest::from_toml(&manifest_text).map_err(|_| recovery_blocked())?;
    let revision = derive_manifest_revision(&manifest).map_err(|_| recovery_blocked())?;
    effective_guarded_control_text(
        store,
        &journal.staging_lock,
        &portable_path(LOCK_PATH)?,
        journal.old_lock_hash.as_ref(),
        &journal.new_lock_hash,
        MAX_CONTROL_BYTES,
    )?;
    let direction = if journal.operation == JournalOperation::Lock {
        if revision == journal.new_manifest_revision {
            PortableRecoveryDirection::Forward
        } else {
            return Err(recovery_blocked());
        }
    } else if journal.old_manifest_revision != journal.new_manifest_revision {
        if revision == journal.old_manifest_revision {
            PortableRecoveryDirection::Rollback
        } else if revision == journal.new_manifest_revision {
            PortableRecoveryDirection::Forward
        } else {
            return Err(recovery_blocked());
        }
    } else if journal.phase == JournalPhase::Prepared {
        PortableRecoveryDirection::Rollback
    } else if revision == journal.new_manifest_revision {
        PortableRecoveryDirection::Forward
    } else {
        return Err(recovery_blocked());
    };
    if direction == PortableRecoveryDirection::Forward {
        let expected_lock = derive_lockfile(&manifest)
            .and_then(|lock| lock.to_json())
            .map_err(|_| recovery_blocked())?;
        if ContentHash::digest(expected_lock.as_bytes()) != journal.new_lock_hash {
            return Err(recovery_blocked());
        }
    }
    Ok(direction)
}

fn recover_with_store(
    store: &ObjectStore,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableRecoveryOutcome, PortableTransactionError> {
    let control_state = portable_journal_control_state(store)?;
    if matches!(control_state, PortableJournalControlState::Invalid) {
        return Err(journal_invalid());
    }
    let Some(journal) = control_state.selected_journal().cloned() else {
        if !control_state.requires_reconciliation() {
            return Ok(PortableRecoveryOutcome::NoJournal);
        }
        let work = MutationWork::try_from_counts(ORPHAN_PENDING_CLEANUP_TOMBSTONES, 0, limits)
            .map_err(cleanup_error)?;
        let cleanup_budget =
            cleanup_locked_stores(&[store], work, MutationWork::none()).map_err(cleanup_error)?;
        let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;
        return recover_with_store_inner(store, environment_root, limits, None);
    };
    if journal.operation == JournalOperation::Update {
        return Err(PortableTransactionError::new(
            "transaction.update_recovery_required",
            "an interrupted update requires environment and machine-local recovery",
        ));
    }
    let direction = portable_recovery_direction(store, &journal)?;
    let kind = match journal.operation {
        JournalOperation::Adopt => PortableMutationKind::Adoption,
        JournalOperation::Manifest => PortableMutationKind::Manifest {
            rollback_objects: 0,
        },
        JournalOperation::Lock => PortableMutationKind::Lock,
        JournalOperation::Update => unreachable!("checked above"),
    };
    let (forward_work, rollback_work) = kind.recovery_work(direction, limits)?;
    let cleanup_budget =
        cleanup_locked_stores(&[store], forward_work, rollback_work).map_err(cleanup_error)?;
    let _mutation_budget = match direction {
        PortableRecoveryDirection::Forward => cleanup_budget.begin_forward(),
        PortableRecoveryDirection::Rollback => cleanup_budget.begin_rollback(),
    }
    .map_err(cleanup_error)?;
    recover_with_store_inner(store, environment_root, limits, Some(&journal))
}

fn recover_with_store_inner(
    store: &ObjectStore,
    environment_root: &Path,
    limits: CaptureLimits,
    expected_journal: Option<&PortableJournal>,
) -> Result<PortableRecoveryOutcome, PortableTransactionError> {
    restore_interrupted_journal_control(store)?;
    let Some(encoded) = store
        .read_text(&portable_path(JOURNAL_PATH)?, MAX_JOURNAL_BYTES)
        .map_err(store_error)?
    else {
        return if expected_journal.is_none() {
            Ok(PortableRecoveryOutcome::NoJournal)
        } else {
            Err(recovery_blocked())
        };
    };
    let journal: PortableJournal = serde_json::from_str(&encoded).map_err(|_| journal_invalid())?;
    validate_journal(&journal)?;
    if expected_journal != Some(&journal) {
        return Err(recovery_blocked());
    }
    if journal.operation == JournalOperation::Update {
        return Err(PortableTransactionError::new(
            "transaction.update_recovery_required",
            "an interrupted update requires environment and machine-local recovery",
        ));
    }
    reconcile_interrupted_authority_controls(store, &journal)?;
    let manifest_text = required_text(store, MANIFEST_PATH)?;
    let manifest =
        EnvironmentManifest::from_toml(&manifest_text).map_err(|_| recovery_blocked())?;
    let revision = derive_manifest_revision(&manifest).map_err(|_| recovery_blocked())?;

    let discard_uncommitted = match journal.operation {
        JournalOperation::Adopt | JournalOperation::Manifest
            if journal.old_manifest_revision != journal.new_manifest_revision =>
        {
            revision == journal.old_manifest_revision
        }
        JournalOperation::Adopt => journal.phase == JournalPhase::Prepared,
        JournalOperation::Manifest => journal.phase == JournalPhase::Prepared,
        JournalOperation::Lock => false,
        JournalOperation::Update => unreachable!("update journals require combined recovery"),
    };
    if discard_uncommitted {
        if journal.operation == JournalOperation::Manifest {
            cleanup_manifest_transaction(store, &journal)?;
        } else {
            cleanup_abandoned_adoption(store, &journal, &manifest, limits)?;
        }
        store
            .remove_regular_file_if_present(&portable_path(JOURNAL_PATH)?)
            .map_err(store_error)?;
        store
            .remove_regular_file_if_present(&portable_path(JOURNAL_PENDING_PATH)?)
            .map_err(store_error)?;
        return Ok(PortableRecoveryOutcome::DiscardedUncommitted);
    }
    if revision != journal.new_manifest_revision {
        return Err(recovery_blocked());
    }

    let expected_lock = derive_lockfile(&manifest).map_err(|_| recovery_blocked())?;
    let expected_lock_encoded = expected_lock.to_json().map_err(|_| recovery_blocked())?;
    if ContentHash::digest(expected_lock_encoded.as_bytes()) != journal.new_lock_hash {
        return Err(recovery_blocked());
    }
    let lock_text = store
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(store_error)?;
    let current_lock_hash = lock_text
        .as_deref()
        .map(|text| ContentHash::digest(text.as_bytes()));
    if current_lock_hash.as_ref() != Some(&journal.new_lock_hash) {
        if current_lock_hash != journal.old_lock_hash {
            return Err(recovery_blocked());
        }
        store
            .replace_text_atomically_guarded(
                &portable_path(RECOVERY_LOCK_STAGE_PATH)?,
                &portable_path(LOCK_PATH)?,
                lock_text.as_deref(),
                &expected_lock_encoded,
                MAX_CONTROL_BYTES,
            )
            .map_err(store_error)?;
    }
    match journal.operation {
        JournalOperation::Adopt => verify_committed(store, environment_root, limits, &manifest)?,
        JournalOperation::Manifest => {
            verify_committed(store, environment_root, limits, &manifest)?;
        }
        JournalOperation::Lock => verify_lock_committed(store, &manifest)?,
        JournalOperation::Update => unreachable!("update journals require combined recovery"),
    }
    store
        .remove_regular_file_if_present(&portable_path(JOURNAL_PATH)?)
        .map_err(store_error)?;
    store
        .remove_regular_file_if_present(&portable_path(JOURNAL_PENDING_PATH)?)
        .map_err(store_error)?;
    if let Some(staging_manifest) = &journal.staging_manifest {
        store
            .remove_regular_file_if_present(staging_manifest)
            .map_err(store_error)?;
    }
    store
        .remove_regular_file_if_present(&journal.staging_lock)
        .map_err(store_error)?;
    store
        .remove_regular_file_if_present(
            &guarded_backup_path(&journal.staging_lock).map_err(store_error)?,
        )
        .map_err(store_error)?;
    if let Some(staging_manifest) = &journal.staging_manifest {
        store
            .remove_regular_file_if_present(
                &guarded_backup_path(staging_manifest).map_err(store_error)?,
            )
            .map_err(store_error)?;
    }
    let staging_root_source = journal
        .staging_manifest
        .as_ref()
        .unwrap_or(&journal.staging_lock);
    if let Some(base) = staging_root_source.as_str().rsplit_once('/') {
        cleanup_empty_staging(store, &portable_path(base.0)?)?;
    }
    Ok(PortableRecoveryOutcome::CompletedCommitted)
}

fn cleanup_abandoned_adoption(
    store: &ObjectStore,
    journal: &PortableJournal,
    manifest: &EnvironmentManifest,
    limits: CaptureLimits,
) -> Result<(), PortableTransactionError> {
    if journal.operation == JournalOperation::Lock {
        return Ok(());
    }
    let paths = transaction_paths(&journal.plan_digest)?;
    let object_kind = journal_object_kind(journal).ok_or_else(journal_invalid)?;
    let portable_root = journal.portable_root.as_ref().ok_or_else(journal_invalid)?;
    let portable_hash = journal.portable_hash.as_ref().ok_or_else(journal_invalid)?;
    if journal.operation == JournalOperation::Update || journal.portable_preexisting == Some(true) {
        object_kind.clear_portable(store, &paths.portable, portable_hash, limits)?;
    } else if !manifest.assets.values().any(|asset| {
        asset
            .portable
            .as_ref()
            .is_some_and(|portable| portable.root == *portable_root)
    }) {
        object_kind.remove_portable(
            store,
            &paths.portable,
            portable_root,
            portable_hash,
            limits,
        )?;
    }
    let native_root = journal.native_root.as_ref().ok_or_else(journal_invalid)?;
    let native_hash = journal.native_hash.as_ref().ok_or_else(journal_invalid)?;
    if journal.operation == JournalOperation::Update || journal.native_preexisting == Some(true) {
        object_kind.clear_native(store, &paths.native, native_hash, limits)?;
    } else if !manifest.assets.values().any(|asset| {
        asset
            .native_variants
            .values()
            .any(|native| native.root == *native_root)
    }) {
        object_kind.remove_native(store, &paths.native, native_root, native_hash, limits)?;
    }
    for path in [&paths.manifest, &paths.lock] {
        store
            .remove_regular_file_if_present(path)
            .map_err(store_error)?;
        store
            .remove_regular_file_if_present(&guarded_backup_path(path).map_err(store_error)?)
            .map_err(store_error)?;
    }
    cleanup_empty_staging(store, &paths.base)
}

fn cleanup_manifest_transaction(
    store: &ObjectStore,
    journal: &PortableJournal,
) -> Result<(), PortableTransactionError> {
    let paths = transaction_paths(&journal.plan_digest)?;
    for path in [&paths.manifest, &paths.lock] {
        store
            .remove_regular_file_if_present(path)
            .map_err(store_error)?;
        store
            .remove_regular_file_if_present(&guarded_backup_path(path).map_err(store_error)?)
            .map_err(store_error)?;
    }
    store
        .remove_regular_file_if_present(&portable_path(JOURNAL_PATH)?)
        .map_err(store_error)?;
    store
        .remove_regular_file_if_present(&portable_path(JOURNAL_PENDING_PATH)?)
        .map_err(store_error)?;
    cleanup_empty_staging(store, &paths.base)
}

fn journal_uses_instruction_objects(journal: &PortableJournal) -> bool {
    journal.portable_format.as_deref() == Some(StoredInstruction::format())
        && journal.native_format.as_deref() == Some(NativeInstructionRegion::format())
}

fn journal_uses_prompt_command_objects(journal: &PortableJournal) -> bool {
    journal.portable_format.as_deref() == Some(StoredPromptCommand::format())
        && journal.native_format.as_deref() == Some(StoredNativePromptCommand::format())
}

fn journal_uses_agent_objects(journal: &PortableJournal) -> bool {
    journal.portable_format.as_deref() == Some(StoredAgent::format())
        && journal.native_format.as_deref() == Some(StoredNativeAgent::format())
}

fn journal_uses_mcp_objects(journal: &PortableJournal) -> bool {
    journal.portable_format.as_deref() == Some(StoredMcpServer::format())
        && journal.native_format.as_deref() == Some(StoredNativeMcpEntry::format())
}

#[derive(Clone, Copy)]
enum JournalObjectKind {
    Skill,
    Instruction,
    PromptCommand,
    Agent,
    Mcp,
}

fn journal_object_kind(journal: &PortableJournal) -> Option<JournalObjectKind> {
    if journal.portable_format.is_none() && journal.native_format.is_none() {
        Some(JournalObjectKind::Skill)
    } else if journal_uses_instruction_objects(journal) {
        Some(JournalObjectKind::Instruction)
    } else if journal_uses_prompt_command_objects(journal) {
        Some(JournalObjectKind::PromptCommand)
    } else if journal_uses_agent_objects(journal) {
        Some(JournalObjectKind::Agent)
    } else if journal_uses_mcp_objects(journal) {
        Some(JournalObjectKind::Mcp)
    } else {
        None
    }
}

impl JournalObjectKind {
    fn clear_portable(
        self,
        store: &ObjectStore,
        staging: &PortablePath,
        hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), PortableTransactionError> {
        match self {
            Self::Skill => store.clear_portable_staging(staging, hash, limits),
            Self::Instruction => store.clear_portable_instruction_staging(staging, hash, limits),
            Self::PromptCommand => {
                store.clear_portable_prompt_command_staging(staging, hash, limits)
            }
            Self::Agent => store.clear_portable_agent_staging(staging, hash, limits),
            Self::Mcp => store.clear_portable_mcp_staging(staging, hash, limits),
        }
        .map_err(store_error)
    }

    fn clear_native(
        self,
        store: &ObjectStore,
        staging: &PortablePath,
        hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), PortableTransactionError> {
        match self {
            Self::Skill => store.clear_native_staging(staging, hash, limits),
            Self::Instruction => store.clear_native_instruction_staging(staging, hash, limits),
            Self::PromptCommand => store.clear_native_prompt_command_staging(staging, hash, limits),
            Self::Agent => store.clear_native_agent_staging(staging, hash, limits),
            Self::Mcp => store.clear_native_mcp_staging(staging, hash, limits),
        }
        .map_err(store_error)
    }

    fn remove_portable(
        self,
        store: &ObjectStore,
        staging: &PortablePath,
        destination: &PortablePath,
        hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), PortableTransactionError> {
        match self {
            Self::Skill => store.remove_unreferenced_portable(staging, destination, hash, limits),
            Self::Instruction => {
                store.remove_unreferenced_portable_instruction(staging, destination, hash, limits)
            }
            Self::PromptCommand => store.remove_unreferenced_portable_prompt_command(
                staging,
                destination,
                hash,
                limits,
            ),
            Self::Agent => {
                store.remove_unreferenced_portable_agent(staging, destination, hash, limits)
            }
            Self::Mcp => store.remove_unreferenced_portable_mcp(staging, destination, hash, limits),
        }
        .map_err(store_error)
    }

    fn remove_native(
        self,
        store: &ObjectStore,
        staging: &PortablePath,
        destination: &PortablePath,
        hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), PortableTransactionError> {
        match self {
            Self::Skill => store.remove_unreferenced_native(staging, destination, hash, limits),
            Self::Instruction => {
                store.remove_unreferenced_native_instruction(staging, destination, hash, limits)
            }
            Self::PromptCommand => {
                store.remove_unreferenced_native_prompt_command(staging, destination, hash, limits)
            }
            Self::Agent => {
                store.remove_unreferenced_native_agent(staging, destination, hash, limits)
            }
            Self::Mcp => store.remove_unreferenced_native_mcp(staging, destination, hash, limits),
        }
        .map_err(store_error)
    }
}

fn verify_committed(
    store: &ObjectStore,
    environment_root: &Path,
    limits: CaptureLimits,
    expected_manifest: &EnvironmentManifest,
) -> Result<(), PortableTransactionError> {
    let manifest_text = required_text(store, MANIFEST_PATH)?;
    let manifest =
        EnvironmentManifest::from_toml(&manifest_text).map_err(|_| verification_failed())?;
    if &manifest != expected_manifest {
        return Err(verification_failed());
    }
    let lock_text = store
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(store_error)?;
    if compare_lockfile(&manifest, lock_text.as_deref())
        .map_err(|_| verification_failed())?
        .status()
        != LockStatus::InSync
        || !verify_referenced_objects(&manifest, environment_root, limits)
            .map_err(|_| verification_failed())?
            .is_clean()
    {
        return Err(verification_failed());
    }
    Ok(())
}

fn verify_lock_committed(
    store: &ObjectStore,
    expected_manifest: &EnvironmentManifest,
) -> Result<(), PortableTransactionError> {
    let manifest_text = required_text(store, MANIFEST_PATH)?;
    let manifest =
        EnvironmentManifest::from_toml(&manifest_text).map_err(|_| verification_failed())?;
    let lock_text = store
        .read_text(&portable_path(LOCK_PATH)?, MAX_CONTROL_BYTES)
        .map_err(store_error)?;
    if &manifest != expected_manifest
        || compare_lockfile(&manifest, lock_text.as_deref())
            .map_err(|_| verification_failed())?
            .status()
            != LockStatus::InSync
    {
        return Err(verification_failed());
    }
    Ok(())
}

fn write_journal(
    store: &ObjectStore,
    journal: &PortableJournal,
) -> Result<String, PortableTransactionError> {
    write_journal_guarded(store, journal, None)
}

fn write_journal_guarded(
    store: &ObjectStore,
    journal: &PortableJournal,
    expected_current: Option<&str>,
) -> Result<String, PortableTransactionError> {
    let mut encoded = serde_json::to_string_pretty(journal).map_err(|_| journal_invalid())?;
    encoded.push('\n');
    if encoded.len() > MAX_JOURNAL_BYTES {
        return Err(journal_invalid());
    }
    store
        .replace_text_atomically_guarded(
            &portable_path(JOURNAL_PENDING_PATH)?,
            &portable_path(JOURNAL_PATH)?,
            expected_current,
            &encoded,
            MAX_JOURNAL_BYTES,
        )
        .map_err(|error| store_error_at(error, "transaction.journal_write_io"))?;
    Ok(encoded)
}

fn update_phase(
    store: &ObjectStore,
    journal: &mut PortableJournal,
    current_encoded: &mut String,
    phase: JournalPhase,
) -> Result<(), PortableTransactionError> {
    journal.phase = phase;
    let next = write_journal_guarded(store, journal, Some(current_encoded))?;
    *current_encoded = next;
    Ok(())
}

fn validate_journal(journal: &PortableJournal) -> Result<(), PortableTransactionError> {
    if !matches!(
        (journal.schema_version, journal.operation),
        (2, JournalOperation::Adopt | JournalOperation::Lock)
            | (3, JournalOperation::Update)
            | (4, JournalOperation::Adopt)
            | (5, JournalOperation::Update)
            | (6, JournalOperation::Adopt)
            | (7, JournalOperation::Adopt)
            | (8, JournalOperation::Adopt)
            | (9, JournalOperation::Manifest)
    ) || !journal
        .staging_lock
        .as_str()
        .starts_with(".kitrove/staging/")
    {
        return Err(journal_invalid());
    }
    let valid = match journal.operation {
        JournalOperation::Adopt => {
            let Ok(paths) = transaction_paths(&journal.plan_digest) else {
                return Err(journal_invalid());
            };
            let formats_valid = match journal.schema_version {
                2 => journal.portable_format.is_none() && journal.native_format.is_none(),
                4 => journal_uses_instruction_objects(journal),
                6 => journal_uses_prompt_command_objects(journal),
                7 => journal_uses_agent_objects(journal),
                8 => journal_uses_mcp_objects(journal),
                _ => false,
            };
            formats_valid
                && journal.staging_manifest.as_ref() == Some(&paths.manifest)
                && journal.staging_lock == paths.lock
                && journal.portable_root.is_some()
                && journal.portable_hash.is_some()
                && journal.native_root.is_some()
                && journal.native_hash.is_some()
                && journal.portable_preexisting.is_some()
                && journal.native_preexisting.is_some()
                && update_fields_absent(journal)
                && journal.phase != JournalPhase::StateCommitted
        }
        JournalOperation::Lock => {
            journal.staging_manifest.is_none()
                && journal.portable_root.is_none()
                && journal.portable_hash.is_none()
                && journal.native_root.is_none()
                && journal.native_hash.is_none()
                && journal.portable_preexisting.is_none()
                && journal.native_preexisting.is_none()
                && journal.portable_format.is_none()
                && journal.native_format.is_none()
                && update_fields_absent(journal)
                && journal.old_manifest_revision == journal.new_manifest_revision
                && !matches!(
                    journal.phase,
                    JournalPhase::ObjectsInstalled
                        | JournalPhase::ManifestCommitted
                        | JournalPhase::StateCommitted
                )
        }
        JournalOperation::Manifest => {
            let Ok(paths) = transaction_paths(&journal.plan_digest) else {
                return Err(journal_invalid());
            };
            journal.staging_manifest.as_ref() == Some(&paths.manifest)
                && journal.staging_lock == paths.lock
                && journal.portable_root.is_none()
                && journal.portable_hash.is_none()
                && journal.native_root.is_none()
                && journal.native_hash.is_none()
                && journal.portable_preexisting.is_none()
                && journal.native_preexisting.is_none()
                && journal.portable_format.is_none()
                && journal.native_format.is_none()
                && update_fields_absent(journal)
                && !matches!(
                    journal.phase,
                    JournalPhase::ObjectsInstalled | JournalPhase::StateCommitted
                )
        }
        JournalOperation::Update => {
            let Ok(paths) = transaction_paths(&journal.plan_digest) else {
                return Err(journal_invalid());
            };
            matches!(journal.schema_version, 3 | 5)
                && journal.staging_manifest.as_ref() == Some(&paths.manifest)
                && journal.staging_lock == paths.lock
                && journal.portable_root.is_some()
                && journal.portable_hash.is_some()
                && journal.native_root.is_some()
                && journal.native_hash.is_some()
                && journal.portable_preexisting.is_some()
                && journal.native_preexisting.is_some()
                && match journal.schema_version {
                    3 => journal.portable_format.is_none() && journal.native_format.is_none(),
                    5 => journal_uses_instruction_objects(journal),
                    _ => false,
                }
                && journal.expected_prior.is_some()
                && match (
                    &journal.staging_state,
                    &journal.old_state_hash,
                    &journal.new_state_hash,
                    &journal.receipt_id,
                    &journal.reviewed_target_hash,
                ) {
                    (None, None, None, None, None) => journal.phase != JournalPhase::StateCommitted,
                    (Some(path), Some(_), Some(_), Some(_), Some(_)) => {
                        update_state_staging_path(&journal.plan_digest)
                            .is_ok_and(|expected| path == &expected)
                    }
                    _ => false,
                }
        }
    };
    if !valid {
        return Err(journal_invalid());
    }
    Ok(())
}

fn update_fields_absent(journal: &PortableJournal) -> bool {
    journal.staging_state.is_none()
        && journal.old_state_hash.is_none()
        && journal.new_state_hash.is_none()
        && journal.receipt_id.is_none()
        && journal.reviewed_target_hash.is_none()
        && journal.expected_prior.is_none()
}

struct TransactionPaths {
    base: PortablePath,
    portable: PortablePath,
    native: PortablePath,
    manifest: PortablePath,
    lock: PortablePath,
}

fn transaction_paths(digest: &ContentHash) -> Result<TransactionPaths, PortableTransactionError> {
    let digest = digest
        .as_str()
        .strip_prefix("blake3:")
        .ok_or_else(proposed_invalid)?;
    let base = format!(".kitrove/staging/{digest}");
    Ok(TransactionPaths {
        base: portable_path(&base)?,
        portable: portable_path(&format!("{base}/portable"))?,
        native: portable_path(&format!("{base}/native"))?,
        manifest: portable_path(&format!("{base}/kitrove.toml"))?,
        lock: portable_path(&format!("{base}/kitrove.lock.json"))?,
    })
}

fn update_state_staging_path(
    digest: &ContentHash,
) -> Result<PortablePath, PortableTransactionError> {
    let digest = digest
        .as_str()
        .strip_prefix("blake3:")
        .ok_or_else(proposed_invalid)?;
    portable_path(&format!(".kitrove/update-staging/{digest}/state.json"))
}

fn cleanup_empty_staging(
    store: &ObjectStore,
    transaction_root: &PortablePath,
) -> Result<(), PortableTransactionError> {
    store
        .remove_empty_directory_if_present(transaction_root)
        .map_err(store_error)?;
    store
        .remove_empty_directory_if_present(&portable_path(".kitrove/staging")?)
        .map_err(store_error)
}

fn required_text(store: &ObjectStore, path: &str) -> Result<String, PortableTransactionError> {
    store
        .read_text(&portable_path(path)?, MAX_CONTROL_BYTES)
        .map_err(store_error)?
        .ok_or_else(manifest_invalid)
}

fn portable_path(value: &str) -> Result<PortablePath, PortableTransactionError> {
    PortablePath::parse(value).map_err(|_| path_invalid())
}

fn interrupt(
    phase: JournalPhase,
    requested: Option<JournalPhase>,
) -> Result<(), PortableTransactionError> {
    if requested == Some(phase) {
        Err(PortableTransactionError::new(
            "transaction.interrupted",
            "the portable transaction was interrupted at a test boundary",
        ))
    } else {
        Ok(())
    }
}

const fn lock_status_tag(status: LockStatus) -> u8 {
    match status {
        LockStatus::Missing => 0,
        LockStatus::Invalid => 1,
        LockStatus::Drift => 2,
        LockStatus::InSync => 3,
    }
}

fn write_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn write_optional_hash(hasher: &mut blake3::Hasher, value: Option<&ContentHash>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            write_record(hasher, value.as_str());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn store_error(error: crate::ObjectMutationError) -> PortableTransactionError {
    PortableTransactionError::new(
        error.code(),
        "the capability-scoped storage operation failed",
    )
}

fn store_error_at(
    error: crate::ObjectMutationError,
    io_code: &'static str,
) -> PortableTransactionError {
    if error.code() == "object.io" {
        PortableTransactionError::new(io_code, "the capability-scoped storage operation failed")
    } else {
        store_error(error)
    }
}

fn transaction_error_at(
    error: PortableTransactionError,
    io_code: &'static str,
) -> PortableTransactionError {
    if error.code() == "object.io" {
        PortableTransactionError::new(io_code, "the capability-scoped storage operation failed")
    } else {
        error
    }
}

fn cleanup_error(error: MutationCleanupError) -> PortableTransactionError {
    match error {
        MutationCleanupError::InvalidReservation => cleanup_limit(),
        MutationCleanupError::CleanupFailed => PortableTransactionError::new(
            "transaction.cleanup_failed",
            "portable mutation cleanup failed",
        ),
    }
}

const fn cleanup_limit() -> PortableTransactionError {
    PortableTransactionError::new(
        "transaction.cleanup_limit",
        "the portable transaction exceeds the supported mutation cleanup limit",
    )
}

const fn observation_stale() -> PortableTransactionError {
    PortableTransactionError::new(
        "adoption.observation_stale",
        "the selected observation changed after planning",
    )
}

const fn manifest_stale() -> PortableTransactionError {
    PortableTransactionError::new(
        "adoption.manifest_stale",
        "the authoritative manifest changed after planning",
    )
}

const fn local_state_stale() -> PortableTransactionError {
    PortableTransactionError::new(
        "update.local_state_stale",
        "machine-local update authority changed after planning",
    )
}

const fn target_stale() -> PortableTransactionError {
    PortableTransactionError::new(
        "update.target_stale",
        "the reviewed update target changed after planning",
    )
}

const fn manifest_invalid() -> PortableTransactionError {
    PortableTransactionError::new(
        "transaction.manifest_invalid",
        "the authoritative manifest is missing or invalid",
    )
}

const fn proposed_invalid() -> PortableTransactionError {
    PortableTransactionError::new(
        "transaction.proposed_state_invalid",
        "the proposed portable state is invalid",
    )
}

const fn journal_invalid() -> PortableTransactionError {
    PortableTransactionError::new(
        "transaction.journal_invalid",
        "the portable recovery journal is invalid",
    )
}

const fn recovery_blocked() -> PortableTransactionError {
    PortableTransactionError::new(
        "transaction.recovery_blocked",
        "portable recovery found concurrent or corrupt authority and made no replacement",
    )
}

const fn verification_failed() -> PortableTransactionError {
    PortableTransactionError::new(
        "transaction.verification_failed",
        "the committed portable environment failed independent verification",
    )
}

const fn path_invalid() -> PortableTransactionError {
    PortableTransactionError::new(
        "transaction.path_invalid",
        "the transaction could not form a fixed portable control path",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::sync::Arc;

    use kitrove_adapter_api::{
        CapabilityMatrix, InstructionTargetAnchor, InstructionTargetPolicy, PolicyLine,
    };
    use kitrove_agent_skills::{CaptureUsage, NativeSkillObject, StoredSkillTree};
    use kitrove_instructions::InstructionLimits;
    use kitrove_model::{
        AssetId, ContentClass, DeploymentReceipt, EnvironmentManifest, HarnessId, HarnessScope,
        LocalState, MachineConfig, MachineId, NormalizedDestination, ProfileId, ReceiptTarget,
        RemoteRevision, SchemaVersion, SyncLimits,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::adoption::tests::{capabilities, ready_plan, with_changed_document_bytes};
    use crate::agent_adoption::tests::{
        capabilities as agent_capabilities, empty_manifest as empty_agent_manifest,
        portable_observation as agent_observation,
    };
    use crate::mcp_adoption::tests::{
        capabilities as mcp_capabilities, empty_manifest as empty_mcp_manifest,
        observe as mcp_observation,
    };
    use crate::prompt_command_adoption::tests::{
        capabilities as prompt_command_capabilities, manifest as empty_prompt_command_manifest,
        observation as prompt_command_observation,
    };
    use crate::update::tests::{
        REDACTION_AUTHORED, REDACTION_DESTINATION, REDACTION_NATIVE_ID, REDACTION_PATH,
        REDACTION_SECRET, explicit_update_fixture, managed_update_fixture_at,
        redaction_update_fixture,
    };
    use crate::{
        AdoptionPlanOutcome, AgentAdoptionOutcome, InstructionAdoptionOutcome,
        InstructionScanEntry, McpAdoptionOutcome, PromptCommandAdoptionOutcome, ScanMode,
        ScanReport, TierOneInstructionCapabilities, VerifiedSkillObjectCatalog,
        load_native_agent_object, load_native_instruction_object, load_native_mcp_object,
        load_native_prompt_command_object, load_native_skill_object, load_portable_agent_object,
        load_portable_instruction_object, load_portable_mcp_object,
        load_portable_prompt_command_object, load_portable_skill_object,
        observe_instruction_document, plan_adoption, plan_agent_adoption, plan_agent_update,
        plan_instruction_adoption, plan_instruction_update, plan_mcp_adoption, plan_mcp_update,
        plan_prompt_command_adoption, plan_prompt_command_update, plan_update_adoption,
    };

    #[test]
    fn update_adoption_interlock_refuses_every_foreign_state_journal() {
        for path in [
            local_state_authority::TRUST_JOURNAL_PATH,
            local_state_authority::TRUST_PENDING_PATH,
            local_state_authority::EXTENSION_APPLY_JOURNAL_PATH,
            local_state_authority::SKILL_APPLY_JOURNAL_PATH,
            local_state_authority::SKILL_APPLY_PENDING_PATH,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            fs::create_dir_all(temporary.path().join(".kitrove")).unwrap();
            fs::write(temporary.path().join(path), "{}\n").unwrap();
            let state_root = fs::canonicalize(temporary.path()).unwrap();
            let state = ObjectStore::open(&state_root).unwrap();
            let error = ensure_no_foreign_local_state_journal(&state).unwrap_err();
            assert_eq!(error.code(), "transaction.local_state_recovery_required");
        }
    }

    #[test]
    fn portable_mutations_refuse_every_foreign_sync_artifact() {
        for path in [
            local_state_authority::SYNC_PORTABLE_JOURNAL_PATH,
            local_state_authority::SYNC_PORTABLE_PENDING_PATH,
            local_state_authority::OUTER_SYNC_GUARD_PATH,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            fs::create_dir_all(temporary.path().join(".kitrove")).unwrap();
            fs::write(temporary.path().join(path), "foreign\n").unwrap();
            let environment_root = fs::canonicalize(temporary.path()).unwrap();
            let environment = ObjectStore::open(&environment_root).unwrap();

            let error = ensure_no_foreign_environment_journal(&environment).unwrap_err();

            assert_eq!(error.code(), "transaction.foreign_recovery_required");
        }
    }

    fn environment() -> (
        TempDir,
        std::path::PathBuf,
        AdoptionPlan,
        AcceptedObservedCandidate,
    ) {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let (plan, candidate, manifest) = ready_plan();
        stage_control_file(&canonical_root, MANIFEST_PATH, &manifest.to_toml().unwrap());
        (root, canonical_root, plan, candidate)
    }

    fn stage_control_file(environment: &Path, path: &str, contents: &str) {
        ObjectStore::open(environment)
            .unwrap()
            .stage_text(&portable_path(path).unwrap(), contents, MAX_CONTROL_BYTES)
            .unwrap();
    }

    fn pack_creation_environment() -> (TempDir, std::path::PathBuf, PackCreationPlan) {
        let root = tempfile::tempdir().unwrap();
        let environment = root.path().canonicalize().unwrap();
        let manifest = crate::pack_creation::tests::manifest();
        let lock = derive_lockfile(&manifest).unwrap().to_json().unwrap();
        stage_control_file(
            environment.as_path(),
            MANIFEST_PATH,
            &manifest.to_toml().unwrap(),
        );
        stage_control_file(environment.as_path(), LOCK_PATH, &lock);
        let plan = crate::plan_pack_creation(
            &manifest,
            AssetId::parse("tooling").unwrap(),
            [
                AssetId::parse("left").unwrap(),
                AssetId::parse("right").unwrap(),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        (root, environment, plan)
    }

    fn pack_update_environment() -> (TempDir, std::path::PathBuf, PackUpdatePlan) {
        let root = tempfile::tempdir().unwrap();
        let environment = root.path().canonicalize().unwrap();
        let base = crate::pack_creation::tests::manifest();
        let created = crate::plan_pack_creation(
            &base,
            AssetId::parse("tooling").unwrap(),
            BTreeSet::from([
                AssetId::parse("left").unwrap(),
                AssetId::parse("right").unwrap(),
            ]),
        )
        .unwrap();
        let manifest = created.proposed_manifest();
        let lock = derive_lockfile(manifest).unwrap().to_json().unwrap();
        stage_control_file(
            environment.as_path(),
            MANIFEST_PATH,
            &manifest.to_toml().unwrap(),
        );
        stage_control_file(environment.as_path(), LOCK_PATH, &lock);
        let left = AssetId::parse("left").unwrap();
        let plan = crate::plan_pack_update(
            manifest,
            left.clone(),
            manifest.packs[&left].content_hash.clone(),
            BTreeSet::from([AssetId::parse("right").unwrap()]),
        )
        .unwrap();
        (root, environment, plan)
    }

    fn pack_rollback_environment() -> (TempDir, std::path::PathBuf, PackRollbackPlan) {
        let root = tempfile::tempdir().unwrap();
        let environment = root.path().canonicalize().unwrap();
        let historical = crate::pack_creation::tests::manifest();
        let mut current = historical.clone();
        let alpha = AssetId::parse("alpha").unwrap();
        current.assets.get_mut(&alpha).unwrap().content_class = ContentClass::AgentActive;
        current
            .assets
            .get_mut(&alpha)
            .unwrap()
            .refresh_content_hash();
        current.refresh_pack_revisions().unwrap();
        stage_control_file(
            environment.as_path(),
            MANIFEST_PATH,
            &current.to_toml().unwrap(),
        );
        stage_control_file(
            environment.as_path(),
            LOCK_PATH,
            &derive_lockfile(&current).unwrap().to_json().unwrap(),
        );
        let left = AssetId::parse("left").unwrap();
        let limits = SyncLimits::default();
        let history = crate::VerifiedRemoteHistory::new(
            vec![
                (
                    RemoteRevision::parse("test:rollback-current").unwrap(),
                    Arc::new(
                        crate::PortableSnapshotV1::new(current.clone(), BTreeSet::new(), limits)
                            .unwrap(),
                    ),
                ),
                (
                    RemoteRevision::parse("test:rollback-history").unwrap(),
                    Arc::new(
                        crate::PortableSnapshotV1::new(historical.clone(), BTreeSet::new(), limits)
                            .unwrap(),
                    ),
                ),
            ],
            limits,
        )
        .unwrap();
        let selection = crate::select_pack_rollback_snapshot(
            &history,
            &left,
            &current.packs[&left].content_hash,
            &historical.packs[&left].content_hash,
        )
        .unwrap();
        let plan = crate::plan_pack_rollback(&current, &selection).unwrap();
        (root, environment, plan)
    }

    fn pack_rollback_object_environment() -> (
        TempDir,
        std::path::PathBuf,
        PackRollbackPlan,
        Vec<VerifiedObjectEnvelope>,
    ) {
        let root = tempfile::tempdir().unwrap();
        let environment = root.path().canonicalize().unwrap();
        let (adoption, _, _) = crate::adoption::tests::ready_plan();
        let current = crate::pack_creation::tests::manifest();
        let mut historical = current.clone();
        let alpha = AssetId::parse("alpha").unwrap();
        let left = AssetId::parse("left").unwrap();
        let mut asset = adoption.asset().clone();
        asset.id = alpha.clone();
        asset.refresh_content_hash();
        historical.assets.insert(alpha, asset.clone());
        historical.refresh_pack_revisions().unwrap();
        let objects = vec![
            VerifiedObjectEnvelope::portable(
                asset.portable.as_ref().unwrap().root.clone(),
                adoption.portable_object().clone(),
            )
            .unwrap(),
            VerifiedObjectEnvelope::native(
                asset.native_variants[adoption.origin_harness()]
                    .root
                    .clone(),
                adoption.native_object().clone(),
            )
            .unwrap(),
        ];
        let descriptors = objects
            .iter()
            .map(|object| object.descriptor().clone())
            .collect();
        let limits = SyncLimits::default();
        let history = crate::VerifiedRemoteHistory::new(
            vec![
                (
                    RemoteRevision::parse("test:object-current").unwrap(),
                    Arc::new(
                        crate::PortableSnapshotV1::new(current.clone(), BTreeSet::new(), limits)
                            .unwrap(),
                    ),
                ),
                (
                    RemoteRevision::parse("test:object-history").unwrap(),
                    Arc::new(
                        crate::PortableSnapshotV1::new(historical, descriptors, limits).unwrap(),
                    ),
                ),
            ],
            limits,
        )
        .unwrap();
        let selection = crate::select_pack_rollback_snapshot(
            &history,
            &left,
            &current.packs[&left].content_hash,
            &history.snapshots()[1].snapshot().manifest().packs[&left].content_hash,
        )
        .unwrap();
        let plan = crate::plan_pack_rollback(&current, &selection).unwrap();
        stage_control_file(
            environment.as_path(),
            MANIFEST_PATH,
            &current.to_toml().unwrap(),
        );
        stage_control_file(
            environment.as_path(),
            LOCK_PATH,
            &derive_lockfile(&current).unwrap().to_json().unwrap(),
        );
        (root, environment, plan, objects)
    }

    #[test]
    fn pack_creation_recovers_every_durable_metadata_phase() {
        for phase in [
            JournalPhase::Prepared,
            JournalPhase::ManifestCommitted,
            JournalPhase::LockCommitted,
            JournalPhase::Verified,
            JournalPhase::Complete,
        ] {
            let (_root, environment, plan) = pack_creation_environment();
            let interrupted = commit_pack_mutation_inner(
                &plan,
                PackMutationKind::Create,
                &environment,
                CaptureLimits::default(),
                Some(phase),
            )
            .unwrap_err();
            assert_eq!(interrupted.code(), "transaction.interrupted");

            let outcome =
                commit_pack_creation(&plan, &environment, CaptureLimits::default()).unwrap();
            let expected = if phase == JournalPhase::Prepared {
                PortableManifestCommitOutcome::Committed
            } else {
                PortableManifestCommitOutcome::Recovered
            };
            assert_eq!(outcome, expected);
            assert_eq!(
                fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
                plan.proposed_manifest().to_toml().unwrap()
            );
            assert_eq!(
                fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
                plan.proposed_lock().to_json().unwrap()
            );
            assert!(!environment.join(JOURNAL_PATH).exists());
        }
    }

    #[test]
    fn pack_update_recovers_every_durable_metadata_phase() {
        for phase in [
            JournalPhase::Prepared,
            JournalPhase::ManifestCommitted,
            JournalPhase::LockCommitted,
            JournalPhase::Verified,
            JournalPhase::Complete,
        ] {
            let (_root, environment, plan) = pack_update_environment();
            let interrupted = commit_pack_mutation_inner(
                &plan,
                PackMutationKind::Update,
                &environment,
                CaptureLimits::default(),
                Some(phase),
            )
            .unwrap_err();
            assert_eq!(interrupted.code(), "transaction.interrupted");

            let outcome =
                commit_pack_update(&plan, &environment, CaptureLimits::default()).unwrap();
            let expected = if phase == JournalPhase::Prepared {
                PortableManifestCommitOutcome::Committed
            } else {
                PortableManifestCommitOutcome::Recovered
            };
            assert_eq!(outcome, expected);
            assert_eq!(
                fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
                plan.proposed_manifest().to_toml().unwrap()
            );
            assert_eq!(
                fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
                plan.proposed_lock().to_json().unwrap()
            );
            assert!(!environment.join(JOURNAL_PATH).exists());
        }
    }

    #[test]
    fn pack_rollback_recovers_every_durable_metadata_phase() {
        for phase in [
            JournalPhase::Prepared,
            JournalPhase::ManifestCommitted,
            JournalPhase::LockCommitted,
            JournalPhase::Verified,
            JournalPhase::Complete,
        ] {
            let (_root, environment, plan, objects) = pack_rollback_object_environment();
            let interrupted = commit_manifest_plan_inner(
                &plan,
                ManifestCommitKind::Rollback,
                Some(&objects),
                &environment,
                CaptureLimits::default(),
                Some(phase),
            )
            .unwrap_err();
            assert_eq!(interrupted.code(), "transaction.interrupted");

            let outcome =
                commit_pack_rollback(&plan, &objects, &environment, CaptureLimits::default())
                    .unwrap();
            let expected = if phase == JournalPhase::Prepared {
                PortableManifestCommitOutcome::Committed
            } else {
                PortableManifestCommitOutcome::Recovered
            };
            assert_eq!(outcome, expected);
            assert_eq!(
                fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
                plan.proposed_manifest().to_toml().unwrap()
            );
            assert_eq!(
                fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
                plan.proposed_lock().to_json().unwrap()
            );
            assert!(!environment.join(JOURNAL_PATH).exists());
        }
    }

    #[test]
    fn pack_rollback_refuses_stale_authority_without_mutation() {
        let (_root, environment, plan) = pack_rollback_environment();
        let original_manifest = fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap();
        fs::write(environment.join(LOCK_PATH), "{}\n").unwrap();

        let error =
            commit_pack_rollback(&plan, &[], &environment, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "transaction.lock_stale");
        assert_eq!(
            fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
            original_manifest
        );
        assert_eq!(
            fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
            "{}\n"
        );
        assert!(!environment.join(JOURNAL_PATH).exists());

        let (_root, environment, plan) = pack_rollback_environment();
        let manifest_path = environment.join(MANIFEST_PATH);
        let mut changed =
            EnvironmentManifest::from_toml(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        changed
            .assets
            .get_mut(&AssetId::parse("beta").unwrap())
            .unwrap()
            .content_class = ContentClass::AgentActive;
        changed
            .assets
            .get_mut(&AssetId::parse("beta").unwrap())
            .unwrap()
            .refresh_content_hash();
        changed.refresh_pack_revisions().unwrap();
        let changed_manifest = changed.to_toml().unwrap();
        let changed_lock = derive_lockfile(&changed).unwrap().to_json().unwrap();
        fs::write(&manifest_path, &changed_manifest).unwrap();
        fs::write(environment.join(LOCK_PATH), &changed_lock).unwrap();

        let error =
            commit_pack_rollback(&plan, &[], &environment, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "pack_rollback.manifest_stale");
        assert_eq!(fs::read_to_string(manifest_path).unwrap(), changed_manifest);
        assert_eq!(
            fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
            changed_lock
        );
        assert!(!environment.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn pack_rollback_requires_historical_objects_before_mutation() {
        let (_root, environment, plan, objects) = pack_rollback_object_environment();
        let manifest_text = fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap();
        let lock_text = fs::read_to_string(environment.join(LOCK_PATH)).unwrap();

        let error =
            commit_pack_rollback(&plan, &[], &environment, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "pack_rollback.objects_invalid");
        assert_eq!(
            fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
            manifest_text
        );
        assert_eq!(
            fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
            lock_text
        );
        assert!(!environment.join(JOURNAL_PATH).exists());

        let outcome =
            commit_pack_rollback(&plan, &objects, &environment, CaptureLimits::default()).unwrap();

        assert_eq!(outcome, PortableManifestCommitOutcome::Committed);
        assert!(
            verify_referenced_objects(
                plan.proposed_manifest(),
                &environment,
                CaptureLimits::default(),
            )
            .unwrap()
            .is_clean()
        );
    }

    #[test]
    fn pack_rollback_retry_replaces_incomplete_object_staging() {
        let (_root, environment, plan, objects) = pack_rollback_object_environment();
        crate::test_authority::initialize_portable_control_root(&environment).unwrap();
        let paths = transaction_paths(plan.digest()).unwrap();
        let incomplete = environment
            .join(paths.base.as_str())
            .join("rollback-00000000");
        crate::test_authority::create_owned_fixture_directory(
            &environment,
            &format!("{}/rollback-00000000", paths.base.as_str()),
        );
        crate::test_authority::write_owned_fixture_file(
            incomplete.join("partial"),
            b"not an object",
        )
        .unwrap();

        let outcome =
            commit_pack_rollback(&plan, &objects, &environment, CaptureLimits::default()).unwrap();

        assert_eq!(outcome, PortableManifestCommitOutcome::Committed);
        assert!(!environment.join(paths.base.as_str()).exists());
        assert!(
            verify_referenced_objects(
                plan.proposed_manifest(),
                &environment,
                CaptureLimits::default(),
            )
            .unwrap()
            .is_clean()
        );
    }

    #[test]
    fn pack_creation_refuses_stale_lock_without_mutation() {
        let (_root, environment, plan) = pack_creation_environment();
        let original_manifest = fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap();
        fs::write(environment.join(LOCK_PATH), "{}\n").unwrap();

        let error =
            commit_pack_creation(&plan, &environment, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "transaction.lock_stale");
        assert_eq!(
            fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
            original_manifest
        );
        assert_eq!(
            fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
            "{}\n"
        );
        assert!(!environment.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn pack_update_refuses_stale_manifest_and_lock_without_mutation() {
        let (_root, environment, plan) = pack_update_environment();
        let original_manifest = fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap();
        fs::write(environment.join(LOCK_PATH), "{}\n").unwrap();

        let error = commit_pack_update(&plan, &environment, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "transaction.lock_stale");
        assert_eq!(
            fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
            original_manifest
        );
        assert_eq!(
            fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
            "{}\n"
        );

        let (_root, environment, plan) = pack_update_environment();
        let manifest_path = environment.join(MANIFEST_PATH);
        let mut changed =
            EnvironmentManifest::from_toml(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        changed
            .packs
            .get_mut(&AssetId::parse("right").unwrap())
            .unwrap()
            .exact_source_hash = ContentHash::digest(b"concurrent-pack-update");
        changed.refresh_pack_revisions().unwrap();
        let changed_manifest = changed.to_toml().unwrap();
        let changed_lock = derive_lockfile(&changed).unwrap().to_json().unwrap();
        fs::write(&manifest_path, &changed_manifest).unwrap();
        fs::write(environment.join(LOCK_PATH), &changed_lock).unwrap();

        let error = commit_pack_update(&plan, &environment, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "pack_update.manifest_stale");
        assert_eq!(fs::read_to_string(manifest_path).unwrap(), changed_manifest);
        assert_eq!(
            fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
            changed_lock
        );
        assert!(!environment.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn pack_creation_refuses_stale_manifest_without_mutation() {
        let (_root, environment, plan) = pack_creation_environment();
        let mut changed = crate::pack_creation::tests::manifest();
        changed.packs.remove(&AssetId::parse("right").unwrap());
        changed.validate().unwrap();
        let changed_manifest = changed.to_toml().unwrap();
        let changed_lock = derive_lockfile(&changed).unwrap().to_json().unwrap();
        fs::write(environment.join(MANIFEST_PATH), &changed_manifest).unwrap();
        fs::write(environment.join(LOCK_PATH), &changed_lock).unwrap();

        let error =
            commit_pack_creation(&plan, &environment, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "pack_create.manifest_stale");
        assert_eq!(
            fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
            changed_manifest
        );
        assert_eq!(
            fs::read_to_string(environment.join(LOCK_PATH)).unwrap(),
            changed_lock
        );
        assert!(!environment.join(JOURNAL_PATH).exists());
    }

    fn instruction_capabilities() -> TierOneInstructionCapabilities {
        TierOneInstructionCapabilities::new(
            [
                HarnessId::Claude,
                HarnessId::Codex,
                HarnessId::Pi,
                HarnessId::OpenCode,
            ]
            .into_iter()
            .map(|harness| {
                (
                    harness,
                    CapabilityMatrix::empty().with_portable_instructions(
                        "test-instructions/1",
                        "test adapter accepts canonical standing instructions",
                    ),
                )
            })
            .collect(),
        )
        .unwrap()
    }

    fn empty_instruction_manifest() -> EnvironmentManifest {
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        }
    }

    fn observed_document(body: &str) -> (TempDir, InstructionDocumentObservation) {
        let source = tempfile::tempdir().unwrap();
        fs::write(
            source.path().join("CLAUDE.md"),
            format!(
                "User preface.\n<!-- kitrove:instruction review begin -->\n{body}\n<!-- kitrove:instruction review end -->\n"
            ),
        )
        .unwrap();
        let policy = InstructionTargetPolicy::new(
            HarnessId::Claude,
            HarnessScope::User,
            PolicyLine::ClaudeCurrent,
            InstructionTargetAnchor::Scope,
            "CLAUDE.md",
            "test-claude/1",
            "claude.instructions.current",
        )
        .unwrap();
        let observation = observe_instruction_document(
            &source.path().canonicalize().unwrap(),
            &policy,
            InstructionLimits::default(),
        )
        .unwrap();
        (source, observation)
    }

    fn instruction_environment() -> (
        TempDir,
        TempDir,
        std::path::PathBuf,
        InstructionAdoptionPlan,
        InstructionDocumentObservation,
    ) {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let (source, observation) = observed_document("Review carefully.");
        let manifest = empty_instruction_manifest();
        let outcome = plan_instruction_adoption(
            &observation,
            &kitrove_model::AssetId::parse("review").unwrap(),
            &manifest,
            &instruction_capabilities(),
        )
        .unwrap();
        let InstructionAdoptionOutcome::Ready(plan) = outcome else {
            panic!("valid instruction must produce a ready plan");
        };
        stage_control_file(&canonical_root, MANIFEST_PATH, &manifest.to_toml().unwrap());
        (root, source, canonical_root, *plan, observation)
    }

    fn prompt_command_environment() -> (
        TempDir,
        std::path::PathBuf,
        PromptCommandAdoptionPlan,
        PromptCommandObservation,
    ) {
        let root = tempfile::tempdir().unwrap();
        let environment = root.path().canonicalize().unwrap();
        let manifest = empty_prompt_command_manifest();
        stage_control_file(
            environment.as_path(),
            MANIFEST_PATH,
            &manifest.to_toml().unwrap(),
        );
        let observation = prompt_command_observation("Review $ARGUMENTS carefully.\n");
        let asset_id = AssetId::parse("review").unwrap();
        let PromptCommandAdoptionOutcome::Ready(plan) = plan_prompt_command_adoption(
            &observation,
            &asset_id,
            &manifest,
            &prompt_command_capabilities(),
        )
        .unwrap() else {
            panic!("portable prompt command must produce a ready plan");
        };
        (root, environment, *plan, observation)
    }

    fn agent_environment() -> (
        TempDir,
        std::path::PathBuf,
        AgentAdoptionPlan,
        AgentObservation,
    ) {
        let root = tempfile::tempdir().unwrap();
        let environment = root.path().canonicalize().unwrap();
        let manifest = empty_agent_manifest();
        stage_control_file(
            environment.as_path(),
            MANIFEST_PATH,
            &manifest.to_toml().unwrap(),
        );
        let observation = agent_observation("Review carefully.");
        let asset_id = AssetId::parse("review").unwrap();
        let AgentAdoptionOutcome::Ready(plan) =
            plan_agent_adoption(&observation, &asset_id, &manifest, &agent_capabilities()).unwrap()
        else {
            panic!("portable agent must produce a ready plan")
        };
        (root, environment, *plan, observation)
    }

    fn mcp_environment() -> (
        TempDir,
        std::path::PathBuf,
        McpAdoptionPlan,
        McpDocumentObservation,
    ) {
        let root = tempfile::tempdir().unwrap();
        let environment = root.path().canonicalize().unwrap();
        let manifest = empty_mcp_manifest();
        stage_control_file(
            environment.as_path(),
            MANIFEST_PATH,
            &manifest.to_toml().unwrap(),
        );
        let observation = mcp_observation(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com/mcp"}}}"#,
        );
        let selected = observation.parsed().unwrap().entries()[0]
            .exact_entry_hash()
            .clone();
        let asset_id = AssetId::parse("company-docs").unwrap();
        let McpAdoptionOutcome::Ready(plan) = plan_mcp_adoption(
            &observation,
            &selected,
            &asset_id,
            None,
            &manifest,
            &mcp_capabilities(),
        )
        .unwrap() else {
            panic!("portable MCP entry must produce a ready plan")
        };
        (root, environment, *plan, observation)
    }

    fn mcp_update_environment() -> (
        TempDir,
        std::path::PathBuf,
        McpUpdatePlan,
        McpDocumentObservation,
    ) {
        let (root, environment, adoption, original) = mcp_environment();
        commit_mcp_adoption(&adoption, &original, &environment, CaptureLimits::default()).unwrap();
        let manifest = adoption.proposed_manifest().clone();
        let manifest_text = fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap();
        let lock_text = fs::read_to_string(environment.join(LOCK_PATH)).unwrap();
        let changed = mcp_observation(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://new.example.com/mcp"}}}"#,
        );
        let selected = changed.parsed().unwrap().entries()[0]
            .exact_entry_hash()
            .clone();
        let expected_prior = manifest.assets[&adoption.asset().id].content_hash.clone();
        let update = plan_mcp_update(
            &changed,
            &selected,
            &adoption.asset().id,
            &expected_prior,
            None,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &mcp_capabilities(),
        )
        .unwrap();
        (root, environment, update, changed)
    }

    fn agent_update_environment() -> (
        TempDir,
        std::path::PathBuf,
        AgentUpdatePlan,
        AgentObservation,
    ) {
        let (root, environment, adoption, original) = agent_environment();
        commit_agent_adoption(&adoption, &original, &environment, CaptureLimits::default())
            .unwrap();
        let manifest = adoption.proposed_manifest().clone();
        let manifest_text = fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap();
        let lock_text = fs::read_to_string(environment.join(LOCK_PATH)).unwrap();
        let changed = agent_observation("Review every file carefully.");
        let expected_prior = manifest.assets[&adoption.asset().id].content_hash.clone();
        let update = plan_agent_update(
            &changed,
            &adoption.asset().id,
            &expected_prior,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &agent_capabilities(),
        )
        .unwrap();
        (root, environment, update, changed)
    }

    #[test]
    fn agent_adoption_commits_and_verifies_both_objects() {
        let (_root, environment, plan, observation) = agent_environment();
        assert_eq!(
            commit_agent_adoption(&plan, &observation, &environment, CaptureLimits::default())
                .unwrap(),
            AdoptionCommitOutcome::Committed
        );
        let asset_id = &plan.asset().id;
        assert_eq!(
            load_portable_agent_object(
                plan.proposed_manifest(),
                asset_id,
                &environment,
                CaptureLimits::default()
            )
            .unwrap(),
            *plan.portable_object()
        );
        assert_eq!(
            load_native_agent_object(
                plan.proposed_manifest(),
                asset_id,
                observation.harness(),
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *plan.native_object()
        );
    }

    #[test]
    fn mcp_adoption_commits_and_recovers_both_verified_objects() {
        let (_root, environment, plan, observation) = mcp_environment();
        assert_eq!(
            commit_mcp_adoption(&plan, &observation, &environment, CaptureLimits::default())
                .unwrap(),
            AdoptionCommitOutcome::Committed
        );
        let asset_id = &plan.asset().id;
        assert_eq!(
            load_portable_mcp_object(
                plan.proposed_manifest(),
                asset_id,
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *plan.portable_object()
        );
        assert_eq!(
            load_native_mcp_object(
                plan.proposed_manifest(),
                asset_id,
                observation.harness(),
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *plan.native_object()
        );
        let mut mismatched = plan.proposed_manifest().clone();
        let asset = mismatched.assets.get_mut(asset_id).unwrap();
        let mut native = asset.native_variants.remove(observation.harness()).unwrap();
        native.harness = HarnessId::Codex;
        asset.native_variants.insert(HarnessId::Codex, native);
        asset.refresh_content_hash();
        mismatched.validate().unwrap();
        assert!(
            load_native_mcp_object(
                &mismatched,
                asset_id,
                &HarnessId::Codex,
                &environment,
                CaptureLimits::default(),
            )
            .is_err()
        );

        let (_root, environment, plan, observation) = mcp_environment();
        assert_eq!(
            commit_mcp_adoption_inner(
                &plan,
                &observation,
                &environment,
                CaptureLimits::default(),
                Some(JournalPhase::ManifestCommitted),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::CompletedCommitted
        );
        assert!(
            inspect_portable_environment(&environment, CaptureLimits::default())
                .unwrap()
                .is_clean()
        );
    }

    #[test]
    fn mcp_update_commits_and_recovers_without_local_receipt_state() {
        let (_root, environment, update, changed) = mcp_update_environment();
        assert_eq!(
            commit_mcp_update(&update, &changed, &environment, CaptureLimits::default()).unwrap(),
            UpdateCommitOutcome::CommittedWithoutReceipt
        );
        assert_eq!(
            load_portable_mcp_object(
                update.proposed_manifest(),
                &update.asset().id,
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *update.portable_object()
        );

        let (_root, environment, update, changed) = mcp_update_environment();
        assert_eq!(
            commit_mcp_update_inner(
                &update,
                &changed,
                &environment,
                CaptureLimits::default(),
                Some(JournalPhase::ManifestCommitted),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::CompletedCommitted
        );
        assert!(
            inspect_portable_environment(&environment, CaptureLimits::default())
                .unwrap()
                .is_clean()
        );
    }

    #[test]
    fn agent_update_commits_without_local_receipt_state() {
        let (_root, environment, update, changed) = agent_update_environment();

        assert_eq!(
            commit_agent_update(&update, &changed, &environment, CaptureLimits::default()).unwrap(),
            UpdateCommitOutcome::CommittedWithoutReceipt
        );
        assert_eq!(
            load_portable_agent_object(
                update.proposed_manifest(),
                &update.asset().id,
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *update.portable_object()
        );
    }

    #[test]
    fn agent_update_recovery_discards_or_completes_from_exact_journal() {
        for (phase, expected) in [
            (
                JournalPhase::ObjectsInstalled,
                PortableRecoveryOutcome::DiscardedUncommitted,
            ),
            (
                JournalPhase::ManifestCommitted,
                PortableRecoveryOutcome::CompletedCommitted,
            ),
        ] {
            let (_root, environment, update, changed) = agent_update_environment();
            assert_eq!(
                commit_agent_update_inner(
                    &update,
                    &changed,
                    &environment,
                    CaptureLimits::default(),
                    Some(phase),
                )
                .unwrap_err()
                .code(),
                "transaction.interrupted"
            );
            assert_eq!(
                recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
                expected
            );
            let recovered_manifest = EnvironmentManifest::from_toml(
                &fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
            )
            .unwrap();
            assert!(
                verify_referenced_objects(
                    &recovered_manifest,
                    &environment,
                    CaptureLimits::default(),
                )
                .unwrap()
                .is_clean()
            );
            if expected == PortableRecoveryOutcome::CompletedCommitted {
                assert_eq!(recovered_manifest, *update.proposed_manifest());
            }
        }
    }

    #[test]
    fn agent_adoption_recovery_discards_or_completes_from_exact_journal() {
        let (_root, environment, plan, observation) = agent_environment();
        assert_eq!(
            commit_agent_adoption_inner(
                &plan,
                &observation,
                &environment,
                CaptureLimits::default(),
                Some(JournalPhase::Prepared),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::DiscardedUncommitted
        );
        assert_eq!(
            commit_agent_adoption_inner(
                &plan,
                &observation,
                &environment,
                CaptureLimits::default(),
                Some(JournalPhase::ManifestCommitted),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::CompletedCommitted
        );
        assert!(
            verify_referenced_objects(
                plan.proposed_manifest(),
                &environment,
                CaptureLimits::default(),
            )
            .unwrap()
            .is_clean()
        );
    }

    #[test]
    fn instruction_adoption_commits_objects_manifest_and_generated_lock() {
        let (_root, _source, environment, plan, observation) = instruction_environment();
        assert_eq!(
            commit_instruction_adoption(
                &plan,
                &observation,
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            AdoptionCommitOutcome::Committed
        );
        let asset_id = &plan.asset().id;
        assert_eq!(
            load_portable_instruction_object(
                plan.proposed_manifest(),
                asset_id,
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *plan.portable_object()
        );
        assert_eq!(
            load_native_instruction_object(
                plan.proposed_manifest(),
                asset_id,
                plan.origin_harness(),
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *plan.native_object()
        );
        assert!(
            inspect_portable_environment(&environment, CaptureLimits::default())
                .unwrap()
                .is_clean()
        );
    }

    #[test]
    fn prompt_command_adoption_commits_and_verifies_both_objects() {
        let (_root, environment, plan, observation) = prompt_command_environment();
        let asset_id = &plan.asset().id;

        assert_eq!(
            commit_prompt_command_adoption(
                &plan,
                &observation,
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            AdoptionCommitOutcome::Committed
        );
        assert_eq!(
            load_portable_prompt_command_object(
                plan.proposed_manifest(),
                asset_id,
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *plan.portable_object()
        );
        assert_eq!(
            load_native_prompt_command_object(
                plan.proposed_manifest(),
                asset_id,
                observation.harness(),
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *plan.native_object()
        );
        assert!(
            verify_referenced_objects(
                plan.proposed_manifest(),
                &environment,
                CaptureLimits::default(),
            )
            .unwrap()
            .is_clean()
        );
    }

    #[test]
    fn prompt_command_adoption_recovery_discards_or_completes_from_exact_journal() {
        let (_root, environment, plan, observation) = prompt_command_environment();
        assert_eq!(
            commit_prompt_command_adoption_inner(
                &plan,
                &observation,
                &environment,
                CaptureLimits::default(),
                Some(JournalPhase::Prepared),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::DiscardedUncommitted
        );
        assert_eq!(
            commit_prompt_command_adoption_inner(
                &plan,
                &observation,
                &environment,
                CaptureLimits::default(),
                Some(JournalPhase::ManifestCommitted),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::CompletedCommitted
        );
        assert!(
            inspect_portable_environment(&environment, CaptureLimits::default())
                .unwrap()
                .is_clean()
        );
    }

    fn committed_prompt_command_update() -> (
        TempDir,
        std::path::PathBuf,
        PromptCommandUpdatePlan,
        PromptCommandObservation,
    ) {
        let (root, environment, adoption, original) = prompt_command_environment();
        commit_prompt_command_adoption(
            &adoption,
            &original,
            &environment,
            CaptureLimits::default(),
        )
        .unwrap();
        let manifest_text = fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap();
        let manifest = EnvironmentManifest::from_toml(&manifest_text).unwrap();
        let lock_text = fs::read_to_string(environment.join(LOCK_PATH)).unwrap();
        let changed = prompt_command_observation("Review every file in $ARGUMENTS.\n");
        let plan = plan_prompt_command_update(
            &changed,
            &adoption.asset().id,
            &adoption.asset().content_hash,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &prompt_command_capabilities(),
        )
        .unwrap();
        (root, environment, plan, changed)
    }

    #[test]
    fn prompt_command_update_commits_without_local_receipt_state() {
        let (_root, environment, plan, changed) = committed_prompt_command_update();
        assert_eq!(
            commit_prompt_command_update(&plan, &changed, &environment, CaptureLimits::default(),)
                .unwrap(),
            UpdateCommitOutcome::CommittedWithoutReceipt
        );
        assert_eq!(
            load_portable_prompt_command_object(
                plan.proposed_manifest(),
                &plan.asset().id,
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            *plan.portable_object()
        );
        assert!(
            inspect_portable_environment(&environment, CaptureLimits::default())
                .unwrap()
                .is_clean()
        );
    }

    #[test]
    fn prompt_command_update_recovers_through_environment_only_journal() {
        let (_root, environment, plan, changed) = committed_prompt_command_update();
        assert_eq!(
            commit_prompt_command_update_inner(
                &plan,
                &changed,
                &environment,
                CaptureLimits::default(),
                Some(JournalPhase::ManifestCommitted),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::CompletedCommitted
        );
        assert!(
            inspect_portable_environment(&environment, CaptureLimits::default())
                .unwrap()
                .is_clean()
        );
    }

    #[test]
    fn stale_instruction_observation_fails_before_journal_or_object_write() {
        let (_root, _source, environment, plan, _observation) = instruction_environment();
        let (_changed_source, changed) = observed_document("Changed review policy.");
        assert_eq!(
            commit_instruction_adoption(&plan, &changed, &environment, CaptureLimits::default(),)
                .unwrap_err()
                .code(),
            "adoption.observation_stale"
        );
        assert!(!environment.join("assets").exists());
        assert!(!environment.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn instruction_adoption_recovery_discards_prepared_and_completes_committed_manifest() {
        let (_root, _source, environment, plan, observation) = instruction_environment();
        assert_eq!(
            commit_instruction_adoption_inner(
                &plan,
                &observation,
                &environment,
                CaptureLimits::default(),
                Some(JournalPhase::Prepared),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::DiscardedUncommitted
        );
        assert_eq!(
            EnvironmentManifest::from_toml(
                &fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap()
            )
            .unwrap(),
            empty_instruction_manifest()
        );

        assert_eq!(
            commit_instruction_adoption_inner(
                &plan,
                &observation,
                &environment,
                CaptureLimits::default(),
                Some(JournalPhase::ManifestCommitted),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::CompletedCommitted
        );
        assert_eq!(
            inspect_portable_environment(&environment, CaptureLimits::default())
                .unwrap()
                .manifest_revision(),
            plan.proposed_manifest_revision()
        );
    }

    #[test]
    fn every_instruction_adoption_phase_recovers_without_lock_ahead_of_manifest() {
        for phase in [
            JournalPhase::Prepared,
            JournalPhase::ObjectsInstalled,
            JournalPhase::ManifestCommitted,
            JournalPhase::LockCommitted,
            JournalPhase::Verified,
            JournalPhase::Complete,
        ] {
            let (_root, _source, environment, plan, observation) = instruction_environment();
            assert_eq!(
                commit_instruction_adoption_inner(
                    &plan,
                    &observation,
                    &environment,
                    CaptureLimits::default(),
                    Some(phase),
                )
                .unwrap_err()
                .code(),
                "transaction.interrupted"
            );
            let recovered =
                recover_portable_environment(&environment, CaptureLimits::default()).unwrap();
            if matches!(
                phase,
                JournalPhase::Prepared | JournalPhase::ObjectsInstalled
            ) {
                assert_eq!(recovered, PortableRecoveryOutcome::DiscardedUncommitted);
                assert_eq!(
                    EnvironmentManifest::from_toml(
                        &fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap()
                    )
                    .unwrap(),
                    empty_instruction_manifest()
                );
                assert!(!environment.join(LOCK_PATH).exists());
                assert!(
                    !environment
                        .join(plan.asset().portable.as_ref().unwrap().root.as_str())
                        .exists()
                );
            } else {
                assert_eq!(recovered, PortableRecoveryOutcome::CompletedCommitted);
                assert!(
                    inspect_portable_environment(&environment, CaptureLimits::default())
                        .unwrap()
                        .is_clean()
                );
            }
            assert!(!environment.join(JOURNAL_PATH).exists());
        }
    }

    struct InstructionUpdateFixture {
        _root: TempDir,
        source: TempDir,
        environment: std::path::PathBuf,
        state: std::path::PathBuf,
        prior_manifest: EnvironmentManifest,
        old_state: String,
        plan: InstructionUpdatePlan,
        reread: InstructionDocumentObservation,
    }

    fn instruction_update_environment() -> InstructionUpdateFixture {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().canonicalize().unwrap();
        let environment = canonical.join("environment");
        let state = canonical.join("state");
        fs::create_dir_all(&environment).unwrap();
        let environment = environment.canonicalize().unwrap();
        let (source, old_observation) = observed_document("Review carefully.");
        let asset_id = AssetId::parse("review").unwrap();
        let InstructionAdoptionOutcome::Ready(adoption) = plan_instruction_adoption(
            &old_observation,
            &asset_id,
            &empty_instruction_manifest(),
            &instruction_capabilities(),
        )
        .unwrap() else {
            panic!("old instruction must be adoptable");
        };
        stage_control_file(
            &environment,
            MANIFEST_PATH,
            &empty_instruction_manifest().to_toml().unwrap(),
        );
        commit_instruction_adoption(
            &adoption,
            &old_observation,
            &environment,
            CaptureLimits::default(),
        )
        .unwrap();
        let prior_manifest = adoption.proposed_manifest().clone();
        let receipt = DeploymentReceipt {
            asset_id: asset_id.clone(),
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            destination: old_observation.destination().clone(),
            target: ReceiptTarget::ManagedInstructionRegion,
            logical_key: None,
            shared_with: BTreeSet::new(),
            shared_adapter_versions: BTreeMap::new(),
            source_hash: prior_manifest.assets[&asset_id].content_hash.clone(),
            rendered_hash: old_observation
                .region(&asset_id)
                .unwrap()
                .exact_region_hash()
                .clone(),
            document_hash: None,
            prior_hash: None,
            adapter_version: "test-claude/1".to_owned(),
            environment_revision: derive_manifest_revision(&prior_manifest).unwrap(),
        };
        let receipt_id = receipt.receipt_id().unwrap();
        let local_state = LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("instruction-update-transaction").unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::new(),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::new(),
            receipts: BTreeMap::from([(receipt_id.clone(), receipt)]),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: Vec::new(),
        };
        let old_state = local_state.to_json().unwrap();
        crate::test_authority::initialize_private_state(&state, &local_state).unwrap();
        let state = state.canonicalize().unwrap();
        fs::write(
            source.path().join("CLAUDE.md"),
            "User preface.\n<!-- kitrove:instruction review begin -->\nReview more carefully.\n<!-- kitrove:instruction review end -->\n",
        )
        .unwrap();
        let reread = observe_instruction_document(
            &source.path().canonicalize().unwrap(),
            old_observation.policy(),
            InstructionLimits::default(),
        )
        .unwrap();
        let region = reread.region(&asset_id).unwrap();
        let entry = InstructionScanEntry {
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            policy_line: PolicyLine::ClaudeCurrent,
            destination: reread.destination().clone(),
            asset_id: asset_id.clone(),
            observation_revision: Some(region.observation_revision().clone()),
            exact_region_hash: Some(region.exact_region_hash().clone()),
            receipt_id: Some(receipt_id),
            classification: crate::ScanClassification::ManagedModified,
            findings: Vec::new(),
        };
        let mut report = ScanReport::new(
            ScanMode::Classified,
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CaptureUsage::default(),
        );
        report.set_instructions(vec![entry], vec![reread.clone()], CaptureUsage::default());
        let selected = report
            .select_instruction_update_source(
                region.observation_revision(),
                &asset_id,
                Some(&old_state),
            )
            .unwrap();
        let manifest_text = prior_manifest.to_toml().unwrap();
        let lock_text = fs::read_to_string(environment.join(LOCK_PATH)).unwrap();
        let plan = plan_instruction_update(
            &selected,
            &prior_manifest.assets[&asset_id].content_hash,
            &manifest_text,
            &prior_manifest,
            Some(&lock_text),
            &instruction_capabilities(),
        )
        .unwrap();
        InstructionUpdateFixture {
            _root: root,
            source,
            environment,
            state,
            prior_manifest,
            old_state,
            plan,
            reread,
        }
    }

    #[test]
    fn instruction_update_recovery_uses_instruction_codecs_and_receipt_authority() {
        for phase in [JournalPhase::Prepared, JournalPhase::ManifestCommitted] {
            let fixture = instruction_update_environment();
            assert_eq!(
                commit_update_authority(
                    UpdatePlanRef::Instruction(&fixture.plan),
                    UpdateObservationRef::Instruction(&fixture.reread),
                    &fixture.environment,
                    &fixture.state,
                    CaptureLimits::default(),
                    Some(phase),
                )
                .unwrap_err()
                .code(),
                "transaction.interrupted"
            );
            let recovered = recover_update_adoption(
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap();
            if phase == JournalPhase::Prepared {
                assert_eq!(recovered, UpdateRecoveryOutcome::DiscardedUncommitted);
                assert_eq!(
                    fs::read_to_string(fixture.state.join("state.json")).unwrap(),
                    fixture.old_state
                );
                assert_eq!(
                    EnvironmentManifest::from_toml(
                        &fs::read_to_string(fixture.environment.join(MANIFEST_PATH)).unwrap()
                    )
                    .unwrap(),
                    fixture.prior_manifest
                );
            } else {
                assert_eq!(recovered, UpdateRecoveryOutcome::CompletedWithReceipt);
                let state = LocalState::from_json(
                    &fs::read_to_string(fixture.state.join("state.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    state.receipts.values().next().unwrap().source_hash,
                    fixture.plan.asset().content_hash
                );
                assert!(
                    inspect_portable_environment(&fixture.environment, CaptureLimits::default())
                        .unwrap()
                        .is_clean()
                );
            }
        }
    }

    #[test]
    fn instruction_update_target_race_fails_before_journal_commit() {
        let fixture = instruction_update_environment();
        fs::write(
            fixture.source.path().join("CLAUDE.md"),
            "<!-- kitrove:instruction review begin -->\nRaced after review.\n<!-- kitrove:instruction review end -->\n",
        )
        .unwrap();

        let error = commit_instruction_update(
            &fixture.plan,
            &fixture.reread,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "update.target_stale");
        assert!(!fixture.environment.join(JOURNAL_PATH).exists());
        assert_eq!(
            fs::read_to_string(fixture.state.join("state.json")).unwrap(),
            fixture.old_state
        );
        assert_eq!(
            EnvironmentManifest::from_toml(
                &fs::read_to_string(fixture.environment.join(MANIFEST_PATH)).unwrap()
            )
            .unwrap(),
            fixture.prior_manifest
        );
    }

    struct UpdateFixture {
        _root: TempDir,
        environment: std::path::PathBuf,
        state: std::path::PathBuf,
        target: std::path::PathBuf,
        plan: UpdatePlan,
        reread: AcceptedObservedCandidate,
        old_state: String,
        prior_manifest: EnvironmentManifest,
    }

    fn update_environment() -> UpdateFixture {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().canonicalize().unwrap();
        let environment = canonical.join("environment");
        let state = canonical.join("state");
        let target = canonical.join("target");
        fs::create_dir_all(&environment).unwrap();
        fs::create_dir_all(&target).unwrap();
        let environment = environment.canonicalize().unwrap();
        let target = target.canonicalize().unwrap();
        let destination = normalized_test_destination(&target);
        let (prior_plan, prior_candidate, empty_manifest) = ready_plan();
        stage_control_file(
            &environment,
            MANIFEST_PATH,
            &empty_manifest.to_toml().unwrap(),
        );
        assert_eq!(
            commit_adoption(
                &prior_plan,
                &prior_candidate,
                &environment,
                CaptureLimits::default(),
            )
            .unwrap(),
            AdoptionCommitOutcome::Committed
        );
        let (source, manifest, lock_text, prior_hash, capabilities) =
            managed_update_fixture_at(destination);
        assert_eq!(manifest, *prior_plan.proposed_manifest());
        for (relative, file) in &source.selected().captured().exact.files {
            let path = target.join(relative.as_str());
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, &file.bytes).unwrap();
        }
        let old_state = source.observed_local_state_text().unwrap().to_owned();
        stage_control_file(&environment, MANIFEST_PATH, &manifest.to_toml().unwrap());
        stage_control_file(&environment, LOCK_PATH, &lock_text);
        let local_state = LocalState::from_json(&old_state).unwrap();
        crate::test_authority::initialize_private_state(&state, &local_state).unwrap();
        let state = state.canonicalize().unwrap();
        let objects = VerifiedSkillObjectCatalog::new(
            Vec::<StoredSkillTree>::new(),
            Vec::<NativeSkillObject>::new(),
        )
        .unwrap();
        let plan = plan_update_adoption(
            &source,
            &prior_hash,
            &manifest.to_toml().unwrap(),
            &manifest,
            Some(&lock_text),
            &objects,
            &capabilities,
            SyncLimits::default(),
        )
        .unwrap();
        let reread = source.selected().clone();
        UpdateFixture {
            _root: root,
            environment,
            state,
            target,
            plan,
            reread,
            old_state,
            prior_manifest: manifest,
        }
    }

    fn assert_prior_objects_preserved(fixture: &UpdateFixture) {
        for (asset_id, asset) in &fixture.prior_manifest.assets {
            if asset.portable.is_some() {
                load_portable_skill_object(
                    &fixture.prior_manifest,
                    asset_id,
                    &fixture.environment,
                    CaptureLimits::default(),
                )
                .unwrap();
            }
            for harness in asset.native_variants.keys() {
                load_native_skill_object(
                    &fixture.prior_manifest,
                    asset_id,
                    harness,
                    &fixture.environment,
                    CaptureLimits::default(),
                )
                .unwrap();
            }
        }
    }

    fn normalized_test_destination(path: &std::path::Path) -> NormalizedDestination {
        let encoded = path.to_str().unwrap();
        let encoded = encoded
            .strip_prefix(r"\\?\")
            .filter(|stripped| {
                let bytes = stripped.as_bytes();
                bytes.len() >= 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && matches!(bytes[2], b'/' | b'\\')
            })
            .unwrap_or(encoded);
        NormalizedDestination::parse(encoded).unwrap()
    }

    #[test]
    fn adoption_commits_objects_then_manifest_then_generated_lock() {
        let (root, environment_root, plan, candidate) = environment();
        let outcome = commit_adoption(
            &plan,
            &candidate,
            &environment_root,
            CaptureLimits::default(),
        )
        .unwrap();

        assert_eq!(outcome, AdoptionCommitOutcome::Committed);
        let manifest = EnvironmentManifest::from_toml(
            &fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest, *plan.proposed_manifest());
        assert_eq!(
            compare_lockfile(
                &manifest,
                Some(&fs::read_to_string(root.path().join(LOCK_PATH)).unwrap())
            )
            .unwrap()
            .status(),
            LockStatus::InSync
        );
        assert!(
            verify_referenced_objects(&manifest, &environment_root, CaptureLimits::default())
                .unwrap()
                .is_clean()
        );
        assert!(!root.path().join(JOURNAL_PATH).exists());
        assert!(!root.path().join(".kitrove/staging").exists());
        assert_eq!(
            inspect_portable_journal(&environment_root).unwrap(),
            PortableJournalStatus::Absent
        );
        let status =
            inspect_portable_environment(&environment_root, CaptureLimits::default()).unwrap();
        assert!(status.is_clean());
        assert_eq!(
            status.manifest_revision(),
            plan.proposed_manifest_revision()
        );
        assert_eq!(
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::NoJournal
        );
    }

    #[test]
    fn update_commits_new_authority_and_rebases_exact_receipt() {
        let fixture = update_environment();
        let outcome = commit_update_adoption(
            &fixture.plan,
            &fixture.reread,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(outcome, UpdateCommitOutcome::CommittedWithReceipt);
        let manifest = EnvironmentManifest::from_toml(
            &fs::read_to_string(fixture.environment.join(MANIFEST_PATH)).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest, *fixture.plan.proposed_manifest());
        assert_eq!(
            fs::read_to_string(fixture.state.join("state.json")).unwrap(),
            fixture.plan.proposed_local_state_text().unwrap()
        );
        assert!(
            verify_referenced_objects(&manifest, &fixture.environment, CaptureLimits::default())
                .unwrap()
                .is_clean()
        );
        assert!(!fixture.environment.join(JOURNAL_PATH).exists());
    }

    #[cfg(unix)]
    #[test]
    fn update_commit_reclaims_retained_state_from_both_locked_roots() {
        let fixture = update_environment();
        let environment_obsolete = PortablePath::parse("obsolete-environment-control").unwrap();
        let state_obsolete = PortablePath::parse("obsolete-state-control").unwrap();
        fs::write(
            fixture.environment.join(environment_obsolete.as_str()),
            "retained",
        )
        .unwrap();
        fs::write(fixture.state.join(state_obsolete.as_str()), "retained").unwrap();
        let environment_store = ObjectStore::open(&fixture.environment).unwrap();
        {
            let _lock = environment_store.try_lock_environment().unwrap();
            environment_store
                .remove_regular_file_if_present(&environment_obsolete)
                .unwrap();
        }
        let state_store = ObjectStore::open_private_state_for_mutation(&fixture.state).unwrap();
        {
            let _lock = state_store.try_lock_environment().unwrap();
            state_store
                .remove_regular_file_if_present(&state_obsolete)
                .unwrap();
        }
        let retained = [&fixture.environment, &fixture.state].map(|root| {
            let quarantine = root.join(".kitrove/removal-quarantine");
            let names = fs::read_dir(&quarantine)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            assert!(!names.is_empty());
            (quarantine, names)
        });

        assert_eq!(
            commit_update_adoption(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap(),
            UpdateCommitOutcome::CommittedWithReceipt
        );

        for (quarantine, names) in retained {
            for name in names {
                assert!(!quarantine.join(name).exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_state_quarantine_blocks_update_commit_before_authority_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = update_environment();
        let manifest_before = fs::read(fixture.environment.join(MANIFEST_PATH)).unwrap();
        let lock_before = fs::read(fixture.environment.join(LOCK_PATH)).unwrap();
        let state_before = fs::read(fixture.state.join("state.json")).unwrap();
        let control = fixture.state.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir_all(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

        let error = commit_update_adoption(
            &fixture.plan,
            &fixture.reread,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "transaction.cleanup_failed");
        assert_eq!(
            fs::read(fixture.environment.join(MANIFEST_PATH)).unwrap(),
            manifest_before
        );
        assert_eq!(
            fs::read(fixture.environment.join(LOCK_PATH)).unwrap(),
            lock_before
        );
        assert_eq!(
            fs::read(fixture.state.join("state.json")).unwrap(),
            state_before
        );
        assert!(!fixture.environment.join(JOURNAL_PATH).exists());
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_state_quarantine_blocks_update_recovery_before_reconciliation() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = update_environment();
        assert_eq!(
            commit_update_adoption_inner(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(JournalPhase::Prepared),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        let journal_path = fixture.environment.join(JOURNAL_PATH);
        let journal_before = fs::read(&journal_path).unwrap();
        let journal: PortableJournal = serde_json::from_slice(&journal_before).unwrap();
        let manifest_before = fs::read(fixture.environment.join(MANIFEST_PATH)).unwrap();
        let lock_before = fs::read(fixture.environment.join(LOCK_PATH)).unwrap();
        let state_before = fs::read(fixture.state.join("state.json")).unwrap();
        let staged_manifest_before = fs::read(
            fixture
                .environment
                .join(journal.staging_manifest.as_ref().unwrap().as_str()),
        )
        .unwrap();
        let staged_lock_before =
            fs::read(fixture.environment.join(journal.staging_lock.as_str())).unwrap();
        let staged_state_path = fixture
            .state
            .join(journal.staging_state.as_ref().unwrap().as_str());
        let staged_state_before = fs::read(&staged_state_path).unwrap();
        let control = fixture.state.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir_all(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

        let error = recover_update_adoption(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "transaction.cleanup_failed");
        assert_eq!(fs::read(journal_path).unwrap(), journal_before);
        assert_eq!(
            fs::read(fixture.environment.join(MANIFEST_PATH)).unwrap(),
            manifest_before
        );
        assert_eq!(
            fs::read(fixture.environment.join(LOCK_PATH)).unwrap(),
            lock_before
        );
        assert_eq!(
            fs::read(fixture.state.join("state.json")).unwrap(),
            state_before
        );
        assert_eq!(
            fs::read(
                fixture
                    .environment
                    .join(journal.staging_manifest.as_ref().unwrap().as_str())
            )
            .unwrap(),
            staged_manifest_before
        );
        assert_eq!(
            fs::read(fixture.environment.join(journal.staging_lock.as_str())).unwrap(),
            staged_lock_before
        );
        assert_eq!(fs::read(staged_state_path).unwrap(), staged_state_before);
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[test]
    fn explicit_root_update_commits_without_creating_local_state() {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().canonicalize().unwrap();
        let environment = canonical.join("environment");
        let state = canonical.join("state");
        fs::create_dir_all(&environment).unwrap();
        crate::test_authority::initialize_empty_private_root(&state).unwrap();
        let environment = environment.canonicalize().unwrap();
        let state = state.canonicalize().unwrap();
        let (source, manifest, lock_text, prior_hash, capabilities) = explicit_update_fixture();
        stage_control_file(&environment, MANIFEST_PATH, &manifest.to_toml().unwrap());
        stage_control_file(&environment, LOCK_PATH, &lock_text);
        let objects = VerifiedSkillObjectCatalog::new(
            Vec::<StoredSkillTree>::new(),
            Vec::<NativeSkillObject>::new(),
        )
        .unwrap();
        let plan = plan_update_adoption(
            &source,
            &prior_hash,
            &manifest.to_toml().unwrap(),
            &manifest,
            Some(&lock_text),
            &objects,
            &capabilities,
            SyncLimits::default(),
        )
        .unwrap();

        assert_eq!(
            commit_update_adoption(
                &plan,
                source.selected(),
                &environment,
                &state,
                CaptureLimits::default(),
            )
            .unwrap(),
            UpdateCommitOutcome::Committed
        );
        assert!(!state.join("state.json").exists());
        let committed = EnvironmentManifest::from_toml(
            &fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
        )
        .unwrap();
        assert_eq!(committed, *plan.proposed_manifest());
    }

    #[test]
    fn every_update_phase_recovers_without_false_receipt_ownership() {
        for phase in [
            JournalPhase::Prepared,
            JournalPhase::ObjectsInstalled,
            JournalPhase::ManifestCommitted,
            JournalPhase::LockCommitted,
            JournalPhase::StateCommitted,
            JournalPhase::Verified,
            JournalPhase::Complete,
        ] {
            let fixture = update_environment();
            let error = commit_update_adoption_inner(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(phase),
            )
            .unwrap_err();
            assert_eq!(error.code(), "transaction.interrupted");
            let journal = fs::read_to_string(fixture.environment.join(JOURNAL_PATH)).unwrap();
            assert!(!journal.contains(fixture.target.to_str().unwrap()));
            assert!(!journal.contains("Inspect the newest change"));
            assert_eq!(
                recover_portable_environment(&fixture.environment, CaptureLimits::default())
                    .unwrap_err()
                    .code(),
                "transaction.update_recovery_required"
            );

            let recovered = recover_update_adoption(
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap();
            if matches!(
                phase,
                JournalPhase::Prepared | JournalPhase::ObjectsInstalled
            ) {
                assert_eq!(recovered, UpdateRecoveryOutcome::DiscardedUncommitted);
                assert_eq!(
                    fs::read_to_string(fixture.state.join("state.json")).unwrap(),
                    fixture.old_state
                );
            } else {
                assert_eq!(recovered, UpdateRecoveryOutcome::CompletedWithReceipt);
                assert_eq!(
                    fs::read_to_string(fixture.state.join("state.json")).unwrap(),
                    fixture.plan.proposed_local_state_text().unwrap()
                );
            }
            assert!(!fixture.environment.join(JOURNAL_PATH).exists());
            assert_prior_objects_preserved(&fixture);
        }
    }

    #[test]
    fn every_explicit_root_update_phase_recovers_without_local_state() {
        for phase in [
            JournalPhase::Prepared,
            JournalPhase::ObjectsInstalled,
            JournalPhase::ManifestCommitted,
            JournalPhase::LockCommitted,
            JournalPhase::Verified,
            JournalPhase::Complete,
        ] {
            let root = tempfile::tempdir().unwrap();
            let canonical = root.path().canonicalize().unwrap();
            let environment = canonical.join("environment");
            let state = canonical.join("state");
            fs::create_dir_all(&environment).unwrap();
            crate::test_authority::initialize_empty_private_root(&state).unwrap();
            let environment = environment.canonicalize().unwrap();
            let state = state.canonicalize().unwrap();
            let (source, manifest, lock_text, prior_hash, capabilities) = explicit_update_fixture();
            let manifest_text = manifest.to_toml().unwrap();
            stage_control_file(&environment, MANIFEST_PATH, &manifest_text);
            stage_control_file(&environment, LOCK_PATH, &lock_text);
            let objects = VerifiedSkillObjectCatalog::new(
                Vec::<StoredSkillTree>::new(),
                Vec::<NativeSkillObject>::new(),
            )
            .unwrap();
            let plan = plan_update_adoption(
                &source,
                &prior_hash,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &objects,
                &capabilities,
                SyncLimits::default(),
            )
            .unwrap();

            assert_eq!(
                commit_update_adoption_inner(
                    &plan,
                    source.selected(),
                    &environment,
                    &state,
                    CaptureLimits::default(),
                    Some(phase),
                )
                .unwrap_err()
                .code(),
                "transaction.interrupted"
            );
            assert_eq!(
                recover_update_adoption(&environment, &state, CaptureLimits::default()).unwrap(),
                if matches!(
                    phase,
                    JournalPhase::Prepared | JournalPhase::ObjectsInstalled
                ) {
                    UpdateRecoveryOutcome::DiscardedUncommitted
                } else {
                    UpdateRecoveryOutcome::Completed
                }
            );
            assert!(!state.join("state.json").exists());
            assert!(!environment.join(JOURNAL_PATH).exists());
            let recovered = EnvironmentManifest::from_toml(
                &fs::read_to_string(environment.join(MANIFEST_PATH)).unwrap(),
            )
            .unwrap();
            assert_eq!(
                recovered,
                if matches!(
                    phase,
                    JournalPhase::Prepared | JournalPhase::ObjectsInstalled
                ) {
                    manifest.clone()
                } else {
                    plan.proposed_manifest().clone()
                }
            );
        }
    }

    #[test]
    fn post_manifest_target_race_completes_without_advancing_receipt() {
        for phase in [JournalPhase::ManifestCommitted, JournalPhase::LockCommitted] {
            let fixture = update_environment();
            let error = commit_update_adoption_inner(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(phase),
            )
            .unwrap_err();
            assert_eq!(error.code(), "transaction.interrupted");
            fs::write(
                fixture.target.join("SKILL.md"),
                b"---\nname: review\ndescription: Review code carefully\n---\nConcurrent edit.\n",
            )
            .unwrap();

            assert_eq!(
                recover_update_adoption(
                    &fixture.environment,
                    &fixture.state,
                    CaptureLimits::default(),
                )
                .unwrap(),
                UpdateRecoveryOutcome::CompletedWithoutReceipt
            );
            assert_eq!(
                fs::read_to_string(fixture.state.join("state.json")).unwrap(),
                fixture.old_state
            );
            let manifest = EnvironmentManifest::from_toml(
                &fs::read_to_string(fixture.environment.join(MANIFEST_PATH)).unwrap(),
            )
            .unwrap();
            assert_eq!(manifest, *fixture.plan.proposed_manifest());
        }
    }

    #[test]
    fn pre_manifest_target_race_discards_update_without_changing_authority() {
        let fixture = update_environment();
        assert_eq!(
            commit_update_adoption_inner(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(JournalPhase::ObjectsInstalled),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        fs::write(
            fixture.target.join("SKILL.md"),
            b"---\nname: review\ndescription: Review code carefully\n---\nConcurrent edit.\n",
        )
        .unwrap();
        assert_eq!(
            recover_update_adoption(
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap(),
            UpdateRecoveryOutcome::DiscardedUncommitted
        );
        assert_eq!(
            commit_update_adoption(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "update.target_stale"
        );
        assert_eq!(
            fs::read_to_string(fixture.state.join("state.json")).unwrap(),
            fixture.old_state
        );
        let manifest = EnvironmentManifest::from_toml(
            &fs::read_to_string(fixture.environment.join(MANIFEST_PATH)).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest, fixture.prior_manifest);
    }

    #[test]
    fn forged_staged_local_state_cannot_acquire_receipt_authority() {
        let fixture = update_environment();
        assert_eq!(
            commit_update_adoption_inner(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(JournalPhase::ManifestCommitted),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        let journal_path = fixture.environment.join(JOURNAL_PATH);
        let mut journal: PortableJournal =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        let staging = journal.staging_state.as_ref().unwrap();
        let staging_path = fixture.state.join(staging.as_str());
        let mut forged =
            LocalState::from_json(&fs::read_to_string(&staging_path).unwrap()).unwrap();
        forged.machine.active_profile = Some(ProfileId::parse("hostile").unwrap());
        let forged_text = forged.to_json().unwrap();
        fs::write(&staging_path, &forged_text).unwrap();
        journal.new_state_hash = Some(ContentHash::digest(forged_text.as_bytes()));
        let mut encoded = serde_json::to_string_pretty(&journal).unwrap();
        encoded.push('\n');
        fs::write(journal_path, encoded).unwrap();

        assert_eq!(
            recover_update_adoption(
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "transaction.recovery_blocked"
        );
        assert_eq!(
            fs::read_to_string(fixture.state.join("state.json")).unwrap(),
            fixture.old_state
        );
    }

    #[test]
    fn corrupt_post_commit_state_staging_never_replaces_live_state() {
        let fixture = update_environment();
        assert_eq!(
            commit_update_adoption_inner(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(JournalPhase::StateCommitted),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        let journal: PortableJournal = serde_json::from_str(
            &fs::read_to_string(fixture.environment.join(JOURNAL_PATH)).unwrap(),
        )
        .unwrap();
        let staging = journal.staging_state.as_ref().unwrap();
        crate::test_authority::stage_private_text(
            &fixture.state,
            staging.as_str(),
            "hostile staging bytes",
        )
        .unwrap();
        let live_before = fs::read(fixture.state.join("state.json")).unwrap();

        assert_eq!(
            recover_update_adoption(
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "transaction.recovery_blocked"
        );
        assert_eq!(
            fs::read(fixture.state.join("state.json")).unwrap(),
            live_before
        );
    }

    #[test]
    fn semantically_equal_manifest_edit_is_stale_before_update_staging() {
        let fixture = update_environment();
        let manifest_path = fixture.environment.join(MANIFEST_PATH);
        let original = fs::read_to_string(&manifest_path).unwrap();
        let changed = format!("# concurrent authored comment\n{original}");
        fs::write(&manifest_path, &changed).unwrap();

        assert_eq!(
            commit_update_adoption(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "adoption.manifest_stale"
        );
        assert_eq!(fs::read_to_string(manifest_path).unwrap(), changed);
        assert!(!fixture.environment.join(JOURNAL_PATH).exists());
        assert_eq!(
            fs::read_to_string(fixture.state.join("state.json")).unwrap(),
            fixture.old_state
        );
    }

    #[test]
    fn changed_observation_is_stale_before_update_staging() {
        let fixture = update_environment();
        let changed = with_changed_document_bytes(&fixture.reread);
        assert_eq!(
            commit_update_adoption(
                &fixture.plan,
                &changed,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "adoption.observation_stale"
        );
        assert_eq!(
            EnvironmentManifest::from_toml(
                &fs::read_to_string(fixture.environment.join(MANIFEST_PATH)).unwrap(),
            )
            .unwrap(),
            fixture.prior_manifest
        );
        assert_eq!(
            fs::read_to_string(fixture.state.join("state.json")).unwrap(),
            fixture.old_state
        );
        assert!(!fixture.environment.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn changed_lock_is_stale_before_update_staging() {
        let fixture = update_environment();
        let lock_path = fixture.environment.join(LOCK_PATH);
        let changed = format!("{}\n", fs::read_to_string(&lock_path).unwrap());
        fs::write(&lock_path, &changed).unwrap();
        assert_eq!(
            commit_update_adoption(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "adoption.manifest_stale"
        );
        assert_eq!(fs::read_to_string(lock_path).unwrap(), changed);
        assert!(!fixture.environment.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn changed_local_state_is_stale_before_update_staging() {
        let fixture = update_environment();
        let state_path = fixture.state.join("state.json");
        let mut changed = LocalState::from_json(&fixture.old_state).unwrap();
        changed.machine.active_profile = Some(ProfileId::parse("concurrent").unwrap());
        let changed_text = changed.to_json().unwrap();
        fs::write(&state_path, &changed_text).unwrap();
        assert_eq!(
            commit_update_adoption(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "update.local_state_stale"
        );
        assert_eq!(fs::read_to_string(state_path).unwrap(), changed_text);
        assert!(!fixture.environment.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn journal_cannot_redirect_update_state_staging() {
        let fixture = update_environment();
        assert_eq!(
            commit_update_adoption_inner(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(JournalPhase::Prepared),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        let journal_path = fixture.environment.join(JOURNAL_PATH);
        let mut journal: PortableJournal =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        journal.staging_state =
            Some(PortablePath::parse(".kitrove/update-staging/redirected-state.json").unwrap());
        let mut encoded = serde_json::to_string_pretty(&journal).unwrap();
        encoded.push('\n');
        fs::write(&journal_path, encoded).unwrap();
        let live_before = fs::read(fixture.state.join("state.json")).unwrap();

        assert_eq!(
            recover_update_adoption(
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "transaction.journal_invalid"
        );
        assert_eq!(
            fs::read(fixture.state.join("state.json")).unwrap(),
            live_before
        );
    }

    #[test]
    fn update_journal_redacts_all_review_canaries() {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().canonicalize().unwrap();
        let environment = canonical.join("environment");
        let state = canonical.join("state");
        fs::create_dir_all(&environment).unwrap();
        crate::test_authority::initialize_empty_private_root(&state).unwrap();
        let environment = environment.canonicalize().unwrap();
        let state = state.canonicalize().unwrap();
        let (source, manifest, lock_text, prior_hash, capabilities) = redaction_update_fixture();
        let manifest_text = manifest.to_toml().unwrap();
        stage_control_file(&environment, MANIFEST_PATH, &manifest_text);
        stage_control_file(&environment, LOCK_PATH, &lock_text);
        let objects = VerifiedSkillObjectCatalog::new(
            Vec::<StoredSkillTree>::new(),
            Vec::<NativeSkillObject>::new(),
        )
        .unwrap();
        let plan = plan_update_adoption(
            &source,
            &prior_hash,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &objects,
            &capabilities,
            SyncLimits::default(),
        )
        .unwrap();
        assert_eq!(
            commit_update_adoption_inner(
                &plan,
                source.selected(),
                &environment,
                &state,
                CaptureLimits::default(),
                Some(JournalPhase::Prepared),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        let journal = fs::read_to_string(environment.join(JOURNAL_PATH)).unwrap();
        for canary in [
            REDACTION_AUTHORED,
            REDACTION_NATIVE_ID,
            REDACTION_PATH,
            REDACTION_DESTINATION,
            REDACTION_SECRET,
        ] {
            assert!(!journal.contains(canary), "journal disclosed {canary}");
        }
    }

    #[test]
    fn concurrent_local_state_change_blocks_recovery_and_is_preserved() {
        let fixture = update_environment();
        assert_eq!(
            commit_update_adoption_inner(
                &fixture.plan,
                &fixture.reread,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(JournalPhase::ManifestCommitted),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        let mut concurrent = LocalState::from_json(&fixture.old_state).unwrap();
        concurrent.machine.active_profile = Some(ProfileId::parse("concurrent").unwrap());
        let concurrent_text = concurrent.to_json().unwrap();
        fs::write(fixture.state.join("state.json"), &concurrent_text).unwrap();

        assert_eq!(
            recover_update_adoption(
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "transaction.recovery_blocked"
        );
        assert_eq!(
            fs::read_to_string(fixture.state.join("state.json")).unwrap(),
            concurrent_text
        );
    }

    #[test]
    fn every_interruption_recovers_without_committing_lock_ahead_of_manifest() {
        for phase in [
            JournalPhase::Prepared,
            JournalPhase::ObjectsInstalled,
            JournalPhase::ManifestCommitted,
            JournalPhase::LockCommitted,
            JournalPhase::Verified,
            JournalPhase::Complete,
        ] {
            let (root, environment_root, plan, candidate) = environment();
            let error = commit_adoption_inner(
                &plan,
                &candidate,
                &environment_root,
                CaptureLimits::default(),
                Some(phase),
            )
            .unwrap_err();
            assert_eq!(error.code(), "transaction.interrupted");
            assert!(root.path().join(JOURNAL_PATH).exists());
            assert_eq!(
                inspect_portable_journal(&environment_root).unwrap(),
                PortableJournalStatus::Pending
            );

            let recovered =
                recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap();
            match phase {
                JournalPhase::Prepared | JournalPhase::ObjectsInstalled => {
                    assert_eq!(recovered, PortableRecoveryOutcome::DiscardedUncommitted);
                    assert!(!root.path().join(LOCK_PATH).exists());
                    assert!(!root.path().join(".kitrove/staging").exists());
                    assert!(
                        !root
                            .path()
                            .join(plan.asset().portable.as_ref().unwrap().root.as_str())
                            .exists()
                    );
                    assert!(
                        !root
                            .path()
                            .join(
                                plan.asset()
                                    .native_variants
                                    .values()
                                    .next()
                                    .unwrap()
                                    .root
                                    .as_str()
                            )
                            .exists()
                    );
                    let changed = with_changed_document_bytes(&candidate);
                    let current = EnvironmentManifest::from_toml(
                        &fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
                    )
                    .unwrap();
                    let changed_plan =
                        plan_adoption(&changed, None, &current, &capabilities()).unwrap();
                    let AdoptionPlanOutcome::Ready(changed_plan) = changed_plan else {
                        panic!("changed first adoption should remain ready");
                    };
                    assert_eq!(
                        commit_adoption(
                            &changed_plan,
                            &changed,
                            &environment_root,
                            CaptureLimits::default(),
                        )
                        .unwrap(),
                        AdoptionCommitOutcome::Committed
                    );
                }
                JournalPhase::ManifestCommitted
                | JournalPhase::LockCommitted
                | JournalPhase::Verified
                | JournalPhase::Complete => {
                    assert_eq!(recovered, PortableRecoveryOutcome::CompletedCommitted);
                    let manifest = EnvironmentManifest::from_toml(
                        &fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(manifest, *plan.proposed_manifest());
                    assert_eq!(
                        compare_lockfile(
                            &manifest,
                            Some(&fs::read_to_string(root.path().join(LOCK_PATH)).unwrap())
                        )
                        .unwrap()
                        .status(),
                        LockStatus::InSync
                    );
                }
                JournalPhase::StateCommitted => {
                    panic!("adoption never enters the update-only state phase")
                }
            }
            assert!(!root.path().join(JOURNAL_PATH).exists());
        }
    }

    #[test]
    fn idempotent_adoption_repairs_missing_objects_and_lock_drift() {
        let (root, environment_root, first_plan, candidate) = environment();
        commit_adoption(
            &first_plan,
            &candidate,
            &environment_root,
            CaptureLimits::default(),
        )
        .unwrap();
        let current = first_plan.proposed_manifest().clone();
        let outcome = plan_adoption(&candidate, None, &current, &capabilities()).unwrap();
        let AdoptionPlanOutcome::Ready(repair_plan) = outcome else {
            panic!("equivalent adoption must produce a repairable plan");
        };
        let native_root = repair_plan
            .asset()
            .native_variants
            .values()
            .next()
            .unwrap()
            .root
            .as_str();
        fs::remove_dir_all(root.path().join(native_root)).unwrap();
        fs::write(root.path().join(LOCK_PATH), "{}\n").unwrap();
        let broken =
            inspect_portable_environment(&environment_root, CaptureLimits::default()).unwrap();
        assert_eq!(broken.lock_status(), LockStatus::Invalid);
        assert!(!broken.objects().is_clean());
        assert!(!broken.is_clean());

        assert_eq!(
            commit_adoption(
                &repair_plan,
                &candidate,
                &environment_root,
                CaptureLimits::default(),
            )
            .unwrap(),
            AdoptionCommitOutcome::Repaired
        );
        assert!(
            verify_referenced_objects(&current, &environment_root, CaptureLimits::default())
                .unwrap()
                .is_clean()
        );
        assert_eq!(
            compare_lockfile(
                &current,
                Some(&fs::read_to_string(root.path().join(LOCK_PATH)).unwrap())
            )
            .unwrap()
            .status(),
            LockStatus::InSync
        );
    }

    #[test]
    fn stale_observation_and_manifest_fail_before_a_journal_or_object_write() {
        let (root, environment_root, plan, candidate) = environment();
        let stale_candidate = crate::adoption::tests::make_candidate(
            kitrove_agent_skills::FileMode::Regular,
            "changed-native-id",
        );
        assert_eq!(
            commit_adoption(
                &plan,
                &stale_candidate,
                &environment_root,
                CaptureLimits::default()
            )
            .unwrap_err()
            .code(),
            "adoption.observation_stale"
        );
        assert!(!root.path().join("assets").exists());
        assert!(!root.path().join(JOURNAL_PATH).exists());

        fs::write(
            root.path().join(MANIFEST_PATH),
            plan.proposed_manifest().to_toml().unwrap(),
        )
        .unwrap();
        assert_eq!(
            inspect_portable_journal(&environment_root).unwrap(),
            PortableJournalStatus::Absent
        );
        assert_eq!(
            commit_adoption(
                &plan,
                &candidate,
                &environment_root,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
            "adoption.manifest_stale"
        );
        assert!(!root.path().join(JOURNAL_PATH).exists());
    }

    #[test]
    fn malformed_or_concurrently_diverged_journal_blocks_recovery() {
        let (root, environment_root, plan, _) = environment();
        crate::test_authority::initialize_portable_control_root(&environment_root).unwrap();
        fs::write(
            root.path().join(JOURNAL_PATH),
            r#"{"schema_version":1,"secret":"DO_NOT_ECHO"}"#,
        )
        .unwrap();
        assert_eq!(
            inspect_portable_journal(&environment_root).unwrap(),
            PortableJournalStatus::Invalid
        );
        let error =
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap_err();
        assert_eq!(error.code(), "transaction.journal_invalid");
        assert!(!format!("{error:?}").contains("DO_NOT_ECHO"));

        fs::remove_file(root.path().join(JOURNAL_PATH)).unwrap();
        let paths = transaction_paths(plan.digest()).unwrap();
        let journal = PortableJournal {
            schema_version: 2,
            operation: JournalOperation::Adopt,
            phase: JournalPhase::Prepared,
            plan_digest: plan.digest().clone(),
            old_manifest_revision: Revision::parse(format!("manifest:blake3:{}", "a".repeat(64)))
                .unwrap(),
            new_manifest_revision: Revision::parse(format!("manifest:blake3:{}", "b".repeat(64)))
                .unwrap(),
            old_manifest_hash: ContentHash::digest(b"old manifest"),
            new_manifest_hash: ContentHash::digest(b"new manifest"),
            staging_manifest: Some(paths.manifest),
            staging_lock: paths.lock,
            old_lock_hash: None,
            new_lock_hash: ContentHash::digest(b"lock"),
            portable_root: Some(portable_path("assets/review/portable").unwrap()),
            portable_hash: Some(ContentHash::digest(b"portable")),
            native_root: Some(portable_path("assets/review/native/claude").unwrap()),
            native_hash: Some(ContentHash::digest(b"native")),
            portable_preexisting: Some(false),
            native_preexisting: Some(false),
            portable_format: None,
            native_format: None,
            staging_state: None,
            old_state_hash: None,
            new_state_hash: None,
            receipt_id: None,
            reviewed_target_hash: None,
            expected_prior: None,
        };
        let mut encoded = serde_json::to_string_pretty(&journal).unwrap();
        encoded.push('\n');
        fs::write(root.path().join(JOURNAL_PATH), encoded).unwrap();
        let error =
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap_err();
        assert_eq!(error.code(), "transaction.recovery_blocked");
        assert!(root.path().join(JOURNAL_PATH).exists());
    }

    #[test]
    fn recovery_restores_a_journal_interrupted_during_identity_preserving_replacement() {
        let (root, environment_root, plan, candidate) = environment();
        assert_eq!(
            commit_adoption_inner(
                &plan,
                &candidate,
                &environment_root,
                CaptureLimits::default(),
                Some(JournalPhase::Prepared),
            )
            .unwrap_err()
            .code(),
            "transaction.interrupted"
        );
        let journal_path = root.path().join(JOURNAL_PATH);
        let pending_path = root.path().join(JOURNAL_PENDING_PATH);
        let backup_path = root.path().join(format!("{JOURNAL_PENDING_PATH}.previous"));
        let old = fs::read_to_string(&journal_path).unwrap();
        let mut next: PortableJournal = serde_json::from_str(&old).unwrap();
        next.phase = JournalPhase::ObjectsInstalled;
        let mut next_encoded = serde_json::to_string_pretty(&next).unwrap();
        next_encoded.push('\n');
        crate::test_authority::write_owned_fixture_file(&pending_path, next_encoded).unwrap();
        fs::rename(&journal_path, &backup_path).unwrap();

        assert_eq!(
            inspect_portable_journal(&environment_root).unwrap(),
            PortableJournalStatus::Pending
        );
        assert_eq!(
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::DiscardedUncommitted
        );
        assert!(!journal_path.exists());
        assert!(!pending_path.exists());
        assert!(!backup_path.exists());
        assert!(!root.path().join(".kitrove/staging").exists());
    }

    #[test]
    fn adoption_journal_cannot_redirect_digest_scoped_staging_paths() {
        let (root, environment_root, plan, candidate) = environment();
        commit_adoption_inner(
            &plan,
            &candidate,
            &environment_root,
            CaptureLimits::default(),
            Some(JournalPhase::Prepared),
        )
        .unwrap_err();
        let journal_path = root.path().join(JOURNAL_PATH);
        let mut journal: PortableJournal =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        journal.staging_manifest =
            Some(portable_path(".kitrove/staging/foreign/kitrove.toml").unwrap());
        let mut encoded = serde_json::to_string_pretty(&journal).unwrap();
        encoded.push('\n');
        fs::write(&journal_path, encoded).unwrap();

        assert_eq!(
            recover_portable_environment(&environment_root, CaptureLimits::default())
                .unwrap_err()
                .code(),
            "transaction.journal_invalid"
        );
        assert!(journal_path.exists());
    }

    #[test]
    fn instruction_journal_cannot_substitute_object_codec_authority() {
        let (_root, _source, environment, plan, observation) = instruction_environment();
        commit_instruction_adoption_inner(
            &plan,
            &observation,
            &environment,
            CaptureLimits::default(),
            Some(JournalPhase::Prepared),
        )
        .unwrap_err();
        let journal_path = environment.join(JOURNAL_PATH);
        let mut journal: PortableJournal =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        journal.native_format = Some("kitrove-native-skill-object/v1".to_owned());
        let mut encoded = serde_json::to_string_pretty(&journal).unwrap();
        encoded.push('\n');
        fs::write(&journal_path, encoded).unwrap();

        assert_eq!(
            recover_portable_environment(&environment, CaptureLimits::default())
                .unwrap_err()
                .code(),
            "transaction.journal_invalid"
        );
        assert!(journal_path.exists());
    }

    #[test]
    fn recovery_reconciles_both_manifest_replacement_crash_windows() {
        for install_new in [false, true] {
            let (root, environment_root, plan, candidate) = environment();
            commit_adoption_inner(
                &plan,
                &candidate,
                &environment_root,
                CaptureLimits::default(),
                Some(JournalPhase::ObjectsInstalled),
            )
            .unwrap_err();
            let paths = transaction_paths(plan.digest()).unwrap();
            let manifest_backup = root
                .path()
                .join(format!("{}.previous", paths.manifest.as_str()));
            fs::rename(root.path().join(MANIFEST_PATH), &manifest_backup).unwrap();
            if install_new {
                fs::rename(
                    root.path().join(paths.manifest.as_str()),
                    root.path().join(MANIFEST_PATH),
                )
                .unwrap();
            }

            let recovered =
                recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap();
            assert_eq!(
                recovered,
                if install_new {
                    PortableRecoveryOutcome::CompletedCommitted
                } else {
                    PortableRecoveryOutcome::DiscardedUncommitted
                }
            );
            assert!(root.path().join(MANIFEST_PATH).exists());
            assert!(!manifest_backup.exists());
            assert!(!root.path().join(".kitrove/staging").exists());
        }
    }

    #[test]
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    fn recovery_completes_an_atomic_manifest_exchange_interruption() {
        let (root, environment_root, plan, candidate) = environment();
        commit_adoption_inner(
            &plan,
            &candidate,
            &environment_root,
            CaptureLimits::default(),
            Some(JournalPhase::ObjectsInstalled),
        )
        .unwrap_err();
        let paths = transaction_paths(plan.digest()).unwrap();
        {
            let store = ObjectStore::open(&environment_root).unwrap();
            let _lock = store.try_lock_environment().unwrap();
            store
                .exchange_control_files(&paths.manifest, &portable_path(MANIFEST_PATH).unwrap())
                .unwrap();
        }
        assert_eq!(
            EnvironmentManifest::from_toml(
                &fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap()
            )
            .unwrap(),
            *plan.proposed_manifest()
        );

        assert_eq!(
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::CompletedCommitted
        );
        assert!(!root.path().join(".kitrove/staging").exists());
    }

    #[test]
    fn recovery_reconciles_both_existing_lock_replacement_crash_windows() {
        for install_new in [false, true] {
            let (root, environment_root, _, _) = environment();
            let manifest = EnvironmentManifest::from_toml(
                &fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
            )
            .unwrap();
            let old_lock = "drifting lock\n";
            stage_control_file(&environment_root, LOCK_PATH, old_lock);
            let plan = plan_lock_repair(&manifest, Some(old_lock)).unwrap();
            commit_lock_repair_inner(
                &plan,
                &environment_root,
                CaptureLimits::default(),
                Some(JournalPhase::Prepared),
            )
            .unwrap_err();
            let paths = transaction_paths(plan.digest()).unwrap();
            let lock_backup = root
                .path()
                .join(format!("{}.previous", paths.lock.as_str()));
            fs::rename(root.path().join(LOCK_PATH), &lock_backup).unwrap();
            if install_new {
                fs::rename(
                    root.path().join(paths.lock.as_str()),
                    root.path().join(LOCK_PATH),
                )
                .unwrap();
            }

            assert_eq!(
                recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap(),
                PortableRecoveryOutcome::CompletedCommitted
            );
            assert_eq!(
                compare_lockfile(
                    &manifest,
                    Some(&fs::read_to_string(root.path().join(LOCK_PATH)).unwrap())
                )
                .unwrap()
                .status(),
                LockStatus::InSync
            );
            assert!(!lock_backup.exists());
            assert!(!root.path().join(".kitrove/staging").exists());
        }
    }

    #[test]
    fn recovery_cleans_a_crash_between_individual_object_installs() {
        let (root, environment_root, plan, candidate) = environment();
        commit_adoption_inner(
            &plan,
            &candidate,
            &environment_root,
            CaptureLimits::default(),
            Some(JournalPhase::Prepared),
        )
        .unwrap_err();
        let paths = transaction_paths(plan.digest()).unwrap();
        let portable = plan.asset().portable.as_ref().unwrap();
        {
            let store = ObjectStore::open(&environment_root).unwrap();
            let _lock = store.try_lock_environment().unwrap();
            store
                .install_portable(
                    &paths.portable,
                    &portable.root,
                    &portable.object_hash,
                    CaptureLimits::default(),
                )
                .unwrap();
        }

        assert_eq!(
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::DiscardedUncommitted
        );
        assert!(!root.path().join(portable.root.as_str()).exists());
        assert!(!root.path().join(".kitrove/staging").exists());
    }

    #[test]
    fn abandoned_recovery_preserves_exact_objects_that_predated_the_transaction() {
        let (root, environment_root, plan, candidate) = environment();
        let paths = transaction_paths(plan.digest()).unwrap();
        let portable = plan.asset().portable.as_ref().unwrap();
        let native = plan.asset().native_variants.values().next().unwrap();
        {
            let store = ObjectStore::open(&environment_root).unwrap();
            let _lock = store.try_lock_environment().unwrap();
            store
                .stage_portable(
                    &paths.portable,
                    plan.portable_object(),
                    CaptureLimits::default(),
                )
                .unwrap();
            store
                .install_portable(
                    &paths.portable,
                    &portable.root,
                    &portable.object_hash,
                    CaptureLimits::default(),
                )
                .unwrap();
            store
                .stage_native(
                    &paths.native,
                    plan.native_object(),
                    CaptureLimits::default(),
                )
                .unwrap();
            store
                .install_native(
                    &paths.native,
                    &native.root,
                    &native.object_hash,
                    CaptureLimits::default(),
                )
                .unwrap();
            store
                .stage_portable(
                    &paths.portable,
                    plan.portable_object(),
                    CaptureLimits::default(),
                )
                .unwrap();
            store
                .stage_native(
                    &paths.native,
                    plan.native_object(),
                    CaptureLimits::default(),
                )
                .unwrap();
        }
        commit_adoption_inner(
            &plan,
            &candidate,
            &environment_root,
            CaptureLimits::default(),
            Some(JournalPhase::ObjectsInstalled),
        )
        .unwrap_err();

        assert_eq!(
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::DiscardedUncommitted
        );
        assert!(root.path().join(portable.root.as_str()).exists());
        assert!(root.path().join(native.root.as_str()).exists());
        assert!(!root.path().join(".kitrove/staging").exists());
    }

    #[test]
    fn retry_replaces_incomplete_digest_scoped_object_staging() {
        let (root, environment_root, plan, candidate) = environment();
        crate::test_authority::initialize_portable_control_root(&environment_root).unwrap();
        let paths = transaction_paths(plan.digest()).unwrap();
        crate::test_authority::create_owned_fixture_directory(
            &environment_root,
            paths.portable.as_str(),
        );
        crate::test_authority::write_owned_fixture_file(
            root.path()
                .join(paths.portable.as_str())
                .join("metadata.json"),
            "{}\n",
        )
        .unwrap();
        crate::test_authority::write_owned_fixture_file(
            root.path().join(paths.manifest.as_str()),
            [0xc3],
        )
        .unwrap();
        crate::test_authority::write_owned_fixture_file(
            root.path().join(paths.lock.as_str()),
            [0xf0, 0x9f],
        )
        .unwrap();

        assert_eq!(
            commit_adoption(
                &plan,
                &candidate,
                &environment_root,
                CaptureLimits::default(),
            )
            .unwrap(),
            AdoptionCommitOutcome::Committed
        );
        assert!(!root.path().join(".kitrove/staging").exists());
    }

    #[test]
    fn lock_repair_changes_only_generated_state_and_is_idempotent() {
        let (root, environment_root, _, _) = environment();
        let original_manifest = fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap();
        let manifest = EnvironmentManifest::from_toml(&original_manifest).unwrap();
        let plan = plan_lock_repair(&manifest, None).unwrap();
        assert_eq!(plan.observed_status(), LockStatus::Missing);
        assert_eq!(
            commit_lock_repair(&plan, &environment_root, CaptureLimits::default()).unwrap(),
            LockRepairOutcome::Repaired
        );
        assert_eq!(
            fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
            original_manifest
        );
        let lock_text = fs::read_to_string(root.path().join(LOCK_PATH)).unwrap();
        assert_eq!(
            compare_lockfile(&manifest, Some(&lock_text))
                .unwrap()
                .status(),
            LockStatus::InSync
        );

        let clean_plan = plan_lock_repair(&manifest, Some(&lock_text)).unwrap();
        assert_eq!(clean_plan.observed_status(), LockStatus::InSync);
        assert_eq!(
            commit_lock_repair(&clean_plan, &environment_root, CaptureLimits::default()).unwrap(),
            LockRepairOutcome::AlreadyInSync
        );
        assert!(!root.path().join(JOURNAL_PATH).exists());
    }

    #[cfg(unix)]
    #[test]
    fn lock_repair_reclaims_prior_retained_tombstone_before_mutation() {
        let (root, environment_root, _, _) = environment();
        let manifest = EnvironmentManifest::from_toml(
            &fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
        )
        .unwrap();
        let plan = plan_lock_repair(&manifest, None).unwrap();
        let obsolete = PortablePath::parse("obsolete-control").unwrap();
        fs::write(root.path().join(obsolete.as_str()), "retained").unwrap();
        let store = ObjectStore::open(&environment_root).unwrap();
        {
            let _lock = store.try_lock_environment().unwrap();
            store.remove_regular_file_if_present(&obsolete).unwrap();
        }
        let quarantine = root.path().join(".kitrove/removal-quarantine");
        let retained_before = fs::read_dir(&quarantine)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(retained_before.len(), 1);

        assert_eq!(
            commit_lock_repair(&plan, &environment_root, CaptureLimits::default()).unwrap(),
            LockRepairOutcome::Repaired
        );

        for retained in retained_before {
            assert!(!quarantine.join(retained).exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_quarantine_blocks_lock_repair_before_transaction_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let (root, environment_root, _, _) = environment();
        let manifest_text = fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap();
        let manifest = EnvironmentManifest::from_toml(&manifest_text).unwrap();
        let plan = plan_lock_repair(&manifest, None).unwrap();
        let control = root.path().join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir_all(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

        let error =
            commit_lock_repair(&plan, &environment_root, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "transaction.cleanup_failed");
        assert_eq!(
            fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
            manifest_text
        );
        assert!(!root.path().join(LOCK_PATH).exists());
        assert!(!root.path().join(JOURNAL_PATH).exists());
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_quarantine_blocks_portable_recovery_before_reconciliation() {
        use std::os::unix::fs::PermissionsExt as _;

        let (root, environment_root, _, _) = environment();
        let manifest_text = fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap();
        let manifest = EnvironmentManifest::from_toml(&manifest_text).unwrap();
        let plan = plan_lock_repair(&manifest, None).unwrap();
        commit_lock_repair_inner(
            &plan,
            &environment_root,
            CaptureLimits::default(),
            Some(JournalPhase::Prepared),
        )
        .unwrap_err();
        let journal_before = fs::read(root.path().join(JOURNAL_PATH)).unwrap();
        let journal: PortableJournal = serde_json::from_slice(&journal_before).unwrap();
        let staging_path = root.path().join(journal.staging_lock.as_str());
        let staging_before = fs::read(&staging_path).unwrap();
        let control = root.path().join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

        let error =
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "transaction.cleanup_failed");
        assert_eq!(
            fs::read(root.path().join(JOURNAL_PATH)).unwrap(),
            journal_before
        );
        assert_eq!(fs::read(staging_path).unwrap(), staging_before);
        assert_eq!(
            fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
            manifest_text
        );
        assert!(!root.path().join(LOCK_PATH).exists());
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[test]
    fn recovery_removes_an_orphan_pending_journal_after_cleanup_preflight() {
        let (root, environment_root, _, _) = environment();
        crate::test_authority::initialize_portable_control_root(&environment_root).unwrap();
        let pending_path = root.path().join(JOURNAL_PENDING_PATH);
        let pending = b"orphan pending journal\n";
        crate::test_authority::write_owned_fixture_file(&pending_path, pending).unwrap();

        assert_eq!(
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap(),
            PortableRecoveryOutcome::NoJournal
        );
        assert!(!pending_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_quarantine_preserves_an_orphan_pending_journal() {
        use std::os::unix::fs::PermissionsExt as _;

        let (root, environment_root, _, _) = environment();
        let pending_path = root.path().join(JOURNAL_PENDING_PATH);
        let pending = b"orphan pending journal\n";
        fs::create_dir_all(pending_path.parent().unwrap()).unwrap();
        fs::write(&pending_path, pending).unwrap();
        let control = root.path().join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

        let error =
            recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "transaction.cleanup_failed");
        assert_eq!(fs::read(&pending_path).unwrap(), pending);
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[test]
    fn lock_repair_refuses_a_changed_precondition_without_touching_manifest() {
        let (root, environment_root, _, _) = environment();
        let original_manifest = fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap();
        let manifest = EnvironmentManifest::from_toml(&original_manifest).unwrap();
        let plan = plan_lock_repair(&manifest, None).unwrap();
        fs::write(root.path().join(LOCK_PATH), "changed after planning\n").unwrap();

        assert_eq!(
            commit_lock_repair(&plan, &environment_root, CaptureLimits::default())
                .unwrap_err()
                .code(),
            "transaction.lock_stale"
        );
        assert_eq!(
            fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
            original_manifest
        );
        assert_eq!(
            fs::read_to_string(root.path().join(LOCK_PATH)).unwrap(),
            "changed after planning\n"
        );
        assert!(!root.path().join(JOURNAL_PATH).exists());
    }

    #[test]
    fn lock_repair_recovery_rolls_forward_every_durable_phase() {
        for phase in [
            JournalPhase::Prepared,
            JournalPhase::LockCommitted,
            JournalPhase::Verified,
            JournalPhase::Complete,
        ] {
            let (root, environment_root, _, _) = environment();
            let manifest = EnvironmentManifest::from_toml(
                &fs::read_to_string(root.path().join(MANIFEST_PATH)).unwrap(),
            )
            .unwrap();
            let plan = plan_lock_repair(&manifest, None).unwrap();
            assert_eq!(
                commit_lock_repair_inner(
                    &plan,
                    &environment_root,
                    CaptureLimits::default(),
                    Some(phase),
                )
                .unwrap_err()
                .code(),
                "transaction.interrupted"
            );
            assert_eq!(
                recover_portable_environment(&environment_root, CaptureLimits::default()).unwrap(),
                PortableRecoveryOutcome::CompletedCommitted
            );
            let lock_text = fs::read_to_string(root.path().join(LOCK_PATH)).unwrap();
            assert_eq!(
                compare_lockfile(&manifest, Some(&lock_text))
                    .unwrap()
                    .status(),
                LockStatus::InSync
            );
            assert!(!root.path().join(JOURNAL_PATH).exists());
        }
    }

    #[test]
    fn lock_repair_does_not_hide_or_repair_corrupt_objects() {
        let (root, environment_root, adoption, candidate) = environment();
        commit_adoption(
            &adoption,
            &candidate,
            &environment_root,
            CaptureLimits::default(),
        )
        .unwrap();
        let manifest = adoption.proposed_manifest().clone();
        let native_root = adoption
            .asset()
            .native_variants
            .values()
            .next()
            .unwrap()
            .root
            .as_str();
        fs::remove_dir_all(root.path().join(native_root)).unwrap();
        fs::write(root.path().join(LOCK_PATH), "invalid\n").unwrap();
        let plan = plan_lock_repair(&manifest, Some("invalid\n")).unwrap();
        assert_eq!(
            commit_lock_repair(&plan, &environment_root, CaptureLimits::default()).unwrap(),
            LockRepairOutcome::Repaired
        );
        let status =
            inspect_portable_environment(&environment_root, CaptureLimits::default()).unwrap();
        assert_eq!(status.lock_status(), LockStatus::InSync);
        assert!(!status.objects().is_clean());
        assert!(!status.is_clean());
    }
}
