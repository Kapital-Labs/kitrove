use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::{Path, PathBuf};

use kitrove_agent_skills::{CaptureLimits, StoredSkillTree};
use kitrove_agents::{AgentLimits, StoredAgent};
use kitrove_instructions::StoredInstruction;
use kitrove_mcp::StoredMcpServer;
use kitrove_model::{AssetId, EnvironmentManifest, HarnessId, NormalizedDestination, PortablePath};
use kitrove_prompt_commands::{PromptCommandLimits, StoredPromptCommand};

use crate::apply_batch::{
    ATOMIC_COMMIT_CONTROL_TOMBSTONES, ATOMIC_COMMIT_TOMBSTONES_PER_PARTICIPANT,
    ATOMIC_RECOVERY_FORWARD_CONTROL_TOMBSTONES, ATOMIC_RECOVERY_FORWARD_TOMBSTONES_PER_PARTICIPANT,
    ATOMIC_ROLLBACK_CONTROL_TOMBSTONES, ATOMIC_ROLLBACK_TOMBSTONES_PER_PARTICIPANT,
    ATOMIC_TREE_TOMBSTONES_PER_TREE_PARTICIPANT,
};
use crate::apply_batch_journal::{
    AtomicApplyBatchJournalCursor, AtomicApplyBatchPhase, BatchParticipantJournal, ParticipantKind,
    ParticipantProgress as Progress, StoredDisposition,
};
use crate::apply_target::{self, ApplyTargetIdentity, ApplyTargetMaterialization};
use crate::local_state_authority;
use crate::object_mutation::EnvironmentLock;
use crate::quarantine_cleanup::coordinator::{
    LockedMutationBudget, MutationCleanupError, MutationWork, cleanup_locked_stores,
};
use crate::{
    ApplyDisposition, AtomicApplyBatchPlan, AtomicApplyItem, DestinationObservation,
    ExtensionDestinationObservation, NativeExtensionObject, ObjectStore, derive_manifest_revision,
    observe_agent_destination, observe_prompt_command_destination, observe_skill_destination,
};

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 8 * 1024 * 1024;
const MANIFEST_PATH: &str = "kitrove.toml";
const STATE_PATH: &str = "state.json";

/// Stable, path- and content-redacted atomic batch transaction failure.
#[derive(Clone, Eq, PartialEq)]
pub struct AtomicApplyBatchTransactionError {
    code: &'static str,
    message: &'static str,
}

impl AtomicApplyBatchTransactionError {
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

impl Debug for AtomicApplyBatchTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicApplyBatchTransactionError")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl Display for AtomicApplyBatchTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AtomicApplyBatchTransactionError {}

struct TargetRoot {
    identity: NormalizedDestination,
    path: PathBuf,
    store: ObjectStore,
    requires_lock: bool,
}

struct BatchSources {
    skills: BTreeMap<AssetId, StoredSkillTree>,
    extensions: BTreeMap<AssetId, NativeExtensionObject>,
    instructions: BTreeMap<AssetId, StoredInstruction>,
    commands: BTreeMap<AssetId, StoredPromptCommand>,
    agents: BTreeMap<AssetId, StoredAgent>,
    mcps: BTreeMap<AssetId, StoredMcpServer>,
}

/// Successful result of committing one failure-atomic batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicApplyBatchCommitOutcome {
    Committed,
}

#[path = "apply_batch_recovery.rs"]
mod recovery;

pub use recovery::{AtomicApplyBatchRecoveryOutcome, recover_atomic_apply_batch};

/// Commits every participant and the final machine state as one recoverable batch.
pub fn commit_atomic_apply_batch(
    plan: &AtomicApplyBatchPlan,
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
) -> Result<AtomicApplyBatchCommitOutcome, AtomicApplyBatchTransactionError> {
    with_locked_batch_authority(
        plan,
        environment_root,
        state_root,
        limits,
        |environment, state, targets, sources| {
            let (forward, rollback) = atomic_batch_mutation_work(plan, limits)?;
            let cleanup_budget =
                cleanup_batch_roots(environment, state, targets, forward, rollback)?;
            let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;
            commit_locked_batch(
                plan,
                environment,
                state,
                targets,
                sources,
                limits,
                || {},
                |_| {},
                |_| {},
                || {},
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_locked_batch(
    plan: &AtomicApplyBatchPlan,
    environment: &ObjectStore,
    state: &ObjectStore,
    targets: &[TargetRoot],
    sources: &BatchSources,
    limits: CaptureLimits,
    after_prepared: impl FnOnce(),
    mut after_quarantine: impl FnMut(usize),
    mut after_target_install: impl FnMut(usize),
    after_state_install: impl FnOnce(),
) -> Result<AtomicApplyBatchCommitOutcome, AtomicApplyBatchTransactionError> {
    let mut journal = AtomicApplyBatchJournalCursor::install(state, plan).map_err(journal_error)?;
    for (index, item) in plan.items().iter().enumerate() {
        journal
            .transition_participant(state, index, Progress::StagingPending)
            .map_err(journal_error)?;
        if item.disposition().materializes_target() {
            let target = target_for(item, targets)?;
            apply_target::stage(
                &target.store,
                journal.staging_target(index).map_err(journal_error)?,
                &new_materialization(item, sources)?,
                limits,
            )
            .map_err(|_| storage_failed())?;
        }
        journal
            .transition_participant(state, index, Progress::Prepared)
            .map_err(journal_error)?;
    }
    state
        .reset_incomplete_staged_text(
            journal.staging_state(),
            plan.proposed_local_state_text(),
            MAX_CONTROL_BYTES,
        )
        .map_err(|_| storage_failed())?;
    state
        .stage_private_text(
            journal.staging_state(),
            plan.proposed_local_state_text(),
            MAX_CONTROL_BYTES,
        )
        .map_err(|_| storage_failed())?;
    journal
        .transition_phase(state, AtomicApplyBatchPhase::Prepared)
        .map_err(journal_error)?;
    after_prepared();

    revalidate_locked_authority(plan, environment, state, targets, sources, limits)?;
    journal
        .transition_phase(state, AtomicApplyBatchPhase::QuarantiningOldTargets)
        .map_err(journal_error)?;
    for (index, item) in plan.items().iter().enumerate() {
        if !item.disposition().requires_quarantine() {
            continue;
        }
        journal
            .transition_participant(state, index, Progress::QuarantinePending)
            .map_err(journal_error)?;
        let target = target_for(item, targets)?;
        quarantine_old_target(
            item,
            target,
            journal.backup_target(index).map_err(journal_error)?,
            limits,
        )?;
        after_quarantine(index);
        journal
            .transition_participant(state, index, Progress::Quarantined)
            .map_err(journal_error)?;
    }
    journal
        .transition_phase(state, AtomicApplyBatchPhase::OldTargetsQuarantined)
        .map_err(journal_error)?;
    journal
        .transition_phase(state, AtomicApplyBatchPhase::CommittingNewTargets)
        .map_err(journal_error)?;
    for (index, item) in plan.items().iter().enumerate() {
        let target = target_for(item, targets)?;
        if item.disposition() == ApplyDisposition::Remove {
            journal
                .transition_participant(state, index, Progress::CommitPending)
                .map_err(journal_error)?;
            after_target_install(index);
        } else if item.disposition() == ApplyDisposition::NoOp {
            let identity = new_identity(item, sources)?;
            apply_target::clear_staging(
                &target.store,
                journal.staging_target(index).map_err(journal_error)?,
                &identity,
                limits,
            )
            .map_err(|_| storage_failed())?;
        } else {
            let identity = new_identity(item, sources)?;
            journal
                .transition_participant(state, index, Progress::CommitPending)
                .map_err(journal_error)?;
            apply_target::install(
                &target.store,
                journal.staging_target(index).map_err(journal_error)?,
                item.relative_destination(),
                &identity,
                limits,
            )
            .map_err(|_| storage_failed())?;
            after_target_install(index);
        }
        journal
            .transition_participant(state, index, Progress::Committed)
            .map_err(journal_error)?;
    }
    journal
        .transition_phase(state, AtomicApplyBatchPhase::NewTargetsCommitted)
        .map_err(journal_error)?;
    state
        .install_staged_text_guarded(
            journal.staging_state(),
            &portable_path(STATE_PATH),
            Some(plan.observed_local_state_text()),
            plan.proposed_local_state_text(),
            MAX_CONTROL_BYTES,
        )
        .map_err(|_| storage_failed())?;
    after_state_install();
    journal
        .transition_phase(state, AtomicApplyBatchPhase::StateCommitted)
        .map_err(journal_error)?;
    verify_batch(plan, state, targets, sources, limits)?;
    for index in 0..plan.items().len() {
        journal
            .transition_participant(state, index, Progress::Verified)
            .map_err(journal_error)?;
    }
    journal
        .transition_phase(state, AtomicApplyBatchPhase::Verified)
        .map_err(journal_error)?;
    cleanup_verified_batch(plan, state, targets, sources, &journal, limits)?;
    Ok(AtomicApplyBatchCommitOutcome::Committed)
}

/// Rechecks complete batch authority under every canonical mutation lock.
///
/// Manifest, destination, and local-state authority are not changed. Acquiring the locks may create
/// transaction-control files and authorized private-state opening may repair its boundary mode.
pub fn validate_atomic_apply_batch_authority(
    plan: &AtomicApplyBatchPlan,
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    with_locked_batch_authority(plan, environment_root, state_root, limits, |_, _, _, _| {
        Ok(())
    })
}

fn with_locked_batch_authority<T>(
    plan: &AtomicApplyBatchPlan,
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
    operation: impl FnOnce(
        &ObjectStore,
        &ObjectStore,
        &[TargetRoot],
        &BatchSources,
    ) -> Result<T, AtomicApplyBatchTransactionError>,
) -> Result<T, AtomicApplyBatchTransactionError> {
    let environment = ObjectStore::open(environment_root).map_err(|_| storage_failed())?;
    let state =
        ObjectStore::open_private_state_for_mutation(state_root).map_err(|_| storage_failed())?;
    environment
        .require_non_overlapping_root(&state)
        .map_err(|_| root_overlap())?;

    let targets = open_target_roots(plan, &environment, &state)?;
    let _root_locks = try_lock_batch_roots(&environment, &state, &targets)?;
    ensure_no_pending_recovery(&environment, &state)?;

    let manifest_text = required_text(&environment, MANIFEST_PATH)?;
    let manifest = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| stale_manifest())?;
    let revision = derive_manifest_revision(&manifest).map_err(|_| stale_manifest())?;
    if &revision != plan.manifest_revision() {
        return Err(stale_manifest());
    }
    if required_text(&state, STATE_PATH)? != plan.observed_local_state_text() {
        return Err(stale_state());
    }
    let sources = load_batch_sources(plan, &manifest, &environment, limits)?;
    for item in plan.items() {
        validate_item_authority(item, &manifest, &sources, &targets, limits)?;
    }
    operation(&environment, &state, &targets, &sources)
}

fn try_lock_batch_roots(
    environment: &ObjectStore,
    state: &ObjectStore,
    targets: &[TargetRoot],
) -> Result<Vec<EnvironmentLock>, AtomicApplyBatchTransactionError> {
    let roots = batch_root_stores(environment, state, targets);
    ObjectStore::try_lock_distinct_roots(&roots).map_err(root_lock_error)
}

fn root_lock_error(error: crate::ObjectMutationError) -> AtomicApplyBatchTransactionError {
    match error.code() {
        "object.environment_locked" => lock_unavailable(),
        "object.io" => storage_failed(),
        _ => target_invalid(),
    }
}

fn batch_root_stores<'a>(
    environment: &'a ObjectStore,
    state: &'a ObjectStore,
    targets: &'a [TargetRoot],
) -> Vec<&'a ObjectStore> {
    let mut roots = vec![environment, state];
    roots.extend(
        targets
            .iter()
            .filter(|target| target.requires_lock)
            .map(|target| &target.store),
    );
    roots
}

fn cleanup_batch_roots(
    environment: &ObjectStore,
    state: &ObjectStore,
    targets: &[TargetRoot],
    forward: MutationWork,
    rollback: MutationWork,
) -> Result<LockedMutationBudget, AtomicApplyBatchTransactionError> {
    cleanup_locked_stores(
        &batch_root_stores(environment, state, targets),
        forward,
        rollback,
    )
    .map_err(cleanup_error)
}

fn atomic_batch_mutation_work(
    plan: &AtomicApplyBatchPlan,
    limits: CaptureLimits,
) -> Result<(MutationWork, MutationWork), AtomicApplyBatchTransactionError> {
    let inventory = AtomicMutationInventory::from_tree_kinds(plan.items().iter().map(|item| {
        matches!(
            item,
            AtomicApplyItem::Skill(_) | AtomicApplyItem::Extension(_)
        )
    }))?;
    inventory.reservation(AtomicForwardPath::Commit, limits)
}

#[derive(Clone, Copy)]
enum AtomicForwardPath {
    Commit,
    Recovery,
}

struct AtomicMutationInventory {
    participants: usize,
    tree_participants: usize,
}

impl AtomicMutationInventory {
    fn from_tree_kinds(
        tree_kinds: impl IntoIterator<Item = bool>,
    ) -> Result<Self, AtomicApplyBatchTransactionError> {
        tree_kinds.into_iter().try_fold(
            Self {
                participants: 0,
                tree_participants: 0,
            },
            |inventory, is_tree| {
                Ok(Self {
                    participants: inventory
                        .participants
                        .checked_add(1)
                        .ok_or_else(cleanup_limit)?,
                    tree_participants: inventory
                        .tree_participants
                        .checked_add(usize::from(is_tree))
                        .ok_or_else(cleanup_limit)?,
                })
            },
        )
    }

    fn reservation(
        &self,
        forward_path: AtomicForwardPath,
        limits: CaptureLimits,
    ) -> Result<(MutationWork, MutationWork), AtomicApplyBatchTransactionError> {
        let tree_tombstones = self
            .tree_participants
            .checked_mul(ATOMIC_TREE_TOMBSTONES_PER_TREE_PARTICIPANT)
            .ok_or_else(cleanup_limit)?;
        let (forward_per_participant, forward_control) = match forward_path {
            AtomicForwardPath::Commit => (
                ATOMIC_COMMIT_TOMBSTONES_PER_PARTICIPANT,
                ATOMIC_COMMIT_CONTROL_TOMBSTONES,
            ),
            AtomicForwardPath::Recovery => (
                ATOMIC_RECOVERY_FORWARD_TOMBSTONES_PER_PARTICIPANT,
                ATOMIC_RECOVERY_FORWARD_CONTROL_TOMBSTONES,
            ),
        };
        let forward_tombstones =
            checked_linear_work(self.participants, forward_per_participant, forward_control)?;
        let rollback_tombstones = checked_linear_work(
            self.participants,
            ATOMIC_ROLLBACK_TOMBSTONES_PER_PARTICIPANT,
            ATOMIC_ROLLBACK_CONTROL_TOMBSTONES,
        )?;
        Ok((
            MutationWork::try_from_counts(forward_tombstones, tree_tombstones, limits)
                .map_err(cleanup_error)?,
            MutationWork::try_from_counts(rollback_tombstones, tree_tombstones, limits)
                .map_err(cleanup_error)?,
        ))
    }
}

fn checked_linear_work(
    participants: usize,
    per_participant: usize,
    control: usize,
) -> Result<usize, AtomicApplyBatchTransactionError> {
    participants
        .checked_mul(per_participant)
        .and_then(|work| work.checked_add(control))
        .ok_or_else(cleanup_limit)
}

fn open_target_roots(
    plan: &AtomicApplyBatchPlan,
    environment: &ObjectStore,
    state: &ObjectStore,
) -> Result<Vec<TargetRoot>, AtomicApplyBatchTransactionError> {
    open_target_identities(plan.target_anchors().iter().cloned(), environment, state)
}

fn open_recovery_target_roots(
    journal: &AtomicApplyBatchJournalCursor,
    environment: &ObjectStore,
    state: &ObjectStore,
) -> Result<Vec<TargetRoot>, AtomicApplyBatchTransactionError> {
    let identities = journal
        .participants()
        .iter()
        .map(BatchParticipantJournal::target_anchor)
        .cloned()
        .collect::<BTreeSet<_>>();
    open_target_identities(identities, environment, state)
}

fn open_target_identities(
    identities: impl IntoIterator<Item = NormalizedDestination>,
    environment: &ObjectStore,
    state: &ObjectStore,
) -> Result<Vec<TargetRoot>, AtomicApplyBatchTransactionError> {
    let identities = identities.into_iter().collect::<Vec<_>>();
    let mut targets: Vec<TargetRoot> = Vec::with_capacity(identities.len());
    let environment_identity = environment
        .verified_root_identity()
        .map_err(|_| target_invalid())?;
    let state_identity = state
        .verified_root_identity()
        .map_err(|_| target_invalid())?;
    let mut target_identities = BTreeSet::new();
    for identity in identities {
        let path = PathBuf::from(identity.as_str());
        let store = ObjectStore::open(&path).map_err(|_| target_invalid())?;
        let root_identity = store
            .verified_root_identity()
            .map_err(|_| target_invalid())?;
        if root_identity == state_identity || !target_identities.insert(root_identity) {
            return Err(target_invalid());
        }
        targets.push(TargetRoot {
            identity,
            path,
            store,
            requires_lock: root_identity != environment_identity,
        });
    }
    Ok(targets)
}

fn validate_item_authority(
    item: &AtomicApplyItem,
    manifest: &EnvironmentManifest,
    sources: &BatchSources,
    targets: &[TargetRoot],
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    let target = target_for(item, targets)?;
    match item {
        AtomicApplyItem::Skill(plan) => {
            let object = sources
                .skills
                .get(plan.asset_id())
                .ok_or_else(stale_manifest)?;
            if object.tree() != plan.rendered().tree() {
                return Err(stale_manifest());
            }
            if observe_skill_destination(
                &target.path.join(plan.relative_destination().as_str()),
                limits,
            ) != *plan.observed_destination()
            {
                return Err(stale_target());
            }
        }
        AtomicApplyItem::Extension(plan) => {
            if !plan
                .revalidate_project_trust()
                .map_err(|_| stale_target())?
            {
                return Err(stale_target());
            }
            let object = sources
                .extensions
                .get(plan.asset_id())
                .ok_or_else(stale_manifest)?;
            if !extension_matches_plan(object, plan) {
                return Err(stale_manifest());
            }
            if observe_extension(&target.store, plan.relative_destination(), object, limits)?
                != *plan.observed_destination()
            {
                return Err(stale_target());
            }
        }
        AtomicApplyItem::Instruction(plan) => {
            let document = plan.document();
            for region in document.regions() {
                if let Some(receipt) = region.proposed_receipt() {
                    let object = sources
                        .instructions
                        .get(region.asset_id())
                        .ok_or_else(stale_manifest)?;
                    let (_, rendered_hash) = kitrove_instructions::render_managed_region(
                        region.asset_id(),
                        object.body(),
                    )
                    .map_err(|_| stale_manifest())?;
                    if rendered_hash != receipt.rendered_hash {
                        return Err(stale_manifest());
                    }
                } else if region.observed_receipt().is_none() {
                    return Err(stale_manifest());
                }
                for policy in region.policies() {
                    let observed = crate::observe_instruction_document(
                        &target.path,
                        policy,
                        kitrove_instructions::InstructionLimits::default(),
                    )
                    .map_err(|_| stale_target())?;
                    if !observed.has_same_physical_authority(document.observation()) {
                        return Err(stale_target());
                    }
                }
            }
        }
        AtomicApplyItem::PromptCommand(plan) => {
            let object = sources
                .commands
                .get(plan.asset_id())
                .ok_or_else(stale_manifest)?;
            let rendered = kitrove_prompt_commands::render_native_prompt_command(
                crate::prompt_command_observation::prompt_command_dialect(&plan.policy().harness)
                    .ok_or_else(stale_manifest)?,
                object.command(),
            )
            .map_err(|_| stale_manifest())?;
            if rendered.as_bytes() != plan.rendered().bytes() {
                return Err(stale_manifest());
            }
            if observe_prompt_command_destination(
                &target.path,
                plan.policy(),
                object.command().name(),
                PromptCommandLimits::default(),
            )
            .map_err(|_| stale_target())?
                != *plan.observation()
            {
                return Err(stale_target());
            }
        }
        AtomicApplyItem::PromptCommandRemoval(plan) => {
            if observe_prompt_command_destination(
                &target.path,
                plan.policy(),
                plan.observation().command_name(),
                PromptCommandLimits::default(),
            )
            .map_err(|_| stale_target())?
                != *plan.observation()
            {
                return Err(stale_target());
            }
        }
        AtomicApplyItem::Agent(plan) => {
            let object = sources
                .agents
                .get(plan.asset_id())
                .ok_or_else(stale_manifest)?;
            let rendered =
                kitrove_agents::render_native_agent(plan.policy().dialect, object.agent())
                    .map_err(|_| stale_manifest())?;
            if rendered.as_bytes() != plan.rendered().bytes() {
                return Err(stale_manifest());
            }
            if observe_agent_destination(
                &target.path,
                plan.policy(),
                object.agent().name(),
                AgentLimits::default(),
            )
            .map_err(|_| stale_target())?
                != *plan.observation()
            {
                return Err(stale_target());
            }
        }
        AtomicApplyItem::AgentRemoval(plan) => {
            if observe_agent_destination(
                &target.path,
                plan.policy(),
                plan.observation().agent_name(),
                AgentLimits::default(),
            )
            .map_err(|_| stale_target())?
                != *plan.observation()
            {
                return Err(stale_target());
            }
        }
        AtomicApplyItem::Mcp(plan) => {
            let mut projections = Vec::with_capacity(plan.document().entries().len());
            for entry in plan.document().entries() {
                let object = sources
                    .mcps
                    .get(entry.asset_id())
                    .ok_or_else(stale_manifest)?;
                let observation = crate::observe_mcp_document(
                    &target.path,
                    entry.policy(),
                    kitrove_mcp::McpParseLimits::default(),
                )
                .map_err(|_| stale_target())?;
                if !observation.has_same_physical_authority(plan.document().observation()) {
                    return Err(stale_target());
                }
                projections.push(crate::McpProjection::new(
                    entry.asset_id().clone(),
                    object.clone(),
                    entry.policy().clone(),
                    observation,
                ));
            }
            let removal = plan
                .document()
                .entries()
                .iter()
                .all(|entry| entry.disposition() == ApplyDisposition::Remove);
            let has_removal = plan
                .document()
                .entries()
                .iter()
                .any(|entry| entry.disposition() == ApplyDisposition::Remove);
            if has_removal
                && plan.document().entries().iter().any(|entry| {
                    !matches!(
                        entry.disposition(),
                        ApplyDisposition::NoOp | ApplyDisposition::Remove
                    )
                })
            {
                return Err(stale_manifest());
            }
            let recomputed = if removal {
                crate::plan_coalesced_mcp_removal(
                    manifest,
                    projections,
                    plan.observed_local_state_text(),
                    kitrove_mcp::McpParseLimits::default(),
                )
            } else if has_removal {
                crate::plan_coalesced_mcp_removal_selection(
                    manifest,
                    projections
                        .into_iter()
                        .zip(plan.document().entries())
                        .map(|(projection, entry)| {
                            if entry.disposition() == ApplyDisposition::NoOp {
                                crate::McpRemovalSelection::retain(projection)
                            } else {
                                crate::McpRemovalSelection::remove(projection)
                            }
                        })
                        .collect(),
                    plan.observed_local_state_text(),
                    kitrove_mcp::McpParseLimits::default(),
                )
            } else {
                crate::plan_coalesced_mcp_apply(
                    manifest,
                    projections,
                    plan.observed_local_state_text(),
                    None,
                    kitrove_mcp::McpParseLimits::default(),
                )
            }
            .map_err(|_| stale_manifest())?;
            if recomputed.documents().len() != 1 || &recomputed.documents()[0] != plan.document() {
                return Err(stale_manifest());
            }
        }
    }
    Ok(())
}

fn load_batch_sources(
    plan: &AtomicApplyBatchPlan,
    manifest: &EnvironmentManifest,
    environment: &ObjectStore,
    limits: CaptureLimits,
) -> Result<BatchSources, AtomicApplyBatchTransactionError> {
    let mut sources = BatchSources {
        skills: BTreeMap::new(),
        extensions: BTreeMap::new(),
        instructions: BTreeMap::new(),
        commands: BTreeMap::new(),
        agents: BTreeMap::new(),
        mcps: BTreeMap::new(),
    };
    for item in plan.items() {
        match item {
            AtomicApplyItem::Skill(plan) if !sources.skills.contains_key(plan.asset_id()) => {
                let portable = manifest
                    .assets
                    .get(plan.asset_id())
                    .and_then(|asset| asset.portable.as_ref())
                    .filter(|portable| portable.format == "agent-skills/v1")
                    .ok_or_else(stale_manifest)?;
                let object = environment
                    .load_portable(&portable.root, limits)
                    .map_err(|_| stale_manifest())?;
                if object.tree().hash != portable.object_hash {
                    return Err(stale_manifest());
                }
                sources.skills.insert(plan.asset_id().clone(), object);
            }
            AtomicApplyItem::Extension(plan)
                if !sources.extensions.contains_key(plan.asset_id()) =>
            {
                let native = manifest
                    .assets
                    .get(plan.asset_id())
                    .and_then(|asset| asset.native_variants.get(&HarnessId::Pi))
                    .filter(|native| native.format == "kitrove-native-pi-extension-object/v1")
                    .ok_or_else(stale_manifest)?;
                let object = environment
                    .load_native_extension(&native.root, limits)
                    .map_err(|_| stale_manifest())?;
                if object.hash() != &native.object_hash {
                    return Err(stale_manifest());
                }
                sources.extensions.insert(plan.asset_id().clone(), object);
            }
            AtomicApplyItem::Instruction(plan) => {
                for region in plan.document().regions() {
                    if region.is_removal() || sources.instructions.contains_key(region.asset_id()) {
                        continue;
                    }
                    let portable = manifest
                        .assets
                        .get(region.asset_id())
                        .and_then(|asset| asset.portable.as_ref())
                        .filter(|portable| portable.format == StoredInstruction::format())
                        .ok_or_else(stale_manifest)?;
                    let object = environment
                        .load_portable_instruction(&portable.root, limits)
                        .map_err(|_| stale_manifest())?;
                    if object.object_hash() != &portable.object_hash {
                        return Err(stale_manifest());
                    }
                    sources
                        .instructions
                        .insert(region.asset_id().clone(), object);
                }
            }
            AtomicApplyItem::PromptCommand(plan)
                if !sources.commands.contains_key(plan.asset_id()) =>
            {
                load_prompt_command_source(
                    &mut sources.commands,
                    manifest,
                    plan.asset_id(),
                    environment,
                    limits,
                )?;
            }
            AtomicApplyItem::PromptCommandRemoval(plan)
                if !sources.commands.contains_key(plan.asset_id()) =>
            {
                load_prompt_command_source(
                    &mut sources.commands,
                    manifest,
                    plan.asset_id(),
                    environment,
                    limits,
                )?;
            }
            AtomicApplyItem::Agent(plan) if !sources.agents.contains_key(plan.asset_id()) => {
                load_agent_source(
                    &mut sources.agents,
                    manifest,
                    plan.asset_id(),
                    environment,
                    limits,
                )?;
            }
            AtomicApplyItem::AgentRemoval(plan)
                if !sources.agents.contains_key(plan.asset_id()) =>
            {
                load_agent_source(
                    &mut sources.agents,
                    manifest,
                    plan.asset_id(),
                    environment,
                    limits,
                )?;
            }
            AtomicApplyItem::Mcp(plan) => {
                for entry in plan.document().entries() {
                    if sources.mcps.contains_key(entry.asset_id()) {
                        continue;
                    }
                    let portable = manifest
                        .assets
                        .get(entry.asset_id())
                        .and_then(|asset| asset.portable.as_ref())
                        .filter(|portable| portable.format == StoredMcpServer::format())
                        .ok_or_else(stale_manifest)?;
                    let object = environment
                        .load_portable_mcp(&portable.root, limits)
                        .map_err(|_| stale_manifest())?;
                    if object.object_hash() != &portable.object_hash {
                        return Err(stale_manifest());
                    }
                    sources.mcps.insert(entry.asset_id().clone(), object);
                }
            }
            AtomicApplyItem::Skill(_)
            | AtomicApplyItem::Extension(_)
            | AtomicApplyItem::PromptCommand(_)
            | AtomicApplyItem::PromptCommandRemoval(_)
            | AtomicApplyItem::Agent(_)
            | AtomicApplyItem::AgentRemoval(_) => {}
        }
    }
    Ok(sources)
}

fn load_agent_source(
    agents: &mut BTreeMap<AssetId, StoredAgent>,
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    environment: &ObjectStore,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    let portable = manifest
        .assets
        .get(asset_id)
        .and_then(|asset| asset.portable.as_ref())
        .filter(|portable| portable.format == StoredAgent::format())
        .ok_or_else(stale_manifest)?;
    let object = environment
        .load_portable_agent(&portable.root, limits)
        .map_err(|_| stale_manifest())?;
    if object.object_hash() != &portable.object_hash {
        return Err(stale_manifest());
    }
    agents.insert(asset_id.clone(), object);
    Ok(())
}

fn load_prompt_command_source(
    commands: &mut BTreeMap<AssetId, StoredPromptCommand>,
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    environment: &ObjectStore,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    let portable = manifest
        .assets
        .get(asset_id)
        .and_then(|asset| asset.portable.as_ref())
        .filter(|portable| portable.format == StoredPromptCommand::format())
        .ok_or_else(stale_manifest)?;
    let object = environment
        .load_portable_prompt_command(&portable.root, limits)
        .map_err(|_| stale_manifest())?;
    if object.object_hash() != &portable.object_hash {
        return Err(stale_manifest());
    }
    commands.insert(asset_id.clone(), object);
    Ok(())
}

fn target_for<'a>(
    item: &AtomicApplyItem,
    targets: &'a [TargetRoot],
) -> Result<&'a TargetRoot, AtomicApplyBatchTransactionError> {
    let anchor = item.target_anchor().map_err(|_| target_invalid())?;
    targets
        .binary_search_by(|target| target.identity.cmp(&anchor))
        .ok()
        .and_then(|index| targets.get(index))
        .ok_or_else(target_invalid)
}

fn extension_matches_plan(
    object: &NativeExtensionObject,
    plan: &crate::ExtensionApplyPlan,
) -> bool {
    object.layout() == plan.rendered().layout()
        && object.native_id() == plan.rendered().native_id().as_str()
        && object.tree() == plan.rendered().tree()
        && object.hash() == plan.rendered().rendered_hash()
}

fn observe_extension(
    target: &ObjectStore,
    relative: &PortablePath,
    expected: &NativeExtensionObject,
    limits: CaptureLimits,
) -> Result<ExtensionDestinationObservation, AtomicApplyBatchTransactionError> {
    target
        .capture_extension_target_object(
            relative,
            expected.layout(),
            expected.entrypoint(),
            expected.native_id(),
            limits,
        )
        .map(|observed| match observed {
            None => ExtensionDestinationObservation::Absent,
            Some(object) => ExtensionDestinationObservation::Present {
                layout: object.layout(),
                object_hash: object.hash().clone(),
            },
        })
        .map_err(|_| stale_target())
}

fn new_materialization<'a>(
    item: &'a AtomicApplyItem,
    sources: &'a BatchSources,
) -> Result<ApplyTargetMaterialization<'a>, AtomicApplyBatchTransactionError> {
    if let Some(authority) = exact_text_authority(item)? {
        return Ok(ApplyTargetMaterialization::ExactText {
            text: authority.text,
            mode: authority.mode,
            max_bytes: authority.max_bytes,
        });
    }
    match item {
        AtomicApplyItem::Skill(plan) => Ok(ApplyTargetMaterialization::Skill {
            tree: plan.rendered().tree(),
            rendered_hash: plan.rendered().rendered_hash(),
        }),
        AtomicApplyItem::Extension(plan) => sources
            .extensions
            .get(plan.asset_id())
            .map(ApplyTargetMaterialization::Extension)
            .ok_or_else(stale_manifest),
        AtomicApplyItem::PromptCommandRemoval(_) => Err(stale_manifest()),
        AtomicApplyItem::AgentRemoval(_) => Err(stale_manifest()),
        AtomicApplyItem::Instruction(_)
        | AtomicApplyItem::PromptCommand(_)
        | AtomicApplyItem::Agent(_)
        | AtomicApplyItem::Mcp(_) => unreachable!("handled by exact-text authority"),
    }
}

fn new_identity<'a>(
    item: &'a AtomicApplyItem,
    sources: &'a BatchSources,
) -> Result<ApplyTargetIdentity<'a>, AtomicApplyBatchTransactionError> {
    if let Some(authority) = exact_text_authority(item)? {
        return Ok(ApplyTargetIdentity::ExactText {
            text: authority.text,
            mode: authority.mode,
            max_bytes: authority.max_bytes,
        });
    }
    match item {
        AtomicApplyItem::Skill(plan) => {
            Ok(ApplyTargetIdentity::Skill(plan.rendered().rendered_hash()))
        }
        AtomicApplyItem::Extension(plan) => sources
            .extensions
            .get(plan.asset_id())
            .map(ApplyTargetIdentity::Extension)
            .ok_or_else(stale_manifest),
        AtomicApplyItem::PromptCommandRemoval(_) => Err(stale_manifest()),
        AtomicApplyItem::AgentRemoval(_) => Err(stale_manifest()),
        AtomicApplyItem::Instruction(_)
        | AtomicApplyItem::PromptCommand(_)
        | AtomicApplyItem::Agent(_)
        | AtomicApplyItem::Mcp(_) => unreachable!("handled by exact-text authority"),
    }
}

struct ExactTextAuthority<'a> {
    text: &'a str,
    mode: crate::read_only_fs::RegularFileMode,
    max_bytes: usize,
}

fn exact_text_authority(
    item: &AtomicApplyItem,
) -> Result<Option<ExactTextAuthority<'_>>, AtomicApplyBatchTransactionError> {
    let (bytes, mode, max_bytes) = match item {
        AtomicApplyItem::Instruction(plan) => (
            plan.document().rendered().bytes(),
            plan.document().rendered().mode(),
            crate::apply_batch::instruction_document_limit(plan.document())
                .map_err(|_| stale_manifest())?,
        ),
        AtomicApplyItem::PromptCommand(plan) => (
            plan.rendered().bytes(),
            plan.rendered().mode(),
            PromptCommandLimits::default().max_document_bytes,
        ),
        AtomicApplyItem::Agent(plan) => (
            plan.rendered().bytes(),
            plan.rendered().mode(),
            AgentLimits::default().max_document_bytes,
        ),
        AtomicApplyItem::Mcp(plan) => (
            plan.document().rendered().bytes(),
            plan.document().rendered().mode(),
            crate::apply_batch::mcp_document_limit(plan.document())
                .map_err(|_| stale_manifest())?,
        ),
        AtomicApplyItem::Skill(_)
        | AtomicApplyItem::Extension(_)
        | AtomicApplyItem::PromptCommandRemoval(_)
        | AtomicApplyItem::AgentRemoval(_) => return Ok(None),
    };
    Ok(Some(ExactTextAuthority {
        text: std::str::from_utf8(bytes).map_err(|_| stale_manifest())?,
        mode,
        max_bytes,
    }))
}

fn quarantine_old_target(
    item: &AtomicApplyItem,
    target: &TargetRoot,
    backup: &PortablePath,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    match item {
        AtomicApplyItem::Skill(plan) => {
            let DestinationObservation::Present { rendered_hash, .. } = plan.observed_destination()
            else {
                return Err(stale_target());
            };
            apply_target::quarantine(
                &target.store,
                plan.relative_destination(),
                backup,
                &ApplyTargetIdentity::Skill(rendered_hash),
                limits,
            )
            .map_err(|_| storage_failed())
        }
        AtomicApplyItem::Agent(plan) => {
            let old = plan.observation().content_text().ok_or_else(stale_target)?;
            apply_target::quarantine(
                &target.store,
                plan.relative_destination(),
                backup,
                &ApplyTargetIdentity::ExactText {
                    text: old,
                    mode: plan.rendered().mode(),
                    max_bytes: AgentLimits::default().max_document_bytes,
                },
                limits,
            )
            .map_err(|_| storage_failed())
        }
        AtomicApplyItem::AgentRemoval(plan) => {
            let old = plan.observation().content_text().ok_or_else(stale_target)?;
            apply_target::quarantine(
                &target.store,
                plan.relative_destination(),
                backup,
                &ApplyTargetIdentity::ExactText {
                    text: old,
                    mode: plan.observation().mode(),
                    max_bytes: AgentLimits::default().max_document_bytes,
                },
                limits,
            )
            .map_err(|_| storage_failed())
        }
        AtomicApplyItem::Extension(plan) => {
            let old =
                capture_old_extension(&target.store, plan.relative_destination(), plan, limits)?;
            apply_target::quarantine(
                &target.store,
                plan.relative_destination(),
                backup,
                &ApplyTargetIdentity::Extension(&old),
                limits,
            )
            .map_err(|_| storage_failed())
        }
        AtomicApplyItem::Instruction(plan) => {
            let old = plan
                .document()
                .observation()
                .document_text()
                .ok_or_else(stale_target)?;
            apply_target::quarantine(
                &target.store,
                plan.document().relative_destination(),
                backup,
                &ApplyTargetIdentity::ExactText {
                    text: old,
                    mode: plan.document().rendered().mode(),
                    max_bytes: crate::apply_batch::instruction_document_limit(plan.document())
                        .map_err(|_| stale_manifest())?,
                },
                limits,
            )
            .map_err(|_| storage_failed())
        }
        AtomicApplyItem::PromptCommand(plan) => {
            let old = plan.observation().content_text().ok_or_else(stale_target)?;
            apply_target::quarantine(
                &target.store,
                plan.relative_destination(),
                backup,
                &ApplyTargetIdentity::ExactText {
                    text: old,
                    mode: plan.rendered().mode(),
                    max_bytes: PromptCommandLimits::default().max_document_bytes,
                },
                limits,
            )
            .map_err(|_| storage_failed())
        }
        AtomicApplyItem::Mcp(plan) => {
            let old = plan
                .document()
                .observation()
                .document_text()
                .ok_or_else(stale_target)?;
            apply_target::quarantine(
                &target.store,
                plan.document().relative_destination(),
                backup,
                &ApplyTargetIdentity::ExactText {
                    text: old,
                    mode: plan.document().rendered().mode(),
                    max_bytes: crate::apply_batch::mcp_document_limit(plan.document())
                        .map_err(|_| stale_manifest())?,
                },
                limits,
            )
            .map_err(|_| storage_failed())
        }
        AtomicApplyItem::PromptCommandRemoval(plan) => {
            let old = plan.observation().content_text().ok_or_else(stale_target)?;
            apply_target::quarantine(
                &target.store,
                plan.relative_destination(),
                backup,
                &ApplyTargetIdentity::ExactText {
                    text: old,
                    mode: plan.observation().mode(),
                    max_bytes: PromptCommandLimits::default().max_document_bytes,
                },
                limits,
            )
            .map_err(|_| storage_failed())
        }
    }
}

fn capture_old_extension(
    store: &ObjectStore,
    path: &PortablePath,
    plan: &crate::ExtensionApplyPlan,
    limits: CaptureLimits,
) -> Result<NativeExtensionObject, AtomicApplyBatchTransactionError> {
    let ExtensionDestinationObservation::Present {
        layout,
        object_hash,
    } = plan.observed_destination()
    else {
        return Err(stale_target());
    };
    let native_id = plan.rendered().native_id().as_str();
    let entrypoint = match layout {
        crate::NativeExtensionLayout::Standalone => format!("{native_id}.ts"),
        crate::NativeExtensionLayout::Directory => "index.ts".to_owned(),
    };
    store
        .capture_extension_target_object(path, *layout, &entrypoint, native_id, limits)
        .map_err(|_| stale_target())?
        .filter(|object| object.hash() == object_hash)
        .ok_or_else(stale_target)
}

fn revalidate_locked_authority(
    plan: &AtomicApplyBatchPlan,
    environment: &ObjectStore,
    state: &ObjectStore,
    targets: &[TargetRoot],
    sources: &BatchSources,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    let manifest = EnvironmentManifest::from_toml(&required_text(environment, MANIFEST_PATH)?)
        .map_err(|_| stale_manifest())?;
    if derive_manifest_revision(&manifest).map_err(|_| stale_manifest())?
        != *plan.manifest_revision()
    {
        return Err(stale_manifest());
    }
    if required_text(state, STATE_PATH)? != plan.observed_local_state_text() {
        return Err(stale_state());
    }
    let reloaded = load_batch_sources(plan, &manifest, environment, limits)?;
    if reloaded.skills != sources.skills
        || reloaded.extensions != sources.extensions
        || reloaded.instructions != sources.instructions
        || reloaded.commands != sources.commands
        || reloaded.agents != sources.agents
        || reloaded.mcps != sources.mcps
    {
        return Err(stale_manifest());
    }
    for item in plan.items() {
        validate_item_authority(item, &manifest, &reloaded, targets, limits)?;
    }
    Ok(())
}

fn verify_batch(
    plan: &AtomicApplyBatchPlan,
    state: &ObjectStore,
    targets: &[TargetRoot],
    sources: &BatchSources,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    if required_text(state, STATE_PATH)? != plan.proposed_local_state_text() {
        return Err(verification_failed());
    }
    for item in plan.items() {
        let target = target_for(item, targets)?;
        match item {
            AtomicApplyItem::Skill(plan) => {
                let observation = observe_skill_destination(
                    &target.path.join(plan.relative_destination().as_str()),
                    limits,
                );
                let expected = if plan.disposition() == ApplyDisposition::Remove {
                    DestinationObservation::Absent
                } else {
                    DestinationObservation::Present {
                        layout: kitrove_agent_skills::SkillSourceLayout::Directory,
                        rendered_hash: plan.rendered().rendered_hash().clone(),
                    }
                };
                if observation != expected {
                    return Err(verification_failed());
                }
            }
            AtomicApplyItem::Extension(plan) => {
                let object = sources
                    .extensions
                    .get(plan.asset_id())
                    .ok_or_else(stale_manifest)?;
                let expected = if plan.disposition() == ApplyDisposition::Remove {
                    ExtensionDestinationObservation::Absent
                } else {
                    ExtensionDestinationObservation::Present {
                        layout: object.layout(),
                        object_hash: object.hash().clone(),
                    }
                };
                if observe_extension(&target.store, plan.relative_destination(), object, limits)?
                    != expected
                {
                    return Err(verification_failed());
                }
            }
            AtomicApplyItem::Instruction(plan) => {
                let expected = std::str::from_utf8(plan.document().rendered().bytes())
                    .map_err(|_| verification_failed())?;
                let max_bytes = crate::apply_batch::instruction_document_limit(plan.document())
                    .map_err(|_| verification_failed())?;
                if !target
                    .store
                    .exact_text_matches(
                        plan.document().relative_destination(),
                        expected,
                        plan.document().rendered().mode(),
                        max_bytes,
                    )
                    .map_err(|_| verification_failed())?
                {
                    return Err(verification_failed());
                }
            }
            AtomicApplyItem::PromptCommand(plan) => {
                let expected = std::str::from_utf8(plan.rendered().bytes())
                    .map_err(|_| verification_failed())?;
                if !target
                    .store
                    .exact_text_matches(
                        plan.relative_destination(),
                        expected,
                        plan.rendered().mode(),
                        PromptCommandLimits::default().max_document_bytes,
                    )
                    .map_err(|_| verification_failed())?
                {
                    return Err(verification_failed());
                }
            }
            AtomicApplyItem::PromptCommandRemoval(plan) => {
                if target
                    .store
                    .read_text(
                        plan.relative_destination(),
                        PromptCommandLimits::default().max_document_bytes,
                    )
                    .map_err(|_| verification_failed())?
                    .is_some()
                {
                    return Err(verification_failed());
                }
            }
            AtomicApplyItem::Agent(plan) => {
                let expected = std::str::from_utf8(plan.rendered().bytes())
                    .map_err(|_| verification_failed())?;
                if !target
                    .store
                    .exact_text_matches(
                        plan.relative_destination(),
                        expected,
                        plan.rendered().mode(),
                        AgentLimits::default().max_document_bytes,
                    )
                    .map_err(|_| verification_failed())?
                {
                    return Err(verification_failed());
                }
            }
            AtomicApplyItem::AgentRemoval(plan) => {
                if target
                    .store
                    .read_text(
                        plan.relative_destination(),
                        AgentLimits::default().max_document_bytes,
                    )
                    .map_err(|_| verification_failed())?
                    .is_some()
                {
                    return Err(verification_failed());
                }
            }
            AtomicApplyItem::Mcp(plan) => {
                let expected = std::str::from_utf8(plan.document().rendered().bytes())
                    .map_err(|_| verification_failed())?;
                if !target
                    .store
                    .exact_text_matches(
                        plan.document().relative_destination(),
                        expected,
                        plan.document().rendered().mode(),
                        crate::apply_batch::mcp_document_limit(plan.document())
                            .map_err(|_| verification_failed())?,
                    )
                    .map_err(|_| verification_failed())?
                {
                    return Err(verification_failed());
                }
            }
        }
    }
    Ok(())
}

fn cleanup_verified_batch(
    plan: &AtomicApplyBatchPlan,
    state: &ObjectStore,
    targets: &[TargetRoot],
    sources: &BatchSources,
    journal: &AtomicApplyBatchJournalCursor,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    for (index, item) in plan.items().iter().enumerate() {
        let target = target_for(item, targets)?;
        if item.disposition().requires_quarantine() {
            match item {
                AtomicApplyItem::Skill(plan) => {
                    let DestinationObservation::Present { rendered_hash, .. } =
                        plan.observed_destination()
                    else {
                        return Err(verification_failed());
                    };
                    apply_target::remove_exact(
                        &target.store,
                        journal.backup_target(index).map_err(journal_error)?,
                        &ApplyTargetIdentity::Skill(rendered_hash),
                        limits,
                    )
                    .map_err(|_| storage_failed())?;
                }
                AtomicApplyItem::Extension(plan) => {
                    let old = capture_old_extension(
                        &target.store,
                        journal.backup_target(index).map_err(journal_error)?,
                        plan,
                        limits,
                    )?;
                    apply_target::remove_exact(
                        &target.store,
                        journal.backup_target(index).map_err(journal_error)?,
                        &ApplyTargetIdentity::Extension(&old),
                        limits,
                    )
                    .map_err(|_| storage_failed())?;
                }
                AtomicApplyItem::Instruction(plan) => {
                    let old = plan
                        .document()
                        .observation()
                        .document_text()
                        .ok_or_else(verification_failed)?;
                    apply_target::remove_exact(
                        &target.store,
                        journal.backup_target(index).map_err(journal_error)?,
                        &ApplyTargetIdentity::ExactText {
                            text: old,
                            mode: plan.document().rendered().mode(),
                            max_bytes: crate::apply_batch::instruction_document_limit(
                                plan.document(),
                            )
                            .map_err(|_| verification_failed())?,
                        },
                        limits,
                    )
                    .map_err(|_| storage_failed())?;
                }
                AtomicApplyItem::PromptCommand(plan) => {
                    let old = plan
                        .observation()
                        .content_text()
                        .ok_or_else(verification_failed)?;
                    apply_target::remove_exact(
                        &target.store,
                        journal.backup_target(index).map_err(journal_error)?,
                        &ApplyTargetIdentity::ExactText {
                            text: old,
                            mode: plan.rendered().mode(),
                            max_bytes: PromptCommandLimits::default().max_document_bytes,
                        },
                        limits,
                    )
                    .map_err(|_| storage_failed())?;
                }
                AtomicApplyItem::PromptCommandRemoval(plan) => {
                    let old = plan
                        .observation()
                        .content_text()
                        .ok_or_else(verification_failed)?;
                    apply_target::remove_exact(
                        &target.store,
                        journal.backup_target(index).map_err(journal_error)?,
                        &ApplyTargetIdentity::ExactText {
                            text: old,
                            mode: plan.observation().mode(),
                            max_bytes: PromptCommandLimits::default().max_document_bytes,
                        },
                        limits,
                    )
                    .map_err(|_| storage_failed())?;
                }
                AtomicApplyItem::Agent(plan) => {
                    let old = plan
                        .observation()
                        .content_text()
                        .ok_or_else(verification_failed)?;
                    apply_target::remove_exact(
                        &target.store,
                        journal.backup_target(index).map_err(journal_error)?,
                        &ApplyTargetIdentity::ExactText {
                            text: old,
                            mode: plan.rendered().mode(),
                            max_bytes: AgentLimits::default().max_document_bytes,
                        },
                        limits,
                    )
                    .map_err(|_| storage_failed())?;
                }
                AtomicApplyItem::AgentRemoval(plan) => {
                    let old = plan
                        .observation()
                        .content_text()
                        .ok_or_else(verification_failed)?;
                    apply_target::remove_exact(
                        &target.store,
                        journal.backup_target(index).map_err(journal_error)?,
                        &ApplyTargetIdentity::ExactText {
                            text: old,
                            mode: plan.observation().mode(),
                            max_bytes: AgentLimits::default().max_document_bytes,
                        },
                        limits,
                    )
                    .map_err(|_| storage_failed())?;
                }
                AtomicApplyItem::Mcp(plan) => {
                    let old = plan
                        .document()
                        .observation()
                        .document_text()
                        .ok_or_else(verification_failed)?;
                    apply_target::remove_exact(
                        &target.store,
                        journal.backup_target(index).map_err(journal_error)?,
                        &ApplyTargetIdentity::ExactText {
                            text: old,
                            mode: plan.document().rendered().mode(),
                            max_bytes: crate::apply_batch::mcp_document_limit(plan.document())
                                .map_err(|_| verification_failed())?,
                        },
                        limits,
                    )
                    .map_err(|_| storage_failed())?;
                }
            }
        }
        if item.disposition().materializes_target() {
            apply_target::clear_staging(
                &target.store,
                journal.staging_target(index).map_err(journal_error)?,
                &new_identity(item, sources)?,
                limits,
            )
            .map_err(|_| storage_failed())?;
        }
    }
    state
        .remove_regular_file_if_present(journal.staging_state())
        .map_err(|_| storage_failed())?;
    journal.remove_terminal(state).map_err(journal_error)
}

fn portable_path(path: &str) -> PortablePath {
    PortablePath::parse(path).expect("fixed portable control path")
}

fn journal_error(_: crate::AtomicApplyBatchJournalError) -> AtomicApplyBatchTransactionError {
    storage_failed()
}

fn cleanup_error(error: MutationCleanupError) -> AtomicApplyBatchTransactionError {
    match error {
        MutationCleanupError::InvalidReservation => cleanup_limit(),
        MutationCleanupError::CleanupFailed => storage_failed(),
    }
}

fn cleanup_limit() -> AtomicApplyBatchTransactionError {
    AtomicApplyBatchTransactionError::new(
        "apply_batch.cleanup_limit",
        "the batch exceeds the supported mutation cleanup limit",
    )
}

fn ensure_no_pending_recovery(
    environment: &ObjectStore,
    state: &ObjectStore,
) -> Result<(), AtomicApplyBatchTransactionError> {
    let local = local_state_authority::any_journal_present(
        state,
        local_state_authority::ALL_LOCAL_STATE_RECOVERY,
        MAX_JOURNAL_BYTES,
    )
    .map_err(|_| storage_failed())?;
    let portable = local_state_authority::any_journal_present(
        environment,
        local_state_authority::ALL_PORTABLE_RECOVERY,
        MAX_JOURNAL_BYTES,
    )
    .map_err(|_| storage_failed())?;
    if local || portable {
        return Err(recovery_required());
    }
    Ok(())
}

fn ensure_no_foreign_recovery(
    environment: &ObjectStore,
    state: &ObjectStore,
) -> Result<(), AtomicApplyBatchTransactionError> {
    let local = local_state_authority::any_journal_present(
        state,
        &[
            local_state_authority::TRUST_JOURNAL_PATH,
            local_state_authority::TRUST_PENDING_PATH,
            local_state_authority::EXTENSION_APPLY_JOURNAL_PATH,
            local_state_authority::SKILL_APPLY_JOURNAL_PATH,
            local_state_authority::SKILL_APPLY_PENDING_PATH,
        ],
        MAX_JOURNAL_BYTES,
    )
    .map_err(|_| storage_failed())?;
    let portable = local_state_authority::any_journal_present(
        environment,
        local_state_authority::ALL_PORTABLE_RECOVERY,
        MAX_JOURNAL_BYTES,
    )
    .map_err(|_| storage_failed())?;
    if local || portable {
        return Err(recovery_required());
    }
    Ok(())
}

fn required_text(
    store: &ObjectStore,
    path: &str,
) -> Result<String, AtomicApplyBatchTransactionError> {
    store
        .read_text(
            &PortablePath::parse(path).expect("fixed portable control path"),
            MAX_CONTROL_BYTES,
        )
        .map_err(|_| storage_failed())?
        .ok_or_else(storage_failed)
}

macro_rules! transaction_error {
    ($name:ident, $code:literal, $message:literal) => {
        const fn $name() -> AtomicApplyBatchTransactionError {
            AtomicApplyBatchTransactionError::new($code, $message)
        }
    };
}

transaction_error!(
    storage_failed,
    "apply.batch_storage_failed",
    "atomic batch authority could not be read safely"
);
transaction_error!(
    root_overlap,
    "apply.batch_root_overlap",
    "environment and private-state roots must not overlap"
);
transaction_error!(
    lock_unavailable,
    "apply.batch_lock_unavailable",
    "an atomic batch mutation lock is unavailable"
);
transaction_error!(
    recovery_required,
    "apply.batch_recovery_required",
    "a pending transaction must recover before atomic batch validation"
);
transaction_error!(
    stale_manifest,
    "apply.batch_manifest_stale",
    "manifest or source-object authority changed after batch planning"
);
transaction_error!(
    stale_state,
    "apply.batch_state_stale",
    "machine-local state changed after batch planning"
);
transaction_error!(
    stale_target,
    "apply.batch_target_stale",
    "a target changed after batch planning"
);
transaction_error!(
    target_invalid,
    "apply.batch_target_invalid",
    "a canonical target root could not be opened safely"
);
transaction_error!(
    verification_failed,
    "apply.batch_verification_failed",
    "atomic batch target or machine state failed exact verification"
);
transaction_error!(
    recovery_blocked,
    "apply.batch_recovery_blocked",
    "atomic batch recovery authority is incomplete or changed"
);

#[cfg(test)]
#[path = "apply_batch_transaction_tests.rs"]
mod tests;
