use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_instructions::DEFAULT_MAX_INSTRUCTION_DOCUMENT_BYTES;
use kitrove_model::{
    AssetId, ContentHash, NormalizedDestination, PortablePath, ProfileId, Revision,
};
use serde::{Deserialize, Serialize};

use crate::apply_batch::{
    AGENT_BATCH_ITEM_TAG, AtomicApplyBatchPlan, AtomicApplyItem, BatchDigestItem,
    BatchExactFileDigestAuthority, BatchExtensionDigestAuthority, DIRECTORY_EXTENSION_LAYOUT_TAG,
    EXTENSION_BATCH_ITEM_TAG, INSTALL_DISPOSITION_TAG, INSTRUCTION_BATCH_ITEM_TAG,
    MANAGED_UPDATE_DISPOSITION_TAG, MAX_BATCH_PARTICIPANTS, MCP_BATCH_ITEM_TAG,
    NO_OP_DISPOSITION_TAG, PROMPT_COMMAND_BATCH_ITEM_TAG, REMOVE_DISPOSITION_TAG,
    RESTORE_DISPOSITION_TAG, SKILL_BATCH_ITEM_TAG, STANDALONE_EXTENSION_LAYOUT_TAG,
    derive_batch_digest_from_authority,
};
use crate::guarded_journal::{self, GuardedJournalError};
use crate::local_state_authority::{ATOMIC_APPLY_JOURNAL_PATH, ATOMIC_APPLY_PENDING_PATH};
use crate::native_extension::valid_native_extension_identity;
use crate::read_only_fs::RegularFileMode;
use crate::{
    ApplyDisposition, DestinationObservation, ExtensionDestinationObservation,
    NativeExtensionLayout, ObjectStore,
};

const JOURNAL_SCHEMA_VERSION: u32 = 6;
const MAX_BATCH_JOURNAL_BYTES: usize = 8 * 1024 * 1024;

/// Durable phase of a failure-atomic multi-target apply operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicApplyBatchPhase {
    Preparing,
    Prepared,
    QuarantiningOldTargets,
    OldTargetsQuarantined,
    CommittingNewTargets,
    NewTargetsCommitted,
    StateCommitted,
    Verified,
    RollingBack,
    RolledBack,
}

/// Read-only status of the durable batch journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicApplyBatchJournalStatus {
    NoJournal,
    Pending {
        phase: AtomicApplyBatchPhase,
        participant_count: usize,
    },
}

/// Stable, path- and content-redacted journal inspection failure.
#[derive(Clone, Eq, PartialEq)]
pub struct AtomicApplyBatchJournalError {
    code: &'static str,
    message: &'static str,
}

impl AtomicApplyBatchJournalError {
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

impl Debug for AtomicApplyBatchJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicApplyBatchJournalError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for AtomicApplyBatchJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AtomicApplyBatchJournalError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ParticipantKind {
    Skill,
    Extension,
    Instruction,
    PromptCommand,
    Agent,
    Mcp,
}

impl ParticipantKind {
    const fn digest_tag(self) -> u8 {
        match self {
            Self::Skill => SKILL_BATCH_ITEM_TAG,
            Self::Extension => EXTENSION_BATCH_ITEM_TAG,
            Self::Instruction => INSTRUCTION_BATCH_ITEM_TAG,
            Self::PromptCommand => PROMPT_COMMAND_BATCH_ITEM_TAG,
            Self::Agent => AGENT_BATCH_ITEM_TAG,
            Self::Mcp => MCP_BATCH_ITEM_TAG,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoredExtensionLayout {
    Standalone,
    Directory,
}

impl StoredExtensionLayout {
    const fn from_native(layout: NativeExtensionLayout) -> Self {
        match layout {
            NativeExtensionLayout::Standalone => Self::Standalone,
            NativeExtensionLayout::Directory => Self::Directory,
        }
    }

    const fn digest_tag(self) -> u8 {
        match self {
            Self::Standalone => STANDALONE_EXTENSION_LAYOUT_TAG,
            Self::Directory => DIRECTORY_EXTENSION_LAYOUT_TAG,
        }
    }

    fn entrypoint(self, native_id: &str) -> String {
        match self {
            Self::Standalone => format!("{native_id}.ts"),
            Self::Directory => "index.ts".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredExtensionAuthority {
    layout: StoredExtensionLayout,
    old_layout: Option<StoredExtensionLayout>,
    entrypoint: String,
    native_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredExactFileAuthority {
    mode: RegularFileMode,
    max_bytes: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoredDisposition {
    Install,
    NoOp,
    Restore,
    ManagedUpdate,
    Remove,
}

impl StoredDisposition {
    const fn from_apply(disposition: ApplyDisposition) -> Self {
        match disposition {
            ApplyDisposition::Install => Self::Install,
            ApplyDisposition::NoOp => Self::NoOp,
            ApplyDisposition::Restore => Self::Restore,
            ApplyDisposition::ManagedUpdate => Self::ManagedUpdate,
            ApplyDisposition::Remove => Self::Remove,
        }
    }

    const fn digest_tag(self) -> u8 {
        match self {
            Self::Install => INSTALL_DISPOSITION_TAG,
            Self::NoOp => NO_OP_DISPOSITION_TAG,
            Self::Restore => RESTORE_DISPOSITION_TAG,
            Self::ManagedUpdate => MANAGED_UPDATE_DISPOSITION_TAG,
            Self::Remove => REMOVE_DISPOSITION_TAG,
        }
    }

    const fn requires_quarantine(self) -> bool {
        matches!(self, Self::ManagedUpdate | Self::Remove)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ParticipantProgress {
    Unstaged,
    StagingPending,
    Prepared,
    QuarantinePending,
    Quarantined,
    CommitPending,
    Committed,
    Verified,
    RemovePending,
    Removed,
    RestorePending,
    RolledBack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchParticipantJournal {
    index: u32,
    kind: ParticipantKind,
    progress: ParticipantProgress,
    disposition: StoredDisposition,
    plan_digest: ContentHash,
    asset_id: AssetId,
    target_anchor: NormalizedDestination,
    destination: NormalizedDestination,
    relative_destination: PortablePath,
    staging_target: PortablePath,
    backup_target: PortablePath,
    old_target_hash: Option<ContentHash>,
    new_target_hash: ContentHash,
    extension: Option<StoredExtensionAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exact_file: Option<StoredExactFileAuthority>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AtomicApplyBatchJournal {
    schema_version: u32,
    phase: AtomicApplyBatchPhase,
    batch_digest: ContentHash,
    manifest_revision: Revision,
    active_profile: Option<ProfileId>,
    staging_state: PortablePath,
    old_state_hash: ContentHash,
    new_state_hash: ContentHash,
    participants: Vec<BatchParticipantJournal>,
}

/// In-memory cursor whose transitions are installed through guarded replacement before mutation.
pub(crate) struct AtomicApplyBatchJournalCursor {
    journal: AtomicApplyBatchJournal,
    encoded: String,
}

impl AtomicApplyBatchJournalCursor {
    pub(crate) fn load(state: &ObjectStore) -> Result<Option<Self>, AtomicApplyBatchJournalError> {
        guarded_journal::reconcile(
            state,
            &journal_path(),
            &journal_pending_path(),
            MAX_BATCH_JOURNAL_BYTES,
            parse_journal,
            valid_journal_transition,
            journal_invalid,
        )
        .map_err(map_guarded_storage)?;
        let Some(encoded) = state
            .read_text(&journal_path(), MAX_BATCH_JOURNAL_BYTES)
            .map_err(|_| journal_storage_failed())?
        else {
            return Ok(None);
        };
        let journal = parse_journal(&encoded)?;
        Ok(Some(Self { journal, encoded }))
    }

    pub(crate) fn install(
        state: &ObjectStore,
        plan: &AtomicApplyBatchPlan,
    ) -> Result<Self, AtomicApplyBatchJournalError> {
        let journal = initial_journal(plan)?;
        let encoded = journal.encoded()?;
        state
            .replace_text_atomically_guarded(
                &journal_pending_path(),
                &journal_path(),
                None,
                &encoded,
                MAX_BATCH_JOURNAL_BYTES,
            )
            .map_err(|_| journal_storage_failed())?;
        Ok(Self { journal, encoded })
    }

    pub(crate) fn staging_state(&self) -> &PortablePath {
        &self.journal.staging_state
    }

    pub(crate) fn encoded_authority(&self) -> &str {
        &self.encoded
    }

    pub(crate) const fn phase(&self) -> AtomicApplyBatchPhase {
        self.journal.phase
    }

    pub(crate) fn old_state_hash(&self) -> &ContentHash {
        &self.journal.old_state_hash
    }

    pub(crate) fn new_state_hash(&self) -> &ContentHash {
        &self.journal.new_state_hash
    }

    pub(crate) fn manifest_revision(&self) -> &Revision {
        &self.journal.manifest_revision
    }

    pub(crate) fn participants(&self) -> &[BatchParticipantJournal] {
        &self.journal.participants
    }

    pub(crate) fn staging_target(
        &self,
        index: usize,
    ) -> Result<&PortablePath, AtomicApplyBatchJournalError> {
        self.journal
            .participants
            .get(index)
            .map(|participant| &participant.staging_target)
            .ok_or_else(journal_invalid)
    }

    pub(crate) fn transition_participant(
        &mut self,
        state: &ObjectStore,
        index: usize,
        progress: ParticipantProgress,
    ) -> Result<(), AtomicApplyBatchJournalError> {
        self.persist_transition(state, |journal| {
            journal.transition_participant(index, progress)
        })
    }

    pub(crate) fn transition_phase(
        &mut self,
        state: &ObjectStore,
        phase: AtomicApplyBatchPhase,
    ) -> Result<(), AtomicApplyBatchJournalError> {
        self.persist_transition(state, |journal| journal.transition_phase(phase))
    }

    pub(crate) fn backup_target(
        &self,
        index: usize,
    ) -> Result<&PortablePath, AtomicApplyBatchJournalError> {
        self.journal
            .participants
            .get(index)
            .map(|participant| &participant.backup_target)
            .ok_or_else(journal_invalid)
    }

    pub(crate) fn remove_terminal(
        &self,
        state: &ObjectStore,
    ) -> Result<(), AtomicApplyBatchJournalError> {
        if !matches!(
            self.journal.phase,
            AtomicApplyBatchPhase::Verified | AtomicApplyBatchPhase::RolledBack
        ) {
            return Err(journal_invalid());
        }
        state
            .remove_regular_file_if_present(&journal_path())
            .map_err(|_| journal_storage_failed())?;
        state
            .remove_regular_file_if_present(&journal_pending_path())
            .map_err(|_| journal_storage_failed())
    }

    fn persist_transition(
        &mut self,
        state: &ObjectStore,
        transition: impl FnOnce(
            &mut AtomicApplyBatchJournal,
        ) -> Result<(), AtomicApplyBatchJournalError>,
    ) -> Result<(), AtomicApplyBatchJournalError> {
        let mut next = self.journal.clone();
        transition(&mut next)?;
        let next_encoded = next.encoded()?;
        state
            .replace_text_atomically_guarded(
                &journal_pending_path(),
                &journal_path(),
                Some(&self.encoded),
                &next_encoded,
                MAX_BATCH_JOURNAL_BYTES,
            )
            .map_err(|_| journal_storage_failed())?;
        self.journal = next;
        self.encoded = next_encoded;
        Ok(())
    }
}

impl BatchParticipantJournal {
    pub(crate) const fn kind(&self) -> ParticipantKind {
        self.kind
    }

    pub(crate) const fn progress(&self) -> ParticipantProgress {
        self.progress
    }

    pub(crate) const fn disposition(&self) -> StoredDisposition {
        self.disposition
    }

    pub(crate) fn target_anchor(&self) -> &NormalizedDestination {
        &self.target_anchor
    }

    pub(crate) fn relative_destination(&self) -> &PortablePath {
        &self.relative_destination
    }

    pub(crate) fn staging_target(&self) -> &PortablePath {
        &self.staging_target
    }

    pub(crate) fn backup_target(&self) -> &PortablePath {
        &self.backup_target
    }

    pub(crate) fn old_target_hash(&self) -> Option<&ContentHash> {
        self.old_target_hash.as_ref()
    }

    pub(crate) fn new_target_hash(&self) -> &ContentHash {
        &self.new_target_hash
    }

    pub(crate) fn extension(&self) -> Option<&StoredExtensionAuthority> {
        self.extension.as_ref()
    }

    pub(crate) fn exact_file(&self) -> Option<&StoredExactFileAuthority> {
        self.exact_file.as_ref()
    }
}

impl StoredExactFileAuthority {
    pub(crate) const fn mode(&self) -> RegularFileMode {
        self.mode
    }

    pub(crate) const fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

impl StoredExtensionAuthority {
    pub(crate) fn layout(&self) -> NativeExtensionLayout {
        self.layout.into_native()
    }

    pub(crate) fn old_layout(&self) -> Option<NativeExtensionLayout> {
        self.old_layout.map(StoredExtensionLayout::into_native)
    }

    pub(crate) fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    pub(crate) fn native_id(&self) -> &str {
        &self.native_id
    }
}

impl StoredExtensionLayout {
    const fn into_native(self) -> NativeExtensionLayout {
        match self {
            Self::Standalone => NativeExtensionLayout::Standalone,
            Self::Directory => NativeExtensionLayout::Directory,
        }
    }
}

fn map_guarded_storage(
    error: GuardedJournalError<AtomicApplyBatchJournalError>,
) -> AtomicApplyBatchJournalError {
    match error {
        GuardedJournalError::Storage => journal_storage_failed(),
        GuardedJournalError::Authority(error) => error,
    }
}

fn journal_path() -> PortablePath {
    PortablePath::parse(ATOMIC_APPLY_JOURNAL_PATH).expect("fixed journal path")
}

fn journal_pending_path() -> PortablePath {
    PortablePath::parse(ATOMIC_APPLY_PENDING_PATH).expect("fixed journal path")
}

pub(crate) fn validate_prepared_plan(
    plan: &AtomicApplyBatchPlan,
) -> Result<(), AtomicApplyBatchJournalError> {
    let mut journal = initial_journal(plan)?;
    journal.validate_forward_path()?;
    journal.encoded().map(|_| ())
}

fn initial_journal(
    plan: &AtomicApplyBatchPlan,
) -> Result<AtomicApplyBatchJournal, AtomicApplyBatchJournalError> {
    let participants = plan
        .items()
        .iter()
        .enumerate()
        .map(|(index, item)| prepared_participant(plan.digest(), index, item))
        .collect::<Result<Vec<_>, _>>()?;
    let journal = AtomicApplyBatchJournal {
        schema_version: JOURNAL_SCHEMA_VERSION,
        phase: AtomicApplyBatchPhase::Preparing,
        batch_digest: plan.digest().clone(),
        manifest_revision: plan.manifest_revision().clone(),
        active_profile: plan.active_profile().cloned(),
        staging_state: expected_state_path(plan.digest())?,
        old_state_hash: ContentHash::digest(plan.observed_local_state_text().as_bytes()),
        new_state_hash: ContentHash::digest(plan.proposed_local_state_text().as_bytes()),
        participants,
    };
    validate_journal(&journal)?;
    Ok(journal)
}

impl AtomicApplyBatchJournal {
    fn validate_forward_path(&mut self) -> Result<(), AtomicApplyBatchJournalError> {
        for index in 0..self.participants.len() {
            self.transition_participant(index, ParticipantProgress::StagingPending)?;
            self.transition_participant(index, ParticipantProgress::Prepared)?;
        }
        self.transition_phase(AtomicApplyBatchPhase::Prepared)?;
        self.transition_phase(AtomicApplyBatchPhase::QuarantiningOldTargets)?;
        for index in 0..self.participants.len() {
            if self.participants[index].disposition.requires_quarantine() {
                self.transition_participant(index, ParticipantProgress::QuarantinePending)?;
                self.transition_participant(index, ParticipantProgress::Quarantined)?;
            }
        }
        self.transition_phase(AtomicApplyBatchPhase::OldTargetsQuarantined)?;
        self.transition_phase(AtomicApplyBatchPhase::CommittingNewTargets)?;
        for index in 0..self.participants.len() {
            if self.participants[index].disposition == StoredDisposition::NoOp {
                self.transition_participant(index, ParticipantProgress::Committed)?;
            } else {
                self.transition_participant(index, ParticipantProgress::CommitPending)?;
                self.transition_participant(index, ParticipantProgress::Committed)?;
            }
        }
        self.transition_phase(AtomicApplyBatchPhase::NewTargetsCommitted)?;
        self.transition_phase(AtomicApplyBatchPhase::StateCommitted)?;
        for index in 0..self.participants.len() {
            self.transition_participant(index, ParticipantProgress::Verified)?;
        }
        self.transition_phase(AtomicApplyBatchPhase::Verified)?;
        validate_journal(self)
    }

    fn transition_phase(
        &mut self,
        next: AtomicApplyBatchPhase,
    ) -> Result<(), AtomicApplyBatchJournalError> {
        if !valid_phase_transition(self.phase, next) {
            return Err(journal_invalid());
        }
        self.phase = next;
        Ok(())
    }

    fn transition_participant(
        &mut self,
        index: usize,
        next: ParticipantProgress,
    ) -> Result<(), AtomicApplyBatchJournalError> {
        let participant = self
            .participants
            .get_mut(index)
            .ok_or_else(journal_invalid)?;
        if !valid_participant_transition(
            self.phase,
            participant.disposition,
            participant.progress,
            next,
        ) {
            return Err(journal_invalid());
        }
        participant.progress = next;
        Ok(())
    }

    fn encoded(&self) -> Result<String, AtomicApplyBatchJournalError> {
        validate_journal(self)?;
        let mut encoded = serde_json::to_string_pretty(self).map_err(|_| journal_invalid())?;
        encoded.push('\n');
        if encoded.len() > MAX_BATCH_JOURNAL_BYTES {
            return Err(journal_invalid());
        }
        Ok(encoded)
    }
}

fn prepared_participant(
    batch_digest: &ContentHash,
    index: usize,
    item: &AtomicApplyItem,
) -> Result<BatchParticipantJournal, AtomicApplyBatchJournalError> {
    let authority = participant_authority(item)?;
    Ok(BatchParticipantJournal {
        index: u32::try_from(index).map_err(|_| journal_invalid())?,
        kind: authority.kind,
        progress: ParticipantProgress::Unstaged,
        disposition: StoredDisposition::from_apply(item.disposition()),
        plan_digest: item.digest().clone(),
        asset_id: item.asset_id().clone(),
        target_anchor: item.target_anchor().map_err(|_| journal_invalid())?,
        destination: item.destination().clone(),
        relative_destination: item.relative_destination().clone(),
        staging_target: expected_participant_path(
            batch_digest,
            index,
            "target",
            item.relative_destination(),
        )?,
        backup_target: expected_participant_path(
            batch_digest,
            index,
            "backup",
            item.relative_destination(),
        )?,
        old_target_hash: authority.old_target_hash,
        new_target_hash: authority.new_target_hash,
        extension: authority.extension,
        exact_file: authority.exact_file,
    })
}

struct ParticipantAuthority {
    kind: ParticipantKind,
    old_target_hash: Option<ContentHash>,
    new_target_hash: ContentHash,
    extension: Option<StoredExtensionAuthority>,
    exact_file: Option<StoredExactFileAuthority>,
}

fn participant_authority(
    item: &AtomicApplyItem,
) -> Result<ParticipantAuthority, AtomicApplyBatchJournalError> {
    match item {
        AtomicApplyItem::Skill(plan) => Ok(ParticipantAuthority {
            kind: ParticipantKind::Skill,
            old_target_hash: match plan.observed_destination() {
                DestinationObservation::Absent => None,
                DestinationObservation::Present { rendered_hash, .. } => {
                    Some(rendered_hash.clone())
                }
                DestinationObservation::Unsafe => return Err(journal_invalid()),
            },
            new_target_hash: if plan.disposition() == ApplyDisposition::Remove {
                crate::apply_batch::absent_target_hash().clone()
            } else {
                plan.rendered().rendered_hash().clone()
            },
            extension: None,
            exact_file: None,
        }),
        AtomicApplyItem::Extension(plan) => {
            let layout = StoredExtensionLayout::from_native(plan.rendered().layout());
            let native_id = plan.rendered().native_id().as_str().to_owned();
            let entrypoint = layout.entrypoint(&native_id);
            let (old_target_hash, old_layout) = match plan.observed_destination() {
                ExtensionDestinationObservation::Absent => (None, None),
                ExtensionDestinationObservation::Present {
                    layout,
                    object_hash,
                } => (
                    Some(object_hash.clone()),
                    Some(StoredExtensionLayout::from_native(*layout)),
                ),
                ExtensionDestinationObservation::Unsafe => return Err(journal_invalid()),
            };
            Ok(ParticipantAuthority {
                kind: ParticipantKind::Extension,
                old_target_hash,
                new_target_hash: if plan.disposition() == ApplyDisposition::Remove {
                    crate::apply_batch::absent_target_hash().clone()
                } else {
                    plan.rendered().rendered_hash().clone()
                },
                extension: Some(StoredExtensionAuthority {
                    layout,
                    old_layout,
                    entrypoint,
                    native_id,
                }),
                exact_file: None,
            })
        }
        AtomicApplyItem::Instruction(plan) => {
            let authority = item.digest_authority().map_err(|_| journal_invalid())?;
            let instruction = authority.exact_file.ok_or_else(journal_invalid)?;
            Ok(ParticipantAuthority {
                kind: ParticipantKind::Instruction,
                old_target_hash: plan.document().observation().document_hash().cloned(),
                new_target_hash: plan.document().rendered().document_hash().clone(),
                extension: None,
                exact_file: Some(StoredExactFileAuthority {
                    mode: plan.document().rendered().mode(),
                    max_bytes: instruction.max_bytes,
                }),
            })
        }
        AtomicApplyItem::PromptCommand(plan) => {
            let authority = item.digest_authority().map_err(|_| journal_invalid())?;
            let exact_file = authority.exact_file.ok_or_else(journal_invalid)?;
            Ok(ParticipantAuthority {
                kind: ParticipantKind::PromptCommand,
                old_target_hash: plan.observation().content_hash().cloned(),
                new_target_hash: plan.rendered().content_hash().clone(),
                extension: None,
                exact_file: Some(StoredExactFileAuthority {
                    mode: plan.rendered().mode(),
                    max_bytes: exact_file.max_bytes,
                }),
            })
        }
        AtomicApplyItem::PromptCommandRemoval(plan) => {
            let authority = item.digest_authority().map_err(|_| journal_invalid())?;
            let exact_file = authority.exact_file.ok_or_else(journal_invalid)?;
            Ok(ParticipantAuthority {
                kind: ParticipantKind::PromptCommand,
                old_target_hash: plan.observation().content_hash().cloned(),
                new_target_hash: crate::apply_batch::absent_target_hash().clone(),
                extension: None,
                exact_file: Some(StoredExactFileAuthority {
                    mode: plan.observation().mode(),
                    max_bytes: exact_file.max_bytes,
                }),
            })
        }
        AtomicApplyItem::Agent(plan) => {
            let authority = item.digest_authority().map_err(|_| journal_invalid())?;
            let exact_file = authority.exact_file.ok_or_else(journal_invalid)?;
            Ok(ParticipantAuthority {
                kind: ParticipantKind::Agent,
                old_target_hash: plan.observation().content_hash().cloned(),
                new_target_hash: plan.rendered().content_hash().clone(),
                extension: None,
                exact_file: Some(StoredExactFileAuthority {
                    mode: plan.rendered().mode(),
                    max_bytes: exact_file.max_bytes,
                }),
            })
        }
        AtomicApplyItem::AgentRemoval(plan) => {
            let authority = item.digest_authority().map_err(|_| journal_invalid())?;
            let exact_file = authority.exact_file.ok_or_else(journal_invalid)?;
            Ok(ParticipantAuthority {
                kind: ParticipantKind::Agent,
                old_target_hash: plan.observation().content_hash().cloned(),
                new_target_hash: crate::apply_batch::absent_target_hash().clone(),
                extension: None,
                exact_file: Some(StoredExactFileAuthority {
                    mode: plan.observation().mode(),
                    max_bytes: exact_file.max_bytes,
                }),
            })
        }
        AtomicApplyItem::Mcp(plan) => {
            let authority = item.digest_authority().map_err(|_| journal_invalid())?;
            let exact_file = authority.exact_file.ok_or_else(journal_invalid)?;
            Ok(ParticipantAuthority {
                kind: ParticipantKind::Mcp,
                old_target_hash: plan
                    .document()
                    .observation()
                    .parsed()
                    .map(kitrove_mcp::ObservedMcpDocument::exact_document_hash)
                    .cloned(),
                new_target_hash: plan.document().rendered().document_hash().clone(),
                extension: None,
                exact_file: Some(StoredExactFileAuthority {
                    mode: plan.document().rendered().mode(),
                    max_bytes: exact_file.max_bytes,
                }),
            })
        }
    }
}

/// Inspects the durable batch journal without creating or repairing private state.
pub fn inspect_atomic_apply_batch_journal(
    state_root: &Path,
) -> Result<AtomicApplyBatchJournalStatus, AtomicApplyBatchJournalError> {
    let state = ObjectStore::open_private_state(state_root).map_err(|_| inspection_failed())?;
    let live = journal_path();
    let pending = journal_pending_path();
    let Some(journal) = guarded_journal::inspect(
        &state,
        &live,
        &pending,
        MAX_BATCH_JOURNAL_BYTES,
        parse_journal,
        valid_journal_transition,
        journal_invalid,
    )
    .map_err(|error| match error {
        GuardedJournalError::Storage => inspection_failed(),
        GuardedJournalError::Authority(error) => error,
    })?
    else {
        return Ok(AtomicApplyBatchJournalStatus::NoJournal);
    };
    Ok(AtomicApplyBatchJournalStatus::Pending {
        phase: journal.phase,
        participant_count: journal.participants.len(),
    })
}

fn parse_journal(encoded: &str) -> Result<AtomicApplyBatchJournal, AtomicApplyBatchJournalError> {
    let journal = serde_json::from_str(encoded).map_err(|_| journal_invalid())?;
    validate_journal(&journal)?;
    Ok(journal)
}

fn valid_journal_transition(old: &AtomicApplyBatchJournal, next: &AtomicApplyBatchJournal) -> bool {
    if !same_transition_authority(old, next) {
        return false;
    }
    if old.phase != next.phase {
        return old
            .participants
            .iter()
            .zip(&next.participants)
            .all(|(old, next)| old.progress == next.progress)
            && valid_phase_transition(old.phase, next.phase);
    }
    let mut changes = old
        .participants
        .iter()
        .zip(&next.participants)
        .filter(|(old, next)| old.progress != next.progress);
    let Some((old_participant, next_participant)) = changes.next() else {
        return false;
    };
    changes.next().is_none()
        && valid_participant_transition(
            old.phase,
            old_participant.disposition,
            old_participant.progress,
            next_participant.progress,
        )
}

fn same_transition_authority(
    old: &AtomicApplyBatchJournal,
    next: &AtomicApplyBatchJournal,
) -> bool {
    let mut expected = old.clone();
    expected.phase = next.phase;
    for (expected, next) in expected.participants.iter_mut().zip(&next.participants) {
        expected.progress = next.progress;
    }
    expected == *next
}

const fn valid_phase_transition(old: AtomicApplyBatchPhase, next: AtomicApplyBatchPhase) -> bool {
    use AtomicApplyBatchPhase as Phase;

    matches!(
        (old, next),
        (Phase::Preparing, Phase::Prepared)
            | (Phase::Prepared, Phase::QuarantiningOldTargets)
            | (Phase::QuarantiningOldTargets, Phase::OldTargetsQuarantined)
            | (Phase::OldTargetsQuarantined, Phase::CommittingNewTargets)
            | (Phase::CommittingNewTargets, Phase::NewTargetsCommitted)
            | (Phase::NewTargetsCommitted, Phase::StateCommitted)
            | (Phase::StateCommitted, Phase::Verified)
            | (Phase::Preparing, Phase::RollingBack)
            | (Phase::Prepared, Phase::RollingBack)
            | (Phase::QuarantiningOldTargets, Phase::RollingBack)
            | (Phase::OldTargetsQuarantined, Phase::RollingBack)
            | (Phase::CommittingNewTargets, Phase::RollingBack)
            | (Phase::NewTargetsCommitted, Phase::RollingBack)
            | (Phase::RollingBack, Phase::RolledBack)
    )
}

fn valid_participant_transition(
    phase: AtomicApplyBatchPhase,
    disposition: StoredDisposition,
    old: ParticipantProgress,
    next: ParticipantProgress,
) -> bool {
    use AtomicApplyBatchPhase as Phase;
    use ParticipantProgress as Progress;

    match phase {
        Phase::Preparing => matches!(
            (old, next),
            (Progress::Unstaged, Progress::StagingPending)
                | (Progress::StagingPending, Progress::Prepared)
        ),
        Phase::QuarantiningOldTargets => {
            matches!(
                (old, next),
                (Progress::Prepared, Progress::QuarantinePending)
                    | (Progress::QuarantinePending, Progress::Quarantined)
            ) && disposition.requires_quarantine()
        }
        Phase::CommittingNewTargets => {
            matches!(
                (old, next),
                (
                    Progress::Prepared | Progress::Quarantined,
                    Progress::CommitPending
                ) | (Progress::CommitPending, Progress::Committed)
            ) || (disposition == StoredDisposition::NoOp
                && old == Progress::Prepared
                && next == Progress::Committed)
        }
        Phase::StateCommitted => old == Progress::Committed && next == Progress::Verified,
        Phase::RollingBack => valid_rollback_transition(disposition, old, next),
        Phase::Prepared
        | Phase::OldTargetsQuarantined
        | Phase::NewTargetsCommitted
        | Phase::Verified
        | Phase::RolledBack => false,
    }
}

fn valid_rollback_transition(
    disposition: StoredDisposition,
    old: ParticipantProgress,
    next: ParticipantProgress,
) -> bool {
    use ParticipantProgress as Progress;

    match (old, next) {
        (
            Progress::Unstaged | Progress::StagingPending | Progress::Prepared,
            Progress::RolledBack,
        ) => true,
        (Progress::CommitPending, Progress::RemovePending)
        | (Progress::RemovePending, Progress::Removed)
        | (Progress::Committed, Progress::RemovePending) => disposition != StoredDisposition::NoOp,
        (Progress::QuarantinePending, Progress::RolledBack) => disposition.requires_quarantine(),
        (Progress::QuarantinePending | Progress::Quarantined, Progress::RestorePending)
        | (Progress::RestorePending, Progress::RolledBack) => disposition.requires_quarantine(),
        (Progress::CommitPending | Progress::Committed, Progress::RestorePending) => {
            disposition == StoredDisposition::Remove
        }
        (Progress::CommitPending, Progress::RolledBack) => {
            matches!(
                disposition,
                StoredDisposition::Install | StoredDisposition::Restore
            )
        }
        (Progress::Committed, Progress::RolledBack) => disposition == StoredDisposition::NoOp,
        (Progress::Removed, Progress::RestorePending) => {
            disposition == StoredDisposition::ManagedUpdate
        }
        (Progress::Removed, Progress::RolledBack) => {
            disposition != StoredDisposition::ManagedUpdate
        }
        _ => false,
    }
}

fn validate_journal(journal: &AtomicApplyBatchJournal) -> Result<(), AtomicApplyBatchJournalError> {
    if journal.schema_version != JOURNAL_SCHEMA_VERSION
        || journal.participants.is_empty()
        || journal.participants.len() > MAX_BATCH_PARTICIPANTS
        || journal.staging_state != expected_state_path(&journal.batch_digest)?
    {
        return Err(journal_invalid());
    }

    let mut destinations = BTreeSet::new();
    let mut plan_digests = BTreeSet::new();
    for (index, participant) in journal.participants.iter().enumerate() {
        if participant.index != u32::try_from(index).map_err(|_| journal_invalid())?
            || !destinations.insert(participant.destination.as_str())
            || !plan_digests.insert(&participant.plan_digest)
            || participant.destination
                != joined_destination(
                    &participant.target_anchor,
                    &participant.relative_destination,
                )?
            || participant.staging_target
                != expected_participant_path(
                    &journal.batch_digest,
                    index,
                    "target",
                    &participant.relative_destination,
                )?
            || participant.backup_target
                != expected_participant_path(
                    &journal.batch_digest,
                    index,
                    "backup",
                    &participant.relative_destination,
                )?
            || participant
                .relative_destination
                .as_str()
                .starts_with(".kitrove/")
            || !valid_kind_authority(participant)
            || !valid_hash_authority(participant)
            || !valid_progress(journal.phase, participant)
        {
            return Err(journal_invalid());
        }
    }
    if journal.participants.iter().any(|participant| {
        participant
            .destination
            .strict_ancestor_strings()
            .any(|ancestor| destinations.contains(ancestor))
    }) {
        return Err(journal_invalid());
    }
    if journal
        .participants
        .windows(2)
        .any(|pair| participant_order_key(&pair[0]) >= participant_order_key(&pair[1]))
    {
        return Err(journal_invalid());
    }
    let digest_items = journal
        .participants
        .iter()
        .map(|participant| BatchDigestItem {
            kind_tag: participant.kind.digest_tag(),
            asset_id: participant.asset_id.as_str(),
            destination: participant.destination.as_str(),
            relative_destination: participant.relative_destination.as_str(),
            plan_digest: participant.plan_digest.as_str(),
            disposition_tag: participant.disposition.digest_tag(),
            old_target_hash: participant
                .old_target_hash
                .as_ref()
                .map(ContentHash::as_str),
            new_target_hash: participant.new_target_hash.as_str(),
            extension: participant.extension.as_ref().map(|extension| {
                BatchExtensionDigestAuthority {
                    layout_tag: extension.layout.digest_tag(),
                    old_layout_tag: extension.old_layout.map(StoredExtensionLayout::digest_tag),
                    native_id: extension.native_id.as_str(),
                }
            }),
            exact_file: participant.exact_file.as_ref().map(|instruction| {
                BatchExactFileDigestAuthority {
                    unix_mode: instruction.mode.unix_mode(),
                    readonly: instruction.mode.readonly(),
                    max_bytes: instruction.max_bytes,
                }
            }),
        })
        .collect::<Vec<_>>();
    let expected_digest = derive_batch_digest_from_authority(
        &digest_items,
        &journal.manifest_revision,
        &journal.old_state_hash,
        &journal.new_state_hash,
        journal.active_profile.as_ref(),
    )
    .map_err(|_| journal_invalid())?;
    if journal.batch_digest != expected_digest {
        return Err(journal_invalid());
    }
    Ok(())
}

fn valid_kind_authority(participant: &BatchParticipantJournal) -> bool {
    match (
        participant.kind,
        participant.extension.as_ref(),
        participant.exact_file.as_ref(),
    ) {
        (ParticipantKind::Skill, None, None) => true,
        (ParticipantKind::Extension, Some(extension), None) => {
            let Some(destination_leaf) = participant
                .relative_destination
                .as_str()
                .rsplit_once('/')
                .map(|(_, leaf)| leaf)
            else {
                return false;
            };
            valid_native_extension_identity(
                match extension.layout {
                    StoredExtensionLayout::Standalone => NativeExtensionLayout::Standalone,
                    StoredExtensionLayout::Directory => NativeExtensionLayout::Directory,
                },
                &extension.entrypoint,
                &extension.native_id,
                destination_leaf,
            ) && valid_old_extension_layout(participant, extension)
        }
        (ParticipantKind::Instruction, None, Some(instruction)) => {
            instruction.mode.is_valid_for_platform()
                && instruction.max_bytes > 0
                && instruction.max_bytes <= DEFAULT_MAX_INSTRUCTION_DOCUMENT_BYTES + 1
        }
        (ParticipantKind::PromptCommand, None, Some(command)) => {
            command.mode.is_valid_for_platform()
                && command.max_bytes > 0
                && command.max_bytes
                    <= kitrove_prompt_commands::PromptCommandLimits::default().max_document_bytes
        }
        (ParticipantKind::Agent, None, Some(agent)) => {
            agent.mode.is_valid_for_platform()
                && agent.max_bytes > 0
                && agent.max_bytes <= kitrove_agents::AgentLimits::default().max_document_bytes
        }
        (ParticipantKind::Mcp, None, Some(mcp)) => {
            mcp.mode.is_valid_for_platform()
                && mcp.max_bytes > 0
                && mcp.max_bytes <= kitrove_mcp::McpParseLimits::default().max_document_bytes + 1
        }
        _ => false,
    }
}

fn valid_old_extension_layout(
    participant: &BatchParticipantJournal,
    extension: &StoredExtensionAuthority,
) -> bool {
    match participant.old_target_hash {
        Some(_) => extension.old_layout == Some(extension.layout),
        None => extension.old_layout.is_none(),
    }
}

fn participant_order_key(
    participant: &BatchParticipantJournal,
) -> (&str, &AssetId, u8, &ContentHash) {
    (
        participant.destination.as_str(),
        &participant.asset_id,
        participant.kind.digest_tag(),
        &participant.plan_digest,
    )
}

fn valid_hash_authority(participant: &BatchParticipantJournal) -> bool {
    match participant.disposition {
        StoredDisposition::Install | StoredDisposition::Restore => {
            participant.old_target_hash.is_none()
        }
        StoredDisposition::NoOp => {
            participant.old_target_hash.as_ref() == Some(&participant.new_target_hash)
        }
        StoredDisposition::ManagedUpdate => participant
            .old_target_hash
            .as_ref()
            .is_some_and(|old| old != &participant.new_target_hash),
        StoredDisposition::Remove => {
            matches!(
                participant.kind,
                ParticipantKind::Skill
                    | ParticipantKind::Extension
                    | ParticipantKind::PromptCommand
                    | ParticipantKind::Agent
            ) && participant.old_target_hash.is_some()
                && participant.new_target_hash == *crate::apply_batch::absent_target_hash()
        }
    }
}

fn valid_progress(phase: AtomicApplyBatchPhase, participant: &BatchParticipantJournal) -> bool {
    use AtomicApplyBatchPhase as Batch;
    use ParticipantProgress as Participant;

    let progress = participant.progress;
    let requires_quarantine = participant.disposition.requires_quarantine();
    match phase {
        Batch::Preparing => matches!(
            progress,
            Participant::Unstaged | Participant::StagingPending | Participant::Prepared
        ),
        Batch::Prepared => progress == Participant::Prepared,
        Batch::QuarantiningOldTargets => matches!(
            progress,
            Participant::Prepared | Participant::QuarantinePending | Participant::Quarantined
        ),
        Batch::OldTargetsQuarantined => match progress {
            Participant::Quarantined => requires_quarantine,
            Participant::Prepared => !requires_quarantine,
            _ => false,
        },
        Batch::CommittingNewTargets => matches!(
            progress,
            Participant::Prepared
                | Participant::Quarantined
                | Participant::CommitPending
                | Participant::Committed
        ),
        Batch::NewTargetsCommitted | Batch::StateCommitted => {
            matches!(progress, Participant::Committed | Participant::Verified)
        }
        Batch::Verified => progress == Participant::Verified,
        Batch::RollingBack => valid_rollback_progress(participant),
        Batch::RolledBack => progress == Participant::RolledBack,
    }
}

fn valid_rollback_progress(participant: &BatchParticipantJournal) -> bool {
    use ParticipantProgress as Progress;

    match participant.disposition {
        StoredDisposition::ManagedUpdate => matches!(
            participant.progress,
            Progress::Unstaged
                | Progress::StagingPending
                | Progress::Prepared
                | Progress::QuarantinePending
                | Progress::Quarantined
                | Progress::CommitPending
                | Progress::Committed
                | Progress::RemovePending
                | Progress::Removed
                | Progress::RestorePending
                | Progress::RolledBack
        ),
        StoredDisposition::Remove => matches!(
            participant.progress,
            Progress::Unstaged
                | Progress::StagingPending
                | Progress::Prepared
                | Progress::QuarantinePending
                | Progress::Quarantined
                | Progress::CommitPending
                | Progress::Committed
                | Progress::RestorePending
                | Progress::RolledBack
        ),
        StoredDisposition::Install | StoredDisposition::Restore => matches!(
            participant.progress,
            Progress::Unstaged
                | Progress::StagingPending
                | Progress::Prepared
                | Progress::CommitPending
                | Progress::Committed
                | Progress::RemovePending
                | Progress::Removed
                | Progress::RolledBack
        ),
        StoredDisposition::NoOp => matches!(
            participant.progress,
            Progress::Unstaged
                | Progress::StagingPending
                | Progress::Prepared
                | Progress::Committed
                | Progress::RolledBack
        ),
    }
}

fn joined_destination(
    anchor: &NormalizedDestination,
    relative: &PortablePath,
) -> Result<NormalizedDestination, AtomicApplyBatchJournalError> {
    anchor
        .join_portable(relative)
        .map_err(|_| journal_invalid())
}

fn expected_state_path(digest: &ContentHash) -> Result<PortablePath, AtomicApplyBatchJournalError> {
    PortablePath::parse(format!(
        ".kitrove/atomic-apply/{}/state.json",
        raw_digest(digest)?
    ))
    .map_err(|_| journal_invalid())
}

fn expected_participant_path(
    digest: &ContentHash,
    index: usize,
    role: &str,
    destination: &PortablePath,
) -> Result<PortablePath, AtomicApplyBatchJournalError> {
    let destination_leaf = destination
        .as_str()
        .rsplit('/')
        .next()
        .filter(|leaf| !leaf.is_empty())
        .ok_or_else(journal_invalid)?;
    PortablePath::parse(format!(
        ".kitrove/atomic-apply/{}/{index:04}/{role}/{destination_leaf}",
        raw_digest(digest)?,
    ))
    .map_err(|_| journal_invalid())
}

fn raw_digest(digest: &ContentHash) -> Result<&str, AtomicApplyBatchJournalError> {
    digest
        .as_str()
        .strip_prefix("blake3:")
        .ok_or_else(journal_invalid)
}

const fn journal_invalid() -> AtomicApplyBatchJournalError {
    AtomicApplyBatchJournalError::new(
        "apply.batch_journal_invalid",
        "atomic apply batch journal authority is invalid",
    )
}

const fn inspection_failed() -> AtomicApplyBatchJournalError {
    AtomicApplyBatchJournalError::new(
        "apply.batch_journal_inspection_failed",
        "atomic apply batch journal could not be inspected safely",
    )
}

const fn journal_storage_failed() -> AtomicApplyBatchJournalError {
    AtomicApplyBatchJournalError::new(
        "apply.batch_journal_storage_failed",
        "atomic apply batch journal could not be stored safely",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(value: &str) -> ContentHash {
        ContentHash::digest(value.as_bytes())
    }

    fn journal() -> AtomicApplyBatchJournal {
        let manifest_revision = Revision::parse("rev-1").unwrap();
        let old_state_hash = hash("old-state");
        let new_state_hash = hash("new-state");
        let plan_digest = hash("plan");
        let asset_id = AssetId::parse("example-skill").unwrap();
        let destination = NormalizedDestination::parse("/targets/skills/example").unwrap();
        let old_target_hash = hash("old-target");
        let new_target_hash = hash("new-target");
        let digest_items = [BatchDigestItem {
            kind_tag: ParticipantKind::Skill.digest_tag(),
            asset_id: asset_id.as_str(),
            destination: destination.as_str(),
            relative_destination: "skills/example",
            plan_digest: plan_digest.as_str(),
            disposition_tag: StoredDisposition::ManagedUpdate.digest_tag(),
            old_target_hash: Some(old_target_hash.as_str()),
            new_target_hash: new_target_hash.as_str(),
            extension: None,
            exact_file: None,
        }];
        let batch_digest = derive_batch_digest_from_authority(
            &digest_items,
            &manifest_revision,
            &old_state_hash,
            &new_state_hash,
            None,
        )
        .unwrap();
        AtomicApplyBatchJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            phase: AtomicApplyBatchPhase::Prepared,
            manifest_revision,
            active_profile: None,
            staging_state: expected_state_path(&batch_digest).unwrap(),
            old_state_hash,
            new_state_hash,
            participants: vec![BatchParticipantJournal {
                index: 0,
                kind: ParticipantKind::Skill,
                progress: ParticipantProgress::Prepared,
                disposition: StoredDisposition::ManagedUpdate,
                plan_digest,
                asset_id,
                target_anchor: NormalizedDestination::parse("/targets").unwrap(),
                destination,
                relative_destination: PortablePath::parse("skills/example").unwrap(),
                staging_target: expected_participant_path(
                    &batch_digest,
                    0,
                    "target",
                    &PortablePath::parse("skills/example").unwrap(),
                )
                .unwrap(),
                backup_target: expected_participant_path(
                    &batch_digest,
                    0,
                    "backup",
                    &PortablePath::parse("skills/example").unwrap(),
                )
                .unwrap(),
                old_target_hash: Some(old_target_hash),
                new_target_hash,
                extension: None,
                exact_file: None,
            }],
            batch_digest,
        }
    }

    #[test]
    fn validates_canonical_prepared_journal() {
        validate_journal(&journal()).unwrap();
    }

    #[test]
    fn preparing_journal_reaches_verified_through_guarded_transitions() {
        let mut journal = journal();
        journal.phase = AtomicApplyBatchPhase::Preparing;
        journal.participants[0].progress = ParticipantProgress::Unstaged;

        journal.validate_forward_path().unwrap();

        assert_eq!(journal.phase, AtomicApplyBatchPhase::Verified);
        assert!(
            journal
                .participants
                .iter()
                .all(|participant| participant.progress == ParticipantProgress::Verified)
        );
    }

    #[test]
    fn preparing_journal_requires_a_durable_staging_intent() {
        assert!(!valid_participant_transition(
            AtomicApplyBatchPhase::Preparing,
            StoredDisposition::ManagedUpdate,
            ParticipantProgress::Unstaged,
            ParticipantProgress::Prepared,
        ));
        assert!(valid_participant_transition(
            AtomicApplyBatchPhase::Preparing,
            StoredDisposition::ManagedUpdate,
            ParticipantProgress::Unstaged,
            ParticipantProgress::StagingPending,
        ));
        assert!(valid_participant_transition(
            AtomicApplyBatchPhase::Preparing,
            StoredDisposition::ManagedUpdate,
            ParticipantProgress::StagingPending,
            ParticipantProgress::Prepared,
        ));
    }

    #[test]
    fn preparing_journal_can_enter_rollback_from_every_staging_progress() {
        for progress in [
            ParticipantProgress::Unstaged,
            ParticipantProgress::StagingPending,
            ParticipantProgress::Prepared,
        ] {
            let mut journal = journal();
            journal.phase = AtomicApplyBatchPhase::Preparing;
            journal.participants[0].progress = progress;
            validate_journal(&journal).unwrap();
            journal
                .transition_phase(AtomicApplyBatchPhase::RollingBack)
                .unwrap();
            journal
                .transition_participant(0, ParticipantProgress::RolledBack)
                .unwrap();
        }
    }

    #[test]
    fn encoded_journal_is_bounded_canonical_json() {
        let journal = journal();
        let encoded = journal.encoded().unwrap();

        assert!(encoded.ends_with('\n'));
        assert!(!encoded.contains("\"instruction\""));
        assert_eq!(parse_journal(&encoded).unwrap(), journal);
        assert!(encoded.len() <= MAX_BATCH_JOURNAL_BYTES);
    }

    #[test]
    fn extension_layout_owns_its_recovery_entrypoint() {
        assert_eq!(
            StoredExtensionLayout::from_native(NativeExtensionLayout::Standalone)
                .entrypoint("example"),
            "example.ts"
        );
        assert_eq!(
            StoredExtensionLayout::from_native(NativeExtensionLayout::Directory)
                .entrypoint("example"),
            "index.ts"
        );
    }

    #[test]
    fn prior_extension_layout_must_match_managed_recovery_shape() {
        let journal = journal();
        let participant = &journal.participants[0];
        let mut extension = StoredExtensionAuthority {
            layout: StoredExtensionLayout::Directory,
            old_layout: Some(StoredExtensionLayout::Directory),
            entrypoint: "index.ts".to_owned(),
            native_id: "example".to_owned(),
        };

        assert!(valid_old_extension_layout(participant, &extension));
        extension.old_layout = Some(StoredExtensionLayout::Standalone);
        assert!(!valid_old_extension_layout(participant, &extension));
        extension.old_layout = None;
        assert!(!valid_old_extension_layout(participant, &extension));
    }

    #[test]
    fn rejects_paths_not_derived_from_batch_authority() {
        let mut journal = journal();
        journal.participants[0].backup_target =
            PortablePath::parse(".kitrove/atomic-apply/elsewhere/0000/backup").unwrap();

        assert_eq!(
            validate_journal(&journal).unwrap_err().code(),
            "apply.batch_journal_invalid"
        );
    }

    #[test]
    fn rejects_batch_digest_not_derived_from_complete_authority() {
        let mut journal = journal();
        journal.active_profile = Some(ProfileId::parse("changed-profile").unwrap());

        assert!(validate_journal(&journal).is_err());
    }

    #[test]
    fn rejects_recovery_hash_not_bound_to_the_batch_digest() {
        let mut journal = journal();
        journal.participants[0].new_target_hash = hash("forged-new-target");

        assert!(validate_journal(&journal).is_err());
    }

    #[test]
    fn rejects_impossible_global_and_participant_phase() {
        let mut journal = journal();
        journal.participants[0].progress = ParticipantProgress::Committed;

        assert!(validate_journal(&journal).is_err());
    }

    #[test]
    fn rollback_accepts_a_pre_mutation_progress_marker() {
        let mut journal = journal();
        journal.phase = AtomicApplyBatchPhase::RollingBack;
        journal.participants[0].progress = ParticipantProgress::CommitPending;

        validate_journal(&journal).unwrap();
    }

    #[test]
    fn guarded_transitions_allow_only_one_monotonic_progress_change() {
        let mut old = journal();
        old.phase = AtomicApplyBatchPhase::QuarantiningOldTargets;
        let mut pending = old.clone();
        pending.participants[0].progress = ParticipantProgress::QuarantinePending;

        assert!(valid_journal_transition(&old, &pending));

        pending.participants[0].progress = ParticipantProgress::Quarantined;
        assert!(!valid_journal_transition(&old, &pending));
    }

    #[test]
    fn guarded_transitions_reject_authority_changes() {
        let old = journal();
        let mut pending = old.clone();
        pending.phase = AtomicApplyBatchPhase::QuarantiningOldTargets;
        pending.participants[0].new_target_hash = hash("changed-authority");

        assert!(!valid_journal_transition(&old, &pending));
    }

    #[test]
    fn rollback_progress_cannot_cross_disposition_authority() {
        let mut fixture = journal();
        let mut participant = fixture.participants.remove(0);
        participant.disposition = StoredDisposition::NoOp;
        participant.progress = ParticipantProgress::RemovePending;
        assert!(!valid_rollback_progress(&participant));
        assert!(valid_rollback_transition(
            StoredDisposition::NoOp,
            ParticipantProgress::Committed,
            ParticipantProgress::RolledBack,
        ));

        participant.disposition = StoredDisposition::Install;
        participant.progress = ParticipantProgress::RestorePending;
        assert!(!valid_rollback_progress(&participant));
    }

    #[test]
    fn removal_disposition_accepts_only_reviewed_kinds_with_exact_absence_authority() {
        let mut fixture = journal();
        let participant = &mut fixture.participants[0];
        participant.disposition = StoredDisposition::Remove;
        participant.new_target_hash = crate::apply_batch::absent_target_hash().clone();
        assert!(valid_hash_authority(participant));

        participant.kind = ParticipantKind::Extension;
        participant.extension = Some(StoredExtensionAuthority {
            layout: StoredExtensionLayout::Directory,
            old_layout: Some(StoredExtensionLayout::Directory),
            entrypoint: "index.ts".to_owned(),
            native_id: "example".to_owned(),
        });
        assert!(valid_hash_authority(participant));

        participant.kind = ParticipantKind::PromptCommand;
        participant.exact_file = Some(StoredExactFileAuthority {
            mode: RegularFileMode::conservative(),
            max_bytes: 1024,
        });
        assert!(valid_hash_authority(participant));

        participant.new_target_hash = hash("forged-presence");
        assert!(!valid_hash_authority(participant));
    }

    #[test]
    fn rejects_skill_with_extension_only_recovery_authority() {
        let mut journal = journal();
        journal.participants[0].extension = Some(StoredExtensionAuthority {
            layout: StoredExtensionLayout::Directory,
            old_layout: None,
            entrypoint: "index.ts".to_owned(),
            native_id: "example".to_owned(),
        });

        assert!(validate_journal(&journal).is_err());
    }

    #[test]
    fn rejects_skill_with_instruction_only_recovery_authority() {
        let mut journal = journal();
        journal.participants[0].exact_file = Some(StoredExactFileAuthority {
            mode: RegularFileMode::conservative(),
            max_bytes: 1024,
        });

        assert!(validate_journal(&journal).is_err());
    }

    #[test]
    fn instruction_recovery_limits_are_bound_to_the_batch_digest() {
        let manifest_revision = Revision::parse("rev-1").unwrap();
        let old_state_hash = hash("old-state");
        let new_state_hash = hash("new-state");
        let authority = |max_bytes| BatchDigestItem {
            kind_tag: ParticipantKind::Instruction.digest_tag(),
            asset_id: "review",
            destination: "/targets/AGENTS.md",
            relative_destination: "AGENTS.md",
            plan_digest: "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            disposition_tag: StoredDisposition::Install.digest_tag(),
            old_target_hash: None,
            new_target_hash: "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            extension: None,
            exact_file: Some(BatchExactFileDigestAuthority {
                unix_mode: RegularFileMode::conservative().unix_mode(),
                readonly: RegularFileMode::conservative().readonly(),
                max_bytes,
            }),
        };

        let first = derive_batch_digest_from_authority(
            &[authority(1024)],
            &manifest_revision,
            &old_state_hash,
            &new_state_hash,
            None,
        )
        .unwrap();
        let changed = derive_batch_digest_from_authority(
            &[authority(1025)],
            &manifest_revision,
            &old_state_hash,
            &new_state_hash,
            None,
        )
        .unwrap();

        assert_ne!(first, changed);
    }

    #[test]
    fn rejects_anchor_and_destination_mismatch() {
        let mut journal = journal();
        journal.participants[0].target_anchor = NormalizedDestination::parse("/different").unwrap();

        assert!(validate_journal(&journal).is_err());
    }

    #[test]
    fn parser_rejects_unknown_authority() {
        let encoded = serde_json::to_string(&journal()).unwrap();
        let schema = format!("\"schema_version\":{JOURNAL_SCHEMA_VERSION}");
        let encoded = encoded.replacen(&schema, &format!("{schema},\"unexpected\":true"), 1);

        assert!(serde_json::from_str::<AtomicApplyBatchJournal>(&encoded).is_err());
    }

    #[test]
    fn read_only_inspection_reports_a_pending_only_guarded_journal() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().canonicalize().unwrap().join("state");
        let state = ObjectStore::open_or_create_private_state(&state_root).unwrap();
        state
            .stage_private_text(
                &PortablePath::parse(ATOMIC_APPLY_PENDING_PATH).unwrap(),
                &serde_json::to_string(&journal()).unwrap(),
                MAX_BATCH_JOURNAL_BYTES,
            )
            .unwrap();
        drop(state);

        assert_eq!(
            inspect_atomic_apply_batch_journal(&state_root).unwrap(),
            AtomicApplyBatchJournalStatus::Pending {
                phase: AtomicApplyBatchPhase::Prepared,
                participant_count: 1,
            }
        );
    }
}
