use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_instructions::DEFAULT_MAX_INSTRUCTION_DOCUMENT_BYTES;
use kitrove_model::{
    AssetId, ContentHash, DeploymentReceipt, EnvironmentManifest, HarnessId, HarnessScope,
    LocalState, NormalizedDestination, PackApplicationClaim, ProfileId, ReceiptId, Revision,
};

use crate::materialization::write_digest_record;
use crate::{
    AgentApplyPlan, AgentRemovalPlan, ApplyDisposition, ApplyPlan, CoalescedInstructionApplyPlan,
    CoalescedInstructionDocument, CoalescedMcpApplyPlan, CoalescedMcpDocument,
    DestinationObservation, ExtensionApplyPlan, ExtensionDestinationObservation,
    NativeExtensionLayout, PromptCommandApplyPlan, PromptCommandRemovalPlan,
};

pub(crate) const MAX_BATCH_PARTICIPANTS: usize = 4096;
pub(crate) const ATOMIC_COMMIT_TOMBSTONES_PER_PARTICIPANT: usize = 8;
pub(crate) const ATOMIC_COMMIT_CONTROL_TOMBSTONES: usize = 10;
pub(crate) const ATOMIC_RECOVERY_FORWARD_TOMBSTONES_PER_PARTICIPANT: usize = 3;
pub(crate) const ATOMIC_RECOVERY_FORWARD_CONTROL_TOMBSTONES: usize = 5;
pub(crate) const ATOMIC_ROLLBACK_TOMBSTONES_PER_PARTICIPANT: usize = 5;
pub(crate) const ATOMIC_ROLLBACK_CONTROL_TOMBSTONES: usize = 5;
pub(crate) const ATOMIC_TREE_TOMBSTONES_PER_TREE_PARTICIPANT: usize = 2;
const MAX_SELECTED_PACK_APPLICATIONS: usize = 64;
const MAX_PACK_APPLICATION_CLAIMS: usize = 4096;
const MAX_PACK_APPLICATION_RECEIPT_REFERENCES: usize = 4096;
pub(crate) const SKILL_BATCH_ITEM_TAG: u8 = 0;
pub(crate) const EXTENSION_BATCH_ITEM_TAG: u8 = 1;
pub(crate) const INSTRUCTION_BATCH_ITEM_TAG: u8 = 2;
pub(crate) const PROMPT_COMMAND_BATCH_ITEM_TAG: u8 = 3;
pub(crate) const AGENT_BATCH_ITEM_TAG: u8 = 4;
pub(crate) const MCP_BATCH_ITEM_TAG: u8 = 5;
pub(crate) const INSTALL_DISPOSITION_TAG: u8 = 0;
pub(crate) const NO_OP_DISPOSITION_TAG: u8 = 1;
pub(crate) const RESTORE_DISPOSITION_TAG: u8 = 2;
pub(crate) const MANAGED_UPDATE_DISPOSITION_TAG: u8 = 3;
pub(crate) const REMOVE_DISPOSITION_TAG: u8 = 4;
pub(crate) const STANDALONE_EXTENSION_LAYOUT_TAG: u8 = 0;
pub(crate) const DIRECTORY_EXTENSION_LAYOUT_TAG: u8 = 1;

pub(crate) struct BatchExtensionDigestAuthority<'a> {
    pub(crate) layout_tag: u8,
    pub(crate) old_layout_tag: Option<u8>,
    pub(crate) native_id: &'a str,
}

pub(crate) struct BatchExactFileDigestAuthority {
    pub(crate) unix_mode: Option<u32>,
    pub(crate) readonly: bool,
    pub(crate) max_bytes: usize,
}

pub(crate) struct BatchDigestItem<'a> {
    pub(crate) kind_tag: u8,
    pub(crate) asset_id: &'a str,
    pub(crate) destination: &'a str,
    pub(crate) relative_destination: &'a str,
    pub(crate) plan_digest: &'a str,
    pub(crate) disposition_tag: u8,
    pub(crate) old_target_hash: Option<&'a str>,
    pub(crate) new_target_hash: &'a str,
    pub(crate) extension: Option<BatchExtensionDigestAuthority<'a>>,
    pub(crate) exact_file: Option<BatchExactFileDigestAuthority>,
}

/// One confirmed materialization participant in an atomic apply batch.
#[derive(Clone, Eq, PartialEq)]
pub enum AtomicApplyItem {
    Skill(ApplyPlan),
    Extension(ExtensionApplyPlan),
    Instruction(AtomicInstructionApplyPlan),
    PromptCommand(PromptCommandApplyPlan),
    PromptCommandRemoval(PromptCommandRemovalPlan),
    Agent(AgentApplyPlan),
    AgentRemoval(AgentRemovalPlan),
    Mcp(AtomicMcpApplyPlan),
}

/// One coalesced physical instruction document prepared for the shared atomic coordinator.
#[derive(Clone, Eq, PartialEq)]
pub struct AtomicInstructionApplyPlan {
    document: CoalescedInstructionDocument,
    manifest_revision: Revision,
    observed_local_state_text: String,
}

/// One coalesced physical MCP document prepared for the shared atomic coordinator.
#[derive(Clone, Eq, PartialEq)]
pub struct AtomicMcpApplyPlan {
    document: Box<CoalescedMcpDocument>,
    manifest_revision: Revision,
    observed_local_state_text: String,
}

impl AtomicMcpApplyPlan {
    #[must_use]
    pub const fn document(&self) -> &CoalescedMcpDocument {
        &self.document
    }

    pub(crate) fn observed_local_state_text(&self) -> &str {
        &self.observed_local_state_text
    }
}

impl Debug for AtomicMcpApplyPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicMcpApplyPlan")
            .field("document", &self.document)
            .field("manifest_revision", &self.manifest_revision)
            .finish()
    }
}

impl AtomicInstructionApplyPlan {
    #[must_use]
    pub const fn document(&self) -> &CoalescedInstructionDocument {
        &self.document
    }
}

impl Debug for AtomicInstructionApplyPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicInstructionApplyPlan")
            .field("document", &self.document)
            .field("manifest_revision", &self.manifest_revision)
            .finish()
    }
}

impl AtomicApplyItem {
    fn kind_tag(&self) -> u8 {
        match self {
            Self::Skill(_) => SKILL_BATCH_ITEM_TAG,
            Self::Extension(_) => EXTENSION_BATCH_ITEM_TAG,
            Self::Instruction(_) => INSTRUCTION_BATCH_ITEM_TAG,
            Self::PromptCommand(_) => PROMPT_COMMAND_BATCH_ITEM_TAG,
            Self::PromptCommandRemoval(_) => PROMPT_COMMAND_BATCH_ITEM_TAG,
            Self::Agent(_) => AGENT_BATCH_ITEM_TAG,
            Self::AgentRemoval(_) => AGENT_BATCH_ITEM_TAG,
            Self::Mcp(_) => MCP_BATCH_ITEM_TAG,
        }
    }

    pub(crate) fn asset_id(&self) -> &kitrove_model::AssetId {
        match self {
            Self::Skill(plan) => plan.asset_id(),
            Self::Extension(plan) => plan.asset_id(),
            Self::Instruction(plan) => plan
                .document
                .regions()
                .first()
                .expect("a coalesced document has at least one region")
                .asset_id(),
            Self::PromptCommand(plan) => plan.asset_id(),
            Self::PromptCommandRemoval(plan) => plan.asset_id(),
            Self::Agent(plan) => plan.asset_id(),
            Self::AgentRemoval(plan) => plan.asset_id(),
            Self::Mcp(plan) => plan
                .document
                .entries()
                .first()
                .expect("a coalesced MCP document has at least one entry")
                .asset_id(),
        }
    }

    pub(crate) fn destination(&self) -> &NormalizedDestination {
        match self {
            Self::Skill(plan) => plan.destination(),
            Self::Extension(plan) => plan.destination(),
            Self::Instruction(plan) => plan.document.destination(),
            Self::PromptCommand(plan) => plan.destination(),
            Self::PromptCommandRemoval(plan) => plan.destination(),
            Self::Agent(plan) => plan.destination(),
            Self::AgentRemoval(plan) => plan.destination(),
            Self::Mcp(plan) => plan.document.destination(),
        }
    }

    pub(crate) fn relative_destination(&self) -> &kitrove_model::PortablePath {
        match self {
            Self::Skill(plan) => plan.relative_destination(),
            Self::Extension(plan) => plan.relative_destination(),
            Self::Instruction(plan) => plan.document.relative_destination(),
            Self::PromptCommand(plan) => plan.relative_destination(),
            Self::PromptCommandRemoval(plan) => plan.relative_destination(),
            Self::Agent(plan) => plan.relative_destination(),
            Self::AgentRemoval(plan) => plan.relative_destination(),
            Self::Mcp(plan) => plan.document.relative_destination(),
        }
    }

    pub fn disposition(&self) -> ApplyDisposition {
        match self {
            Self::Skill(plan) => plan.disposition(),
            Self::Extension(plan) => plan.disposition(),
            Self::Instruction(plan) => plan.document.disposition(),
            Self::PromptCommand(plan) => plan.disposition(),
            Self::PromptCommandRemoval(_) => ApplyDisposition::Remove,
            Self::Agent(plan) => plan.disposition(),
            Self::AgentRemoval(_) => ApplyDisposition::Remove,
            Self::Mcp(plan) => plan.document.disposition(),
        }
    }

    pub(crate) fn target_anchor(&self) -> Result<NormalizedDestination, AtomicApplyBatchError> {
        match self {
            Self::Instruction(plan) => Ok(plan.document.target_anchor().clone()),
            Self::Mcp(plan) => Ok(plan.document.target_anchor().clone()),
            Self::Skill(_)
            | Self::Extension(_)
            | Self::PromptCommand(_)
            | Self::PromptCommandRemoval(_)
            | Self::Agent(_)
            | Self::AgentRemoval(_) => self
                .destination()
                .anchor_for(self.relative_destination())
                .map_err(|_| target_anchor_invalid()),
        }
    }

    fn manifest_revision(&self) -> &Revision {
        match self {
            Self::Skill(plan) => plan.manifest_revision(),
            Self::Extension(plan) => plan.manifest_revision(),
            Self::Instruction(plan) => &plan.manifest_revision,
            Self::PromptCommand(plan) => plan.manifest_revision(),
            Self::PromptCommandRemoval(plan) => plan.manifest_revision(),
            Self::Agent(plan) => plan.manifest_revision(),
            Self::AgentRemoval(plan) => plan.manifest_revision(),
            Self::Mcp(plan) => &plan.manifest_revision,
        }
    }

    fn observed_local_state_text(&self) -> &str {
        match self {
            Self::Skill(plan) => plan.observed_local_state_text(),
            Self::Extension(plan) => plan.observed_local_state_text(),
            Self::Instruction(plan) => &plan.observed_local_state_text,
            Self::PromptCommand(plan) => plan.observed_local_state_text(),
            Self::PromptCommandRemoval(plan) => plan.observed_local_state_text(),
            Self::Agent(plan) => plan.observed_local_state_text(),
            Self::AgentRemoval(plan) => plan.observed_local_state_text(),
            Self::Mcp(plan) => &plan.observed_local_state_text,
        }
    }

    pub(crate) fn digest(&self) -> &ContentHash {
        match self {
            Self::Skill(plan) => plan.digest(),
            Self::Extension(plan) => plan.digest(),
            Self::Instruction(plan) => plan.document.digest(),
            Self::PromptCommand(plan) => plan.digest(),
            Self::PromptCommandRemoval(plan) => plan.digest(),
            Self::Agent(plan) => plan.digest(),
            Self::AgentRemoval(plan) => plan.digest(),
            Self::Mcp(plan) => plan.document.digest(),
        }
    }

    pub(crate) fn digest_authority(&self) -> Result<BatchDigestItem<'_>, AtomicApplyBatchError> {
        let (old_target_hash, new_target_hash, extension, exact_file) = match self {
            Self::Skill(plan) => (
                observed_skill_hash(plan.observed_destination())?,
                if plan.disposition() == ApplyDisposition::Remove {
                    absent_target_hash()
                } else {
                    plan.rendered().rendered_hash()
                },
                None,
                None,
            ),
            Self::Extension(plan) => {
                let (old_target_hash, old_layout) =
                    observed_extension_authority(plan.observed_destination())?;
                (
                    old_target_hash,
                    if plan.disposition() == ApplyDisposition::Remove {
                        absent_target_hash()
                    } else {
                        plan.rendered().rendered_hash()
                    },
                    Some(BatchExtensionDigestAuthority {
                        layout_tag: extension_layout_tag(plan.rendered().layout()),
                        old_layout_tag: old_layout.map(extension_layout_tag),
                        native_id: plan.rendered().native_id().as_str(),
                    }),
                    None,
                )
            }
            Self::Instruction(plan) => {
                let max_bytes = instruction_document_limit(&plan.document)?;
                (
                    plan.document.observation().document_hash(),
                    plan.document.rendered().document_hash(),
                    None,
                    Some(BatchExactFileDigestAuthority {
                        unix_mode: plan.document.rendered().mode().unix_mode(),
                        readonly: plan.document.rendered().mode().readonly(),
                        max_bytes,
                    }),
                )
            }
            Self::PromptCommand(plan) => (
                plan.observation().content_hash(),
                plan.rendered().content_hash(),
                None,
                Some(BatchExactFileDigestAuthority {
                    unix_mode: plan.rendered().mode().unix_mode(),
                    readonly: plan.rendered().mode().readonly(),
                    max_bytes: kitrove_prompt_commands::PromptCommandLimits::default()
                        .max_document_bytes,
                }),
            ),
            Self::PromptCommandRemoval(plan) => (
                plan.observation().content_hash(),
                absent_target_hash(),
                None,
                Some(BatchExactFileDigestAuthority {
                    unix_mode: plan.observation().mode().unix_mode(),
                    readonly: plan.observation().mode().readonly(),
                    max_bytes: kitrove_prompt_commands::PromptCommandLimits::default()
                        .max_document_bytes,
                }),
            ),
            Self::Agent(plan) => (
                plan.observation().content_hash(),
                plan.rendered().content_hash(),
                None,
                Some(BatchExactFileDigestAuthority {
                    unix_mode: plan.rendered().mode().unix_mode(),
                    readonly: plan.rendered().mode().readonly(),
                    max_bytes: kitrove_agents::AgentLimits::default().max_document_bytes,
                }),
            ),
            Self::AgentRemoval(plan) => (
                plan.observation().content_hash(),
                absent_target_hash(),
                None,
                Some(BatchExactFileDigestAuthority {
                    unix_mode: plan.observation().mode().unix_mode(),
                    readonly: plan.observation().mode().readonly(),
                    max_bytes: kitrove_agents::AgentLimits::default().max_document_bytes,
                }),
            ),
            Self::Mcp(plan) => (
                plan.document
                    .observation()
                    .parsed()
                    .map(kitrove_mcp::ObservedMcpDocument::exact_document_hash),
                plan.document.rendered().document_hash(),
                None,
                Some(BatchExactFileDigestAuthority {
                    unix_mode: plan.document.rendered().mode().unix_mode(),
                    readonly: plan.document.rendered().mode().readonly(),
                    max_bytes: mcp_document_limit(plan.document())?,
                }),
            ),
        };
        Ok(BatchDigestItem {
            kind_tag: self.kind_tag(),
            asset_id: self.asset_id().as_str(),
            destination: self.destination().as_str(),
            relative_destination: self.relative_destination().as_str(),
            plan_digest: self.digest().as_str(),
            disposition_tag: disposition_tag(self.disposition()),
            old_target_hash: old_target_hash.map(ContentHash::as_str),
            new_target_hash: new_target_hash.as_str(),
            extension,
            exact_file,
        })
    }
}

impl Debug for AtomicApplyItem {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicApplyItem")
            .field("kind", &self.kind_tag())
            .field("digest", self.digest())
            .finish()
    }
}

/// Complete immutable authority for one failure-atomic multi-target application.
#[derive(Clone, Eq, PartialEq)]
pub struct AtomicApplyBatchPlan {
    items: Vec<AtomicApplyItem>,
    target_anchors: Vec<NormalizedDestination>,
    manifest_revision: Revision,
    observed_local_state_text: String,
    proposed_local_state: LocalState,
    proposed_local_state_text: String,
    active_profile: Option<ProfileId>,
    digest: ContentHash,
}

/// One selected pack and its exact transitive leaf assets for local ownership attribution.
#[derive(Clone, Eq, PartialEq)]
pub struct PackApplicationSelection {
    pub pack_id: AssetId,
    pub pack_revision: ContentHash,
    pub leaf_assets: BTreeSet<AssetId>,
}

impl Debug for PackApplicationSelection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackApplicationSelection")
            .field("leaf_asset_count", &self.leaf_assets.len())
            .finish_non_exhaustive()
    }
}

impl Debug for AtomicApplyBatchPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicApplyBatchPlan")
            .field("participant_count", &self.items.len())
            .field("target_anchor_count", &self.target_anchors.len())
            .field("manifest_revision", &self.manifest_revision)
            .field("digest", &self.digest)
            .finish()
    }
}

impl AtomicApplyBatchPlan {
    /// Builds one canonical batch from plans derived from the same initial authority.
    pub fn new(
        mut items: Vec<AtomicApplyItem>,
        active_profile: Option<ProfileId>,
    ) -> Result<Self, AtomicApplyBatchError> {
        if items.is_empty() {
            return Err(batch_empty());
        }
        if items.len() > MAX_BATCH_PARTICIPANTS {
            return Err(batch_limit());
        }
        items.sort_by(|left, right| {
            left.destination()
                .as_str()
                .cmp(right.destination().as_str())
                .then_with(|| left.asset_id().cmp(right.asset_id()))
                .then_with(|| left.kind_tag().cmp(&right.kind_tag()))
                .then_with(|| left.digest().cmp(right.digest()))
        });
        let destinations: BTreeSet<_> = items
            .iter()
            .map(|item| item.destination().as_str())
            .collect();
        if destinations.len() != items.len() {
            return Err(destination_duplicate());
        }
        if items.iter().any(|item| {
            item.destination()
                .strict_ancestor_strings()
                .any(|ancestor| destinations.contains(ancestor))
        }) {
            return Err(destination_overlap());
        }
        let target_anchors = items
            .iter()
            .map(AtomicApplyItem::target_anchor)
            .collect::<Result<BTreeSet<_>, _>>()?
            .into_iter()
            .collect();

        let manifest_revision = items[0].manifest_revision().clone();
        let observed_local_state_text = items[0].observed_local_state_text().to_owned();
        let initial_local_state =
            LocalState::from_json(&observed_local_state_text).map_err(|_| state_invalid())?;
        let mut proposed_local_state = initial_local_state.clone();
        let mut receipt_ids = BTreeSet::new();
        for item in &items {
            if item.manifest_revision() != &manifest_revision
                || item.observed_local_state_text() != observed_local_state_text
            {
                return Err(authority_mismatch());
            }
            validate_single_item_state(item, &initial_local_state)?;
            for receipt_id in item_receipt_ids(item)? {
                if !receipt_ids.insert(receipt_id) {
                    return Err(receipt_duplicate());
                }
            }
            apply_item_receipts(item, &initial_local_state, &mut proposed_local_state)?;
        }
        validate_pack_application_claims(&initial_local_state)?;
        retain_existing_pack_application_receipts(&mut proposed_local_state);
        proposed_local_state.machine.active_profile = active_profile.clone();
        let proposed_local_state_text = proposed_local_state
            .to_json()
            .map_err(|_| state_invalid())?;
        let digest = derive_batch_digest(
            &items,
            &manifest_revision,
            &observed_local_state_text,
            &proposed_local_state_text,
            active_profile.as_ref(),
        )?;
        let plan = Self {
            items,
            target_anchors,
            manifest_revision,
            observed_local_state_text,
            proposed_local_state,
            proposed_local_state_text,
            active_profile,
            digest,
        };
        crate::apply_batch_journal::validate_prepared_plan(&plan)
            .map_err(|_| journal_authority_invalid())?;
        Ok(plan)
    }

    /// Adds coalesced physical instruction documents to the shared atomic coordinator.
    pub fn with_instructions(
        items: Vec<AtomicApplyItem>,
        instructions: CoalescedInstructionApplyPlan,
    ) -> Result<Self, AtomicApplyBatchError> {
        Self::with_shared_documents(items, Some(instructions), None)
    }

    /// Adds coalesced physical MCP documents to the shared atomic coordinator.
    pub fn with_mcp(
        items: Vec<AtomicApplyItem>,
        mcp: CoalescedMcpApplyPlan,
    ) -> Result<Self, AtomicApplyBatchError> {
        Self::with_shared_documents(items, None, Some(mcp))
    }

    /// Adds every coalesced shared-document family to one failure-atomic batch.
    pub fn with_shared_documents(
        mut items: Vec<AtomicApplyItem>,
        instructions: Option<CoalescedInstructionApplyPlan>,
        mcp: Option<CoalescedMcpApplyPlan>,
    ) -> Result<Self, AtomicApplyBatchError> {
        if items.iter().any(|item| {
            matches!(
                item,
                AtomicApplyItem::Instruction(_) | AtomicApplyItem::Mcp(_)
            )
        }) {
            return Err(item_state_invalid());
        }
        if instructions.is_none() && mcp.is_none() {
            return Err(item_state_invalid());
        }
        if let (Some(instructions), Some(mcp)) = (&instructions, &mcp) {
            if instructions.active_profile() != mcp.active_profile()
                || instructions.manifest_revision() != mcp.manifest_revision()
                || instructions.observed_local_state_text() != mcp.observed_local_state_text()
            {
                return Err(item_state_invalid());
            }
        }
        if let Some(instructions) = &instructions {
            items.extend(instructions.documents().iter().cloned().map(|document| {
                AtomicApplyItem::Instruction(AtomicInstructionApplyPlan {
                    document,
                    manifest_revision: instructions.manifest_revision().clone(),
                    observed_local_state_text: instructions.observed_local_state_text().to_owned(),
                })
            }));
        }
        if let Some(mcp) = &mcp {
            items.extend(mcp.documents().iter().cloned().map(|document| {
                AtomicApplyItem::Mcp(AtomicMcpApplyPlan {
                    document: Box::new(document),
                    manifest_revision: mcp.manifest_revision().clone(),
                    observed_local_state_text: mcp.observed_local_state_text().to_owned(),
                })
            }));
        }
        let active_profile = instructions
            .as_ref()
            .and_then(CoalescedInstructionApplyPlan::active_profile)
            .or_else(|| mcp.as_ref().and_then(CoalescedMcpApplyPlan::active_profile))
            .cloned();
        let plan = Self::new(items, active_profile)?;
        if let Some(instructions) = &instructions {
            validate_instruction_batch_state(&plan, instructions)?;
        }
        if let Some(mcp) = &mcp {
            validate_mcp_batch_state(&plan, mcp)?;
        }
        Ok(plan)
    }

    #[must_use]
    pub fn items(&self) -> &[AtomicApplyItem] {
        &self.items
    }

    /// Returns distinct canonical target roots in the order required for locking.
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

    /// Attributes the receipts produced by this batch to selected packs and gives explicit or
    /// profile-selected assets retention precedence over every overlapping pack claim.
    pub fn with_pack_application_ownership(
        mut self,
        manifest: &EnvironmentManifest,
        selections: &[PackApplicationSelection],
        independently_selected_assets: &BTreeSet<AssetId>,
        scope: HarnessScope,
        targets: BTreeSet<HarnessId>,
    ) -> Result<Self, AtomicApplyBatchError> {
        let roots = selections
            .iter()
            .map(|selection| selection.pack_id.clone())
            .collect::<BTreeSet<_>>();
        let exact_memberships = crate::resolve_pack_asset_memberships(manifest, &roots)
            .map_err(|_| pack_application_context_invalid())?;
        if crate::derive_manifest_revision(manifest).ok().as_ref() != Some(&self.manifest_revision)
            || targets.is_empty()
            || selections.len() > MAX_SELECTED_PACK_APPLICATIONS
            || roots.len() != selections.len()
            || selections.iter().any(|selection| {
                manifest
                    .packs
                    .get(&selection.pack_id)
                    .is_none_or(|pack| pack.content_hash != selection.pack_revision)
                    || exact_memberships.get(&selection.pack_id) != Some(&selection.leaf_assets)
            })
        {
            return Err(pack_application_context_invalid());
        }
        validate_pack_application_claims(&self.proposed_local_state)?;
        let initial =
            LocalState::from_json(&self.observed_local_state_text).map_err(|_| state_invalid())?;
        let mut participant_receipts_by_anchor = BTreeMap::new();
        for item in &self.items {
            participant_receipts_by_anchor
                .entry(item.target_anchor()?)
                .or_insert_with(BTreeSet::new)
                .extend(item_receipt_ids(item)?);
        }
        let participant_receipts = participant_receipts_by_anchor
            .values()
            .flat_map(|receipt_ids| receipt_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        let participant_consumers = participant_receipts
            .iter()
            .filter_map(|receipt_id| self.proposed_local_state.receipts.get(receipt_id))
            .flat_map(DeploymentReceipt::consumers)
            .cloned()
            .collect::<BTreeSet<_>>();
        if participant_consumers != targets
            || participant_receipts.iter().any(|receipt_id| {
                self.proposed_local_state
                    .receipts
                    .get(receipt_id)
                    .is_none_or(|receipt| receipt.scope != scope)
            })
        {
            return Err(pack_application_context_invalid());
        }
        let initial_pack_owned = initial
            .pack_applications
            .values()
            .flat_map(|claim| claim.receipts.iter().cloned())
            .collect::<BTreeSet<_>>();
        let independent_receipts = participant_receipts
            .iter()
            .filter(|receipt_id| {
                self.proposed_local_state
                    .receipts
                    .get(*receipt_id)
                    .is_some_and(|receipt| {
                        independently_selected_assets.contains(&receipt.asset_id)
                    })
            })
            .cloned()
            .collect::<BTreeSet<_>>();

        for claim in self.proposed_local_state.pack_applications.values_mut() {
            claim
                .receipts
                .retain(|receipt_id| !independent_receipts.contains(receipt_id));
        }
        self.proposed_local_state
            .pack_applications
            .retain(|_, claim| !claim.receipts.is_empty());

        for selection in selections {
            if selection.leaf_assets.is_empty() {
                return Err(pack_application_context_invalid());
            }
            for (target_anchor, anchored_receipts) in &participant_receipts_by_anchor {
                let mut candidate = PackApplicationClaim {
                    pack_id: selection.pack_id.clone(),
                    pack_revision: selection.pack_revision.clone(),
                    scope,
                    target_anchor: target_anchor.clone(),
                    targets: targets.clone(),
                    receipts: BTreeSet::new(),
                };
                let application_id = candidate
                    .application_id()
                    .map_err(|_| pack_application_context_invalid())?;
                if let Some(existing) = self
                    .proposed_local_state
                    .pack_applications
                    .get(&application_id)
                {
                    candidate.receipts.extend(existing.receipts.iter().cloned());
                }
                candidate.receipts.extend(
                    anchored_receipts
                        .iter()
                        .filter(|receipt_id| !independent_receipts.contains(*receipt_id))
                        .filter(|receipt_id| {
                            self.proposed_local_state
                                .receipts
                                .get(*receipt_id)
                                .is_some_and(|receipt| {
                                    selection.leaf_assets.contains(&receipt.asset_id)
                                })
                        })
                        .filter(|receipt_id| {
                            !initial.receipts.contains_key(*receipt_id)
                                || initial_pack_owned.contains(*receipt_id)
                        })
                        .cloned(),
                );
                if candidate.receipts.is_empty() {
                    self.proposed_local_state
                        .pack_applications
                        .remove(&application_id);
                } else {
                    self.proposed_local_state
                        .pack_applications
                        .insert(application_id, candidate);
                }
            }
        }
        validate_pack_application_claims(&self.proposed_local_state)?;
        self.proposed_local_state_text = self
            .proposed_local_state
            .to_json()
            .map_err(|_| state_invalid())?;
        self.digest = derive_batch_digest(
            &self.items,
            &self.manifest_revision,
            &self.observed_local_state_text,
            &self.proposed_local_state_text,
            self.active_profile.as_ref(),
        )?;
        crate::apply_batch_journal::validate_prepared_plan(&self)
            .map_err(|_| journal_authority_invalid())?;
        Ok(self)
    }

    /// Releases every local application of one exact pack revision and permits target removal
    /// only for receipts that have no remaining pack owner.
    pub fn with_pack_application_removal(
        mut self,
        manifest: &EnvironmentManifest,
        pack_id: &AssetId,
        expected_revision: &ContentHash,
    ) -> Result<Self, AtomicApplyBatchError> {
        if crate::derive_manifest_revision(manifest).ok().as_ref() != Some(&self.manifest_revision)
        {
            return Err(pack_application_context_invalid());
        }
        let initial =
            LocalState::from_json(&self.observed_local_state_text).map_err(|_| state_invalid())?;
        validate_pack_application_claims(&initial)?;
        let selected_claims = initial
            .pack_applications
            .iter()
            .filter(|(_, claim)| &claim.pack_id == pack_id)
            .collect::<Vec<_>>();
        if selected_claims.is_empty()
            || selected_claims
                .iter()
                .any(|(_, claim)| &claim.pack_revision != expected_revision)
        {
            return Err(pack_application_context_invalid());
        }
        let selected_receipts = selected_claims
            .iter()
            .flat_map(|(_, claim)| claim.receipts.iter().cloned())
            .collect::<BTreeSet<_>>();
        let retained_receipts = initial
            .pack_applications
            .values()
            .filter(|claim| &claim.pack_id != pack_id)
            .flat_map(|claim| claim.receipts.iter().cloned())
            .collect::<BTreeSet<_>>();
        let mut transitions = BTreeMap::new();
        for item in &self.items {
            for (receipt_id, disposition) in item_receipt_transitions(item)? {
                if transitions.insert(receipt_id, disposition).is_some() {
                    return Err(receipt_duplicate());
                }
            }
        }
        if transitions.len() != selected_receipts.len()
            || transitions.iter().any(|(receipt_id, disposition)| {
                !selected_receipts.contains(receipt_id)
                    || if retained_receipts.contains(receipt_id) {
                        *disposition != ApplyDisposition::NoOp
                    } else {
                        *disposition != ApplyDisposition::Remove
                    }
            })
        {
            return Err(pack_application_authority_invalid());
        }
        self.proposed_local_state
            .pack_applications
            .retain(|_, claim| &claim.pack_id != pack_id);
        validate_pack_application_claims(&self.proposed_local_state)?;
        self.proposed_local_state_text = self
            .proposed_local_state
            .to_json()
            .map_err(|_| state_invalid())?;
        self.digest = derive_batch_digest(
            &self.items,
            &self.manifest_revision,
            &self.observed_local_state_text,
            &self.proposed_local_state_text,
            self.active_profile.as_ref(),
        )?;
        crate::apply_batch_journal::validate_prepared_plan(&self)
            .map_err(|_| journal_authority_invalid())?;
        Ok(self)
    }
}

fn retain_existing_pack_application_receipts(state: &mut LocalState) {
    for claim in state.pack_applications.values_mut() {
        claim
            .receipts
            .retain(|receipt_id| state.receipts.contains_key(receipt_id));
    }
    state
        .pack_applications
        .retain(|_, claim| !claim.receipts.is_empty());
}

fn validate_pack_application_claims(state: &LocalState) -> Result<(), AtomicApplyBatchError> {
    if state.pack_applications.len() > MAX_PACK_APPLICATION_CLAIMS
        || state
            .pack_applications
            .values()
            .try_fold(0usize, |count, claim| {
                count.checked_add(claim.receipts.len())
            })
            .is_none_or(|count| count > MAX_PACK_APPLICATION_RECEIPT_REFERENCES)
    {
        return Err(pack_application_authority_invalid());
    }
    for (application_id, claim) in &state.pack_applications {
        if claim.receipts.is_empty()
            || claim.application_id().ok().as_ref() != Some(application_id)
            || claim.receipts.iter().any(|receipt_id| {
                state.receipts.get(receipt_id).is_none_or(|receipt| {
                    receipt.scope != claim.scope
                        || !claim.target_anchor.is_ancestor_of(&receipt.destination)
                        || receipt
                            .consumers()
                            .any(|consumer| !claim.targets.contains(consumer))
                })
            })
        {
            return Err(pack_application_authority_invalid());
        }
    }
    Ok(())
}

fn validate_instruction_batch_state(
    plan: &AtomicApplyBatchPlan,
    instructions: &CoalescedInstructionApplyPlan,
) -> Result<(), AtomicApplyBatchError> {
    if plan.manifest_revision() != instructions.manifest_revision()
        || plan.observed_local_state_text() != instructions.observed_local_state_text()
    {
        return Err(item_state_invalid());
    }
    for document in instructions.documents() {
        for region in document.regions() {
            if let Some(receipt) = region.proposed_receipt() {
                require_planned_receipt(plan, receipt)?;
            }
        }
    }
    Ok(())
}

fn validate_mcp_batch_state(
    plan: &AtomicApplyBatchPlan,
    mcp: &CoalescedMcpApplyPlan,
) -> Result<(), AtomicApplyBatchError> {
    if plan.manifest_revision() != mcp.manifest_revision()
        || plan.observed_local_state_text() != mcp.observed_local_state_text()
    {
        return Err(item_state_invalid());
    }
    for document in mcp.documents() {
        for entry in document.entries() {
            if let Some(receipt) = entry.proposed_receipt() {
                require_planned_receipt(plan, receipt)?;
            }
        }
    }
    Ok(())
}

fn require_planned_receipt(
    plan: &AtomicApplyBatchPlan,
    receipt: &DeploymentReceipt,
) -> Result<(), AtomicApplyBatchError> {
    let receipt_id = receipt.receipt_id().map_err(|_| receipt_invalid())?;
    if plan.proposed_local_state().receipts.get(&receipt_id) == Some(receipt) {
        Ok(())
    } else {
        Err(item_state_invalid())
    }
}

fn validate_single_item_state(
    item: &AtomicApplyItem,
    initial: &LocalState,
) -> Result<(), AtomicApplyBatchError> {
    match item {
        AtomicApplyItem::Skill(plan) if plan.disposition() == ApplyDisposition::Remove => {
            validate_single_receipt_removal(
                initial,
                plan.proposed_receipt(),
                plan.proposed_local_state(),
            )
        }
        AtomicApplyItem::Skill(plan) => validate_single_receipt_state(
            initial,
            plan.proposed_receipt(),
            plan.proposed_local_state(),
        ),
        AtomicApplyItem::Extension(plan) if plan.disposition() == ApplyDisposition::Remove => {
            validate_single_receipt_removal(
                initial,
                plan.proposed_receipt(),
                plan.proposed_local_state(),
            )
        }
        AtomicApplyItem::Extension(plan) => validate_single_receipt_state(
            initial,
            plan.proposed_receipt(),
            plan.proposed_local_state(),
        ),
        AtomicApplyItem::PromptCommand(plan) => validate_single_receipt_state(
            initial,
            plan.proposed_receipt(),
            plan.proposed_local_state(),
        ),
        AtomicApplyItem::Agent(plan) => validate_single_receipt_state(
            initial,
            plan.proposed_receipt(),
            plan.proposed_local_state(),
        ),
        AtomicApplyItem::AgentRemoval(plan) => {
            let mut expected = initial.clone();
            if expected.receipts.remove(plan.receipt_id()).as_ref() != Some(plan.observed_receipt())
                || &expected != plan.proposed_local_state()
            {
                return Err(item_state_invalid());
            }
            Ok(())
        }
        AtomicApplyItem::PromptCommandRemoval(plan) => {
            let mut expected = initial.clone();
            if expected.receipts.remove(plan.receipt_id()).as_ref() != Some(plan.observed_receipt())
                || &expected != plan.proposed_local_state()
            {
                return Err(item_state_invalid());
            }
            Ok(())
        }
        AtomicApplyItem::Instruction(plan) => {
            let mut expected = initial.clone();
            apply_instruction_receipts(&plan.document, initial, &mut expected)?;
            Ok(())
        }
        AtomicApplyItem::Mcp(plan) => {
            let mut expected = initial.clone();
            apply_mcp_receipts(&plan.document, initial, &mut expected)?;
            Ok(())
        }
    }
}

fn validate_single_receipt_state(
    initial: &LocalState,
    receipt: &DeploymentReceipt,
    proposed: &LocalState,
) -> Result<(), AtomicApplyBatchError> {
    let receipt_id = receipt.receipt_id().map_err(|_| receipt_invalid())?;
    let mut expected = initial.clone();
    expected.receipts.insert(receipt_id, receipt.clone());
    if &expected == proposed {
        Ok(())
    } else {
        Err(item_state_invalid())
    }
}

fn validate_single_receipt_removal(
    initial: &LocalState,
    receipt: &DeploymentReceipt,
    proposed: &LocalState,
) -> Result<(), AtomicApplyBatchError> {
    let receipt_id = receipt.receipt_id().map_err(|_| receipt_invalid())?;
    let mut expected = initial.clone();
    if expected.receipts.remove(&receipt_id).as_ref() != Some(receipt) || &expected != proposed {
        return Err(item_state_invalid());
    }
    Ok(())
}

fn apply_item_receipts(
    item: &AtomicApplyItem,
    initial: &LocalState,
    state: &mut LocalState,
) -> Result<(), AtomicApplyBatchError> {
    match item {
        AtomicApplyItem::Skill(plan) if plan.disposition() == ApplyDisposition::Remove => {
            remove_receipt(state, initial, plan.proposed_receipt())
        }
        AtomicApplyItem::Skill(plan) => insert_receipt(state, plan.proposed_receipt()),
        AtomicApplyItem::Extension(plan) if plan.disposition() == ApplyDisposition::Remove => {
            remove_receipt(state, initial, plan.proposed_receipt())
        }
        AtomicApplyItem::Extension(plan) => insert_receipt(state, plan.proposed_receipt()),
        AtomicApplyItem::PromptCommand(plan) => insert_receipt(state, plan.proposed_receipt()),
        AtomicApplyItem::Agent(plan) => insert_receipt(state, plan.proposed_receipt()),
        AtomicApplyItem::AgentRemoval(plan) => {
            if initial.receipts.get(plan.receipt_id()) != Some(plan.observed_receipt())
                || state.receipts.remove(plan.receipt_id()).as_ref()
                    != Some(plan.observed_receipt())
            {
                return Err(item_state_invalid());
            }
            Ok(())
        }
        AtomicApplyItem::PromptCommandRemoval(plan) => {
            if initial.receipts.get(plan.receipt_id()) != Some(plan.observed_receipt())
                || state.receipts.remove(plan.receipt_id()).as_ref()
                    != Some(plan.observed_receipt())
            {
                return Err(item_state_invalid());
            }
            Ok(())
        }
        AtomicApplyItem::Instruction(plan) => {
            apply_instruction_receipts(&plan.document, initial, state)
        }
        AtomicApplyItem::Mcp(plan) => apply_mcp_receipts(&plan.document, initial, state),
    }
}

fn insert_receipt(
    state: &mut LocalState,
    receipt: &DeploymentReceipt,
) -> Result<(), AtomicApplyBatchError> {
    let receipt_id = receipt.receipt_id().map_err(|_| receipt_invalid())?;
    state.receipts.insert(receipt_id, receipt.clone());
    Ok(())
}

fn remove_receipt(
    state: &mut LocalState,
    initial: &LocalState,
    receipt: &DeploymentReceipt,
) -> Result<(), AtomicApplyBatchError> {
    let receipt_id = receipt.receipt_id().map_err(|_| receipt_invalid())?;
    if initial.receipts.get(&receipt_id) != Some(receipt)
        || state.receipts.remove(&receipt_id).as_ref() != Some(receipt)
    {
        return Err(item_state_invalid());
    }
    Ok(())
}

fn item_receipt_ids(item: &AtomicApplyItem) -> Result<Vec<ReceiptId>, AtomicApplyBatchError> {
    item_receipt_transitions(item).map(|transitions| {
        transitions
            .into_iter()
            .map(|(receipt_id, _)| receipt_id)
            .collect()
    })
}

fn item_receipt_transitions(
    item: &AtomicApplyItem,
) -> Result<Vec<(ReceiptId, ApplyDisposition)>, AtomicApplyBatchError> {
    let one = |receipt: &DeploymentReceipt, disposition| {
        receipt
            .receipt_id()
            .map(|receipt_id| vec![(receipt_id, disposition)])
            .map_err(|_| receipt_invalid())
    };
    match item {
        AtomicApplyItem::Skill(plan) => one(plan.proposed_receipt(), plan.disposition()),
        AtomicApplyItem::Extension(plan) => one(plan.proposed_receipt(), plan.disposition()),
        AtomicApplyItem::PromptCommand(plan) => one(plan.proposed_receipt(), plan.disposition()),
        AtomicApplyItem::Agent(plan) => one(plan.proposed_receipt(), plan.disposition()),
        AtomicApplyItem::AgentRemoval(plan) => {
            Ok(vec![(plan.receipt_id().clone(), ApplyDisposition::Remove)])
        }
        AtomicApplyItem::PromptCommandRemoval(plan) => {
            Ok(vec![(plan.receipt_id().clone(), ApplyDisposition::Remove)])
        }
        AtomicApplyItem::Instruction(plan) => plan
            .document
            .regions()
            .iter()
            .filter_map(|region| {
                region
                    .proposed_receipt()
                    .or_else(|| region.observed_receipt())
                    .map(|receipt| (receipt, region.disposition()))
            })
            .map(|(receipt, disposition)| {
                receipt
                    .receipt_id()
                    .map(|receipt_id| (receipt_id, disposition))
                    .map_err(|_| receipt_invalid())
            })
            .collect(),
        AtomicApplyItem::Mcp(plan) => plan
            .document
            .entries()
            .iter()
            .filter_map(|entry| {
                entry
                    .proposed_receipt()
                    .or_else(|| entry.observed_receipt())
                    .map(|receipt| (receipt, entry.disposition()))
            })
            .map(|(receipt, disposition)| {
                receipt
                    .receipt_id()
                    .map(|receipt_id| (receipt_id, disposition))
                    .map_err(|_| receipt_invalid())
            })
            .collect(),
    }
}

fn apply_mcp_receipts(
    document: &CoalescedMcpDocument,
    initial: &LocalState,
    state: &mut LocalState,
) -> Result<(), AtomicApplyBatchError> {
    for entry in document.entries() {
        if let Some(observed) = entry.observed_receipt() {
            let receipt_id = observed.receipt_id().map_err(|_| receipt_invalid())?;
            if initial.receipts.get(&receipt_id) != Some(observed)
                || state.receipts.remove(&receipt_id).as_ref() != Some(observed)
            {
                return Err(item_state_invalid());
            }
        }
        if let Some(proposed) = entry.proposed_receipt() {
            insert_receipt(state, proposed)?;
        }
    }
    Ok(())
}

fn apply_instruction_receipts(
    document: &CoalescedInstructionDocument,
    initial: &LocalState,
    state: &mut LocalState,
) -> Result<(), AtomicApplyBatchError> {
    for region in document.regions() {
        if let Some(observed) = region.observed_receipt() {
            let receipt_id = observed.receipt_id().map_err(|_| receipt_invalid())?;
            if initial.receipts.get(&receipt_id) != Some(observed)
                || state.receipts.remove(&receipt_id).as_ref() != Some(observed)
            {
                return Err(item_state_invalid());
            }
        }
        if let Some(proposed) = region.proposed_receipt() {
            insert_receipt(state, proposed)?;
        }
    }
    Ok(())
}

fn derive_batch_digest(
    items: &[AtomicApplyItem],
    manifest_revision: &Revision,
    observed_state: &str,
    proposed_state: &str,
    active_profile: Option<&ProfileId>,
) -> Result<ContentHash, AtomicApplyBatchError> {
    let observed_state_hash = ContentHash::digest(observed_state.as_bytes());
    let proposed_state_hash = ContentHash::digest(proposed_state.as_bytes());
    let digest_items = items
        .iter()
        .map(AtomicApplyItem::digest_authority)
        .collect::<Result<Vec<_>, _>>()?;
    derive_batch_digest_from_authority(
        &digest_items,
        manifest_revision,
        &observed_state_hash,
        &proposed_state_hash,
        active_profile,
    )
}

pub(crate) fn derive_batch_digest_from_authority(
    items: &[BatchDigestItem<'_>],
    manifest_revision: &Revision,
    observed_state_hash: &ContentHash,
    proposed_state_hash: &ContentHash,
    active_profile: Option<&ProfileId>,
) -> Result<ContentHash, AtomicApplyBatchError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-atomic-apply-batch-v3\0");
    write_digest_record(&mut hasher, manifest_revision.as_str());
    write_digest_record(&mut hasher, observed_state_hash.as_str());
    write_digest_record(&mut hasher, proposed_state_hash.as_str());
    match active_profile {
        Some(profile) => {
            hasher.update(&[1]);
            write_digest_record(&mut hasher, profile.as_str());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&(items.len() as u64).to_be_bytes());
    for item in items {
        hasher.update(&[item.kind_tag, item.disposition_tag]);
        for value in [
            item.asset_id,
            item.destination,
            item.relative_destination,
            item.plan_digest,
            item.new_target_hash,
        ] {
            write_digest_record(&mut hasher, value);
        }
        write_optional_digest_record(&mut hasher, item.old_target_hash);
        match &item.extension {
            Some(extension) => {
                hasher.update(&[1, extension.layout_tag]);
                match extension.old_layout_tag {
                    Some(layout) => hasher.update(&[1, layout]),
                    None => hasher.update(&[0]),
                };
                write_digest_record(&mut hasher, extension.native_id);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        if let Some(exact_file) = &item.exact_file {
            hasher.update(b"exact-file-authority-v1\0");
            hasher.update(&[u8::from(exact_file.readonly)]);
            match exact_file.unix_mode {
                Some(mode) => {
                    hasher.update(&[1]);
                    hasher.update(&mode.to_be_bytes());
                }
                None => {
                    hasher.update(&[0]);
                }
            }
            hasher.update(&(exact_file.max_bytes as u64).to_be_bytes());
        }
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .map_err(|_| digest_failed())
}

pub(crate) fn instruction_document_limit(
    document: &CoalescedInstructionDocument,
) -> Result<usize, AtomicApplyBatchError> {
    let observed = document
        .observation()
        .document_byte_count()
        .unwrap_or_default();
    let required = observed.max(document.rendered().bytes().len());
    if required > DEFAULT_MAX_INSTRUCTION_DOCUMENT_BYTES {
        return Err(item_state_invalid());
    }
    Ok(required.saturating_add(1).max(1))
}

pub(crate) fn mcp_document_limit(
    document: &CoalescedMcpDocument,
) -> Result<usize, AtomicApplyBatchError> {
    let limit = kitrove_mcp::McpParseLimits::default().max_document_bytes;
    let observed = document
        .observation()
        .document_bytes()
        .map_or(0, <[u8]>::len);
    let required = observed.max(document.rendered().bytes().len());
    if required > limit {
        return Err(item_state_invalid());
    }
    Ok(required.saturating_add(1).max(1))
}

fn write_optional_digest_record(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            write_digest_record(hasher, value);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

const fn disposition_tag(disposition: ApplyDisposition) -> u8 {
    match disposition {
        ApplyDisposition::Install => INSTALL_DISPOSITION_TAG,
        ApplyDisposition::NoOp => NO_OP_DISPOSITION_TAG,
        ApplyDisposition::Restore => RESTORE_DISPOSITION_TAG,
        ApplyDisposition::ManagedUpdate => MANAGED_UPDATE_DISPOSITION_TAG,
        ApplyDisposition::Remove => REMOVE_DISPOSITION_TAG,
    }
}

pub(crate) fn absent_target_hash() -> &'static ContentHash {
    static HASH: std::sync::OnceLock<ContentHash> = std::sync::OnceLock::new();
    HASH.get_or_init(|| ContentHash::digest(b"kitrove-absent-target-v1"))
}

const fn extension_layout_tag(layout: NativeExtensionLayout) -> u8 {
    match layout {
        NativeExtensionLayout::Standalone => STANDALONE_EXTENSION_LAYOUT_TAG,
        NativeExtensionLayout::Directory => DIRECTORY_EXTENSION_LAYOUT_TAG,
    }
}

fn observed_skill_hash(
    observation: &DestinationObservation,
) -> Result<Option<&ContentHash>, AtomicApplyBatchError> {
    match observation {
        DestinationObservation::Absent => Ok(None),
        DestinationObservation::Present { rendered_hash, .. } => Ok(Some(rendered_hash)),
        DestinationObservation::Unsafe => Err(item_state_invalid()),
    }
}

fn observed_extension_authority(
    observation: &ExtensionDestinationObservation,
) -> Result<(Option<&ContentHash>, Option<NativeExtensionLayout>), AtomicApplyBatchError> {
    match observation {
        ExtensionDestinationObservation::Absent => Ok((None, None)),
        ExtensionDestinationObservation::Present {
            layout,
            object_hash,
        } => Ok((Some(object_hash), Some(*layout))),
        ExtensionDestinationObservation::Unsafe => Err(item_state_invalid()),
    }
}

/// Stable, redacted rejection from atomic batch construction.
#[derive(Clone, Eq, PartialEq)]
pub struct AtomicApplyBatchError {
    code: &'static str,
    message: &'static str,
}

impl AtomicApplyBatchError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for AtomicApplyBatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicApplyBatchError")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl Display for AtomicApplyBatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for AtomicApplyBatchError {}

macro_rules! batch_error {
    ($name:ident, $code:literal, $message:literal) => {
        const fn $name() -> AtomicApplyBatchError {
            AtomicApplyBatchError {
                code: $code,
                message: $message,
            }
        }
    };
}

batch_error!(
    batch_empty,
    "apply.batch_empty",
    "an atomic apply batch requires at least one participant"
);
batch_error!(
    batch_limit,
    "apply.batch_limit",
    "the atomic apply batch exceeds the participant limit"
);
batch_error!(
    state_invalid,
    "apply.batch_state_invalid",
    "the atomic apply batch local-state authority is invalid"
);
batch_error!(
    authority_mismatch,
    "apply.batch_authority_mismatch",
    "all atomic apply participants must share exact initial authority"
);
batch_error!(
    destination_duplicate,
    "apply.batch_destination_duplicate",
    "an atomic apply batch cannot target one destination more than once"
);
batch_error!(
    destination_overlap,
    "apply.batch_destination_overlap",
    "atomic apply batch destinations must not overlap"
);
batch_error!(
    target_anchor_invalid,
    "apply.batch_target_anchor_invalid",
    "an atomic apply participant destination is not rooted at its relative destination"
);
batch_error!(
    receipt_invalid,
    "apply.batch_receipt_invalid",
    "an atomic apply participant contains an invalid receipt identity"
);
batch_error!(
    receipt_duplicate,
    "apply.batch_receipt_duplicate",
    "an atomic apply batch cannot update one receipt more than once"
);
batch_error!(
    item_state_invalid,
    "apply.batch_item_state_invalid",
    "an atomic apply participant proposes unrelated local-state changes"
);
batch_error!(
    digest_failed,
    "apply.batch_digest_failed",
    "the atomic apply batch digest could not be derived"
);
batch_error!(
    journal_authority_invalid,
    "apply.batch_journal_authority_invalid",
    "the atomic apply batch cannot be represented by bounded recovery authority"
);
batch_error!(
    pack_application_context_invalid,
    "apply.pack_application_context_invalid",
    "pack application ownership requires one exact non-empty materialization context"
);
batch_error!(
    pack_application_authority_invalid,
    "apply.pack_application_authority_invalid",
    "machine-local pack application ownership is invalid"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_digest_binds_prior_extension_layout() {
        let manifest_revision = Revision::parse("rev-1").unwrap();
        let old_state = ContentHash::digest(b"old-state");
        let new_state = ContentHash::digest(b"new-state");
        let plan_digest = ContentHash::digest(b"plan");
        let old_target = ContentHash::digest(b"old-target");
        let new_target = ContentHash::digest(b"new-target");
        let digest_for = |old_layout_tag| {
            derive_batch_digest_from_authority(
                &[BatchDigestItem {
                    kind_tag: EXTENSION_BATCH_ITEM_TAG,
                    asset_id: "example",
                    destination: "/targets/extensions/example",
                    relative_destination: "extensions/example",
                    plan_digest: plan_digest.as_str(),
                    disposition_tag: MANAGED_UPDATE_DISPOSITION_TAG,
                    old_target_hash: Some(old_target.as_str()),
                    new_target_hash: new_target.as_str(),
                    extension: Some(BatchExtensionDigestAuthority {
                        layout_tag: DIRECTORY_EXTENSION_LAYOUT_TAG,
                        old_layout_tag: Some(old_layout_tag),
                        native_id: "example",
                    }),
                    exact_file: None,
                }],
                &manifest_revision,
                &old_state,
                &new_state,
                None,
            )
            .unwrap()
        };

        assert_ne!(
            digest_for(STANDALONE_EXTENSION_LAYOUT_TAG),
            digest_for(DIRECTORY_EXTENSION_LAYOUT_TAG)
        );
    }
}
