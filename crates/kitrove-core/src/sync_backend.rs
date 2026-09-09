use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_agent_skills::{CapturedTree, NativeSkillObject, StoredSkillTree, hash_tree};
use kitrove_agents::{StoredAgent, StoredNativeAgent};
use kitrove_instructions::{NativeInstructionRegion, StoredInstruction};
use kitrove_mcp::{StoredMcpServer, StoredNativeMcpEntry};
use kitrove_model::{
    ObjectDescriptor, PortablePath, PublicationId, RemoteRevision, SnapshotObjectKind, SyncLimits,
};
use kitrove_prompt_commands::{StoredNativePromptCommand, StoredPromptCommand};

use crate::{
    NativeExtensionObject, ObjectInstallOutcome, ObjectMutationError, ObjectStore,
    PortableSnapshotV1, VerifiedRemoteHistory,
};

pub(crate) mod sealed {
    pub trait Sealed {}
}

pub(crate) struct DescriptorBudgetExceeded;

pub(crate) fn validate_descriptor_budget<'a>(
    descriptors: impl IntoIterator<Item = &'a ObjectDescriptor>,
    limits: SyncLimits,
) -> Result<(), DescriptorBudgetExceeded> {
    let mut total = 0_u64;
    let mut count = 0_usize;
    for descriptor in descriptors {
        count = count.checked_add(1).ok_or(DescriptorBudgetExceeded)?;
        if count > limits.max_object_count() || descriptor.encoded_len() > limits.max_object_bytes()
        {
            return Err(DescriptorBudgetExceeded);
        }
        total = total
            .checked_add(descriptor.encoded_len())
            .ok_or(DescriptorBudgetExceeded)?;
        if total > limits.max_total_object_bytes() {
            return Err(DescriptorBudgetExceeded);
        }
    }
    Ok(())
}

/// One verified immutable object exchanged through a synchronization backend.
#[derive(Clone, Eq, PartialEq)]
pub enum VerifiedObjectEnvelope {
    /// A canonical portable skill tree.
    Portable {
        descriptor: ObjectDescriptor,
        object: StoredSkillTree,
    },
    /// A canonical origin-native skill object.
    Native {
        descriptor: ObjectDescriptor,
        object: NativeSkillObject,
    },
    /// A canonical origin-native executable extension object.
    NativeExtension {
        descriptor: ObjectDescriptor,
        object: NativeExtensionObject,
    },
    /// A canonical JSON-only portable or native capability object.
    Document {
        descriptor: ObjectDescriptor,
        object: VerifiedDocumentObject,
    },
}

/// One parsed canonical JSON-only synchronization object.
#[derive(Clone, Eq, PartialEq)]
pub enum VerifiedDocumentObject {
    PortableInstruction(StoredInstruction),
    NativeInstruction(NativeInstructionRegion),
    PortablePromptCommand(StoredPromptCommand),
    NativePromptCommand(StoredNativePromptCommand),
    PortableAgent(StoredAgent),
    NativeAgent(StoredNativeAgent),
    PortableMcp(StoredMcpServer),
    NativeMcp(StoredNativeMcpEntry),
}

impl VerifiedDocumentObject {
    #[must_use]
    pub const fn kind(&self) -> SnapshotObjectKind {
        match self {
            Self::PortableInstruction(_) => SnapshotObjectKind::PortableInstruction,
            Self::NativeInstruction(_) => SnapshotObjectKind::NativeInstruction,
            Self::PortablePromptCommand(_) => SnapshotObjectKind::PortablePromptCommand,
            Self::NativePromptCommand(_) => SnapshotObjectKind::NativePromptCommand,
            Self::PortableAgent(_) => SnapshotObjectKind::PortableAgent,
            Self::NativeAgent(_) => SnapshotObjectKind::NativeAgent,
            Self::PortableMcp(_) => SnapshotObjectKind::PortableMcp,
            Self::NativeMcp(_) => SnapshotObjectKind::NativeMcp,
        }
    }

    #[must_use]
    pub const fn object_hash(&self) -> &kitrove_model::ContentHash {
        match self {
            Self::PortableInstruction(object) => object.object_hash(),
            Self::NativeInstruction(object) => object.object_hash(),
            Self::PortablePromptCommand(object) => object.object_hash(),
            Self::NativePromptCommand(object) => object.object_hash(),
            Self::PortableAgent(object) => object.object_hash(),
            Self::NativeAgent(object) => object.object_hash(),
            Self::PortableMcp(object) => object.object_hash(),
            Self::NativeMcp(object) => object.object_hash(),
        }
    }

    pub fn to_json(&self) -> Result<String, BackendError> {
        match self {
            Self::PortableInstruction(object) => object.to_json().map_err(|_| object_invalid()),
            Self::NativeInstruction(object) => object.to_json().map_err(|_| object_invalid()),
            Self::PortablePromptCommand(object) => object.to_json().map_err(|_| object_invalid()),
            Self::NativePromptCommand(object) => object.to_json().map_err(|_| object_invalid()),
            Self::PortableAgent(object) => object.to_json().map_err(|_| object_invalid()),
            Self::NativeAgent(object) => object.to_json().map_err(|_| object_invalid()),
            Self::PortableMcp(object) => object.to_json().map_err(|_| object_invalid()),
            Self::NativeMcp(object) => object.to_json().map_err(|_| object_invalid()),
        }
    }

    pub(crate) fn stage(
        &self,
        store: &ObjectStore,
        root: &PortablePath,
        limits: kitrove_agent_skills::CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        match self {
            Self::PortableInstruction(object) => {
                store.stage_portable_instruction(root, object, limits)?;
            }
            Self::NativeInstruction(object) => {
                store.stage_native_instruction(root, object, limits)?;
            }
            Self::PortablePromptCommand(object) => {
                store.stage_portable_prompt_command(root, object, limits)?;
            }
            Self::NativePromptCommand(object) => {
                store.stage_native_prompt_command(root, object, limits)?;
            }
            Self::PortableAgent(object) => {
                store.stage_portable_agent(root, object, limits)?;
            }
            Self::NativeAgent(object) => {
                store.stage_native_agent(root, object, limits)?;
            }
            Self::PortableMcp(object) => {
                store.stage_portable_mcp(root, object, limits)?;
            }
            Self::NativeMcp(object) => {
                store.stage_native_mcp(root, object, limits)?;
            }
        }
        Ok(())
    }

    pub(crate) fn install(
        &self,
        store: &ObjectStore,
        staging: &PortablePath,
        destination: &PortablePath,
        expected_hash: &kitrove_model::ContentHash,
        limits: kitrove_agent_skills::CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        match self {
            Self::PortableInstruction(_) => {
                store.install_portable_instruction(staging, destination, expected_hash, limits)
            }
            Self::NativeInstruction(_) => {
                store.install_native_instruction(staging, destination, expected_hash, limits)
            }
            Self::PortablePromptCommand(_) => {
                store.install_portable_prompt_command(staging, destination, expected_hash, limits)
            }
            Self::NativePromptCommand(_) => {
                store.install_native_prompt_command(staging, destination, expected_hash, limits)
            }
            Self::PortableAgent(_) => {
                store.install_portable_agent(staging, destination, expected_hash, limits)
            }
            Self::NativeAgent(_) => {
                store.install_native_agent(staging, destination, expected_hash, limits)
            }
            Self::PortableMcp(_) => {
                store.install_portable_mcp(staging, destination, expected_hash, limits)
            }
            Self::NativeMcp(_) => {
                store.install_native_mcp(staging, destination, expected_hash, limits)
            }
        }
    }

    pub(crate) fn load(
        store: &ObjectStore,
        root: &PortablePath,
        kind: SnapshotObjectKind,
        limits: kitrove_agent_skills::CaptureLimits,
        encoded_len: u64,
    ) -> Result<Self, ObjectMutationError> {
        let stored = store.capture_document_bounded(root, limits, encoded_len)?;
        match kind {
            SnapshotObjectKind::PortableInstruction => {
                crate::object_store::decode_portable_instruction_object(stored, limits)
                    .map(Self::PortableInstruction)
            }
            SnapshotObjectKind::NativeInstruction => {
                crate::object_store::decode_native_instruction_object(stored)
                    .map(Self::NativeInstruction)
            }
            SnapshotObjectKind::PortablePromptCommand => {
                crate::object_store::decode_portable_prompt_command_object(stored, limits)
                    .map(Self::PortablePromptCommand)
            }
            SnapshotObjectKind::NativePromptCommand => {
                crate::object_store::decode_native_prompt_command_object(stored)
                    .map(Self::NativePromptCommand)
            }
            SnapshotObjectKind::PortableAgent => {
                crate::object_store::decode_portable_agent_object(stored, limits)
                    .map(Self::PortableAgent)
            }
            SnapshotObjectKind::NativeAgent => {
                crate::object_store::decode_native_agent_object(stored).map(Self::NativeAgent)
            }
            SnapshotObjectKind::PortableMcp => {
                crate::object_store::decode_portable_mcp_object(stored).map(Self::PortableMcp)
            }
            SnapshotObjectKind::NativeMcp => {
                crate::object_store::decode_native_mcp_object(stored).map(Self::NativeMcp)
            }
            SnapshotObjectKind::PortableSkillTree
            | SnapshotObjectKind::NativeSkillObject
            | SnapshotObjectKind::NativeExtensionObject => unreachable!("not a document object"),
        }
        .map_err(|()| ObjectMutationError::invalid_object())
    }

    pub(crate) fn clear_staging(
        store: &ObjectStore,
        root: &PortablePath,
        kind: SnapshotObjectKind,
        expected_hash: &kitrove_model::ContentHash,
        limits: kitrove_agent_skills::CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        match kind {
            SnapshotObjectKind::PortableInstruction => {
                store.clear_portable_instruction_staging(root, expected_hash, limits)
            }
            SnapshotObjectKind::NativeInstruction => {
                store.clear_native_instruction_staging(root, expected_hash, limits)
            }
            SnapshotObjectKind::PortablePromptCommand => {
                store.clear_portable_prompt_command_staging(root, expected_hash, limits)
            }
            SnapshotObjectKind::NativePromptCommand => {
                store.clear_native_prompt_command_staging(root, expected_hash, limits)
            }
            SnapshotObjectKind::PortableAgent => {
                store.clear_portable_agent_staging(root, expected_hash, limits)
            }
            SnapshotObjectKind::NativeAgent => {
                store.clear_native_agent_staging(root, expected_hash, limits)
            }
            SnapshotObjectKind::PortableMcp => {
                store.clear_portable_mcp_staging(root, expected_hash, limits)
            }
            SnapshotObjectKind::NativeMcp => {
                store.clear_native_mcp_staging(root, expected_hash, limits)
            }
            SnapshotObjectKind::PortableSkillTree
            | SnapshotObjectKind::NativeSkillObject
            | SnapshotObjectKind::NativeExtensionObject => unreachable!("not a document object"),
        }
    }

    pub(crate) fn from_json(
        kind: SnapshotObjectKind,
        input: &str,
        max_body_bytes: usize,
    ) -> Result<Self, BackendError> {
        match kind {
            SnapshotObjectKind::PortableInstruction => {
                StoredInstruction::from_json(input, max_body_bytes)
                    .map(Self::PortableInstruction)
                    .map_err(|_| object_invalid())
            }
            SnapshotObjectKind::NativeInstruction => NativeInstructionRegion::from_json(input)
                .map(Self::NativeInstruction)
                .map_err(|_| object_invalid()),
            SnapshotObjectKind::PortablePromptCommand => {
                StoredPromptCommand::from_json(input, max_body_bytes)
                    .map(Self::PortablePromptCommand)
                    .map_err(|_| object_invalid())
            }
            SnapshotObjectKind::NativePromptCommand => StoredNativePromptCommand::from_json(input)
                .map(Self::NativePromptCommand)
                .map_err(|_| object_invalid()),
            SnapshotObjectKind::PortableAgent => StoredAgent::from_json(input, max_body_bytes)
                .map(Self::PortableAgent)
                .map_err(|_| object_invalid()),
            SnapshotObjectKind::NativeAgent => StoredNativeAgent::from_json(input)
                .map(Self::NativeAgent)
                .map_err(|_| object_invalid()),
            SnapshotObjectKind::PortableMcp => StoredMcpServer::from_json(input)
                .map(Self::PortableMcp)
                .map_err(|_| object_invalid()),
            SnapshotObjectKind::NativeMcp => StoredNativeMcpEntry::from_json(input)
                .map(Self::NativeMcp)
                .map_err(|_| object_invalid()),
            SnapshotObjectKind::PortableSkillTree
            | SnapshotObjectKind::NativeSkillObject
            | SnapshotObjectKind::NativeExtensionObject => Err(object_invalid()),
        }
    }
}

impl Debug for VerifiedDocumentObject {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDocumentObject")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl VerifiedObjectEnvelope {
    /// Constructs and verifies a portable transport envelope.
    pub fn portable(root: PortablePath, object: StoredSkillTree) -> Result<Self, BackendError> {
        let descriptor = descriptor_for(
            SnapshotObjectKind::PortableSkillTree,
            root,
            object.tree().hash.clone(),
            &object.metadata_json(),
            object.tree(),
        )?;
        Ok(Self::Portable { descriptor, object })
    }

    /// Constructs and verifies an origin-native transport envelope.
    pub fn native(root: PortablePath, object: NativeSkillObject) -> Result<Self, BackendError> {
        let descriptor = descriptor_for(
            SnapshotObjectKind::NativeSkillObject,
            root,
            object.hash().clone(),
            &object.metadata_json(),
            object.tree(),
        )?;
        Ok(Self::Native { descriptor, object })
    }

    /// Constructs and verifies an origin-native extension transport envelope.
    pub fn native_extension(
        root: PortablePath,
        object: NativeExtensionObject,
    ) -> Result<Self, BackendError> {
        let descriptor = descriptor_for(
            SnapshotObjectKind::NativeExtensionObject,
            root,
            object.hash().clone(),
            &object.metadata_json(),
            object.tree(),
        )?;
        Ok(Self::NativeExtension { descriptor, object })
    }

    /// Returns the exact descriptor bound to this verified object.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        match self {
            Self::Portable { descriptor, .. }
            | Self::Native { descriptor, .. }
            | Self::NativeExtension { descriptor, .. }
            | Self::Document { descriptor, .. } => descriptor,
        }
    }

    /// Constructs and verifies a canonical JSON-only capability envelope.
    pub fn document(
        root: PortablePath,
        object: VerifiedDocumentObject,
    ) -> Result<Self, BackendError> {
        let metadata = object.to_json()?;
        let descriptor = descriptor_for(
            object.kind(),
            root,
            object.object_hash().clone(),
            &metadata,
            &CapturedTree {
                hash: hash_tree(&Default::default()),
                files: Default::default(),
            },
        )?;
        Ok(Self::Document { descriptor, object })
    }

    pub(crate) fn reset_incomplete_staging(
        &self,
        store: &ObjectStore,
        staging: &PortablePath,
        limits: kitrove_agent_skills::CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        let descriptor = self.descriptor();
        match descriptor.kind() {
            SnapshotObjectKind::PortableSkillTree => {
                store.reset_incomplete_portable_staging(staging, descriptor.object_hash(), limits)
            }
            SnapshotObjectKind::NativeSkillObject => {
                store.reset_incomplete_native_staging(staging, descriptor.object_hash(), limits)
            }
            SnapshotObjectKind::NativeExtensionObject => store
                .reset_incomplete_native_extension_staging(
                    staging,
                    descriptor.object_hash(),
                    limits,
                ),
            SnapshotObjectKind::PortableInstruction => store
                .reset_incomplete_portable_instruction_staging(
                    staging,
                    descriptor.object_hash(),
                    limits,
                ),
            SnapshotObjectKind::NativeInstruction => store
                .reset_incomplete_native_instruction_staging(
                    staging,
                    descriptor.object_hash(),
                    limits,
                ),
            SnapshotObjectKind::PortablePromptCommand => store
                .reset_incomplete_portable_prompt_command_staging(
                    staging,
                    descriptor.object_hash(),
                    limits,
                ),
            SnapshotObjectKind::NativePromptCommand => store
                .reset_incomplete_native_prompt_command_staging(
                    staging,
                    descriptor.object_hash(),
                    limits,
                ),
            SnapshotObjectKind::PortableAgent => store.reset_incomplete_portable_agent_staging(
                staging,
                descriptor.object_hash(),
                limits,
            ),
            SnapshotObjectKind::NativeAgent => store.reset_incomplete_native_agent_staging(
                staging,
                descriptor.object_hash(),
                limits,
            ),
            SnapshotObjectKind::PortableMcp => store.reset_incomplete_portable_mcp_staging(
                staging,
                descriptor.object_hash(),
                limits,
            ),
            SnapshotObjectKind::NativeMcp => {
                store.reset_incomplete_native_mcp_staging(staging, descriptor.object_hash(), limits)
            }
        }
    }

    pub(crate) fn stage_to(
        &self,
        store: &ObjectStore,
        staging: &PortablePath,
        limits: kitrove_agent_skills::CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        match self {
            Self::Portable { object, .. } => {
                store.stage_portable(staging, object, limits).map(drop)
            }
            Self::Native { object, .. } => store.stage_native(staging, object, limits).map(drop),
            Self::NativeExtension { object, .. } => store
                .stage_native_extension(staging, object, limits)
                .map(drop),
            Self::Document { object, .. } => object.stage(store, staging, limits),
        }
    }

    pub(crate) fn install_from(
        &self,
        store: &ObjectStore,
        staging: &PortablePath,
        limits: kitrove_agent_skills::CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        let descriptor = self.descriptor();
        match self {
            Self::Portable { .. } => {
                store.install_portable(staging, descriptor.root(), descriptor.object_hash(), limits)
            }
            Self::Native { .. } => {
                store.install_native(staging, descriptor.root(), descriptor.object_hash(), limits)
            }
            Self::NativeExtension { .. } => store.install_native_extension(
                staging,
                descriptor.root(),
                descriptor.object_hash(),
                limits,
            ),
            Self::Document { object, .. } => object.install(
                store,
                staging,
                descriptor.root(),
                descriptor.object_hash(),
                limits,
            ),
        }
    }

    pub(crate) fn clear_staging(
        &self,
        store: &ObjectStore,
        staging: &PortablePath,
        limits: kitrove_agent_skills::CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        let descriptor = self.descriptor();
        match descriptor.kind() {
            SnapshotObjectKind::PortableSkillTree => {
                store.clear_portable_staging(staging, descriptor.object_hash(), limits)
            }
            SnapshotObjectKind::NativeSkillObject => {
                store.clear_native_staging(staging, descriptor.object_hash(), limits)
            }
            SnapshotObjectKind::NativeExtensionObject => {
                store.clear_native_extension_staging(staging, descriptor.object_hash(), limits)
            }
            kind @ (SnapshotObjectKind::PortableInstruction
            | SnapshotObjectKind::NativeInstruction
            | SnapshotObjectKind::PortablePromptCommand
            | SnapshotObjectKind::NativePromptCommand
            | SnapshotObjectKind::PortableAgent
            | SnapshotObjectKind::NativeAgent
            | SnapshotObjectKind::PortableMcp
            | SnapshotObjectKind::NativeMcp) => VerifiedDocumentObject::clear_staging(
                store,
                staging,
                kind,
                descriptor.object_hash(),
                limits,
            ),
        }
    }
}

impl Debug for VerifiedObjectEnvelope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedObjectEnvelope")
            .field("kind", &self.descriptor().kind())
            .field("encoded_len", &self.descriptor().encoded_len())
            .finish_non_exhaustive()
    }
}

/// A mutation-free view of current remote snapshot authority.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteSnapshot {
    revision: RemoteRevision,
    snapshot: Option<PortableSnapshotV1>,
}

impl RemoteSnapshot {
    /// Constructs an absent remote observation with its backend-specific absent token.
    #[must_use]
    pub const fn absent(revision: RemoteRevision) -> Self {
        Self {
            revision,
            snapshot: None,
        }
    }

    /// Constructs a present verified remote snapshot observation.
    #[must_use]
    pub const fn present(revision: RemoteRevision, snapshot: PortableSnapshotV1) -> Self {
        Self {
            revision,
            snapshot: Some(snapshot),
        }
    }

    /// Returns the exact opaque revision inspected with this snapshot.
    #[must_use]
    pub const fn revision(&self) -> &RemoteRevision {
        &self.revision
    }

    /// Returns verified snapshot authority when the remote is initialized.
    #[must_use]
    pub const fn snapshot(&self) -> Option<&PortableSnapshotV1> {
        self.snapshot.as_ref()
    }
}

impl Debug for RemoteSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteSnapshot")
            .field("present", &self.snapshot.is_some())
            .finish_non_exhaustive()
    }
}

/// Exact bounded backend-private publication evidence persisted by core.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicationIntent {
    encoded: String,
    proposed_revision: RemoteRevision,
}

impl PublicationIntent {
    /// Reconstructs one exact bounded intent from durable backend-owned bytes.
    pub fn from_persisted(
        encoded: String,
        proposed_revision: RemoteRevision,
        limits: SyncLimits,
    ) -> Result<Self, BackendError> {
        if encoded.is_empty()
            || encoded.len() as u64 > limits.max_control_bytes()
            || encoded.bytes().any(|byte| byte == 0)
        {
            return Err(BackendError::new(
                "sync_backend.intent_invalid",
                "publication intent is not a valid bounded control document",
            ));
        }
        Ok(Self {
            encoded,
            proposed_revision,
        })
    }

    /// Returns the exact backend-owned bytes for durable persistence.
    #[must_use]
    pub fn as_persisted(&self) -> &str {
        &self.encoded
    }

    /// Returns the proposed revision for exact journal and base binding.
    #[must_use]
    pub const fn proposed_revision(&self) -> &RemoteRevision {
        &self.proposed_revision
    }
}

impl Debug for PublicationIntent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationIntent")
            .field("bytes", &self.encoded.len())
            .finish_non_exhaustive()
    }
}

/// Backend-private reconciliation of one exact durable publication intent.
#[derive(Clone, Eq, PartialEq)]
pub enum PublicationStatus {
    /// Positive backend evidence proves the intent is in the selected history.
    Published(RemoteRevision),
    /// Exact expected authority is current, so the same intent may be retried.
    Ready,
    /// Publication cannot be safely proved or retried.
    Uncertain,
}

impl Debug for PublicationStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Published(_) => "PublicationStatus::Published([redacted])",
            Self::Ready => "PublicationStatus::Ready",
            Self::Uncertain => "PublicationStatus::Uncertain",
        })
    }
}

/// Stable path- and content-redacted backend failure.
#[derive(Clone, Eq, PartialEq)]
pub struct BackendError {
    code: &'static str,
    message: &'static str,
}

impl BackendError {
    pub(crate) const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the compiled non-authored explanation.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for BackendError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for BackendError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for BackendError {}

/// Exclusive backend session held after local locks for exact apply revalidation.
pub trait SyncBackendApply {
    /// Reinspects current remote authority under the backend apply lock.
    fn inspect(&mut self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError>;

    /// Fetches and verifies one exact immutable object under the same session.
    fn fetch_object(
        &mut self,
        descriptor: &ObjectDescriptor,
        limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError>;

    /// Deterministically prepares the exact backend-private conditional publication.
    fn prepare_publication(
        &mut self,
        expected: &RemoteRevision,
        publication_id: &PublicationId,
        staged: &PortableSnapshotV1,
        objects: &[VerifiedObjectEnvelope],
        limits: SyncLimits,
    ) -> Result<PublicationIntent, BackendError>;

    /// Attempts only the supplied exact durable publication intent.
    fn publish(
        &mut self,
        intent: &PublicationIntent,
        staged: &PortableSnapshotV1,
        objects: &[VerifiedObjectEnvelope],
        limits: SyncLimits,
    ) -> Result<PublicationStatus, BackendError>;

    /// Reconciles only the supplied exact durable publication intent.
    fn reconcile(
        &mut self,
        intent: &PublicationIntent,
        limits: SyncLimits,
    ) -> Result<PublicationStatus, BackendError>;
}

/// Mutation-free backend session used to bind one plan to a stable remote view.
pub trait SyncBackendRead {
    /// Inspects current remote authority under the backend read session.
    fn inspect(&mut self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError>;

    /// Inspects complete bounded verified ancestry under the same read session.
    fn inspect_history(
        &mut self,
        _limits: SyncLimits,
    ) -> Result<VerifiedRemoteHistory, BackendError> {
        Err(history_unsupported())
    }

    /// Fetches and verifies one immutable object under the same read session.
    fn fetch_object(
        &mut self,
        descriptor: &ObjectDescriptor,
        limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError>;
}

/// Sealed transport-only synchronization backend contract.
pub trait SyncBackend: sealed::Sealed {
    type ReadSession<'a>: SyncBackendRead
    where
        Self: 'a;

    type ApplySession<'a>: SyncBackendApply
    where
        Self: 'a;

    /// Inspects current remote authority without creating backend state.
    fn inspect(&self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError>;

    /// Fetches and verifies one exact immutable object without mutation.
    fn fetch_object(
        &self,
        descriptor: &ObjectDescriptor,
        limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError>;

    /// Acquires a mutation-free session without creating absent backend state.
    fn begin_read(&self, limits: SyncLimits) -> Result<Self::ReadSession<'_>, BackendError>;

    /// Acquires the exclusive backend apply session after local locks.
    fn begin_apply(&self, limits: SyncLimits) -> Result<Self::ApplySession<'_>, BackendError>;
}

fn descriptor_for(
    kind: SnapshotObjectKind,
    root: PortablePath,
    object_hash: kitrove_model::ContentHash,
    metadata: &str,
    tree: &kitrove_agent_skills::CapturedTree,
) -> Result<ObjectDescriptor, BackendError> {
    let mut encoded_len = u64::try_from(metadata.len()).map_err(|_| object_too_large())?;
    for (path, file) in &tree.files {
        encoded_len = encoded_len
            .checked_add(u64::try_from(path.as_str().len()).map_err(|_| object_too_large())?)
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(u64::try_from(file.bytes.len()).ok()?))
            .ok_or_else(object_too_large)?;
    }
    ObjectDescriptor::new(kind, root, object_hash, encoded_len).map_err(|_| object_invalid())
}

const fn history_unsupported() -> BackendError {
    BackendError::new(
        "sync_backend.history_unsupported",
        "this synchronization backend does not expose verified history",
    )
}

const fn object_too_large() -> BackendError {
    BackendError::new(
        "sync_backend.object_too_large",
        "verified object envelope length exceeds the supported range",
    )
}

const fn object_invalid() -> BackendError {
    BackendError::new(
        "sync_backend.object_invalid",
        "verified object envelope is structurally invalid",
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use kitrove_instructions::{InstructionBody, StoredInstruction};
    use kitrove_model::{ContentHash, EnvironmentManifest, SchemaVersion};
    use tempfile::TempDir;

    pub(crate) trait BackendContractFixture {
        type Backend: SyncBackend;

        fn backend(&self) -> &Self::Backend;
        fn assert_exact_fetch_and_immutable_rules(&self);
        fn assert_aba_and_selected_history_rules(&self);
        fn assert_publication_interruption_rules(&self);
        fn assert_alias_and_hostile_filesystem_rules(&self);
        fn assert_aggregate_limit_rules(&self);
        fn assert_redaction_rules(&self);
    }

    pub(crate) fn assert_backend_contract(fixture: &impl BackendContractFixture) {
        assert_backend_lifecycle_contract(fixture.backend());

        fixture.assert_exact_fetch_and_immutable_rules();
        fixture.assert_aba_and_selected_history_rules();
        fixture.assert_publication_interruption_rules();
        fixture.assert_alias_and_hostile_filesystem_rules();
        fixture.assert_aggregate_limit_rules();
        fixture.assert_redaction_rules();
    }

    pub(crate) fn assert_backend_lifecycle_contract(backend: &impl SyncBackend) {
        let limits = SyncLimits::default();
        let absent = backend.inspect(limits).unwrap();
        assert!(absent.snapshot().is_none());
        let snapshot = PortableSnapshotV1::new(
            EnvironmentManifest {
                schema_version: SchemaVersion::V1,
                assets: BTreeMap::new(),
                packs: BTreeMap::new(),
                profiles: BTreeMap::new(),
                required_bindings: BTreeSet::new(),
            },
            BTreeSet::new(),
            limits,
        )
        .unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let mut apply = backend.begin_apply(limits).unwrap();
        let intent = apply
            .prepare_publication(absent.revision(), &publication, &snapshot, &[], limits)
            .unwrap();
        let PublicationStatus::Published(revision) =
            apply.publish(&intent, &snapshot, &[], limits).unwrap()
        else {
            panic!("contract publication must succeed");
        };
        assert_eq!(
            apply.reconcile(&intent, limits).unwrap(),
            PublicationStatus::Published(revision.clone())
        );
        drop(apply);
        let mut read = backend.begin_read(limits).unwrap();
        let selected = read.inspect(limits).unwrap();
        assert_eq!(selected.revision(), &revision);
        assert_eq!(selected.snapshot(), Some(&snapshot));
        drop(read);
        let mut stale = backend.begin_apply(limits).unwrap();
        assert!(
            stale
                .prepare_publication(absent.revision(), &publication, &snapshot, &[], limits)
                .is_err()
        );
        drop(stale);
    }

    #[test]
    fn document_envelope_stages_and_loads_through_shared_dispatch() {
        let temporary = TempDir::new().unwrap();
        let store = ObjectStore::open(&temporary.path().canonicalize().unwrap()).unwrap();
        let root = PortablePath::parse("instruction-stage").unwrap();
        let object = VerifiedDocumentObject::PortableInstruction(StoredInstruction::new(
            InstructionBody::parse("Keep changes small.\n", 1024).unwrap(),
        ));
        let envelope = VerifiedObjectEnvelope::document(root.clone(), object.clone()).unwrap();
        object
            .stage(
                &store,
                &root,
                kitrove_agent_skills::CaptureLimits::default(),
            )
            .unwrap();
        let undersized = envelope.descriptor().encoded_len() - 1;
        assert!(
            VerifiedDocumentObject::load(
                &store,
                &root,
                SnapshotObjectKind::PortableInstruction,
                kitrove_agent_skills::CaptureLimits::default(),
                undersized,
            )
            .is_err()
        );
        let loaded = VerifiedDocumentObject::load(
            &store,
            &root,
            SnapshotObjectKind::PortableInstruction,
            kitrove_agent_skills::CaptureLimits::default(),
            envelope.descriptor().encoded_len(),
        )
        .unwrap();
        let loaded_envelope = VerifiedObjectEnvelope::document(root, loaded).unwrap();
        assert_eq!(loaded_envelope, envelope);
    }

    #[test]
    fn intent_and_status_debug_redact_backend_canaries() {
        let revision_canary = "DO_NOT_ECHO_BACKEND_REVISION_62af";
        let intent_canary = "DO_NOT_ECHO_PUBLICATION_INTENT_a931";
        let revision = RemoteRevision::parse(revision_canary).unwrap();
        let intent = PublicationIntent::from_persisted(
            intent_canary.to_owned(),
            revision.clone(),
            SyncLimits::default(),
        )
        .unwrap();

        assert!(!format!("{intent:?}").contains(intent_canary));
        assert!(!format!("{:?}", PublicationStatus::Published(revision)).contains(revision_canary));
    }

    #[test]
    fn oversized_or_empty_intent_is_refused_without_echo() {
        let limits = SyncLimits::new(8, 8, 4, 4, 1, 1, 1, 1, 1, 1).unwrap();
        let revision = RemoteRevision::parse("revision").unwrap();
        assert_eq!(
            PublicationIntent::from_persisted(String::new(), revision.clone(), limits)
                .unwrap_err()
                .code(),
            "sync_backend.intent_invalid"
        );
        let canary = "SECRET-CANARY";
        let error =
            PublicationIntent::from_persisted(canary.to_owned(), revision, limits).unwrap_err();
        assert!(!error.to_string().contains(canary));
        assert!(!format!("{error:?}").contains(canary));
    }

    #[test]
    fn object_error_debug_is_structural() {
        let error = descriptor_for(
            SnapshotObjectKind::PortableSkillTree,
            PortablePath::parse("objects/example").unwrap(),
            ContentHash::digest(b"object"),
            "",
            &kitrove_agent_skills::CapturedTree {
                files: Default::default(),
                hash: ContentHash::digest(b"tree"),
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "sync_backend.object_invalid");
    }
}
