use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    AssetId, BindingName, ContentHash, HarnessId, PortablePath, ProfileId, Revision,
    ValidationError,
};

const MAX_REMOTE_REVISION_BYTES: usize = 1024;

/// Hard maximum semantic components supported by one synchronization plan.
pub const MAX_SUPPORTED_SYNC_COMPONENTS: usize = 65_536;
/// Default maximum semantic components visited by one synchronization plan.
pub const DEFAULT_MAX_SYNC_COMPONENTS: usize = MAX_SUPPORTED_SYNC_COMPONENTS;

macro_rules! qualified_digest {
    ($name:ident, $prefix:literal, $label:literal, $code:literal) => {
        #[doc = concat!("A validated ", $label, ".")]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Parses a ", $label, ".")]
            pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                let Some(digest) = value.strip_prefix($prefix) else {
                    return Err(ValidationError::new(
                        concat!($code, ".unsupported_format"),
                        concat!($label, " uses an unsupported format"),
                    ));
                };
                if digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(ValidationError::new(
                        concat!($code, ".invalid_digest"),
                        concat!($label, " must contain 64 lowercase hexadecimal digits"),
                    ));
                }
                Ok(Self(value))
            }

            #[doc = concat!("Returns the ", $label, ".")]
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

qualified_digest!(
    SnapshotDigest,
    "snapshot:blake3:",
    "snapshot digest",
    "snapshot_digest"
);
qualified_digest!(RemoteKey, "remote:blake3:", "remote key", "remote_key");
qualified_digest!(
    PublicationId,
    "publication:blake3:",
    "publication ID",
    "publication_id"
);

/// Bounded opaque concurrency evidence returned by a synchronization backend.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RemoteRevision(String);

impl RemoteRevision {
    /// Parses bounded printable ASCII without interpreting backend semantics.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REMOTE_REVISION_BYTES
            || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(ValidationError::new(
                "remote_revision.invalid",
                "remote revision must be non-empty printable ASCII within 1024 bytes",
            ));
        }
        Ok(Self(value))
    }

    /// Returns opaque backend evidence for an explicit backend comparison.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RemoteRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl Debug for RemoteRevision {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteRevision")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Refusing request-global synchronization budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncLimits {
    max_snapshot_bytes: u64,
    max_control_bytes: u64,
    max_manifest_bytes: u64,
    max_lock_bytes: u64,
    max_object_count: usize,
    max_object_bytes: u64,
    max_total_object_bytes: u64,
    max_conflicts: usize,
    max_components: usize,
    max_backend_history: usize,
    git: GitSyncLimits,
}

/// Refusing request-global budgets for the bounded Git HTTPS backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitSyncLimits {
    max_response_header_bytes: usize,
    http_input_buffer_bytes: usize,
    http_output_buffer_bytes: usize,
    max_response_body_bytes: u64,
    max_request_body_bytes: u64,
    max_advertisement_bytes: u64,
    max_advertisement_refs: usize,
    max_packet_lines: usize,
    max_received_pack_bytes: u64,
    max_decoded_objects: usize,
    max_decoded_object_bytes: u64,
    max_total_decoded_object_bytes: u64,
    max_delta_depth: usize,
    connect_timeout_ms: u64,
    response_header_timeout_ms: u64,
    body_read_timeout_ms: u64,
    exchange_deadline_ms: u64,
    operation_deadline_ms: u64,
}

impl GitSyncLimits {
    /// Creates internally consistent, non-zero refusing Git transport limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_response_header_bytes: usize,
        http_input_buffer_bytes: usize,
        http_output_buffer_bytes: usize,
        max_response_body_bytes: u64,
        max_request_body_bytes: u64,
        max_advertisement_bytes: u64,
        max_advertisement_refs: usize,
        max_packet_lines: usize,
        max_received_pack_bytes: u64,
        max_decoded_objects: usize,
        max_decoded_object_bytes: u64,
        max_total_decoded_object_bytes: u64,
        max_delta_depth: usize,
        connect_timeout_ms: u64,
        response_header_timeout_ms: u64,
        body_read_timeout_ms: u64,
        exchange_deadline_ms: u64,
        operation_deadline_ms: u64,
    ) -> Result<Self, ValidationError> {
        if [
            max_response_header_bytes,
            http_input_buffer_bytes,
            http_output_buffer_bytes,
            max_advertisement_refs,
            max_packet_lines,
            max_decoded_objects,
            max_delta_depth,
        ]
        .contains(&0)
            || [
                max_response_body_bytes,
                max_request_body_bytes,
                max_advertisement_bytes,
                max_received_pack_bytes,
                max_decoded_object_bytes,
                max_total_decoded_object_bytes,
                connect_timeout_ms,
                response_header_timeout_ms,
                body_read_timeout_ms,
                exchange_deadline_ms,
                operation_deadline_ms,
            ]
            .contains(&0)
            || max_response_body_bytes < max_received_pack_bytes
            || max_total_decoded_object_bytes < max_decoded_object_bytes
            || operation_deadline_ms < exchange_deadline_ms
        {
            return Err(ValidationError::new(
                "git_sync_limits.invalid",
                "Git synchronization limits must be non-zero and internally consistent",
            ));
        }
        Ok(Self {
            max_response_header_bytes,
            http_input_buffer_bytes,
            http_output_buffer_bytes,
            max_response_body_bytes,
            max_request_body_bytes,
            max_advertisement_bytes,
            max_advertisement_refs,
            max_packet_lines,
            max_received_pack_bytes,
            max_decoded_objects,
            max_decoded_object_bytes,
            max_total_decoded_object_bytes,
            max_delta_depth,
            connect_timeout_ms,
            response_header_timeout_ms,
            body_read_timeout_ms,
            exchange_deadline_ms,
            operation_deadline_ms,
        })
    }

    /// Returns the maximum complete response-header bytes for one exchange.
    #[must_use]
    pub const fn max_response_header_bytes(self) -> usize {
        self.max_response_header_bytes
    }
    /// Returns the fixed HTTP input-buffer bytes.
    #[must_use]
    pub const fn http_input_buffer_bytes(self) -> usize {
        self.http_input_buffer_bytes
    }
    /// Returns the fixed HTTP output-buffer bytes.
    #[must_use]
    pub const fn http_output_buffer_bytes(self) -> usize {
        self.http_output_buffer_bytes
    }
    /// Returns the aggregate response-body byte budget.
    #[must_use]
    pub const fn max_response_body_bytes(self) -> u64 {
        self.max_response_body_bytes
    }
    /// Returns the maximum outbound request-body bytes.
    #[must_use]
    pub const fn max_request_body_bytes(self) -> u64 {
        self.max_request_body_bytes
    }
    /// Returns the advertisement packet-byte budget.
    #[must_use]
    pub const fn max_advertisement_bytes(self) -> u64 {
        self.max_advertisement_bytes
    }
    /// Returns the maximum advertised refs.
    #[must_use]
    pub const fn max_advertisement_refs(self) -> usize {
        self.max_advertisement_refs
    }
    /// Returns the aggregate packet-line record budget.
    #[must_use]
    pub const fn max_packet_lines(self) -> usize {
        self.max_packet_lines
    }
    /// Returns the maximum received pack bytes.
    #[must_use]
    pub const fn max_received_pack_bytes(self) -> u64 {
        self.max_received_pack_bytes
    }
    /// Returns the maximum decoded Git object count.
    #[must_use]
    pub const fn max_decoded_objects(self) -> usize {
        self.max_decoded_objects
    }
    /// Returns the maximum bytes in one decoded Git object.
    #[must_use]
    pub const fn max_decoded_object_bytes(self) -> u64 {
        self.max_decoded_object_bytes
    }
    /// Returns the aggregate decoded Git object-byte budget.
    #[must_use]
    pub const fn max_total_decoded_object_bytes(self) -> u64 {
        self.max_total_decoded_object_bytes
    }
    /// Returns the maximum delta-chain depth.
    #[must_use]
    pub const fn max_delta_depth(self) -> usize {
        self.max_delta_depth
    }
    /// Returns the connection timeout in milliseconds.
    #[must_use]
    pub const fn connect_timeout_ms(self) -> u64 {
        self.connect_timeout_ms
    }
    /// Returns the response-header timeout in milliseconds.
    #[must_use]
    pub const fn response_header_timeout_ms(self) -> u64 {
        self.response_header_timeout_ms
    }
    /// Returns the body-read inactivity timeout in milliseconds.
    #[must_use]
    pub const fn body_read_timeout_ms(self) -> u64 {
        self.body_read_timeout_ms
    }
    /// Returns the deadline for one HTTP exchange in milliseconds.
    #[must_use]
    pub const fn exchange_deadline_ms(self) -> u64 {
        self.exchange_deadline_ms
    }
    /// Returns the deadline for one backend operation in milliseconds.
    #[must_use]
    pub const fn operation_deadline_ms(self) -> u64 {
        self.operation_deadline_ms
    }
}

impl Default for GitSyncLimits {
    fn default() -> Self {
        Self::new(
            32 * 1024,
            8 * 1024,
            8 * 1024,
            512 * 1024 * 1024,
            384 * 1024 * 1024,
            4 * 1024 * 1024,
            4096,
            DEFAULT_MAX_SYNC_COMPONENTS,
            384 * 1024 * 1024,
            16_384,
            32 * 1024 * 1024,
            512 * 1024 * 1024,
            64,
            10_000,
            15_000,
            15_000,
            120_000,
            300_000,
        )
        .expect("compiled Git synchronization limits are internally consistent")
    }
}

impl SyncLimits {
    /// Creates internally consistent, non-zero refusing limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_snapshot_bytes: u64,
        max_control_bytes: u64,
        max_manifest_bytes: u64,
        max_lock_bytes: u64,
        max_object_count: usize,
        max_object_bytes: u64,
        max_total_object_bytes: u64,
        max_conflicts: usize,
        max_components: usize,
        max_backend_history: usize,
    ) -> Result<Self, ValidationError> {
        if [
            max_snapshot_bytes,
            max_control_bytes,
            max_manifest_bytes,
            max_lock_bytes,
            max_object_bytes,
            max_total_object_bytes,
        ]
        .contains(&0)
            || [
                max_object_count,
                max_conflicts,
                max_components,
                max_backend_history,
            ]
            .contains(&0)
            || max_components > MAX_SUPPORTED_SYNC_COMPONENTS
            || max_total_object_bytes < max_object_bytes
            || max_snapshot_bytes < max_manifest_bytes.saturating_add(max_lock_bytes)
        {
            return Err(ValidationError::new(
                "sync_limits.invalid",
                "sync limits must be non-zero and internally consistent",
            ));
        }
        Ok(Self {
            max_snapshot_bytes,
            max_control_bytes,
            max_manifest_bytes,
            max_lock_bytes,
            max_object_count,
            max_object_bytes,
            max_total_object_bytes,
            max_conflicts,
            max_components,
            max_backend_history,
            git: GitSyncLimits::default(),
        })
    }

    /// Replaces the Git transport limits while preserving shared sync limits.
    #[must_use]
    pub const fn with_git_limits(mut self, git: GitSyncLimits) -> Self {
        self.git = git;
        self
    }

    /// Returns the refusing Git transport limits.
    #[must_use]
    pub const fn git(self) -> GitSyncLimits {
        self.git
    }

    /// Returns the maximum encoded snapshot bytes.
    #[must_use]
    pub const fn max_snapshot_bytes(self) -> u64 {
        self.max_snapshot_bytes
    }
    /// Returns the maximum local control-document bytes.
    #[must_use]
    pub const fn max_control_bytes(self) -> u64 {
        self.max_control_bytes
    }
    /// Returns the maximum canonical manifest bytes.
    #[must_use]
    pub const fn max_manifest_bytes(self) -> u64 {
        self.max_manifest_bytes
    }
    /// Returns the maximum canonical lock bytes.
    #[must_use]
    pub const fn max_lock_bytes(self) -> u64 {
        self.max_lock_bytes
    }
    /// Returns the maximum immutable object count.
    #[must_use]
    pub const fn max_object_count(self) -> usize {
        self.max_object_count
    }
    /// Returns the maximum bytes for one immutable object envelope.
    #[must_use]
    pub const fn max_object_bytes(self) -> u64 {
        self.max_object_bytes
    }
    /// Returns the maximum aggregate immutable object bytes.
    #[must_use]
    pub const fn max_total_object_bytes(self) -> u64 {
        self.max_total_object_bytes
    }
    /// Returns the maximum retained structured conflicts.
    #[must_use]
    pub const fn max_conflicts(self) -> usize {
        self.max_conflicts
    }
    /// Returns the maximum semantic components visited by one plan.
    #[must_use]
    pub const fn max_components(self) -> usize {
        self.max_components
    }
    /// Returns the maximum backend publication heads visited by one request.
    #[must_use]
    pub const fn max_backend_history(self) -> usize {
        self.max_backend_history
    }
}

impl Default for SyncLimits {
    fn default() -> Self {
        Self::new(
            256 * 1024 * 1024,
            4 * 1024 * 1024,
            4 * 1024 * 1024,
            4 * 1024 * 1024,
            4096,
            16 * 1024 * 1024,
            240 * 1024 * 1024,
            1024,
            65_536,
            4096,
        )
        .expect("compiled synchronization limits are internally consistent")
    }
}

/// The immutable envelope shape named by one snapshot descriptor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotObjectKind {
    PortableSkillTree,
    NativeSkillObject,
    NativeExtensionObject,
    PortableInstruction,
    NativeInstruction,
    PortablePromptCommand,
    NativePromptCommand,
    PortableAgent,
    NativeAgent,
    PortableMcp,
    NativeMcp,
}

impl SnapshotObjectKind {
    /// Returns whether this object is stored as a directory tree rather than one document.
    #[must_use]
    pub const fn is_tree_backed(self) -> bool {
        matches!(
            self,
            Self::PortableSkillTree | Self::NativeSkillObject | Self::NativeExtensionObject
        )
    }
}

/// A bounded immutable object reference carried by a snapshot or retained base.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ObjectDescriptor {
    kind: SnapshotObjectKind,
    root: PortablePath,
    object_hash: ContentHash,
    encoded_len: u64,
}

impl<'de> Deserialize<'de> for ObjectDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PersistedDescriptor {
            kind: SnapshotObjectKind,
            root: PortablePath,
            object_hash: ContentHash,
            encoded_len: u64,
        }
        let value = PersistedDescriptor::deserialize(deserializer)?;
        Self::new(value.kind, value.root, value.object_hash, value.encoded_len)
            .map_err(D::Error::custom)
    }
}

impl ObjectDescriptor {
    /// Constructs a non-empty immutable object descriptor.
    pub fn new(
        kind: SnapshotObjectKind,
        root: PortablePath,
        object_hash: ContentHash,
        encoded_len: u64,
    ) -> Result<Self, ValidationError> {
        if encoded_len == 0 {
            return Err(ValidationError::new(
                "sync_objects.empty_object",
                "object descriptor encoded length must be non-zero",
            ));
        }
        Ok(Self {
            kind,
            root,
            object_hash,
            encoded_len,
        })
    }

    /// Returns the immutable envelope kind.
    #[must_use]
    pub const fn kind(&self) -> SnapshotObjectKind {
        self.kind
    }

    /// Returns the portable object root.
    #[must_use]
    pub const fn root(&self) -> &PortablePath {
        &self.root
    }

    /// Returns the immutable object identity.
    #[must_use]
    pub const fn object_hash(&self) -> &ContentHash {
        &self.object_hash
    }

    /// Returns the bounded encoded envelope length.
    #[must_use]
    pub const fn encoded_len(&self) -> u64 {
        self.encoded_len
    }
}

/// Machine-local evidence for the last accepted snapshot of one remote.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncBaseRecord {
    schema_version: u32,
    remote_key: RemoteKey,
    snapshot_digest: SnapshotDigest,
    manifest_revision: Revision,
    backend_revision: RemoteRevision,
    objects: BTreeSet<ObjectDescriptor>,
}

impl SyncBaseRecord {
    /// Derives the existing generation identity from exact encoded bytes.
    /// This checksum does not validate the document or grant storage authority.
    #[must_use]
    pub fn generation_id_for_json(record: &str) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-sync-base-generation-v1\0");
        hasher.update(&(record.len() as u64).to_be_bytes());
        hasher.update(record.as_bytes());
        ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
            .expect("BLAKE3 produces a valid content hash")
    }

    /// Constructs and validates a version-1 retained base.
    pub fn new(
        remote_key: RemoteKey,
        snapshot_digest: SnapshotDigest,
        manifest_revision: Revision,
        backend_revision: RemoteRevision,
        objects: BTreeSet<ObjectDescriptor>,
        limits: SyncLimits,
    ) -> Result<Self, ValidationError> {
        validate_descriptors(&objects, limits)?;
        Ok(Self {
            schema_version: 1,
            remote_key,
            snapshot_digest,
            manifest_revision,
            backend_revision,
            objects,
        })
    }

    /// Parses a strict bounded local base document.
    pub fn from_json(input: &str, limits: SyncLimits) -> Result<Self, ValidationError> {
        if input.len() as u64 > limits.max_control_bytes() {
            return Err(ValidationError::new(
                "sync_base.too_large",
                "sync base exceeds the configured control-document limit",
            ));
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PersistedBase {
            schema_version: u32,
            remote_key: RemoteKey,
            snapshot_digest: SnapshotDigest,
            manifest_revision: Revision,
            backend_revision: RemoteRevision,
            #[serde(default)]
            objects: BTreeSet<ObjectDescriptor>,
        }
        let value: PersistedBase = serde_json::from_str(input).map_err(|_| {
            ValidationError::new(
                "sync_base.invalid_json",
                "sync base is not valid strict JSON",
            )
        })?;
        if value.schema_version != 1 {
            return Err(ValidationError::new(
                "sync_base.unsupported_version",
                "sync base schema version is unsupported",
            ));
        }
        Self::new(
            value.remote_key,
            value.snapshot_digest,
            value.manifest_revision,
            value.backend_revision,
            value.objects,
            limits,
        )
    }

    /// Serializes a validated local base deterministically.
    pub fn to_json(&self, limits: SyncLimits) -> Result<String, ValidationError> {
        validate_descriptors(&self.objects, limits)?;
        let mut encoded = serde_json::to_string_pretty(self).map_err(|_| {
            ValidationError::new("sync_base.serialize", "sync base serialization failed")
        })?;
        encoded.push('\n');
        if encoded.len() as u64 > limits.max_control_bytes() {
            return Err(ValidationError::new(
                "sync_base.too_large",
                "sync base exceeds the configured control-document limit",
            ));
        }
        Ok(encoded)
    }

    /// Returns the hashed local remote identity.
    #[must_use]
    pub const fn remote_key(&self) -> &RemoteKey {
        &self.remote_key
    }

    /// Returns the accepted portable snapshot identity.
    #[must_use]
    pub const fn snapshot_digest(&self) -> &SnapshotDigest {
        &self.snapshot_digest
    }

    /// Returns the accepted manifest revision.
    #[must_use]
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    /// Returns the opaque backend revision used for the next comparison.
    #[must_use]
    pub const fn backend_revision(&self) -> &RemoteRevision {
        &self.backend_revision
    }

    /// Returns the exact accepted immutable object descriptors.
    #[must_use]
    pub const fn objects(&self) -> &BTreeSet<ObjectDescriptor> {
        &self.objects
    }
}

impl Debug for SyncBaseRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncBaseRecord")
            .field("schema_version", &self.schema_version)
            .field("objects", &self.objects.len())
            .finish_non_exhaustive()
    }
}

fn validate_descriptors(
    objects: &BTreeSet<ObjectDescriptor>,
    limits: SyncLimits,
) -> Result<(), ValidationError> {
    if objects.len() > limits.max_object_count() {
        return Err(ValidationError::new(
            "sync_objects.count_exceeded",
            "object descriptor count exceeds the configured limit",
        ));
    }
    let mut roots = BTreeSet::new();
    let mut total = 0_u64;
    for object in objects {
        if object.encoded_len == 0 {
            return Err(ValidationError::new(
                "sync_objects.empty_object",
                "object descriptor encoded length must be non-zero",
            ));
        }
        if object.encoded_len > limits.max_object_bytes() {
            return Err(ValidationError::new(
                "sync_objects.object_bytes_exceeded",
                "one object descriptor exceeds the configured byte limit",
            ));
        }
        total = total.checked_add(object.encoded_len).ok_or_else(|| {
            ValidationError::new(
                "sync_objects.total_bytes_exceeded",
                "aggregate object descriptor bytes overflow the configured limit",
            )
        })?;
        if total > limits.max_total_object_bytes() {
            return Err(ValidationError::new(
                "sync_objects.total_bytes_exceeded",
                "aggregate object descriptor bytes exceed the configured limit",
            ));
        }
        if !roots.insert(object.root.clone()) {
            return Err(ValidationError::new(
                "sync_objects.duplicate_root",
                "multiple object descriptors claim one portable root",
            ));
        }
    }
    Ok(())
}

/// Stable non-secret category for a semantic synchronization conflict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncConflictCode {
    DivergentComponent,
    DeletionUnsupported,
    ComponentUnsupported,
    BootstrapAmbiguous,
}

impl SyncConflictCode {
    /// Returns the stable public error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DivergentComponent => "sync.divergent_component",
            Self::DeletionUnsupported => "sync.deletion_unsupported",
            Self::ComponentUnsupported => "sync.component_unsupported",
            Self::BootstrapAmbiguous => "sync.bootstrap_ambiguous",
        }
    }

    /// Returns the compiled non-authored explanation.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::DivergentComponent => "both sides changed the same semantic component",
            Self::DeletionUnsupported => "automatic deletion is not supported in Gate D",
            Self::ComponentUnsupported => "this semantic component is not mergeable in Gate D",
            Self::BootstrapAmbiguous => "distinct non-empty states have no retained merge base",
        }
    }
}

/// Typed location of one semantic synchronization conflict.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SyncConflictSubject {
    AssetKind { asset: AssetId },
    Portable { asset: AssetId },
    Native { asset: AssetId, harness: HarnessId },
    Pack { pack: AssetId },
    Profile { profile: ProfileId },
    RequiredBinding { binding: BindingName },
    Bootstrap,
}

impl Debug for SyncConflictSubject {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AssetKind { .. } => "AssetKind([redacted])",
            Self::Portable { .. } => "Portable([redacted])",
            Self::Native { .. } => "Native([redacted])",
            Self::Pack { .. } => "Pack([redacted])",
            Self::Profile { .. } => "Profile([redacted])",
            Self::RequiredBinding { .. } => "RequiredBinding([redacted])",
            Self::Bootstrap => "Bootstrap",
        })
    }
}

/// One bounded structured conflict; it never carries authored content or object bytes.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncConflict {
    pub code: SyncConflictCode,
    pub subject: SyncConflictSubject,
}

impl Debug for SyncConflict {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncConflict")
            .field("code", &self.code.as_str())
            .field("subject", &self.subject)
            .finish()
    }
}
