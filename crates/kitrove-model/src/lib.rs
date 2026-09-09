#![forbid(unsafe_code)]
//! Harness-neutral domain and persistence contracts for Kitrove.

mod asset;
mod content;
mod error;
mod fidelity;
mod identity;
mod local;
mod mcp;
mod portable;
mod sync;
mod sync_base_pointer;
mod validation;

pub use asset::{
    Asset, AssetKind, ComponentProvenance, LockedAsset, LockedPack, NativeVariant, Pack,
    PortableContent, ResolvedSource, Source,
};
pub use content::{ContentClass, ContentHash, PortablePath, RepositoryUrl};
pub use error::ValidationError;
pub use fidelity::{
    BlockedRequirement, Fidelity, FidelityEvidence, FidelityReason, FidelityResult,
};
pub use identity::{
    AssetId, BindingName, CommunityHarnessId, EnvironmentVariableName, HarnessId, HarnessScope,
    InvalidAssetId, MachineId, NormalizedDestination, PackApplicationId, ProfileId, ProvenanceId,
    ReceiptId, Revision,
};
pub use kitrove_windows_names::is_lossless_windows_component;
pub use local::{
    BindingResolver, DeploymentReceipt, LocalState, MachineConfig, PackApplicationClaim,
    ReceiptTarget, ScanRecord, TrustDecision,
};
pub use mcp::is_portable_mcp_server_name;
pub use portable::{EnvironmentManifest, Lockfile, Profile, SchemaVersion};
pub use sync::{
    DEFAULT_MAX_SYNC_COMPONENTS, GitSyncLimits, MAX_SUPPORTED_SYNC_COMPONENTS, ObjectDescriptor,
    PublicationId, RemoteKey, RemoteRevision, SnapshotDigest, SnapshotObjectKind, SyncBaseRecord,
    SyncConflict, SyncConflictCode, SyncConflictSubject, SyncLimits,
};
pub use sync_base_pointer::SyncBasePointer;
pub use validation::Validate;
