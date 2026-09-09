use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_model::{EnvironmentManifest, ObjectDescriptor, PortablePath, SyncLimits};

use crate::{
    NativeExtensionObservation, NativeExtensionPlan, ObjectStore, PortableSnapshotV1,
    SyncPortableCommitOutcome, VerifiedObjectEnvelope, commit_sync_portable_snapshot,
};

/// A redacted failure to commit one native extension plan.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeExtensionCommitError {
    code: &'static str,
    message: &'static str,
}

impl NativeExtensionCommitError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for NativeExtensionCommitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeExtensionCommitError")
            .field("code", &self.code)
            .finish()
    }
}
impl Display for NativeExtensionCommitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}
impl Error for NativeExtensionCommitError {}

/// Commits a fresh native extension plan through the crash-recoverable portable transaction.
///
/// `current_objects` and `proposed_objects` must be complete exact catalogs for their respective
/// manifests. This commits portable preservation authority only; it grants no materialization or
/// execution trust.
#[allow(clippy::too_many_arguments)]
pub fn commit_native_extension_plan(
    environment_root: &Path,
    plan: &NativeExtensionPlan,
    reread_observation: &NativeExtensionObservation,
    current_objects: &[VerifiedObjectEnvelope],
    proposed_objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<SyncPortableCommitOutcome, NativeExtensionCommitError> {
    let store = ObjectStore::open(environment_root).map_err(|_| storage_error())?;
    let manifest_text = store
        .read_text(
            &PortablePath::parse("kitrove.toml").expect("fixed portable path"),
            usize::try_from(limits.max_manifest_bytes()).unwrap_or(usize::MAX),
        )
        .map_err(|_| storage_error())?
        .ok_or_else(storage_error)?;
    let current_manifest = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| {
        commit_error(
            "native_extension.manifest_invalid",
            "current manifest authority is invalid",
        )
    })?;
    plan.ensure_fresh(reread_observation, &current_manifest)
        .map_err(|_| commit_error("native_extension.plan_stale", "the extension plan is stale"))?;

    let expected_local =
        PortableSnapshotV1::new(current_manifest, descriptors(current_objects)?, limits)
            .map_err(|_| catalog_error())?;
    let merged = PortableSnapshotV1::new(
        plan.proposed_manifest().clone(),
        descriptors(proposed_objects)?,
        limits,
    )
    .map_err(|_| catalog_error())?;

    let selected_native = plan
        .asset()
        .native_variants
        .get(&kitrove_model::HarnessId::Pi)
        .ok_or_else(catalog_error)?;
    let exact_plan_object = proposed_objects.iter().any(|object| {
        matches!(object, VerifiedObjectEnvelope::NativeExtension { object, .. } if object == plan.native_object())
            && object.descriptor().root() == &selected_native.root
            && object.descriptor().object_hash() == &selected_native.object_hash
    });
    if !exact_plan_object {
        return Err(catalog_error());
    }
    drop(store);

    commit_sync_portable_snapshot(
        environment_root,
        &expected_local,
        &merged,
        proposed_objects,
        plan.digest(),
        limits,
    )
    .map_err(|_| {
        commit_error(
            "native_extension.commit_failed",
            "native extension transaction did not commit",
        )
    })
}

fn descriptors(
    objects: &[VerifiedObjectEnvelope],
) -> Result<BTreeSet<ObjectDescriptor>, NativeExtensionCommitError> {
    let descriptors: BTreeSet<_> = objects
        .iter()
        .map(|object| object.descriptor().clone())
        .collect();
    if descriptors.len() != objects.len() {
        Err(catalog_error())
    } else {
        Ok(descriptors)
    }
}

fn storage_error() -> NativeExtensionCommitError {
    commit_error(
        "native_extension.storage_unavailable",
        "portable environment authority is unavailable",
    )
}

fn catalog_error() -> NativeExtensionCommitError {
    commit_error(
        "native_extension.object_catalog_invalid",
        "the exact object catalog does not match manifest authority",
    )
}

const fn commit_error(code: &'static str, message: &'static str) -> NativeExtensionCommitError {
    NativeExtensionCommitError { code, message }
}
