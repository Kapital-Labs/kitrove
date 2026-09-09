use kitrove_agent_skills::{CaptureLimits, CapturedTree};
use kitrove_model::{ContentHash, PortablePath};

use crate::read_only_fs::RegularFileMode;
use crate::{NativeExtensionObject, ObjectMutationError, ObjectStore};

/// Exact target identity shared by single-item and atomic-batch apply transactions.
pub(crate) enum ApplyTargetIdentity<'a> {
    Skill(&'a ContentHash),
    Extension(&'a NativeExtensionObject),
    ExactText {
        text: &'a str,
        mode: RegularFileMode,
        max_bytes: usize,
    },
}

/// Exact target bytes and identity required to stage one apply participant.
pub(crate) enum ApplyTargetMaterialization<'a> {
    Skill {
        tree: &'a CapturedTree,
        rendered_hash: &'a ContentHash,
    },
    Extension(&'a NativeExtensionObject),
    ExactText {
        text: &'a str,
        mode: RegularFileMode,
        max_bytes: usize,
    },
}

pub(crate) fn stage(
    store: &ObjectStore,
    staging_root: &PortablePath,
    materialization: &ApplyTargetMaterialization<'_>,
    limits: CaptureLimits,
) -> Result<(), ObjectMutationError> {
    match materialization {
        ApplyTargetMaterialization::Skill {
            tree,
            rendered_hash,
        } => store.stage_rendered_directory(staging_root, tree, rendered_hash, limits),
        ApplyTargetMaterialization::Extension(object) => {
            store.stage_extension_target(staging_root, object, limits)
        }
        ApplyTargetMaterialization::ExactText {
            text,
            mode,
            max_bytes,
        } => store.stage_text_with_mode(staging_root, text, *mode, *max_bytes),
    }
}

pub(crate) fn install(
    store: &ObjectStore,
    staging_root: &PortablePath,
    destination_root: &PortablePath,
    identity: &ApplyTargetIdentity<'_>,
    limits: CaptureLimits,
) -> Result<(), ObjectMutationError> {
    match identity {
        ApplyTargetIdentity::Skill(rendered_hash) => {
            store.install_rendered_directory(staging_root, destination_root, rendered_hash, limits)
        }
        ApplyTargetIdentity::Extension(object) => {
            store.install_extension_target(staging_root, destination_root, object, limits)
        }
        ApplyTargetIdentity::ExactText {
            text,
            mode,
            max_bytes,
        } => {
            store.install_staged_exact_text(staging_root, destination_root, text, *mode, *max_bytes)
        }
    }
}

pub(crate) fn quarantine(
    store: &ObjectStore,
    destination_root: &PortablePath,
    backup_root: &PortablePath,
    identity: &ApplyTargetIdentity<'_>,
    limits: CaptureLimits,
) -> Result<(), ObjectMutationError> {
    match identity {
        ApplyTargetIdentity::Skill(rendered_hash) => store.quarantine_rendered_directory(
            destination_root,
            backup_root,
            rendered_hash,
            limits,
        ),
        ApplyTargetIdentity::Extension(object) => {
            store.quarantine_extension_target(destination_root, backup_root, object, limits)
        }
        ApplyTargetIdentity::ExactText {
            text,
            mode,
            max_bytes,
        } => store.quarantine_exact_text(destination_root, backup_root, text, *mode, *max_bytes),
    }
}

pub(crate) fn restore_quarantined(
    store: &ObjectStore,
    backup_root: &PortablePath,
    destination_root: &PortablePath,
    identity: &ApplyTargetIdentity<'_>,
    limits: CaptureLimits,
) -> Result<(), ObjectMutationError> {
    match identity {
        ApplyTargetIdentity::Skill(rendered_hash) => store.restore_quarantined_rendered_directory(
            backup_root,
            destination_root,
            rendered_hash,
            limits,
        ),
        ApplyTargetIdentity::Extension(object) => store.restore_quarantined_extension_target(
            backup_root,
            destination_root,
            object,
            limits,
        ),
        ApplyTargetIdentity::ExactText {
            text,
            mode,
            max_bytes,
        } => store.restore_quarantined_exact_text(
            backup_root,
            destination_root,
            text,
            *mode,
            *max_bytes,
        ),
    }
}

pub(crate) fn remove_exact(
    store: &ObjectStore,
    root: &PortablePath,
    identity: &ApplyTargetIdentity<'_>,
    limits: CaptureLimits,
) -> Result<(), ObjectMutationError> {
    match identity {
        ApplyTargetIdentity::Skill(rendered_hash) => {
            store.remove_exact_rendered_directory(root, rendered_hash, limits)
        }
        ApplyTargetIdentity::Extension(object) => {
            store.remove_exact_extension_target(root, object, limits)
        }
        ApplyTargetIdentity::ExactText {
            text,
            mode,
            max_bytes,
        } => store.remove_regular_file_if_matches_with_mode(root, *max_bytes, *mode, |bytes| {
            bytes == text.as_bytes()
        }),
    }
}

pub(crate) fn clear_staging(
    store: &ObjectStore,
    staging_root: &PortablePath,
    identity: &ApplyTargetIdentity<'_>,
    limits: CaptureLimits,
) -> Result<(), ObjectMutationError> {
    match identity {
        ApplyTargetIdentity::Skill(rendered_hash) => {
            store.clear_rendered_staging(staging_root, rendered_hash, limits)
        }
        ApplyTargetIdentity::Extension(object) => {
            store.clear_extension_target_staging(staging_root, object, limits)
        }
        ApplyTargetIdentity::ExactText {
            text,
            mode,
            max_bytes,
        } => store.remove_regular_file_if_matches_with_mode(
            staging_root,
            *max_bytes,
            *mode,
            |bytes| bytes == text.as_bytes(),
        ),
    }
}
