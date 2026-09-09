use kitrove_model::MAX_SUPPORTED_SYNC_COMPONENTS;

/// One outer and one nested staging tombstone can exist for every synchronized object.
pub(crate) const SYNC_TOMBSTONES_PER_OBJECT: usize = 2;
/// Outer recovery contributes eighteen controls and nested portable recovery contributes fifteen.
pub(crate) const SYNC_RECOVERY_CONTROL_TOMBSTONES: usize = 33;
/// Both outer and nested object staging can retain the same tree object.
pub(crate) const SYNC_TREE_TOMBSTONES_PER_OBJECT: usize = 2;

pub(crate) const MAX_SYNC_RECOVERY_TOMBSTONES: usize =
    MAX_SUPPORTED_SYNC_COMPONENTS * SYNC_TOMBSTONES_PER_OBJECT + SYNC_RECOVERY_CONTROL_TOMBSTONES;
pub(crate) const MAX_SYNC_TREE_TOMBSTONES: usize =
    MAX_SUPPORTED_SYNC_COMPONENTS * SYNC_TREE_TOMBSTONES_PER_OBJECT;
