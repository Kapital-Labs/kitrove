//! Read-only retained journal evidence, not permission to move either executable.
//!
//! The coordinator must authenticate the binding, validate the complete operation
//! inventory and physical pair, and retain lifecycle locks. Opening or rejecting a
//! journal never repairs permissions, truncates pending bytes, or removes evidence.

use super::windows_journal_policy::{self as policy, Binding, MAX_RECORD_BYTES, PHASES};
use super::windows_recovery_plan::JournalStage;
use crate::InstallerStageError;
use crate::staging_policy::{
    InstallerDirectory, PrivateDataLeaf, entry_exists, read_pending_data_leaf,
    read_private_data_leaf,
};

#[cfg(windows)]
#[path = "windows_journal_writer.rs"]
pub(super) mod writer;

struct Marker {
    phase: JournalStage,
    pending: bool,
    name: String,
    leaf: PrivateDataLeaf,
}

pub(crate) struct RetainedJournal {
    markers: Vec<Marker>,
    binding: Binding,
}

#[cfg(windows)]
pub(crate) struct ReleasedJournal {
    leaves: Vec<(String, crate::NativeFileIdentity, Vec<u8>)>,
}

#[cfg(windows)]
impl ReleasedJournal {
    pub(crate) fn require_same(
        &self,
        journal: &RetainedJournal,
    ) -> Result<(), InstallerStageError> {
        if self.leaves.len() != journal.markers.len()
            || self.leaves.iter().any(|(name, identity, bytes)| {
                !journal.markers.iter().any(|marker| {
                    marker.name == *name
                        && marker.leaf.identity == *identity
                        && marker.leaf.bytes == *bytes
                })
            })
        {
            return Err(InstallerStageError::RecoveryRequired);
        }
        Ok(())
    }
}

impl RetainedJournal {
    #[cfg(windows)]
    pub(crate) fn release(self) -> ReleasedJournal {
        ReleasedJournal {
            leaves: self
                .markers
                .into_iter()
                .map(|marker| (marker.name, marker.leaf.identity, marker.leaf.bytes))
                .collect(),
        }
    }

    pub(crate) fn open(
        parent: &InstallerDirectory,
        binding: Binding,
    ) -> Result<Self, InstallerStageError> {
        let mut markers = Vec::new();
        for phase in PHASES {
            for pending in [false, true] {
                let name = policy::name(phase, pending)?;
                if entry_exists(parent, &name)? {
                    let leaf = if pending {
                        read_pending_data_leaf(parent, &name, MAX_RECORD_BYTES)?
                    } else {
                        read_private_data_leaf(parent, &name, MAX_RECORD_BYTES)?
                    };
                    markers.push(Marker {
                        phase,
                        pending,
                        name,
                        leaf,
                    });
                }
            }
        }
        let journal = Self { markers, binding };
        journal.revalidate(parent)?;
        Ok(journal)
    }

    pub(crate) fn names(&self) -> Vec<&std::ffi::OsStr> {
        self.markers
            .iter()
            .map(|marker| std::ffi::OsStr::new(&marker.name))
            .collect()
    }

    pub(crate) fn phases(&self, pending: bool) -> Vec<JournalStage> {
        self.markers
            .iter()
            .filter(|marker| marker.pending == pending)
            .map(|marker| marker.phase)
            .collect()
    }

    pub(super) fn stage(
        &self,
        parent: &InstallerDirectory,
    ) -> Result<JournalStage, InstallerStageError> {
        self.revalidate(parent)?;
        policy::stage(&self.phases(false), &self.phases(true))
    }

    pub(crate) fn revalidate(
        &self,
        parent: &InstallerDirectory,
    ) -> Result<(), InstallerStageError> {
        policy::validate_history(&self.phases(false), &self.phases(true))?;
        for phase in PHASES {
            for pending in [false, true] {
                let name = policy::name(phase, pending)?;
                let retained = self.markers.iter().find(|marker| marker.name == name);
                if entry_exists(parent, &name)? != retained.is_some() {
                    return Err(InstallerStageError::RecoveryRequired);
                }
                if let Some(marker) = retained {
                    let canonical = self.binding.bytes(phase)?;
                    if pending {
                        marker.leaf.require_prefix(parent, &name, &canonical)?;
                    } else {
                        marker.leaf.require_contents(parent, &name, &canonical)?;
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn synchronize(
        mut self,
        parent: &InstallerDirectory,
    ) -> Result<Self, InstallerStageError> {
        self.synchronize_leaves(parent)?;
        Ok(self)
    }

    #[cfg(windows)]
    fn synchronize_leaves(
        &mut self,
        parent: &InstallerDirectory,
    ) -> Result<(), InstallerStageError> {
        self.revalidate(parent)?;
        for index in 0..self.markers.len() {
            let mut marker = self.markers.remove(index);
            marker.leaf = marker.leaf.sync_owned(parent, &marker.name)?;
            self.markers.insert(index, marker);
        }
        self.revalidate(parent)
    }
}

#[cfg(test)]
#[path = "windows_journal_tests.rs"]
mod tests;
