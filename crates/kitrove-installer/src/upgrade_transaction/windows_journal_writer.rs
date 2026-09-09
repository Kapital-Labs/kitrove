//! Owned placement journal coordinator for Windows replacement and recovery.

use std::ffi::OsStr;

use super::super::windows_pair::{Layout, WindowsPair};
use super::super::windows_recovery_plan::JournalStage;
use super::{Marker, RetainedJournal, policy};
use crate::InstallerStageError;
use crate::staging_policy::{create_private_data_leaf, read_private_data_leaf};

#[path = "windows_placement_recovery.rs"]
pub(in crate::upgrade_transaction) mod recovery;

#[path = "windows_verification.rs"]
pub(in crate::upgrade_transaction) mod verification;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::upgrade_transaction) enum WriteBoundary {
    Created,
    Completed,
    BeforePublish,
    Published,
    Synced,
}

/// Drop journal leases before pair/preparation releases the lifecycle locks. Every
/// mutation consumes self: a failed write/move cannot reuse incomplete capabilities.
pub(in crate::upgrade_transaction) struct JournaledPair<'a> {
    journal: RetainedJournal,
    pair: WindowsPair<'a>,
}

impl<'a> JournaledPair<'a> {
    /// Reopens journal evidence around a still-owned pair, not fresh-process recovery.
    pub(in crate::upgrade_transaction) fn from_pair(
        pair: WindowsPair<'a>,
    ) -> Result<Self, InstallerStageError> {
        let journal = RetainedJournal::open(pair.operation(), pair.journal_binding()?)?;
        let mut retained = Self { journal, pair };
        retained.revalidate()?;
        Ok(retained)
    }

    fn revalidate(&mut self) -> Result<(), InstallerStageError> {
        self.journal.revalidate(self.pair.operation())?;
        policy::require_layout(
            self.pair.layout(),
            &self.journal.phases(false),
            &self.journal.phases(true),
        )?;
        self.pair.revalidate(&self.journal.names())?;
        self.journal.revalidate(self.pair.operation())
    }

    pub(in crate::upgrade_transaction) fn move_to(
        mut self,
        next: Layout,
    ) -> Result<Self, InstallerStageError> {
        self.revalidate()?;
        policy::require_move(
            self.pair.layout(),
            next,
            &self.journal.phases(false),
            &self.journal.phases(true),
        )?;
        // Reopened completed markers must be durable before authorizing a move.
        self.sync_markers()?;
        self.pair.sync_pair(&self.journal.names())?;
        self.revalidate()?;
        self.pair.move_to(next, &self.journal.names())?;
        self.revalidate()?;
        Ok(self)
    }

    pub(in crate::upgrade_transaction) fn record(
        self,
        phase: JournalStage,
    ) -> Result<Self, InstallerStageError> {
        self.record_with_hook(phase, |_| Ok(()))
    }

    pub(in crate::upgrade_transaction) fn record_with_hook(
        self,
        phase: JournalStage,
        boundary: impl FnMut(WriteBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<Self, InstallerStageError> {
        self.record_impl(phase, boundary, None)
            .map_err(|_| InstallerStageError::RecoveryRequired)
    }

    fn record_impl(
        mut self,
        phase: JournalStage,
        mut boundary: impl FnMut(WriteBoundary) -> Result<(), InstallerStageError>,
        probe: Option<&verification::FreshProbe>,
    ) -> Result<Self, InstallerStageError> {
        self.revalidate()?;
        if let Some(probe) = probe {
            probe.require_binding(self.journal.binding)?;
            policy::require_probe_write(
                self.pair.layout(),
                &self.journal.phases(false),
                &self.journal.phases(true),
                phase,
            )?;
        } else {
            policy::require_write(
                self.pair.layout(),
                &self.journal.phases(false),
                &self.journal.phases(true),
                phase,
            )?;
        }
        self.sync_markers()?;
        self.pair.sync_pair(&self.journal.names())?;
        self.revalidate()?;
        let index = if let Some(index) = self
            .journal
            .markers
            .iter()
            .position(|marker| marker.phase == phase && marker.pending)
        {
            index
        } else {
            let name = policy::name(phase, true)?;
            let leaf = create_private_data_leaf(self.pair.operation(), &name, Vec::new())?;
            self.journal.markers.push(Marker {
                phase,
                pending: true,
                name,
                leaf,
            });
            boundary(WriteBoundary::Created)?;
            self.journal.markers.len() - 1
        };
        self.revalidate()?;
        let mut marker = self.journal.markers.remove(index);
        let canonical = self.journal.binding.bytes(phase)?;
        marker.leaf =
            marker
                .leaf
                .complete_prefix_owned(self.pair.operation(), &marker.name, &canonical)?;
        self.journal.markers.insert(index, marker);
        boundary(WriteBoundary::Completed)?;
        self.revalidate()?;
        boundary(WriteBoundary::BeforePublish)?;
        self.publish(index)?;
        boundary(WriteBoundary::Published)?;
        self.revalidate()?;
        self.pair.sync_operation()?;
        boundary(WriteBoundary::Synced)?;
        self.revalidate()?;
        Ok(self)
    }

    fn publish(&mut self, index: usize) -> Result<(), InstallerStageError> {
        let marker = self.journal.markers.remove(index);
        let identity = kitrove_windows_security::file_identity(&marker.leaf.file)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let expected = marker.leaf.identity;
        drop(marker.leaf.file);
        let name = policy::name(marker.phase, false)?;
        kitrove_windows_security::promote_owned_file(
            self.pair.operation(),
            OsStr::new(&marker.name),
            OsStr::new(&name),
            OsStr::new("windows-upgrade-phase-record.uncertain"),
            identity,
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let leaf = read_private_data_leaf(self.pair.operation(), &name, policy::MAX_RECORD_BYTES)?;
        if leaf.identity != expected {
            return Err(InstallerStageError::RecoveryRequired);
        }
        leaf.require_contents(self.pair.operation(), &name, &marker.leaf.bytes)?;
        let leaf = leaf.sync_owned(self.pair.operation(), &name)?;
        self.journal.markers.insert(
            index,
            Marker {
                phase: marker.phase,
                pending: false,
                name,
                leaf,
            },
        );
        Ok(())
    }

    fn sync_markers(&mut self) -> Result<(), InstallerStageError> {
        self.journal.synchronize_leaves(self.pair.operation())?;
        self.revalidate()
    }
}
