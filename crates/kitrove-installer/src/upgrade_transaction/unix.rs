use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};

use super::PreparedReplacement;
use crate::install_phase::InstallPhase;
use crate::replacement_phase::{
    MAX_UPGRADE_PHASE_BYTES, ReplacementLayout as Layout, encode_phase_evidence, marker_name,
    pending_name,
};
use crate::staging_policy::{OPERATION_RECORD, STAGED_EXECUTABLE};
use crate::unix_staging::{
    require_exact_inventory, require_named_file_identity, verify_sha256_contents,
};
use crate::{InstalledApplication, InstallerStageError, NativeFileIdentity};

#[path = "recovery.rs"]
mod recovery;

#[path = "retirement.rs"]
mod retirement;

#[path = "pending.rs"]
mod pending;
use pending::PendingMarker;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UpgradeBoundary {
    BeforeExchange,
    Exchanged,
    ReplacedRecorded,
    VerifiedRecorded,
    CommittedRecorded,
    BeforeRestore,
    Restored,
    RolledBackRecorded,
    PhaseCreated(InstallPhase),
    PhaseWritten(InstallPhase),
    PhasePublished(InstallPhase),
}

pub(super) use crate::unix_history::RetirementBoundary;

struct Marker {
    phase: InstallPhase,
    file: cap_std::fs::File,
    identity: NativeFileIdentity,
}

struct Exchange<'a> {
    // Close phase capabilities before preparation releases lifecycle guards.
    markers: Vec<Marker>,
    pending: Vec<PendingMarker>,
    prepared: PreparedReplacement<'a>,
    layout: Layout,
}

impl PreparedReplacement<'_> {
    pub(crate) fn install(self) -> Result<InstalledApplication, InstallerStageError> {
        self.install_with_hooks(crate::verify_installed_application, |_| Ok(()))
    }

    pub(super) fn install_with_hooks(
        mut self,
        verify: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
        mut boundary: impl FnMut(UpgradeBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<InstalledApplication, InstallerStageError> {
        self.revalidate()?;
        boundary(UpgradeBoundary::BeforeExchange)?;
        exchange(&self)?;
        let mut transaction = Exchange {
            prepared: self,
            markers: Vec::new(),
            pending: Vec::new(),
            layout: Layout::Exchanged,
        };
        (|| {
            boundary(UpgradeBoundary::Exchanged)?;
            transaction.revalidate()?;
            transaction.sync_pair()?;
            transaction.write_marker_with_hook(InstallPhase::Replaced, &mut boundary)?;
            boundary(UpgradeBoundary::ReplacedRecorded)?;
            transaction.revalidate()?;
            Ok::<(), InstallerStageError>(())
        })()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;

        transaction.finish(verify, &mut boundary)
    }
}

impl Exchange<'_> {
    fn finish(
        mut self,
        verify: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
        boundary: &mut impl FnMut(UpgradeBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<InstalledApplication, InstallerStageError> {
        let transaction = &mut self;
        if transaction.layout != Layout::Exchanged
            || transaction.has_marker(InstallPhase::RolledBack)
        {
            return Err(InstallerStageError::RecoveryRequired);
        }
        transaction
            .revalidate()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let path = transaction.installed_path();
        let observed = verify(
            &path,
            transaction.prepared.staged.manifest.release_version(),
        );
        if observed.as_ref() != Ok(&transaction.prepared.staged.executable_content_hash) {
            transaction
                .restore(boundary)
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
            return Err(InstallerStageError::VerificationFailed);
        }
        (|| -> Result<InstalledApplication, InstallerStageError> {
            transaction.revalidate()?;
            if !transaction.has_marker(InstallPhase::Verified) {
                transaction.write_marker_with_hook(InstallPhase::Verified, boundary)?;
            }
            boundary(UpgradeBoundary::VerifiedRecorded)?;
            transaction.revalidate()?;
            if !transaction.has_marker(InstallPhase::Committed) {
                transaction.write_marker_with_hook(InstallPhase::Committed, boundary)?;
            }
            boundary(UpgradeBoundary::CommittedRecorded)?;
            transaction.revalidate()?;
            Ok(InstalledApplication {
                record: transaction.prepared.staged.record.clone(),
                manifest: transaction.prepared.staged.manifest.clone(),
                path,
            })
        })()
        .map_err(|_| InstallerStageError::RecoveryRequired)
    }
}

impl Exchange<'_> {
    fn has_marker(&self, phase: InstallPhase) -> bool {
        self.markers.iter().any(|marker| marker.phase == phase)
    }
    fn installed_path(&self) -> PathBuf {
        PathBuf::from(OsString::from_vec(
            self.prepared
                .staged
                ._retained
                .destination
                .path_bytes()
                .to_vec(),
        ))
        .join(self.prepared.staged.record.executable_name())
    }

    fn inventory(&self) -> Vec<&'static OsStr> {
        let mut names = phase_inventory(self.markers.iter().map(|marker| marker.phase));
        names.extend(
            self.pending
                .iter()
                .map(|marker| OsStr::new(pending_name(marker.phase))),
        );
        names
    }

    fn require_pair(&self) -> Result<(), InstallerStageError> {
        require_pair(&self.prepared.staged, &self.prepared.prior, self.layout)
    }

    fn revalidate(&mut self) -> Result<(), InstallerStageError> {
        pending::require_phase_order(
            &self
                .markers
                .iter()
                .map(|marker| marker.phase)
                .collect::<Vec<_>>(),
            &self
                .pending
                .iter()
                .map(|marker| marker.phase)
                .collect::<Vec<_>>(),
            self.layout,
        )?;
        self.prepared
            .prior
            .bind_stage_identity(&self.prepared.staged)?;
        crate::unix_install::revalidate_common(&self.prepared.staged)?;
        require_exact_inventory(&self.prepared.staged._retained.operation, &self.inventory())?;
        self.require_pair()?;
        self.prepared
            .kit
            .revalidate_material(&self.prepared.staged, self.prepared.prior.rollback())?;
        self.prepared.record.revalidate_evidence(
            &self.prepared.staged,
            &self.prepared.prior,
            &self.prepared.kit,
            &mut self.prepared.states,
        )?;
        for marker in &self.markers {
            marker.revalidate(
                &self.prepared.staged._retained.operation,
                &self.phase_bytes(marker.phase)?,
            )?;
        }
        for pending in &self.pending {
            pending.revalidate(
                &self.prepared.staged._retained.operation,
                &self.phase_bytes(pending.phase)?,
            )?;
        }
        self.require_pair()?;
        crate::unix_install::revalidate_common(&self.prepared.staged)?;
        require_exact_inventory(&self.prepared.staged._retained.operation, &self.inventory())?;
        self.prepared.states.revalidate()
    }

    fn phase_bytes(&self, phase: InstallPhase) -> Result<Vec<u8>, InstallerStageError> {
        encode_phase_evidence(
            phase,
            self.prepared.record.binding_digest()?,
            *self.prepared.staged.record.staged_identity(),
            self.prepared.prior.prior_identity(),
        )
    }

    fn sync_pair(&self) -> Result<(), InstallerStageError> {
        self.prepared
            .staged
            ._retained
            .executable
            .sync_all()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.prepared.prior.sync_prior()?;
        crate::unix_staging::sync_directory(&self.prepared.staged._retained.operation)?;
        crate::unix_staging::sync_directory(self.prepared.staged._retained.destination.directory())
    }

    fn restore(
        &mut self,
        boundary: &mut impl FnMut(UpgradeBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        if self.layout != Layout::Exchanged || self.has_marker(InstallPhase::RolledBack) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        self.revalidate()?;
        boundary(UpgradeBoundary::BeforeRestore)?;
        exchange(&self.prepared)?;
        self.layout = Layout::Restored;
        boundary(UpgradeBoundary::Restored)?;
        self.revalidate()?;
        self.sync_pair()?;
        self.write_marker_with_hook(InstallPhase::RolledBack, boundary)?;
        boundary(UpgradeBoundary::RolledBackRecorded)?;
        self.revalidate()
    }
}

fn phase_inventory(phases: impl Iterator<Item = InstallPhase>) -> Vec<&'static OsStr> {
    let mut names = vec![
        OsStr::new(STAGED_EXECUTABLE),
        OsStr::new(OPERATION_RECORD),
        OsStr::new(crate::rollback_kit::ROLLBACK_DIRECTORY),
        OsStr::new(crate::upgrade_record::UPGRADE_RECORD),
    ];
    names.extend(phases.map(|phase| OsStr::new(marker_name(phase))));
    names
}

fn exchange(prepared: &PreparedReplacement<'_>) -> Result<(), InstallerStageError> {
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    {
        rustix::fs::renameat_with(
            &prepared.staged._retained.operation,
            STAGED_EXECUTABLE,
            prepared.staged._retained.destination.directory(),
            prepared.staged.record.executable_name(),
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    {
        let _ = prepared;
        Err(InstallerStageError::UnsupportedPlatform)
    }
}

fn require_pair(
    staged: &crate::StagedApplication,
    prior: &crate::upgrade_precondition::ReplacementPrecondition<'_>,
    layout: Layout,
) -> Result<(), InstallerStageError> {
    let (candidate_parent, candidate_name, prior_parent, prior_name) = match layout {
        Layout::Exchanged => (
            staged._retained.destination.directory(),
            staged.record.executable_name(),
            &staged._retained.operation,
            STAGED_EXECUTABLE,
        ),
        Layout::Restored => (
            &staged._retained.operation,
            STAGED_EXECUTABLE,
            staged._retained.destination.directory(),
            staged.record.executable_name(),
        ),
    };
    require_named_file_identity(
        candidate_parent,
        candidate_name,
        &staged._retained.executable,
        *staged.record.staged_identity(),
        0o700,
        staged.record.executable_size(),
    )?;
    verify_sha256_contents(
        &staged._retained.executable,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )?;
    prior.revalidate_prior_at(prior_parent, prior_name)?;
    require_named_file_identity(
        candidate_parent,
        candidate_name,
        &staged._retained.executable,
        *staged.record.staged_identity(),
        0o700,
        staged.record.executable_size(),
    )
}

impl Marker {
    fn revalidate(
        &self,
        operation: &cap_std::fs::Dir,
        bytes: &[u8],
    ) -> Result<(), InstallerStageError> {
        let require_named = || {
            require_named_file_identity(
                operation,
                marker_name(self.phase),
                &self.file,
                self.identity,
                0o600,
                bytes.len() as u64,
            )
        };
        require_named()?;
        if crate::unix_staging::read_bounded_file(&self.file, MAX_UPGRADE_PHASE_BYTES)? != bytes {
            return Err(InstallerStageError::RecoveryRequired);
        }
        require_named()
    }
}
