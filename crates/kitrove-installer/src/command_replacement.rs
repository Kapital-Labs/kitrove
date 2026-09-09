//! Directional CLI routing; filesystem and release authority stay in existing owners.

use super::Action;
use super::release::{ReleaseInput, ReleasePin};
use crate::installation_history::replacement::{ArchivedReplacement, synchronization};
use crate::replacement_direction::ReplacementDirection;
use crate::upgrade_precondition::ReplacementPrecondition;
use crate::upgrade_transaction::PreparedReplacement;
use kitrove_release_provenance::{
    AuthenticatedApplicationExecutable, AuthenticatedRecoveryMaterial,
};
use std::collections::BTreeMap;
use std::ffi::OsString;

#[cfg(debug_assertions)]
#[cfg(test)]
#[path = "command_replacement_tests.rs"]
mod tests;

#[cfg(all(test, debug_assertions, windows))]
pub(super) fn exercise_windows_for_tests() {
    tests::exercise_windows();
}

pub(super) fn command(command: &str) -> Option<(Action, ReplacementDirection)> {
    for (name, direction) in [
        ("upgrade", ReplacementDirection::Upgrade),
        ("rollback", ReplacementDirection::Rollback),
    ] {
        let action = if command == name {
            Action::Install
        } else if command.strip_prefix("preflight-") == Some(name) {
            Action::Preflight
        } else if command.strip_prefix("recover-") == Some(name) {
            Action::Recover
        } else if command.strip_prefix("retire-") == Some(name) {
            Action::Retire
        } else if command.strip_suffix("-history-status") == Some(name) {
            Action::Status
        } else if command.strip_suffix("-history-sync") == Some(name) {
            Action::Sync
        } else {
            continue;
        };
        return Some((action, direction));
    }
    None
}

enum Prior {
    Fresh(ReleaseInput),
    Retained(ReleasePin),
}

pub(super) struct Request {
    direction: ReplacementDirection,
    prior: Prior,
}

impl Request {
    pub(super) fn parse(
        values: &mut BTreeMap<String, OsString>,
        action: Action,
        direction: ReplacementDirection,
    ) -> Result<Self, String> {
        let prior = if matches!(action, Action::Preflight | Action::Install) {
            Prior::Fresh(ReleaseInput::parse(values, "prior-")?)
        } else {
            Prior::Retained(ReleasePin::parse(values, "prior-")?)
        };
        Ok(Self { direction, prior })
    }

    pub(super) fn execute(
        &self,
        request: &super::Request,
        candidate: &AuthenticatedApplicationExecutable,
    ) -> Result<String, String> {
        let result = match &self.prior {
            Prior::Fresh(input) => {
                let prior = input.authenticate()?;
                self.execute_fresh(request, candidate, &prior)
            }
            Prior::Retained(pin) => self.execute_retained(request, candidate, pin),
        };
        result.map_err(super::recovery_error)
    }

    fn execute_fresh(
        &self,
        request: &super::Request,
        candidate: &AuthenticatedApplicationExecutable,
        prior: &AuthenticatedRecoveryMaterial,
    ) -> Result<String, crate::InstallerStageError> {
        match request.action {
            Action::Preflight => ReplacementPrecondition::preflight(
                &request.destination, candidate, prior, &request.roots, self.direction,
            ).map(|()| "Replacement preflight passed without mutation. Replacement will recheck all authority.".into()),
            Action::Install => {
                let prepared = match self.direction {
                    ReplacementDirection::Upgrade => PreparedReplacement::prepare(
                        &request.destination, candidate, prior, &request.roots,
                    ),
                    ReplacementDirection::Rollback => PreparedReplacement::prepare_rollback(
                        &request.destination, candidate, prior, &request.roots,
                    ),
                }?;
                prepared.install().map(|installed| format!(
                    "Replacement committed. Operation: {}", installed.record.operation_id(),
                ))
            }
            _ => Err(crate::InstallerStageError::UnsafeState),
        }
    }

    fn execute_retained(
        &self,
        request: &super::Request,
        candidate: &AuthenticatedApplicationExecutable,
        pin: &ReleasePin,
    ) -> Result<String, crate::InstallerStageError> {
        let destination = &request.destination;
        let roots = &request.roots;
        match request.action {
            Action::Recover => {
                let recovered = match self.direction {
                    ReplacementDirection::Upgrade => PreparedReplacement::recover_upgrade(
                        destination,
                        candidate,
                        &pin.expected,
                        pin.digest,
                        roots,
                    ),
                    ReplacementDirection::Rollback => PreparedReplacement::recover_rollback(
                        destination,
                        candidate,
                        &pin.expected,
                        pin.digest,
                        roots,
                    ),
                }?;
                Ok(format!(
                    "Replacement recovery committed. Operation: {}",
                    recovered.record.operation_id()
                ))
            }
            Action::Retire => PreparedReplacement::retire_completed(
                destination,
                candidate,
                &pin.expected,
                pin.digest,
                roots,
                self.direction,
            )
            .map(|()| "Completed replacement retained in history.".into()),
            Action::Status | Action::Sync => {
                let selected = request
                    .operation
                    .as_deref()
                    .ok_or(crate::InstallerStageError::UnsafeState)?;
                let outcome = if request.action == Action::Status {
                    ArchivedReplacement::open(
                        destination,
                        selected,
                        candidate,
                        &pin.expected,
                        pin.digest,
                        self.direction,
                    )
                    .and_then(|history| history.outcome())
                } else {
                    synchronization::synchronize(
                        destination,
                        selected,
                        candidate,
                        &pin.expected,
                        pin.digest,
                        roots,
                        self.direction,
                    )
                }?;
                Ok(format!("Historical replacement: {outcome:?}."))
            }
            _ => Err(crate::InstallerStageError::UnsafeState),
        }
    }
}
