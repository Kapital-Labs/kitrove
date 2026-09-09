use std::path::Path;

use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    AtomicApplyBatchJournalStatus, inspect_atomic_apply_batch_journal, recover_atomic_apply_batch,
};

use crate::args::CliError;
use crate::scan::{resolve_required_environment_root, resolve_required_state_root};

pub(crate) fn recover_pending_batch(environment: Option<&Path>) -> Result<(), CliError> {
    let state_root = resolve_required_state_root()?;
    match inspect_atomic_apply_batch_journal(&state_root) {
        Ok(AtomicApplyBatchJournalStatus::NoJournal) => Ok(()),
        Ok(AtomicApplyBatchJournalStatus::Pending { .. }) => {
            let environment_root = resolve_required_environment_root(environment)?;
            recover_atomic_apply_batch(&environment_root, &state_root, CaptureLimits::default())
                .map(|_| ())
                .map_err(|error| CliError::new(error.code(), error.message()))
        }
        Err(error) if error.code() == "apply.batch_journal_inspection_failed" => Ok(()),
        Err(error) => Err(CliError::new(error.code(), error.message())),
    }
}
