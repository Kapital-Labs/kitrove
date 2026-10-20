use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    AtomicApplyBatchJournalStatus, commit_atomic_apply_batch, inspect_atomic_apply_batch_journal,
};
use kitrove_model::ContentHash;

use super::{build_atomic_batch, build_plans, render_batch_result, render_plans};
use crate::args::{CliError, MaterializeArgs};
use crate::batch_recovery::recover_pending_batch;
use crate::portable::CompletedCommand;
use crate::scan::resolve_required_state_root;

pub(crate) fn run_apply(
    arguments: MaterializeArgs,
    confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    run_apply_with_approval(arguments, None, confirm)
}

pub(crate) fn run_confirmed_apply(
    arguments: MaterializeArgs,
    expected: &ContentHash,
) -> Result<CompletedCommand, CliError> {
    run_apply_with_approval(arguments, Some(expected), |_| false)
}

fn require_no_pending_batch() -> Result<(), CliError> {
    let state_root = resolve_required_state_root()?;
    match inspect_atomic_apply_batch_journal(&state_root)
        .map_err(|error| CliError::new(error.code(), error.message()))?
    {
        AtomicApplyBatchJournalStatus::NoJournal => Ok(()),
        AtomicApplyBatchJournalStatus::Pending { .. } => Err(CliError::new(
            "apply.recovery_required",
            "pending batch recovery requires explicit handling before a new confirmed apply",
        )),
    }
}

fn run_apply_with_approval(
    arguments: MaterializeArgs,
    expected: Option<&ContentHash>,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let json = arguments.json;
    if expected.is_some() {
        require_no_pending_batch()?;
    } else {
        recover_pending_batch(arguments.environment.as_deref())?;
    }
    let first = build_plans(&arguments)?;
    let first_batch = build_atomic_batch(&first)?;
    let plan_output = render_plans(&first, &first_batch, json)?;
    if let Some(expected) = expected {
        if first_batch.digest() != expected {
            return Err(CliError::new(
                "apply.plan_stale",
                "the current atomic batch does not match --confirm; generate and approve a fresh plan",
            ));
        }
    } else if !confirm(&plan_output) {
        return Err(CliError::new(
            "apply.confirmation_required",
            "the apply plan was not confirmed; no changes were made",
        ));
    }
    if expected.is_some() {
        require_no_pending_batch()?;
    } else {
        recover_pending_batch(arguments.environment.as_deref())?;
    }
    let refreshed = build_plans(&arguments)?;
    let refreshed_batch = build_atomic_batch(&refreshed)?;
    if refreshed_batch.digest() != first_batch.digest()
        || refreshed.pack_selections != first.pack_selections
    {
        return Err(CliError::new(
            "apply.plan_stale",
            "materialization authority changed after confirmation",
        ));
    }
    let outcome = commit_atomic_apply_batch(
        &refreshed_batch,
        &refreshed.environment_root,
        &refreshed.state_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_batch_result(&refreshed_batch, outcome, json)?,
        status: 0,
    })
}
