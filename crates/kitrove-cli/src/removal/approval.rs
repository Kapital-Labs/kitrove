use super::{
    build_pack_removal, build_removal, render_pack_removal_plan, render_pack_removal_result,
    render_plan, render_result,
};
use crate::args::{ApprovalMode, CliError, PackRemoveArgs, RemoveArgs};
use crate::batch_recovery::{recover_pending_batch, require_no_pending_batch};
use crate::portable::CompletedCommand;
use kitrove_agent_skills::CaptureLimits;
use kitrove_core::commit_atomic_apply_batch;
use kitrove_model::ContentHash;
use std::path::Path;

pub(crate) fn run_remove(
    arguments: RemoveArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    prepare(&arguments.approval, arguments.environment.as_deref())?;
    let first = build_removal(&arguments)?;
    let output = render_plan(&first.batch, arguments.json)?;
    if matches!(arguments.approval, ApprovalMode::Preview) {
        return Ok(CompletedCommand { output, status: 0 });
    }
    approve(
        &arguments.approval,
        first.batch.digest(),
        &output,
        &mut confirm,
        "remove.confirmation_required",
    )?;
    prepare(&arguments.approval, arguments.environment.as_deref())?;
    let refreshed = build_removal(&arguments)?;
    if refreshed.batch.digest() != first.batch.digest() {
        return Err(CliError::new(
            "remove.plan_stale",
            "removal authority changed after confirmation",
        ));
    }
    let outcome = commit_atomic_apply_batch(
        &refreshed.batch,
        &refreshed.environment_root,
        &refreshed.state_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_result(&refreshed.batch, outcome, arguments.json)?,
        status: 0,
    })
}

pub(crate) fn run_pack_remove(
    arguments: PackRemoveArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    prepare(&arguments.approval, arguments.environment.as_deref())?;
    let first = build_pack_removal(&arguments)?;
    let output = render_pack_removal_plan(&arguments, &first.batch)?;
    if matches!(arguments.approval, ApprovalMode::Preview) {
        return Ok(CompletedCommand { output, status: 0 });
    }
    approve(
        &arguments.approval,
        first.batch.digest(),
        &output,
        &mut confirm,
        "pack_remove.confirmation_required",
    )?;
    prepare(&arguments.approval, arguments.environment.as_deref())?;
    let refreshed = build_pack_removal(&arguments)?;
    if refreshed.batch.digest() != first.batch.digest() {
        return Err(CliError::new(
            "pack_remove.plan_stale",
            "pack removal authority changed after confirmation",
        ));
    }
    let outcome = commit_atomic_apply_batch(
        &refreshed.batch,
        &refreshed.environment_root,
        &refreshed.state_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_pack_removal_result(&arguments, &refreshed.batch, outcome)?,
        status: 0,
    })
}

fn prepare(mode: &ApprovalMode, environment: Option<&Path>) -> Result<(), CliError> {
    match mode {
        ApprovalMode::Interactive => recover_pending_batch(environment),
        ApprovalMode::Preview | ApprovalMode::Confirm(_) => {
            require_no_pending_batch("remove.recovery_required")
        }
    }
}

fn approve(
    mode: &ApprovalMode,
    digest: &ContentHash,
    output: &str,
    confirm: &mut impl FnMut(&str) -> bool,
    confirmation_code: &'static str,
) -> Result<(), CliError> {
    match mode {
        ApprovalMode::Confirm(expected) if digest == expected => Ok(()),
        ApprovalMode::Confirm(_) => Err(CliError::new(
            "remove.plan_stale",
            "the removal batch differs from --confirm; obtain fresh approval",
        )),
        ApprovalMode::Interactive if confirm(output) => Ok(()),
        ApprovalMode::Interactive => Err(CliError::new(
            confirmation_code,
            "the removal plan was not confirmed; no changes were made",
        )),
        ApprovalMode::Preview => unreachable!("preview returns before confirmation"),
    }
}
