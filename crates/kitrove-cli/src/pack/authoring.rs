use super::{
    CaptureLimits, CliError, CompletedCommand, PackCreateArgs, PackMutationPlan, PackUpdateArgs,
    commit_pack_creation, commit_pack_update, load_manifest, plan_pack_creation, plan_pack_update,
    render_pack_mutation_plan, render_pack_mutation_result, resolve_required_environment_root,
};
use crate::args::PackApproval;
use kitrove_core::commit_approved_pack_mutation;
use std::path::Path;

pub(crate) fn run_pack_create(
    arguments: PackCreateArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let manifest = load_manifest(&root)?;
    let plan = plan_pack_creation(&manifest, arguments.pack_id, arguments.members)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    finish(
        plan,
        &root,
        arguments.approval,
        arguments.json,
        &mut confirm,
        true,
    )
}

pub(crate) fn run_pack_update(
    arguments: PackUpdateArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let manifest = load_manifest(&root)?;
    let plan = plan_pack_update(
        &manifest,
        arguments.pack_id,
        arguments.expected_prior,
        arguments.members,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    finish(
        plan,
        &root,
        arguments.approval,
        arguments.json,
        &mut confirm,
        false,
    )
}

fn finish(
    plan: PackMutationPlan,
    root: &Path,
    approval: PackApproval,
    json: bool,
    confirm: &mut impl FnMut(&str) -> bool,
    create: bool,
) -> Result<CompletedCommand, CliError> {
    let rendered = render_pack_mutation_plan(&plan, json)?;
    let unattended = match approval {
        PackApproval::Preview => {
            return Ok(CompletedCommand {
                output: rendered,
                status: 0,
            });
        }
        PackApproval::Confirm(expected) => {
            if plan.digest() != &expected {
                return Err(CliError::new(
                    "pack.plan_stale",
                    "the current pack plan does not match --confirm; obtain fresh approval",
                ));
            }
            true
        }
        PackApproval::Interactive => {
            if !confirm(&rendered) {
                return Err(CliError::new(
                    if create {
                        "pack_create.confirmation_required"
                    } else {
                        "pack_update.confirmation_required"
                    },
                    "the pack plan was not confirmed; no changes were made",
                ));
            }
            false
        }
    };
    let outcome = if unattended {
        commit_approved_pack_mutation(&plan, root, CaptureLimits::default())
    } else if create {
        commit_pack_creation(&plan, root, CaptureLimits::default())
    } else {
        commit_pack_update(&plan, root, CaptureLimits::default())
    }
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_pack_mutation_result(&plan, outcome, json)?,
        status: 0,
    })
}
