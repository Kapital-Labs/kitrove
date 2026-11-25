//! Explicit preservation of a whole retained quarantine.

use crate::args::{CliError, RecoverArgs};
use crate::portable::CompletedCommand;

pub(crate) const HELP: &str = "Preserve retained files on macOS

  kitrove recover plan --root collection|private-state [--environment PATH] [--json]
  kitrove recover preserve --root collection|private-state --confirm DIGEST [--environment PATH] [--json]

Plan checks the selected storage without changing files.
Preserve moves the entire retained directory into a private holding location.
Use separate plans for the collection and private state. Start with kitrove doctor.
";

#[cfg(target_os = "macos")]
pub(crate) fn run(args: RecoverArgs) -> Result<CompletedCommand, CliError> {
    use crate::args::RecoverRoot;
    use kitrove_core::{
        PreservationRoot, RETAINED_HOLD_PATH, plan_quarantine_preservation, preserve_quarantine,
    };

    let (collection, private_state) =
        crate::doctor::recovery_locations(args.environment.as_deref())?;
    let role = match args.root {
        RecoverRoot::Collection => PreservationRoot::Collection,
        RecoverRoot::PrivateState => PreservationRoot::PrivateState,
    };
    let plan = match &args.confirm {
        Some(digest) => preserve_quarantine(&collection, &private_state, role, digest),
        None => plan_quarantine_preservation(&collection, &private_state, role),
    }
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let completed = args.confirm.is_some();
    let output = if args.json {
        format!(
            "{}\n",
            serde_json::json!({
                "schema_version": 1,
                "root": role.as_str(),
                "entries": plan.entries,
                "device_mismatches": plan.device_mismatches,
                "plan_digest": plan.digest.as_str(),
                "hold_relative_path": RETAINED_HOLD_PATH,
                "outcome": if completed { "preserved" } else { "preview" },
            })
        )
    } else if completed {
        format!(
            "Preserved {} retained entries in the {}.\nHolding directory: {RETAINED_HOLD_PATH}\nRun kitrove doctor before resuming writes.\n",
            plan.entries,
            role.as_str()
        )
    } else {
        format!(
            "Recovery preview for {}\nRetained entries: {} ({} with a different device ID)\nPreserve moves the entire directory to {RETAINED_HOLD_PATH}.\nPlan digest: {}\nRun recover preserve with the same root and environment and pass this digest to --confirm.\n",
            role.as_str(),
            plan.entries,
            plan.device_mismatches,
            plan.digest.as_str()
        )
    };
    Ok(CompletedCommand { output, status: 0 })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn run(args: RecoverArgs) -> Result<CompletedCommand, CliError> {
    let RecoverArgs {
        root,
        environment,
        json,
        confirm,
    } = args;
    drop((root, environment, json, confirm));
    Err(CliError::new(
        "recover.platform_unsupported",
        "retained-file preservation is available on macOS",
    ))
}
