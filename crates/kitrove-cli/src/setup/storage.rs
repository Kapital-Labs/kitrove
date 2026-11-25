//! Guided storage checks and explicit, digest-bound retained-file preservation.
use super::*;

pub(super) fn inspect<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    environment: Option<PathBuf>,
) -> Result<u8, CliError> {
    let status = doctor(dialog, environment.as_deref())?;
    if status == 0 {
        return Ok(0);
    }
    if preserve_retained(dialog, environment.as_deref())? {
        return doctor(dialog, environment.as_deref());
    }
    Ok(status)
}

fn doctor<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    environment: Option<&std::path::Path>,
) -> Result<u8, CliError> {
    let result = crate::doctor::run_doctor(EnvironmentArgs {
        environment: environment.map(std::path::Path::to_path_buf),
        json: false,
    })?;
    dialog.say(result.output.trim_end())?;
    Ok(result.status)
}

pub(super) fn repair<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    environment: &std::path::Path,
) -> Result<bool, CliError> {
    if !preserve_retained(dialog, Some(environment))? {
        return Ok(false);
    }
    Ok(doctor(dialog, Some(environment))? == 0)
}

#[cfg(target_os = "macos")]
fn preserve_retained<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    environment: Option<&std::path::Path>,
) -> Result<bool, CliError> {
    use kitrove_core::{
        PreservationRoot, RETAINED_HOLD_PATH, plan_quarantine_preservation, preserve_quarantine,
    };

    let Ok((collection, state)) = crate::doctor::recovery_locations(environment) else {
        return Ok(false);
    };
    let plans: Vec<_> = [PreservationRoot::Collection, PreservationRoot::PrivateState]
        .into_iter()
        .filter_map(|role| plan_quarantine_preservation(&collection, &state, role).ok())
        .collect();
    if plans.is_empty() {
        return Ok(false);
    }
    dialog.heading("Preserve retained files")?;
    for plan in &plans {
        let role = match plan.root {
            PreservationRoot::Collection => "Collection",
            PreservationRoot::PrivateState => "Private state",
        };
        dialog.say(&format!(
            "  {role} · {} retained entries, {} with a changed device ID",
            plan.entries, plan.device_mismatches
        ))?;
    }
    dialog.say(&format!("Each listed directory will move intact to {RETAINED_HOLD_PATH} within its own storage root."))?;
    dialog
        .hint("Skills and sync are separate. Recovery does not approve any pending operation.")?;
    loop {
        match dialog
            .decision("Preserve the listed directories?\ny        Preserve retained files\nEnter/n  Back [default]")?
            .to_ascii_lowercase()
            .as_str()
        {
            "y" | "yes" => break,
            "" | "n" | "no" => return Ok(false),
            _ => dialog.say("Type y and Enter to preserve, or Enter alone to go back.")?,
        }
    }
    for plan in plans {
        // Each root retains its own exact digest and locked revalidation. Keep
        // completed moves visible if the second directory changes or fails.
        preserve_quarantine(&collection, &state, plan.root, &plan.digest)
            .map_err(|error| CliError::new(error.code(), error.message()))?;
        dialog.success(&format!(
            "Preserved {} entries in {}.",
            plan.entries,
            plan.root.as_str()
        ))?;
    }
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
fn preserve_retained<R: PromptInput, W: Write>(
    _dialog: &mut Dialog<R, W>,
    _environment: Option<&std::path::Path>,
) -> Result<bool, CliError> {
    Ok(false)
}
