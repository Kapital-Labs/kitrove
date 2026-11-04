//! Setup routing only; existing status, lifecycle and initialization gates retain authority.
use super::*;
use crate::scan::read_portable_text;
use kitrove_model::LocalState;
use std::path::Path;

pub(super) fn select<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    registry: &PolicyRegistry,
) -> Result<Option<(PathBuf, bool)>, CliError> {
    let suggestion = default_collection()?;
    let response = dialog.ask(&format!(
        "Where should your portable collection live? [{}]",
        safe(&suggestion.display().to_string())
    ))?;
    let root = if response.is_empty() {
        suggestion
    } else {
        PathBuf::from(response)
    };
    let root = if root.is_absolute() {
        root
    } else {
        std::env::current_dir().map_err(|_| io_error())?.join(root)
    };
    let local = resolve_required_state_root()?;
    let mut existing = present(&local)?;
    for marker in ["kitrove.toml", "kitrove.lock.json", ".kitrove"] {
        existing |= present(&root.join(marker))?;
    }
    if existing {
        dialog.say(&format!(
            "Existing setup detected. Collection: {}\nLocal-only state: {}",
            safe(&root.display().to_string()),
            safe(&local.display().to_string())
        ))?;
        if let Err(error) = validate_existing(dialog, &root, &local) {
            dialog.say("Inspect with kitrove status --environment PATH. Keep existing collections and local state; do not delete them to restart setup.")?;
            return Err(error);
        }
        return if dialog.confirm("Continue setup with this existing collection? Nothing will be re-created; apply and sync still need separate approvals.")? {
            Ok(Some((root, true)))
        } else {
            Ok(None)
        };
    }
    let machine = dialog.ask("Name this computer (for example mac-mini):")?;
    let machine = MachineId::parse(machine).map_err(|_| {
        CliError::new(
            "setup.machine_invalid",
            "choose a valid machine name using lowercase letters, digits and hyphens",
        )
    })?;
    if !dialog.confirm(&format!("Create an empty collection at {}\nLocal-only state at {}\nExisting agent files will not be changed.", safe(&root.display().to_string()), safe(&local.display().to_string())))? {
        return Ok(None);
    }
    let completed = crate::init::run_init(
        InitArgs {
            machine_id: Some(machine),
            project_root: None,
            environment: Some(root.clone()),
            json: false,
        },
        registry,
    )?;
    dialog.report(&completed.output)?;
    Ok(Some((root, false)))
}

// Presence is only a routing hint. Bounded no-follow readers and the original
// operation preconditions still validate authority; absence never permits overwrite.
fn present(path: &Path) -> Result<bool, CliError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(attention()),
    }
}

fn validate_existing<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &Path,
    local: &Path,
) -> Result<(), CliError> {
    let authority =
        kitrove_state_lifecycle::StateAuthority::open_existing(local).map_err(|_| attention())?;
    let _guard = authority.try_lock_shared().map_err(|_| attention())?;
    let text = read_portable_text(local, "state.json", 32 * 1024 * 1024)
        .map_err(|_| attention())?
        .ok_or_else(attention)?;
    LocalState::from_json(&text).map_err(|_| attention())?;
    let status = run_status(EnvironmentArgs {
        environment: Some(root.to_owned()),
        json: false,
    })
    .map_err(|_| attention())?;
    if status.status != 0 {
        dialog.report(&status.output)?;
        return Err(attention());
    }
    Ok(())
}

fn attention() -> CliError {
    CliError::new(
        "setup.existing_attention",
        "existing collection or local state needs attention; inspect it with status before continuing; nothing was reinitialized",
    )
}
