use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::installation_history::{ArchivedInstallation, synchronization};
use crate::installation_state::{
    PreparedInstallation,
    recovery::{ClosedInstallation, ReopenedInstallation},
};

#[path = "command_release.rs"]
mod release;
use crate::release_intake::{BundleArtifactKind, LocalReleaseRequest};
use release::ReleaseInput;

#[path = "command_replacement.rs"]
mod replacement;

const HELP: &str = "Offline Kitrove installer (current user only)

Commands: preflight-install, install, recover-install, retire-install, history-status, history-sync
Replacement commands: preflight-upgrade, upgrade, recover-upgrade, retire-upgrade,
  preflight-rollback, rollback, recover-rollback, retire-rollback,
  upgrade-history-status, upgrade-history-sync, rollback-history-status, rollback-history-sync

Read-only bundle commands: select-application-bundle, select-installer-bundle
  Require only --archive, --bundle (downloaded JSONL collection), --tag, --commit,
  and --sha256. Emit one authenticated bundle to stdout; no destination or state options.
  Run only with an independently trusted or reviewed-source-built installer.

Every installation/replacement/history command requires:
  --archive PATH --bundle PATH --tag vVERSION --commit FULL_COMMIT
  --sha256 ARCHIVE_SHA256 --destination EXISTING_DIRECTORY

Installation/replacement and history-sync require every configured --state-root PATH (repeatable),
or --no-state-roots to explicitly declare that no application state exists.
History commands require --operation ID. history-status is read-only and
does not accept state roots; history-sync requires current state-root selection.

Replacement commands additionally require --prior-tag, --prior-commit and --prior-sha256
for the executable being replaced. Initial upgrade/rollback and their preflight commands
also require --prior-archive and --prior-bundle. Recovery, retirement and history freshly
verify the retained prior kit instead; they do not accept prior file paths.

Inputs must already be downloaded and verified against independently selected
release identity. Offline signature verification is always enforced. No latest
release discovery, privilege elevation, permission repair, or network access.
Windows replacement uses journaled two-step moves, not atomic exchange: the CLI path
may be absent after interruption. Keep this separate installer and exact inputs for recovery.
";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Action {
    Preflight,
    Install,
    Recover,
    Retire,
    Status,
    Sync,
}

struct Request {
    action: Action,
    release: ReleaseInput,
    destination: PathBuf,
    roots: Vec<PathBuf>,
    operation: Option<String>,
    replacement: Option<replacement::Request>,
}

enum Parsed {
    Help,
    Version,
    BundleSelection(BundleArtifactKind, ReleaseInput),
    Request(Box<Request>),
}

fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Parsed, String> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or_else(|| HELP.to_owned())?;
    let bundle_kind = match command.to_str() {
        Some("select-application-bundle") => Some(BundleArtifactKind::Application),
        Some("select-installer-bundle") => Some(BundleArtifactKind::Installer),
        _ => None,
    };
    let (action, direction) = match command.to_str() {
        Some("--help" | "-h") if arguments.next().is_none() => return Ok(Parsed::Help),
        Some("--version") if arguments.next().is_none() => return Ok(Parsed::Version),
        Some("preflight-install") => (Action::Preflight, None),
        Some("install") => (Action::Install, None),
        Some("recover-install") => (Action::Recover, None),
        Some("retire-install") => (Action::Retire, None),
        Some("history-status") => (Action::Status, None),
        Some("history-sync") => (Action::Sync, None),
        Some("select-application-bundle" | "select-installer-bundle") => (Action::Status, None),
        Some(command) => {
            let (action, direction) = replacement::command(command).ok_or("invalid command")?;
            (action, Some(direction))
        }
        _ => return Err("unknown installer command; use --help".into()),
    };
    let mut values = BTreeMap::new();
    let mut roots = Vec::new();
    let mut no_roots = false;
    while let Some(option) = arguments.next() {
        let option = option.to_str().ok_or("option names must be UTF-8")?;
        if option == "--no-state-roots" {
            if no_roots {
                return Err("duplicate --no-state-roots".into());
            }
            no_roots = true;
            continue;
        }
        if !matches!(
            option,
            "--archive"
                | "--bundle"
                | "--tag"
                | "--commit"
                | "--sha256"
                | "--destination"
                | "--operation"
                | "--state-root"
                | "--prior-archive"
                | "--prior-bundle"
                | "--prior-tag"
                | "--prior-commit"
                | "--prior-sha256"
        ) {
            return Err("unknown installer option; use --help".into());
        }
        let value = arguments.next().ok_or("missing option value")?;
        if value.is_empty() || value.to_str().is_some_and(|value| value.starts_with("--")) {
            return Err("missing option value (prefix paths beginning with -- with ./)".into());
        }
        if option == "--state-root" {
            if roots.len() == crate::state_preflight::MAX_STATE_ROOTS {
                return Err("at most 16 state roots are supported".into());
            }
            roots.push(PathBuf::from(value));
        } else if values.insert(option.to_owned(), value).is_some() {
            return Err("duplicate installer option".into());
        }
    }
    if let Some(kind) = bundle_kind {
        if no_roots || !roots.is_empty() {
            return Err("bundle selection does not accept state selection".into());
        }
        let release = ReleaseInput::parse(&mut values, "")?;
        if !values.is_empty() {
            return Err("bundle selection accepts only exact release inputs".into());
        }
        return Ok(Parsed::BundleSelection(kind, release));
    }
    if action == Action::Status {
        if no_roots || !roots.is_empty() {
            return Err("history-status does not accept state selection".into());
        }
    } else if (no_roots && !roots.is_empty()) || (!no_roots && roots.is_empty()) {
        return Err(
            "supply --state-root for every configured root or --no-state-roots, exclusively".into(),
        );
    }
    let release = ReleaseInput::parse(&mut values, "")?;
    let destination = PathBuf::from(release::take(&mut values, "--destination")?);
    let replacement = direction
        .map(|direction| replacement::Request::parse(&mut values, action, direction))
        .transpose()?;
    let operation = values
        .remove("--operation")
        .map(|value| value.into_string().map_err(|_| "invalid operation ID"))
        .transpose()?;
    if matches!(action, Action::Status | Action::Sync) != operation.is_some() {
        return Err("--operation is required only for history commands".into());
    }
    if let Some(operation) = &operation {
        if !crate::record::is_operation_id(operation) {
            return Err("operation ID must contain 32 lowercase hexadecimal digits".into());
        }
    }
    if !values.is_empty() {
        return Err("option is not applicable to this installer command".into());
    }
    Ok(Parsed::Request(Box::new(Request {
        action,
        release,
        destination,
        roots,
        operation,
        replacement,
    })))
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;

pub(crate) fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<String, String> {
    let request = match parse(arguments)? {
        Parsed::Help => return Ok(HELP.into()),
        Parsed::Version => return Ok(format!("kitrove-installer {}", env!("CARGO_PKG_VERSION"))),
        Parsed::BundleSelection(kind, release) => {
            return LocalReleaseRequest {
                archive: &release.archive,
                bundle: &release.bundle,
                expected: &release.pin.expected,
                archive_sha256: release.pin.digest,
            }
            .select_bundle(kind)
            .map_err(|error| error.to_string());
        }
        Parsed::Request(request) => request,
    };
    crate::require_current_user_installation().map_err(|error| error.to_string())?;
    let material = request.release.authenticate()?;
    execute(&request, &material)
}

// Only production-authenticated material reaches this dispatcher from run(). Tests
// exercise command routing with opaque fixture material, never a verification switch.
fn execute(
    request: &Request,
    material: &kitrove_release_provenance::AuthenticatedRecoveryMaterial,
) -> Result<String, String> {
    let executable = material.executable();
    if let Some(replacement) = &request.replacement {
        return replacement.execute(request, executable);
    }
    let result = match request.action {
        Action::Preflight => PreparedInstallation::preflight(&request.destination, executable, &request.roots)
            .map(|()| "First-install preflight passed without mutation. Installation will recheck all authority.".to_owned()),
        Action::Install => {
            PreparedInstallation::prepare(&request.destination, executable, &request.roots)
                .and_then(|prepared| prepared.install())
                .map(|installed| {
                    format!(
                        "Installation committed. Operation: {}",
                        installed.record.operation_id()
                    )
                })
        }
        Action::Recover => {
            ReopenedInstallation::reopen(&request.destination, executable, &request.roots)
                .and_then(|reopened| reopened.recover())
                .map(|installed| {
                    format!(
                        "Installation recovery committed. Operation: {}",
                        installed.record.operation_id()
                    )
                })
        }
        Action::Retire => {
            ClosedInstallation::retire(&request.destination, executable, &request.roots)
                .map(|()| "Completed installation retained in history.".to_owned())
        }
        Action::Status | Action::Sync => {
            let selected = request.operation.as_deref().ok_or("missing operation ID")?;
            let outcome = if request.action == Action::Status {
                ArchivedInstallation::open(&request.destination, selected, executable)
                    .and_then(|history| history.outcome())
            } else {
                synchronization::synchronize(
                    &request.destination,
                    selected,
                    executable,
                    &request.roots,
                )
            };
            outcome.map(|outcome| format!("Historical installation: {outcome:?}."))
        }
    };
    result.map_err(recovery_error)
}

fn recovery_error(error: crate::InstallerStageError) -> String {
    format!(
        "{error}. No cleanup was attempted. Preserve existing installer state; use the same authenticated release inputs for guarded recovery."
    )
}
