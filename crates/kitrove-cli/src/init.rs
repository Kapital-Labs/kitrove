use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use kitrove_adapter_api::ScopeSelection;
use kitrove_core::{
    PolicyRegistry, initialize_empty_authority, preflight_empty_authority_initialization,
};
use kitrove_model::{EnvironmentManifest, LocalState, MachineConfig, MachineId, SchemaVersion};
use serde_json::json;

use crate::args::{CliError, InitArgs, ScanArgs, tier_one_harnesses};
use crate::portable::CompletedCommand;
use crate::scan::{resolve_required_state_root, scan_report};

pub(crate) fn run_init(
    arguments: InitArgs,
    registry: &PolicyRegistry,
) -> Result<CompletedCommand, CliError> {
    let environment_root = resolve_environment_root(arguments.environment.as_deref())?;
    let state_root = resolve_required_state_root()?;
    let machine_id = arguments.machine_id.unwrap_or_else(generated_machine_id);
    let manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    let state = LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: machine_id.clone(),
            active_profile: None,
            enabled_targets: BTreeSet::new(),
            harness_roots: BTreeMap::new(),
        },
        bindings: BTreeMap::new(),
        receipts: BTreeMap::new(),
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::new(),
        scans: Vec::new(),
    };
    preflight_empty_authority_initialization(&environment_root, &state_root, &manifest, &state)
        .map_err(map_initialization_error)?;
    let (state_authority, lifecycle_guard) =
        match kitrove_state_lifecycle::StateAuthority::open_existing(&state_root) {
            Ok(authority) => {
                let guard = authority
                    .try_lock_exclusive()
                    .map_err(map_lifecycle_error)?;
                (authority, guard)
            }
            Err(_) => kitrove_state_lifecycle::StateAuthority::initialize_absent(&state_root)
                .map_err(map_lifecycle_error)?,
        };
    let state_access = state_authority
        .exclusive_access(&lifecycle_guard)
        .map_err(map_lifecycle_error)?;
    state_access
        .validate_initialization_inventory()
        .map_err(map_lifecycle_error)?;
    let report = scan_report(
        ScanArgs {
            harnesses: tier_one_harnesses(),
            scope: ScopeSelection::All,
            project_root: arguments.project_root,
            roots: Vec::new(),
            environment: Some(environment_root.clone()),
            json: arguments.json,
        },
        registry,
    )?;

    initialize_empty_authority(&environment_root, &state_access, &manifest, &state)
        .map_err(map_initialization_error)?;

    let output = if arguments.json {
        format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "init",
                "environment": environment_root,
                "machine_id": machine_id.as_str(),
                "harnesses_inspected": report.versions.len(),
                "unmanaged_capabilities": report.entries.len(),
                "native_extensions": report.native_extensions.len(),
                "adopted": 0,
            }))
            .map_err(|_| serialization_error())?
        )
    } else {
        format!(
            "initialized environment: {}\nmachine: {}\nharnesses inspected: {}\nunmanaged capabilities: {}\nnative extensions: {}\nadopted: 0\n",
            environment_root.display(),
            machine_id,
            report.versions.len(),
            report.entries.len(),
            report.native_extensions.len(),
        )
    };
    Ok(CompletedCommand { output, status: 0 })
}

fn map_lifecycle_error(error: kitrove_state_lifecycle::LifecycleError) -> CliError {
    match error {
        kitrove_state_lifecycle::LifecycleError::InitializationConflict => CliError::new(
            "init.already_initialized",
            "machine-local state already exists or initialization is incomplete",
        ),
        kitrove_state_lifecycle::LifecycleError::LockUnavailable => CliError::new(
            "init.state_in_use",
            "another cooperating Kitrove process is using the machine-local state",
        ),
        kitrove_state_lifecycle::LifecycleError::UnsafeState
        | kitrove_state_lifecycle::LifecycleError::WriteFailed => create_error(),
    }
}

fn resolve_environment_root(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    let root = match explicit {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => std::env::current_dir()
            .map_err(|_| create_error())?
            .join(path),
        None => std::env::current_dir().map_err(|_| create_error())?,
    };
    Ok(root)
}

fn generated_machine_id() -> MachineId {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    MachineId::parse(format!("machine-{}-{nanos}", std::process::id()))
        .expect("generated machine IDs use only validated characters")
}

fn map_initialization_error(error: kitrove_core::ObjectMutationError) -> CliError {
    if error.code() == "object.existing_conflict" {
        CliError::new(
            "init.already_initialized",
            "an environment manifest or machine-local state already exists",
        )
    } else {
        create_error()
    }
}

const fn create_error() -> CliError {
    CliError::new(
        "init.create_failed",
        "the environment and machine-local state could not be created safely",
    )
}

const fn serialization_error() -> CliError {
    CliError::new(
        "init.serialization_failed",
        "the initial environment authority could not be serialized",
    )
}
