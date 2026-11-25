//! Read-only composition of portable integrity and closed storage observations.
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    LockStatus, ObjectState, StorageDoctorCleanupDetail, StorageDoctorCleanupIdentityComponent,
    StorageDoctorCleanupReason, StorageDoctorRoots, compare_lockfile, inspect_storage_doctor,
    verify_referenced_objects,
};
use serde_json::{Value, json};

use crate::args::{CliError, EnvironmentArgs};
use crate::portable::{CompletedCommand, load_manifest};
use crate::scan::{
    read_portable_text, resolve_inspection_home_root, resolve_required_environment_root,
    resolve_required_state_root,
};

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;

struct Check {
    role: &'static str,
    stage: &'static str,
    status: &'static str,
    code: &'static str,
    count: Option<usize>,
    detail: Option<StorageDoctorCleanupDetail>,
}

impl Check {
    fn portable(
        stage: &'static str,
        status: &'static str,
        code: &'static str,
        count: Option<usize>,
    ) -> Self {
        Self {
            role: "collection",
            stage,
            status,
            code,
            count,
            detail: None,
        }
    }

    fn attention(&self) -> bool {
        match self.status {
            "blocked" => true,
            "not_checked" => !(self.stage == "private_acl" && self.code == "acl_not_applicable"),
            "absent" => !matches!(
                self.stage,
                "control_directory" | "existing_lock" | "recovery_markers" | "retained_cleanup"
            ),
            "ok" => false,
            _ => true,
        }
    }

    fn encoded(&self) -> Value {
        let mut value =
            json!({"role":self.role,"stage":self.stage,"status":self.status,"code":self.code});
        if let Some(count) = self.count {
            value["count"] = json!(count);
        }
        if let Some(detail) = self.detail {
            value["detail"] = json!(detail);
        }
        value
    }
}

fn locations(explicit: Option<&Path>) -> Result<(PathBuf, PathBuf, PathBuf), Check> {
    let failed = |role, code| Check {
        role,
        stage: "root",
        status: "not_checked",
        code,
        count: None,
        detail: None,
    };
    let home =
        resolve_inspection_home_root().map_err(|_| failed("user_home", "home_unavailable"))?;
    let default = home.join("Kitrove");
    let collection = resolve_required_environment_root(Some(explicit.unwrap_or(&default)))
        .map_err(|_| failed("collection", "collection_unavailable"))?;
    let state = resolve_required_state_root()
        .map_err(|_| failed("private_state", "private_state_unavailable"))?;
    Ok((home, collection, state))
}

#[cfg(target_os = "macos")]
pub(crate) fn recovery_locations(explicit: Option<&Path>) -> Result<(PathBuf, PathBuf), CliError> {
    locations(explicit)
        .map(|(_, collection, state)| (collection, state))
        .map_err(|_| {
            CliError::new(
                "recover.location_unavailable",
                "run doctor to check the collection and private storage paths",
            )
        })
}

pub(crate) fn run_doctor(arguments: EnvironmentArgs) -> Result<CompletedCommand, CliError> {
    let (inspection, mutation_access, checks) = match locations(arguments.environment.as_deref()) {
        Err(check) => ("unlocked", "not_tested", vec![check]),
        Ok((home, collection, state)) => {
            let storage = inspect_storage_doctor(StorageDoctorRoots {
                collection: &collection,
                private_state: &state,
                user_home: &home,
                project: None,
            });
            let collection_inspected = storage.checks.iter().any(|check| {
                check.role.as_str() == "collection"
                    && check.stage.as_str() == "root"
                    && check.status.as_str() == "ok"
            });
            let mut checks: Vec<_> = storage
                .checks
                .iter()
                .map(|check| Check {
                    role: check.role.as_str(),
                    stage: check.stage.as_str(),
                    status: check.status.as_str(),
                    code: check.code.as_str(),
                    count: check.count,
                    detail: check.detail,
                })
                .collect();
            if collection_inspected {
                checks.extend(portable_checks(&collection));
            } else {
                checks.extend(portable_not_checked());
            }
            (
                storage.inspection.as_str(),
                storage.mutation_access.as_str(),
                checks,
            )
        }
    };
    let attention = checks.iter().any(Check::attention);
    let output = if arguments.json {
        format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version":3,"version":env!("CARGO_PKG_VERSION"),
                "inspection":inspection,"mutation_access":mutation_access,
                "checks":checks.iter().map(Check::encoded).collect::<Vec<_>>(),
            }))
            .map_err(|_| CliError::new(
                "doctor.serialization_failed",
                "the doctor report could not be serialized"
            ))?
        )
    } else {
        human_report(&checks, attention)
    };
    Ok(CompletedCommand {
        output,
        status: if attention { 3 } else { 0 },
    })
}

fn portable_not_checked() -> Vec<Check> {
    ["portable_manifest", "portable_lock", "portable_objects"]
        .into_iter()
        .map(|stage| Check::portable(stage, "not_checked", "prior_check_blocked", None))
        .collect()
}

fn portable_checks(root: &Path) -> Vec<Check> {
    let mut checks = Vec::new();
    let manifest = match load_manifest(root) {
        Ok(manifest) => manifest,
        Err(error) => {
            let (status, code) = match error.code {
                "cli.environment_manifest_missing" => ("absent", "manifest_missing"),
                "cli.environment_manifest_invalid" => ("blocked", "manifest_invalid"),
                _ => ("not_checked", "manifest_unverified"),
            };
            checks.push(Check::portable("portable_manifest", status, code, None));
            checks.extend(portable_not_checked().into_iter().skip(1));
            return checks;
        }
    };
    checks.push(Check::portable(
        "portable_manifest",
        "ok",
        "manifest_valid",
        Some(manifest.assets.len()),
    ));
    let lock = read_portable_text(root, "kitrove.lock.json", MAX_CONTROL_BYTES)
        .ok()
        .and_then(|text| compare_lockfile(&manifest, text.as_deref()).ok());
    let (status, code) = match lock.map(|lock| lock.status()) {
        Some(LockStatus::InSync) => ("ok", "lock_in_sync"),
        Some(LockStatus::Missing) => ("absent", "lock_missing"),
        Some(LockStatus::Drift) => ("blocked", "lock_drift"),
        Some(LockStatus::Invalid) => ("blocked", "lock_invalid"),
        None => ("not_checked", "lock_unverified"),
    };
    checks.push(Check::portable("portable_lock", status, code, None));
    match verify_referenced_objects(&manifest, root, CaptureLimits::default()) {
        Err(_) => checks.push(Check::portable(
            "portable_objects",
            "not_checked",
            "objects_unverified",
            None,
        )),
        Ok(objects) => {
            let mut counts = [0usize; 6];
            for finding in objects.findings() {
                counts[match finding.state() {
                    ObjectState::Verified => 0,
                    ObjectState::Missing => 1,
                    ObjectState::HashMismatch => 2,
                    ObjectState::Unsafe => 3,
                    ObjectState::Invalid => 4,
                    ObjectState::Unreadable => 5,
                }] += 1;
            }
            for (index, (count, code)) in counts
                .into_iter()
                .zip([
                    "objects_verified",
                    "objects_missing",
                    "objects_hash_mismatch",
                    "objects_unsafe",
                    "objects_invalid",
                    "objects_unreadable",
                ])
                .enumerate()
            {
                if index == 0 || count > 0 {
                    checks.push(Check::portable(
                        "portable_objects",
                        if index == 0 { "ok" } else { "blocked" },
                        code,
                        Some(count),
                    ));
                }
            }
        }
    }
    checks
}

fn human_report(checks: &[Check], attention: bool) -> String {
    let mut output = format!(
        "Kitrove doctor: {}\n",
        if attention {
            "needs attention"
        } else {
            "inspected checks passed"
        }
    );
    let issues: Vec<_> = checks
        .iter()
        .filter(|check| check.attention() && check.code != "prior_check_blocked")
        .collect();
    for check in issues.iter().take(3) {
        writeln!(
            output,
            "  {} ({}): {}.",
            role_label(check.role),
            stage_label(check.stage),
            problem(check)
        )
        .expect("writing to a string cannot fail");
        if let Some(detail) = check.detail
            && let Some(entry) = detail.entry
        {
            writeln!(
                output,
                "    Retained item {entry} in this inspection{}.",
                if detail.location.as_str() == "descendant" {
                    ", inside its directory"
                } else {
                    ""
                }
            )
            .expect("writing to a string cannot fail");
        }
    }
    if issues.len() > 3 {
        writeln!(
            output,
            "  {} further findings are available in --json.",
            issues.len() - 3
        )
        .expect("writing to a string cannot fail");
    }
    if attention {
        writeln!(output, "Next: {}", next_step(checks)).expect("writing to a string cannot fail");
    }
    output.push_str("No changes made. Write access and lock availability were not tested.\n");
    output
}

fn role_label(role: &str) -> &'static str {
    match role {
        "collection" => "Collection",
        "private_state" => "Private state",
        "user_home" => "Home",
        _ => "Project",
    }
}

fn stage_label(stage: &str) -> &'static str {
    match stage {
        "root" => "root",
        "private_boundary" => "permissions",
        "state_file" => "machine-local state",
        "private_acl" => "access rules",
        "control_directory" => "control folder",
        "existing_lock" => "lock file",
        "recovery_markers" => "pending work",
        "retained_cleanup" => "retained files",
        "portable_manifest" => "manifest",
        "portable_lock" => "generated lock",
        _ => "objects",
    }
}

fn problem(check: &Check) -> &'static str {
    if let Some(detail) = check.detail {
        if detail.reason == StorageDoctorCleanupReason::IdentityMismatch {
            use StorageDoctorCleanupIdentityComponent as C;
            match detail.identity_component {
                Some(C::Device) => {
                    return "the recorded device ID differs; the file ID matches";
                }
                Some(C::File) => {
                    return "the recorded file ID differs; the device ID matches";
                }
                Some(C::DeviceAndFile) => {
                    return "the recorded device and file IDs both differ";
                }
                None => {}
            }
        }
        return cleanup_problem(detail.reason);
    }
    match check.code {
        "home_unavailable" | "collection_unavailable" | "private_state_unavailable" => {
            "the configured location could not be resolved"
        }
        "unsafe_root" => "the selected root did not pass inspection",
        "inspect_rejected" => "the current ownership or permissions did not pass inspection",
        "acl_not_empty" => "extra filesystem access rules are present",
        "acl_read_failed" => "filesystem access rules could not be read",
        "native_acl_rejected" => "private filesystem access rules could not be verified",
        "state_file_missing" => "the machine-local state file is missing",
        "state_file_unverified" => "the machine-local state file did not pass metadata inspection",
        "lock_unsafe" => "existing lock metadata did not pass inspection",
        "recovery_present" => "a pending transaction marker is present",
        "recovery_unsafe" => "transaction-marker metadata needs review",
        "retained_unrecognized" => "unrecognized retained cleanup entries need review",
        "retained_unsafe" => "retained cleanup metadata did not pass inspection",
        "inspection_limit" => "the inspection reached its bound",
        "manifest_missing" => "the collection manifest is missing",
        "manifest_invalid" => "the collection manifest did not parse or validate",
        "lock_missing" => "the generated collection lock is missing",
        "lock_invalid" => "the generated collection lock is invalid",
        "lock_drift" => "the generated collection lock differs from the manifest",
        "objects_missing"
        | "objects_hash_mismatch"
        | "objects_unsafe"
        | "objects_invalid"
        | "objects_unreadable" => "referenced object content needs review",
        "absent" => "the required root is absent",
        _ => "this check remains unverified",
    }
}

fn cleanup_problem(reason: StorageDoctorCleanupReason) -> &'static str {
    use StorageDoctorCleanupReason as R;
    match reason {
        R::MetadataUnreadable => "retained cleanup metadata could not be read",
        R::DirectoryUnreadable => "the retained cleanup directory could not be listed",
        R::OpenRejected => "a retained cleanup entry could not be opened without following links",
        R::LinkOrReparsePoint => "retained cleanup contains a link or redirected entry",
        R::WrongEntryKind => "a retained cleanup entry has the wrong file or directory type",
        R::IdentityMismatch => {
            "a retained item's recorded filesystem identity does not match the current entry"
        }
        R::ChangedDuringInspection => {
            "a retained cleanup entry changed type or identity during inspection"
        }
        R::FileLinkCountRejected => "a retained cleanup file does not have exactly one hard link",
        R::PendingBatchNotVerifiedEmpty => "a pending cleanup folder could not be verified empty",
        R::MultipleCleanupBatches => {
            "more than one pending or interrupted cleanup batch is present"
        }
        R::UnrecognizedName => "a retained cleanup entry has an unrecognized name format",
        R::DirectoryOwnerMismatch => "a cleanup directory is not owned by the current user",
        R::DirectoryModeRejected => {
            "a cleanup directory does not have the required owner-only permissions (0700)"
        }
        R::AclNotEmpty => "a cleanup directory has extra filesystem access rules",
        R::AclUnreadable => "a cleanup directory's filesystem access rules could not be read",
        R::NativeProtectionRejected => "native cleanup protection could not be verified",
        R::BoundaryUnverified => "the cleanup directory boundary could not be verified",
        R::InspectionLimit => "retained cleanup inspection reached its bound",
    }
}

fn next_step(checks: &[Check]) -> &'static str {
    if checks.iter().any(|check| {
        check.attention() && matches!(check.code, "recovery_present" | "recovery_unsafe")
    }) {
        "share the full JSON report for review of the transaction-marker finding; leave existing files in place."
    } else if checks
        .iter()
        .any(|check| check.attention() && check.stage == "retained_cleanup")
    {
        "leave retained files in place and share this report for recovery review."
    } else if checks
        .iter()
        .any(|check| check.attention() && !check.stage.starts_with("portable_"))
    {
        "share the full JSON report for review of the identified storage checks."
    } else {
        "use kitrove status on this collection to review its portable integrity."
    }
}
