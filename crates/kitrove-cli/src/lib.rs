#![forbid(unsafe_code)]
//! Concrete composition root for the Kitrove command-line interface.

/// Writes command output. A reader that closed the pipe ends output quietly.
macro_rules! out {
    ($($argument:tt)*) => {
        $crate::emit(format_args!($($argument)*))
    };
}

macro_rules! outln {
    ($($argument:tt)*) => {
        $crate::emit(format_args!("{}\n", format_args!($($argument)*)))
    };
}

mod adapters;
mod args;
mod batch_recovery;
mod doctor;
mod help;
mod init;
mod materialize;
mod pack;
mod portable;
#[cfg(test)]
#[path = "probe_fixture.rs"]
mod probe_fixture;
mod recover;
mod registry;
mod removal;
mod scan;
mod scan_display;
mod setup;
mod sync;
mod trust;
mod version_probe;

pub use registry::tier_one_registry;

use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal as _, Write as _};
use std::process::ExitCode;

use args::{Command, DOCTOR_HELP, parse_args};
use init::run_init;
use materialize::{run_apply, run_confirmed_apply, run_plan};
use pack::{
    run_pack_adopt, run_pack_create, run_pack_discover, run_pack_inspect, run_pack_list,
    run_pack_rollback, run_pack_update,
};
use portable::{run_adopt, run_lock, run_status};
use registry::try_tier_one_registry;
use removal::{run_pack_remove, run_remove};
use scan::run_scan;
use sync::{run_sync_apply, run_sync_plan};
use trust::{run_trust_apply, run_trust_audit, run_trust_plan};
use version_probe::run_version_probe;

const NORTH_STAR: &str = include_str!("../../../NORTH_STAR.md");
const INVARIANTS: &str = include_str!("../../../docs/architecture/INVARIANTS.md");

fn emit(output: std::fmt::Arguments<'_>) {
    if let Err(error) = write!(io::stdout().lock(), "{output}") {
        assert!(
            error.kind() == io::ErrorKind::BrokenPipe,
            "failed printing to stdout: {error}"
        );
    }
}

/// Runs the process-facing CLI entry point.
pub fn main_entry() -> ExitCode {
    ExitCode::from(run(env::args_os().skip(1)))
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> u8 {
    let mut arguments = arguments.into_iter().peekable();
    let json_errors = arguments.peek().is_some_and(|arg| arg == "--json-errors");
    if json_errors {
        arguments.next();
    }
    let arguments: Vec<_> = arguments.collect();
    if let Some(text) = help::requested(&arguments) {
        out!("{text}");
        return 0;
    }
    if matches!(arguments.as_slice(), [command, flag] if command == "help" && flag == "--all") {
        out!("{}", help::reference());
        return 0;
    }
    let guided_apply = !json_errors && bare_apply_requested(&arguments);
    let command = match parse_args(arguments.iter().cloned()) {
        Ok(command) => command,
        Err(error) => {
            report_error(json_errors, error.code, &error, 2);
            if !json_errors {
                eprintln!("{}", help::error_hint(&arguments));
            }
            return 2;
        }
    };
    match command {
        Command::Setup => return setup::entry(None, false),
        Command::Configure(arguments) => {
            if arguments.json {
                if json_errors {
                    report_error(true, "cli.interactive_required", &"", 2);
                } else {
                    eprintln!(
                        "configure is interactive; use explicit commands for JSON automation"
                    );
                }
                return 2;
            }
            return setup::entry(arguments.environment, true);
        }
        Command::Init(arguments) => {
            let registry = match try_tier_one_registry() {
                Ok(registry) => registry,
                Err(_) => {
                    report_error(
                        json_errors,
                        "scan.registry_invalid",
                        &"the compiled policy registry is invalid",
                        1,
                    );
                    return 1;
                }
            };
            match run_init(arguments, &registry) {
                Ok(completed) => {
                    out!("{}", completed.output);
                    return completed.status;
                }
                Err(error) => {
                    report_error(json_errors, error.code, &error, 1);
                    return 1;
                }
            }
        }
        Command::Help => out!("{}", help::INDEX),
        Command::DoctorHelp => out!("{DOCTOR_HELP}"),
        Command::RecoverHelp => out!("{}", recover::HELP),
        Command::Recover(arguments) => match recover::run(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::About => outln!(
            "Kitrove {} — bidirectional agent capability portability",
            env!("CARGO_PKG_VERSION")
        ),
        Command::NorthStar => out!("{NORTH_STAR}"),
        Command::Invariants => out!("{INVARIANTS}"),
        Command::Version => outln!("kitrove {}", env!("CARGO_PKG_VERSION")),
        Command::VersionProbe(arguments) => match run_version_probe(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::Doctor(arguments) => match doctor::run_doctor(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::Status(arguments) => match run_status(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::Lock(arguments) => match run_lock(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::Plan(arguments) => match run_plan(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::ConfirmedApply(arguments, digest) => match run_confirmed_apply(arguments, &digest)
        {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::Apply(arguments)
            if guided_apply && io::stdin().is_terminal() && io::stdout().is_terminal() =>
        {
            return setup::apply_entry(arguments.environment);
        }
        Command::Apply(arguments) => match run_apply(arguments, confirm_apply) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::Remove(arguments) => match run_remove(arguments, confirm_removal) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::SyncPlan(arguments) => match run_sync_plan(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::SyncApply(arguments) => match run_sync_apply(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::TrustPlan(arguments) => match run_trust_plan(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::TrustApply(arguments) => match run_trust_apply(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::TrustAudit(arguments) => match run_trust_audit(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::PackList(arguments) => match run_pack_list(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::PackDiscover(arguments) => match run_pack_discover(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::PackAdopt(arguments) => match run_pack_adopt(arguments, confirm_pack_adoption) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::PackCreate(arguments) => match run_pack_create(arguments, confirm_pack_creation) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::PackUpdate(arguments) => match run_pack_update(arguments, confirm_pack_update) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::PackRollback(arguments) => {
            match run_pack_rollback(arguments, confirm_pack_rollback) {
                Ok(completed) => {
                    out!("{}", completed.output);
                    return completed.status;
                }
                Err(error) => {
                    report_error(json_errors, error.code, &error, 1);
                    return 1;
                }
            }
        }
        Command::PackRemove(arguments) => match run_pack_remove(arguments, confirm_removal) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::PackInspect(arguments) => match run_pack_inspect(arguments) {
            Ok(completed) => {
                out!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                report_error(json_errors, error.code, &error, 1);
                return 1;
            }
        },
        Command::Adopt(arguments) => {
            let registry = match try_tier_one_registry() {
                Ok(registry) => registry,
                Err(_) => {
                    report_error(
                        json_errors,
                        "scan.registry_invalid",
                        &"the compiled policy registry is invalid",
                        1,
                    );
                    return 1;
                }
            };
            match run_adopt(arguments, &registry, confirm_adoption) {
                Ok(completed) => {
                    out!("{}", completed.output);
                    return completed.status;
                }
                Err(error) => {
                    report_error(json_errors, error.code, &error, 1);
                    return 1;
                }
            }
        }
        Command::Scan(arguments) => {
            let registry = match try_tier_one_registry() {
                Ok(registry) => registry,
                Err(_) => {
                    report_error(
                        json_errors,
                        "scan.registry_invalid",
                        &"the compiled policy registry is invalid",
                        1,
                    );
                    return 1;
                }
            };
            match run_scan(arguments, &registry) {
                Ok(status) => return status,
                Err(error) => {
                    report_error(json_errors, error.code, &error, 1);
                    return 1;
                }
            }
        }
    }
    0
}

fn report_error(json: bool, code: &str, message: &dyn std::fmt::Display, exit_code: u8) {
    if json {
        eprintln!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "error": { "code": code },
                "exit_code": exit_code,
            })
        );
    } else {
        eprintln!("error[{code}]: {message}");
        if code == "apply.batch_storage_failed" {
            eprintln!(
                "Run kitrove doctor with --environment set to this collection for a read-only storage report."
            );
        }
    }
}

fn confirm_adoption(plan: &str) -> bool {
    confirm_operation(plan, "adoption")
}

fn confirm_pack_creation(plan: &str) -> bool {
    confirm_operation(plan, "pack creation")
}

fn confirm_pack_adoption(plan: &str) -> bool {
    confirm_operation(plan, "pack adoption")
}

fn confirm_pack_update(plan: &str) -> bool {
    confirm_operation(plan, "pack update")
}

fn confirm_pack_rollback(plan: &str) -> bool {
    confirm_operation(plan, "pack rollback")
}

fn confirm_removal(plan: &str) -> bool {
    confirm_operation(plan, "removal")
}

fn confirm_apply(plan: &str) -> bool {
    confirm_operation(plan, "apply")
}

fn confirm_operation(plan: &str, operation: &str) -> bool {
    eprint!("{plan}Confirm {operation} by typing 'yes': ");
    if io::stderr().flush().is_err() {
        return false;
    }
    let mut response = String::new();
    io::stdin().read_line(&mut response).is_ok() && response.trim() == "yes"
}

/// Explicit selections, scope, probes and machine output keep the command path.
fn bare_apply_requested(arguments: &[OsString]) -> bool {
    matches!(arguments, [command] if command == "apply")
        || matches!(arguments, [command, flag, _path] if command == "apply" && flag == "--environment")
}

#[cfg(test)]
mod guided_apply_tests {
    #[test]
    fn only_bare_or_environment_only_apply_selects_guided_entry() {
        for args in [
            vec!["apply"],
            vec!["apply", "--environment", "/synthetic/collection"],
        ] {
            assert!(super::bare_apply_requested(
                &args.into_iter().map(Into::into).collect::<Vec<_>>()
            ));
        }
        for args in [
            vec!["plan"],
            vec!["apply", "--json"],
            vec!["apply", "--scope", "user"],
            vec!["apply", "--pack", "review"],
            vec!["apply", "--target", "opencode"],
            vec!["apply", "--confirm", "digest"],
        ] {
            assert!(!super::bare_apply_requested(
                &args.into_iter().map(Into::into).collect::<Vec<_>>()
            ));
        }
    }
}
