#![forbid(unsafe_code)]
//! Concrete composition root for the Kitrove command-line interface.

mod adapters;
mod args;
mod batch_recovery;
mod init;
mod materialize;
mod pack;
mod portable;
mod registry;
mod removal;
mod scan;
mod sync;
mod trust;
mod version_probe;

pub use registry::tier_one_registry;

use std::env;
use std::ffi::OsString;
use std::io::{self, Write as _};
use std::process::ExitCode;

use args::{
    ADDITIONAL_MCP_HELP, ADDITIONAL_PACK_HELP, ADDITIONAL_SYNC_HELP, Command, HELP, parse_args,
};
use init::run_init;
use materialize::{run_apply, run_plan};
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

/// Runs the process-facing CLI entry point.
#[must_use]
pub fn main_entry() -> ExitCode {
    ExitCode::from(run(env::args_os().skip(1)))
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> u8 {
    let command = match parse_args(arguments) {
        Ok(command) => command,
        Err(error) => {
            eprintln!(
                "error[{}]: {error}\n\n{HELP}{ADDITIONAL_MCP_HELP}{ADDITIONAL_SYNC_HELP}{ADDITIONAL_PACK_HELP}",
                error.code
            );
            return 2;
        }
    };
    match command {
        Command::Init(arguments) => {
            let registry = match try_tier_one_registry() {
                Ok(registry) => registry,
                Err(_) => {
                    eprintln!(
                        "error[scan.registry_invalid]: the compiled policy registry is invalid"
                    );
                    return 1;
                }
            };
            match run_init(arguments, &registry) {
                Ok(completed) => {
                    print!("{}", completed.output);
                    return completed.status;
                }
                Err(error) => {
                    eprintln!("error[{}]: {error}", error.code);
                    return 1;
                }
            }
        }
        Command::Help => {
            print!("{HELP}{ADDITIONAL_MCP_HELP}{ADDITIONAL_SYNC_HELP}{ADDITIONAL_PACK_HELP}")
        }
        Command::About => println!(
            "Kitrove {} — bidirectional agent capability portability",
            env!("CARGO_PKG_VERSION")
        ),
        Command::NorthStar => print!("{NORTH_STAR}"),
        Command::Invariants => print!("{INVARIANTS}"),
        Command::Version => println!("kitrove {}", env!("CARGO_PKG_VERSION")),
        Command::VersionProbe(arguments) => match run_version_probe(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::Status(arguments) => match run_status(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::Lock(arguments) => match run_lock(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::Plan(arguments) => match run_plan(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::Apply(arguments) => match run_apply(arguments, confirm_apply) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::Remove(arguments) => match run_remove(arguments, confirm_removal) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::SyncPlan(arguments) => match run_sync_plan(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::SyncApply(arguments) => match run_sync_apply(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::TrustPlan(arguments) => match run_trust_plan(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::TrustApply(arguments) => match run_trust_apply(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::TrustAudit(arguments) => match run_trust_audit(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::PackList(arguments) => match run_pack_list(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::PackDiscover(arguments) => match run_pack_discover(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::PackAdopt(arguments) => match run_pack_adopt(arguments, confirm_pack_adoption) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::PackCreate(arguments) => match run_pack_create(arguments, confirm_pack_creation) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::PackUpdate(arguments) => match run_pack_update(arguments, confirm_pack_update) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::PackRollback(arguments) => {
            match run_pack_rollback(arguments, confirm_pack_rollback) {
                Ok(completed) => {
                    print!("{}", completed.output);
                    return completed.status;
                }
                Err(error) => {
                    eprintln!("error[{}]: {error}", error.code);
                    return 1;
                }
            }
        }
        Command::PackRemove(arguments) => match run_pack_remove(arguments, confirm_removal) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::PackInspect(arguments) => match run_pack_inspect(arguments) {
            Ok(completed) => {
                print!("{}", completed.output);
                return completed.status;
            }
            Err(error) => {
                eprintln!("error[{}]: {error}", error.code);
                return 1;
            }
        },
        Command::Adopt(arguments) => {
            let registry = match try_tier_one_registry() {
                Ok(registry) => registry,
                Err(_) => {
                    eprintln!(
                        "error[scan.registry_invalid]: the compiled policy registry is invalid"
                    );
                    return 1;
                }
            };
            match run_adopt(arguments, &registry, confirm_adoption) {
                Ok(completed) => {
                    print!("{}", completed.output);
                    return completed.status;
                }
                Err(error) => {
                    eprintln!("error[{}]: {error}", error.code);
                    return 1;
                }
            }
        }
        Command::Scan(arguments) => {
            let registry = match try_tier_one_registry() {
                Ok(registry) => registry,
                Err(_) => {
                    eprintln!(
                        "error[scan.registry_invalid]: the compiled policy registry is invalid"
                    );
                    return 1;
                }
            };
            match run_scan(arguments, &registry) {
                Ok(completed) => {
                    print!("{}", completed.output);
                    return completed.status;
                }
                Err(error) => {
                    eprintln!("error[{}]: {error}", error.code);
                    return 1;
                }
            }
        }
    }
    0
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
