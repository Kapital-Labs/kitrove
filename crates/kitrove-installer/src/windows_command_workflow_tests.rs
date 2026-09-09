use super::*;
use crate::windows_test_support::{destination_in, initialized_state, inventory};
use std::fs;

#[test]
#[ignore = "run explicitly under the dedicated unelevated Windows CI account"]
fn standard_user_command_workflow() {
    assert!(!kitrove_windows_security::current_process_is_elevated().unwrap());
    crate::command::replacement::exercise_windows_for_tests();
    let current = std::env::current_dir().unwrap();
    let bytes = fs::read(current.join("application-probe-fixture.exe")).unwrap();
    let (_, material) = crate::test_support::replacement_releases_with_bytes(
        &bytes,
        b"unused candidate",
        crate::replacement_direction::ReplacementDirection::Upgrade,
    );
    let destination = destination_in(&current);
    let state = initialized_state(destination.path());
    let execute_command = |command: &str, operation: Option<&str>| {
        let mut args = arguments(command);
        let index = args.iter().position(|arg| arg == "--destination").unwrap();
        args[index + 1] = destination.path().as_os_str().to_owned();
        if command != "history-status" {
            args.extend([OsString::from("--state-root"), state.as_os_str().to_owned()]);
        }
        if let Some(operation) = operation {
            args.extend(["--operation", operation].map(OsString::from));
        }
        let Parsed::Request(request) = parse(args).unwrap() else {
            panic!("not a request")
        };
        execute(&request, &material)
    };
    let before = inventory(destination.path());
    let state_before = fs::read(state.join("state.json")).unwrap();
    execute_command("preflight-install", None).unwrap();
    assert_eq!(inventory(destination.path()), before);
    assert_eq!(fs::read(state.join("state.json")).unwrap(), state_before);
    let installed = execute_command("install", None).unwrap();
    let operation = installed
        .strip_prefix("Installation committed. Operation: ")
        .unwrap();
    assert!(crate::record::is_operation_id(operation));
    assert_eq!(
        fs::read(destination.path().join("kitrove.exe")).unwrap(),
        bytes
    );
    assert!(execute_command("preflight-install", None).is_err());
    assert!(
        execute_command("recover-install", None)
            .unwrap()
            .ends_with(operation)
    );
    execute_command("retire-install", None).unwrap();
    let archive = destination
        .path()
        .join(crate::INSTALLER_HISTORY_DIRECTORY)
        .join(operation);
    let names = inventory(&archive);
    for command in ["history-status", "history-sync", "history-sync"] {
        assert!(
            execute_command(command, Some(operation))
                .unwrap()
                .contains("Committed")
        );
        assert_eq!(inventory(&archive), names);
        assert_eq!(fs::read(state.join("state.json")).unwrap(), state_before);
        assert_eq!(
            fs::read(destination.path().join("kitrove.exe")).unwrap(),
            bytes
        );
    }
}
