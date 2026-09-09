use super::*;

#[test]
#[ignore = "run explicitly under the dedicated unelevated Windows CI account"]
fn standard_user_first_install_state_preparation() {
    assert!(!kitrove_windows_security::current_process_is_elevated().unwrap());
    let destination =
        crate::windows_test_support::destination_in(&std::env::current_dir().unwrap());
    let state = crate::windows_test_support::initialized_state(destination.path());
    let (executable, _) = crate::test_support::replacement_releases_with_bytes(
        b"prior executable",
        b"candidate executable",
        crate::replacement_direction::ReplacementDirection::Upgrade,
    );
    let mut prepared = PreparedInstallation::prepare(
        destination.path(),
        &executable,
        std::slice::from_ref(&state),
    )
    .unwrap();
    prepared.revalidate().unwrap();
    let record = prepared.staged.record.clone();
    let record_path = destination
        .path()
        .join(crate::INSTALLER_STATE_DIRECTORY)
        .join(record.operation_id())
        .join(INSTALL_STATE_RECORD);
    assert!(std::fs::write(&record_path, b"competing writer").is_err());
    let authority = kitrove_state_lifecycle::StateAuthority::open_existing(&state).unwrap();
    assert!(authority.try_lock_shared().is_err());
    assert!(!destination.path().join(record.executable_name()).exists());
    drop(prepared);
    let directory =
        kitrove_windows_security::validate_install_directory(destination.path()).unwrap();
    let installer = kitrove_windows_security::open_private_directory(
        directory.directory().unwrap(),
        OsStr::new(crate::INSTALLER_STATE_DIRECTORY),
    )
    .unwrap();
    let operation = kitrove_windows_security::open_private_directory(
        &installer,
        OsStr::new(record.operation_id()),
    )
    .unwrap();
    let mut states = InspectedStateRoots::capture(std::slice::from_ref(&state)).unwrap();
    RetainedInstallState::reopen(&operation, &record, &mut states).unwrap();
    let mut omitted = InspectedStateRoots::capture(&[]).unwrap();
    assert!(RetainedInstallState::reopen(&operation, &record, &mut omitted).is_err());
    drop(states);
    let bytes = std::fs::read(&record_path).unwrap();
    kitrove_windows_security::write_current_user_owned_file_for_tests(
        &state.join("state.json"),
        br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":"work"}}"#,
    )
    .unwrap();
    let mut changed = InspectedStateRoots::capture(std::slice::from_ref(&state)).unwrap();
    assert!(RetainedInstallState::reopen(&operation, &record, &mut changed).is_err());
    assert_eq!(std::fs::read(&record_path).unwrap(), bytes);
    assert!(!destination.path().join(record.executable_name()).exists());
}
