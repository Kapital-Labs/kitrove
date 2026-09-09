#![cfg(all(
    debug_assertions,
    any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "x86_64")
    )
))]

#[cfg(unix)]
#[path = "../test-fixtures/release_archive.rs"]
mod release_archive;

#[cfg(unix)]
use kitrove_installer::InstallerOperationPhase;
use kitrove_installer::{
    resume_authenticated_application_staging, stage_authenticated_application,
};
use kitrove_release_provenance::{AuthenticatedApplicationExecutable, ExpectedReleaseIdentity};

#[cfg(unix)]
const EXECUTABLE_BYTES: &[u8] = b"#!/bin/sh\nprintf 'kitrove 1.2.3\\n'\n";

#[test]
#[cfg(unix)]
fn authenticated_executable_crosses_the_public_staging_boundary() {
    let spec =
        kitrove_release_policy::application_archive_for_target(compiled_release_target()).unwrap();
    let archive =
        release_archive::archive(spec, &semver::Version::new(1, 2, 3), EXECUTABLE_BYTES, &[]);
    let expected =
        ExpectedReleaseIdentity::new("v1.2.3", "0123456789abcdef0123456789abcdef01234567").unwrap();
    let executable =
        AuthenticatedApplicationExecutable::from_test_archive(spec, &archive, &expected).unwrap();
    let user_directory = std::env::var_os("HOME").expect("test user directory");
    let destination = tempfile::Builder::new()
        .prefix(".kitrove-public-installer-test-")
        .tempdir_in(user_directory)
        .unwrap();

    let staged = stage_authenticated_application(destination.path(), &executable).unwrap();

    let record = serde_json::to_value(staged.record()).unwrap();
    assert_eq!(record["target"], spec.target());
    assert_eq!(record["archive_name"], spec.archive_name());
    assert_eq!(record["release_tag"], expected.tag());
    assert_eq!(record["source_commit"], expected.source_commit());
    assert_eq!(staged.record().phase(), InstallerOperationPhase::Prepared);
    let operation_id = staged.record().operation_id().to_owned();
    drop(staged);

    let resumed =
        resume_authenticated_application_staging(destination.path(), &executable).unwrap();
    assert_eq!(resumed.record().operation_id(), operation_id);
}

#[cfg(unix)]
fn compiled_release_target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        _ => unreachable!("the module cfg admits only supported Unix targets"),
    }
}

#[test]
#[cfg(windows)]
fn authenticated_windows_executable_crosses_the_public_staging_boundary() {
    const ARCHIVE: &[u8] = include_bytes!(
        "../../kitrove-release-policy/tests/fixtures/archive-conformance/valid_zip/kitrove-cli-x86_64-pc-windows-msvc.zip"
    );
    let spec =
        kitrove_release_policy::application_archive_for_target("x86_64-pc-windows-msvc").unwrap();
    let expected =
        ExpectedReleaseIdentity::new("v1.2.3", "0123456789abcdef0123456789abcdef01234567").unwrap();
    let executable =
        AuthenticatedApplicationExecutable::from_test_archive(spec, ARCHIVE, &expected).unwrap();
    let destination = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();

    if kitrove_windows_security::current_process_is_elevated().unwrap() {
        assert!(matches!(
            stage_authenticated_application(destination.path(), &executable),
            Err(kitrove_installer::InstallerStageError::UnsafeDestination)
        ));
        assert!(!destination.path().join(".kitrove-installer").exists());
        return;
    }

    let install = destination.path().join("install");
    kitrove_windows_security::ensure_private_directory_for_tests(&install).unwrap();
    let install = kitrove_windows_security::canonical_directory_path_for_tests(&install).unwrap();
    let staged = stage_authenticated_application(&install, &executable).unwrap();
    let operation_id = staged.record().operation_id().to_owned();
    drop(staged);
    let resumed = resume_authenticated_application_staging(&install, &executable).unwrap();
    assert_eq!(resumed.record().operation_id(), operation_id);
}
