#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kitrove_model::ContentHash;
use kitrove_version_probe::{
    probe_application_version, probe_opencode_v2_version, probe_pi_version,
};
use kitrove_windows_process::{
    InheritableHandleCanary, LaunchRequest, launch_contained, process_has_exited,
};
use kitrove_windows_security::{
    canonical_directory_path_for_tests, validate_executable_path, validated_system_launch_directory,
};
use semver::Version;

fn fixture(behavior: &str, name: &str) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::Builder::new()
        .prefix("kitrove-windows-probe-")
        .tempdir()
        .expect("fixture directory");
    let canonical_root =
        canonical_directory_path_for_tests(root.path()).expect("canonical fixture path");
    let behavior_directory = canonical_root.join(behavior);
    std::fs::create_dir(&behavior_directory).expect("behavior directory");
    let destination = behavior_directory.join(name);
    std::fs::copy(
        env!("CARGO_BIN_EXE_kitrove-version-probe-fixture"),
        &destination,
    )
    .expect("copy fixture executable");
    (root, destination)
}

#[test]
fn windows_probe_accepts_pi_and_opencode_with_exact_isolation() {
    let (_pi_root, pi_path) = fixture("supported", "pi.exe");
    let expected_hash = ContentHash::digest(&std::fs::read(&pi_path).unwrap());
    let pi = probe_pi_version(&pi_path).expect("Pi version should be accepted");
    assert_eq!(pi.evidence().observed().as_str(), "0.83.0");
    assert_eq!(pi.executable_hash(), &expected_hash);

    let (_opencode_root, opencode) = fixture("supported", "opencode2.exe");
    let opencode =
        probe_opencode_v2_version(&opencode).expect("OpenCode V2 version should be accepted");
    assert_eq!(opencode.evidence().observed().as_str(), "opencode2 v2.1.0");

    let (_uppercase_root, uppercase) = fixture("supported", "PI.EXE");
    assert!(probe_pi_version(&uppercase).is_ok());

    let (_unicode_root, unicode) = fixture("supported-東京", "pi.exe");
    assert!(probe_pi_version(&unicode).is_ok());
}

#[test]
fn windows_application_probe_requires_the_authenticated_version() {
    let (_root, application) = fixture("supported", "kitrove.exe");
    let expected_hash = ContentHash::digest(&std::fs::read(&application).unwrap());
    let expected_version = Version::new(1, 2, 3);
    let verified = probe_application_version(&application, &expected_version).unwrap();
    assert_eq!(verified.version(), &expected_version);
    assert_eq!(verified.executable_hash(), &expected_hash);
    assert_eq!(
        probe_application_version(&application, &Version::new(1, 2, 4))
            .unwrap_err()
            .code(),
        "version.probe_unexpected_application_version"
    );
}

#[test]
fn windows_probe_refuses_invalid_output_and_timeout() {
    for (behavior, expected_code) in [
        ("malformed", "version.probe_output_invalid"),
        ("stderr", "version.probe_output_invalid"),
        ("oversized", "version.probe_output_limit"),
        ("timeout", "version.probe_timeout"),
    ] {
        let (_root, executable) = fixture(behavior, "pi.exe");
        assert_eq!(
            probe_pi_version(&executable).unwrap_err().code(),
            expected_code,
            "{behavior}"
        );
    }
}

#[test]
fn windows_probe_terminates_descendants_on_success_timeout_and_output_error() {
    for (behavior, succeeds) in [
        ("descendant", true),
        ("descendant-timeout", false),
        ("descendant-stderr", false),
    ] {
        let (root, executable) = fixture(behavior, "pi.exe");
        assert_eq!(
            probe_pi_version(&executable).is_ok(),
            succeeds,
            "{behavior}"
        );
        let pid = read_pid(root.path().join(behavior).join("descendant.pid"));
        assert_process_exited(pid);
    }
}

#[test]
fn contained_process_drop_terminates_a_ready_descendant() {
    let (root, executable_path) = fixture("descendant-drop", "pi.exe");
    let executable = validate_executable_path(&executable_path).unwrap();
    let working_directory = validated_system_launch_directory().unwrap();
    let arguments = ["--version".into()];
    let environment = [
        ("PI_OFFLINE".into(), "1".into()),
        ("PI_SKIP_VERSION_CHECK".into(), "1".into()),
    ];
    let process = launch_contained(LaunchRequest {
        executable: &executable,
        working_directory: &working_directory,
        arguments: &arguments,
        environment: &environment,
    })
    .unwrap();
    let pid = read_pid(root.path().join("descendant-drop").join("descendant.pid"));
    drop(process);
    assert_process_exited(pid);
}

#[test]
fn contained_launch_excludes_an_unrelated_inheritable_handle() {
    let canary = InheritableHandleCanary::new().unwrap();
    let behavior = format!("handle-{}", canary.raw_value());
    let (_root, executable) = fixture(&behavior, "pi.exe");
    assert!(probe_pi_version(&executable).is_ok());
    assert!(!canary.was_signaled().unwrap());
}

#[test]
fn windows_probe_rejects_noncanonical_or_wrong_named_targets() {
    assert!(probe_pi_version(Path::new("pi.exe")).is_err());
    let (_root, executable) = fixture("supported", "other.exe");
    assert!(probe_pi_version(&executable).is_err());
}

fn read_pid(path: PathBuf) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(value) = std::fs::read_to_string(&path) {
            return value.trim().parse().expect("fixture PID");
        }
        assert!(Instant::now() < deadline, "fixture PID was not recorded");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_process_exited(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if process_has_exited(pid).expect("query fixture process") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "descendant {pid} survived containment"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
