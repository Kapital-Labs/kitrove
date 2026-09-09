use super::*;
use crate::test_support::{TestDestination, private_tempdir, upgrade_releases};
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;

struct Fixture {
    root: TestDestination,
    archive: PathBuf,
    bundle: PathBuf,
    material: AuthenticatedRecoveryMaterial,
    expected: ExpectedReleaseIdentity,
}

impl Fixture {
    fn new() -> Self {
        let (_, material) = upgrade_releases();
        let root = private_tempdir();
        let archive = root
            .path()
            .join(material.executable().subject().spec().archive_name());
        let bundle = root.path().join("attestation.json");
        fs::write(&archive, material.archive_bytes()).unwrap();
        fs::write(&bundle, material.bundle_bytes()).unwrap();
        for path in [&archive, &bundle] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let expected = ExpectedReleaseIdentity::new(
            material.executable().subject().release_tag(),
            material.executable().subject().source_commit(),
        )
        .unwrap();
        Self {
            root,
            archive,
            bundle,
            material,
            expected,
        }
    }

    fn request(&self) -> LocalReleaseRequest<'_> {
        LocalReleaseRequest {
            archive: &self.archive,
            bundle: &self.bundle,
            expected: &self.expected,
            archive_sha256: self.material.executable().subject().archive_sha256(),
        }
    }
}

fn synthetic_verify(
    spec: ApplicationArchiveSpec,
    archive: &[u8],
    bundle: &[u8],
    expected: &ExpectedReleaseIdentity,
) -> Result<AuthenticatedRecoveryMaterial, InstallerStageError> {
    AuthenticatedRecoveryMaterial::from_test_archive(spec, archive, bundle, expected)
        .map_err(|_| InstallerStageError::VerificationFailed)
}

#[test]
fn bundle_commands_are_read_only_and_do_not_accept_synthetic_provenance() {
    let fixture = Fixture::new();
    let subject = fixture.material.executable().subject();
    let digest = crate::record::encode_hex(&subject.archive_sha256());
    for command in ["select-application-bundle", "select-installer-bundle"] {
        let mut args = vec![std::ffi::OsString::from(command)];
        for (option, value) in [
            ("--archive", fixture.archive.as_os_str()),
            ("--bundle", fixture.bundle.as_os_str()),
            ("--tag", std::ffi::OsStr::new(subject.release_tag())),
            ("--commit", std::ffi::OsStr::new(subject.source_commit())),
            ("--sha256", std::ffi::OsStr::new(&digest)),
        ] {
            args.extend([option.into(), value.to_owned()]);
        }
        let before = kitrove_testkit::FilesystemSnapshot::capture(fixture.root.path()).unwrap();
        let error = crate::command::run(args).unwrap_err();
        assert!(!error.contains(fixture.root.path().to_str().unwrap()));
        assert_eq!(
            kitrove_testkit::FilesystemSnapshot::capture(fixture.root.path()).unwrap(),
            before
        );
    }
}

#[test]
fn selection_handoff_revalidates_inputs_before_returning_bytes() {
    let fixture = Fixture::new();
    let name = fixture.archive.file_name().unwrap().to_str().unwrap();
    let result = fixture.request().with_inputs(
        name,
        kitrove_release_provenance::ATTESTATION_COLLECTION_MAX_BYTES,
        |_, bundle| {
            let selected = bundle.to_vec();
            fs::write(&fixture.bundle, b"substituted after selection").unwrap();
            Ok(selected)
        },
    );
    assert_eq!(result, Err(ReleaseIntakeError::UnsafeInput));
    assert_eq!(
        fs::read(&fixture.bundle).unwrap(),
        b"substituted after selection"
    );
}

#[test]
fn local_intake_preserves_inputs_and_returns_only_captured_material() {
    let fixture = Fixture::new();
    let material = fixture
        .request()
        .authenticate_with(synthetic_verify)
        .unwrap();
    assert_eq!(material.archive_bytes(), fixture.material.archive_bytes());
    assert_eq!(material.bundle_bytes(), fixture.material.bundle_bytes());
    for path in [&fixture.archive, &fixture.bundle] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o644
        );
    }
    assert_eq!(fs::read_dir(fixture.root.path()).unwrap().count(), 2);
    fs::write(&fixture.archive, b"later archive").unwrap();
    fs::write(&fixture.bundle, b"later bundle").unwrap();
    assert_eq!(material.archive_bytes(), fixture.material.archive_bytes());
    assert_eq!(material.bundle_bytes(), fixture.material.bundle_bytes());
}

#[test]
fn local_intake_never_treats_a_checksum_as_provenance() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.request().authenticate().err(),
        Some(ReleaseIntakeError::VerificationFailed)
    );
    let mut request = fixture.request();
    request.archive_sha256 = [0; 32];
    assert_eq!(
        request
            .authenticate_with(|_, _, _, _| panic!("checksum mismatch reached verifier"))
            .err(),
        Some(ReleaseIntakeError::VerificationFailed)
    );
    let expected =
        ExpectedReleaseIdentity::new("v9.9.9", fixture.expected.source_commit()).unwrap();
    let mut request = fixture.request();
    request.expected = &expected;
    assert!(request.authenticate_with(synthetic_verify).is_err());
}

#[test]
fn every_public_command_refuses_synthetic_provenance_without_mutation() {
    use std::ffi::OsString;
    let fixture = Fixture::new();
    let subject = fixture.material.executable().subject();
    let digest = crate::record::encode_hex(&subject.archive_sha256());
    for command in [
        "preflight-install",
        "install",
        "recover-install",
        "retire-install",
        "history-status",
        "history-sync",
    ] {
        let mut args = vec![OsString::from(command)];
        for (option, value) in [
            ("--archive", fixture.archive.as_os_str()),
            ("--bundle", fixture.bundle.as_os_str()),
            ("--destination", fixture.root.path().as_os_str()),
            ("--tag", std::ffi::OsStr::new(subject.release_tag())),
            ("--commit", std::ffi::OsStr::new(subject.source_commit())),
            ("--sha256", std::ffi::OsStr::new(&digest)),
        ] {
            args.extend([OsString::from(option), value.to_owned()]);
        }
        if command != "history-status" {
            args.push("--no-state-roots".into());
        }
        if command.starts_with("history-") {
            args.extend(["--operation", "0123456789abcdef0123456789abcdef"].map(OsString::from));
        }
        let before = kitrove_testkit::FilesystemSnapshot::capture(fixture.root.path()).unwrap();
        let error = crate::command::run(args).unwrap_err();
        assert!(
            error.contains("authentication policy"),
            "{command}: {error}"
        );
        assert_eq!(
            kitrove_testkit::FilesystemSnapshot::capture(fixture.root.path()).unwrap(),
            before
        );
    }
}

#[test]
fn local_intake_rejects_unsafe_leaves_without_repair() {
    for change in [
        "writable",
        "executable",
        "symlink",
        "hardlink",
        "directory",
        "empty",
        "name",
    ] {
        let fixture = Fixture::new();
        let saved = fixture.root.path().join("retained");
        match change {
            "writable" => {
                fs::set_permissions(&fixture.archive, fs::Permissions::from_mode(0o666)).unwrap()
            }
            "executable" => {
                fs::set_permissions(&fixture.archive, fs::Permissions::from_mode(0o755)).unwrap()
            }
            "symlink" | "directory" | "name" => {
                fs::rename(&fixture.archive, &saved).unwrap();
                if change == "symlink" {
                    symlink(&saved, &fixture.archive).unwrap();
                }
                if change == "directory" {
                    fs::create_dir(&fixture.archive).unwrap();
                }
            }
            "hardlink" => fs::hard_link(&fixture.archive, &saved).unwrap(),
            "empty" => fs::write(&fixture.archive, b"").unwrap(),
            _ => unreachable!(),
        }
        let mut request = fixture.request();
        if change == "name" {
            request.archive = &saved;
        }
        assert_eq!(
            request
                .authenticate_with(|_, _, _, _| panic!("unsafe input reached verifier"))
                .err(),
            Some(ReleaseIntakeError::UnsafeInput)
        );
        if saved.is_file() {
            assert_eq!(fs::read(&saved).unwrap(), fixture.material.archive_bytes());
        }
        if change == "writable" {
            assert_eq!(
                fs::metadata(&fixture.archive).unwrap().permissions().mode() & 0o7777,
                0o666
            );
        }
    }
}

#[test]
fn retained_artifact_enforces_exact_bound_and_parent_authority() {
    let fixture = Fixture::new();
    let size = fixture.material.archive_bytes().len() as u64;
    assert!(RetainedArtifact::open(&fixture.archive, size).is_ok());
    assert!(RetainedArtifact::open(&fixture.archive, size - 1).is_err());
    let alias = fixture.root.path().join("alias");
    symlink(fixture.root.path(), &alias).unwrap();
    assert!(
        RetainedArtifact::open(&alias.join(fixture.archive.file_name().unwrap()), size).is_err()
    );
    fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(RetainedArtifact::open(&fixture.archive, size).is_err());
    assert_eq!(
        fs::metadata(fixture.root.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o777
    );
    // Restore only this test-owned directory so its ordinary fixture cleanup can run.
    fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn changes_during_authentication_preserve_all_evidence_and_refuse_authority() {
    for change in ["archive", "bundle", "replacement", "mode", "parent"] {
        let fixture = Fixture::new();
        let saved = fixture.root.path().join("retained");
        let result = fixture
            .request()
            .authenticate_with(|spec, archive, bundle, expected| {
                let material = synthetic_verify(spec, archive, bundle, expected)?;
                match change {
                    "archive" => fs::write(&fixture.archive, vec![b'x'; archive.len()]).unwrap(),
                    "bundle" => fs::write(&fixture.bundle, vec![b'x'; bundle.len()]).unwrap(),
                    "replacement" => {
                        fs::rename(&fixture.archive, &saved).unwrap();
                        fs::write(&fixture.archive, archive).unwrap();
                        fs::set_permissions(&fixture.archive, fs::Permissions::from_mode(0o644))
                            .unwrap();
                    }
                    "mode" => {
                        fs::set_permissions(&fixture.bundle, fs::Permissions::from_mode(0o666))
                            .unwrap()
                    }
                    "parent" => {
                        fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o777))
                            .unwrap()
                    }
                    _ => unreachable!(),
                }
                Ok(material)
            });
        assert_eq!(result.err(), Some(ReleaseIntakeError::UnsafeInput));
        if change == "replacement" {
            assert_eq!(fs::read(&saved).unwrap(), fixture.material.archive_bytes());
        }
        if change == "archive" {
            assert_eq!(
                fs::read(&fixture.archive).unwrap(),
                vec![b'x'; fixture.material.archive_bytes().len()]
            );
        }
        if change == "bundle" {
            assert_eq!(
                fs::read(&fixture.bundle).unwrap(),
                vec![b'x'; fixture.material.bundle_bytes().len()]
            );
        }
        if change == "parent" {
            fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}
