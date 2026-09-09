use super::tests::{dist_manifest, prepare_fixture, prepare_fixture_with_signer};
use super::*;
use kitrove_release_policy::{INSTALLER_ARCHIVES, extract_installer_release};

fn installer_fixture(spec: kitrove_release_policy::InstallerArchiveSpec) -> Vec<u8> {
    let files = BINARY_COMPANIONS
        .into_iter()
        .map(|name| (name.to_owned(), b"placeholder".to_vec()))
        .chain(std::iter::once((
            spec.executable_name().to_owned(),
            b"installer bytes".to_vec(),
        )))
        .collect::<BTreeMap<_, _>>();
    if spec.format() == ArchiveFormat::TarXz {
        write_tar_archive(ReleaseArchiveSpec::Installer(spec), &files).unwrap()
    } else {
        let mut output = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in files {
            let mode = if name == spec.executable_name() {
                0o755
            } else {
                0o644
            };
            output
                .start_file(
                    name,
                    SimpleFileOptions::default()
                        .compression_method(CompressionMethod::Stored)
                        .unix_permissions(mode),
                )
                .unwrap();
            output.write_all(&bytes).unwrap();
        }
        output.finish().unwrap().into_inner()
    }
}

#[test]
fn signed_installer_bytes_are_preserved_without_application_authority() {
    for spec in INSTALLER_ARCHIVES {
        let bytes = installer_fixture(spec);
        let signed = prepare_fixture_with_signer(
            spec.archive_name(),
            spec.target(),
            &bytes,
            |_, name, original| {
                assert_eq!(name, spec.executable_name());
                assert_eq!(original, b"installer bytes");
                Ok(Some(b"synthetic signed installer".to_vec()))
            },
        );
        let release = extract_installer_release(spec, &signed).unwrap();
        release.validate_manifest(&Version::new(0, 0, 0)).unwrap();
        assert_eq!(release.executable_bytes(), b"synthetic signed installer");
    }
}

#[test]
fn prepares_and_verifies_each_installer_archive_with_exact_checksums() {
    for spec in INSTALLER_ARCHIVES {
        let original = installer_fixture(spec);
        let first = prepare_fixture(spec.archive_name(), spec.target(), &original);
        let second = prepare_fixture(spec.archive_name(), spec.target(), &original);
        assert_eq!(first, second);
        let extracted = extract_installer_release(spec, &first).unwrap();
        extracted.validate_manifest(&Version::new(0, 0, 0)).unwrap();
        assert_eq!(extracted.executable_bytes(), b"installer bytes");
        let fields: Value = serde_json::from_slice(extracted.manifest_bytes()).unwrap();
        assert_eq!(fields["artifact_kind"], "installer");
        assert!(fields.get("rollback_compatible_predecessors").is_none());
        assert!(fields.get("application_state_schema").is_none());
    }
}

#[test]
fn installer_preparation_does_not_read_application_compatibility_or_accept_aliases() {
    for spec in INSTALLER_ARCHIVES {
        let bytes = installer_fixture(spec);
        let resolved = ReleaseArchiveSpec::Installer(spec);
        let manifest = resolved
            .prepare_manifest(
                &bytes,
                &Version::new(1, 0, 0),
                Path::new("missing-application-compatibility.json"),
            )
            .unwrap();
        kitrove_release_policy::parse_installer_manifest(spec, &manifest).unwrap();
        for name in ["installer.zip", "kitrove.exe", "../unexpected.tar.xz"] {
            assert!(resolve_archive(Path::new(name), spec.target()).is_err());
        }
    }
}

#[test]
fn preparation_preserves_other_products_in_the_shared_build_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let target = "aarch64-apple-darwin";
    let application = kitrove_release_policy::application_archive_for_target(target).unwrap();
    let installer = kitrove_release_policy::installer_archive_for_target(target).unwrap();
    let application_bytes = include_bytes!(
        "../../crates/kitrove-release-policy/tests/fixtures/archive-conformance/valid_tar_xz/kitrove-cli-aarch64-apple-darwin.tar.xz"
    );
    let installer_bytes = installer_fixture(installer);
    let manifest = root.join("dist-manifest.json");
    let compatibility = root.join("compatibility.json");
    fs::write(
        &compatibility,
        br#"{"schema":1,"releases":[{"version":"0.0.0","rollback_compatible_predecessors":[]}]}"#,
    )
    .unwrap();
    let mut combined = serde_json::json!({"artifacts": {}});
    let inputs = [
        (application.archive_name(), application_bytes.as_slice()),
        (installer.archive_name(), installer_bytes.as_slice()),
    ];
    for (name, bytes) in inputs {
        let path = root.join(name);
        fs::write(&path, bytes).unwrap();
        fs::write(checksum_path(&path), render_checksum(&path, bytes).unwrap()).unwrap();
        dist_manifest(&manifest, &path, target, bytes);
        let single: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        combined["artifacts"][name] = single["artifacts"][name].clone();
    }
    fs::write(&manifest, serde_json::to_vec(&combined).unwrap()).unwrap();
    for (name, _) in inputs {
        let other_name = if name == application.archive_name() {
            installer.archive_name()
        } else {
            application.archive_name()
        };
        let before: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        prepare(vec![
            root.join(name).into_os_string(),
            target.into(),
            "v0.0.0".into(),
            compatibility.clone().into_os_string(),
            manifest.clone().into_os_string(),
        ])
        .unwrap();
        let after: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        assert_eq!(
            before["artifacts"][other_name],
            after["artifacts"][other_name]
        );
    }
    for (name, _) in inputs {
        verify_bundle(vec![
            root.join(name).into_os_string(),
            target.into(),
            "v0.0.0".into(),
            manifest.clone().into_os_string(),
        ])
        .unwrap();
    }
}
