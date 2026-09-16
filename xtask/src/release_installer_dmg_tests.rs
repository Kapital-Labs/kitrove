use super::*;

fn arguments(target: &str) -> Vec<OsString> {
    vec![
        "missing.tar.xz".into(),
        target.into(),
        "v0.0.0".into(),
        "missing.json".into(),
    ]
}

#[test]
fn host_target_product_and_argument_count_fail_before_opening_inputs() {
    assert!(
        prepare(Vec::new(), "macos")
            .err()
            .unwrap()
            .contains("expected 4")
    );
    for host in ["windows", "linux"] {
        assert!(
            prepare(arguments("aarch64-apple-darwin"), host)
                .err()
                .unwrap()
                .contains("requires a reviewed Mac target")
        );
    }
    for target in [
        "x86_64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu",
        "unknown",
    ] {
        assert!(
            prepare(arguments(target), "macos")
                .err()
                .unwrap()
                .contains("requires a reviewed Mac target")
        );
    }
    assert!(
        prepare(arguments("aarch64-apple-darwin"), "macos")
            .err()
            .unwrap()
            .contains("exact installer archive name")
    );
    let mut application = arguments("aarch64-apple-darwin");
    application[0] = "kitrove-cli-aarch64-apple-darwin.tar.xz".into();
    assert!(
        prepare(application, "macos")
            .err()
            .unwrap()
            .contains("exact installer archive name")
    );
}

#[test]
fn payload_writer_never_overwrites_an_occupied_leaf() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("occupied");
    fs::write(&path, b"preserve").unwrap();
    assert!(write_leaf(&path, b"replacement", false).is_err());
    assert_eq!(fs::read(path).unwrap(), b"preserve");
}

#[cfg(unix)]
fn fixture(target: &str) -> (TempDir, Vec<OsString>) {
    use super::super::{
        installer_tests::installer_fixture,
        tests::{dist_manifest, prepare_fixture},
    };
    let directory = tempfile::tempdir().unwrap();
    let spec = installer_archive_for_target(target).unwrap();
    let bytes = prepare_fixture(spec.archive_name(), target, &installer_fixture(spec));
    let archive = directory.path().join(spec.archive_name());
    let manifest = directory.path().join("dist-manifest.json");
    fs::write(&archive, &bytes).unwrap();
    fs::write(
        checksum_path(&archive),
        render_checksum(&archive, &bytes).unwrap(),
    )
    .unwrap();
    dist_manifest(&manifest, &archive, target, &bytes);
    let args = vec![
        archive.into_os_string(),
        target.into(),
        "v0.0.0".into(),
        manifest.into_os_string(),
    ];
    (directory, args)
}

#[cfg(unix)]
#[test]
fn both_mac_payloads_have_exact_private_inventory_and_unchanged_source() {
    use std::os::unix::fs::PermissionsExt as _;
    for target in ["aarch64-apple-darwin", "x86_64-apple-darwin"] {
        let (_source, args) = fixture(target);
        let archive = PathBuf::from(&args[0]);
        let before = fs::read(&archive).unwrap();
        let checksum_before = fs::read(checksum_path(&archive)).unwrap();
        let manifest_before = fs::read(Path::new(&args[3])).unwrap();
        let payload = prepare(args.clone(), "macos").unwrap();
        let root = payload.directory.path();
        assert_eq!(
            fs::metadata(root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let spec = installer_archive_for_target(target).unwrap();
        let mut names = fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        let mut expected = vec![
            OsString::from("kitrove-installer"),
            spec.archive_name().into(),
            format!("{}.sha256", spec.archive_name()).into(),
        ];
        expected.sort();
        assert_eq!(names, expected);
        assert_eq!(
            fs::read(root.join("kitrove-installer")).unwrap(),
            b"installer bytes"
        );
        assert_eq!(fs::read(root.join(spec.archive_name())).unwrap(), before);
        for name in names {
            let mode = fs::metadata(root.join(&name)).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                if name == "kitrove-installer" {
                    0o700
                } else {
                    0o600
                }
            );
        }
        assert_eq!(fs::read(&archive).unwrap(), before);
        assert_eq!(fs::read(checksum_path(&archive)).unwrap(), checksum_before);
        assert_eq!(fs::read(Path::new(&args[3])).unwrap(), manifest_before);
        let owned = root.to_owned();
        drop(payload);
        assert!(!owned.exists());
    }
}

#[cfg(unix)]
#[test]
fn corrupt_or_redirected_inputs_and_wrong_version_are_refused_without_source_writes() {
    for selected in 0..4 {
        let (_source, mut args) = fixture("aarch64-apple-darwin");
        let archive = PathBuf::from(&args[0]);
        if selected == 3 {
            args[2] = "v1.0.0".into();
        } else {
            let path = match selected {
                0 => archive.clone(),
                1 => checksum_path(&archive),
                _ => PathBuf::from(&args[3]),
            };
            fs::write(path, b"invalid").unwrap();
        }
        let before = fs::read(&archive).unwrap();
        assert!(prepare(args, "macos").is_err());
        assert_eq!(fs::read(archive).unwrap(), before);
    }
    let (source, args) = fixture("aarch64-apple-darwin");
    let archive = PathBuf::from(&args[0]);
    let retained = source.path().join("retained");
    fs::rename(&archive, &retained).unwrap();
    std::os::unix::fs::symlink(&retained, &archive).unwrap();
    assert!(prepare(args, "macos").is_err());
    assert!(fs::symlink_metadata(archive).unwrap().is_symlink());
    assert!(retained.is_file());
}
