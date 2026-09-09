use super::*;
use crate::{
    APPLICATION_ARCHIVES, APPLICATION_RELEASE_MANIFEST_MAX_BYTES,
    APPLICATION_RELEASE_MANIFEST_NAME, BINARY_COMPANIONS, parse_installer_manifest,
    render_installer_manifest,
};
use semver::Version;
use sha2::{Digest as _, Sha256};
use std::io::{Cursor, Write as _};

#[test]
fn installer_catalog_matches_canonical_publication_policy() {
    let policy: serde_json::Value =
        serde_json::from_str(include_str!("../../../release/release-policy.json")).unwrap();
    let expected = INSTALLER_ARCHIVES.map(|spec| {
        serde_json::json!({
            "target": spec.target(),
            "archive": spec.archive_name(),
            "root": spec.archive_root(),
            "executable": spec.executable_name(),
            "format": match spec.format() {
                ArchiveFormat::TarXz => "tar.xz",
                ArchiveFormat::Zip => "zip",
            },
        })
    });
    assert_eq!(policy["installer_archives"], serde_json::json!(expected));
}

fn archive(spec: InstallerArchiveSpec, executable: &[u8], manifest: &[u8]) -> Vec<u8> {
    let entries = BINARY_COMPANIONS
        .into_iter()
        .map(|name| {
            (
                name,
                if name == APPLICATION_RELEASE_MANIFEST_NAME {
                    manifest
                } else {
                    b"companion".as_slice()
                },
                0o644,
            )
        })
        .chain(std::iter::once((spec.executable_name(), executable, 0o755)));
    if let Some(root) = spec.archive_root() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut append = |name: &str, bytes: &[u8], mode: u32, kind: tar::EntryType| {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_entry_type(kind);
            header.set_mode(mode);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            tar.append(&header, bytes).unwrap();
        };
        append(&format!("{root}/"), &[], 0o755, tar::EntryType::Directory);
        for (name, bytes, mode) in entries {
            append(
                &format!("{root}/{name}"),
                bytes,
                mode,
                tar::EntryType::Regular,
            );
        }
        let bytes = tar.into_inner().unwrap();
        let mut xz =
            lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
        xz.write_all(&bytes).unwrap();
        xz.finish().unwrap()
    } else {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes, mode) in entries {
            zip.start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored)
                    .unix_permissions(mode),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }
}

#[test]
fn installer_catalog_and_archives_are_exact_and_separate_from_application_inputs() {
    let version = Version::new(1, 2, 3);
    let executable = b"installer fixture";
    for (index, spec) in INSTALLER_ARCHIVES.into_iter().enumerate() {
        assert_eq!(installer_archive_for_target(spec.target()).unwrap(), spec);
        assert_eq!(spec.target(), APPLICATION_ARCHIVES[index].target());
        assert!(
            spec.archive_name()
                .starts_with(&format!("kitrove-installer-{}.", spec.target()))
        );
        if let Some(root) = spec.archive_root() {
            assert_eq!(root, format!("kitrove-installer-{}", spec.target()));
        }
        let manifest =
            render_installer_manifest(spec, &version, Sha256::digest(executable).into()).unwrap();
        let bytes = archive(spec, executable, &manifest);
        let inspected = extract_installer_release(spec, &bytes).unwrap();
        assert_eq!(inspected.spec(), spec);
        assert_eq!(
            inspected.archive_sha256(),
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        assert_eq!(inspected.executable_bytes(), executable);
        assert_eq!(inspected.manifest_bytes(), manifest);
        assert_eq!(
            inspected.validate_manifest(&version).unwrap().target(),
            spec.target()
        );
        for application in APPLICATION_ARCHIVES {
            assert!(crate::extract_application_release(application, &bytes).is_err());
        }
        for other in INSTALLER_ARCHIVES {
            if other != spec {
                assert!(extract_installer_release(other, &bytes).is_err());
            }
        }
        assert_eq!(
            inspected.validate_manifest(&Version::new(9, 9, 9)),
            Err(ReleaseManifestError::ReleaseVersionMismatch)
        );
        let changed = archive(spec, b"changed installer", &manifest);
        assert_eq!(
            extract_installer_release(spec, &changed)
                .unwrap()
                .validate_manifest(&version),
            Err(ReleaseManifestError::ExecutableDigestMismatch)
        );
        assert!(crate::parse_release_manifest(APPLICATION_ARCHIVES[index], &manifest).is_err());
        let application_manifest =
            crate::render_release_manifest(APPLICATION_ARCHIVES[index], &version, [0; 32], &[])
                .unwrap();
        assert!(parse_installer_manifest(spec, &application_manifest).is_err());
    }
    assert!(installer_archive_for_target("unknown").is_err());
}

#[test]
fn installer_manifests_reject_wrong_kind_schema_target_name_and_malformed_claims() {
    let spec = INSTALLER_ARCHIVES[0];
    let bytes = render_installer_manifest(spec, &Version::new(1, 2, 3), [0xab; 32]).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for (field, replacement) in [
        ("schema", serde_json::json!(2)),
        ("artifact_kind", serde_json::json!("application")),
        ("target", serde_json::json!("unknown")),
        ("executable_name", serde_json::json!("kitrove")),
        ("release_version", serde_json::json!("v1.2.3")),
        ("executable_sha256", serde_json::json!("AB".repeat(32))),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        assert!(
            parse_installer_manifest(spec, &serde_json::to_vec(&changed).unwrap()).is_err(),
            "accepted {field}"
        );
    }
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        parse_installer_manifest(
            spec,
            text.replace("\"schema\":1", "\"schema\":1,\"schema\":1")
                .as_bytes()
        )
        .is_err()
    );
    assert_eq!(
        parse_installer_manifest(
            spec,
            &vec![b' '; APPLICATION_RELEASE_MANIFEST_MAX_BYTES + 1]
        ),
        Err(ReleaseManifestError::TooLarge)
    );
}
