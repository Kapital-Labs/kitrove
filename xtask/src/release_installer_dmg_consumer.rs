//! Reviewed-source consumer: authenticate both artifacts before any native parsing.
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use kitrove_release_policy::{extract_installer_release, installer_container_for_target};
use kitrove_release_provenance::{
    APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES, ExpectedReleaseIdentity,
    verify_installer_archive_attestation, verify_installer_container_attestation,
};

use super::super::{exact_arguments, read_bounded_archive, read_bounded_file, utf8_argument};
use super::{image, private_directory, render_checksum, stage_payload, write_leaf};

pub(crate) fn verify(arguments: Vec<OsString>) -> Result<(), String> {
    verify_on_host(arguments, std::env::consts::OS)
}

fn verify_on_host(arguments: Vec<OsString>, host: &str) -> Result<(), String> {
    verify_with_native(arguments, host, image::verify)
}

fn verify_with_native(
    arguments: Vec<OsString>,
    host: &str,
    native: impl FnOnce(&mut super::Payload, &Path) -> Result<(), String>,
) -> Result<(), String> {
    let [
        image_path,
        image_bundle,
        archive_path,
        archive_bundle,
        target,
        tag,
        commit,
    ] = exact_arguments::<7>(arguments)?;
    if host != "macos" {
        return Err("native installer image verification requires macOS".into());
    }
    let target = utf8_argument(&target, "target")?;
    let spec = installer_container_for_target(&target)
        .map_err(|_| "unsupported installer image target")?;
    let expected = ExpectedReleaseIdentity::new(
        &utf8_argument(&tag, "tag")?,
        &utf8_argument(&commit, "commit")?,
    )
    .map_err(|_| "invalid exact release identity")?;
    let image_path = PathBuf::from(image_path);
    let archive_path = PathBuf::from(archive_path);
    if image_path.file_name().and_then(|name| name.to_str()) != Some(spec.image_name())
        || archive_path.file_name().and_then(|name| name.to_str())
            != Some(spec.installer_archive().archive_name())
    {
        return Err("consumer requires exact image and installer archive names".into());
    }
    let mut source_image = read_bounded_archive(&image_path, false)?;
    let mut source_archive = read_bounded_archive(&archive_path, false)?;
    let mut image_bundle = read_bounded_file(
        Path::new(&image_bundle),
        APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES as u64,
        "image attestation",
        false,
    )?;
    let mut archive_bundle = read_bounded_file(
        Path::new(&archive_bundle),
        APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES as u64,
        "installer attestation",
        false,
    )?;

    let authenticated_image = verify_installer_container_attestation(
        spec,
        source_image.bytes.clone(),
        &expected,
        &image_bundle.bytes,
    )
    .map_err(|_| "image release provenance refused")?;
    let inspected = extract_installer_release(spec.installer_archive(), &source_archive.bytes)
        .map_err(|_| "installer archive refused")?;
    let authenticated_installer =
        verify_installer_archive_attestation(inspected, &expected, &archive_bundle.bytes)
            .map_err(|_| "installer release provenance refused")?;
    for input in [
        &mut source_image,
        &mut source_archive,
        &mut image_bundle,
        &mut archive_bundle,
    ] {
        input.revalidate()?;
    }

    // Only independently authenticated snapshots reach native tools. The image and
    // expected payload live in fresh private directories, never caller destinations.
    let mut payload = stage_payload(spec, &source_archive.bytes, authenticated_installer.bytes())?;
    let directory = private_directory("kitrove-consumer-image-")?;
    let image_path = directory.path().join(spec.image_name());
    write_leaf(&image_path, authenticated_image.bytes(), false)?;
    write_leaf(
        &super::super::checksum_path(&image_path),
        render_checksum(&image_path, authenticated_image.bytes())?.as_bytes(),
        false,
    )?;
    native(&mut payload, &image_path)?;
    for input in [
        &mut source_image,
        &mut source_archive,
        &mut image_bundle,
        &mut archive_bundle,
    ] {
        input.revalidate()?;
    }
    println!(
        "verified authenticated installer image and exact payload; detached, nothing installed or executed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<OsString> {
        [
            "kitrove-installer-aarch64-apple-darwin.dmg",
            "image.json",
            "kitrove-installer-aarch64-apple-darwin.tar.xz",
            "installer.json",
            "aarch64-apple-darwin",
            "v1.2.3",
            "0123456789abcdef0123456789abcdef01234567",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn consumer_rejects_host_identity_names_and_argument_count_before_io() {
        assert!(
            verify_on_host(arguments(), "windows")
                .unwrap_err()
                .contains("macOS")
        );
        assert!(verify_on_host(vec![], "macos").is_err());
        for (index, value) in [
            (0, "other.dmg"),
            (2, "kitrove.tar.xz"),
            (4, "x86_64-pc-windows-msvc"),
            (5, "main"),
            (6, "short"),
        ] {
            let mut args = arguments();
            args[index] = value.into();
            assert!(verify_on_host(args, "macos").is_err());
        }
    }

    #[test]
    fn invalid_provenance_never_reaches_native_tools_or_changes_inputs() {
        let directory = private_directory("kitrove-consumer-refusal-").unwrap();
        let mut args = arguments();
        for argument in args.iter_mut().take(4) {
            let path = directory.path().join(&*argument);
            write_leaf(&path, b"untrusted", false).unwrap();
            *argument = path.into_os_string();
        }
        let error = verify_with_native(args.clone(), "macos", |_, _| {
            panic!("untrusted input reached native verification")
        })
        .unwrap_err();
        assert_eq!(error, "image release provenance refused");
        for path in &args[..4] {
            assert_eq!(std::fs::read(path).unwrap(), b"untrusted");
        }
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 4);
    }
}
