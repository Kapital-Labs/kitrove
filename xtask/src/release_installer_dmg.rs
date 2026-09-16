//! Operator-only DMG preparation; product binaries are never executed.
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use kitrove_release_policy::{
    InstallerContainerSpec, extract_installer_release, installer_container_for_target,
};
use tempfile::TempDir;

use super::{
    MAX_DIST_MANIFEST_BYTES, ReleaseArchiveSpec, checksum_path, exact_arguments, parse_release_tag,
    read_bounded_archive, read_bounded_file, render_checksum, sha256_hex, utf8_argument,
    validate_checksum_bytes, validate_dist_manifest,
};

/// A retained private payload, not a DMG or an authenticated public download.
struct Payload {
    directory: TempDir,
    files: Vec<super::RetainedFile>,
    container: InstallerContainerSpec,
}

#[path = "release_installer_dmg_image.rs"]
mod image;

pub(crate) fn prepare_image(arguments: Vec<OsString>) -> Result<(), String> {
    let payload = prepare(arguments, std::env::consts::OS)?;
    image::prepare(payload)
}

impl Payload {
    fn revalidate(&mut self) -> Result<(), String> {
        let names = inventory(self.directory.path())?;
        if names != self.files.iter().map(|file| file.leaf.clone()).collect() {
            return Err("DMG payload inventory changed".into());
        }
        for file in &mut self.files {
            file.revalidate()?;
        }
        Ok(())
    }
}

fn inventory(path: &Path) -> Result<std::collections::BTreeSet<OsString>, String> {
    // Three payload leaves are allowed; a fourth is already enough to refuse.
    fs::read_dir(path)
        .map_err(|_| "cannot inspect DMG payload inventory".to_owned())?
        .take(4)
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<_, _>>()
        .map_err(|_| "cannot inspect DMG payload inventory".to_owned())
}

pub(crate) fn stage(arguments: Vec<OsString>) -> Result<(), String> {
    let payload = prepare(arguments, std::env::consts::OS)?;
    let path = payload.directory.keep();
    println!(
        "staged installer DMG payload (not signed or releasable): {}",
        path.display()
    );
    Ok(())
}

fn prepare(arguments: Vec<OsString>, host: &str) -> Result<Payload, String> {
    let [archive, target, tag, manifest] = exact_arguments::<4>(arguments)?;
    let target = utf8_argument(&target, "target")?;
    if host != "macos" {
        return Err("installer DMG staging requires a reviewed Mac target on macOS".into());
    }
    let container = installer_container_for_target(&target)
        .map_err(|_| "installer DMG staging requires a reviewed Mac target on macOS".to_owned())?;
    let version = parse_release_tag(&tag)?;
    let spec = container.installer_archive();
    let archive_path = PathBuf::from(archive);
    if archive_path.file_name().and_then(|name| name.to_str()) != Some(spec.archive_name()) {
        return Err("installer DMG staging requires the exact installer archive name".into());
    }
    let mut archive = read_bounded_archive(&archive_path, false)?;
    let mut checksum = read_bounded_file(
        &checksum_path(&archive_path),
        4096,
        "installer checksum",
        false,
    )?;
    let mut manifest = read_bounded_file(
        Path::new(&manifest),
        MAX_DIST_MANIFEST_BYTES,
        "cargo-dist manifest",
        false,
    )?;
    validate_checksum_bytes(&archive_path, &archive.bytes, &checksum.bytes)?;
    validate_dist_manifest(
        &manifest.bytes,
        ReleaseArchiveSpec::Installer(spec),
        &target,
        &sha256_hex(&archive.bytes),
    )?;
    let inspected = extract_installer_release(spec, &archive.bytes)
        .map_err(|error| format!("installer DMG archive refused: {error}"))?;
    inspected
        .validate_manifest(&version)
        .map_err(|error| format!("installer DMG manifest refused: {error}"))?;
    archive.revalidate()?;
    checksum.revalidate()?;
    manifest.revalidate()?;

    // No caller-selected output can overwrite a prior artifact. Dropping an
    // incomplete payload removes only this newly owned temporary directory.
    let directory = private_directory("kitrove-dmg-payload-")?;
    let canonical_checksum = render_checksum(&archive_path, &archive.bytes)?;
    let leaves = [
        (
            spec.executable_name().to_owned(),
            inspected.executable_bytes(),
            true,
        ),
        (
            spec.archive_name().to_owned(),
            archive.bytes.as_slice(),
            false,
        ),
        (
            format!("{}.sha256", spec.archive_name()),
            canonical_checksum.as_bytes(),
            false,
        ),
    ];
    for (name, bytes, executable) in &leaves {
        write_leaf(&directory.path().join(name), bytes, *executable)?;
    }
    let mut files = Vec::new();
    for (name, bytes, _) in &leaves {
        let mut retained = read_bounded_file(
            &directory.path().join(name),
            bytes.len() as u64,
            "DMG payload",
            false,
        )?;
        if retained.bytes != *bytes {
            return Err("installer DMG payload changed".into());
        }
        retained.revalidate()?;
        files.push(retained);
    }
    archive.revalidate()?;
    checksum.revalidate()?;
    manifest.revalidate()?;
    fs::File::open(directory.path())
        .and_then(|file| file.sync_all())
        .map_err(|_| "cannot synchronize installer DMG payload directory".to_owned())?;
    Ok(Payload {
        directory,
        files,
        container,
    })
}

fn private_directory(prefix: &str) -> Result<TempDir, String> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder
        .tempdir()
        .map_err(|_| "cannot create private installer DMG directory".to_owned())
}

fn write_leaf(path: &Path, bytes: &[u8], executable: bool) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if executable { 0o700 } else { 0o600 });
    }
    #[cfg(not(unix))]
    let _ = executable;
    let mut file = options
        .open(path)
        .map_err(|_| "cannot create installer DMG payload leaf".to_owned())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot synchronize installer DMG payload leaf".to_owned())
}

#[cfg(test)]
#[path = "release_installer_dmg_tests.rs"]
mod tests;
