//! Native image construction; no product execution or release publication.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::super::signing;
use super::{Payload, private_directory, read_bounded_file, render_checksum, write_leaf};

pub(super) fn prepare(mut payload: Payload, output: Option<PathBuf>) -> Result<(), String> {
    let directory = new_output_directory(output)?;
    let image = directory.join(payload.container.image_name());
    let result = build(&mut payload, &image);
    // Even an uncertain native-tool failure retains its output for diagnosis.
    // Never advertise a checksum until all verification and detach steps pass.
    match result {
        Ok(()) => {
            println!(
                "prepared signed and stapled DMG (not published): {}",
                directory.display()
            );
            Ok(())
        }
        Err(error) => Err(format!(
            "{error}; incomplete DMG output retained at {}",
            directory.display()
        )),
    }
}

fn new_output_directory(output: Option<PathBuf>) -> Result<PathBuf, String> {
    let Some(path) = output else {
        return Ok(private_directory("kitrove-dmg-image-")?.keep());
    };
    let parent = path.parent().ok_or("DMG output parent missing")?;
    if !path.is_absolute()
        || path.file_name().is_none()
        || fs::canonicalize(parent).map_err(|_| "cannot resolve DMG output parent")? != parent
    {
        return Err("DMG output requires an absolute path with a canonical existing parent".into());
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(&path)
        .map_err(|_| "cannot create fresh DMG output directory")?;
    Ok(path)
}

/// Reverify staged image bytes without signing credentials or product execution.
pub(super) fn verify(payload: &mut Payload, image: &Path) -> Result<(), String> {
    if image.file_name().and_then(|name| name.to_str()) != Some(payload.container.image_name()) {
        return Err("DMG verification requires the exact container name".into());
    }
    let mut retained = super::super::read_bounded_archive(image, false)?;
    let mut checksum = read_bounded_file(
        &super::super::checksum_path(image),
        4096,
        "DMG checksum",
        false,
    )?;
    super::validate_checksum_bytes(image, &retained.bytes, &checksum.bytes)?;
    native_step(Step::VerifyInstaller, payload, image)?;
    signing::verify_apple_container(image)?;
    for step in [Step::VerifyImage, Step::VerifyPayload] {
        native_step(step, payload, image)?;
        retained.revalidate()?;
    }
    checksum.revalidate()?;
    payload.revalidate()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    VerifyInstaller,
    Create,
    Sign,
    VerifyImage,
    VerifyPayload,
}

fn native_step(step: Step, payload: &mut Payload, image: &Path) -> Result<(), String> {
    match step {
        Step::VerifyInstaller => signing::verify_apple_signature(
            &payload.directory.path().join("kitrove-installer"),
            true,
        ),
        Step::Create => signing::run(
            Command::new("/usr/bin/hdiutil")
                .args([
                    "create",
                    "-format",
                    "UDZO",
                    "-fs",
                    "HFS+",
                    "-volname",
                    "Kitrove Installer",
                    "-srcfolder",
                ])
                .arg(payload.directory.path())
                .arg(image),
            "installer disk image creation",
        )
        .map(|_| ()),
        Step::Sign => signing::sign_apple_container(image, payload.container.target()),
        Step::VerifyImage => signing::run(
            Command::new("/usr/bin/hdiutil").arg("verify").arg(image),
            "disk image integrity verification",
        )
        .map(|_| ()),
        Step::VerifyPayload => verify_mounted_payload(payload, image),
    }
}

fn build(payload: &mut Payload, image: &Path) -> Result<(), String> {
    build_with(payload, image, native_step)
}

fn build_with(
    payload: &mut Payload,
    image: &Path,
    mut execute: impl FnMut(Step, &mut Payload, &Path) -> Result<(), String>,
) -> Result<(), String> {
    payload.revalidate()?;
    for step in [Step::VerifyInstaller, Step::Create, Step::Sign] {
        execute(step, payload, image)?;
        payload.revalidate()?;
    }
    let mut final_image = super::super::read_bounded_archive(image, false)?;
    for step in [Step::VerifyImage, Step::VerifyPayload] {
        execute(step, payload, image)?;
        final_image.revalidate()?;
    }
    payload.revalidate()?;
    final_image
        .file
        .sync_all()
        .map_err(|_| "cannot synchronize final DMG".to_owned())?;
    let checksum = super::super::checksum_path(image);
    write_leaf(
        &checksum,
        render_checksum(image, &final_image.bytes)?.as_bytes(),
        false,
    )?;
    final_image.revalidate()?;
    fs::File::open(image.parent().ok_or("image parent missing")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "cannot synchronize final DMG output".to_owned())
}

fn verify_mounted_payload(payload: &mut Payload, image: &Path) -> Result<(), String> {
    // Persist the empty mountpoint before attaching. An uncertain attach/detach
    // must never make TempDir recursively traverse a still-mounted filesystem.
    let mount = private_directory("kitrove-dmg-mount-")?.keep();
    let attached = signing::run(
        Command::new("/usr/bin/hdiutil")
            .args([
                "attach",
                "-readonly",
                "-nobrowse",
                "-noautoopen",
                "-mountpoint",
            ])
            .arg(&mount)
            .arg(image),
        "read-only DMG mount",
    );
    let checked = attached.and_then(|_| verify_contents(payload, &mount));
    let detached = signing::run(
        Command::new("/usr/bin/hdiutil").arg("detach").arg(&mount),
        "DMG detach",
    );
    finish_mount(&mount, checked, detached.map(|_| ()))
}

fn finish_mount(
    mount: &Path,
    checked: Result<(), String>,
    detached: Result<(), String>,
) -> Result<(), String> {
    if detached.is_err() {
        let cause = checked
            .err()
            .unwrap_or_else(|| "DMG payload checked".into());
        return Err(format!(
            "{cause}; DMG detach could not be confirmed; mountpoint retained at {}",
            mount.display()
        ));
    }
    fs::remove_dir(mount).map_err(|_| "cannot remove empty DMG mountpoint".to_owned())?;
    checked
}

fn verify_contents(payload: &mut Payload, mount: &Path) -> Result<(), String> {
    payload.revalidate()?;
    let names = super::inventory(mount)?;
    if names != payload.files.iter().map(|file| file.leaf.clone()).collect() {
        return Err("mounted DMG has an unexpected file inventory".into());
    }
    for expected in &payload.files {
        let mut observed = read_bounded_file(
            &mount.join(&expected.leaf),
            expected.bytes.len() as u64,
            "mounted DMG payload",
            false,
        )?;
        if observed.bytes != expected.bytes {
            return Err("mounted DMG payload differs from prepared installer".into());
        }
        observed.revalidate()?;
    }
    payload.revalidate()
}

#[cfg(test)]
#[path = "release_installer_dmg_image_tests.rs"]
mod tests;
