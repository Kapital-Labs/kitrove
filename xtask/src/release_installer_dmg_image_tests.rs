#![cfg(unix)]
use super::*;

fn payload() -> super::super::Payload {
    let (_source, args) = super::super::tests::fixture("aarch64-apple-darwin");
    super::super::prepare(args, "macos").unwrap()
}

#[test]
fn every_native_stage_failure_stops_before_checksum_authority() {
    for failure in [
        Step::VerifyInstaller,
        Step::Create,
        Step::Sign,
        Step::VerifyImage,
        Step::VerifyPayload,
    ] {
        let mut payload = payload();
        let output = private_directory("image-test-").unwrap();
        let image = output.path().join(&payload.image_name);
        let mut visited = Vec::new();
        let result = build_with(&mut payload, &image, |step, _, image| {
            visited.push(step);
            if step == failure {
                return Err("synthetic native failure".into());
            }
            if step == Step::Create {
                write_leaf(image, b"synthetic image", false)?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(visited.last(), Some(&failure));
        assert!(!super::super::super::checksum_path(&image).exists());
        payload.revalidate().unwrap();
    }
}

#[test]
fn final_checksum_binds_post_stapling_bytes_and_late_image_changes_are_refused() {
    for tamper in [false, true] {
        let mut payload = payload();
        let output = private_directory("image-test-").unwrap();
        let image = output.path().join(&payload.image_name);
        let result = build_with(&mut payload, &image, |step, _, image| {
            match step {
                Step::Create => write_leaf(image, b"unsigned", false)?,
                Step::Sign => fs::write(image, b"signed and stapled").unwrap(),
                Step::VerifyPayload if tamper => fs::write(image, b"late substitution").unwrap(),
                _ => (),
            }
            Ok(())
        });
        let checksum = super::super::super::checksum_path(&image);
        if tamper {
            assert!(result.is_err());
            assert!(!checksum.exists());
        } else {
            result.unwrap();
            assert_eq!(
                fs::read_to_string(checksum).unwrap(),
                render_checksum(&image, b"signed and stapled").unwrap()
            );
        }
    }
}

#[test]
fn mounted_inventory_bytes_and_symlinks_are_checked_without_execution() {
    let mut payload = payload();
    let mount = private_directory("mount-test-").unwrap();
    for expected in &payload.files {
        write_leaf(&mount.path().join(&expected.leaf), &expected.bytes, false).unwrap();
    }
    verify_contents(&mut payload, mount.path()).unwrap();
    fs::write(mount.path().join("extra"), b"unexpected").unwrap();
    assert!(verify_contents(&mut payload, mount.path()).is_err());
    fs::remove_file(mount.path().join("extra")).unwrap();
    let leaf = mount.path().join("kitrove-installer");
    fs::write(&leaf, b"tampered").unwrap();
    assert!(verify_contents(&mut payload, mount.path()).is_err());
    fs::remove_file(&leaf).unwrap();
    std::os::unix::fs::symlink(payload.directory.path().join("kitrove-installer"), &leaf).unwrap();
    assert!(verify_contents(&mut payload, mount.path()).is_err());
}

#[test]
fn changed_payload_is_refused_before_any_native_tool() {
    let mut payload = payload();
    fs::write(payload.directory.path().join("unexpected"), b"extra").unwrap();
    let output = private_directory("image-test-").unwrap();
    let image = output.path().join(&payload.image_name);
    assert!(
        build_with(&mut payload, &image, |_, _, _| panic!(
            "must not invoke native tools"
        ))
        .is_err()
    );
}

#[test]
fn uncertain_detach_preserves_mountpoint_and_original_failure() {
    let mount = private_directory("mount-test-").unwrap();
    fs::write(mount.path().join("preserve"), b"evidence").unwrap();
    let error = finish_mount(
        mount.path(),
        Err("payload mismatch".into()),
        Err("detach failed".into()),
    )
    .unwrap_err();
    assert!(error.contains("payload mismatch"));
    assert!(error.contains("detach could not be confirmed"));
    assert_eq!(
        fs::read(mount.path().join("preserve")).unwrap(),
        b"evidence"
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "operator-only native image creation and mount; no signing or execution"]
fn native_unsigned_image_round_trip_preserves_exact_payload() {
    let mut payload = payload();
    let output = private_directory("image-native-test-").unwrap();
    let image = output.path().join(&payload.image_name);
    native_step(Step::Create, &mut payload, &image).unwrap();
    native_step(Step::VerifyImage, &mut payload, &image).unwrap();
    native_step(Step::VerifyPayload, &mut payload, &image).unwrap();
    payload.revalidate().unwrap();
}
