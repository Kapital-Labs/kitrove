use super::*;

#[test]
fn windows_payload_is_private_exact_and_retained_after_drop() {
    let root = crate::windows_test_support::destination();
    let retained = stage(root.path(), b"data only", |_| Ok(())).unwrap();
    retained.revalidate(b"data only").unwrap();
    kitrove_windows_security::inspect_private_directory(&retained.directory).unwrap();
    kitrove_windows_security::inspect_private_single_link_file(&retained.file).unwrap();
    let payload = root.path().join(DIRECTORY).join(PAYLOAD);
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&payload)
            .is_err()
    );
    assert!(stage(root.path(), b"other", |_| Ok(())).is_err());
    drop(retained);
    assert_eq!(std::fs::read(payload).unwrap(), b"data only");
}

#[test]
fn windows_payload_preserves_partial_output_at_every_boundary() {
    for failed in 0..3 {
        let root = crate::windows_test_support::destination();
        let result = stage(root.path(), b"data", |boundary| {
            if boundary as usize == failed {
                Err(InstallerStageError::WriteFailed)
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
        assert!(root.path().join(DIRECTORY).is_dir());
        if failed > 0 {
            assert_eq!(
                std::fs::read(root.path().join(DIRECTORY).join(PAYLOAD)).unwrap(),
                b"data"
            );
        }
    }
}

#[test]
fn windows_payload_refuses_competing_private_leaf_without_overwrite() {
    let root = crate::windows_test_support::destination();
    let payload = root.path().join(DIRECTORY).join(PAYLOAD);
    let result = stage(root.path(), b"candidate", |boundary| {
        if matches!(boundary, Boundary::DirectoryCreated) {
            kitrove_windows_security::write_current_user_owned_file_for_tests(
                &payload,
                b"unmanaged",
            )
            .unwrap();
        }
        Ok(())
    });
    assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
    assert_eq!(std::fs::read(payload).unwrap(), b"unmanaged");
}
