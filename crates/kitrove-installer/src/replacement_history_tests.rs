use super::*;
use crate::installation_history::replacement::ArchivedReplacement;
use crate::record::history::journal::HistoricalInstallOutcome;

#[test]
fn replacement_history_preserves_interrupted_commit_evidence_after_restoration() {
    use crate::install_phase::InstallPhase;
    use crate::upgrade_transaction::unix::UpgradeBoundary;
    for length in [0, 1, 31] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
        let operation = fixture
            .installer_state()
            .join(prepared.staged.record.operation_id());
        assert!(
            prepared
                .install_with_hooks(
                    |_, _| Ok(kitrove_model::ContentHash::digest(
                        fixture.candidate.bytes()
                    )),
                    |point| if point == UpgradeBoundary::PhaseWritten(InstallPhase::Committed) {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    },
                )
                .is_err()
        );
        let pending = operation.join("upgrade-committed.pending");
        let bytes = fs::read(&pending).unwrap();
        fs::write(&pending, &bytes[..length]).unwrap();
        assert!(
            fixture
                .recover_transaction(|_, _| Err(InstallerStageError::VerificationFailed))
                .is_err()
        );
        retire(&fixture, |_| Ok(())).unwrap();
        let archive = history(&fixture, &operation);
        let before = kitrove_testkit::FilesystemSnapshot::capture(&archive).unwrap();
        assert_eq!(
            inspect(&fixture, &operation).unwrap().outcome().unwrap(),
            HistoricalInstallOutcome::RolledBack
        );
        assert_eq!(
            crate::installation_history::replacement::synchronization::synchronize_test_archive(
                std::slice::from_ref(&fixture.state),
                || inspect(&fixture, &operation),
                |_| Ok(()),
            )
            .unwrap(),
            HistoricalInstallOutcome::RolledBack
        );
        assert_eq!(
            kitrove_testkit::FilesystemSnapshot::capture(&archive).unwrap(),
            before
        );
    }
}

#[test]
fn replacement_history_accepts_explicit_rollback_without_reinterpreting_direction() {
    let (candidate, material) = crate::test_support::replacement_releases_with_bytes(
        b"old executable",
        b"current executable",
        ReplacementDirection::Rollback,
    );
    let fixture = Fixture::with_releases(candidate, material);
    let prepared = PreparedReplacement::prepare_rollback(
        fixture.destination.path(),
        &fixture.candidate,
        &fixture.rollback,
        std::slice::from_ref(&fixture.state),
    )
    .unwrap();
    let operation = fixture
        .installer_state()
        .join(prepared.staged.record.operation_id());
    prepared
        .install_with_hooks(
            |_, _| {
                Ok(kitrove_model::ContentHash::digest(
                    fixture.candidate.bytes(),
                ))
            },
            |_| Ok(()),
        )
        .unwrap();
    PreparedReplacement::retire_completed_with(
        fixture.destination.path(),
        &fixture.candidate,
        std::slice::from_ref(&fixture.state),
        ReplacementDirection::Rollback,
        |staged| {
            RetainedRollbackKit::reopen_material_with_test_subject(
                staged,
                &fixture.expected_prior(),
                fixture.rollback.executable().subject().archive_sha256(),
            )
        },
        |_| Ok(()),
    )
    .unwrap();
    let retained = ArchivedReplacement::open_with_test_subject(
        fixture.destination.path(),
        operation.file_name().unwrap().to_str().unwrap(),
        &fixture.candidate,
        &fixture.expected_prior(),
        fixture.rollback.executable().subject().archive_sha256(),
        ReplacementDirection::Rollback,
    )
    .unwrap();
    assert_eq!(
        retained.outcome().unwrap(),
        HistoricalInstallOutcome::Committed
    );
    drop(retained);
    assert!(inspect(&fixture, &operation).is_err());
    assert_eq!(
        crate::installation_history::replacement::synchronization::synchronize_test_archive(
            std::slice::from_ref(&fixture.state),
            || ArchivedReplacement::open_with_test_subject(
                fixture.destination.path(),
                operation.file_name().unwrap().to_str().unwrap(),
                &fixture.candidate,
                &fixture.expected_prior(),
                fixture.rollback.executable().subject().archive_sha256(),
                ReplacementDirection::Rollback,
            ),
            |_| Ok(()),
        )
        .unwrap(),
        HistoricalInstallOutcome::Committed
    );
}

fn inspect(
    fixture: &Fixture,
    operation: &Path,
) -> Result<ArchivedReplacement, InstallerStageError> {
    ArchivedReplacement::open_with_test_subject(
        fixture.destination.path(),
        operation.file_name().unwrap().to_str().unwrap(),
        &fixture.candidate,
        &fixture.expected_prior(),
        fixture.rollback.executable().subject().archive_sha256(),
        ReplacementDirection::Upgrade,
    )
}

#[test]
fn replacement_history_sync_preserves_evidence_and_locks_only_current_state() {
    use crate::installation_history::replacement::synchronization::synchronize_test_archive as synchronize_archive;
    use crate::installation_history::synchronization::HistorySyncBoundary;
    for succeeds in [false, true] {
        let fixture = Fixture::new();
        let operation = finish(&fixture, succeeds);
        retire(&fixture, |_| Ok(())).unwrap();
        let current = Fixture::new();
        fs::rename(&fixture.state, fixture.state.with_extension("unavailable")).unwrap();
        let installed = fixture
            .destination
            .path()
            .join(fixture.candidate.subject().spec().executable_name());
        fs::write(&installed, b"later installation").unwrap();
        let before =
            kitrove_testkit::FilesystemSnapshot::capture(fixture.destination.path()).unwrap();
        for _ in 0..2 {
            let mut seen = Vec::new();
            let outcome = synchronize_archive(
                std::slice::from_ref(&current.state),
                || inspect(&fixture, &operation),
                |point| {
                    seen.push(point);
                    let authority =
                        kitrove_state_lifecycle::StateAuthority::open_existing(&current.state)
                            .unwrap();
                    assert!(authority.try_lock_shared().is_err());
                    assert!(inspect(&fixture, &operation).is_err());
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                seen,
                [
                    HistorySyncBoundary::Inspected,
                    HistorySyncBoundary::FilesSynced,
                    HistorySyncBoundary::OperationSynced,
                    HistorySyncBoundary::HistorySynced,
                    HistorySyncBoundary::SourceSynced
                ]
            );
            assert_eq!(
                outcome,
                if succeeds {
                    HistoricalInstallOutcome::Committed
                } else {
                    HistoricalInstallOutcome::RolledBack
                }
            );
            assert_eq!(
                kitrove_testkit::FilesystemSnapshot::capture(fixture.destination.path()).unwrap(),
                before
            );
        }
        assert!(
            crate::installation_history::replacement::synchronization::synchronize(
                fixture.destination.path(),
                operation.file_name().unwrap().to_str().unwrap(),
                &fixture.candidate,
                &fixture.expected_prior(),
                fixture.rollback.executable().subject().archive_sha256(),
                std::slice::from_ref(&current.state),
                ReplacementDirection::Upgrade,
            )
            .is_err(),
            "production entry must freshly reject synthetic attestation material"
        );
        assert_eq!(
            kitrove_testkit::FilesystemSnapshot::capture(fixture.destination.path()).unwrap(),
            before
        );
    }
}

#[test]
fn replacement_history_sync_interruptions_and_late_edits_preserve_retry_evidence() {
    use crate::installation_history::replacement::synchronization::synchronize_test_archive as synchronize_archive;
    use crate::installation_history::synchronization::HistorySyncBoundary::*;
    for point in [
        Inspected,
        FilesSynced,
        OperationSynced,
        HistorySynced,
        SourceSynced,
    ] {
        let fixture = Fixture::new();
        let operation = finish(&fixture, true);
        retire(&fixture, |_| Ok(())).unwrap();
        let archive = history(&fixture, &operation);
        let before = kitrove_testkit::FilesystemSnapshot::capture(&archive).unwrap();
        let roots = std::slice::from_ref(&fixture.state);
        assert!(
            synchronize_archive(
                roots,
                || inspect(&fixture, &operation),
                |observed| {
                    if observed == point {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        assert_eq!(
            kitrove_testkit::FilesystemSnapshot::capture(&archive).unwrap(),
            before
        );
        synchronize_archive(roots, || inspect(&fixture, &operation), |_| Ok(())).unwrap();
        let leaf = archive.join("rollback-kit/archive");
        let original = fs::read(&leaf).unwrap();
        let mut changed = original.clone();
        changed[0] ^= 1;
        assert!(
            synchronize_archive(
                roots,
                || inspect(&fixture, &operation),
                |observed| {
                    if observed == point {
                        fs::write(&leaf, &changed).unwrap();
                    }
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&leaf).unwrap(),
            changed,
            "uncertain bytes must not be repaired or deleted"
        );
        fs::write(&leaf, original).unwrap();
        synchronize_archive(roots, || inspect(&fixture, &operation), |_| Ok(())).unwrap();
        assert_eq!(
            kitrove_testkit::FilesystemSnapshot::capture(&archive).unwrap(),
            before
        );
    }
}

#[test]
fn replacement_history_is_read_only_and_independent_of_current_installation() {
    for succeeds in [false, true] {
        let fixture = Fixture::new();
        let operation = finish(&fixture, succeeds);
        retire(&fixture, |_| Ok(())).unwrap();
        fs::write(
            fixture
                .destination
                .path()
                .join(fixture.candidate.subject().spec().executable_name()),
            b"later installation",
        )
        .unwrap();
        fs::rename(&fixture.state, fixture.state.with_extension("unavailable")).unwrap();
        let before =
            kitrove_testkit::FilesystemSnapshot::capture(fixture.destination.path()).unwrap();
        let retained = inspect(&fixture, &operation).unwrap();
        assert_eq!(
            retained.outcome().unwrap(),
            if succeeds {
                HistoricalInstallOutcome::Committed
            } else {
                HistoricalInstallOutcome::RolledBack
            }
        );
        assert!(inspect(&fixture, &operation).is_err());
        drop(retained);
        inspect(&fixture, &operation).unwrap();
        assert_eq!(
            kitrove_testkit::FilesystemSnapshot::capture(fixture.destination.path()).unwrap(),
            before
        );
        // Synthetic fixture evidence must never pass the production verifier.
        assert!(
            ArchivedReplacement::open(
                fixture.destination.path(),
                operation.file_name().unwrap().to_str().unwrap(),
                &fixture.candidate,
                &fixture.expected_prior(),
                fixture.rollback.executable().subject().archive_sha256(),
                ReplacementDirection::Upgrade,
            )
            .is_err()
        );
    }
}

#[test]
fn replacement_history_refuses_changed_evidence_before_and_after_open() {
    for succeeds in [false, true] {
        let fixture = Fixture::new();
        let operation = finish(&fixture, succeeds);
        retire(&fixture, |_| Ok(())).unwrap();
        let archive = history(&fixture, &operation);
        let mut leaves = Vec::new();
        for entry in fs::read_dir(&archive).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                leaves.extend(
                    fs::read_dir(path)
                        .unwrap()
                        .map(|entry| entry.unwrap().path()),
                );
            } else {
                leaves.push(path);
            }
        }
        for leaf in leaves {
            let retained = inspect(&fixture, &operation).unwrap();
            let original = fs::read(&leaf).unwrap();
            let mut changed = original.clone();
            changed[0] ^= 1;
            fs::write(&leaf, &changed).unwrap();
            assert!(retained.outcome().is_err(), "accepted {}", leaf.display());
            drop(retained);
            let before = kitrove_testkit::FilesystemSnapshot::capture(&archive).unwrap();
            assert!(
                inspect(&fixture, &operation).is_err(),
                "accepted {}",
                leaf.display()
            );
            assert_eq!(
                kitrove_testkit::FilesystemSnapshot::capture(&archive).unwrap(),
                before
            );
            fs::write(&leaf, original).unwrap();
        }
        inspect(&fixture, &operation).unwrap();
    }
}

#[test]
fn replacement_history_requires_explicit_matching_release_and_exact_inventory() {
    let fixture = Fixture::new();
    let operation = finish(&fixture, true);
    retire(&fixture, |_| Ok(())).unwrap();
    let selected = operation.file_name().unwrap().to_str().unwrap();
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        assert!(
            ArchivedReplacement::open_with_test_subject(
                fixture.destination.path(),
                selected,
                &fixture.candidate,
                &fixture.expected_prior(),
                [0; 32],
                direction,
            )
            .is_err()
        );
    }
    assert!(
        ArchivedReplacement::open_with_test_subject(
            fixture.destination.path(),
            selected,
            &fixture.candidate,
            &fixture.expected_prior(),
            fixture.rollback.executable().subject().archive_sha256(),
            ReplacementDirection::Rollback,
        )
        .is_err()
    );
    let archive = history(&fixture, &operation);
    let retained = inspect(&fixture, &operation).unwrap();
    fs::write(archive.join("unknown"), b"preserve").unwrap();
    assert!(retained.outcome().is_err());
    drop(retained);
    let before = kitrove_testkit::FilesystemSnapshot::capture(&archive).unwrap();
    assert!(inspect(&fixture, &operation).is_err());
    assert_eq!(
        kitrove_testkit::FilesystemSnapshot::capture(&archive).unwrap(),
        before
    );
}
