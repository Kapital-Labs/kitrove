use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::*;
use crate::ObjectStore;
#[cfg(unix)]
use crate::filesystem_identity::MetadataIdentity;
#[cfg(unix)]
use crate::quarantine_name::{RemovalTombstoneName, RemovedObjectKind};

struct Fixture {
    root: tempfile::TempDir,
    collection: PathBuf,
    state: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let collection = base.join("collection");
        let state = base.join("private-state");
        let home = base.join("home");
        for path in [&collection, &home] {
            fs::create_dir(path).unwrap();
            private_mode(path);
        }
        ObjectStore::open_or_create_private_state(&state).unwrap();
        write_fixture_file(&state.join("state.json"), b"fixture-private-body\xff");
        Self {
            root,
            collection,
            state,
            home,
        }
    }

    fn roots(&self) -> StorageDoctorRoots<'_> {
        StorageDoctorRoots {
            collection: &self.collection,
            private_state: &self.state,
            user_home: &self.home,
            project: None,
        }
    }

    fn control(&self, root: &Path) -> PathBuf {
        let control = root.join(".kitrove");
        #[cfg(windows)]
        drop(
            ObjectStore::open(root)
                .unwrap()
                .try_lock_environment()
                .unwrap(),
        );
        #[cfg(not(windows))]
        {
            fs::create_dir_all(&control).unwrap();
            private_mode(&control);
        }
        control
    }

    fn quarantine(&self, root: &Path) -> PathBuf {
        let quarantine = self.control(root).join("removal-quarantine");
        #[cfg(windows)]
        {
            let control = cap_std::fs::Dir::open_ambient_dir(
                quarantine.parent().unwrap(),
                cap_std::ambient_authority(),
            )
            .unwrap();
            kitrove_windows_security::create_private_directory(
                &control,
                std::ffi::OsStr::new("removal-quarantine"),
            )
            .unwrap();
        }
        #[cfg(not(windows))]
        {
            fs::create_dir(&quarantine).unwrap();
            private_mode(&quarantine);
        }
        quarantine
    }

    fn inspect_unchanged(&self) -> StorageDoctorReport {
        let before = snapshot(self.root.path());
        let report = inspect_storage_doctor(self.roots());
        assert_eq!(snapshot(self.root.path()), before);
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains(self.root.path().to_str().unwrap()));
        assert!(!encoded.contains("fixture-private-body"));
        report
    }
}

fn write_fixture_file(path: &Path, bytes: &[u8]) {
    #[cfg(windows)]
    {
        use std::io::Write as _;
        let directory = cap_std::fs::Dir::open_ambient_dir(
            path.parent().unwrap(),
            cap_std::ambient_authority(),
        )
        .unwrap();
        let mut file =
            kitrove_windows_security::create_private_file(&directory, path.file_name().unwrap())
                .unwrap();
        file.write_all(bytes).unwrap();
    }
    #[cfg(not(windows))]
    fs::write(path, bytes).unwrap();
}

fn private_mode(path: &Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    #[cfg(not(unix))]
    let _ = path;
}

#[derive(Debug, Eq, PartialEq)]
struct SnapshotEntry {
    mode: u32,
    bytes: Vec<u8>,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, u64, u32, u32, i64, i64),
    #[cfg(target_os = "macos")]
    acl: Option<calcifer_macos_acl::Acl>,
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, SnapshotEntry> {
    fn visit(root: &Path, current: &Path, result: &mut BTreeMap<PathBuf, SnapshotEntry>) {
        let metadata = fs::symlink_metadata(current).unwrap();
        #[cfg(unix)]
        let mode = metadata.permissions().mode();
        #[cfg(not(unix))]
        let mode = u32::from(metadata.permissions().readonly());
        let bytes = if metadata.file_type().is_symlink() {
            fs::read_link(current)
                .unwrap()
                .into_os_string()
                .into_encoded_bytes()
        } else if metadata.is_file() && metadata.len() != 0 {
            fs::read(current).unwrap()
        } else {
            Vec::new()
        };
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt as _;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.nlink(),
                metadata.uid(),
                metadata.gid(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        };
        #[cfg(target_os = "macos")]
        let acl = {
            use std::os::fd::AsFd as _;
            (!metadata.file_type().is_symlink()).then(|| {
                let file = fs::File::open(current).unwrap();
                calcifer_macos_acl::read_acl(file.as_fd()).unwrap()
            })
        };
        result.insert(
            current.strip_prefix(root).unwrap().to_owned(),
            SnapshotEntry {
                mode,
                bytes,
                modified: metadata.modified().ok(),
                #[cfg(unix)]
                identity,
                #[cfg(target_os = "macos")]
                acl,
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(current).unwrap() {
                visit(root, &entry.unwrap().path(), result);
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn check(
    report: &StorageDoctorReport,
    role: StorageDoctorRole,
    stage: StorageDoctorStage,
) -> &StorageDoctorCheck {
    report
        .checks
        .iter()
        .find(|check| check.role == role && check.stage == stage)
        .expect("required doctor observation")
}

#[test]
fn absent_controls_are_reported_without_creating_them_or_parsing_state() {
    let fixture = Fixture::new();
    let report = fixture.inspect_unchanged();
    assert_eq!(report.inspection, StorageDoctorInspection::Unlocked);
    assert_eq!(
        report.mutation_access,
        StorageDoctorMutationAccess::NotTested
    );
    for role in [
        StorageDoctorRole::Collection,
        StorageDoctorRole::PrivateState,
        StorageDoctorRole::UserHome,
    ] {
        assert_eq!(
            check(&report, role, StorageDoctorStage::Root).status,
            StorageDoctorStatus::Ok
        );
        assert_eq!(
            check(&report, role, StorageDoctorStage::ControlDirectory).status,
            StorageDoctorStatus::Absent
        );
        assert_eq!(
            check(&report, role, StorageDoctorStage::RecoveryMarkers).count,
            Some(0)
        );
    }
    assert!(
        !report
            .checks
            .iter()
            .any(|check| check.role == StorageDoctorRole::Project)
    );
}

fn state_file_observation(report: &StorageDoctorReport) -> &StorageDoctorCheck {
    report
        .checks
        .iter()
        .find(|check| {
            check.role == StorageDoctorRole::PrivateState && check.stage.as_str() == "state_file"
        })
        .expect("required private state file metadata observation")
}

#[test]
fn state_file_missing_is_reported_without_creating_an_authority_file() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.state.join("state.json")).unwrap();
    let report = fixture.inspect_unchanged();
    let state = state_file_observation(&report);
    assert_eq!(state.status, StorageDoctorStatus::Absent);
    assert_eq!(state.code.as_str(), "state_file_missing");
    assert_eq!(state.count, Some(0));
    assert!(!fixture.state.join("state.json").exists());
}

#[test]
fn state_file_present_reports_metadata_without_parsing_its_body() {
    let fixture = Fixture::new();
    let report = fixture.inspect_unchanged();
    let state = state_file_observation(&report);
    assert_eq!(state.status, StorageDoctorStatus::Ok);
    assert_eq!(state.code, StorageDoctorCode::Checked);
    assert_eq!(state.count, Some(1));
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        b"fixture-private-body\xff"
    );
    assert!(
        !report
            .checks
            .iter()
            .any(|check| check.role != StorageDoctorRole::PrivateState
                && check.stage.as_str() == "state_file")
    );
}

#[cfg(unix)]
#[test]
fn state_file_symlink_is_unverified_without_following_or_replacing_it() {
    let fixture = Fixture::new();
    let outside = fixture.home.join("outside-state");
    fs::write(&outside, b"fixture-private-body\xff").unwrap();
    fs::remove_file(fixture.state.join("state.json")).unwrap();
    std::os::unix::fs::symlink(&outside, fixture.state.join("state.json")).unwrap();
    let report = fixture.inspect_unchanged();
    let state = state_file_observation(&report);
    assert_eq!(state.status, StorageDoctorStatus::Blocked);
    assert_eq!(state.code.as_str(), "state_file_unverified");
    assert_eq!(
        fs::read_link(fixture.state.join("state.json")).unwrap(),
        outside
    );
}

#[cfg(unix)]
#[test]
fn state_file_hardlink_is_unverified_without_repair_or_replacement() {
    let fixture = Fixture::new();
    fs::hard_link(
        fixture.state.join("state.json"),
        fixture.home.join("state-link"),
    )
    .unwrap();
    let report = fixture.inspect_unchanged();
    let state = state_file_observation(&report);
    assert_eq!(state.status, StorageDoctorStatus::Blocked);
    assert_eq!(state.code.as_str(), "state_file_unverified");
}

#[test]
fn missing_required_root_leaves_dependent_observations_unchecked() {
    let fixture = Fixture::new();
    fs::remove_dir(&fixture.home).unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::UserHome,
            StorageDoctorStage::Root
        )
        .status,
        StorageDoctorStatus::Absent
    );
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::UserHome,
            StorageDoctorStage::ExistingLock
        )
        .code,
        StorageDoctorCode::PriorCheckBlocked
    );
}

#[test]
fn optional_project_is_checked_only_when_requested() {
    let fixture = Fixture::new();
    let project = fixture.home.join("project");
    fs::create_dir(&project).unwrap();
    let before = snapshot(fixture.root.path());
    let mut roots = fixture.roots();
    roots.project = Some(&project);
    let report = inspect_storage_doctor(roots);
    assert_eq!(snapshot(fixture.root.path()), before);
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::Project,
            StorageDoctorStage::Root
        )
        .status,
        StorageDoctorStatus::Ok
    );
}

#[cfg(unix)]
#[test]
fn a_linked_root_is_refused_without_following_the_link() {
    let fixture = Fixture::new();
    fs::remove_dir(&fixture.home).unwrap();
    std::os::unix::fs::symlink(&fixture.collection, &fixture.home).unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::UserHome,
            StorageDoctorStage::Root
        )
        .code,
        StorageDoctorCode::UnsafeRoot
    );
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::UserHome,
            StorageDoctorStage::RetainedCleanup
        )
        .status,
        StorageDoctorStatus::NotChecked
    );
}

#[test]
fn malformed_marker_bodies_are_never_parsed_and_are_reported_as_present() {
    let fixture = Fixture::new();
    let control = fixture.control(&fixture.state);
    write_fixture_file(
        &control.join("atomic-apply-journal.pending.previous"),
        b"fixture-private-body\xff",
    );
    let report = fixture.inspect_unchanged();
    let marker = check(
        &report,
        StorageDoctorRole::PrivateState,
        StorageDoctorStage::RecoveryMarkers,
    );
    assert_eq!(marker.code, StorageDoctorCode::RecoveryPresent);
    assert_eq!(marker.count, Some(1));
}

#[test]
fn a_nonregular_fixed_marker_is_reported_without_reading_it() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.control(&fixture.state).join("trust-journal.json")).unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::PrivateState,
            StorageDoctorStage::RecoveryMarkers
        )
        .code,
        StorageDoctorCode::RecoveryUnsafe
    );
}

#[test]
fn a_held_lock_is_observed_without_attempting_to_acquire_it() {
    let fixture = Fixture::new();
    let store = ObjectStore::open(&fixture.collection).unwrap();
    let _lock = store.try_lock_environment().unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::Collection,
            StorageDoctorStage::ExistingLock
        )
        .status,
        StorageDoctorStatus::Ok
    );
}

#[cfg(unix)]
#[test]
fn linked_lock_is_refused_without_following_or_replacing_it() {
    let fixture = Fixture::new();
    let outside = fixture.collection.join("outside-lock");
    fs::write(&outside, "fixture-private-body").unwrap();
    std::os::unix::fs::symlink(
        &outside,
        fixture
            .control(&fixture.collection)
            .join("environment.lock"),
    )
    .unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::Collection,
            StorageDoctorStage::ExistingLock
        )
        .code,
        StorageDoctorCode::LockUnsafe
    );
}

#[test]
fn unrecognized_retained_state_is_refused_and_preserved() {
    let fixture = Fixture::new();
    let quarantine = fixture.quarantine(&fixture.home);
    fs::write(
        quarantine.join("fixture-private-body"),
        "retained-body-is-never-reported",
    )
    .unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::UserHome,
            StorageDoctorStage::RetainedCleanup
        )
        .detail,
        Some(StorageDoctorCleanupDetail {
            identity_component: None,
            reason: StorageDoctorCleanupReason::UnrecognizedName,
            entry: Some(1),
            location: StorageDoctorCleanupLocation::Entry
        })
    );
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::UserHome,
            StorageDoctorStage::RetainedCleanup
        )
        .code,
        StorageDoctorCode::RetainedUnrecognized
    );
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("retained-body-is-never-reported")
    );
}

#[cfg(unix)]
#[test]
fn retained_identity_mismatch_is_refused_without_reclamation() {
    let fixture = Fixture::new();
    let quarantine = fixture.quarantine(&fixture.state);
    let name = RemovalTombstoneName {
        kind: RemovedObjectKind::File,
        identity: MetadataIdentity {
            device: 0,
            inode: 0,
        },
    }
    .encode("00112233445566778899aabbccddeeff")
    .unwrap();
    fs::write(quarantine.join(name), "").unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::PrivateState,
            StorageDoctorStage::RetainedCleanup
        )
        .detail,
        Some(StorageDoctorCleanupDetail {
            identity_component: Some(StorageDoctorCleanupIdentityComponent::DeviceAndFile),
            reason: StorageDoctorCleanupReason::IdentityMismatch,
            entry: Some(1),
            location: StorageDoctorCleanupLocation::Entry
        })
    );
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::PrivateState,
            StorageDoctorStage::RetainedCleanup
        )
        .code,
        StorageDoctorCode::RetainedUnsafe
    );
}

#[cfg(unix)]
#[test]
fn valid_retained_file_is_counted_without_truncation_or_deletion() {
    let fixture = Fixture::new();
    let quarantine = fixture.quarantine(&fixture.collection);
    let original = quarantine.join("temporary");
    fs::write(&original, "fixture-private-body").unwrap();
    let name = RemovalTombstoneName {
        kind: RemovedObjectKind::File,
        identity: MetadataIdentity::from_metadata(&fs::metadata(&original).unwrap()),
    }
    .encode("00112233445566778899aabbccddeeff")
    .unwrap();
    fs::rename(original, quarantine.join(name)).unwrap();
    let report = fixture.inspect_unchanged();
    let retained = check(
        &report,
        StorageDoctorRole::Collection,
        StorageDoctorStage::RetainedCleanup,
    );
    assert_eq!(retained.status, StorageDoctorStatus::Ok);
    assert_eq!(retained.count, Some(1));
}

#[cfg(unix)]
#[test]
fn owned_nonwritable_control_without_quarantine_preserves_existing_inspection_policy() {
    let fixture = Fixture::new();
    let control = fixture.control(&fixture.collection);
    fs::set_permissions(&control, fs::Permissions::from_mode(0o755)).unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::Collection,
            StorageDoctorStage::ControlDirectory
        )
        .status,
        StorageDoctorStatus::Ok
    );
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::Collection,
            StorageDoctorStage::RetainedCleanup
        )
        .status,
        StorageDoctorStatus::Absent
    );
}

#[cfg(unix)]
#[test]
fn broad_control_with_quarantine_is_refused_without_permission_repair() {
    let fixture = Fixture::new();
    fixture.quarantine(&fixture.collection);
    fs::set_permissions(
        fixture.collection.join(".kitrove"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::Collection,
            StorageDoctorStage::ControlDirectory
        )
        .status,
        StorageDoctorStatus::Blocked
    );
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::Collection,
            StorageDoctorStage::RetainedCleanup
        )
        .status,
        StorageDoctorStatus::NotChecked
    );
}

#[cfg(unix)]
#[test]
fn broad_private_root_mode_is_observed_without_repair() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o755)).unwrap();
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::PrivateState,
            StorageDoctorStage::PrivateBoundary
        )
        .status,
        StorageDoctorStatus::Blocked
    );
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::PrivateState,
            StorageDoctorStage::ExistingLock
        )
        .status,
        StorageDoctorStatus::NotChecked
    );
}

#[cfg(target_os = "macos")]
#[test]
fn native_private_root_acl_is_reported_and_preserved_without_chmod() {
    use std::os::fd::AsFd as _;
    let fixture = Fixture::new();
    kitrove_testkit::install_macos_extended_acl(&fixture.state);
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::PrivateState,
            StorageDoctorStage::PrivateAcl
        )
        .code,
        StorageDoctorCode::AclNotEmpty
    );
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::PrivateState,
            StorageDoctorStage::PrivateBoundary
        )
        .status,
        StorageDoctorStatus::Blocked
    );
    let file = fs::File::open(&fixture.state).unwrap();
    assert!(
        !calcifer_macos_acl::read_acl(file.as_fd())
            .unwrap()
            .is_empty()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn quarantine_acl_rejection_stays_in_retained_cleanup_without_repair() {
    use std::os::fd::AsFd as _;
    let fixture = Fixture::new();
    let quarantine = fixture.quarantine(&fixture.home);
    kitrove_testkit::install_macos_extended_acl(&quarantine);
    let report = fixture.inspect_unchanged();
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::UserHome,
            StorageDoctorStage::RetainedCleanup
        )
        .detail,
        Some(StorageDoctorCleanupDetail {
            identity_component: None,
            reason: StorageDoctorCleanupReason::AclNotEmpty,
            entry: None,
            location: StorageDoctorCleanupLocation::Boundary
        })
    );
    assert_eq!(
        check(
            &report,
            StorageDoctorRole::UserHome,
            StorageDoctorStage::RetainedCleanup
        )
        .code,
        StorageDoctorCode::RetainedUnsafe
    );
    let file = fs::File::open(quarantine).unwrap();
    assert!(
        !calcifer_macos_acl::read_acl(file.as_fd())
            .unwrap()
            .is_empty()
    );
}

#[cfg(unix)]
fn retained_directory(quarantine: &Path) -> PathBuf {
    let original = quarantine.join("temporary-directory");
    fs::create_dir(&original).unwrap();
    let name = RemovalTombstoneName {
        kind: RemovedObjectKind::Directory,
        identity: MetadataIdentity::from_metadata(&fs::metadata(&original).unwrap()),
    }
    .encode("00112233445566778899aabbccddeeff")
    .unwrap();
    let retained = quarantine.join(name);
    fs::rename(original, &retained).unwrap();
    retained
}

#[cfg(unix)]
#[test]
fn cleanup_reasons_distinguish_invariants_without_writes_or_private_data() {
    use crate::quarantine_name::CleanupPendingName;
    use StorageDoctorCleanupReason as R;
    use std::os::unix::fs::symlink;
    for (case, reason, location, entry) in [
        (
            0,
            R::DirectoryModeRejected,
            StorageDoctorCleanupLocation::Boundary,
            None,
        ),
        (
            1,
            R::WrongEntryKind,
            StorageDoctorCleanupLocation::Entry,
            Some(1),
        ),
        (
            2,
            R::LinkOrReparsePoint,
            StorageDoctorCleanupLocation::Entry,
            Some(1),
        ),
        (
            3,
            R::FileLinkCountRejected,
            StorageDoctorCleanupLocation::Entry,
            Some(1),
        ),
        (
            4,
            R::PendingBatchNotVerifiedEmpty,
            StorageDoctorCleanupLocation::Entry,
            Some(1),
        ),
        (
            5,
            R::MultipleCleanupBatches,
            StorageDoctorCleanupLocation::Entry,
            Some(2),
        ),
        (
            6,
            R::LinkOrReparsePoint,
            StorageDoctorCleanupLocation::Descendant,
            Some(1),
        ),
    ] {
        let fixture = Fixture::new();
        let q = fixture.quarantine(&fixture.collection);
        let pending =
            || q.join(CleanupPendingName::encode("00112233445566778899aabbccddeeff").unwrap());
        match case {
            0 => fs::set_permissions(&q, fs::Permissions::from_mode(0o755)).unwrap(),
            1 | 2 => {
                let name = RemovalTombstoneName {
                    kind: RemovedObjectKind::Directory,
                    identity: MetadataIdentity {
                        device: 0,
                        inode: 0,
                    },
                }
                .encode("00112233445566778899aabbccddeeff")
                .unwrap();
                if case == 1 {
                    fs::write(q.join(name), "fixture-private-body").unwrap();
                } else {
                    symlink(&fixture.home, q.join(name)).unwrap();
                }
            }
            3 => {
                let original = fixture.home.join("hardlink-private-canary");
                fs::write(&original, "fixture-private-body").unwrap();
                let name = RemovalTombstoneName {
                    kind: RemovedObjectKind::File,
                    identity: MetadataIdentity::from_metadata(&fs::metadata(&original).unwrap()),
                }
                .encode("00112233445566778899aabbccddeeff")
                .unwrap();
                fs::hard_link(original, q.join(name)).unwrap();
            }
            4 => {
                fs::create_dir(pending()).unwrap();
                fs::write(
                    pending().join("PRIVATE_NAME_CANARY"),
                    "fixture-private-body",
                )
                .unwrap();
            }
            5 => {
                fs::create_dir(pending()).unwrap();
                fs::create_dir(
                    q.join(CleanupPendingName::encode("ffeeddccbbaa99887766554433221100").unwrap()),
                )
                .unwrap();
            }
            6 => {
                symlink(
                    &fixture.home,
                    retained_directory(&q).join("PRIVATE_NAME_CANARY"),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let report = fixture.inspect_unchanged();
        let check = check(
            &report,
            StorageDoctorRole::Collection,
            StorageDoctorStage::RetainedCleanup,
        );
        assert_eq!(check.code, StorageDoctorCode::RetainedUnsafe, "case {case}");
        assert_eq!(
            check.detail,
            Some(StorageDoctorCleanupDetail {
                identity_component: None,
                location,
                reason,
                entry
            }),
            "case {case}"
        );
        let encoded = serde_json::to_string(&report).unwrap();
        for secret in [
            "PRIVATE_NAME_CANARY",
            "hardlink-private-canary",
            ".kitrove-removed-v1",
            "00112233445566778899aabbccddeeff",
        ] {
            assert!(!encoded.contains(secret), "reported private entry data");
        }
    }
}

#[cfg(unix)]
#[test]
fn cleanup_ordinal_is_sorted_snapshot_only_and_stops_at_first_failure() {
    let fixture = Fixture::new();
    let q = fixture.quarantine(&fixture.collection);
    let original = q.join("temporary");
    fs::write(&original, "fixture-private-body").unwrap();
    let name = RemovalTombstoneName {
        kind: RemovedObjectKind::File,
        identity: MetadataIdentity::from_metadata(&fs::metadata(&original).unwrap()),
    }
    .encode("00112233445566778899aabbccddeeff")
    .unwrap();
    fs::rename(original, q.join(name)).unwrap();
    fs::write(q.join("zz-PRIVATE_CANARY"), "").unwrap();
    let report = fixture.inspect_unchanged();
    let detail = check(
        &report,
        StorageDoctorRole::Collection,
        StorageDoctorStage::RetainedCleanup,
    )
    .detail
    .unwrap();
    assert_eq!(detail.reason, StorageDoctorCleanupReason::UnrecognizedName);
    assert_eq!(detail.entry, Some(2));
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("zz-PRIVATE_CANARY")
    );
}
