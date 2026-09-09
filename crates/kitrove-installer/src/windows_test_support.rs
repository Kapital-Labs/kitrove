use std::ffi::OsString;
use std::path::{Path, PathBuf};

use kitrove_release_provenance::{AuthenticatedApplicationExecutable, ExpectedReleaseIdentity};

const WINDOWS_ARCHIVE: &[u8] = include_bytes!(
    "../../kitrove-release-policy/tests/fixtures/archive-conformance/valid_zip/kitrove-cli-x86_64-pc-windows-msvc.zip"
);

pub(crate) fn authenticated_executable() -> AuthenticatedApplicationExecutable {
    let spec =
        kitrove_release_policy::application_archive_for_target("x86_64-pc-windows-msvc").unwrap();
    let expected =
        ExpectedReleaseIdentity::new("v1.2.3", "0123456789abcdef0123456789abcdef01234567").unwrap();
    AuthenticatedApplicationExecutable::from_test_archive(spec, WINDOWS_ARCHIVE, &expected).unwrap()
}

pub(crate) struct TestDestination {
    path: PathBuf,
    _directory: tempfile::TempDir,
}

impl TestDestination {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn destination() -> TestDestination {
    destination_in(&std::env::temp_dir())
}

pub(crate) fn destination_in(parent: &Path) -> TestDestination {
    let destination = tempfile::Builder::new()
        .prefix("kitrove-windows-stage-")
        .tempdir_in(parent)
        .unwrap();
    let install = destination.path().join("install");
    kitrove_windows_security::ensure_private_directory_for_tests(&install).unwrap();
    let path = kitrove_windows_security::canonical_directory_path_for_tests(&install).unwrap();
    TestDestination {
        path,
        _directory: destination,
    }
}

pub(crate) fn inventory(path: &Path) -> Vec<OsString> {
    let mut entries = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

pub(crate) fn initialized_state(parent: &Path) -> PathBuf {
    let state = parent.join("app-state");
    let (authority, guard) =
        kitrove_state_lifecycle::StateAuthority::initialize_absent(&state).unwrap();
    authority
        .exclusive_access(&guard)
        .unwrap()
        .create_initial_state(crate::test_support::EMPTY_STATE)
        .unwrap();
    state
}

/// Test-owned, data-only fixtures: compare complete trees without adding the core
/// testkit dependency graph to the standalone Windows installer acceptance build.
pub(crate) fn snapshot_tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut result = std::collections::BTreeMap::new();
    let mut directories = vec![PathBuf::new()];
    while let Some(relative) = directories.pop() {
        for entry in std::fs::read_dir(root.join(&relative)).unwrap() {
            let entry = entry.unwrap();
            let path = relative.join(entry.file_name());
            let kind = entry.file_type().unwrap();
            assert!(result.len() < 256, "fixture tree exceeds snapshot limit");
            assert!(kind.is_file() || kind.is_dir(), "unexpected fixture type");
            if kind.is_dir() {
                directories.push(path.clone());
                result.insert(path, None);
            } else {
                // Windows byte-range locks reject reads even for a zero-byte lock
                // file. Its exact empty content follows from metadata; do not turn
                // errors reading any nonempty file into a successful snapshot.
                let bytes = if entry.metadata().unwrap().len() == 0 {
                    Vec::new()
                } else {
                    std::fs::read(entry.path()).unwrap()
                };
                result.insert(path, Some(bytes));
            }
        }
    }
    result
}
