use std::path::Path;

use kitrove_model::{LocalState, PortablePath};

use crate::{ObjectMutationError, ObjectStore};

const TEST_STATE_LIMIT: usize = 32 * 1024 * 1024;

/// Creates current-user-owned test content even when the native runner is elevated.
pub(crate) fn write_owned_fixture_file(
    path: impl AsRef<Path>,
    bytes: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        let path = path.as_ref();
        let parent = cap_std::fs::Dir::open_ambient_dir(
            path.parent().expect("fixture file has a parent"),
            cap_std::ambient_authority(),
        )?;
        parent.write(path.file_name().expect("fixture file has a name"), bytes)
    }
    #[cfg(windows)]
    {
        kitrove_windows_security::write_current_user_owned_file_for_tests(
            path.as_ref(),
            bytes.as_ref(),
        )
        .map_err(|_| std::io::Error::other("cannot write owned fixture file"))
    }
}

/// Creates an absent synthetic directory tree using production ownership rules.
pub(crate) fn create_owned_fixture_directory(root: &Path, relative: &str) {
    let relative = PortablePath::parse(relative).expect("fixture directory is portable");
    ObjectStore::open(root)
        .unwrap()
        .create_empty_directory_for_test(&relative)
        .unwrap();
}

pub(crate) fn trusted_tempdir(prefix: &str) -> tempfile::TempDir {
    #[cfg(unix)]
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(std::env::var_os("HOME").expect("test user directory"))
        .expect("trusted test directory");
    #[cfg(windows)]
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("test directory");
    directory
}

pub(crate) fn initialize_portable_environment(
    environment_root: &Path,
    manifest_text: &str,
    lock_text: &str,
) -> Result<(), ObjectMutationError> {
    let store = ObjectStore::open_or_create(environment_root)?;
    let _lock = store.try_lock_environment()?;
    store.stage_text(
        &PortablePath::parse("kitrove.toml").expect("fixed manifest path is portable"),
        manifest_text,
        TEST_STATE_LIMIT,
    )?;
    store.stage_text(
        &PortablePath::parse("kitrove.lock.json").expect("fixed lock path is portable"),
        lock_text,
        TEST_STATE_LIMIT,
    )
}

pub(crate) fn initialize_private_state(
    state_root: &Path,
    desired_state: &LocalState,
) -> Result<(), ObjectMutationError> {
    let desired_text = desired_state
        .to_json()
        .expect("test desired state is valid");
    let store = ObjectStore::open_or_create_private_state(state_root)?;
    let _lock = store.try_lock_environment()?;
    store.stage_private_text(
        &PortablePath::parse("state.json").expect("fixed test state path is portable"),
        &desired_text,
        TEST_STATE_LIMIT,
    )
}

pub(crate) fn initialize_empty_private_root(state_root: &Path) -> Result<(), ObjectMutationError> {
    ObjectStore::open_or_create_private_state(state_root).map(|_| ())
}

pub(crate) fn initialize_portable_control_root(
    environment_root: &Path,
) -> Result<(), ObjectMutationError> {
    let store = ObjectStore::open(environment_root)?;
    store.try_lock_environment().map(|_| ())
}

pub(crate) fn stage_private_text(
    state_root: &Path,
    path: &str,
    text: &str,
) -> Result<(), ObjectMutationError> {
    let store = ObjectStore::open_private_state_for_mutation(state_root)?;
    let _lock = store.try_lock_environment()?;
    store.stage_private_text(
        &PortablePath::parse(path).expect("fixed test state path is portable"),
        text,
        TEST_STATE_LIMIT,
    )
}

#[test]
fn private_state_fixture_has_exact_authority_without_cleanup_debt() {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_model::{MachineConfig, MachineId, SchemaVersion};

    let temporary = trusted_tempdir(".kitrove-test-authority-");
    let state_root = temporary.path().canonicalize().unwrap().join("state");
    let state = LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: MachineId::parse("test-authority-machine").unwrap(),
            active_profile: None,
            enabled_targets: BTreeSet::new(),
            harness_roots: BTreeMap::new(),
        },
        bindings: BTreeMap::new(),
        receipts: BTreeMap::new(),
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::new(),
        scans: Vec::new(),
    };

    initialize_private_state(&state_root, &state).unwrap();

    assert_eq!(
        std::fs::read_to_string(state_root.join("state.json")).unwrap(),
        state.to_json().unwrap()
    );
    assert!(!state_root.join(".kitrove/removal-quarantine").exists());
}
