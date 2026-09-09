use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use kitrove_model::{
    EnvironmentManifest, LocalState, SchemaVersion, SyncBasePointer, SyncBaseRecord, SyncLimits,
};
use kitrove_state_lifecycle::{
    ExclusiveLifecycleGuard, LifecycleError, StateAuthority, StateTreeSnapshot,
};
use serde::{Deserialize, Serialize};

use crate::InstallerStageError;

pub(crate) const MAX_STATE_ROOTS: usize = 16;
const MAX_ALL_STATE_BYTES: usize = 256 * 1024 * 1024;

/// Local-only transaction evidence; parsing this value never grants authority.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateRootRecord {
    path_hex: String,
    tree_fingerprint: String,
}

impl std::fmt::Debug for StateRootRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateRootRecord")
            .finish_non_exhaustive()
    }
}

impl StateRootRecord {
    /// Shape only: retained historical paths are data, never a selection of roots to open.
    pub(crate) fn validate_history(records: &[Self]) -> Result<(), InstallerStageError> {
        let mut paths = BTreeSet::new();
        if records.len() > MAX_STATE_ROOTS
            || records.iter().any(|record| {
                record.path_hex.is_empty()
                    || record.path_hex.len() > crate::record::MAX_DESTINATION_PATH_BYTES * 2
                    || record.path_hex.len() % 2 != 0
                    || !crate::record::is_lower_hex(&record.path_hex, record.path_hex.len())
                    || !crate::record::is_lower_hex(&record.tree_fingerprint, 64)
                    || !paths.insert(record.path_hex.as_str())
            })
        {
            return Err(InstallerStageError::RecoveryRequired);
        }
        Ok(())
    }
}

/// All selected roots stay exclusively locked; evidence still needs durable transaction binding.
pub(crate) struct InspectedStateRoots {
    roots: Vec<InspectedRoot>,
}

struct LockedRoot {
    authority: StateAuthority,
    guard: ExclusiveLifecycleGuard,
}

struct InspectedRoot {
    // Close retained snapshot handles before releasing the lifecycle lock to another writer.
    snapshot: StateTreeSnapshot,
    locked: LockedRoot,
}

impl InspectedStateRoots {
    pub(crate) fn capture(paths: &[PathBuf]) -> Result<Self, InstallerStageError> {
        if paths.len() > MAX_STATE_ROOTS {
            return Err(InstallerStageError::UnsafeState);
        }
        let mut ordered = paths
            .iter()
            .map(std::path::absolute)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| InstallerStageError::UnsafeState)?;
        ordered.sort();
        if ordered.windows(2).any(|pair| pair[1].starts_with(&pair[0])) {
            return Err(InstallerStageError::UnsafeState);
        }
        let mut locked = Vec::new();
        // No state bytes are read until every selected root has been exclusively locked.
        for path in ordered {
            let authority = StateAuthority::open_existing(&path).map_err(lifecycle_error)?;
            let guard = authority.try_lock_exclusive().map_err(lifecycle_error)?;
            locked.push(LockedRoot { authority, guard });
        }
        let mut roots = Vec::new();
        let mut total_bytes = 0_usize;
        for locked in locked {
            let access = locked
                .authority
                .exclusive_access(&locked.guard)
                .map_err(lifecycle_error)?;
            let snapshot = access.capture_state_tree().map_err(lifecycle_error)?;
            for (_, bytes) in snapshot.files() {
                total_bytes = total_bytes
                    .checked_add(bytes.len())
                    .ok_or(InstallerStageError::UnsafeState)?;
            }
            if total_bytes > MAX_ALL_STATE_BYTES {
                return Err(InstallerStageError::UnsafeState);
            }
            validate_state(&snapshot)?;
            roots.push(InspectedRoot { locked, snapshot });
        }
        let mut inspected = Self { roots };
        // Successful preflight must also fit the durable path encoding before
        // a caller starts writing installer preparation artifacts.
        inspected.records()?;
        Ok(inspected)
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), InstallerStageError> {
        for root in &mut self.roots {
            root.locked
                .authority
                .exclusive_access(&root.locked.guard)
                .map_err(lifecycle_error)?
                .revalidate_state_tree(&mut root.snapshot)
                .map_err(lifecycle_error)?;
        }
        Ok(())
    }

    pub(crate) fn fingerprints(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.roots.iter().map(|root| root.snapshot.fingerprint())
    }

    pub(crate) fn records(&mut self) -> Result<Vec<StateRootRecord>, InstallerStageError> {
        self.revalidate()?;
        self.roots
            .iter()
            .map(|root| {
                let access = root
                    .locked
                    .authority
                    .exclusive_access(&root.locked.guard)
                    .map_err(lifecycle_error)?;
                let path = access.state_root_path();
                #[cfg(unix)]
                let bytes = crate::unix_staging::bounded_destination_path_bytes(path);
                #[cfg(windows)]
                let bytes = crate::windows_staging::encode_destination_path(path);
                let bytes = bytes.map_err(|_| InstallerStageError::UnsafeState)?;
                Ok(StateRootRecord {
                    path_hex: crate::record::encode_hex(&bytes),
                    tree_fingerprint: crate::record::encode_hex(&root.snapshot.fingerprint()),
                })
            })
            .collect()
    }
}

fn lifecycle_error(error: LifecycleError) -> InstallerStageError {
    match error {
        LifecycleError::LockUnavailable => InstallerStageError::Conflict,
        _ => InstallerStageError::UnsafeState,
    }
}

fn validate_state(snapshot: &StateTreeSnapshot) -> Result<(), InstallerStageError> {
    let files = snapshot.files().collect::<BTreeMap<_, _>>();
    let state = LocalState::from_json(text(required(&files, Path::new("state.json"))?)?)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    match state.schema_version {
        SchemaVersion::V1 => {}
    }
    if !required(&files, Path::new(".kitrove/lifecycle.lock"))?.is_empty() {
        return Err(InstallerStageError::UnsafeState);
    }
    let mut allowed_files = BTreeSet::from([
        PathBuf::from("state.json"),
        PathBuf::from(".kitrove/lifecycle.lock"),
    ]);
    if let Some(bytes) = files.get(Path::new(".kitrove/environment.lock")) {
        if !bytes.is_empty() {
            return Err(InstallerStageError::UnsafeState);
        }
        allowed_files.insert(PathBuf::from(".kitrove/environment.lock"));
    }
    let limits = SyncLimits::default();
    let mut generations = BTreeMap::new();
    let mut pointers = Vec::new();
    for (path, bytes) in &files {
        let parts = components(path)?;
        match parts.as_slice() {
            ["sync", remote, "base-current.json"] if hex(remote) => {
                let pointer = SyncBasePointer::from_json(text(bytes)?, limits)
                    .map_err(|_| InstallerStageError::UnsafeState)?;
                if pointer.remote_key().as_str() != format!("remote:blake3:{remote}") {
                    return Err(InstallerStageError::UnsafeState);
                }
                pointers.push(((*remote).to_owned(), pointer));
                allowed_files.insert(path.to_path_buf());
            }
            ["sync", remote, "bases", generation, "base.json"]
                if hex(remote) && hex(generation) =>
            {
                let record = SyncBaseRecord::from_json(text(bytes)?, limits)
                    .map_err(|_| InstallerStageError::UnsafeState)?;
                if SyncBaseRecord::generation_id_for_json(text(bytes)?).as_str()
                    != format!("blake3:{generation}")
                {
                    return Err(InstallerStageError::UnsafeState);
                }
                if record.remote_key().as_str() != format!("remote:blake3:{remote}") {
                    return Err(InstallerStageError::UnsafeState);
                }
                let base = path.parent().ok_or(InstallerStageError::UnsafeState)?;
                let manifest_path = base.join("base-manifest.toml");
                let manifest_text = text(required(&files, &manifest_path)?)?;
                if manifest_text.len() as u64 > limits.max_manifest_bytes() {
                    return Err(InstallerStageError::UnsafeState);
                }
                EnvironmentManifest::from_toml(manifest_text)
                    .map_err(|_| InstallerStageError::UnsafeState)?;
                allowed_files.insert(path.to_path_buf());
                allowed_files.insert(manifest_path);
                generations.insert(
                    ((*remote).to_owned(), (*generation).to_owned()),
                    (base.to_path_buf(), record),
                );
            }
            _ => {}
        }
    }
    for (remote, pointer) in pointers {
        let generation = pointer
            .generation()
            .as_str()
            .strip_prefix("blake3:")
            .ok_or(InstallerStageError::UnsafeState)?;
        if !generations.contains_key(&(remote, generation.to_owned())) {
            return Err(InstallerStageError::UnsafeState);
        }
    }
    for path in files.keys() {
        if allowed_files.contains(*path) || path.starts_with(".kitrove/removal-quarantine") {
            continue;
        }
        if generations.values().any(|(base, record)| {
            record
                .objects()
                .iter()
                .any(|object| path.starts_with(base.join(object.root().as_str())))
        }) {
            continue;
        }
        // In particular this rejects journals, pending/backup leaves and sync staging files.
        return Err(InstallerStageError::RecoveryRequired);
    }
    for path in snapshot.directories() {
        let parts = components(path)?;
        let known = match parts.as_slice() {
            [] | [".kitrove", ..] | ["sync"] => true,
            ["sync", remote] | ["sync", remote, "bases"] if hex(remote) => true,
            ["sync", remote, "staging", ..] if hex(remote) => true,
            ["sync", remote, "bases", generation, ..] => {
                generations.contains_key(&(remote.to_string(), generation.to_string()))
            }
            _ => false,
        };
        if !known {
            return Err(InstallerStageError::RecoveryRequired);
        }
    }
    Ok(())
}

fn required<'a>(
    files: &BTreeMap<&Path, &'a [u8]>,
    path: &Path,
) -> Result<&'a [u8], InstallerStageError> {
    files
        .get(path)
        .copied()
        .ok_or(InstallerStageError::UnsafeState)
}

fn text(bytes: &[u8]) -> Result<&str, InstallerStageError> {
    std::str::from_utf8(bytes).map_err(|_| InstallerStageError::UnsafeState)
}

fn components(path: &Path) -> Result<Vec<&str>, InstallerStageError> {
    path.iter()
        .map(|part| part.to_str().ok_or(InstallerStageError::UnsafeState))
        .collect()
}

fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{EMPTY_STATE as STATE, initialized_state as state};
    use std::fs;

    fn directory(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)]
        // Existing directories are inspected, not repaired, by this helper.
        // Let it create the private object instead of inheriting a DACL first.
        kitrove_windows_security::ensure_private_directory_for_tests(path).unwrap();
    }

    fn file(path: &Path, bytes: &[u8]) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        {
            use std::io::Write as _;
            let parent = cap_std::fs::Dir::open_ambient_dir(
                path.parent().unwrap(),
                cap_std::ambient_authority(),
            )
            .unwrap();
            let mut file =
                kitrove_windows_security::create_private_file(&parent, path.file_name().unwrap())
                    .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
    }

    #[test]
    fn root_records_are_stable_lossless_and_debug_redacted() {
        let (_parent, path) = state(STATE);
        let mut inspected = InspectedStateRoots::capture(std::slice::from_ref(&path)).unwrap();
        let records = inspected.records().unwrap();
        assert_eq!(records, inspected.records().unwrap());
        assert_eq!(records.len(), 1);
        #[cfg(unix)]
        let encoded = {
            use std::os::unix::ffi::OsStrExt as _;
            crate::record::encode_hex(path.as_os_str().as_bytes())
        };
        #[cfg(windows)]
        let encoded = crate::record::encode_hex(
            &crate::windows_staging::encode_destination_path(&path).unwrap(),
        );
        assert_eq!(records[0].path_hex, encoded);
        assert!(!format!("{records:?}").contains(&encoded));
        assert!(!format!("{records:?}").contains(&records[0].tree_fingerprint));
        fs::write(path.join("state.json"), b"changed").unwrap();
        assert!(inspected.records().is_err());
    }

    #[test]
    fn all_selected_roots_remain_locked_and_order_is_stable() {
        let (_first_parent, first) = state(STATE);
        let (_second_parent, second) = state(STATE);
        let mut inspected = InspectedStateRoots::capture(&[second.clone(), first.clone()]).unwrap();
        inspected.revalidate().unwrap();
        let fingerprints = inspected.fingerprints().collect::<Vec<_>>();
        for path in [&first, &second] {
            let authority = StateAuthority::open_existing(path).unwrap();
            assert!(matches!(
                authority.try_lock_shared(),
                Err(LifecycleError::LockUnavailable)
            ));
        }
        drop(inspected);
        let inspected = InspectedStateRoots::capture(&[first, second]).unwrap();
        assert_eq!(fingerprints, inspected.fingerprints().collect::<Vec<_>>());
    }

    #[test]
    fn busy_or_invalid_roots_release_previously_acquired_guards() {
        let (_first_parent, first) = state(STATE);
        let (_second_parent, second) = state(STATE);
        let mut paths = [first, second];
        paths.sort();
        let busy = StateAuthority::open_existing(&paths[1]).unwrap();
        let guard = busy.try_lock_shared().unwrap();
        assert_eq!(
            InspectedStateRoots::capture(&paths).err(),
            Some(InstallerStageError::Conflict)
        );
        let first = StateAuthority::open_existing(&paths[0]).unwrap();
        let _first_guard = first.try_lock_exclusive().unwrap();
        drop(guard);
    }

    #[test]
    fn unsupported_malformed_and_unknown_state_schemas_are_read_only_refusals() {
        for bytes in [
            b"PRIVATE-CANARY".as_slice(),
            br#"{"schema_version":2,"machine":{"id":"test-machine"}}"#,
            br#"{"schema_version":1,"machine":{"id":"test-machine"},"foreign":"PRIVATE-CANARY"}"#,
        ] {
            let (_parent, path) = state(bytes);
            assert_eq!(
                InspectedStateRoots::capture(std::slice::from_ref(&path)).err(),
                Some(InstallerStageError::UnsafeState)
            );
            assert_eq!(fs::read(path.join("state.json")).unwrap(), bytes);
            let authority = StateAuthority::open_existing(&path).unwrap();
            let _guard = authority.try_lock_exclusive().unwrap();
        }
    }

    #[test]
    fn duplicate_excess_and_absent_roots_do_not_create_authority() {
        let (_parent, path) = state(STATE);
        assert_eq!(
            InspectedStateRoots::capture(&[path.clone(), path.clone()]).err(),
            Some(InstallerStageError::UnsafeState)
        );
        assert_eq!(
            InspectedStateRoots::capture(&vec![path.clone(); MAX_STATE_ROOTS + 1]).err(),
            Some(InstallerStageError::UnsafeState)
        );
        let absent = path.join("absent");
        assert!(InspectedStateRoots::capture(std::slice::from_ref(&absent)).is_err());
        assert!(!absent.exists());
    }

    #[test]
    fn stable_locks_and_historical_quarantine_are_preserved_but_pending_controls_block() {
        let (_parent, path) = state(STATE);
        file(&path.join(".kitrove/environment.lock"), b"");
        directory(&path.join(".kitrove/removal-quarantine"));
        file(
            &path.join(".kitrove/removal-quarantine/retained"),
            b"PRIVATE-CANARY",
        );
        directory(&path.join(".kitrove/trust-staging"));
        let inspected = InspectedStateRoots::capture(std::slice::from_ref(&path)).unwrap();
        drop(inspected);
        file(
            &path.join(".kitrove/trust-staging/pending.json"),
            b"unfinished",
        );
        assert_eq!(
            InspectedStateRoots::capture(std::slice::from_ref(&path)).err(),
            Some(InstallerStageError::RecoveryRequired)
        );
        assert_eq!(
            fs::read(path.join(".kitrove/removal-quarantine/retained")).unwrap(),
            b"PRIVATE-CANARY"
        );
    }

    #[test]
    fn an_uncooperative_writer_invalidates_the_selected_root_set() {
        let (_parent, path) = state(STATE);
        let mut inspected = InspectedStateRoots::capture(std::slice::from_ref(&path)).unwrap();
        let changed = String::from_utf8(STATE.to_vec())
            .unwrap()
            .replace("test-machine", "next-machine");
        fs::write(path.join("state.json"), changed.as_bytes()).unwrap();
        assert_eq!(
            inspected.revalidate(),
            Err(InstallerStageError::UnsafeState)
        );
        assert_eq!(
            fs::read(path.join("state.json")).unwrap(),
            changed.as_bytes()
        );
    }

    // Typed schema fixture, not a claim that preflight verifies portable object contents.
    fn sync_controls(path: &Path, unsupported_schema: bool) -> (PathBuf, PathBuf) {
        use kitrove_model::{RemoteKey, RemoteRevision, Revision, SnapshotDigest};
        let remote = RemoteKey::parse(format!("remote:blake3:{}", "1".repeat(64))).unwrap();
        let record = SyncBaseRecord::new(
            remote.clone(),
            SnapshotDigest::parse(format!("snapshot:blake3:{}", "2".repeat(64))).unwrap(),
            Revision::parse("fixture-revision").unwrap(),
            RemoteRevision::parse("fixture-backend").unwrap(),
            BTreeSet::new(),
            SyncLimits::default(),
        )
        .unwrap();
        let mut text = record.to_json(SyncLimits::default()).unwrap();
        if unsupported_schema {
            text = text.replace("\"schema_version\": 1", "\"schema_version\": 2");
        }
        let generation = SyncBaseRecord::generation_id_for_json(&text);
        let remote_path = path.join("sync").join("1".repeat(64));
        let base = remote_path
            .join("bases")
            .join(generation.as_str().strip_prefix("blake3:").unwrap());
        for directory_path in [
            path.join("sync"),
            remote_path.clone(),
            remote_path.join("bases"),
            base.clone(),
        ] {
            directory(&directory_path);
        }
        file(&base.join("base.json"), text.as_bytes());
        file(&base.join("base-manifest.toml"), b"schema_version = 1\n");
        let selector = remote_path.join("base-current.json");
        file(
            &selector,
            SyncBasePointer::new(remote, generation)
                .to_json()
                .unwrap()
                .as_bytes(),
        );
        (base, selector)
    }

    #[test]
    fn selected_sync_controls_use_the_shared_schema_and_generation_identity() {
        let (_parent, path) = state(STATE);
        let (base, _) = sync_controls(&path, false);
        let mut inspected = InspectedStateRoots::capture(std::slice::from_ref(&path)).unwrap();
        inspected.revalidate().unwrap();
        fs::write(base.join("base-manifest.toml"), b"schema_version = 2\n").unwrap();
        assert_eq!(
            inspected.revalidate(),
            Err(InstallerStageError::UnsafeState)
        );
        drop(inspected);
        assert_eq!(
            InspectedStateRoots::capture(std::slice::from_ref(&path)).err(),
            Some(InstallerStageError::UnsafeState)
        );
    }

    #[test]
    fn unsupported_retained_base_schema_and_wrong_selectors_are_refused() {
        let (_parent, path) = state(STATE);
        sync_controls(&path, true);
        assert_eq!(
            InspectedStateRoots::capture(std::slice::from_ref(&path)).err(),
            Some(InstallerStageError::UnsafeState)
        );

        let (_parent, path) = state(STATE);
        let (_, selector) = sync_controls(&path, false);
        let mut pointer: serde_json::Value =
            serde_json::from_slice(&fs::read(&selector).unwrap()).unwrap();
        pointer["generation"] = serde_json::json!(format!("blake3:{}", "f".repeat(64)));
        // Reconstitute through the same canonical writer so this tests a missing generation,
        // not merely noncanonical JSON formatting.
        let pointer = SyncBasePointer::new(
            kitrove_model::RemoteKey::parse(pointer["remote_key"].as_str().unwrap()).unwrap(),
            kitrove_model::ContentHash::parse(pointer["generation"].as_str().unwrap()).unwrap(),
        );
        fs::write(&selector, pointer.to_json().unwrap()).unwrap();
        assert_eq!(
            InspectedStateRoots::capture(std::slice::from_ref(&path)).err(),
            Some(InstallerStageError::UnsafeState)
        );
    }

    #[test]
    fn sync_staging_bytes_require_recovery_but_empty_staging_directories_do_not() {
        let (_parent, path) = state(STATE);
        let (_, selector) = sync_controls(&path, false);
        let staging = selector.parent().unwrap().join("staging");
        directory(&staging);
        directory(&staging.join("prior-operation"));
        assert!(InspectedStateRoots::capture(std::slice::from_ref(&path)).is_ok());
        file(
            &staging.join("prior-operation/base-current.json"),
            b"retained pending control",
        );
        assert_eq!(
            InspectedStateRoots::capture(std::slice::from_ref(&path)).err(),
            Some(InstallerStageError::RecoveryRequired)
        );
    }
}
