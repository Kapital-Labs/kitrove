use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::path::Path;

use kitrove_model::{ContentHash, NormalizedDestination};
use serde::de::{Deserializer as _, Error as _, MapAccess, Visitor};

use crate::materialization::normalized_destination_from_path;
#[cfg(not(windows))]
use crate::read_only_fs::{ReadOnlyFileError, read_bounded_regular_file_with_mode};

const MAX_PI_TRUST_BYTES: usize = 1024 * 1024;
const MAX_PI_TRUST_ENTRIES: usize = 4096;

/// Normalized identity plus the exact spelling needed to repeat platform inspection.
#[derive(Clone, Eq, PartialEq)]
struct InspectionPathBinding {
    normalized: NormalizedDestination,
    #[cfg(windows)]
    inspection: String,
}

impl InspectionPathBinding {
    fn new(
        normalized: NormalizedDestination,
        path: &Path,
        invalid: PiProjectTrustError,
    ) -> Result<Self, PiProjectTrustError> {
        #[cfg(not(windows))]
        let _ = (path, invalid);
        Ok(Self {
            normalized,
            #[cfg(windows)]
            inspection: path.to_str().ok_or(invalid)?.to_owned(),
        })
    }

    fn inspection_path(&self) -> &str {
        #[cfg(windows)]
        return &self.inspection;
        #[cfg(not(windows))]
        return self.normalized.as_str();
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ProjectPathBinding {
    inspection: InspectionPathBinding,
    #[cfg(windows)]
    lookup: String,
}

#[derive(Clone, Eq, PartialEq)]
struct SelectedPathBinding {
    normalized: NormalizedDestination,
    #[cfg(windows)]
    lookup: String,
}

/// Exact saved Pi project-trust authority used by one project-scoped plan.
#[derive(Clone, Eq, PartialEq)]
pub struct PiProjectTrustEvidence {
    trust_store: InspectionPathBinding,
    project: ProjectPathBinding,
    selected: SelectedPathBinding,
    trust_store_hash: ContentHash,
}

impl PiProjectTrustEvidence {
    #[must_use]
    pub const fn project_anchor(&self) -> &NormalizedDestination {
        &self.project.inspection.normalized
    }

    #[must_use]
    pub const fn selected_anchor(&self) -> &NormalizedDestination {
        &self.selected.normalized
    }

    #[cfg(all(windows, test))]
    pub(crate) fn lookup_project_anchor(&self) -> &str {
        &self.project.lookup
    }

    #[cfg(all(windows, test))]
    pub(crate) fn selected_lookup_anchor(&self) -> &str {
        &self.selected.lookup
    }

    #[must_use]
    pub const fn trust_store_hash(&self) -> &ContentHash {
        &self.trust_store_hash
    }

    pub(crate) fn revalidate(&self) -> Result<bool, PiProjectTrustError> {
        Ok(matches!(
            inspect_pi_project_trust(
                Path::new(self.trust_store.inspection_path()),
                Path::new(self.project.inspection.inspection_path()),
            )?,
            PiProjectTrustStatus::Trusted(ref current) if current == self
        ))
    }

    #[cfg(not(windows))]
    pub(crate) fn binding_values(&self) -> [&str; 3] {
        [
            self.trust_store.normalized.as_str(),
            self.project.inspection.normalized.as_str(),
            self.selected.normalized.as_str(),
        ]
    }

    #[cfg(windows)]
    pub(crate) fn binding_values(&self) -> [&str; 7] {
        [
            self.trust_store.normalized.as_str(),
            &self.trust_store.inspection,
            self.project.inspection.normalized.as_str(),
            &self.project.inspection.inspection,
            &self.project.lookup,
            self.selected.normalized.as_str(),
            &self.selected.lookup,
        ]
    }
}

impl Debug for PiProjectTrustEvidence {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PiProjectTrustEvidence")
            .field("trust_store_hash", &self.trust_store_hash)
            .finish_non_exhaustive()
    }
}

/// Effective saved Pi trust for one exact project anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PiProjectTrustStatus {
    Trusted(PiProjectTrustEvidence),
    Declined,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PiProjectTrustError {
    code: &'static str,
    message: &'static str,
}

impl PiProjectTrustError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

/// Reads Pi's documented saved trust store without following links or changing harness state.
pub fn inspect_pi_project_trust(
    trust_store_path: &Path,
    project_anchor: &Path,
) -> Result<PiProjectTrustStatus, PiProjectTrustError> {
    let project_anchor_path = project_anchor;
    let project_anchor = normalized_destination_from_path(project_anchor).map_err(|_| {
        trust_error(
            "pi.project_trust_anchor_invalid",
            "the Pi project trust anchor is not a supported absolute path",
        )
    })?;
    let trust_store_identity =
        normalized_destination_from_path(trust_store_path).map_err(|_| invalid_store())?;
    let TrustStoreRead::Bytes {
        bytes,
        lookup_project_anchor,
    } = read_trust_store(
        trust_store_path,
        project_anchor_path,
        project_anchor.as_str(),
    )?
    else {
        return Ok(PiProjectTrustStatus::Unknown);
    };
    let trust_store_hash = ContentHash::digest(&bytes);
    let entries = parse_trust_store(&bytes)?;
    let selected = find_saved_decision(&entries, &project_anchor, &lookup_project_anchor)?;
    match selected {
        Some((selected_lookup_anchor, true)) => {
            let selected_anchor = normalized_lookup_anchor(&selected_lookup_anchor)?;
            Ok(PiProjectTrustStatus::Trusted(PiProjectTrustEvidence {
                trust_store: InspectionPathBinding::new(
                    trust_store_identity,
                    trust_store_path,
                    invalid_store(),
                )?,
                project: ProjectPathBinding {
                    inspection: InspectionPathBinding::new(
                        project_anchor,
                        project_anchor_path,
                        trust_error(
                            "pi.project_trust_anchor_invalid",
                            "the Pi project trust anchor is not a supported absolute path",
                        ),
                    )?,
                    #[cfg(windows)]
                    lookup: lookup_project_anchor,
                },
                selected: SelectedPathBinding {
                    normalized: selected_anchor,
                    #[cfg(windows)]
                    lookup: selected_lookup_anchor,
                },
                trust_store_hash,
            }))
        }
        Some((_, false)) => Ok(PiProjectTrustStatus::Declined),
        None => Ok(PiProjectTrustStatus::Unknown),
    }
}

enum TrustStoreRead {
    Bytes {
        bytes: Vec<u8>,
        lookup_project_anchor: String,
    },
    Missing,
}

#[cfg(not(windows))]
fn read_trust_store(
    trust_store_path: &Path,
    _project_anchor: &Path,
    normalized_project_anchor: &str,
) -> Result<TrustStoreRead, PiProjectTrustError> {
    let file = match read_bounded_regular_file_with_mode(trust_store_path, MAX_PI_TRUST_BYTES) {
        Ok(file) => file,
        Err(ReadOnlyFileError::Missing) => return Ok(TrustStoreRead::Missing),
        Err(ReadOnlyFileError::Limit) => {
            return Err(trust_error(
                "pi.project_trust_store_limit",
                "the Pi project trust store exceeds the supported bound",
            ));
        }
        Err(ReadOnlyFileError::Unsafe) => {
            return Err(trust_error(
                "pi.project_trust_store_unsafe",
                "the Pi project trust store could not be read safely",
            ));
        }
    };
    if file.mode.unix_mode().is_some_and(|mode| mode & 0o022 != 0) {
        return Err(trust_error(
            "pi.project_trust_store_permissions",
            "the Pi project trust store is writable by another user or group",
        ));
    }
    validate_trust_store_permissions(trust_store_path)?;
    Ok(TrustStoreRead::Bytes {
        bytes: file.bytes,
        lookup_project_anchor: normalized_project_anchor.to_owned(),
    })
}

#[cfg(windows)]
fn read_trust_store(
    trust_store_path: &Path,
    project_anchor: &Path,
    _normalized_project_anchor: &str,
) -> Result<TrustStoreRead, PiProjectTrustError> {
    use kitrove_windows_security::{
        IntegrityFileRead, canonical_nofollow_directory_path, read_bounded_integrity_file,
    };

    match read_bounded_integrity_file(trust_store_path, MAX_PI_TRUST_BYTES) {
        IntegrityFileRead::Bytes(bytes) => {
            let project = canonical_nofollow_directory_path(project_anchor)
                .map_err(|_| trust_anchor_unsafe())?;
            let lookup = project.to_str().ok_or_else(trust_anchor_unsafe)?.to_owned();
            Ok(TrustStoreRead::Bytes {
                bytes,
                lookup_project_anchor: lookup,
            })
        }
        IntegrityFileRead::Missing => Ok(TrustStoreRead::Missing),
        IntegrityFileRead::Limit => Err(trust_error(
            "pi.project_trust_store_limit",
            "the Pi project trust store exceeds the supported bound",
        )),
        IntegrityFileRead::Unsafe => Err(trust_error(
            "pi.project_trust_store_unsafe",
            "the Pi project trust store could not be read safely",
        )),
    }
}

#[cfg(not(windows))]
fn find_saved_decision(
    entries: &BTreeMap<String, bool>,
    project_anchor: &NormalizedDestination,
    _lookup_project_anchor: &str,
) -> Result<Option<(String, bool)>, PiProjectTrustError> {
    let ancestors = project_anchor.strict_ancestor_strings().collect::<Vec<_>>();
    Ok(std::iter::once(project_anchor.as_str())
        .chain(ancestors.into_iter().rev())
        .find_map(|candidate| {
            entries
                .get(candidate)
                .map(|decision| (candidate.to_owned(), *decision))
        }))
}

#[cfg(windows)]
fn find_saved_decision(
    entries: &BTreeMap<String, bool>,
    _project_anchor: &NormalizedDestination,
    lookup_project_anchor: &str,
) -> Result<Option<(String, bool)>, PiProjectTrustError> {
    use kitrove_windows_security::WindowsOrdinalPath;

    let stored_paths = entries
        .keys()
        .map(|stored| {
            WindowsOrdinalPath::new(std::ffi::OsStr::new(stored))
                .map(|encoded| (stored.as_str(), encoded))
                .map_err(|_| invalid_store())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut candidate = Some(Path::new(lookup_project_anchor));
    while let Some(path) = candidate {
        let exact = path.to_str().ok_or_else(invalid_store)?;
        let encoded_candidate =
            WindowsOrdinalPath::new(path.as_os_str()).map_err(|_| invalid_store())?;
        for (stored, encoded_stored) in &stored_paths {
            if *stored != exact
                && encoded_stored
                    .eq_ignore_case(&encoded_candidate)
                    .map_err(|_| invalid_store())?
            {
                return Err(invalid_store());
            }
        }
        if let Some(decision) = entries.get(exact) {
            return Ok(Some((exact.to_owned(), *decision)));
        }
        candidate = path.parent();
    }
    Ok(None)
}

fn normalized_lookup_anchor(value: &str) -> Result<NormalizedDestination, PiProjectTrustError> {
    NormalizedDestination::parse(value).map_err(|_| invalid_store())
}

#[cfg(windows)]
const fn trust_anchor_unsafe() -> PiProjectTrustError {
    trust_error(
        "pi.project_trust_anchor_unsafe",
        "the Pi project trust anchor could not be resolved safely",
    )
}

#[cfg(unix)]
fn validate_trust_store_permissions(path: &Path) -> Result<(), PiProjectTrustError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let expected_owner = rustix::process::geteuid().as_raw();
    let file = std::fs::symlink_metadata(path).map_err(|_| unsafe_permissions())?;
    if file.file_type().is_symlink()
        || !file.is_file()
        || file.uid() != expected_owner
        || file.permissions().mode() & 0o022 != 0
    {
        return Err(unsafe_permissions());
    }
    let mut directory = path.parent().ok_or_else(unsafe_permissions)?;
    loop {
        let metadata = std::fs::symlink_metadata(directory).map_err(|_| unsafe_permissions())?;
        let mode = metadata.permissions().mode();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != expected_owner && metadata.uid() != 0)
            || (mode & 0o022 != 0 && !(metadata.uid() == 0 && mode & 0o1000 != 0))
        {
            return Err(unsafe_permissions());
        }
        let Some(parent) = directory.parent() else {
            break;
        };
        directory = parent;
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_trust_store_permissions(_path: &Path) -> Result<(), PiProjectTrustError> {
    Err(trust_error(
        "pi.project_trust_store_permissions_unverified",
        "Pi project trust store permissions cannot be verified on this platform",
    ))
}

#[cfg(unix)]
const fn unsafe_permissions() -> PiProjectTrustError {
    trust_error(
        "pi.project_trust_store_permissions",
        "the Pi project trust store or its configuration directories have unsafe ownership or permissions",
    )
}

fn parse_trust_store(bytes: &[u8]) -> Result<BTreeMap<String, bool>, PiProjectTrustError> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let entries = deserializer
        .deserialize_map(TrustStoreVisitor)
        .map_err(|_| invalid_store())?;
    deserializer.end().map_err(|_| invalid_store())?;
    Ok(entries)
}

struct TrustStoreVisitor;

impl<'de> Visitor<'de> for TrustStoreVisitor {
    type Value = BTreeMap<String, bool>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Pi project trust object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut entries = BTreeMap::new();
        let mut seen = BTreeSet::new();
        while let Some((path, decision)) = map.next_entry::<String, Option<bool>>()? {
            if seen.len() >= MAX_PI_TRUST_ENTRIES {
                return Err(A::Error::custom("invalid Pi project trust store"));
            }
            let path = parsed_store_key(path)
                .map_err(|_| A::Error::custom("invalid Pi project trust store"))?;
            if !seen.insert(path.clone()) {
                return Err(A::Error::custom("invalid Pi project trust store"));
            }
            if let Some(decision) = decision {
                entries.insert(path, decision);
            }
        }
        Ok(entries)
    }
}

#[cfg(not(windows))]
fn parsed_store_key(path: String) -> Result<String, ()> {
    NormalizedDestination::parse(path)
        .map(|path| path.as_str().to_owned())
        .map_err(|_| ())
}

#[cfg(windows)]
fn parsed_store_key(path: String) -> Result<String, ()> {
    NormalizedDestination::parse(&path).map_err(|_| ())?;
    Ok(path)
}

const fn invalid_store() -> PiProjectTrustError {
    trust_error(
        "pi.project_trust_store_invalid",
        "the Pi project trust store is invalid",
    )
}

const fn trust_error(code: &'static str, message: &'static str) -> PiProjectTrustError {
    PiProjectTrustError { code, message }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    fn write_store(root: &Path, text: &str) -> std::path::PathBuf {
        let pi = root.join(".pi");
        let agent = pi.join("agent");
        fs::create_dir_all(&agent).unwrap();
        #[cfg(unix)]
        for directory in [pi, agent.clone()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = agent.join("trust.json");
        #[cfg(windows)]
        kitrove_windows_security::write_current_user_owned_file_for_tests(&path, text.as_bytes())
            .unwrap();
        #[cfg(not(windows))]
        fs::write(&path, text).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn nearest_saved_decision_wins_and_null_is_not_authority() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let project = canonical_root.join("work/project");
        fs::create_dir_all(&project).unwrap();
        let parent = normalized_destination_from_path(&canonical_root).unwrap();
        let exact = normalized_destination_from_path(&project).unwrap();
        let store = write_store(
            &canonical_root,
            &format!(
                "{{\"{}\":true,\"{}\":null}}",
                parent.as_str(),
                exact.as_str()
            ),
        );
        let PiProjectTrustStatus::Trusted(evidence) =
            inspect_pi_project_trust(&store, &project).unwrap()
        else {
            panic!("parent trust should be inherited");
        };
        assert_eq!(evidence.project_anchor(), &exact);
        assert_eq!(evidence.selected_anchor(), &parent);
    }

    #[cfg(unix)]
    #[test]
    fn nearer_decline_overrides_trusted_parent() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let project = canonical_root.join("work/project");
        fs::create_dir_all(&project).unwrap();
        let parent = normalized_destination_from_path(&canonical_root).unwrap();
        let exact = normalized_destination_from_path(&project).unwrap();
        let store = write_store(
            &canonical_root,
            &format!(
                "{{\"{}\":true,\"{}\":false}}",
                parent.as_str(),
                exact.as_str()
            ),
        );
        assert_eq!(
            inspect_pi_project_trust(&store, &project).unwrap(),
            PiProjectTrustStatus::Declined
        );
    }

    #[cfg(unix)]
    #[test]
    fn malformed_duplicate_and_unsafe_stores_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let project = canonical_root.join("project");
        fs::create_dir(&project).unwrap();
        let normalized = normalized_destination_from_path(&project).unwrap();
        let malformed = [
            "[]".to_owned(),
            "{\"relative\":true}".to_owned(),
            format!(
                "{{\"{}\":true,\"{}\":false}}",
                normalized.as_str(),
                normalized.as_str()
            ),
            format!(
                "{{\"{}\":true,\"{}//project\":false}}",
                normalized.as_str(),
                canonical_root.to_str().unwrap()
            ),
        ];
        for text in malformed {
            let store = write_store(&canonical_root, &text);
            assert_eq!(
                inspect_pi_project_trust(&store, &project)
                    .unwrap_err()
                    .code(),
                "pi.project_trust_store_invalid"
            );
        }
        let target = canonical_root.join("real.json");
        fs::write(&target, "{}").unwrap();
        let store = canonical_root.join(".pi/agent/trust.json");
        fs::remove_file(&store).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &store).unwrap();
        assert_eq!(
            inspect_pi_project_trust(&store, &project)
                .unwrap_err()
                .code(),
            "pi.project_trust_store_unsafe"
        );
    }

    #[cfg(unix)]
    #[test]
    fn documented_utf8_bom_is_accepted_and_bound_into_evidence() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let project = canonical_root.join("project");
        fs::create_dir(&project).unwrap();
        let normalized = normalized_destination_from_path(&project).unwrap();
        let store = write_store(
            &canonical_root,
            &format!("\u{feff}{{\"{}\":true}}", normalized.as_str()),
        );
        assert!(matches!(
            inspect_pi_project_trust(&store, &project).unwrap(),
            PiProjectTrustStatus::Trusted(_)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_exact_canonical_saved_path_is_trust_authority() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root =
            kitrove_windows_security::canonical_directory_path_for_tests(root.path()).unwrap();
        let project = canonical_root.join("Work").join("Project");
        fs::create_dir_all(&project).unwrap();
        let store = write_store(
            &canonical_root,
            &serde_json::to_string(&BTreeMap::from([(project.to_str().unwrap(), true)])).unwrap(),
        );

        let PiProjectTrustStatus::Trusted(evidence) =
            inspect_pi_project_trust(&store, &project).unwrap()
        else {
            panic!("exact canonical Windows path should grant saved trust");
        };
        assert_eq!(evidence.lookup_project_anchor(), project.to_str().unwrap());
        assert_eq!(evidence.selected_lookup_anchor(), project.to_str().unwrap());
        assert!(evidence.revalidate().unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn windows_exact_parent_saved_path_is_inherited() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root =
            kitrove_windows_security::canonical_directory_path_for_tests(root.path()).unwrap();
        let parent = canonical_root.join("Work");
        let project = parent.join("Project");
        fs::create_dir_all(&project).unwrap();
        let store = write_store(
            &canonical_root,
            &serde_json::to_string(&BTreeMap::from([(parent.to_str().unwrap(), true)])).unwrap(),
        );

        let PiProjectTrustStatus::Trusted(evidence) =
            inspect_pi_project_trust(&store, &project).unwrap()
        else {
            panic!("exact canonical Windows parent path should grant inherited saved trust");
        };
        assert_eq!(evidence.lookup_project_anchor(), project.to_str().unwrap());
        assert_eq!(evidence.selected_lookup_anchor(), parent.to_str().unwrap());
        assert_eq!(
            evidence.selected_anchor(),
            &normalized_destination_from_path(&parent).unwrap()
        );
        assert!(evidence.revalidate().unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn windows_equivalent_non_exact_saved_paths_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root =
            kitrove_windows_security::canonical_directory_path_for_tests(root.path()).unwrap();
        let project = canonical_root.join("MixedCase");
        fs::create_dir(&project).unwrap();
        for alias in [
            project.to_str().unwrap().replace("MixedCase", "mixedcase"),
            project.to_str().unwrap().replace('\\', "/"),
        ] {
            let store = write_store(
                &canonical_root,
                &serde_json::to_string(&BTreeMap::from([(alias, true)])).unwrap(),
            );
            assert_eq!(
                inspect_pi_project_trust(&store, &project)
                    .unwrap_err()
                    .code(),
                "pi.project_trust_store_invalid"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_nearest_exact_decline_precedes_aliased_parent_affirmative() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root =
            kitrove_windows_security::canonical_directory_path_for_tests(root.path()).unwrap();
        let project = canonical_root.join("Work").join("Project");
        fs::create_dir_all(&project).unwrap();
        let aliased_parent = project
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        let store = write_store(
            &canonical_root,
            &serde_json::to_string(&BTreeMap::from([
                (project.to_str().unwrap().to_owned(), false),
                (aliased_parent, true),
            ]))
            .unwrap(),
        );

        assert_eq!(
            inspect_pi_project_trust(&store, &project).unwrap(),
            PiProjectTrustStatus::Declined
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_malformed_and_oversized_stores_keep_typed_failures() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root =
            kitrove_windows_security::canonical_directory_path_for_tests(root.path()).unwrap();
        let project = canonical_root.join("Project");
        fs::create_dir(&project).unwrap();
        let store = write_store(&canonical_root, "[]");
        assert_eq!(
            inspect_pi_project_trust(&store, &project)
                .unwrap_err()
                .code(),
            "pi.project_trust_store_invalid"
        );
        fs::write(&store, vec![b' '; MAX_PI_TRUST_BYTES + 1]).unwrap();
        assert_eq!(
            inspect_pi_project_trust(&store, &project)
                .unwrap_err()
                .code(),
            "pi.project_trust_store_limit"
        );
    }

    #[cfg(unix)]
    #[test]
    fn writable_configuration_directory_is_not_trust_authority() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let project = canonical_root.join("project");
        fs::create_dir(&project).unwrap();
        let store = write_store(&canonical_root, "{}");
        fs::set_permissions(store.parent().unwrap(), fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            inspect_pi_project_trust(&store, &project)
                .unwrap_err()
                .code(),
            "pi.project_trust_store_permissions"
        );
    }

    #[cfg(all(not(unix), not(windows)))]
    #[test]
    fn existing_store_fails_closed_without_platform_acl_evidence() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let project = canonical_root.join("project");
        fs::create_dir(&project).unwrap();
        let store = write_store(&canonical_root, "{}");
        assert_eq!(
            inspect_pi_project_trust(&store, &project)
                .unwrap_err()
                .code(),
            "pi.project_trust_store_permissions_unverified"
        );
    }
}
