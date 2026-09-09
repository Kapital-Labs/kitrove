#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use cap_fs_ext::{
    DirEntryExt as _, DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _,
    OpenOptionsSyncExt as _,
};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirEntry, File, Metadata, OpenOptions};
use kitrove_model::{ContentHash, PortablePath};
use unicode_normalization::UnicodeNormalization as _;

#[cfg(windows)]
use cap_fs_ext::OsMetadataExt as _;

use crate::directory_entries::{BoundedDirectoryEntries, collect_bounded_sorted_directory_entries};
use crate::{CaptureLimits, CaptureMeter, SkillError};

/// Maximum directories visited by any captured tree.
pub const MAX_CAPTURE_DIRECTORIES: usize = 512;
/// Maximum directory nesting accepted by any captured tree.
pub const MAX_CAPTURE_DEPTH: usize = 64;

/// The portable mode bits that contribute to captured tree identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileMode {
    Regular,
    Executable,
}

/// Exact bytes and portable mode captured for one regular file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedFile {
    pub mode: FileMode,
    pub bytes: Vec<u8>,
}

/// A deterministic, content-addressed snapshot of a regular-file tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedTree {
    pub files: BTreeMap<PortablePath, CapturedFile>,
    pub hash: ContentHash,
}

/// Optional same-handle policy applied while capturing an already-opened tree.
pub trait CaptureHandleValidator {
    fn validate_directory(&mut self, directory: &Dir) -> bool;
    fn validate_file(&mut self, file: &File) -> bool;
}

/// Refusing request-global meter used by handle-relative metadata-only walks.
pub trait DirectoryWalkMeter {
    fn try_discovery_entry(&mut self) -> bool;
    fn remaining_discovery_entries(&self) -> usize;
}

/// Whether a verified directory should be traversed after it is reported to the visitor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryWalkControl {
    Continue,
    Skip,
    Stop,
}

/// Redacted terminal state from a bounded metadata-only directory walk.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectoryWalkReport {
    pub budget_exhausted: bool,
    pub depth_exhausted: bool,
    pub unsafe_path: bool,
    pub unreadable: bool,
}

/// Captures a directory without following symlinks or accepting non-portable resources.
pub fn capture_tree(root: &Path, limits: CaptureLimits) -> Result<CapturedTree, SkillError> {
    capture_tree_with_hooks(root, limits, &mut NoopCaptureHooks)
}

/// Captures one regular file as a single-entry tree without following links.
pub fn capture_standalone_tree(
    source: &Path,
    limits: CaptureLimits,
) -> Result<(String, CapturedTree), SkillError> {
    capture_standalone_tree_metered(source, limits, &mut crate::CaptureUsage::default())
}

/// Captures a directory already opened as a capability without resolving its ambient path.
pub fn capture_tree_from_dir(
    root: Dir,
    display_path: &Path,
    limits: CaptureLimits,
) -> Result<CapturedTree, SkillError> {
    capture_tree_from_dir_with_validator(root, display_path, limits, &mut NoopHandleValidator)
}

/// Captures an opened tree while validating every opened directory and file before use.
pub fn capture_tree_from_dir_with_validator(
    root: Dir,
    display_path: &Path,
    limits: CaptureLimits,
    validator: &mut dyn CaptureHandleValidator,
) -> Result<CapturedTree, SkillError> {
    let metadata = root
        .dir_metadata()
        .map_err(|error| io_error(display_path, "inspect capture root", &error))?;
    reject_link_like(&metadata, display_path)?;
    if !metadata.is_dir() {
        return Err(special_file_error(display_path));
    }
    validate_directory_handle(validator, &root, display_path)?;
    let mut state = CaptureState::new(limits);
    capture_directories(
        root,
        display_path,
        &mut state,
        &mut NoopCaptureHooks,
        validator,
    )?;
    let hash = hash_tree(&state.files);
    Ok(CapturedTree {
        files: state.files,
        hash,
    })
}

/// Captures one standalone file relative to an already-opened parent capability.
pub fn capture_standalone_tree_from_dir(
    parent: &Dir,
    file_name: &OsStr,
    display_path: &Path,
    limits: CaptureLimits,
) -> Result<(String, CapturedTree), SkillError> {
    let Some(name) = file_name.to_str() else {
        return Err(SkillError::new(
            "capture.non_utf8_path",
            display_path,
            "captured paths must contain only valid UTF-8",
        ));
    };
    validate_portable_segment(display_path, name)?;
    let portable = PortablePath::parse(name.to_owned()).map_err(|error| {
        SkillError::new(
            "capture.invalid_portable_path",
            display_path,
            format!("path is not portable: {error}"),
        )
    })?;
    let metadata = parent.symlink_metadata(file_name).map_err(|error| {
        relative_open_error(
            parent,
            file_name,
            display_path,
            "inspect standalone source without following symlinks",
            &error,
        )
    })?;
    reject_link_like(&metadata, display_path)?;
    if !metadata.is_file() {
        return Err(special_file_error(display_path));
    }
    let mut state = CaptureState::new(limits);
    capture_standalone_file(
        parent,
        file_name,
        display_path,
        portable,
        &metadata,
        &mut state,
        &mut NoopCaptureHooks,
    )?;
    let hash = hash_tree(&state.files);
    Ok((
        name.to_owned(),
        CapturedTree {
            files: state.files,
            hash,
        },
    ))
}

pub fn capture_tree_metered(
    root: &Path,
    limits: CaptureLimits,
    meter: &mut dyn CaptureMeter,
) -> Result<CapturedTree, SkillError> {
    capture_tree_with_hooks(root, limits, &mut MeteredCaptureHooks { meter })
}

pub fn capture_standalone_tree_metered(
    source: &Path,
    limits: CaptureLimits,
    meter: &mut dyn CaptureMeter,
) -> Result<(String, CapturedTree), SkillError> {
    if contains_parent_component(source) {
        return Err(SkillError::new(
            "capture.invalid_root_path",
            source,
            "capture root must not contain parent-directory components",
        ));
    }
    let absolute_source = std::path::absolute(source)
        .map_err(|error| io_error(source, "resolve absolute source path", &error))?;
    let parent_path = absolute_source.parent().ok_or_else(|| {
        SkillError::new(
            "capture.invalid_root_path",
            source,
            "standalone source must have a parent directory",
        )
    })?;
    let file_name = absolute_source.file_name().ok_or_else(|| {
        SkillError::new(
            "capture.invalid_portable_path",
            source,
            "standalone source must have a file name",
        )
    })?;
    let Some(name) = file_name.to_str() else {
        return Err(SkillError::new(
            "capture.non_utf8_path",
            &absolute_source,
            "captured paths must contain only valid UTF-8",
        ));
    };
    validate_portable_segment(&absolute_source, name)?;
    let portable = PortablePath::parse(name.to_owned()).map_err(|error| {
        SkillError::new(
            "capture.invalid_portable_path",
            &absolute_source,
            format!("path is not portable: {error}"),
        )
    })?;
    let parent = open_root(parent_path)?;
    let entry_metadata = parent.symlink_metadata(file_name).map_err(|error| {
        relative_open_error(
            &parent,
            file_name,
            &absolute_source,
            "inspect standalone source without following symlinks",
            &error,
        )
    })?;
    reject_link_like(&entry_metadata, &absolute_source)?;
    if !entry_metadata.is_file() {
        return Err(special_file_error(&absolute_source));
    }

    let mut state = CaptureState::new(limits);
    capture_standalone_file(
        &parent,
        file_name,
        &absolute_source,
        portable,
        &entry_metadata,
        &mut state,
        &mut MeteredCaptureHooks { meter },
    )?;
    let hash = hash_tree(&state.files);
    Ok((
        name.to_owned(),
        CapturedTree {
            files: state.files,
            hash,
        },
    ))
}

fn capture_tree_with_hooks(
    root: &Path,
    limits: CaptureLimits,
    hooks: &mut dyn CaptureHooks,
) -> Result<CapturedTree, SkillError> {
    if contains_parent_component(root) {
        return Err(SkillError::new(
            "capture.invalid_root_path",
            root,
            "capture root must not contain parent-directory components",
        ));
    }
    let absolute_root = std::path::absolute(root)
        .map_err(|error| io_error(root, "resolve absolute root path", &error))?;
    let root_dir = open_root(&absolute_root)?;
    let mut state = CaptureState::new(limits);
    capture_directories(
        root_dir,
        &absolute_root,
        &mut state,
        hooks,
        &mut NoopHandleValidator,
    )?;
    let hash = hash_tree(&state.files);
    Ok(CapturedTree {
        files: state.files,
        hash,
    })
}

/// Hashes a captured tree using Kitrove's versioned, length-delimited framing.
#[must_use]
pub fn hash_tree(files: &BTreeMap<PortablePath, CapturedFile>) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-skill-tree-v1\0");
    for (path, file) in files {
        let path_bytes = path.as_str().as_bytes();
        hasher.update(&(path_bytes.len() as u64).to_be_bytes());
        hasher.update(path_bytes);
        hasher.update(&[match file.mode {
            FileMode::Regular => 0,
            FileMode::Executable => 1,
        }]);
        hasher.update(&(file.bytes.len() as u64).to_be_bytes());
        hasher.update(&file.bytes);
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid ContentHash")
}

/// Walks verified directories through no-follow handles without reading file bodies.
///
/// Each directory enumerates at most the remaining allowance plus one sentinel entry. An
/// overflowing directory is discarded as a unit, so filesystem iteration order cannot choose an
/// arbitrary retained subset.
pub fn walk_directories_nofollow(
    root: &Path,
    max_depth: usize,
    meter: &mut dyn DirectoryWalkMeter,
    visitor: &mut dyn FnMut(&Path, &Path) -> DirectoryWalkControl,
) -> DirectoryWalkReport {
    let mut report = DirectoryWalkReport::default();
    let root_dir = match open_root(root) {
        Ok(directory) => Arc::new(directory),
        Err(error) => {
            report.unsafe_path = matches!(
                error.code(),
                "capture.symlink" | "capture.reparse_point" | "capture.special_file"
            );
            report.unreadable = !report.unsafe_path;
            return report;
        }
    };
    let mut pending = BTreeMap::from([(
        Vec::new(),
        WalkDirectory {
            directory: root_dir,
            absolute: root.to_path_buf(),
            relative: PathBuf::new(),
            depth: 0,
        },
    )]);

    'walk: while let Some((_key, current)) = pending.pop_first() {
        let entries = match current.directory.entries() {
            Ok(entries) => entries,
            Err(_) => {
                report.unreadable = true;
                continue;
            }
        };
        let allowance = meter.remaining_discovery_entries();
        let bounded = match collect_bounded_sorted_directory_entries(entries, allowance) {
            Ok(entries) => entries,
            Err(_) => {
                report.unreadable = true;
                continue;
            }
        };
        let entries = match bounded {
            BoundedDirectoryEntries::Complete(entries) => entries,
            BoundedDirectoryEntries::Overflow => {
                report.budget_exhausted = true;
                break;
            }
        };

        for entry in entries {
            if !meter.try_discovery_entry() {
                report.budget_exhausted = true;
                break 'walk;
            }
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                report.unsafe_path = true;
                continue;
            };
            let absolute = current.absolute.join(&file_name);
            let relative = current.relative.join(name);
            let metadata = match entry.full_metadata() {
                Ok(metadata) => metadata,
                Err(_) => {
                    report.unreadable = true;
                    continue;
                }
            };
            if reject_link_like(&metadata, &absolute).is_err() {
                report.unsafe_path = true;
                continue;
            }
            if metadata.is_file() {
                continue;
            }
            if !metadata.is_dir() {
                report.unsafe_path = true;
                continue;
            }
            let depth = current.depth.saturating_add(1);
            if depth > max_depth {
                report.depth_exhausted = true;
                continue;
            }
            let child = match current.directory.open_dir_nofollow(&file_name) {
                Ok(directory) => directory,
                Err(_) => {
                    report.unsafe_path = true;
                    continue;
                }
            };
            let opened_metadata = match child.dir_metadata() {
                Ok(metadata) => metadata,
                Err(_) => {
                    report.unreadable = true;
                    continue;
                }
            };
            if reject_link_like(&opened_metadata, &absolute).is_err()
                || !opened_metadata.is_dir()
                || !same_file(&metadata, &opened_metadata)
            {
                report.unsafe_path = true;
                continue;
            }
            match visitor(&absolute, &relative) {
                DirectoryWalkControl::Continue => {
                    pending.insert(
                        relative.as_os_str().as_encoded_bytes().to_vec(),
                        WalkDirectory {
                            directory: Arc::new(child),
                            absolute,
                            relative,
                            depth,
                        },
                    );
                }
                DirectoryWalkControl::Skip => {}
                DirectoryWalkControl::Stop => break 'walk,
            }
        }
    }
    report
}

struct WalkDirectory {
    directory: Arc<Dir>,
    absolute: PathBuf,
    relative: PathBuf,
    depth: usize,
}

trait CaptureHooks {
    fn before_open_directory(&mut self, _path: &Path) {}

    fn before_open_file(&mut self, _path: &Path) {}

    fn reserve_file_attempt(&mut self, _path: &Path) -> Result<(), SkillError> {
        Ok(())
    }

    fn before_read_file(&mut self, _path: &Path) {}

    fn read_allowance(&self, requested: u64) -> u64 {
        requested
    }

    fn after_read_file(&mut self, _path: &Path, _bytes_read: u64) -> Result<(), SkillError> {
        Ok(())
    }
}

struct NoopCaptureHooks;

impl CaptureHooks for NoopCaptureHooks {}

struct NoopHandleValidator;

impl CaptureHandleValidator for NoopHandleValidator {
    fn validate_directory(&mut self, _directory: &Dir) -> bool {
        true
    }

    fn validate_file(&mut self, _file: &File) -> bool {
        true
    }
}

struct MeteredCaptureHooks<'a> {
    meter: &'a mut dyn CaptureMeter,
}

impl CaptureHooks for MeteredCaptureHooks<'_> {
    fn reserve_file_attempt(&mut self, path: &Path) -> Result<(), SkillError> {
        if self.meter.try_file_attempt() {
            Ok(())
        } else {
            Err(capture_budget_error(path))
        }
    }

    fn read_allowance(&self, requested: u64) -> u64 {
        requested.min(self.meter.remaining_bytes())
    }

    fn after_read_file(&mut self, path: &Path, bytes_read: u64) -> Result<(), SkillError> {
        if self.meter.try_charge_bytes(bytes_read) {
            Ok(())
        } else {
            Err(capture_budget_error(path))
        }
    }
}

struct CaptureState {
    limits: CaptureLimits,
    files: BTreeMap<PortablePath, CapturedFile>,
    collision_paths: BTreeMap<String, String>,
    total_bytes: u64,
    visited_directories: usize,
    visited_entries: usize,
    max_entries: usize,
}

impl CaptureState {
    fn new(limits: CaptureLimits) -> Self {
        Self {
            max_entries: limits.max_files.saturating_add(MAX_CAPTURE_DIRECTORIES),
            limits,
            files: BTreeMap::new(),
            collision_paths: BTreeMap::new(),
            total_bytes: 0,
            visited_directories: 0,
            visited_entries: 0,
        }
    }

    fn register_portable_path(
        &mut self,
        portable: &PortablePath,
        display_path: &Path,
    ) -> Result<(), SkillError> {
        let key = supported_platform_collision_key(portable.as_str());
        match self.collision_paths.get(&key) {
            Some(existing) if existing != portable.as_str() => {
                return Err(SkillError::new(
                    "capture.path_collision",
                    display_path,
                    "captured paths collide under the supported-platform case-folding key",
                ));
            }
            Some(_) => {}
            None => {
                self.collision_paths
                    .insert(key, portable.as_str().to_owned());
            }
        }
        Ok(())
    }
}

struct PendingEntry {
    entry: DirEntry,
    parent: Arc<Dir>,
    parent_relative: Option<String>,
    parent_key: Vec<u8>,
    file_name: OsString,
    display_path: PathBuf,
    depth: usize,
}

fn capture_directories(
    root_dir: Dir,
    root_path: &Path,
    state: &mut CaptureState,
    hooks: &mut dyn CaptureHooks,
    validator: &mut dyn CaptureHandleValidator,
) -> Result<(), SkillError> {
    let root = Arc::new(root_dir);
    let mut pending = BTreeMap::new();
    enqueue_directory_entries(root, None, Vec::new(), root_path, 0, state, &mut pending)?;

    while let Some((_key, pending_entry)) = pending.pop_first() {
        let PendingEntry {
            entry,
            parent,
            parent_relative,
            parent_key,
            file_name,
            display_path,
            depth: parent_depth,
        } = pending_entry;
        let Some(name) = file_name.to_str() else {
            return Err(SkillError::new(
                "capture.non_utf8_path",
                display_path,
                "captured paths must contain only valid UTF-8",
            ));
        };
        validate_portable_segment(&display_path, name)?;
        let relative = match parent_relative.as_deref() {
            Some(parent) => format!("{parent}/{name}"),
            None => name.to_owned(),
        };
        let portable = PortablePath::parse(relative).map_err(|error| {
            SkillError::new(
                "capture.invalid_portable_path",
                &display_path,
                format!("path is not portable: {error}"),
            )
        })?;
        state.register_portable_path(&portable, &display_path)?;

        let entry_metadata = entry
            .full_metadata()
            .map_err(|error| io_error(&display_path, "inspect directory entry", &error))?;
        reject_link_like(&entry_metadata, &display_path)?;
        if entry_metadata.is_dir() {
            let depth = parent_depth.saturating_add(1);
            if depth > MAX_CAPTURE_DEPTH {
                return Err(SkillError::new(
                    "capture.depth_limit",
                    &display_path,
                    format!("capture exceeds the {MAX_CAPTURE_DEPTH} directory depth limit"),
                ));
            }
            state.visited_directories = state.visited_directories.saturating_add(1);
            if state.visited_directories > MAX_CAPTURE_DIRECTORIES {
                return Err(SkillError::new(
                    "capture.traversal_limit",
                    &display_path,
                    format!(
                        "capture exceeds the {MAX_CAPTURE_DIRECTORIES} directory traversal limit"
                    ),
                ));
            }

            hooks.before_open_directory(&display_path);
            let child = parent.open_dir_nofollow(&file_name).map_err(|error| {
                relative_open_error(
                    &parent,
                    &file_name,
                    &display_path,
                    "open directory without following symlinks",
                    &error,
                )
            })?;
            let child_metadata = child
                .dir_metadata()
                .map_err(|error| io_error(&display_path, "inspect opened directory", &error))?;
            reject_link_like(&child_metadata, &display_path)?;
            if !child_metadata.is_dir() || !same_file(&entry_metadata, &child_metadata) {
                return Err(changed_error(&display_path));
            }
            validate_directory_handle(validator, &child, &display_path)?;

            let mut directory_key = parent_key;
            if !directory_key.is_empty() {
                directory_key.push(b'/');
            }
            directory_key.extend_from_slice(file_name.as_encoded_bytes());
            enqueue_directory_entries(
                Arc::new(child),
                Some(portable.as_str().to_owned()),
                directory_key,
                &display_path,
                depth,
                state,
                &mut pending,
            )?;
        } else if entry_metadata.is_file() {
            capture_file(
                &parent,
                &file_name,
                display_path,
                portable,
                &entry_metadata,
                state,
                hooks,
                validator,
            )?;
        } else {
            return Err(special_file_error(&display_path));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn enqueue_directory_entries(
    directory: Arc<Dir>,
    relative: Option<String>,
    directory_key: Vec<u8>,
    display_path: &Path,
    depth: usize,
    state: &mut CaptureState,
    pending: &mut BTreeMap<Vec<u8>, PendingEntry>,
) -> Result<(), SkillError> {
    let entries = directory
        .entries()
        .map_err(|error| io_error(display_path, "read directory", &error))?;
    let remaining_entry_allowance = state.max_entries.saturating_sub(state.visited_entries);
    let bounded_entries =
        collect_bounded_sorted_directory_entries(entries, remaining_entry_allowance)
            .map_err(|error| io_error(display_path, "read directory entry", &error))?;
    let entries = match bounded_entries {
        BoundedDirectoryEntries::Complete(entries) => entries,
        BoundedDirectoryEntries::Overflow => {
            return Err(SkillError::new(
                "capture.traversal_limit",
                display_path,
                format!(
                    "capture exceeds the {} total entry traversal limit",
                    state.max_entries
                ),
            ));
        }
    };
    state.visited_entries = state.visited_entries.saturating_add(entries.len());

    for entry in entries {
        let file_name = entry.file_name();
        let entry_display_path = display_path.join(&file_name);

        let mut key = directory_key.clone();
        if !key.is_empty() {
            key.push(b'/');
        }
        key.extend_from_slice(file_name.as_encoded_bytes());
        pending.insert(
            key,
            PendingEntry {
                entry,
                parent: Arc::clone(&directory),
                parent_relative: relative.clone(),
                parent_key: directory_key.clone(),
                file_name,
                display_path: entry_display_path,
                depth,
            },
        );
    }
    Ok(())
}

fn open_root(root: &Path) -> Result<Dir, SkillError> {
    let (anchor, components) = split_absolute_root(root)?;
    let mut directory = Dir::open_ambient_dir(&anchor, ambient_authority())
        .map_err(|error| io_error(&anchor, "open filesystem root", &error))?;
    let anchor_metadata = directory
        .dir_metadata()
        .map_err(|error| io_error(&anchor, "inspect opened filesystem root", &error))?;
    reject_link_like(&anchor_metadata, &anchor)?;
    if !anchor_metadata.is_dir() {
        return Err(root_not_directory(&anchor));
    }

    let mut display_path = anchor;
    for component in components {
        display_path.push(&component);
        let entry_metadata = directory.symlink_metadata(&component).map_err(|error| {
            relative_open_error(
                &directory,
                &component,
                &display_path,
                "inspect root path component without following symlinks",
                &error,
            )
        })?;
        reject_link_like(&entry_metadata, &display_path)?;
        if !entry_metadata.is_dir() {
            return Err(root_not_directory(&display_path));
        }

        let child = directory.open_dir_nofollow(&component).map_err(|error| {
            relative_open_error(
                &directory,
                &component,
                &display_path,
                "open root path component without following symlinks",
                &error,
            )
        })?;
        let child_metadata = child.dir_metadata().map_err(|error| {
            io_error(&display_path, "inspect opened root path component", &error)
        })?;
        reject_link_like(&child_metadata, &display_path)?;
        if !child_metadata.is_dir() || !same_file(&entry_metadata, &child_metadata) {
            return Err(changed_error(&display_path));
        }
        directory = child;
    }
    Ok(directory)
}

fn split_absolute_root(root: &Path) -> Result<(PathBuf, Vec<OsString>), SkillError> {
    let mut anchor = PathBuf::new();
    let mut components = Vec::new();
    for component in root.components() {
        match component {
            Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
            Component::RootDir => anchor.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(SkillError::new(
                    "capture.invalid_root_path",
                    root,
                    "capture root must not contain parent-directory components",
                ));
            }
            Component::Normal(component) if component == OsStr::new(".") => {}
            Component::Normal(component) if component == OsStr::new("..") => {
                return Err(SkillError::new(
                    "capture.invalid_root_path",
                    root,
                    "capture root must not contain parent-directory components",
                ));
            }
            Component::Normal(component) => components.push(component.to_owned()),
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err(SkillError::new(
            "capture.invalid_root_path",
            root,
            "capture root must resolve to an absolute filesystem path",
        ));
    }
    Ok((anchor, components))
}

pub(crate) fn contains_parent_component(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(component, Component::ParentDir)
            || matches!(component, Component::Normal(value) if value == OsStr::new(".."))
    }) || raw_parent_component(path)
}

#[cfg(windows)]
fn raw_parent_component(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|segment| segment == "..")
}

#[cfg(not(windows))]
const fn raw_parent_component(_path: &Path) -> bool {
    false
}

#[allow(clippy::too_many_arguments)]
fn capture_file(
    parent: &Dir,
    file_name: &OsStr,
    path: PathBuf,
    portable: PortablePath,
    entry_metadata: &Metadata,
    state: &mut CaptureState,
    hooks: &mut dyn CaptureHooks,
    validator: &mut dyn CaptureHandleValidator,
) -> Result<(), SkillError> {
    if state.files.len() >= state.limits.max_files {
        return Err(SkillError::new(
            "capture.file_count_limit",
            &path,
            format!("capture exceeds the {} file limit", state.limits.max_files),
        ));
    }

    hooks.reserve_file_attempt(&path)?;
    hooks.before_open_file(&path);
    let mut opened = open_file_nofollow(parent, file_name, &path)?;
    let before = opened
        .metadata()
        .map_err(|error| io_error(&path, "inspect opened file", &error))?;
    reject_link_like(&before, &path)?;
    if !before.is_file() {
        return Err(special_file_error(&path));
    }
    if !same_file(entry_metadata, &before) {
        return Err(changed_error(&path));
    }
    validate_file_handle(validator, &opened, &path)?;
    check_initial_file_limits(&path, &before, state)?;

    let remaining_total = state
        .limits
        .max_total_bytes
        .saturating_sub(state.total_bytes);
    hooks.before_read_file(&path);
    let expected_bytes = before.len();
    if hooks.read_allowance(expected_bytes) < expected_bytes {
        return Err(capture_budget_error(&path));
    }
    let bytes = read_bounded(&mut opened, expected_bytes, &path, hooks)?;
    let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if byte_count > state.limits.max_file_bytes {
        return Err(SkillError::new(
            "capture.file_size_limit",
            &path,
            format!(
                "file exceeds the {} byte per-file limit",
                state.limits.max_file_bytes
            ),
        ));
    }
    if byte_count > remaining_total {
        return Err(total_size_error(&path, state.limits.max_total_bytes));
    }

    let after = opened
        .metadata()
        .map_err(|error| io_error(&path, "reinspect opened file", &error))?;
    reject_link_like(&after, &path)?;
    if !metadata_stable(&before, &after, byte_count) {
        return Err(changed_error(&path));
    }
    hooks.reserve_file_attempt(&path)?;
    hooks.before_open_file(&path);
    let reopened = open_file_nofollow(parent, file_name, &path)?;
    let current = reopened
        .metadata()
        .map_err(|error| io_error(&path, "reinspect file entry", &error))?;
    reject_link_like(&current, &path)?;
    if !current.is_file() || !same_file(&after, &current) {
        return Err(changed_error(&path));
    }
    validate_file_handle(validator, &reopened, &path)?;

    state.total_bytes += byte_count;
    state.files.insert(
        portable,
        CapturedFile {
            mode: file_mode(&after),
            bytes,
        },
    );
    Ok(())
}

fn validate_directory_handle(
    validator: &mut dyn CaptureHandleValidator,
    directory: &Dir,
    path: &Path,
) -> Result<(), SkillError> {
    if validator.validate_directory(directory) {
        Ok(())
    } else {
        Err(SkillError::new(
            "capture.handle_policy",
            path,
            "opened directory failed the capture handle policy",
        ))
    }
}

fn validate_file_handle(
    validator: &mut dyn CaptureHandleValidator,
    file: &File,
    path: &Path,
) -> Result<(), SkillError> {
    if validator.validate_file(file) {
        Ok(())
    } else {
        Err(SkillError::new(
            "capture.handle_policy",
            path,
            "opened file failed the capture handle policy",
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn capture_standalone_file(
    parent: &Dir,
    file_name: &OsStr,
    path: &Path,
    portable: PortablePath,
    entry_metadata: &Metadata,
    state: &mut CaptureState,
    hooks: &mut dyn CaptureHooks,
) -> Result<(), SkillError> {
    if state.files.len() >= state.limits.max_files {
        return Err(SkillError::new(
            "capture.file_count_limit",
            path,
            format!("capture exceeds the {} file limit", state.limits.max_files),
        ));
    }

    hooks.reserve_file_attempt(path)?;
    hooks.before_open_file(path);
    let mut opened = open_file_nofollow(parent, file_name, path)?;
    let before = opened
        .metadata()
        .map_err(|error| io_error(path, "inspect opened file", &error))?;
    reject_link_like(&before, path)?;
    if !before.is_file() {
        return Err(special_file_error(path));
    }
    if !same_file(entry_metadata, &before) {
        return Err(changed_error(path));
    }
    check_initial_file_limits(path, &before, state)?;

    hooks.before_read_file(path);
    let expected_bytes = before.len();
    if hooks.read_allowance(expected_bytes) < expected_bytes {
        return Err(capture_budget_error(path));
    }
    let bytes = read_bounded(&mut opened, expected_bytes, path, hooks)?;
    let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if byte_count > state.limits.max_file_bytes {
        return Err(SkillError::new(
            "capture.file_size_limit",
            path,
            format!(
                "file exceeds the {} byte per-file limit",
                state.limits.max_file_bytes
            ),
        ));
    }
    if byte_count > state.limits.max_total_bytes {
        return Err(total_size_error(path, state.limits.max_total_bytes));
    }

    let after = opened
        .metadata()
        .map_err(|error| io_error(path, "reinspect opened file", &error))?;
    reject_link_like(&after, path)?;
    if !metadata_stable(&before, &after, byte_count) {
        return Err(changed_error(path));
    }
    hooks.reserve_file_attempt(path)?;
    hooks.before_open_file(path);
    let reopened = open_file_nofollow(parent, file_name, path)?;
    let current = reopened
        .metadata()
        .map_err(|error| io_error(path, "reinspect file entry", &error))?;
    reject_link_like(&current, path)?;
    if !current.is_file() || !same_file(&after, &current) {
        return Err(changed_error(path));
    }

    state.total_bytes = byte_count;
    state.files.insert(
        portable,
        CapturedFile {
            mode: file_mode(&after),
            bytes,
        },
    );
    Ok(())
}

fn open_file_nofollow(parent: &Dir, file_name: &OsStr, path: &Path) -> Result<File, SkillError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    parent.open_with(file_name, &options).map_err(|error| {
        relative_open_error(
            parent,
            file_name,
            path,
            "open file without following symlinks",
            &error,
        )
    })
}

fn check_initial_file_limits(
    path: &Path,
    metadata: &Metadata,
    state: &CaptureState,
) -> Result<(), SkillError> {
    if metadata.len() > state.limits.max_file_bytes {
        return Err(SkillError::new(
            "capture.file_size_limit",
            path,
            format!(
                "file is {} bytes, exceeding the {} byte per-file limit",
                metadata.len(),
                state.limits.max_file_bytes
            ),
        ));
    }
    let remaining_total = state
        .limits
        .max_total_bytes
        .saturating_sub(state.total_bytes);
    if metadata.len() > remaining_total {
        return Err(total_size_error(path, state.limits.max_total_bytes));
    }
    Ok(())
}

fn relative_open_error(
    parent: &Dir,
    file_name: &OsStr,
    path: &Path,
    action: &str,
    error: &std::io::Error,
) -> SkillError {
    match parent.symlink_metadata(file_name) {
        Ok(metadata) => {
            if let Err(error) = reject_link_like(&metadata, path) {
                return error;
            }
            if !metadata.is_dir() && !metadata.is_file() {
                return special_file_error(path);
            }
            io_error(path, action, error)
        }
        _ => io_error(path, action, error),
    }
}

fn metadata_stable(before: &Metadata, after: &Metadata, bytes_read: u64) -> bool {
    before.is_file()
        && after.is_file()
        && same_file(before, after)
        && before.len() == after.len()
        && after.len() == bytes_read
        && before.modified().ok() == after.modified().ok()
        && file_mode(before) == file_mode(after)
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev() && before.ino() == after.ino()
}

fn read_bounded(
    mut reader: impl Read,
    expected_bytes: u64,
    path: &Path,
    hooks: &mut dyn CaptureHooks,
) -> Result<Vec<u8>, SkillError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    while u64::try_from(bytes.len()).unwrap_or(u64::MAX) < expected_bytes {
        let remaining =
            expected_bytes.saturating_sub(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let requested = remaining.min(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
        let allowance = hooks.read_allowance(requested);
        if allowance == 0 {
            return Err(capture_budget_error(path));
        }
        let allowance = usize::try_from(allowance)
            .unwrap_or(buffer.len())
            .min(buffer.len());
        match reader.read(&mut buffer[..allowance]) {
            Ok(0) => break,
            Ok(read) => {
                hooks.after_read_file(path, u64::try_from(read).unwrap_or(u64::MAX))?;
                bytes.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(path, "read file", &error)),
        }
    }
    Ok(bytes)
}

fn validate_portable_segment(path: &Path, segment: &str) -> Result<(), SkillError> {
    let upper = segment.to_ascii_uppercase();
    let device_base = upper.split('.').next().unwrap_or_default();
    let is_device = matches!(device_base, "CON" | "PRN" | "AUX" | "NUL")
        || device_base.strip_prefix("COM").is_some_and(|number| {
            matches!(
                number,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
        || device_base.strip_prefix("LPT").is_some_and(|number| {
            matches!(
                number,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    let invalid = segment.ends_with(['.', ' '])
        || segment.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        });
    if is_device || invalid {
        return Err(SkillError::new(
            "capture.invalid_portable_path",
            path,
            "path contains a name that is invalid on a supported platform",
        ));
    }
    Ok(())
}

/// The supported-platform collision key applies canonical NFC normalization, default full
/// Unicode case folding, and NFC normalization again to the complete portable path. The second
/// NFC pass composes any decomposed output introduced by folding. This deliberately excludes
/// compatibility normalization so unrelated compatibility characters are not rejected, while
/// conservatively rejecting canonical and full-fold aliases supported filesystems may collapse.
/// U+002F `/` is unchanged by every step, so validated portable separators remain exact.
/// Registering directories as well as files catches sibling and ancestor-component collisions.
fn supported_platform_collision_key(path: &str) -> String {
    let normalized: String = path.nfc().collect();
    unicase::UniCase::unicode(normalized)
        .to_folded_case()
        .nfc()
        .collect()
}

pub(crate) fn has_supported_platform_path_collision<'a>(
    paths: impl IntoIterator<Item = &'a PortablePath>,
) -> bool {
    let mut registered = BTreeMap::new();
    for path in paths {
        let mut prefix = String::new();
        for segment in path.as_str().split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            let key = supported_platform_collision_key(&prefix);
            if registered
                .insert(key, prefix.clone())
                .is_some_and(|existing| existing != prefix)
            {
                return true;
            }
        }
    }
    false
}

fn reject_link_like(metadata: &Metadata, path: &Path) -> Result<(), SkillError> {
    if metadata.is_symlink() {
        return Err(symlink_error(path));
    }
    if metadata_is_windows_reparse(metadata) {
        return Err(reparse_point_error(path));
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_windows_reparse(metadata: &Metadata) -> bool {
    has_windows_reparse_attribute(metadata.file_attributes())
}

#[cfg(not(windows))]
fn metadata_is_windows_reparse(_metadata: &Metadata) -> bool {
    false
}

#[cfg(any(windows, test))]
fn has_windows_reparse_attribute(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn changed_error(path: &Path) -> SkillError {
    SkillError::new(
        "capture.changed_during_read",
        path,
        "resource identity or metadata changed while it was being captured",
    )
}

fn capture_budget_error(path: &Path) -> SkillError {
    SkillError::new(
        "capture.request_budget_exhausted",
        path,
        "request-global capture capacity was exhausted before the next operation",
    )
}

fn special_file_error(path: &Path) -> SkillError {
    SkillError::new(
        "capture.special_file",
        path,
        "only regular files and directories may be captured",
    )
}

fn symlink_error(path: &Path) -> SkillError {
    SkillError::new(
        "capture.symlink",
        path,
        "symlinks are not followed during capture",
    )
}

fn reparse_point_error(path: &Path) -> SkillError {
    SkillError::new(
        "capture.reparse_point",
        path,
        "Windows reparse points are not followed during capture",
    )
}

fn root_not_directory(path: &Path) -> SkillError {
    SkillError::new(
        "capture.root_not_directory",
        path,
        "capture root and every ancestor component must be a directory",
    )
}

fn total_size_error(path: &Path, limit: u64) -> SkillError {
    SkillError::new(
        "capture.total_size_limit",
        path,
        format!("capture exceeds the {limit} byte total limit"),
    )
}

fn io_error(path: &Path, action: &str, error: &std::io::Error) -> SkillError {
    SkillError::new("capture.io", path, format!("failed to {action}: {error}"))
}

#[cfg(unix)]
fn file_mode(metadata: &Metadata) -> FileMode {
    use cap_std::fs::PermissionsExt as _;

    if metadata.permissions().mode() & 0o111 == 0 {
        FileMode::Regular
    } else {
        FileMode::Executable
    }
}

#[cfg(not(unix))]
fn file_mode(_metadata: &Metadata) -> FileMode {
    FileMode::Regular
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;

    #[cfg(unix)]
    use std::path::PathBuf;

    use crate::{CaptureUsage, SkillError};
    use cap_std::ambient_authority;
    use cap_std::fs::{Dir, File};
    use kitrove_model::PortablePath;

    use super::{
        CaptureHandleValidator, CaptureHooks, CaptureLimits, CaptureState,
        capture_tree_from_dir_with_validator, capture_tree_with_hooks,
        has_windows_reparse_attribute, supported_platform_collision_key,
    };

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;

    struct PartialFailureReader {
        consumed: bool,
    }

    #[derive(Default)]
    struct CountingValidator {
        directories: usize,
        files: usize,
        accept_files: bool,
    }

    impl CaptureHandleValidator for CountingValidator {
        fn validate_directory(&mut self, _directory: &Dir) -> bool {
            self.directories += 1;
            true
        }

        fn validate_file(&mut self, _file: &File) -> bool {
            self.files += 1;
            self.accept_files
        }
    }

    #[test]
    fn opened_tree_validator_covers_root_descendants_and_both_file_handles() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::write(root.path().join("nested/file"), b"authority").unwrap();
        let opened = Dir::open_ambient_dir(root.path(), ambient_authority()).unwrap();
        let mut validator = CountingValidator {
            accept_files: true,
            ..CountingValidator::default()
        };

        capture_tree_from_dir_with_validator(
            opened,
            root.path(),
            CaptureLimits::default(),
            &mut validator,
        )
        .unwrap();

        assert_eq!(validator.directories, 2);
        assert_eq!(validator.files, 2);
    }

    #[test]
    fn opened_tree_validator_refuses_before_file_bytes_are_accepted() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("authority"), b"refused").unwrap();
        let opened = Dir::open_ambient_dir(root.path(), ambient_authority()).unwrap();
        let mut validator = CountingValidator::default();

        let error = capture_tree_from_dir_with_validator(
            opened,
            root.path(),
            CaptureLimits::default(),
            &mut validator,
        )
        .unwrap_err();

        assert_eq!(error.code(), "capture.handle_policy");
        assert_eq!(validator.directories, 1);
        assert_eq!(validator.files, 1);
    }

    impl std::io::Read for PartialFailureReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.consumed {
                return Err(io::Error::other("injected read failure"));
            }
            buffer[..3].copy_from_slice(b"abc");
            self.consumed = true;
            Ok(3)
        }
    }

    #[test]
    fn partial_read_error_charges_consumed_bytes() {
        let mut usage = CaptureUsage::default();
        let mut hooks = super::MeteredCaptureHooks { meter: &mut usage };
        let reader = PartialFailureReader { consumed: false };

        let result = super::read_bounded(reader, 4, Path::new("partial.md"), &mut hooks);

        assert!(result.is_err());
        assert_eq!(usage.bytes_read, 3);
    }

    #[test]
    fn windows_reparse_classifier_rejects_name_surrogates_and_other_reparse_attributes() {
        assert!(!has_windows_reparse_attribute(FILE_ATTRIBUTE_NORMAL));
        assert!(!has_windows_reparse_attribute(FILE_ATTRIBUTE_DIRECTORY));
        assert!(has_windows_reparse_attribute(FILE_ATTRIBUTE_REPARSE_POINT));
        assert!(has_windows_reparse_attribute(
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(has_windows_reparse_attribute(
            FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_REPARSE_POINT
        ));
    }

    #[test]
    fn supported_platform_collision_key_case_folds_ascii_and_unicode_lowercase_pairs() {
        assert_eq!(
            supported_platform_collision_key("References/README.md"),
            "references/readme.md"
        );
        assert_eq!(
            supported_platform_collision_key("Ä/file"),
            supported_platform_collision_key("ä/file")
        );
    }

    #[test]
    fn supported_platform_collision_key_composes_literal_nfc_and_nfd_paths() {
        assert_eq!(
            supported_platform_collision_key("Café/Résumé.md"),
            "café/résumé.md"
        );
        assert_eq!(
            supported_platform_collision_key("Cafe\u{301}/Re\u{301}sume\u{301}.md"),
            "café/résumé.md"
        );
    }

    #[test]
    fn supported_platform_collision_key_uses_full_fold_for_literal_sharp_s_and_ss() {
        assert_eq!(
            supported_platform_collision_key("Straße/ß.md"),
            "strasse/ss.md"
        );
        assert_eq!(
            supported_platform_collision_key("STRASSE/SS.md"),
            "strasse/ss.md"
        );
    }

    #[test]
    fn collision_registry_includes_directory_ancestors_before_file_insertion() {
        let mut state = CaptureState::new(CaptureLimits::default());
        let first = PortablePath::parse("References").unwrap();
        let second = PortablePath::parse("references").unwrap();
        state
            .register_portable_path(&first, Path::new("References"))
            .unwrap();

        let error = state
            .register_portable_path(&second, Path::new("references"))
            .unwrap_err();

        assert_eq!(error.code(), "capture.path_collision");
        assert_eq!(error.path(), Path::new("references"));
    }

    #[derive(Default)]
    struct ReadCountingHooks {
        bytes_read: u64,
        reads_started: usize,
    }

    impl CaptureHooks for ReadCountingHooks {
        fn before_read_file(&mut self, _path: &Path) {
            self.reads_started += 1;
        }

        fn after_read_file(&mut self, _path: &Path, bytes_read: u64) -> Result<(), SkillError> {
            self.bytes_read += bytes_read;
            Ok(())
        }
    }

    #[test]
    fn aggregate_ceiling_refuses_a_second_file_before_reading_beyond_it() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a"), b"aa").unwrap();
        std::fs::write(root.path().join("b"), b"bb").unwrap();
        let direct = root.path().canonicalize().unwrap();
        let mut hooks = ReadCountingHooks::default();
        let limits = CaptureLimits {
            max_files: 4,
            max_file_bytes: 2,
            max_total_bytes: 2,
        };

        let error = capture_tree_with_hooks(&direct, limits, &mut hooks).unwrap_err();

        assert_eq!(error.code(), "capture.total_size_limit");
        assert_eq!(hooks.bytes_read, 2);
        assert_eq!(hooks.reads_started, 1);
    }

    #[cfg(unix)]
    enum Replacement {
        Directory { canary: &'static str },
        File { canary: &'static str },
        Fifo,
    }

    #[cfg(unix)]
    struct ReplacingHooks {
        target: PathBuf,
        replacement: Replacement,
        replaced: bool,
        read_started: bool,
    }

    #[cfg(unix)]
    impl ReplacingHooks {
        fn replace(&mut self, path: &Path) {
            if self.replaced || path != self.target {
                return;
            }
            self.replaced = true;
            let original = path.with_extension("captured-original");
            std::fs::rename(path, &original).unwrap();
            match self.replacement {
                Replacement::Directory { canary } => {
                    std::fs::create_dir(path).unwrap();
                    std::fs::write(path.join("external-sentinel"), canary.as_bytes()).unwrap();
                }
                Replacement::File { canary } => {
                    std::fs::write(path, canary.as_bytes()).unwrap();
                }
                Replacement::Fifo => {
                    let status = std::process::Command::new("mkfifo")
                        .arg(path)
                        .status()
                        .expect("mkfifo must be available on supported Unix test hosts");
                    assert!(status.success());
                }
            }
        }
    }

    #[cfg(unix)]
    impl CaptureHooks for ReplacingHooks {
        fn before_open_directory(&mut self, path: &Path) {
            self.replace(path);
        }

        fn before_open_file(&mut self, path: &Path) {
            self.replace(path);
        }

        fn before_read_file(&mut self, path: &Path) {
            if path == self.target {
                self.read_started = true;
            }
        }
    }

    #[cfg(unix)]
    fn direct_temp_root() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let direct = root.path().canonicalize().unwrap();
        (root, direct)
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_directory_replaced_after_enumeration() {
        let canary = "KITROVE_C1_DIRECTORY_REPLACEMENT_CANARY_d5ae5c43";
        let (_root, direct) = direct_temp_root();
        let target = direct.join("references");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("original"), b"verified object").unwrap();
        let mut hooks = ReplacingHooks {
            target,
            replacement: Replacement::Directory { canary },
            replaced: false,
            read_started: false,
        };

        let result = capture_tree_with_hooks(&direct, CaptureLimits::default(), &mut hooks);
        let Err(error) = result else {
            panic!("a replacement directory was captured");
        };

        assert_eq!(error.code(), "capture.changed_during_read");
        assert!(!error.message().contains(canary));
        assert!(!error.to_string().contains(canary));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_regular_file_replaced_before_open_without_reading_the_replacement() {
        let canary = "KITROVE_C1_FILE_REPLACEMENT_CANARY_0a10d8bd";
        let (_root, direct) = direct_temp_root();
        let target = direct.join("payload");
        std::fs::write(&target, b"verified object").unwrap();
        let mut hooks = ReplacingHooks {
            target,
            replacement: Replacement::File { canary },
            replaced: false,
            read_started: false,
        };

        let result = capture_tree_with_hooks(&direct, CaptureLimits::default(), &mut hooks);
        let Err(error) = result else {
            panic!("a replacement file was captured");
        };

        assert_eq!(error.code(), "capture.changed_during_read");
        assert!(!hooks.read_started);
        assert!(!error.message().contains(canary));
        assert!(!error.to_string().contains(canary));
    }

    #[cfg(unix)]
    #[test]
    fn regular_file_to_fifo_replacement_is_refused_before_the_read_boundary() {
        let canary = "KITROVE_C1_FILE_TO_FIFO_CANARY_11f0e24d";
        let (_root, direct) = direct_temp_root();
        let target = direct.join("payload");
        std::fs::write(&target, canary.as_bytes()).unwrap();
        let mut hooks = ReplacingHooks {
            target,
            replacement: Replacement::Fifo,
            replaced: false,
            read_started: false,
        };

        let error = capture_tree_with_hooks(&direct, CaptureLimits::default(), &mut hooks)
            .expect_err("a regular-file-to-FIFO replacement must be refused");

        assert!(matches!(
            error.code(),
            "capture.changed_during_read" | "capture.special_file"
        ));
        assert!(!hooks.read_started);
        assert!(!error.message().contains(canary));
        assert!(!error.to_string().contains(canary));
    }
}
