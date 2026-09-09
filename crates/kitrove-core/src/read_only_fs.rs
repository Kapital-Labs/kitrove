use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, OpenOptions};
use serde::{Deserialize, Serialize};

use crate::filesystem_identity::MetadataIdentity;

pub(crate) enum ReadOnlyRootOpen {
    Open(Dir),
    Missing,
    Unsafe,
}

pub(crate) fn has_single_file_link(metadata: &Metadata) -> bool {
    use cap_fs_ext::MetadataExt as _;

    metadata.nlink() == 1
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadOnlyFileError {
    Missing,
    Unsafe,
    Limit,
}

/// Exact regular-file permission authority retained across guarded replacement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegularFileMode {
    unix_mode: Option<u32>,
    readonly: bool,
}

impl RegularFileMode {
    pub(crate) const fn conservative() -> Self {
        Self {
            #[cfg(unix)]
            unix_mode: Some(0o600),
            #[cfg(not(unix))]
            unix_mode: None,
            readonly: false,
        }
    }

    pub(crate) const fn unix_mode(self) -> Option<u32> {
        self.unix_mode
    }

    pub(crate) const fn readonly(self) -> bool {
        self.readonly
    }

    pub(crate) const fn is_valid_for_platform(self) -> bool {
        #[cfg(unix)]
        {
            matches!(self.unix_mode, Some(mode) if mode <= 0o777 && self.readonly == (mode & 0o222 == 0))
        }
        #[cfg(not(unix))]
        {
            self.unix_mode.is_none()
        }
    }

    pub(crate) fn from_metadata(metadata: &Metadata) -> Result<Self, ReadOnlyFileError> {
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt as _;

            let mode = metadata.permissions().mode() & 0o7777;
            if mode > 0o777 {
                return Err(ReadOnlyFileError::Unsafe);
            }
            Ok(Self {
                unix_mode: Some(mode),
                readonly: metadata.permissions().readonly(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                unix_mode: None,
                readonly: metadata.permissions().readonly(),
            })
        }
    }
}

pub(crate) struct ReadOnlyRegularFile {
    pub(crate) bytes: Vec<u8>,
    pub(crate) mode: RegularFileMode,
}

pub(crate) fn open_root_nofollow(root: &Path) -> ReadOnlyRootOpen {
    let Ok(absolute) = std::path::absolute(root) else {
        return ReadOnlyRootOpen::Unsafe;
    };
    let Ok((anchor, components)) = split_absolute_path(&absolute) else {
        return ReadOnlyRootOpen::Unsafe;
    };
    let Ok(mut directory) = Dir::open_ambient_dir(&anchor, ambient_authority()) else {
        return ReadOnlyRootOpen::Unsafe;
    };
    let Ok(metadata) = directory.dir_metadata() else {
        return ReadOnlyRootOpen::Unsafe;
    };
    if !safe_metadata(&metadata) || !metadata.is_dir() {
        return ReadOnlyRootOpen::Unsafe;
    }
    for component in components {
        let metadata = match directory.symlink_metadata(&component) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ReadOnlyRootOpen::Missing;
            }
            Err(_) => return ReadOnlyRootOpen::Unsafe,
        };
        if !safe_metadata(&metadata) || !metadata.is_dir() {
            return ReadOnlyRootOpen::Unsafe;
        }
        let Ok(child) = directory.open_dir_nofollow(&component) else {
            return ReadOnlyRootOpen::Unsafe;
        };
        let Ok(opened) = child.dir_metadata() else {
            return ReadOnlyRootOpen::Unsafe;
        };
        if !safe_metadata(&opened) || !opened.is_dir() || !same_file(&metadata, &opened) {
            return ReadOnlyRootOpen::Unsafe;
        }
        directory = child;
    }
    ReadOnlyRootOpen::Open(directory)
}

pub(crate) fn read_bounded_regular_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, ReadOnlyFileError> {
    read_bounded_regular_file_with_mode(path, max_bytes).map(|file| file.bytes)
}

pub(crate) fn read_bounded_regular_file_with_mode(
    path: &Path,
    max_bytes: usize,
) -> Result<ReadOnlyRegularFile, ReadOnlyFileError> {
    let absolute = std::path::absolute(path).map_err(|_| ReadOnlyFileError::Unsafe)?;
    let parent_path = absolute.parent().ok_or(ReadOnlyFileError::Unsafe)?;
    let name = absolute.file_name().ok_or(ReadOnlyFileError::Unsafe)?;
    let parent = match open_root_nofollow(parent_path) {
        ReadOnlyRootOpen::Open(parent) => parent,
        ReadOnlyRootOpen::Missing => return Err(ReadOnlyFileError::Missing),
        ReadOnlyRootOpen::Unsafe => return Err(ReadOnlyFileError::Unsafe),
    };
    let before = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReadOnlyFileError::Missing);
        }
        Err(_) => return Err(ReadOnlyFileError::Unsafe),
    };
    if !safe_metadata(&before) || !before.is_file() {
        return Err(ReadOnlyFileError::Unsafe);
    }
    if before.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(ReadOnlyFileError::Limit);
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|_| ReadOnlyFileError::Unsafe)?;
    let opened = file.metadata().map_err(|_| ReadOnlyFileError::Unsafe)?;
    if !safe_metadata(&opened) || !opened.is_file() || !same_file_snapshot(&before, &opened) {
        return Err(ReadOnlyFileError::Unsafe);
    }
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadOnlyFileError::Unsafe)?;
    if bytes.len() > max_bytes {
        return Err(ReadOnlyFileError::Limit);
    }
    let after = file.metadata().map_err(|_| ReadOnlyFileError::Unsafe)?;
    let selected = parent
        .symlink_metadata(name)
        .map_err(|_| ReadOnlyFileError::Unsafe)?;
    if !safe_metadata(&after)
        || !after.is_file()
        || !same_file_snapshot(&opened, &after)
        || !safe_metadata(&selected)
        || !selected.is_file()
        || !same_file_snapshot(&opened, &selected)
    {
        return Err(ReadOnlyFileError::Unsafe);
    }
    let mode = RegularFileMode::from_metadata(&after)?;
    Ok(ReadOnlyRegularFile { bytes, mode })
}

pub(crate) fn safe_metadata(metadata: &Metadata) -> bool {
    !metadata.is_symlink() && !metadata_is_windows_reparse(metadata)
}

pub(crate) fn same_file(left: &Metadata, right: &Metadata) -> bool {
    MetadataIdentity::from_metadata(left) == MetadataIdentity::from_metadata(right)
}

fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    same_file(left, right)
        && left.len() == right.len()
        && matches!(
            (left.modified(), right.modified()),
            (Ok(left), Ok(right)) if left == right
        )
}

fn split_absolute_path(root: &Path) -> Result<(PathBuf, Vec<OsString>), ()> {
    if raw_parent_component(root) {
        return Err(());
    }
    let mut anchor = PathBuf::new();
    let mut components = Vec::new();
    for component in root.components() {
        match component {
            Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
            Component::RootDir => anchor.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(component) if component == OsStr::new(".") => {}
            Component::Normal(component) if component == OsStr::new("..") => return Err(()),
            Component::Normal(component) => components.push(component.to_owned()),
            Component::ParentDir => return Err(()),
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err(());
    }
    Ok((anchor, components))
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

#[cfg(windows)]
fn metadata_is_windows_reparse(metadata: &Metadata) -> bool {
    use cap_fs_ext::OsMetadataExt as _;

    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
const fn metadata_is_windows_reparse(_metadata: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::{ReadOnlyFileError, read_bounded_regular_file};

    #[test]
    fn bounded_reader_accepts_only_the_selected_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let path = root_path.join("known_hosts");
        std::fs::write(&path, b"authority").unwrap();
        assert_eq!(read_bounded_regular_file(&path, 9).unwrap(), b"authority");
        assert_eq!(
            read_bounded_regular_file(&path, 8),
            Err(ReadOnlyFileError::Limit)
        );
        assert_eq!(
            read_bounded_regular_file(&root_path.join("missing"), 9),
            Err(ReadOnlyFileError::Missing)
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_a_symlinked_file_or_parent() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let target = root_path.join("target");
        std::fs::write(&target, b"authority").unwrap();
        let file_link = root_path.join("file-link");
        symlink(&target, &file_link).unwrap();
        assert_eq!(
            read_bounded_regular_file(&file_link, 32),
            Err(ReadOnlyFileError::Unsafe)
        );

        let directory = root_path.join("directory");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("known_hosts"), b"authority").unwrap();
        let parent_link = root_path.join("parent-link");
        symlink(&directory, &parent_link).unwrap();
        assert_eq!(
            read_bounded_regular_file(&parent_link.join("known_hosts"), 32),
            Err(ReadOnlyFileError::Unsafe)
        );
    }
}
