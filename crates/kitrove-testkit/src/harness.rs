use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};

use tempfile::TempDir;

use crate::SyntheticHome;

/// Stable, no-follow filesystem evidence for test input trees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemSnapshot {
    pub entries: BTreeMap<String, SnapshotEntry>,
}

/// One no-follow snapshot entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotEntry {
    Directory,
    File { bytes: Vec<u8>, executable: bool },
    Symlink { target: PathBuf },
}

impl FilesystemSnapshot {
    /// Captures a directory recursively without ever descending through a symlink.
    pub fn capture(root: &Path) -> io::Result<Self> {
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "filesystem snapshots require a directory root",
            ));
        }

        let mut entries = BTreeMap::new();
        capture_directory(root, Path::new(""), &mut entries)?;
        Ok(Self { entries })
    }
}

fn capture_directory(
    directory: &Path,
    relative: &Path,
    entries: &mut BTreeMap<String, SnapshotEntry>,
) -> io::Result<()> {
    let mut children = BTreeMap::new();
    for child in std::fs::read_dir(directory)? {
        let child = child?;
        let Some(name) = child.file_name().to_str().map(str::to_owned) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem snapshots require UTF-8 names",
            ));
        };
        children.insert(name, child.path());
    }

    for (name, path) in children {
        let child_relative = relative.join(&name);
        let stable_name = stable_relative_name(&child_relative)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            entries.insert(
                stable_name,
                SnapshotEntry::Symlink {
                    target: std::fs::read_link(&path)?,
                },
            );
        } else if file_type.is_dir() {
            entries.insert(stable_name, SnapshotEntry::Directory);
            capture_directory(&path, &child_relative, entries)?;
        } else if file_type.is_file() {
            entries.insert(
                stable_name,
                SnapshotEntry::File {
                    bytes: std::fs::read(&path)?,
                    executable: is_executable(&metadata),
                },
            );
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem snapshots do not support special files",
            ));
        }
    }
    Ok(())
}

fn stable_relative_name(relative: &Path) -> io::Result<String> {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => parts.push(
                value
                    .to_str()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "filesystem snapshots require UTF-8 names",
                        )
                    })?
                    .to_owned(),
            ),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "filesystem snapshot entry escaped its root",
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// A complete temporary home/project fixture retained for the lifetime of a test.
#[derive(Debug)]
pub struct HarnessFixture {
    tempdir: TempDir,
    home: SyntheticHome,
    repository_root: Option<PathBuf>,
    working_directory: PathBuf,
    standalone_sources: Vec<PathBuf>,
    malformed_sources: Vec<PathBuf>,
    credential_canary_paths: Vec<PathBuf>,
    duplicate_native_ids: BTreeMap<String, usize>,
}

impl HarnessFixture {
    #[must_use]
    pub fn root(&self) -> &Path {
        self.tempdir.path()
    }

    #[must_use]
    pub fn home(&self) -> &SyntheticHome {
        &self.home
    }

    #[must_use]
    pub fn repository_root(&self) -> Option<&Path> {
        self.repository_root.as_deref()
    }

    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    #[must_use]
    pub fn standalone_sources(&self) -> &[PathBuf] {
        &self.standalone_sources
    }

    #[must_use]
    pub fn malformed_sources(&self) -> &[PathBuf] {
        &self.malformed_sources
    }

    #[must_use]
    pub fn credential_canary_paths(&self) -> &[PathBuf] {
        &self.credential_canary_paths
    }

    #[must_use]
    pub fn duplicate_native_ids(&self) -> &BTreeMap<String, usize> {
        &self.duplicate_native_ids
    }

    pub fn snapshot(&self) -> io::Result<FilesystemSnapshot> {
        FilesystemSnapshot::capture(self.root())
    }
}

/// Builds credential-free temporary source layouts for policy and engine tests.
#[derive(Clone, Debug, Default)]
pub struct FixtureBuilder {
    repository: bool,
    user_roots: Vec<PathBuf>,
    directory_skills: Vec<(String, String)>,
    standalone_skills: Vec<(String, String)>,
    malformed_yaml: Vec<String>,
    credential_canaries: Vec<String>,
    duplicate_ids: Vec<String>,
}

impl FixtureBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            repository: false,
            user_roots: Vec::new(),
            directory_skills: Vec::new(),
            standalone_skills: Vec::new(),
            malformed_yaml: Vec::new(),
            credential_canaries: Vec::new(),
            duplicate_ids: Vec::new(),
        }
    }

    #[must_use]
    pub fn repository(mut self) -> Self {
        self.repository = true;
        self
    }

    #[must_use]
    pub fn no_repository(mut self) -> Self {
        self.repository = false;
        self
    }

    #[must_use]
    pub fn user_root(mut self, relative: impl AsRef<Path>) -> Self {
        self.user_roots.push(relative.as_ref().to_path_buf());
        self
    }

    #[must_use]
    pub fn directory_skill(
        mut self,
        native_id: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        self.directory_skills.push((native_id.into(), body.into()));
        self
    }

    #[must_use]
    pub fn standalone_skill(mut self, name: impl Into<String>, body: impl Into<String>) -> Self {
        self.standalone_skills.push((name.into(), body.into()));
        self
    }

    #[must_use]
    pub fn malformed_yaml(mut self, name: impl Into<String>) -> Self {
        self.malformed_yaml.push(name.into());
        self
    }

    #[must_use]
    pub fn credential_canary(mut self, name: impl Into<String>) -> Self {
        self.credential_canaries.push(name.into());
        self
    }

    #[must_use]
    pub fn duplicate_native_ids(mut self, native_id: impl Into<String>) -> Self {
        self.duplicate_ids.push(native_id.into());
        self
    }

    pub fn build(self) -> io::Result<HarnessFixture> {
        let tempdir = tempfile::tempdir()?;
        let root = tempdir.path();
        let home_path = root.join("home");
        std::fs::create_dir_all(&home_path)?;

        let repository_root = self.repository.then(|| root.join("repository"));
        if let Some(repository_root) = &repository_root {
            std::fs::create_dir_all(repository_root.join(".git"))?;
        }
        let working_directory = repository_root.as_ref().map_or_else(
            || root.join("working"),
            |repository| repository.join("working"),
        );
        std::fs::create_dir_all(&working_directory)?;

        let mut user_roots = Vec::new();
        for relative in self.user_roots {
            let relative = checked_relative(&relative)?;
            let path = home_path.join(relative);
            std::fs::create_dir_all(&path)?;
            user_roots.push(path);
        }
        let source_root = user_roots
            .first()
            .cloned()
            .unwrap_or_else(|| root.join("sources"));
        std::fs::create_dir_all(&source_root)?;

        for (native_id, body) in self.directory_skills {
            let native_id = checked_single_name(&native_id)?;
            let directory = source_root.join(native_id);
            std::fs::create_dir_all(&directory)?;
            std::fs::write(directory.join("SKILL.md"), body)?;
        }

        let mut standalone_sources = Vec::new();
        for (name, body) in self.standalone_skills {
            let name = checked_single_name(&name)?;
            let path = source_root.join(name);
            std::fs::write(&path, body)?;
            standalone_sources.push(path);
        }

        let mut malformed_sources = Vec::new();
        for name in self.malformed_yaml {
            let name = checked_single_name(&name)?;
            let path = source_root.join(name);
            std::fs::write(&path, "---\nname: [unterminated\n---\ninert\n")?;
            malformed_sources.push(path);
        }

        let mut credential_canary_paths = Vec::new();
        for name in self.credential_canaries {
            let name = checked_single_name(&name)?;
            let path = root.join("credential-canaries").join(name);
            let parent = path.parent().expect("a joined canary path has a parent");
            std::fs::create_dir_all(parent)?;
            std::fs::write(&path, b"CREDENTIAL_CANARY_NOT_A_SECRET\n")?;
            credential_canary_paths.push(path);
        }

        let mut duplicate_native_ids = BTreeMap::new();
        for native_id in self.duplicate_ids {
            let native_id = checked_single_name(&native_id)?;
            for source in ["first", "second"] {
                let directory = root.join("duplicates").join(source).join(native_id);
                std::fs::create_dir_all(&directory)?;
                std::fs::write(
                    directory.join("SKILL.md"),
                    "---\nname: duplicate\ndescription: inert\n---\nInert prose.\n",
                )?;
            }
            duplicate_native_ids.insert(native_id.to_owned(), 2);
        }

        Ok(HarnessFixture {
            tempdir,
            home: SyntheticHome::new(home_path),
            repository_root,
            working_directory,
            standalone_sources,
            malformed_sources,
            credential_canary_paths,
            duplicate_native_ids,
        })
    }
}

fn checked_relative(path: &Path) -> io::Result<&Path> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fixture paths must be non-empty relative paths without traversal",
        ));
    }
    Ok(path)
}

fn checked_single_name(value: &str) -> io::Result<&str> {
    let path = checked_relative(Path::new(value))?;
    if path.components().count() != 1 || value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fixture source names must contain one non-empty path component",
        ));
    }
    Ok(value)
}
