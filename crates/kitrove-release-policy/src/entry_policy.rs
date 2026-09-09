use std::collections::BTreeSet;
use std::fmt;

use crate::{
    APPLICATION_ARCHIVE_LIMITS, APPLICATION_RELEASE_MANIFEST_MAX_BYTES,
    APPLICATION_RELEASE_MANIFEST_NAME, ApplicationArchiveSpec, ArchiveFormat, BINARY_COMPANIONS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveEntryKind {
    File,
    Directory,
    Link,
    Special,
}

/// Untrusted metadata reported by an archive decoder.
///
/// Names must be supplied as their original bytes. This deliberately rejects
/// lossy or legacy decoding before path policy is evaluated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveEntrySummary {
    name: String,
    kind: ArchiveEntryKind,
    size: u64,
    mode: Option<u32>,
    encrypted: bool,
}

impl ArchiveEntrySummary {
    pub fn from_utf8_name(
        name: &[u8],
        kind: ArchiveEntryKind,
        size: u64,
        mode: Option<u32>,
        encrypted: bool,
    ) -> Result<Self, ArchivePolicyError> {
        if name.len() > APPLICATION_ARCHIVE_LIMITS.max_path_bytes {
            return Err(ArchivePolicyError::UnsafePath);
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| ArchivePolicyError::InvalidNameEncoding)?
            .to_owned();
        Ok(Self {
            name,
            kind,
            size,
            mode,
            encrypted,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A non-authoritative structural summary of caller-supplied metadata.
///
/// This is not proof that archive bytes were opened, consumed, or verified.
/// Installation authority must use the future crate-owned decoder result that
/// binds those checks to one archive handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationArchiveShapeSummary {
    executable_size: u64,
    release_manifest_size: u64,
}

impl ApplicationArchiveShapeSummary {
    #[must_use]
    pub const fn executable_size(self) -> u64 {
        self.executable_size
    }

    #[must_use]
    pub const fn release_manifest_size(self) -> u64 {
        self.release_manifest_size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchivePolicyError {
    InvalidNameEncoding,
    EntryLimit,
    EntrySize,
    ExpandedSize,
    UnsafePath,
    AmbiguousPath,
    DuplicatePath,
    FileAncestor,
    UnsupportedEntry,
    EncryptedEntry,
    DirectoryPayload,
    UnsafeMode,
    UnexpectedShape,
    EmptyExecutable,
    InvalidReleaseManifestSize,
}

impl fmt::Display for ArchivePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidNameEncoding => "release archive entry name is not valid UTF-8",
            Self::EntryLimit => "release archive exceeds the entry limit",
            Self::EntrySize => "release archive entry exceeds the size limit",
            Self::ExpandedSize => "release archive exceeds the expanded-size limit",
            Self::UnsafePath => "release archive contains an unsafe path",
            Self::AmbiguousPath => "release archive contains a cross-platform ambiguous path",
            Self::DuplicatePath => "release archive contains a duplicate destination",
            Self::FileAncestor => "release archive contains a file/child path conflict",
            Self::UnsupportedEntry => "release archive contains an unsupported entry kind",
            Self::EncryptedEntry => "release archive contains an encrypted entry",
            Self::DirectoryPayload => "release archive directory contains a payload",
            Self::UnsafeMode => "release archive contains unsafe permission bits",
            Self::UnexpectedShape => "release archive does not match the exact application shape",
            Self::EmptyExecutable => "release archive contains an empty application executable",
            Self::InvalidReleaseManifestSize => "release archive manifest has an unsupported size",
        })
    }
}

impl std::error::Error for ArchivePolicyError {}

/// Validates only the supplied entry summaries and exact release shape.
///
/// This does not inspect archive bytes and its result must not authorize
/// extraction or installation.
pub fn validate_application_archive_entry_summaries(
    spec: ApplicationArchiveSpec,
    entries: impl IntoIterator<Item = ArchiveEntrySummary>,
) -> Result<ApplicationArchiveShapeSummary, ArchivePolicyError> {
    let mut accepted = Vec::new();
    let mut destinations = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut expanded_bytes = 0_u64;

    for entry in entries {
        if accepted.len() >= APPLICATION_ARCHIVE_LIMITS.max_entries {
            return Err(ArchivePolicyError::EntryLimit);
        }
        validate_application_archive_entry_summary(&entry)?;
        let key = normalized_path_key(entry.name(), entry.kind == ArchiveEntryKind::Directory)?;
        if !destinations.insert(key.clone()) {
            return Err(ArchivePolicyError::DuplicatePath);
        }
        if entry.kind == ArchiveEntryKind::File {
            files.insert(key);
        }
        expanded_bytes = expanded_bytes
            .checked_add(entry.size)
            .filter(|size| *size <= APPLICATION_ARCHIVE_LIMITS.max_expanded_bytes)
            .ok_or(ArchivePolicyError::ExpandedSize)?;
        accepted.push(entry);
    }

    for file in &files {
        let prefix = format!("{file}/");
        if destinations
            .range(prefix.clone()..)
            .next()
            .is_some_and(|path| path.starts_with(&prefix))
        {
            return Err(ArchivePolicyError::FileAncestor);
        }
    }
    validate_shape(spec, &accepted)
}

pub(crate) fn validate_application_archive_entry_summary(
    entry: &ArchiveEntrySummary,
) -> Result<(), ArchivePolicyError> {
    if !matches!(
        entry.kind,
        ArchiveEntryKind::File | ArchiveEntryKind::Directory
    ) {
        return Err(ArchivePolicyError::UnsupportedEntry);
    }
    if entry.encrypted {
        return Err(ArchivePolicyError::EncryptedEntry);
    }
    if entry.size > APPLICATION_ARCHIVE_LIMITS.max_entry_bytes {
        return Err(ArchivePolicyError::EntrySize);
    }
    if entry.kind == ArchiveEntryKind::Directory && entry.size != 0 {
        return Err(ArchivePolicyError::DirectoryPayload);
    }
    Ok(())
}

fn normalized_path_key(name: &str, directory: bool) -> Result<String, ArchivePolicyError> {
    if name.is_empty()
        || name.len() > APPLICATION_ARCHIVE_LIMITS.max_path_bytes
        || name.starts_with('/')
        || name.contains('\\')
        || name.bytes().any(|byte| byte < 32 || byte == 127)
        || name.as_bytes().get(1) == Some(&b':')
    {
        return Err(ArchivePolicyError::UnsafePath);
    }
    let path = if directory {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    };
    let mut normalized = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(ArchivePolicyError::UnsafePath);
        }
        if component.len() > APPLICATION_ARCHIVE_LIMITS.max_component_bytes
            || !component.is_ascii()
            || !kitrove_windows_names::is_lossless_windows_component(component)
        {
            return Err(ArchivePolicyError::AmbiguousPath);
        }
        normalized.push(component.to_ascii_lowercase());
    }
    Ok(normalized.join("/"))
}

fn validate_shape(
    spec: ApplicationArchiveSpec,
    entries: &[ArchiveEntrySummary],
) -> Result<ApplicationArchiveShapeSummary, ArchivePolicyError> {
    let mut observed_files = BTreeSet::new();
    let mut observed_directories = BTreeSet::new();
    let mut executable_size = None;
    let mut release_manifest_size = None;

    for entry in entries {
        let relative = match (spec.format(), spec.archive_root()) {
            (ArchiveFormat::Zip, None) if !entry.name.contains('/') => entry.name.as_str(),
            (ArchiveFormat::TarXz, Some(root)) if entry.kind == ArchiveEntryKind::Directory => {
                if entry.name.strip_suffix('/').unwrap_or(&entry.name) != root {
                    return Err(ArchivePolicyError::UnexpectedShape);
                }
                observed_directories.insert(root);
                validate_tar_mode(entry, 0o755)?;
                continue;
            }
            (ArchiveFormat::TarXz, Some(root)) => entry
                .name
                .strip_prefix(root)
                .and_then(|name| name.strip_prefix('/'))
                .filter(|name| !name.contains('/'))
                .ok_or(ArchivePolicyError::UnexpectedShape)?,
            _ => return Err(ArchivePolicyError::UnexpectedShape),
        };
        if entry.kind != ArchiveEntryKind::File {
            return Err(ArchivePolicyError::UnexpectedShape);
        }
        if spec.format() == ArchiveFormat::TarXz {
            validate_tar_mode(
                entry,
                if relative == spec.executable_name() {
                    0o755
                } else {
                    0o644
                },
            )?;
        }
        observed_files.insert(relative);
        if relative == spec.executable_name() {
            executable_size = Some(entry.size);
        } else if relative == APPLICATION_RELEASE_MANIFEST_NAME {
            release_manifest_size = Some(entry.size);
        }
    }

    let mut expected_files = BINARY_COMPANIONS.into_iter().collect::<BTreeSet<_>>();
    expected_files.insert(spec.executable_name());
    let expected_directories = spec.archive_root().into_iter().collect::<BTreeSet<_>>();
    if observed_files != expected_files || observed_directories != expected_directories {
        return Err(ArchivePolicyError::UnexpectedShape);
    }
    let executable_size = executable_size
        .filter(|size| *size != 0)
        .ok_or(ArchivePolicyError::EmptyExecutable)?;
    let release_manifest_size = release_manifest_size
        .filter(|size| {
            *size != 0
                && *size
                    <= u64::try_from(APPLICATION_RELEASE_MANIFEST_MAX_BYTES)
                        .expect("manifest bound fits u64")
        })
        .ok_or(ArchivePolicyError::InvalidReleaseManifestSize)?;
    Ok(ApplicationArchiveShapeSummary {
        executable_size,
        release_manifest_size,
    })
}

fn validate_tar_mode(entry: &ArchiveEntrySummary, expected: u32) -> Result<(), ArchivePolicyError> {
    if entry.mode.map(|mode| mode & 0o7777) != Some(expected) {
        return Err(ArchivePolicyError::UnsafeMode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::APPLICATION_ARCHIVES;

    fn summary(
        name: &str,
        kind: ArchiveEntryKind,
        size: u64,
        mode: Option<u32>,
        encrypted: bool,
    ) -> ArchiveEntrySummary {
        ArchiveEntrySummary::from_utf8_name(name.as_bytes(), kind, size, mode, encrypted).unwrap()
    }

    fn valid_names(spec: ApplicationArchiveSpec) -> Vec<String> {
        let mut names = Vec::new();
        if let Some(root) = spec.archive_root() {
            names.push(format!("{root}/"));
            names.extend(
                BINARY_COMPANIONS
                    .into_iter()
                    .chain([spec.executable_name()])
                    .map(|name| format!("{root}/{name}")),
            );
        } else {
            names.extend(
                BINARY_COMPANIONS
                    .into_iter()
                    .chain([spec.executable_name()])
                    .map(str::to_owned),
            );
        }
        names
    }

    fn entries_for(spec: ApplicationArchiveSpec, names: &[String]) -> Vec<ArchiveEntrySummary> {
        names
            .iter()
            .map(|name| {
                let directory = name.ends_with('/');
                let executable = name.ends_with(spec.executable_name());
                summary(
                    name,
                    if directory {
                        ArchiveEntryKind::Directory
                    } else {
                        ArchiveEntryKind::File
                    },
                    u64::from(!directory),
                    match spec.format() {
                        ArchiveFormat::TarXz => Some(if directory || executable {
                            0o755
                        } else {
                            0o644
                        }),
                        ArchiveFormat::Zip => None,
                    },
                    false,
                )
            })
            .collect()
    }

    #[test]
    fn accepts_every_exact_application_archive_shape() {
        for spec in APPLICATION_ARCHIVES {
            let names = valid_names(spec);
            let result =
                validate_application_archive_entry_summaries(spec, entries_for(spec, &names))
                    .expect("canonical application archive shape must pass");
            assert_eq!(result.executable_size(), 1);
            assert_eq!(result.release_manifest_size(), 1);
        }
    }

    #[test]
    fn rejects_invalid_utf8_before_path_validation() {
        assert_eq!(
            ArchiveEntrySummary::from_utf8_name(&[0xff], ArchiveEntryKind::File, 1, None, false,),
            Err(ArchivePolicyError::InvalidNameEncoding)
        );
    }

    #[test]
    fn bounds_raw_names_before_allocation() {
        let exact = vec![b'a'; APPLICATION_ARCHIVE_LIMITS.max_path_bytes];
        assert!(
            ArchiveEntrySummary::from_utf8_name(&exact, ArchiveEntryKind::File, 1, None, false,)
                .is_ok()
        );
        let oversized = vec![b'a'; APPLICATION_ARCHIVE_LIMITS.max_path_bytes + 1];
        assert_eq!(
            ArchiveEntrySummary::from_utf8_name(&oversized, ArchiveEntryKind::File, 1, None, false,),
            Err(ArchivePolicyError::UnsafePath)
        );
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_paths() {
        for name in [
            "../kitrove",
            "/kitrove",
            "C:/kitrove",
            "dir\\kitrove",
            "dir//kitrove",
            "dir/./kitrove",
        ] {
            assert_eq!(
                normalized_path_key(name, false),
                Err(ArchivePolicyError::UnsafePath)
            );
        }
        for name in [
            "CON",
            "aux.txt",
            "CLOCK$",
            "CONIN$.exe",
            "CONOUT$",
            "CON .txt",
            "COM1 .log",
            "COM¹.txt",
            "LPT³",
            "Straße",
            "fullwidth-Ａ",
            "trailing.",
            "bad?name",
        ] {
            assert_eq!(
                normalized_path_key(name, false),
                Err(ArchivePolicyError::AmbiguousPath)
            );
        }
        assert_eq!(
            normalized_path_key(
                &"a".repeat(APPLICATION_ARCHIVE_LIMITS.max_component_bytes + 1),
                false,
            ),
            Err(ArchivePolicyError::AmbiguousPath)
        );
        assert_eq!(
            normalized_path_key(
                &format!(
                    "a/{}",
                    "b".repeat(APPLICATION_ARCHIVE_LIMITS.max_path_bytes)
                ),
                false,
            ),
            Err(ArchivePolicyError::UnsafePath)
        );
    }

    #[test]
    fn rejects_unsupported_encrypted_oversized_and_directory_payload_entries() {
        let cases = [
            (
                summary("file", ArchiveEntryKind::Link, 1, None, false),
                ArchivePolicyError::UnsupportedEntry,
            ),
            (
                summary("file", ArchiveEntryKind::Special, 1, None, false),
                ArchivePolicyError::UnsupportedEntry,
            ),
            (
                summary("file", ArchiveEntryKind::File, 1, None, true),
                ArchivePolicyError::EncryptedEntry,
            ),
            (
                summary(
                    "file",
                    ArchiveEntryKind::File,
                    APPLICATION_ARCHIVE_LIMITS.max_entry_bytes + 1,
                    None,
                    false,
                ),
                ArchivePolicyError::EntrySize,
            ),
            (
                summary("file", ArchiveEntryKind::Directory, 1, None, false),
                ArchivePolicyError::DirectoryPayload,
            ),
        ];
        for (entry, error) in cases {
            assert_eq!(
                validate_application_archive_entry_summary(&entry),
                Err(error)
            );
        }
    }

    #[test]
    fn rejects_duplicate_file_ancestor_and_inexact_shape() {
        let spec = APPLICATION_ARCHIVES[3];
        let duplicate = ["README.md", "readme.md"]
            .map(|name| summary(name, ArchiveEntryKind::File, 1, None, false));
        assert_eq!(
            validate_application_archive_entry_summaries(spec, duplicate),
            Err(ArchivePolicyError::DuplicatePath)
        );

        let ancestor = [
            summary("a", ArchiveEntryKind::File, 1, None, false),
            summary("a/b", ArchiveEntryKind::File, 1, None, false),
        ];
        assert_eq!(
            validate_application_archive_entry_summaries(spec, ancestor),
            Err(ArchivePolicyError::FileAncestor)
        );

        let names = valid_names(spec);
        let mut entries = entries_for(spec, &names);
        entries.pop();
        assert_eq!(
            validate_application_archive_entry_summaries(spec, entries),
            Err(ArchivePolicyError::UnexpectedShape)
        );
    }

    #[test]
    fn rejects_empty_executable_and_wrong_tar_mode() {
        let spec = APPLICATION_ARCHIVES[0];
        let names = valid_names(spec);
        let entries = entries_for(spec, &names);
        let executable_index = entries
            .iter()
            .position(|entry| entry.name.ends_with(spec.executable_name()))
            .unwrap();

        let mut empty = entries.clone();
        empty[executable_index].size = 0;
        assert_eq!(
            validate_application_archive_entry_summaries(spec, empty),
            Err(ArchivePolicyError::EmptyExecutable)
        );

        let mut wrong_mode = entries;
        wrong_mode[executable_index].mode = Some(0o777);
        assert_eq!(
            validate_application_archive_entry_summaries(spec, wrong_mode),
            Err(ArchivePolicyError::UnsafeMode)
        );
    }

    #[test]
    fn enforces_aggregate_entry_and_expanded_size_bounds() {
        let entries = (0..=APPLICATION_ARCHIVE_LIMITS.max_entries).map(|index| {
            summary(
                &format!("entry-{index}"),
                ArchiveEntryKind::File,
                1,
                None,
                false,
            )
        });
        assert_eq!(
            validate_application_archive_entry_summaries(APPLICATION_ARCHIVES[3], entries),
            Err(ArchivePolicyError::EntryLimit)
        );

        let large_entries = ["one", "two", "three", "four", "five"].map(|name| {
            summary(
                name,
                ArchiveEntryKind::File,
                APPLICATION_ARCHIVE_LIMITS.max_entry_bytes,
                None,
                false,
            )
        });
        assert_eq!(
            validate_application_archive_entry_summaries(APPLICATION_ARCHIVES[3], large_entries),
            Err(ArchivePolicyError::ExpandedSize)
        );
    }
}
