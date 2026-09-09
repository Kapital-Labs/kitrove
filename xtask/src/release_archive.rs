use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
#[cfg(test)]
use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cap_fs_ext::{FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use kitrove_release_policy::{
    APPLICATION_ARCHIVE_LIMITS, APPLICATION_RELEASE_MANIFEST_NAME, ArchiveFormat,
    BINARY_COMPANIONS, RELEASE_MANIFEST_MAX_ROLLBACK_PREDECESSORS,
    RELEASE_MANIFEST_MAX_VERSION_BYTES,
};
use lzma_rust2::{XzOptions, XzReader, XzWriter};
use semver::Version;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[path = "release_artifact_spec.rs"]
mod artifact_spec;
use artifact_spec::ReleaseArchiveSpec;

#[path = "release_signing.rs"]
mod signing;

#[cfg(test)]
#[path = "release_installer_archive_tests.rs"]
mod installer_tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityCatalog {
    schema: u32,
    releases: Vec<CompatibilityRelease>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityRelease {
    version: String,
    rollback_compatible_predecessors: Vec<String>,
}

struct RetainedFile {
    parent: Dir,
    parent_path: PathBuf,
    parent_identity: (u64, u64),
    leaf: OsString,
    identity: (u64, u64),
    file: File,
    bytes: Vec<u8>,
}

impl RetainedFile {
    fn revalidate(&mut self) -> Result<(), String> {
        let rebound_parent = Dir::open_ambient_dir(&self.parent_path, ambient_authority())
            .map_err(|error| format!("cannot rebind retained directory: {error}"))?;
        let parent_metadata = rebound_parent
            .dir_metadata()
            .map_err(|error| format!("cannot inspect rebound retained directory: {error}"))?;
        if (parent_metadata.dev(), parent_metadata.ino()) != self.parent_identity {
            return Err("retained directory changed".to_owned());
        }
        let metadata = self
            .file
            .metadata()
            .map_err(|error| format!("cannot revalidate retained file: {error}"))?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || (metadata.dev(), metadata.ino()) != self.identity
            || metadata.len() != self.bytes.len() as u64
        {
            return Err("retained file identity or size changed".to_owned());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("cannot rewind retained file: {error}"))?;
        let mut observed = Vec::new();
        Read::by_ref(&mut self.file)
            .take(self.bytes.len() as u64 + 1)
            .read_to_end(&mut observed)
            .map_err(|error| format!("cannot reread retained file: {error}"))?;
        if observed != self.bytes {
            return Err("retained file content changed".to_owned());
        }
        let named = self
            .parent
            .symlink_metadata(&self.leaf)
            .map_err(|error| format!("cannot rebind retained filename: {error}"))?;
        if !named.is_file() || (named.dev(), named.ino()) != self.identity {
            return Err("retained filename changed".to_owned());
        }
        Ok(())
    }
}

const MAX_COMPATIBILITY_CATALOG_BYTES: u64 = 64 * 1024;
const MAX_COMPATIBILITY_RELEASES: usize = 256;
const MAX_DIST_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_INSTALLER_BYTES: u64 = 16 * 1024 * 1024;

pub(super) fn prepare(arguments: Vec<OsString>) -> Result<(), String> {
    prepare_with_signer(arguments, |_, _, _| Ok(None))
}

pub(super) fn prepare_platform_signed(arguments: Vec<OsString>) -> Result<(), String> {
    prepare_with_signer(arguments, signing::sign)
}

fn prepare_with_signer(
    arguments: Vec<OsString>,
    signer: impl FnOnce(&str, &str, &[u8]) -> Result<Option<Vec<u8>>, String>,
) -> Result<(), String> {
    let [archive, target, tag, compatibility, dist_manifest] = exact_arguments::<5>(arguments)?;
    let archive_path = PathBuf::from(archive);
    let compatibility = PathBuf::from(compatibility);
    let dist_manifest = PathBuf::from(dist_manifest);
    let target = utf8_argument(&target, "target")?;
    let version = parse_release_tag(&tag)?;
    let spec = resolve_archive(&archive_path, &target)?;
    let mut original = read_bounded_archive(&archive_path, true)?;
    let mut original_checksum =
        read_bounded_file(&checksum_path(&archive_path), 1024, "checksum", true)?;
    let mut original_dist_manifest = read_bounded_file(
        &dist_manifest,
        MAX_DIST_MANIFEST_BYTES,
        "cargo-dist manifest",
        true,
    )?;
    let original_digest = sha256_hex(&original.bytes);
    validate_checksum_bytes(&archive_path, &original.bytes, &original_checksum.bytes)?;
    validate_dist_manifest(
        &original_dist_manifest.bytes,
        spec,
        &target,
        &original_digest,
    )?;
    // Structural validation precedes any signer or external process. Preparation owns
    // the only archive/checksum writes, and starts them only after signing succeeds.
    let executable = spec.executable_bytes(&original.bytes)?;
    let signed = signer(&target, spec.executable_name(), &executable)?;
    let manifest = spec.render_manifest(
        Sha256::digest(signed.as_deref().unwrap_or(&executable)).into(),
        &version,
        &compatibility,
    )?;
    let mut replacements =
        BTreeMap::from([(APPLICATION_RELEASE_MANIFEST_NAME, manifest.as_slice())]);
    if let Some(bytes) = &signed {
        replacements.insert(spec.executable_name(), bytes.as_slice());
    }

    let prepared = match spec.format() {
        ArchiveFormat::TarXz => {
            let mut files = read_tar_files(spec, &original.bytes)?;
            for (name, bytes) in &replacements {
                files.insert((*name).to_owned(), bytes.to_vec());
            }
            write_tar_archive(spec, &files)?
        }
        ArchiveFormat::Zip => rewrite_zip_archive(&original.bytes, &replacements)?,
    };
    verify_bytes(spec, &prepared, &version)?;
    replace_generated_file(&prepared, &mut original)?;
    write_checksum_sidecar(&archive_path, &prepared, &mut original_checksum)?;
    rewrite_dist_manifest(
        &mut original_dist_manifest,
        spec,
        &target,
        &original_digest,
        &sha256_hex(&prepared),
    )?;
    original.revalidate()?;
    original_checksum.revalidate()?;
    original_dist_manifest.revalidate()?;
    validate_checksum_bytes(&archive_path, &original.bytes, &original_checksum.bytes)?;
    validate_dist_manifest(
        &original_dist_manifest.bytes,
        spec,
        &target,
        &sha256_hex(&original.bytes),
    )?;
    println!("prepared release metadata in {}", archive_path.display());
    Ok(())
}

pub(super) fn verify(arguments: Vec<OsString>) -> Result<(), String> {
    let [archive, target, tag] = exact_arguments::<3>(arguments)?;
    let archive_path = PathBuf::from(archive);
    let target = utf8_argument(&target, "target")?;
    let version = parse_release_tag(&tag)?;
    let spec = resolve_archive(&archive_path, &target)?;
    let mut retained = read_bounded_archive(&archive_path, false)?;
    verify_bytes(spec, &retained.bytes, &version)?;
    verify_checksum_sidecar(&archive_path, &retained.bytes)?;
    retained.revalidate()?;
    println!("verified release manifest in {}", archive_path.display());
    Ok(())
}

pub(super) fn verify_bundle(arguments: Vec<OsString>) -> Result<(), String> {
    let [archive, target, tag, dist_manifest] = exact_arguments::<4>(arguments)?;
    let archive_path = PathBuf::from(archive);
    let target = utf8_argument(&target, "target")?;
    let version = parse_release_tag(&tag)?;
    let spec = resolve_archive(&archive_path, &target)?;
    let mut archive = read_bounded_archive(&archive_path, false)?;
    let mut manifest = read_bounded_file(
        Path::new(&dist_manifest),
        MAX_DIST_MANIFEST_BYTES,
        "cargo-dist manifest",
        false,
    )?;
    verify_bytes(spec, &archive.bytes, &version)?;
    verify_checksum_sidecar(&archive_path, &archive.bytes)?;
    validate_dist_manifest(&manifest.bytes, spec, &target, &sha256_hex(&archive.bytes))?;
    archive.revalidate()?;
    manifest.revalidate()?;
    println!("verified release bundle in {}", archive_path.display());
    Ok(())
}

pub(super) fn harden_powershell(arguments: Vec<OsString>) -> Result<(), String> {
    let [installer, archive, target] = exact_arguments::<3>(arguments)?;
    let installer = PathBuf::from(installer);
    let archive_path = PathBuf::from(archive);
    let target = utf8_argument(&target, "target")?;
    let spec = resolve_archive(&archive_path, &target)?;
    if spec.format() != ArchiveFormat::Zip {
        return Err("PowerShell installer hardening requires the Windows ZIP target".to_owned());
    }
    let mut archive = read_bounded_archive(&archive_path, false)?;
    verify_checksum_sidecar(&archive_path, &archive.bytes)?;
    archive.revalidate()?;
    let mut installer = read_bounded_file(
        &installer,
        MAX_INSTALLER_BYTES,
        "PowerShell installer",
        true,
    )?;
    let source = std::str::from_utf8(&installer.bytes)
        .map_err(|_| "PowerShell installer must be valid UTF-8".to_owned())?;
    let assignment = format!("      \"artifact_name\" = \"{}\"\n", spec.archive_name());
    if source.matches(&assignment).count() != 3 {
        return Err("PowerShell installer has an unexpected Windows platform map".to_owned());
    }
    let digest = sha256_hex(&archive.bytes);
    let replacement = format!("{assignment}      \"sha256\" = \"{digest}\"\n");
    let download = "  Invoke-DownloadFile -client $wc -url $url -path $dir_path\n";
    if source.matches(download).count() != 1 {
        return Err("PowerShell installer has an unexpected download boundary".to_owned());
    }
    let verification = concat!(
        "  Invoke-DownloadFile -client $wc -url $url -path $dir_path\n",
        "  $expected_sha256 = $info[\"sha256\"]\n",
        "  $observed_sha256 = (Get-FileHash -LiteralPath $dir_path -Algorithm SHA256).Hash.ToLowerInvariant()\n",
        "  if ($observed_sha256 -ne $expected_sha256) {\n",
        "    throw \"downloaded archive checksum mismatch\"\n",
        "  }\n",
    );
    let hardened = source
        .replace(&assignment, &replacement)
        .replacen(download, verification, 1);
    if hardened
        .matches(&format!("      \"sha256\" = \"{digest}\"\n"))
        .count()
        != 3
        || hardened
            .matches("Get-FileHash -LiteralPath $dir_path -Algorithm SHA256")
            .count()
            != 1
    {
        return Err("PowerShell installer hardening was incomplete".to_owned());
    }
    replace_generated_file(hardened.as_bytes(), &mut installer)?;
    archive.revalidate()?;
    installer.revalidate()
}

fn exact_arguments<const N: usize>(arguments: Vec<OsString>) -> Result<[OsString; N], String> {
    arguments.try_into().map_err(|arguments: Vec<OsString>| {
        format!("expected {N} arguments, received {}", arguments.len())
    })
}

fn utf8_argument(argument: &OsString, label: &str) -> Result<String, String> {
    argument
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{label} must be valid UTF-8"))
}

fn parse_release_tag(tag: &OsString) -> Result<Version, String> {
    let tag = utf8_argument(tag, "release tag")?;
    let version = tag
        .strip_prefix('v')
        .and_then(|value| Version::parse(value).ok())
        .filter(|version| format!("v{version}") == tag)
        .ok_or_else(|| "release tag must be canonical v-prefixed SemVer".to_owned())?;
    Ok(version)
}

fn resolve_archive(archive: &Path, target: &str) -> Result<ReleaseArchiveSpec, String> {
    ReleaseArchiveSpec::resolve(archive, target)
}

fn read_bounded_archive(path: &Path, writable: bool) -> Result<RetainedFile, String> {
    read_bounded_file(
        path,
        APPLICATION_ARCHIVE_LIMITS.max_archive_bytes,
        "archive",
        writable,
    )
}

fn read_bounded_file(
    path: &Path,
    max_bytes: u64,
    label: &str,
    writable: bool,
) -> Result<RetainedFile, String> {
    let parent_path = path.parent().unwrap_or_else(|| Path::new(".")).to_owned();
    let leaf = path
        .file_name()
        .ok_or_else(|| format!("{label} {} has no filename", path.display()))?
        .to_owned();
    let parent = Dir::open_ambient_dir(&parent_path, ambient_authority())
        .map_err(|error| format!("cannot open {label} directory: {error}"))?;
    let parent_metadata = parent
        .dir_metadata()
        .map_err(|error| format!("cannot inspect {label} directory: {error}"))?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(&leaf, &options)
        .map_err(|error| format!("cannot safely open {label} {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > max_bytes || metadata.nlink() != 1 {
        return Err(format!(
            "{label} {} is not a bounded regular file",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(format!(
            "{label} {} changed while it was read",
            path.display()
        ));
    }
    Ok(RetainedFile {
        parent,
        parent_path,
        parent_identity: (parent_metadata.dev(), parent_metadata.ino()),
        leaf,
        identity: (metadata.dev(), metadata.ino()),
        file,
        bytes,
    })
}

fn checksum_path(archive: &Path) -> PathBuf {
    let mut name = archive.as_os_str().to_owned();
    name.push(".sha256");
    PathBuf::from(name)
}

fn write_checksum_sidecar(
    archive: &Path,
    bytes: &[u8],
    original: &mut RetainedFile,
) -> Result<(), String> {
    let checksum = render_checksum(archive, bytes)?;
    replace_generated_file(checksum.as_bytes(), original)
}

fn verify_checksum_sidecar(archive: &Path, bytes: &[u8]) -> Result<(), String> {
    let checksum_path = checksum_path(archive);
    let mut observed = read_bounded_file(&checksum_path, 1024, "checksum", false)?;
    validate_checksum_bytes(archive, bytes, &observed.bytes)?;
    observed.revalidate()?;
    Ok(())
}

fn validate_checksum_bytes(archive: &Path, bytes: &[u8], checksum: &[u8]) -> Result<(), String> {
    let expected = render_checksum(archive, bytes)?;
    let cargo_dist_expected = format!("{expected}\n");
    if checksum != expected.as_bytes() && checksum != cargo_dist_expected.as_bytes() {
        return Err(format!(
            "checksum {} does not bind the archive bytes",
            checksum_path(archive).display()
        ));
    }
    Ok(())
}

fn render_checksum(archive: &Path, bytes: &[u8]) -> Result<String, String> {
    let file_name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "archive filename must be valid UTF-8".to_owned())?;
    Ok(format!("{} *{file_name}\n", sha256_hex(bytes)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            use std::fmt::Write as _;
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        })
}

fn validate_dist_manifest(
    bytes: &[u8],
    spec: ReleaseArchiveSpec,
    target: &str,
    expected_digest: &str,
) -> Result<String, String> {
    let manifest: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid cargo-dist manifest: {error}"))?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(Value::as_object)
        .ok_or_else(|| "cargo-dist manifest has no artifact map".to_owned())?;
    let mut matched = Vec::new();
    for (id, artifact) in artifacts {
        let Some(artifact) = artifact.as_object() else {
            continue;
        };
        let target_matches = artifact
            .get("target_triples")
            .and_then(Value::as_array)
            .is_some_and(|targets| targets.len() == 1 && targets[0].as_str() == Some(target));
        let path_matches = artifact
            .get("path")
            .and_then(Value::as_str)
            .and_then(|path| Path::new(path).file_name())
            .and_then(|name| name.to_str())
            == Some(spec.archive_name());
        if artifact.get("name").and_then(Value::as_str) == Some(spec.archive_name())
            && artifact.get("kind").and_then(Value::as_str) == Some("executable-zip")
            && target_matches
            && path_matches
        {
            matched.push(id.clone());
        }
    }
    let [id] = matched.as_slice() else {
        return Err("cargo-dist manifest must contain exactly one matching archive".to_owned());
    };
    let artifact = artifacts[id]
        .as_object()
        .expect("matched cargo-dist artifact was an object");
    let expected_checksum = format!("{}.sha256", spec.archive_name());
    let checksum_matches = artifact
        .get("checksum")
        .and_then(Value::as_str)
        .and_then(|path| Path::new(path).file_name())
        .and_then(|name| name.to_str())
        == Some(expected_checksum.as_str());
    if !checksum_matches {
        return Err("cargo-dist artifact does not reference its exact checksum sidecar".to_owned());
    }
    let checksums = artifact
        .get("checksums")
        .and_then(Value::as_object)
        .ok_or_else(|| "cargo-dist artifact has no checksum authority".to_owned())?;
    if checksums.len() != 1
        || checksums.get("sha256").and_then(Value::as_str) != Some(expected_digest)
    {
        return Err("cargo-dist artifact SHA-256 does not bind the archive".to_owned());
    }
    Ok(id.clone())
}

fn rewrite_dist_manifest(
    original: &mut RetainedFile,
    spec: ReleaseArchiveSpec,
    target: &str,
    original_digest: &str,
    digest: &str,
) -> Result<(), String> {
    let id = validate_dist_manifest(&original.bytes, spec, target, original_digest)?;
    let mut manifest: Value = serde_json::from_slice(&original.bytes)
        .map_err(|error| format!("invalid cargo-dist manifest: {error}"))?;
    manifest["artifacts"][&id]["checksums"]["sha256"] = Value::String(digest.to_owned());
    let mut rendered = serde_json::to_vec(&manifest)
        .map_err(|error| format!("cannot render cargo-dist manifest: {error}"))?;
    rendered.push(b'\n');
    validate_dist_manifest(&rendered, spec, target, digest)?;
    replace_generated_file(&rendered, original)
}

fn load_predecessors(path: &Path, version: &Version) -> Result<Vec<Version>, String> {
    let mut retained = read_bounded_file(
        path,
        MAX_COMPATIBILITY_CATALOG_BYTES,
        "compatibility catalog",
        false,
    )?;
    let catalog: CompatibilityCatalog = serde_json::from_slice(&retained.bytes)
        .map_err(|error| format!("invalid compatibility catalog: {error}"))?;
    if catalog.schema != 1 || catalog.releases.len() > MAX_COMPATIBILITY_RELEASES {
        return Err("compatibility catalog schema is unsupported".to_owned());
    }
    let mut observed = BTreeSet::new();
    let mut selected = None;
    for release in catalog.releases {
        if release.rollback_compatible_predecessors.len()
            > RELEASE_MANIFEST_MAX_ROLLBACK_PREDECESSORS
        {
            return Err("compatibility catalog has too many rollback predecessors".to_owned());
        }
        let parsed = parse_compatibility_version(&release.version, "version")?;
        if !observed.insert(parsed.clone()) {
            return Err("compatibility catalog repeats a release version".to_owned());
        }
        if &parsed == version {
            let predecessors = release
                .rollback_compatible_predecessors
                .into_iter()
                .map(|value| parse_compatibility_version(&value, "predecessor"))
                .collect::<Result<Vec<_>, _>>()?;
            selected = Some(predecessors);
        }
    }
    retained.revalidate()?;
    selected.ok_or_else(|| format!("compatibility catalog has no release {version}"))
}

fn parse_compatibility_version(value: &str, label: &str) -> Result<Version, String> {
    if value.len() > RELEASE_MANIFEST_MAX_VERSION_BYTES {
        return Err(format!("compatibility catalog {label} is too long"));
    }
    Version::parse(value)
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or_else(|| format!("compatibility catalog contains a non-canonical {label}"))
}

fn read_tar_files(
    spec: ReleaseArchiveSpec,
    bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let reader = XzReader::new(Cursor::new(bytes), false);
    let mut archive = tar::Archive::new(reader);
    let root = spec.archive_root().expect("TAR specifications have roots");
    let mut files = BTreeMap::new();
    for entry in archive
        .entries()
        .map_err(|error| format!("cannot read TAR entries: {error}"))?
    {
        let mut entry = entry.map_err(|error| format!("cannot read TAR entry: {error}"))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|error| format!("cannot read TAR path: {error}"))?;
        let relative = path
            .strip_prefix(root)
            .ok()
            .and_then(|path| path.to_str())
            .ok_or_else(|| "TAR entry is outside the canonical root".to_owned())?
            .to_owned();
        let mut content = Vec::new();
        entry
            .read_to_end(&mut content)
            .map_err(|error| format!("cannot read TAR file: {error}"))?;
        files.insert(relative, content);
    }
    Ok(files)
}

fn require_exact_release_files(
    spec: ReleaseArchiveSpec,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let expected = BINARY_COMPANIONS
        .into_iter()
        .chain([spec.executable_name()])
        .collect::<BTreeSet<_>>();
    if files.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err("release archive files changed while preparing the manifest".to_owned());
    }
    Ok(())
}

fn write_tar_archive(
    spec: ReleaseArchiveSpec,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, String> {
    require_exact_release_files(spec, files)?;
    let root = spec.archive_root().expect("TAR specifications have roots");
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        append_tar_entry(&mut builder, root, &[], 0o755, true)?;
        for name in BINARY_COMPANIONS
            .into_iter()
            .chain([spec.executable_name()])
        {
            let mode = if name == spec.executable_name() {
                0o755
            } else {
                0o644
            };
            append_tar_entry(
                &mut builder,
                &format!("{root}/{name}"),
                &files[name],
                mode,
                false,
            )?;
        }
        builder
            .finish()
            .map_err(|error| format!("cannot finish TAR archive: {error}"))?;
    }
    let mut writer = XzWriter::new(Vec::new(), XzOptions::with_preset(6))
        .map_err(|error| format!("cannot initialize XZ encoder: {error}"))?;
    writer
        .write_all(&tar_bytes)
        .map_err(|error| format!("cannot compress TAR archive: {error}"))?;
    writer
        .finish()
        .map_err(|error| format!("cannot finish XZ archive: {error}"))
}

fn append_tar_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    bytes: &[u8],
    mode: u32,
    directory: bool,
) -> Result<(), String> {
    let mut header = tar::Header::new_gnu();
    header
        .set_path(path)
        .map_err(|error| format!("cannot set TAR path: {error}"))?;
    header.set_entry_type(if directory {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    header.set_mode(mode);
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    builder
        .append(&header, bytes)
        .map_err(|error| format!("cannot append TAR entry: {error}"))
}

fn rewrite_zip_archive(
    original: &[u8],
    replacements: &BTreeMap<&str, &[u8]>,
) -> Result<Vec<u8>, String> {
    let mut source = ZipArchive::new(Cursor::new(original))
        .map_err(|error| format!("cannot read ZIP: {error}"))?;
    let mut output = Cursor::new(Vec::new());
    {
        let mut archive = ZipWriter::new(&mut output);
        for index in 0..source.len() {
            let entry = source
                .by_index_raw(index)
                .map_err(|error| format!("cannot read raw ZIP entry: {error}"))?;
            if let Some(bytes) = replacements.get(entry.name()) {
                let options = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored)
                    .unix_permissions(entry.unix_mode().unwrap_or(0o644));
                archive
                    .start_file(entry.name(), options)
                    .map_err(|error| format!("cannot start ZIP manifest: {error}"))?;
                archive
                    .write_all(bytes)
                    .map_err(|error| format!("cannot write ZIP manifest: {error}"))?;
            } else {
                archive
                    .raw_copy_file(entry)
                    .map_err(|error| format!("cannot copy ZIP entry: {error}"))?;
            }
        }
        archive
            .finish()
            .map_err(|error| format!("cannot finish ZIP archive: {error}"))?;
    }
    Ok(output.into_inner())
}

fn verify_bytes(spec: ReleaseArchiveSpec, bytes: &[u8], version: &Version) -> Result<(), String> {
    spec.verify(bytes, version)
}

fn replace_generated_file(bytes: &[u8], original: &mut RetainedFile) -> Result<(), String> {
    replace_generated_file_with_hook(bytes, original, || {})
}

fn replace_generated_file_with_hook(
    bytes: &[u8],
    original: &mut RetainedFile,
    after_revalidation: impl FnOnce(),
) -> Result<(), String> {
    original.revalidate()?;
    after_revalidation();

    original
        .file
        .seek(SeekFrom::Start(0))
        .and_then(|_| original.file.write_all(bytes))
        .and_then(|()| original.file.set_len(bytes.len() as u64))
        .and_then(|()| original.file.sync_all())
        .map_err(|error| format!("cannot rewrite retained file: {error}"))?;
    original.bytes = bytes.to_vec();
    original.revalidate()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAR_FIXTURE: &[u8] = include_bytes!(
        "../../crates/kitrove-release-policy/tests/fixtures/archive-conformance/valid_tar_xz/kitrove-cli-aarch64-apple-darwin.tar.xz"
    );
    const ZIP_FIXTURE: &[u8] = include_bytes!(
        "../../crates/kitrove-release-policy/tests/fixtures/archive-conformance/valid_zip/kitrove-cli-x86_64-pc-windows-msvc.zip"
    );

    fn catalog(path: &Path) {
        fs::write(
            path,
            br#"{"schema":1,"releases":[{"version":"0.0.0","rollback_compatible_predecessors":[]}]}"#,
        )
        .unwrap();
    }

    pub(super) fn dist_manifest(path: &Path, archive: &Path, target: &str, bytes: &[u8]) {
        let name = archive.file_name().unwrap().to_str().unwrap();
        let spec = resolve_archive(archive, target).unwrap();
        let executable = spec.executable_name();
        let package = match spec {
            ReleaseArchiveSpec::Application(_) => "kitrove-cli",
            ReleaseArchiveSpec::Installer(_) => "kitrove-installer",
        };
        let manifest = serde_json::json!({
            "announcement_tag": "v0.0.0",
            "announcement_title": format!("{package} 0.0.0"),
            "artifacts": {
                name: {
                    "name": name,
                    "kind": "executable-zip",
                    "target_triples": [target],
                    "path": archive,
                    "checksum": checksum_path(archive),
                    "checksums": {"sha256": sha256_hex(bytes)},
                    "assets": [
                        {"name": "README.md", "path": "README.md", "kind": "readme"},
                        {"id": format!("{target}-exe-{executable}"), "name": executable, "path": executable, "kind": "executable"},
                        {"name": "kitrove-release.json", "path": "kitrove-release.json", "kind": "unknown"}
                    ],
                    "untouched": true
                }
            },
            "releases": [{"app_name": package, "app_version": "0.0.0"}],
            "upload_files": [archive, checksum_path(archive)]
        });
        fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    pub(super) fn prepare_fixture(name: &str, target: &str, fixture: &[u8]) -> Vec<u8> {
        prepare_fixture_with_signer(name, target, fixture, |_, _, _| Ok(None))
    }

    pub(super) fn prepare_fixture_with_signer(
        name: &str,
        target: &str,
        fixture: &[u8],
        signer: impl FnOnce(&str, &str, &[u8]) -> Result<Option<Vec<u8>>, String>,
    ) -> Vec<u8> {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join(name);
        let compatibility = directory.path().join("compatibility.json");
        let manifest = directory.path().join("dist-manifest.json");
        fs::write(&archive, fixture).unwrap();
        fs::write(
            checksum_path(&archive),
            format!("{}\n", render_checksum(&archive, fixture).unwrap()),
        )
        .unwrap();
        catalog(&compatibility);
        dist_manifest(&manifest, &archive, target, fixture);
        prepare_with_signer(
            vec![
                archive.clone().into_os_string(),
                target.into(),
                "v0.0.0".into(),
                compatibility.into_os_string(),
                manifest.clone().into_os_string(),
            ],
            signer,
        )
        .unwrap();
        let prepared = fs::read(&archive).unwrap();
        let expected_checksum = render_checksum(Path::new(name), &prepared).unwrap();
        assert_eq!(
            fs::read_to_string(checksum_path(&archive)).unwrap(),
            expected_checksum
        );
        let manifest_bytes = fs::read(&manifest).unwrap();
        validate_dist_manifest(
            &manifest_bytes,
            resolve_archive(&archive, target).unwrap(),
            target,
            &sha256_hex(&prepared),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&manifest_bytes).unwrap()["artifacts"][name]["untouched"],
            true
        );
        verify(vec![
            archive.clone().into_os_string(),
            target.into(),
            "v0.0.0".into(),
        ])
        .unwrap();
        verify_bundle(vec![
            archive.clone().into_os_string(),
            target.into(),
            "v0.0.0".into(),
            manifest.into_os_string(),
        ])
        .unwrap();
        prepared
    }

    #[test]
    fn prepares_and_verifies_deterministic_tar_and_zip_releases() {
        for (name, target, fixture) in [
            (
                "kitrove-cli-aarch64-apple-darwin.tar.xz",
                "aarch64-apple-darwin",
                TAR_FIXTURE,
            ),
            (
                "kitrove-cli-x86_64-pc-windows-msvc.zip",
                "x86_64-pc-windows-msvc",
                ZIP_FIXTURE,
            ),
        ] {
            let first = prepare_fixture(name, target, fixture);
            let second = prepare_fixture(name, target, fixture);
            assert_eq!(first, second);
        }
    }

    #[test]
    fn signed_application_bytes_define_final_archive_and_digest_authority() {
        for (name, target, fixture) in [
            (
                "kitrove-cli-aarch64-apple-darwin.tar.xz",
                "aarch64-apple-darwin",
                TAR_FIXTURE,
            ),
            (
                "kitrove-cli-x86_64-pc-windows-msvc.zip",
                "x86_64-pc-windows-msvc",
                ZIP_FIXTURE,
            ),
        ] {
            let spec = resolve_archive(Path::new(name), target).unwrap();
            let prepared = prepare_fixture_with_signer(
                name,
                target,
                fixture,
                |actual_target, executable, bytes| {
                    assert_eq!(actual_target, target);
                    assert_eq!(executable, spec.executable_name());
                    assert_eq!(bytes, spec.executable_bytes(fixture).unwrap());
                    Ok(Some(b"synthetic signed executable".to_vec()))
                },
            );
            assert_eq!(
                spec.executable_bytes(&prepared).unwrap(),
                b"synthetic signed executable"
            );
        }
    }

    #[test]
    fn signer_failure_preserves_archive_checksum_and_build_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory
            .path()
            .join("kitrove-cli-aarch64-apple-darwin.tar.xz");
        let compatibility = directory.path().join("compatibility.json");
        let manifest = directory.path().join("dist-manifest.json");
        fs::write(&archive, TAR_FIXTURE).unwrap();
        fs::write(
            checksum_path(&archive),
            render_checksum(&archive, TAR_FIXTURE).unwrap(),
        )
        .unwrap();
        catalog(&compatibility);
        dist_manifest(&manifest, &archive, "aarch64-apple-darwin", TAR_FIXTURE);
        let originals = [&archive, &checksum_path(&archive), &manifest]
            .map(|path| (path.to_owned(), fs::read(path).unwrap()));
        let result = prepare_with_signer(
            vec![
                archive.into_os_string(),
                "aarch64-apple-darwin".into(),
                "v0.0.0".into(),
                compatibility.into_os_string(),
                manifest.into_os_string(),
            ],
            |_, _, _| Err("synthetic signing/notarization rejection".to_owned()),
        );
        assert!(result.unwrap_err().contains("synthetic signing"));
        for (path, bytes) in originals {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn accepts_cargo_dist_checksum_termination_but_rejects_extra_records() {
        let archive = Path::new("archive.tar.xz");
        let canonical = render_checksum(archive, TAR_FIXTURE).unwrap();
        assert!(validate_checksum_bytes(archive, TAR_FIXTURE, canonical.as_bytes()).is_ok());
        assert!(
            validate_checksum_bytes(archive, TAR_FIXTURE, format!("{canonical}\n").as_bytes())
                .is_ok()
        );
        assert!(
            validate_checksum_bytes(archive, TAR_FIXTURE, format!("{canonical}\n\n").as_bytes())
                .is_err()
        );
    }

    #[test]
    fn hardens_the_exact_cargo_dist_powershell_download_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory
            .path()
            .join("kitrove-cli-x86_64-pc-windows-msvc.zip");
        let installer = directory.path().join("kitrove-cli-installer.ps1");
        fs::write(&archive, ZIP_FIXTURE).unwrap();
        fs::write(
            checksum_path(&archive),
            format!("{}\n", render_checksum(&archive, ZIP_FIXTURE).unwrap()),
        )
        .unwrap();
        let assignment = "      \"artifact_name\" = \"kitrove-cli-x86_64-pc-windows-msvc.zip\"\n";
        fs::write(
            &installer,
            format!(
                "{assignment}{assignment}{assignment}  Invoke-DownloadFile -client $wc -url $url -path $dir_path\n"
            ),
        )
        .unwrap();

        harden_powershell(vec![
            installer.clone().into_os_string(),
            archive.into_os_string(),
            "x86_64-pc-windows-msvc".into(),
        ])
        .unwrap();
        let hardened = fs::read_to_string(installer).unwrap();
        let digest = sha256_hex(ZIP_FIXTURE);
        assert_eq!(
            hardened
                .matches(&format!("      \"sha256\" = \"{digest}\""))
                .count(),
            3
        );
        assert_eq!(
            hardened
                .matches("Get-FileHash -LiteralPath $dir_path -Algorithm SHA256")
                .count(),
            1
        );
    }

    #[test]
    fn bounds_the_compatibility_catalog_before_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let compatibility = directory.path().join("compatibility.json");
        let prefix = br#"{"schema":1,"releases":[{"version":"0.0.0","rollback_compatible_predecessors":[]}]}"#;
        let mut exact = prefix.to_vec();
        exact.resize(MAX_COMPATIBILITY_CATALOG_BYTES as usize, b' ');
        fs::write(&compatibility, &exact).unwrap();
        assert_eq!(
            load_predecessors(&compatibility, &Version::new(0, 0, 0)).unwrap(),
            Vec::<Version>::new()
        );
        exact.push(b' ');
        fs::write(&compatibility, exact).unwrap();
        assert!(load_predecessors(&compatibility, &Version::new(0, 0, 0)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_compatibility_catalog() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real.json");
        let compatibility = directory.path().join("compatibility.json");
        catalog(&real);
        symlink(real, &compatibility).unwrap();
        assert!(load_predecessors(&compatibility, &Version::new(0, 0, 0)).is_err());
    }

    #[test]
    fn rejects_inexact_inputs_without_changing_the_archive() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory
            .path()
            .join("kitrove-cli-aarch64-apple-darwin.tar.xz");
        let compatibility = directory.path().join("compatibility.json");
        let manifest = directory.path().join("dist-manifest.json");
        fs::write(&archive, TAR_FIXTURE).unwrap();
        fs::write(
            checksum_path(&archive),
            render_checksum(&archive, TAR_FIXTURE).unwrap(),
        )
        .unwrap();
        dist_manifest(&manifest, &archive, "aarch64-apple-darwin", TAR_FIXTURE);
        fs::write(&compatibility, br#"{"schema":1,"releases":[]}"#).unwrap();
        let before = fs::read(&archive).unwrap();
        assert!(
            prepare(vec![
                archive.clone().into_os_string(),
                "aarch64-apple-darwin".into(),
                "v0.0.0".into(),
                compatibility.into_os_string(),
                manifest.into_os_string(),
            ])
            .is_err()
        );
        assert_eq!(fs::read(&archive).unwrap(), before);

        for arguments in [
            vec![],
            vec![
                archive.clone().into_os_string(),
                "unknown".into(),
                "v0.0.0".into(),
            ],
            vec![
                archive.clone().into_os_string(),
                "aarch64-apple-darwin".into(),
                "0.0.0".into(),
            ],
        ] {
            assert!(verify(arguments).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_and_replaced_archive_paths() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real.tar.xz");
        let archive = directory
            .path()
            .join("kitrove-cli-aarch64-apple-darwin.tar.xz");
        fs::write(&real, TAR_FIXTURE).unwrap();
        symlink(&real, &archive).unwrap();
        assert!(
            verify(vec![
                archive.clone().into_os_string(),
                "aarch64-apple-darwin".into(),
                "v0.0.0".into(),
            ])
            .is_err()
        );

        fs::remove_file(&archive).unwrap();
        fs::write(&archive, TAR_FIXTURE).unwrap();
        let mut retained = read_bounded_archive(&archive, true).unwrap();
        let moved = directory.path().join("moved.tar.xz");
        assert!(
            replace_generated_file_with_hook(TAR_FIXTURE, &mut retained, || {
                fs::rename(&archive, moved).unwrap();
                fs::write(&archive, b"replacement").unwrap();
            })
            .is_err()
        );
        assert_eq!(fs::read(&archive).unwrap(), b"replacement");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_replaced_parent_directories_without_writing_the_replacement() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("distrib");
        let moved = root.path().join("moved");
        fs::create_dir(&directory).unwrap();
        let archive = directory.join("kitrove-cli-aarch64-apple-darwin.tar.xz");
        fs::write(&archive, TAR_FIXTURE).unwrap();
        let mut retained = read_bounded_archive(&archive, true).unwrap();

        assert!(
            replace_generated_file_with_hook(TAR_FIXTURE, &mut retained, || {
                fs::rename(&directory, &moved).unwrap();
                fs::create_dir(&directory).unwrap();
                fs::write(archive.clone(), b"replacement").unwrap();
            })
            .is_err()
        );
        assert_eq!(fs::read(&archive).unwrap(), b"replacement");
    }
}
