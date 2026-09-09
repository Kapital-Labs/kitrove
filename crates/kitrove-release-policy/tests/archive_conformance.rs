use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use kitrove_release_policy::{
    ArchiveFormat, application_archive_for_target, inspect_tar_xz_application_archive,
    inspect_zip_application_archive,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusCase {
    case: String,
    target: String,
    archive: String,
    accepted: bool,
    sha256: String,
}

const EXPECTED_CASES: [&str; 10] = [
    "valid_tar_xz",
    "valid_zip",
    "tar_unsafe_mode",
    "tar_traversal",
    "tar_extended_metadata",
    "tar_nonzero_padding",
    "tar_concatenated_xz",
    "zip_extra_entry",
    "zip_traversal",
    "zip_corrupt_crc",
];

fn collect_fixture_inventory(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
    directories: &mut BTreeSet<PathBuf>,
) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_owned();
        if kind.is_dir() {
            directories.insert(relative);
            collect_fixture_inventory(root, &path, files, directories)?;
        } else if kind.is_file() {
            if relative != Path::new("README.md") && relative != Path::new("cases.json") {
                files.insert(relative);
            }
        } else {
            return Err(io::Error::other("fixture tree contains a special file"));
        }
    }
    Ok(())
}

#[test]
fn rust_matches_shared_archive_conformance_corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/archive-conformance");
    let manifest = fs::read(root.join("cases.json")).unwrap();
    let cases: Vec<CorpusCase> = serde_json::from_slice(&manifest).unwrap();
    assert_eq!(cases.len(), EXPECTED_CASES.len());
    assert_eq!(
        cases
            .iter()
            .map(|case| case.case.as_str())
            .collect::<BTreeSet<_>>(),
        EXPECTED_CASES.into_iter().collect()
    );
    assert_eq!(
        cases
            .iter()
            .map(|case| case.archive.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        cases.len()
    );

    let manifested_archives = cases
        .iter()
        .map(|case| PathBuf::from(&case.archive))
        .collect::<BTreeSet<_>>();
    let mut actual_archives = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    collect_fixture_inventory(&root, &root, &mut actual_archives, &mut actual_directories).unwrap();
    let expected_directories = cases
        .iter()
        .map(|case| Path::new(&case.archive).parent().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_archives, manifested_archives);
    assert_eq!(actual_directories, expected_directories);

    for case in cases {
        let spec = application_archive_for_target(&case.target).unwrap();
        assert_eq!(
            Path::new(&case.archive).file_name().unwrap(),
            spec.archive_name()
        );
        let archive = fs::read(root.join(&case.archive)).unwrap();
        let observed_digest = Sha256::digest(&archive)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            observed_digest, case.sha256,
            "corpus digest {:?}",
            case.case
        );
        let accepted = match spec.format() {
            ArchiveFormat::TarXz => inspect_tar_xz_application_archive(spec, &archive).is_ok(),
            ArchiveFormat::Zip => inspect_zip_application_archive(spec, &archive).is_ok(),
        };
        assert_eq!(accepted, case.accepted, "corpus case {:?}", case.case);
    }
}
