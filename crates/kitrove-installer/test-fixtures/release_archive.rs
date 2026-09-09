use std::io::Write as _;

pub(crate) fn archive(
    spec: kitrove_release_policy::ApplicationArchiveSpec,
    version: &semver::Version,
    executable: &[u8],
    predecessors: &[semver::Version],
) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    let entries = kitrove_release_policy::BINARY_COMPANIONS
        .into_iter()
        .map(|name| {
            let body = if name == kitrove_release_policy::APPLICATION_RELEASE_MANIFEST_NAME {
                kitrove_release_policy::render_release_manifest(
                    spec,
                    version,
                    Sha256::digest(executable).into(),
                    predecessors,
                )
                .unwrap()
            } else {
                b"companion".to_vec()
            };
            (name, body, 0o644)
        })
        .chain(std::iter::once((
            spec.executable_name(),
            executable.to_vec(),
            0o755,
        )))
        .collect::<Vec<_>>();
    let Some(root) = spec.archive_root() else {
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes, mode) in entries {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(mode);
            archive.start_file(name, options).unwrap();
            archive.write_all(&bytes).unwrap();
        }
        return archive.finish().unwrap().into_inner();
    };
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        append(&mut builder, &format!("{root}/"), &[], 0o755, true);
        for (name, body, mode) in entries {
            append(&mut builder, &format!("{root}/{name}"), &body, mode, false);
        }
        builder.finish().unwrap();
    }
    let mut writer =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
    writer.write_all(&tar_bytes).unwrap();
    writer.finish().unwrap()
}

fn append(
    builder: &mut tar::Builder<&mut Vec<u8>>,
    path: &str,
    body: &[u8],
    mode: u32,
    directory: bool,
) {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).unwrap();
    header.set_entry_type(if directory {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    header.set_mode(mode);
    header.set_size(body.len() as u64);
    header.set_cksum();
    builder.append(&header, body).unwrap();
}

#[cfg(test)]
mod tests {
    #[test]
    fn windows_zip_fixture_carries_exact_release_bytes_and_compatibility() {
        use kitrove_release_provenance::{
            AuthenticatedApplicationExecutable, ExpectedReleaseIdentity,
        };
        let spec = kitrove_release_policy::application_archive_for_target("x86_64-pc-windows-msvc")
            .unwrap();
        let predecessor = semver::Version::new(1, 2, 3);
        let bytes = super::archive(
            spec,
            &semver::Version::new(1, 2, 4),
            b"Windows candidate",
            std::slice::from_ref(&predecessor),
        );
        let identity =
            ExpectedReleaseIdentity::new("v1.2.4", "0123456789abcdef0123456789abcdef01234567")
                .unwrap();
        let candidate =
            AuthenticatedApplicationExecutable::from_test_archive(spec, &bytes, &identity).unwrap();
        assert_eq!(candidate.bytes(), b"Windows candidate");
        let old_archive = super::archive(spec, &predecessor, b"Windows prior", &[]);
        let old_identity =
            ExpectedReleaseIdentity::new("v1.2.3", identity.source_commit()).unwrap();
        let prior = AuthenticatedApplicationExecutable::from_test_archive(
            spec,
            &old_archive,
            &old_identity,
        )
        .unwrap();
        assert!(
            candidate
                .manifest()
                .declares_rollback_compatibility_to(prior.manifest())
        );
        assert!(
            AuthenticatedApplicationExecutable::from_test_archive(spec, &bytes, &old_identity)
                .is_err()
        );
    }
}
