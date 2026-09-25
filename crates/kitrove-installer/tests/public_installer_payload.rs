//! Operator-only, offline public-artifact acceptance. Never executes the payload.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use kitrove_installer::stage_authenticated_installer_payload;
use kitrove_release_policy::{extract_installer_release, installer_archive_for_target};
use kitrove_release_provenance::{ExpectedReleaseIdentity, verify_installer_archive_attestation};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

fn bounded_read(path: &Path, maximum: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() as u64 <= maximum);
    bytes
}

#[test]
#[ignore = "requires independently acquired RC2 arm64 installer archive and selected bundle"]
fn published_rc2_installer_crosses_the_distinct_payload_boundary() {
    let archive_path = std::env::var_os("KITROVE_TEST_INSTALLER_ARCHIVE").expect("archive path");
    let bundle_path =
        std::env::var_os("KITROVE_TEST_INSTALLER_BUNDLE").expect("single bundle path");
    let archive = bounded_read(Path::new(&archive_path), 256 * 1024 * 1024);
    let mut archive_digest = String::with_capacity(64);
    for byte in Sha256::digest(&archive) {
        write!(&mut archive_digest, "{byte:02x}").unwrap();
    }
    assert_eq!(
        archive_digest,
        "a66e06bbcf03279942f2e6e41bb5b5a33ccd2b1628dfa65d4f19e189a07b7eb1"
    );
    let bundle = bounded_read(Path::new(&bundle_path), 256 * 1024);
    let expected =
        ExpectedReleaseIdentity::new("v0.1.0-rc.2", "11f2d7b7daa1115e23d95121a6f7c923153b3190")
            .unwrap();
    let spec = installer_archive_for_target("aarch64-apple-darwin").unwrap();
    let authenticated = verify_installer_archive_attestation(
        extract_installer_release(spec, &archive).unwrap(),
        &expected,
        &bundle,
    )
    .unwrap();
    let executable_digest = Sha256::digest(authenticated.bytes());
    let signature = kitrove_release_policy::apple_code_directory::candidate_signature(
        authenticated.bytes(),
        "aarch64-apple-darwin",
    )
    .unwrap();
    assert_ne!(signature.cdhash(), &[0; 20]);
    assert_ne!(signature.cms_sha256(), &[0; 32]);
    let root = tempfile::Builder::new()
        .prefix(".kitrove-payload-acceptance-")
        .tempdir_in(std::env::var_os("HOME").expect("ordinary-user home"))
        .unwrap();
    let staged = stage_authenticated_installer_payload(root.path(), authenticated).unwrap();
    staged.revalidate().unwrap();
    let payload = root
        .path()
        .join(".kitrove-installer-bootstrap/installer.payload");
    // Operator-only native API evidence, not the still-unimplemented bounded helper.
    kitrove_macos_signature::inspect_captured_signature(&payload, &signature).unwrap();
    staged.revalidate().unwrap();
    assert_eq!(
        std::fs::metadata(&payload).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        Sha256::digest(bounded_read(&payload, 256 * 1024 * 1024)),
        executable_digest
    );
    drop(staged);
    assert!(payload.is_file());
    // TempDir removes only this test-owned fixture after retained handles close.
}
