//! Operator-only, offline public-artifact acceptance. Never executes the payload.

fn main() -> std::process::ExitCode {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return native::run();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        println!("native public-artifact acceptance requires an arm64 Mac");
        if std::env::args_os().len() > 1 {
            std::process::ExitCode::FAILURE
        } else {
            std::process::ExitCode::SUCCESS
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod native {

    use kitrove_installer::stage_authenticated_installer_payload;
    use kitrove_release_policy::apple_code_directory::{
        AppleSignatureCandidate, candidate_signature,
    };
    use kitrove_release_policy::{extract_installer_release, installer_archive_for_target};
    use kitrove_release_provenance::{
        ExpectedReleaseIdentity, verify_installer_archive_attestation,
    };
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

    // Uses the real fixed installer child dispatch in this source-built executable.
    fn inspect_framed(
        path: &Path,
        candidate: &AppleSignatureCandidate,
    ) -> Result<(), kitrove_version_probe::apple_process_identity::IdentityRefused> {
        kitrove_version_probe::apple_process_identity::prepare_verified_suspended_self()?
            .bind_inspection(path, candidate)?
            .inspect_native()
    }

    pub fn run() -> std::process::ExitCode {
        use std::os::unix::ffi::OsStrExt as _;
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.first().is_some_and(|arg| {
            arg.as_bytes() == kitrove_macos_signature::INSPECTION_ARGUMENT.to_bytes()
        }) {
            return kitrove_installer::main_entry();
        }
        if args.is_empty() {
            println!("native public-artifact acceptance skipped; requires --run-native-acceptance");
            return std::process::ExitCode::SUCCESS;
        }
        if args == [std::ffi::OsString::from("--run-interruption-acceptance")] {
            interruption_acceptance();
            return std::process::ExitCode::SUCCESS;
        }
        if args == [std::ffi::OsString::from("--interruption-child")] {
            interruption_child();
            return std::process::ExitCode::SUCCESS;
        }
        assert_eq!(args, [std::ffi::OsString::from("--run-native-acceptance")]);
        published_rc2_installer_crosses_the_distinct_payload_boundary();
        println!("bounded native public-artifact acceptance passed");
        std::process::ExitCode::SUCCESS
    }

    fn pinned_inputs() -> (Vec<u8>, Vec<u8>, ExpectedReleaseIdentity) {
        let archive_path =
            std::env::var_os("KITROVE_TEST_INSTALLER_ARCHIVE").expect("archive path");
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
        (archive, bundle, expected)
    }

    fn authenticate_pinned() -> kitrove_release_provenance::AuthenticatedInstallerExecutable {
        let (archive, bundle, expected) = pinned_inputs();
        let spec = installer_archive_for_target("aarch64-apple-darwin").unwrap();
        verify_installer_archive_attestation(
            extract_installer_release(spec, &archive).unwrap(),
            &expected,
            &bundle,
        )
        .unwrap()
    }

    fn published_rc2_installer_crosses_the_distinct_payload_boundary() {
        let (archive, bundle, expected) = pinned_inputs();
        let spec = installer_archive_for_target("aarch64-apple-darwin").unwrap();
        let authenticated = verify_installer_archive_attestation(
            extract_installer_release(spec, &archive).unwrap(),
            &expected,
            &bundle,
        )
        .unwrap();
        let executable_digest = Sha256::digest(authenticated.bytes());
        let original = authenticated.bytes().to_vec();
        let signature = candidate_signature(&original, "aarch64-apple-darwin").unwrap();
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
        // Only the independently source-built verifier runs; payload stays mode 0600.
        staged.verify_native_signature().unwrap();
        staged.revalidate().unwrap();
        assert_eq!(
            std::fs::metadata(&payload).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            Sha256::digest(bounded_read(&payload, 256 * 1024 * 1024)),
            executable_digest
        );

        let publication_root = tempfile::Builder::new()
            .prefix(".kitrove-publication-acceptance-")
            .tempdir_in(std::env::var_os("HOME").unwrap())
            .unwrap();
        let publication_input = verify_installer_archive_attestation(
            extract_installer_release(spec, &archive).unwrap(),
            &expected,
            &bundle,
        )
        .unwrap();
        let published =
            stage_authenticated_installer_payload(publication_root.path(), publication_input)
                .unwrap()
                .publish_native()
                .unwrap();
        published.revalidate().unwrap();
        let published_path = publication_root
            .path()
            .join(".kitrove-installer-bootstrap/kitrove-installer");
        assert_eq!(
            std::fs::metadata(&published_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            Sha256::digest(bounded_read(&published_path, 256 * 1024 * 1024)),
            executable_digest
        );
        drop(published);
        assert!(published_path.is_file());
        let reopened = kitrove_installer::PublishedInstallerPayload::reopen(
            publication_root.path(),
            verify_installer_archive_attestation(
                extract_installer_release(spec, &archive).unwrap(),
                &expected,
                &bundle,
            )
            .unwrap(),
        )
        .unwrap();
        reopened.revalidate().unwrap();
        drop(reopened);
        // Publication is checked as data only. Never launch the downloaded binary.

        // This exact pinned fixture ends with CMS content followed by zero padding.
        // Prove that the selected mutation affects only CMS before using it as a test.
        let mut changed_cms = original.clone();
        let last_content = changed_cms.iter().rposition(|byte| *byte != 0).unwrap();
        changed_cms[last_content] ^= 1;
        let changed_signature = candidate_signature(&changed_cms, "aarch64-apple-darwin").unwrap();
        assert_eq!(signature.cdhash(), changed_signature.cdhash());
        assert_ne!(signature.cms_sha256(), changed_signature.cms_sha256());

        // A valid signature at the path cannot satisfy a different captured CMS.
        assert!(inspect_framed(&payload, &changed_signature).is_err());
        staged.revalidate().unwrap();

        // Matching fingerprints of corrupted CMS are not cryptographic authority.
        std::fs::write(&payload, &changed_cms).unwrap();
        assert!(inspect_framed(&payload, &changed_signature).is_err());
        assert!(staged.verify_native_signature().is_err());
        assert!(staged.revalidate().is_err());

        // Code-page substitution must fail independently of captured signature data.
        let mut changed_code = original;
        // Offset 4096 lies in the pinned fixture's signed prefix, outside its header.
        changed_code[4096] ^= 1;
        assert!(candidate_signature(&changed_code, "aarch64-apple-darwin").is_err());
        std::fs::write(&payload, &changed_code).unwrap();
        assert!(inspect_framed(&payload, &signature).is_err());
        assert!(staged.verify_native_signature().is_err());
        assert!(staged.revalidate().is_err());
        drop(staged);
        assert!(payload.is_file());
        // TempDir removes only this test-owned fixture after retained handles close.
    }

    struct OwnedChild(std::process::Child);

    impl OwnedChild {
        fn spawn(root: &Path, phase: &str, action: &str) -> Self {
            Self(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--interruption-child")
                    .env("KITROVE_TEST_INTERRUPTION_ROOT", root)
                    .env("KITROVE_TEST_INTERRUPTION_PHASE", phase)
                    .env("KITROVE_TEST_INTERRUPTION_ACTION", action)
                    .spawn()
                    .unwrap(),
            )
        }

        fn wait(&mut self) -> std::process::ExitStatus {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    return status;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "acceptance child timed out"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    fn interruption_child() {
        let root =
            std::path::PathBuf::from(std::env::var_os("KITROVE_TEST_INTERRUPTION_ROOT").unwrap());
        let phase = std::env::var("KITROVE_TEST_INTERRUPTION_PHASE").unwrap();
        assert!(matches!(phase.as_str(), "verified-data" | "published"));
        let authenticated = authenticate_pinned();
        match std::env::var("KITROVE_TEST_INTERRUPTION_ACTION")
            .unwrap()
            .as_str()
        {
            "prepare" => {
                let staged = stage_authenticated_installer_payload(&root, authenticated).unwrap();
                // No helper is alive when readiness is reported. Both public calls
                // require explicit bounded native-helper cleanup before returning.
                let _retained_owner = if phase == "published" {
                    Some(staged.publish_native().unwrap())
                } else {
                    staged.verify_native_signature().unwrap();
                    staged.revalidate().unwrap();
                    // Keep the staged owner alive until SIGKILL, not just its files.
                    std::fs::write(root.join("ready"), b"verified-data").unwrap();
                    std::thread::sleep(std::time::Duration::from_secs(60));
                    drop(staged);
                    panic!("parent did not interrupt staged owner");
                };
                std::fs::write(root.join("ready"), b"published").unwrap();
                std::thread::sleep(std::time::Duration::from_secs(60));
                panic!("parent did not interrupt published owner");
            }
            "reopen" => {
                let result =
                    kitrove_installer::PublishedInstallerPayload::reopen(&root, authenticated);
                assert_eq!(result.is_ok(), phase == "published");
                if let Ok(owner) = result {
                    owner.revalidate().unwrap();
                }
                assert!(
                    stage_authenticated_installer_payload(&root, authenticate_pinned()).is_err()
                );
                std::fs::write(
                    root.join("checked"),
                    b"fresh authentication and reopening checked",
                )
                .unwrap();
            }
            _ => panic!("unknown interruption action"),
        }
    }

    fn interruption_acceptance() {
        use std::os::unix::{fs::MetadataExt, process::ExitStatusExt};
        // Authenticate independently in the parent before interpreting any output.
        let expected_digest = Sha256::digest(authenticate_pinned().bytes());
        let evidence = std::env::var_os("KITROVE_TEST_INTERRUPTION_EVIDENCE")
            .expect("durable evidence directory");
        for phase in ["verified-data", "published"] {
            let root = tempfile::Builder::new()
                .prefix("native-owner-interruption-")
                .tempdir_in(&evidence)
                .unwrap();
            // Preserve output and readiness evidence even on assertion failure.
            let root = root.keep();
            println!("interruption evidence: {} ({phase})", root.display());
            let mut child = OwnedChild::spawn(&root, phase, "prepare");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
            // Creation can precede completion of the marker write. Wait for the
            // complete phase value, not just a newly created empty file.
            while std::fs::read(root.join("ready")).ok().as_deref() != Some(phase.as_bytes()) {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "child exited before readiness"
                );
                assert!(std::time::Instant::now() < deadline, "readiness timed out");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert_eq!(std::fs::read(root.join("ready")).unwrap(), phase.as_bytes());
            child.0.kill().unwrap();
            assert_eq!(child.wait().signal(), Some(9));
            let (name, mode) = if phase == "published" {
                ("kitrove-installer", 0o700)
            } else {
                ("installer.payload", 0o600)
            };
            let directory = root.join(".kitrove-installer-bootstrap");
            let path = directory.join(name);
            let before = std::fs::symlink_metadata(&path).unwrap();
            assert_eq!(before.mode() & 0o777, mode);
            assert_eq!(
                Sha256::digest(bounded_read(&path, 256 * 1024 * 1024)),
                expected_digest
            );
            let mut reopen = OwnedChild::spawn(&root, phase, "reopen");
            assert!(reopen.wait().success());
            assert_eq!(
                std::fs::read(root.join("checked")).unwrap(),
                b"fresh authentication and reopening checked"
            );
            let after = std::fs::symlink_metadata(&path).unwrap();
            assert_eq!(
                (before.dev(), before.ino(), before.mode(), before.len()),
                (after.dev(), after.ino(), after.mode(), after.len())
            );
            assert_eq!(
                Sha256::digest(bounded_read(&path, 256 * 1024 * 1024)),
                expected_digest
            );
            assert_eq!(std::fs::read_dir(directory).unwrap().count(), 1);
        }
        println!(
            "real-artifact owner interruption passed; internal rename/mode cuts and power loss are not covered"
        );
    }
}
