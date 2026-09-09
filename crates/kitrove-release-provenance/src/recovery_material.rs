use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::{
    APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES, AuthenticatedApplicationExecutable,
    ReleaseExecutableError, VerifiedReleaseSubject,
};

/// Exact authenticated inputs available for private offline rollback-kit storage.
///
/// This is in-memory evidence, not a durable rollback kit or proof that an installed
/// executable matches it. Recovery must freshly verify the retained attestation.
#[derive(Eq, PartialEq)]
pub struct AuthenticatedRecoveryMaterial {
    executable: AuthenticatedApplicationExecutable,
    archive_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
}

impl VerifiedReleaseSubject {
    /// Binds recovery inputs to this cryptographically authenticated subject.
    ///
    /// Caller-supplied hashes cannot construct a subject. Archive validation is
    /// shared with ordinary executable intake; the bundle must be byte-identical
    /// to the one that authenticated this subject. Neither input is executed.
    pub fn authenticate_recovery_material(
        &self,
        archive_bytes: &[u8],
        bundle_bytes: &[u8],
    ) -> Result<AuthenticatedRecoveryMaterial, ReleaseExecutableError> {
        if bundle_bytes.len() > APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES
            || <[u8; 32]>::from(Sha256::digest(bundle_bytes)) != self.attestation_bundle_sha256()
        {
            return Err(ReleaseExecutableError::SubjectMismatch);
        }
        let executable = self.authenticate_executable(archive_bytes)?;
        Ok(AuthenticatedRecoveryMaterial {
            executable,
            archive_bytes: archive_bytes.to_vec(),
            bundle_bytes: bundle_bytes.to_vec(),
        })
    }
}

impl AuthenticatedRecoveryMaterial {
    /// Debug-build fixture authority only; absent from production release builds.
    #[cfg(all(feature = "test-support", debug_assertions))]
    #[doc(hidden)]
    pub fn from_test_archive(
        spec: kitrove_release_policy::ApplicationArchiveSpec,
        archive: &[u8],
        bundle: &[u8],
        expected: &crate::ExpectedReleaseIdentity,
    ) -> Result<Self, ReleaseExecutableError> {
        let mut executable =
            AuthenticatedApplicationExecutable::from_test_archive(spec, archive, expected)?;
        executable.subject.attestation_bundle_sha256 = Sha256::digest(bundle).into();
        executable
            .subject
            .authenticate_recovery_material(archive, bundle)
    }
    #[must_use]
    pub const fn executable(&self) -> &AuthenticatedApplicationExecutable {
        &self.executable
    }

    #[must_use]
    pub fn archive_bytes(&self) -> &[u8] {
        &self.archive_bytes
    }

    #[must_use]
    pub fn bundle_bytes(&self) -> &[u8] {
        &self.bundle_bytes
    }
}

impl fmt::Debug for AuthenticatedRecoveryMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRecoveryMaterial")
            .field("executable", &self.executable)
            .field("archive_bytes_len", &self.archive_bytes.len())
            .field("bundle_bytes_len", &self.bundle_bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCHIVE: &[u8] = include_bytes!(
        "../../kitrove-release-policy/tests/fixtures/archive-conformance/valid_zip/kitrove-cli-x86_64-pc-windows-msvc.zip"
    );
    const BUNDLE: &[u8] = b"synthetic-private-bundle-canary";

    // Synthetic authority tests byte binding, not Sigstore verification. The
    // production type has no public constructor; cryptography has its own fixtures.
    fn subject() -> VerifiedReleaseSubject {
        VerifiedReleaseSubject {
            spec: kitrove_release_policy::application_archive_for_target("x86_64-pc-windows-msvc")
                .unwrap(),
            archive_sha256: Sha256::digest(ARCHIVE).into(),
            release_tag: "v1.2.3".to_owned(),
            release_version: semver::Version::new(1, 2, 3),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            signer_identity: "fixture".to_owned(),
            attestation_bundle_sha256: Sha256::digest(BUNDLE).into(),
            trust_root_sha256: crate::PINNED_SIGSTORE_TRUST_ROOT_SHA256,
        }
    }

    #[test]
    fn retains_exact_archive_bundle_and_shared_executable_evidence() {
        let subject = subject();
        let material = subject
            .authenticate_recovery_material(ARCHIVE, BUNDLE)
            .unwrap();
        assert_eq!(material.archive_bytes(), ARCHIVE);
        assert_eq!(material.bundle_bytes(), BUNDLE);
        assert_eq!(
            material.executable(),
            &subject.authenticate_executable(ARCHIVE).unwrap()
        );
        let debug = format!("{material:?}");
        assert!(!debug.contains(std::str::from_utf8(BUNDLE).unwrap()));
        assert!(!debug.contains("binary"));
    }

    #[test]
    fn rejects_substituted_archive_bundle_or_release_identity() {
        let subject = subject();
        for (archive, bundle) in [
            (b"different archive".as_slice(), BUNDLE),
            (ARCHIVE, b"different bundle".as_slice()),
        ] {
            assert_eq!(
                subject.authenticate_recovery_material(archive, bundle),
                Err(ReleaseExecutableError::SubjectMismatch)
            );
        }
        let mut changed = subject;
        changed.release_version = semver::Version::new(1, 2, 4);
        assert_eq!(
            changed.authenticate_recovery_material(ARCHIVE, BUNDLE),
            Err(ReleaseExecutableError::SubjectMismatch)
        );
    }

    #[test]
    fn retained_evidence_is_independent_of_later_caller_mutation() {
        let mut archive = ARCHIVE.to_vec();
        let mut bundle = BUNDLE.to_vec();
        let material = subject()
            .authenticate_recovery_material(&archive, &bundle)
            .unwrap();
        archive.fill(0);
        bundle.fill(0);
        assert_eq!(material.archive_bytes(), ARCHIVE);
        assert_eq!(material.bundle_bytes(), BUNDLE);
        assert_eq!(material.executable().bytes(), b"binary");
    }

    #[test]
    fn rejects_oversized_bundle_even_when_its_digest_matches() {
        let oversized = vec![b'x'; APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES + 1];
        let mut subject = subject();
        subject.attestation_bundle_sha256 = Sha256::digest(&oversized).into();
        assert_eq!(
            subject.authenticate_recovery_material(ARCHIVE, &oversized),
            Err(ReleaseExecutableError::SubjectMismatch)
        );
    }

    #[test]
    fn matching_digest_does_not_bypass_archive_policy() {
        let invalid = b"not an archive";
        let mut subject = subject();
        subject.archive_sha256 = Sha256::digest(invalid).into();
        assert_eq!(
            subject.authenticate_recovery_material(invalid, BUNDLE),
            Err(ReleaseExecutableError::InvalidArchive)
        );
    }
}
