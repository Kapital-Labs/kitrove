use std::fmt;

use semver::Version;
use sha2::{Digest, Sha256};
use sigstore_trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot};
use sigstore_types::{Bundle, Sha256Hash};
use sigstore_verify::{VerificationPolicy, Verifier};

use kitrove_release_policy::{
    APPLICATION_ARCHIVE_LIMITS, ApplicationArchiveIntake, ApplicationArchiveSpec,
    ParsedReleaseManifest, ReleaseManifestError, extract_application_release,
};

mod bundle_selection;
mod bundle_shape;
mod certificate_claims;
mod installer;
mod recovery_material;
mod statement;

pub use bundle_selection::{
    ATTESTATION_COLLECTION_MAX_BYTES, ATTESTATION_COLLECTION_MAX_RECORDS, BundleSelectionError,
    select_application_attestation_bundle, select_installer_attestation_bundle,
};
pub use installer::{
    AuthenticatedInstallerExecutable, InstallerVerificationError,
    verify_installer_archive_attestation,
};
pub use recovery_material::AuthenticatedRecoveryMaterial;

use bundle_shape::{
    reject_duplicate_json_keys, validate as validate_bundle_shape,
    validate_json as validate_json_bundle_shape,
};
#[cfg(test)]
use certificate_claims::validate as validate_certificate_claims;
#[cfg(test)]
use certificate_claims::*;
#[cfg(test)]
use statement::validate as validate_statement;

pub const APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES: usize = 256 * 1024;
pub const PINNED_SIGSTORE_TRUST_ROOT_SHA256: [u8; 32] = [
    0x64, 0x94, 0xe2, 0x1e, 0xa7, 0x3f, 0xa7, 0xee, 0x76, 0x9f, 0x85, 0xf5, 0x7d, 0x5a, 0x3e, 0x6a,
    0x08, 0x72, 0x5e, 0xae, 0x1e, 0x38, 0xc7, 0x55, 0xfc, 0x35, 0x17, 0xc9, 0xe6, 0xbc, 0x0b, 0x66,
];

const GITHUB_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const KITROVE_REPOSITORY_URI: &str = "https://github.com/Kapital-Labs/kitrove";
const KITROVE_REPOSITORY_SLUG: &str = "Kapital-Labs/kitrove";
const KITROVE_REPOSITORY_ID: &str = "1360443188";
const KITROVE_OWNER_URI: &str = "https://github.com/Kapital-Labs";
const KITROVE_OWNER_ID: &str = "320223113";
const KITROVE_RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
const KITROVE_RELEASE_WORKFLOW_NAME: &str = "Release";
const GITHUB_HOSTED_RUNNER: &str = "github-hosted";
const PUBLIC_REPOSITORY_VISIBILITY: &str = "public";
const PUSH_BUILD_TRIGGER: &str = "push";
const SOURCE_COMMIT_HEX_BYTES: usize = 40;
const MAX_RELEASE_TAG_BYTES: usize = 129;

/// Caller-supplied release coordinates that are not authority until attestation succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedReleaseIdentity {
    tag: String,
    release_version: Version,
    source_commit: String,
}

impl ExpectedReleaseIdentity {
    pub fn new(tag: &str, source_commit: &str) -> Result<Self, ReleaseAttestationError> {
        if tag.len() > MAX_RELEASE_TAG_BYTES {
            return Err(ReleaseAttestationError::InvalidExpectedTag);
        }
        let version = tag
            .strip_prefix('v')
            .filter(|value| !value.is_empty())
            .and_then(|value| Version::parse(value).ok())
            .filter(|version| format!("v{version}") == tag)
            .ok_or(ReleaseAttestationError::InvalidExpectedTag)?;
        if source_commit.len() != SOURCE_COMMIT_HEX_BYTES
            || !source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ReleaseAttestationError::InvalidExpectedSourceCommit);
        }
        Ok(Self {
            tag: tag.to_owned(),
            release_version: version,
            source_commit: source_commit.to_owned(),
        })
    }

    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    #[must_use]
    pub fn release_version(&self) -> &Version {
        &self.release_version
    }

    #[must_use]
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    #[must_use]
    pub fn signer_identity(&self) -> String {
        format!(
            "{KITROVE_REPOSITORY_URI}/{KITROVE_RELEASE_WORKFLOW}@refs/tags/{}",
            self.tag
        )
    }
}

/// Cryptographically verified release authority for one exact archive snapshot.
///
/// This type has no public constructor. It can only be produced by the offline
/// Sigstore verification boundary below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReleaseSubject {
    spec: ApplicationArchiveSpec,
    archive_sha256: [u8; 32],
    release_tag: String,
    release_version: Version,
    source_commit: String,
    signer_identity: String,
    attestation_bundle_sha256: [u8; 32],
    trust_root_sha256: [u8; 32],
}

impl VerifiedReleaseSubject {
    #[must_use]
    pub const fn spec(&self) -> ApplicationArchiveSpec {
        self.spec
    }

    #[must_use]
    pub const fn archive_sha256(&self) -> [u8; 32] {
        self.archive_sha256
    }

    #[must_use]
    pub fn release_tag(&self) -> &str {
        &self.release_tag
    }

    #[must_use]
    pub fn release_version(&self) -> &Version {
        &self.release_version
    }

    #[must_use]
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    #[must_use]
    pub fn signer_identity(&self) -> &str {
        &self.signer_identity
    }

    #[must_use]
    pub const fn attestation_bundle_sha256(&self) -> [u8; 32] {
        self.attestation_bundle_sha256
    }

    #[must_use]
    pub const fn trust_root_sha256(&self) -> [u8; 32] {
        self.trust_root_sha256
    }

    /// Revalidates the manifest and executable from the exact authenticated archive bytes.
    pub fn authenticate_executable(
        &self,
        archive_bytes: &[u8],
    ) -> Result<AuthenticatedApplicationExecutable, ReleaseExecutableError> {
        if u64::try_from(archive_bytes.len())
            .ok()
            .filter(|size| *size <= APPLICATION_ARCHIVE_LIMITS.max_archive_bytes)
            .is_none()
        {
            return Err(ReleaseExecutableError::InvalidArchive);
        }
        if <[u8; 32]>::from(Sha256::digest(archive_bytes)) != self.archive_sha256 {
            return Err(ReleaseExecutableError::SubjectMismatch);
        }
        let extracted = extract_application_release(self.spec, archive_bytes)
            .map_err(|_| ReleaseExecutableError::InvalidArchive)?;
        if extracted.intake().spec() != self.spec
            || extracted.intake().archive_sha256() != self.archive_sha256
        {
            return Err(ReleaseExecutableError::SubjectMismatch);
        }
        let manifest_sha256 = Sha256::digest(extracted.manifest_bytes()).into();
        let manifest = extracted
            .validate_manifest(&self.release_version)
            .map_err(|error| match error {
                ReleaseManifestError::ReleaseVersionMismatch
                | ReleaseManifestError::ExecutableDigestMismatch => {
                    ReleaseExecutableError::SubjectMismatch
                }
                _ => ReleaseExecutableError::InvalidArchive,
            })?;
        let executable_sha256 = Sha256::digest(extracted.executable_bytes()).into();
        let bytes = extracted.into_executable_bytes();
        Ok(AuthenticatedApplicationExecutable {
            subject: self.clone(),
            manifest,
            manifest_sha256,
            executable_sha256,
            bytes,
        })
    }
}

/// Exact executable bytes derived from an authenticated release archive.
///
/// This type has no public production constructor. Installer staging accepts
/// this type so caller-provided executable bytes can never become installation
/// authority.
#[derive(Eq, PartialEq)]
pub struct AuthenticatedApplicationExecutable {
    subject: VerifiedReleaseSubject,
    manifest: ParsedReleaseManifest,
    manifest_sha256: [u8; 32],
    executable_sha256: [u8; 32],
    bytes: Vec<u8>,
}

impl fmt::Debug for AuthenticatedApplicationExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedApplicationExecutable")
            .field("subject", &self.subject)
            .field("manifest", &self.manifest)
            .field("manifest_sha256", &self.manifest_sha256)
            .field("executable_sha256", &self.executable_sha256)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl AuthenticatedApplicationExecutable {
    #[must_use]
    pub fn subject(&self) -> &VerifiedReleaseSubject {
        &self.subject
    }

    #[must_use]
    pub const fn manifest(&self) -> &ParsedReleaseManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }

    #[must_use]
    pub const fn executable_sha256(&self) -> [u8; 32] {
        self.executable_sha256
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Constructs debug-build fixture authority for downstream boundary tests.
    ///
    /// This API is absent from release builds and requires the opt-in
    /// `test-support` feature. Production callers must authenticate an attestation.
    #[cfg(all(feature = "test-support", debug_assertions))]
    #[doc(hidden)]
    pub fn from_test_archive(
        spec: ApplicationArchiveSpec,
        archive_bytes: &[u8],
        expected: &ExpectedReleaseIdentity,
    ) -> Result<Self, ReleaseExecutableError> {
        let intake = kitrove_release_policy::inspect_application_archive(spec, archive_bytes)
            .map_err(|_| ReleaseExecutableError::InvalidArchive)?;
        let subject = VerifiedReleaseSubject {
            spec,
            archive_sha256: intake.archive_sha256(),
            release_tag: expected.tag().to_owned(),
            release_version: expected.release_version().clone(),
            source_commit: expected.source_commit().to_owned(),
            signer_identity: expected.signer_identity(),
            attestation_bundle_sha256: [0; 32],
            trust_root_sha256: PINNED_SIGSTORE_TRUST_ROOT_SHA256,
        };
        subject.authenticate_executable(archive_bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseExecutableError {
    InvalidArchive,
    SubjectMismatch,
}

impl fmt::Display for ReleaseExecutableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArchive => "authenticated release archive is malformed",
            Self::SubjectMismatch => "release archive does not match its authenticated subject",
        })
    }
}

impl std::error::Error for ReleaseExecutableError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseAttestationError {
    BundleTooLarge,
    InvalidExpectedTag,
    InvalidExpectedSourceCommit,
    InvalidBundle,
    UnsupportedBundle,
    VerificationFailed,
    InvalidCertificateClaims,
    InvalidStatement,
    SubjectMismatch,
}

impl fmt::Display for ReleaseAttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BundleTooLarge => "release attestation bundle exceeds the supported size",
            Self::InvalidExpectedTag => "expected release tag is not canonical v-prefixed SemVer",
            Self::InvalidExpectedSourceCommit => {
                "expected source commit is not a lowercase SHA-1 object identity"
            }
            Self::InvalidBundle => "release attestation bundle is malformed",
            Self::UnsupportedBundle => "release attestation bundle shape is unsupported",
            Self::VerificationFailed => "release attestation cryptographic verification failed",
            Self::InvalidCertificateClaims => {
                "release attestation certificate claims do not match release policy"
            }
            Self::InvalidStatement => "release attestation statement is unsupported",
            Self::SubjectMismatch => "release attestation subject does not match the archive",
        })
    }
}

impl std::error::Error for ReleaseAttestationError {}

/// Verifies a GitHub Actions release attestation entirely from local inputs.
///
/// The independently resolved commit and exact tag remain caller assertions until
/// the certificate binds both values to KitRove's public release workflow.
pub fn verify_application_archive_attestation(
    intake: ApplicationArchiveIntake,
    expected: &ExpectedReleaseIdentity,
    bundle_bytes: &[u8],
) -> Result<VerifiedReleaseSubject, ReleaseAttestationError> {
    let signer_identity = expected.signer_identity();
    verify_release_attestation(
        intake.spec().archive_name(),
        intake.archive_sha256(),
        expected,
        bundle_bytes,
    )?;

    Ok(VerifiedReleaseSubject {
        spec: intake.spec(),
        archive_sha256: intake.archive_sha256(),
        release_tag: expected.tag().to_owned(),
        release_version: expected.release_version().clone(),
        source_commit: expected.source_commit().to_owned(),
        signer_identity,
        attestation_bundle_sha256: Sha256::digest(bundle_bytes).into(),
        trust_root_sha256: PINNED_SIGSTORE_TRUST_ROOT_SHA256,
    })
}

fn release_policy<'a>(
    expected: &'a ExpectedReleaseIdentity,
    source_ref: &'a str,
    signer_identity: &'a str,
) -> AttestationPolicy<'a> {
    AttestationPolicy {
        signer_identity,
        repository_uri: KITROVE_REPOSITORY_URI,
        repository_slug: KITROVE_REPOSITORY_SLUG,
        repository_id: KITROVE_REPOSITORY_ID,
        owner_uri: KITROVE_OWNER_URI,
        owner_id: KITROVE_OWNER_ID,
        workflow_path: KITROVE_RELEASE_WORKFLOW,
        workflow_name: KITROVE_RELEASE_WORKFLOW_NAME,
        source_ref,
        source_commit: expected.source_commit(),
        runner_environment: GITHUB_HOSTED_RUNNER,
        repository_visibility: PUBLIC_REPOSITORY_VISIBILITY,
        build_trigger: PUSH_BUILD_TRIGGER,
    }
}

fn verify_release_attestation(
    archive_name: &str,
    archive_sha256: [u8; 32],
    expected: &ExpectedReleaseIdentity,
    bundle_bytes: &[u8],
) -> Result<(), ReleaseAttestationError> {
    let source_ref = format!("refs/tags/{}", expected.tag());
    let signer_identity = expected.signer_identity();
    let policy = release_policy(expected, &source_ref, &signer_identity);
    verify_attestation(archive_name, archive_sha256, bundle_bytes, &policy)
}

struct AttestationPolicy<'a> {
    signer_identity: &'a str,
    repository_uri: &'a str,
    repository_slug: &'a str,
    repository_id: &'a str,
    owner_uri: &'a str,
    owner_id: &'a str,
    workflow_path: &'a str,
    workflow_name: &'a str,
    source_ref: &'a str,
    source_commit: &'a str,
    runner_environment: &'a str,
    repository_visibility: &'a str,
    build_trigger: &'a str,
}

fn verify_attestation(
    archive_name: &str,
    archive_sha256: [u8; 32],
    bundle_bytes: &[u8],
    policy: &AttestationPolicy<'_>,
) -> Result<(), ReleaseAttestationError> {
    let bundle = parse_bundle(bundle_bytes)?;

    let trust_root_sha256: [u8; 32] =
        Sha256::digest(SIGSTORE_PRODUCTION_TRUSTED_ROOT.as_bytes()).into();
    if trust_root_sha256 != PINNED_SIGSTORE_TRUST_ROOT_SHA256 {
        return Err(ReleaseAttestationError::VerificationFailed);
    }
    let trusted_root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
        .map_err(|_| ReleaseAttestationError::VerificationFailed)?;
    let digest = Sha256Hash::try_from_slice(&archive_sha256)
        .map_err(|_| ReleaseAttestationError::VerificationFailed)?;
    let verification_policy = VerificationPolicy::with_identity(policy.signer_identity)
        .require_issuer(GITHUB_OIDC_ISSUER);
    Verifier::new(&trusted_root)
        .verify(digest, &bundle, &verification_policy)
        .map_err(|_| ReleaseAttestationError::VerificationFailed)?;

    let run_invocation = certificate_claims::validate(&bundle, policy)?;
    statement::validate(
        &bundle,
        archive_name,
        archive_sha256,
        policy,
        &run_invocation,
    )
}

fn parse_bundle(bundle_bytes: &[u8]) -> Result<Bundle, ReleaseAttestationError> {
    if bundle_bytes.len() > APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES {
        return Err(ReleaseAttestationError::BundleTooLarge);
    }
    let bundle_source =
        std::str::from_utf8(bundle_bytes).map_err(|_| ReleaseAttestationError::InvalidBundle)?;
    reject_duplicate_json_keys(bundle_bytes)?;
    let bundle_value: serde_json::Value =
        serde_json::from_slice(bundle_bytes).map_err(|_| ReleaseAttestationError::InvalidBundle)?;
    validate_json_bundle_shape(&bundle_value)?;
    let bundle =
        Bundle::from_json(bundle_source).map_err(|_| ReleaseAttestationError::InvalidBundle)?;
    validate_bundle_shape(&bundle)?;

    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use const_oid::ObjectIdentifier;
    use der::{
        Decode, Encode,
        asn1::{Ia5String, OctetString, Utf8StringRef},
    };
    use sigstore_types::{
        DerCertificate, KeyId, PayloadBytes, SignatureContent, bundle::VerificationMaterialContent,
    };
    use x509_cert::{
        Certificate,
        ext::{
            Extension,
            pkix::{SubjectAltName, name::GeneralName},
        },
    };

    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/github-actions-public-slsa-v1.json");
    pub(super) const ARCHIVE_NAME: &str = "gam-7.48.02-macos26.5-arm64.tar.xz";
    const KITROVE_ZIP: &[u8] = include_bytes!(
        "../../kitrove-release-policy/tests/fixtures/archive-conformance/valid_zip/kitrove-cli-x86_64-pc-windows-msvc.zip"
    );
    pub(super) const ARCHIVE_DIGEST: [u8; 32] = [
        0xa0, 0xbc, 0xa1, 0x44, 0x64, 0xb5, 0x24, 0x4d, 0x36, 0xdb, 0xae, 0xd1, 0x62, 0xf7, 0x19,
        0x4d, 0x09, 0xd5, 0xbe, 0x45, 0x64, 0xf5, 0xbe, 0xed, 0x84, 0x1d, 0x97, 0xcb, 0x38, 0x93,
        0xc4, 0x6f,
    ];
    type PolicyMutation = (&'static str, fn(&mut AttestationPolicy<'static>));

    pub(super) fn fixture_policy() -> AttestationPolicy<'static> {
        AttestationPolicy {
            signer_identity: "https://github.com/GAM-team/GAM/.github/workflows/build.yml@refs/heads/main",
            repository_uri: "https://github.com/GAM-team/GAM",
            repository_slug: "GAM-team/GAM",
            repository_id: "20185174",
            owner_uri: "https://github.com/GAM-team",
            owner_id: "95577487",
            workflow_path: ".github/workflows/build.yml",
            workflow_name: "Build and test GAM",
            source_ref: "refs/heads/main",
            source_commit: "106b6abc5df1d2e325a15606921ca54b6a849c28",
            runner_environment: "github-hosted",
            repository_visibility: "public",
            build_trigger: "push",
        }
    }

    fn fixture_bundle() -> Bundle {
        Bundle::from_json(std::str::from_utf8(FIXTURE).unwrap()).unwrap()
    }

    fn fixture_invocation(bundle: &Bundle) -> String {
        validate_certificate_claims(bundle, &fixture_policy()).unwrap()
    }

    fn mutate_statement(mutator: impl FnOnce(&mut serde_json::Value)) -> Bundle {
        let mut bundle = fixture_bundle();
        let SignatureContent::DsseEnvelope(envelope) = &mut bundle.content else {
            unreachable!("the reviewed fixture is a DSSE envelope");
        };
        let mut statement: serde_json::Value =
            serde_json::from_slice(envelope.payload.as_bytes()).unwrap();
        mutator(&mut statement);
        envelope.payload = PayloadBytes::from(serde_json::to_vec(&statement).unwrap());
        bundle
    }

    fn mutate_certificate(mutator: impl FnOnce(&mut Certificate)) -> Bundle {
        let mut bundle = fixture_bundle();
        let VerificationMaterialContent::Certificate(content) =
            &mut bundle.verification_material.content
        else {
            unreachable!("the reviewed fixture has one certificate");
        };
        let mut certificate = Certificate::from_der(content.raw_bytes.as_bytes()).unwrap();
        mutator(&mut certificate);
        content.raw_bytes = DerCertificate::from(certificate.to_der().unwrap());
        bundle
    }

    fn extensions_mut(certificate: &mut Certificate) -> &mut Vec<Extension> {
        certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("the reviewed certificate has extensions")
    }

    fn extension_mut(certificate: &mut Certificate, oid: ObjectIdentifier) -> &mut Extension {
        extensions_mut(certificate)
            .iter_mut()
            .find(|extension| extension.extn_id == oid)
            .expect("the reviewed certificate contains the requested extension")
    }

    fn assert_invalid_certificate(bundle: &Bundle) {
        assert_eq!(
            validate_certificate_claims(bundle, &fixture_policy()),
            Err(ReleaseAttestationError::InvalidCertificateClaims)
        );
    }

    fn assert_invalid_statement(bundle: &Bundle, expected: ReleaseAttestationError) {
        assert_eq!(
            validate_statement(
                bundle,
                ARCHIVE_NAME,
                ARCHIVE_DIGEST,
                &fixture_policy(),
                &fixture_invocation(&fixture_bundle()),
            ),
            Err(expected)
        );
    }

    #[test]
    fn production_release_policy_pins_the_fresh_public_repository() {
        let expected =
            ExpectedReleaseIdentity::new("v1.2.3", "0123456789abcdef0123456789abcdef01234567")
                .unwrap();
        let identity = expected.signer_identity();
        let policy = release_policy(&expected, "refs/tags/v1.2.3", &identity);
        assert_eq!(
            policy.repository_uri,
            "https://github.com/Kapital-Labs/kitrove"
        );
        assert_eq!(policy.repository_slug, "Kapital-Labs/kitrove");
        assert_eq!(policy.repository_id, "1360443188");
        assert_eq!(policy.owner_uri, "https://github.com/Kapital-Labs");
        assert_eq!(policy.owner_id, "320223113");
        assert_eq!(
            policy.signer_identity,
            "https://github.com/Kapital-Labs/kitrove/.github/workflows/release.yml@refs/tags/v1.2.3"
        );
        assert_eq!(policy.workflow_path, ".github/workflows/release.yml");
        assert_eq!(policy.workflow_name, "Release");
        assert_eq!(policy.repository_visibility, "public");
        assert_eq!(policy.runner_environment, "github-hosted");
        assert_eq!(policy.build_trigger, "push");
        assert_eq!(policy.source_ref, "refs/tags/v1.2.3");
        assert_eq!(policy.source_commit, expected.source_commit());
        assert!(
            include_str!("../../../Cargo.toml")
                .lines()
                .any(|line| line == format!("repository = \"{}\"", policy.repository_uri))
        );
    }

    #[test]
    fn verifies_current_public_github_actions_slsa_bundle_offline() {
        verify_attestation(ARCHIVE_NAME, ARCHIVE_DIGEST, FIXTURE, &fixture_policy()).unwrap();
    }

    #[test]
    fn exact_certificate_claims_reject_a_repository_id_swap() {
        let bundle = fixture_bundle();
        let mut policy = fixture_policy();
        policy.repository_id = "20185175";
        assert_eq!(
            validate_certificate_claims(&bundle, &policy),
            Err(ReleaseAttestationError::InvalidCertificateClaims)
        );
    }

    #[test]
    fn exact_statement_claims_reject_a_workflow_path_swap() {
        let bundle = fixture_bundle();
        let policy = fixture_policy();
        let invocation = validate_certificate_claims(&bundle, &policy).unwrap();
        let mut changed_policy = fixture_policy();
        changed_policy.workflow_path = ".github/workflows/other.yml";
        assert_eq!(
            validate_statement(
                &bundle,
                ARCHIVE_NAME,
                ARCHIVE_DIGEST,
                &changed_policy,
                &invocation,
            ),
            Err(ReleaseAttestationError::InvalidStatement)
        );
    }

    #[test]
    fn expected_release_coordinates_are_canonical_and_untrusted() {
        let expected = ExpectedReleaseIdentity::new(
            "v1.2.3-alpha.1",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();
        assert_eq!(expected.tag(), "v1.2.3-alpha.1");
        assert_eq!(
            expected.release_version(),
            &Version::parse("1.2.3-alpha.1").unwrap()
        );
        assert_eq!(
            ExpectedReleaseIdentity::new("1.2.3", "0123456789abcdef0123456789abcdef01234567"),
            Err(ReleaseAttestationError::InvalidExpectedTag)
        );
        assert_eq!(
            ExpectedReleaseIdentity::new("v1.2.3", "0123456789abcdef0123456789abcdef0123456A"),
            Err(ReleaseAttestationError::InvalidExpectedSourceCommit)
        );
    }

    #[test]
    fn oversized_bundle_fails_before_parsing() {
        let oversized = vec![b' '; APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES + 1];
        assert_eq!(
            verify_attestation(ARCHIVE_NAME, ARCHIVE_DIGEST, &oversized, &fixture_policy()),
            Err(ReleaseAttestationError::BundleTooLarge)
        );
    }

    #[test]
    fn authenticated_executable_can_only_come_from_the_exact_subject_archive() {
        let spec = kitrove_release_policy::APPLICATION_ARCHIVES[3];
        let intake =
            kitrove_release_policy::inspect_application_archive(spec, KITROVE_ZIP).unwrap();
        let subject = VerifiedReleaseSubject {
            spec,
            archive_sha256: intake.archive_sha256(),
            release_tag: "v1.2.3".to_owned(),
            release_version: Version::parse("1.2.3").unwrap(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            signer_identity: "fixture".to_owned(),
            attestation_bundle_sha256: [1; 32],
            trust_root_sha256: PINNED_SIGSTORE_TRUST_ROOT_SHA256,
        };
        let authenticated = subject.authenticate_executable(KITROVE_ZIP).unwrap();
        assert_eq!(authenticated.subject(), &subject);
        assert_eq!(authenticated.bytes(), b"binary");
        assert_eq!(
            authenticated.manifest().release_version(),
            subject.release_version()
        );
        assert_eq!(authenticated.manifest().target(), spec.target());
        assert_eq!(
            authenticated.manifest().executable_sha256(),
            authenticated.executable_sha256()
        );
        assert_eq!(
            authenticated.executable_sha256(),
            Sha256::digest(authenticated.bytes()).as_slice()
        );

        let mut wrong_release = subject.clone();
        wrong_release.release_version = Version::parse("1.2.4").unwrap();
        assert_eq!(
            wrong_release.authenticate_executable(KITROVE_ZIP),
            Err(ReleaseExecutableError::SubjectMismatch)
        );

        let mut mismatched = subject.clone();
        mismatched.archive_sha256[0] ^= 1;
        assert_eq!(
            mismatched.authenticate_executable(KITROVE_ZIP),
            Err(ReleaseExecutableError::SubjectMismatch)
        );
        assert_eq!(
            subject.authenticate_executable(b"not an archive"),
            Err(ReleaseExecutableError::SubjectMismatch)
        );
    }

    #[test]
    fn every_certificate_policy_claim_fails_closed_when_expected_value_changes() {
        let bundle = fixture_bundle();
        let mutations: &[PolicyMutation] = &[
            ("signer identity", |policy| policy.signer_identity = "wrong"),
            ("repository URI", |policy| policy.repository_uri = "wrong"),
            ("repository slug", |policy| policy.repository_slug = "wrong"),
            ("repository ID", |policy| policy.repository_id = "1"),
            ("owner URI", |policy| policy.owner_uri = "wrong"),
            ("owner ID", |policy| policy.owner_id = "1"),
            ("workflow name", |policy| policy.workflow_name = "wrong"),
            ("source ref", |policy| policy.source_ref = "refs/tags/wrong"),
            ("source commit", |policy| policy.source_commit = "wrong"),
            ("runner", |policy| policy.runner_environment = "self-hosted"),
            ("visibility", |policy| {
                policy.repository_visibility = "private"
            }),
            ("trigger", |policy| {
                policy.build_trigger = "workflow_dispatch"
            }),
        ];
        for (name, mutate) in mutations {
            let mut policy = fixture_policy();
            mutate(&mut policy);
            assert_eq!(
                validate_certificate_claims(&bundle, &policy),
                Err(ReleaseAttestationError::InvalidCertificateClaims),
                "certificate claim accepted changed {name}"
            );
        }
    }

    #[test]
    fn every_certificate_extension_claim_is_independently_pinned() {
        let utf8_claims = [
            OIDC_ISSUER_V2_OID,
            BUILD_SIGNER_URI_OID,
            BUILD_SIGNER_DIGEST_OID,
            RUNNER_ENVIRONMENT_OID,
            SOURCE_REPOSITORY_URI_OID,
            SOURCE_REPOSITORY_DIGEST_OID,
            SOURCE_REPOSITORY_REF_OID,
            SOURCE_REPOSITORY_ID_OID,
            SOURCE_REPOSITORY_OWNER_URI_OID,
            SOURCE_REPOSITORY_OWNER_ID_OID,
            BUILD_CONFIG_URI_OID,
            BUILD_CONFIG_DIGEST_OID,
            BUILD_TRIGGER_OID,
            RUN_INVOCATION_URI_OID,
            SOURCE_REPOSITORY_VISIBILITY_OID,
            TOKEN_SUBJECT_OID,
        ];
        for oid in utf8_claims {
            let bundle = mutate_certificate(|certificate| {
                extension_mut(certificate, oid).extn_value =
                    OctetString::new(Utf8StringRef::new("wrong").unwrap().to_der().unwrap())
                        .unwrap();
            });
            assert_invalid_certificate(&bundle);
        }

        let legacy_claims = [
            LEGACY_ISSUER_OID,
            LEGACY_TRIGGER_OID,
            LEGACY_SOURCE_COMMIT_OID,
            LEGACY_WORKFLOW_NAME_OID,
            LEGACY_REPOSITORY_OID,
            LEGACY_SOURCE_REF_OID,
        ];
        for oid in legacy_claims {
            let bundle = mutate_certificate(|certificate| {
                extension_mut(certificate, oid).extn_value = OctetString::new(b"wrong").unwrap();
            });
            assert_invalid_certificate(&bundle);
        }
    }

    #[test]
    fn certificate_extensions_must_be_unique_noncritical_and_well_formed() {
        let missing = mutate_certificate(|certificate| {
            extensions_mut(certificate)
                .retain(|extension| extension.extn_id != SOURCE_REPOSITORY_ID_OID);
        });
        assert_invalid_certificate(&missing);

        let duplicate = mutate_certificate(|certificate| {
            let duplicate = extension_mut(certificate, SOURCE_REPOSITORY_ID_OID).clone();
            extensions_mut(certificate).push(duplicate);
        });
        assert_invalid_certificate(&duplicate);

        let critical = mutate_certificate(|certificate| {
            extension_mut(certificate, SOURCE_REPOSITORY_ID_OID).critical = true;
        });
        assert_invalid_certificate(&critical);

        let malformed = mutate_certificate(|certificate| {
            extension_mut(certificate, SOURCE_REPOSITORY_ID_OID).extn_value =
                OctetString::new([0xff]).unwrap();
        });
        assert_invalid_certificate(&malformed);
    }

    #[test]
    fn certificate_san_must_be_one_critical_exact_uri() {
        let san_oid = ObjectIdentifier::new_unwrap("2.5.29.17");
        let wrong_identity = mutate_certificate(|certificate| {
            let extension = extension_mut(certificate, san_oid);
            let names = SubjectAltName(vec![GeneralName::UniformResourceIdentifier(
                Ia5String::new("https://example.com").unwrap(),
            )]);
            extension.extn_value = OctetString::new(names.to_der().unwrap()).unwrap();
        });
        assert_invalid_certificate(&wrong_identity);

        let email_identity = mutate_certificate(|certificate| {
            let extension = extension_mut(certificate, san_oid);
            let names = SubjectAltName(vec![GeneralName::Rfc822Name(
                Ia5String::new("release@example.com").unwrap(),
            )]);
            extension.extn_value = OctetString::new(names.to_der().unwrap()).unwrap();
        });
        assert_invalid_certificate(&email_identity);

        let missing = mutate_certificate(|certificate| {
            extensions_mut(certificate).retain(|extension| extension.extn_id != san_oid);
        });
        assert_invalid_certificate(&missing);

        let duplicate = mutate_certificate(|certificate| {
            let duplicate = extension_mut(certificate, san_oid).clone();
            extensions_mut(certificate).push(duplicate);
        });
        assert_invalid_certificate(&duplicate);

        let noncritical = mutate_certificate(|certificate| {
            extension_mut(certificate, san_oid).critical = false;
        });
        assert_invalid_certificate(&noncritical);

        let multiple = mutate_certificate(|certificate| {
            let extension = extension_mut(certificate, san_oid);
            let mut names = SubjectAltName::from_der(extension.extn_value.as_bytes()).unwrap();
            names.0.push(names.0[0].clone());
            extension.extn_value = OctetString::new(names.to_der().unwrap()).unwrap();
        });
        assert_invalid_certificate(&multiple);
    }

    #[test]
    fn run_invocation_grammar_is_exact_and_nonzero() {
        for invalid in [
            "https://example.com/actions/runs/1/attempts/1",
            "https://github.com/GAM-team/GAM/actions/runs/0/attempts/1",
            "https://github.com/GAM-team/GAM/actions/runs/01/attempts/1",
            "https://github.com/GAM-team/GAM/actions/runs/1/attempts/0",
            "https://github.com/GAM-team/GAM/actions/runs/1/attempts/01",
            "https://github.com/GAM-team/GAM/actions/runs/1/attempts/1/extra",
            "https://github.com/GAM-team/GAM/actions/runs/a/attempts/1",
        ] {
            assert_eq!(
                validate_run_invocation(fixture_policy().repository_uri, invalid),
                Err(ReleaseAttestationError::InvalidCertificateClaims),
                "accepted invalid invocation {invalid}"
            );
        }
    }

    #[test]
    fn bundle_json_rejects_unknown_and_duplicate_fields() {
        let fixture = std::str::from_utf8(FIXTURE).unwrap();
        let unknown = fixture.replacen('{', "{\"unexpected\":null,", 1);
        assert_eq!(
            verify_attestation(
                ARCHIVE_NAME,
                ARCHIVE_DIGEST,
                unknown.as_bytes(),
                &fixture_policy(),
            ),
            Err(ReleaseAttestationError::InvalidBundle)
        );
        let media_type = "\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"";
        let duplicate = fixture.replacen(media_type, &format!("{media_type},{media_type}"), 1);
        assert_eq!(
            verify_attestation(
                ARCHIVE_NAME,
                ARCHIVE_DIGEST,
                duplicate.as_bytes(),
                &fixture_policy(),
            ),
            Err(ReleaseAttestationError::InvalidBundle)
        );
    }

    #[test]
    fn dsse_shape_requires_one_empty_key_identifier() {
        let mut multiple = fixture_bundle();
        let SignatureContent::DsseEnvelope(envelope) = &mut multiple.content else {
            unreachable!();
        };
        envelope.signatures.push(envelope.signatures[0].clone());
        assert_eq!(
            validate_bundle_shape(&multiple),
            Err(ReleaseAttestationError::UnsupportedBundle)
        );

        let mut keyed = fixture_bundle();
        let SignatureContent::DsseEnvelope(envelope) = &mut keyed.content else {
            unreachable!();
        };
        envelope.signatures[0].keyid = KeyId::new("unexpected".to_owned());
        assert_eq!(
            validate_bundle_shape(&keyed),
            Err(ReleaseAttestationError::UnsupportedBundle)
        );
    }

    #[test]
    fn statement_subject_is_one_exact_archive_and_digest() {
        let cases = [
            (
                "empty",
                mutate_statement(|value| value["subject"] = serde_json::json!([])),
            ),
            (
                "multiple",
                mutate_statement(|value| {
                    let subject = value["subject"][0].clone();
                    value["subject"] = serde_json::json!([subject.clone(), subject]);
                }),
            ),
            (
                "name",
                mutate_statement(|value| value["subject"][0]["name"] = "wrong".into()),
            ),
            (
                "digest",
                mutate_statement(|value| value["subject"][0]["digest"]["sha256"] = "00".into()),
            ),
            (
                "uppercase digest",
                mutate_statement(|value| {
                    let digest = value["subject"][0]["digest"]["sha256"]
                        .as_str()
                        .unwrap()
                        .to_uppercase();
                    value["subject"][0]["digest"]["sha256"] = digest.into();
                }),
            ),
            (
                "extra digest",
                mutate_statement(|value| value["subject"][0]["digest"]["sha512"] = "00".into()),
            ),
        ];
        for (name, bundle) in cases {
            assert_eq!(
                validate_statement(
                    &bundle,
                    ARCHIVE_NAME,
                    ARCHIVE_DIGEST,
                    &fixture_policy(),
                    &fixture_invocation(&fixture_bundle()),
                ),
                Err(if name == "extra digest" {
                    ReleaseAttestationError::InvalidStatement
                } else {
                    ReleaseAttestationError::SubjectMismatch
                }),
                "accepted invalid subject case {name}"
            );
        }
    }

    #[test]
    fn statement_predicate_claims_and_structure_fail_closed() {
        let invalid_claims = [
            "/predicate/buildDefinition/buildType",
            "/predicate/buildDefinition/externalParameters/workflow/ref",
            "/predicate/buildDefinition/externalParameters/workflow/repository",
            "/predicate/buildDefinition/externalParameters/workflow/path",
            "/predicate/buildDefinition/internalParameters/github/event_name",
            "/predicate/buildDefinition/internalParameters/github/repository_id",
            "/predicate/buildDefinition/internalParameters/github/repository_owner_id",
            "/predicate/buildDefinition/internalParameters/github/runner_environment",
            "/predicate/buildDefinition/resolvedDependencies/0/uri",
            "/predicate/buildDefinition/resolvedDependencies/0/digest/gitCommit",
            "/predicate/runDetails/builder/id",
            "/predicate/runDetails/metadata/invocationId",
        ];
        for pointer in invalid_claims {
            let bundle = mutate_statement(|value| {
                *value.pointer_mut(pointer).expect("fixture path exists") = "wrong".into();
            });
            assert_invalid_statement(&bundle, ReleaseAttestationError::InvalidStatement);
        }

        for dependencies in [serde_json::json!([]), serde_json::json!([{}, {}])] {
            let bundle = mutate_statement(|value| {
                value["predicate"]["buildDefinition"]["resolvedDependencies"] = dependencies;
            });
            assert_invalid_statement(&bundle, ReleaseAttestationError::InvalidStatement);
        }
        let unknown = mutate_statement(|value| value["unexpected"] = serde_json::Value::Null);
        assert_invalid_statement(&unknown, ReleaseAttestationError::InvalidStatement);
    }
}
