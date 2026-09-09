use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::ApplicationArchiveSpec;

pub const APPLICATION_RELEASE_MANIFEST_MAX_BYTES: usize = 16 * 1024;
pub const RELEASE_MANIFEST_MAX_VERSION_BYTES: usize = 128;
pub const RELEASE_MANIFEST_MAX_ROLLBACK_PREDECESSORS: usize = 64;
const RELEASE_MANIFEST_SCHEMA: u64 = 1;
const LIFECYCLE_LOCK_PROTOCOL: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationStateSchema {
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleLockProtocol {
    V1,
}

impl ApplicationStateSchema {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "V1",
        }
    }
}

impl LifecycleLockProtocol {
    #[must_use]
    pub const fn version(self) -> u64 {
        match self {
            Self::V1 => LIFECYCLE_LOCK_PROTOCOL,
        }
    }
}

/// Structurally valid but unauthenticated claims decoded from release-manifest bytes.
///
/// This value is not installation, upgrade, or rollback authority. A later provenance
/// boundary must bind these exact bytes to an authenticated release subject and to the
/// executable inspected from the same immutable archive snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedReleaseManifest {
    release_version: Version,
    target: &'static str,
    executable_sha256: [u8; 32],
    application_state_schema: ApplicationStateSchema,
    lifecycle_lock_protocol: LifecycleLockProtocol,
    rollback_compatible_predecessors: BTreeSet<Version>,
}

impl ParsedReleaseManifest {
    #[must_use]
    pub fn release_version(&self) -> &Version {
        &self.release_version
    }

    #[must_use]
    pub const fn target(&self) -> &'static str {
        self.target
    }

    #[must_use]
    pub const fn executable_sha256(&self) -> [u8; 32] {
        self.executable_sha256
    }

    #[must_use]
    pub const fn application_state_schema(&self) -> ApplicationStateSchema {
        self.application_state_schema
    }

    #[must_use]
    pub const fn lifecycle_lock_protocol(&self) -> LifecycleLockProtocol {
        self.lifecycle_lock_protocol
    }

    #[must_use]
    pub fn declares_rollback_compatibility_to(&self, predecessor: &Self) -> bool {
        self.target == predecessor.target
            && self.application_state_schema == predecessor.application_state_schema
            && self.lifecycle_lock_protocol == predecessor.lifecycle_lock_protocol
            && self
                .release_version
                .cmp_precedence(&predecessor.release_version)
                == Ordering::Greater
            && self
                .rollback_compatible_predecessors
                .contains(&predecessor.release_version)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseManifestError {
    InvalidArtifactKind,
    ExecutableNameMismatch,
    TooLarge,
    InvalidJson,
    UnsupportedSchema,
    UnsupportedStateSchema,
    UnsupportedLifecycleLock,
    TargetMismatch,
    InvalidReleaseVersion,
    InvalidExecutableDigest,
    TooManyPredecessors,
    InvalidPredecessor,
    DuplicatePredecessor,
    ReleaseVersionMismatch,
    ExecutableDigestMismatch,
}

impl fmt::Display for ReleaseManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArtifactKind => "release manifest artifact kind is invalid",
            Self::ExecutableNameMismatch => "release manifest executable name is invalid",
            Self::TooLarge => "release manifest exceeds the supported size",
            Self::InvalidJson => "release manifest is not exact supported JSON",
            Self::UnsupportedSchema => "release manifest schema is unsupported",
            Self::UnsupportedStateSchema => "application state schema is unsupported",
            Self::UnsupportedLifecycleLock => "application lifecycle lock protocol is unsupported",
            Self::TargetMismatch => "release manifest target does not match the selected archive",
            Self::InvalidReleaseVersion => "release manifest version is invalid",
            Self::InvalidExecutableDigest => "release manifest executable digest is invalid",
            Self::TooManyPredecessors => "release manifest has too many rollback predecessors",
            Self::InvalidPredecessor => "release manifest rollback predecessor is invalid",
            Self::DuplicatePredecessor => "release manifest repeats a rollback predecessor",
            Self::ReleaseVersionMismatch => {
                "release manifest version does not match authenticated release"
            }
            Self::ExecutableDigestMismatch => {
                "release manifest executable digest does not match archive content"
            }
        })
    }
}

impl std::error::Error for ReleaseManifestError {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawReleaseManifest {
    schema: u64,
    release_version: String,
    target: String,
    executable_sha256: String,
    application_state_schema: String,
    lifecycle_lock_protocol: u64,
    rollback_compatible_predecessors: Vec<String>,
}

/// Renders the canonical manifest embedded into one target archive.
pub fn render_release_manifest(
    spec: ApplicationArchiveSpec,
    release_version: &Version,
    executable_sha256: [u8; 32],
    rollback_compatible_predecessors: &[Version],
) -> Result<Vec<u8>, ReleaseManifestError> {
    if rollback_compatible_predecessors.len() > RELEASE_MANIFEST_MAX_ROLLBACK_PREDECESSORS {
        return Err(ReleaseManifestError::TooManyPredecessors);
    }
    let mut predecessors = BTreeSet::new();
    for predecessor in rollback_compatible_predecessors {
        if release_version.cmp_precedence(predecessor) != Ordering::Greater {
            return Err(ReleaseManifestError::InvalidPredecessor);
        }
        if !predecessors.insert(predecessor.to_string()) {
            return Err(ReleaseManifestError::DuplicatePredecessor);
        }
    }
    let bytes = serde_json::to_vec(&RawReleaseManifest {
        schema: RELEASE_MANIFEST_SCHEMA,
        release_version: release_version.to_string(),
        target: spec.target().to_owned(),
        executable_sha256: encode_sha256(executable_sha256),
        application_state_schema: ApplicationStateSchema::V1.as_str().to_owned(),
        lifecycle_lock_protocol: LifecycleLockProtocol::V1.version(),
        rollback_compatible_predecessors: predecessors.into_iter().collect(),
    })
    .map_err(|_| ReleaseManifestError::InvalidJson)?;
    if bytes.len() > APPLICATION_RELEASE_MANIFEST_MAX_BYTES {
        return Err(ReleaseManifestError::TooLarge);
    }
    Ok(bytes)
}

/// Parses bounded manifest bytes into unauthenticated claims.
///
/// Successful parsing does not prove archive membership, release provenance, tag identity,
/// or executable identity and must never directly authorize filesystem mutation.
pub fn parse_release_manifest(
    spec: ApplicationArchiveSpec,
    bytes: &[u8],
) -> Result<ParsedReleaseManifest, ReleaseManifestError> {
    if bytes.len() > APPLICATION_RELEASE_MANIFEST_MAX_BYTES {
        return Err(ReleaseManifestError::TooLarge);
    }
    let raw: RawReleaseManifest =
        serde_json::from_slice(bytes).map_err(|_| ReleaseManifestError::InvalidJson)?;
    if raw.schema != RELEASE_MANIFEST_SCHEMA {
        return Err(ReleaseManifestError::UnsupportedSchema);
    }
    if raw.target != spec.target() {
        return Err(ReleaseManifestError::TargetMismatch);
    }
    if raw.application_state_schema != "V1" {
        return Err(ReleaseManifestError::UnsupportedStateSchema);
    }
    if raw.lifecycle_lock_protocol != LIFECYCLE_LOCK_PROTOCOL {
        return Err(ReleaseManifestError::UnsupportedLifecycleLock);
    }

    let release_version = parse_canonical_version(&raw.release_version)
        .ok_or(ReleaseManifestError::InvalidReleaseVersion)?;
    let executable_sha256 = parse_sha256(&raw.executable_sha256)
        .ok_or(ReleaseManifestError::InvalidExecutableDigest)?;
    if raw.rollback_compatible_predecessors.len() > RELEASE_MANIFEST_MAX_ROLLBACK_PREDECESSORS {
        return Err(ReleaseManifestError::TooManyPredecessors);
    }
    let mut rollback_compatible_predecessors = BTreeSet::new();
    for predecessor in raw.rollback_compatible_predecessors {
        let predecessor = parse_canonical_version(&predecessor)
            .filter(|predecessor| release_version.cmp_precedence(predecessor) == Ordering::Greater)
            .ok_or(ReleaseManifestError::InvalidPredecessor)?;
        if !rollback_compatible_predecessors.insert(predecessor) {
            return Err(ReleaseManifestError::DuplicatePredecessor);
        }
    }

    Ok(ParsedReleaseManifest {
        release_version,
        target: spec.target(),
        executable_sha256,
        application_state_schema: ApplicationStateSchema::V1,
        lifecycle_lock_protocol: LifecycleLockProtocol::V1,
        rollback_compatible_predecessors,
    })
}

pub(crate) fn parse_canonical_version(value: &str) -> Option<Version> {
    if value.is_empty()
        || value.len() > RELEASE_MANIFEST_MAX_VERSION_BYTES
        || !value.is_ascii()
        || value.starts_with('v')
    {
        return None;
    }
    Version::parse(value)
        .ok()
        .filter(|version| version.to_string() == value)
}

pub(crate) fn parse_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (output, pair) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *output = hex_nibble(pair[0])?.checked_mul(16)? + hex_nibble(pair[1])?;
    }
    Some(digest)
}

pub(crate) fn encode_sha256(digest: [u8; 32]) -> String {
    use std::fmt::Write as _;

    digest
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        })
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::APPLICATION_ARCHIVES;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn manifest(version: &str, predecessors: &str) -> Vec<u8> {
        format!(
            r#"{{"schema":1,"release_version":"{version}","target":"aarch64-apple-darwin","executable_sha256":"{DIGEST}","application_state_schema":"V1","lifecycle_lock_protocol":1,"rollback_compatible_predecessors":{predecessors}}}"#
        )
        .into_bytes()
    }

    fn parse(
        version: &str,
        predecessors: &str,
    ) -> Result<ParsedReleaseManifest, ReleaseManifestError> {
        parse_release_manifest(APPLICATION_ARCHIVES[0], &manifest(version, predecessors))
    }

    #[test]
    fn parses_exact_v1_manifest_and_rollback_relation() {
        let current = parse("1.2.3", r#"["1.2.2","1.1.0"]"#).unwrap();
        let predecessor = parse("1.2.2", "[]").unwrap();
        let unlisted = parse("1.2.1", "[]").unwrap();
        assert_eq!(current.release_version(), &Version::new(1, 2, 3));
        assert_eq!(current.target(), APPLICATION_ARCHIVES[0].target());
        assert_eq!(current.executable_sha256(), parse_sha256(DIGEST).unwrap());
        assert_eq!(
            current.application_state_schema(),
            ApplicationStateSchema::V1
        );
        assert_eq!(current.lifecycle_lock_protocol(), LifecycleLockProtocol::V1);
        assert!(current.declares_rollback_compatibility_to(&predecessor));
        assert!(!current.declares_rollback_compatibility_to(&unlisted));
        assert!(!predecessor.declares_rollback_compatibility_to(&current));
    }

    #[test]
    fn renderer_is_deterministic_and_round_trips_exact_authority() {
        let digest = parse_sha256(DIGEST).unwrap();
        let version = Version::new(2, 0, 0);
        let predecessors = [Version::new(1, 10, 0), Version::new(1, 2, 0)];
        let first =
            render_release_manifest(APPLICATION_ARCHIVES[0], &version, digest, &predecessors)
                .unwrap();
        let second =
            render_release_manifest(APPLICATION_ARCHIVES[0], &version, digest, &predecessors)
                .unwrap();
        assert_eq!(first, second);
        assert!(first.len() <= APPLICATION_RELEASE_MANIFEST_MAX_BYTES);

        let parsed = parse_release_manifest(APPLICATION_ARCHIVES[0], &first).unwrap();
        assert_eq!(parsed.release_version(), &version);
        assert_eq!(parsed.executable_sha256(), digest);
        for predecessor in predecessors {
            assert!(
                parsed
                    .rollback_compatible_predecessors
                    .contains(&predecessor)
            );
        }
    }

    #[test]
    fn renderer_rejects_duplicate_non_predecessor_and_excessive_authority() {
        let version = Version::new(2, 0, 0);
        let digest = [0_u8; 32];
        assert_eq!(
            render_release_manifest(
                APPLICATION_ARCHIVES[0],
                &version,
                digest,
                &[Version::new(1, 0, 0), Version::new(1, 0, 0)],
            ),
            Err(ReleaseManifestError::DuplicatePredecessor)
        );
        assert_eq!(
            render_release_manifest(
                APPLICATION_ARCHIVES[0],
                &version,
                digest,
                std::slice::from_ref(&version),
            ),
            Err(ReleaseManifestError::InvalidPredecessor)
        );
        assert_eq!(
            render_release_manifest(
                APPLICATION_ARCHIVES[0],
                &Version::new(100, 0, 0),
                digest,
                &vec![Version::new(1, 0, 0); RELEASE_MANIFEST_MAX_ROLLBACK_PREDECESSORS + 1],
            ),
            Err(ReleaseManifestError::TooManyPredecessors)
        );
    }

    #[test]
    fn rejects_non_exact_json_schema_target_and_protocol() {
        let valid = String::from_utf8(manifest("1.2.3", "[]")).unwrap();
        for (source, error) in [
            (
                valid.replace("\"schema\":1", "\"schema\":2"),
                ReleaseManifestError::UnsupportedSchema,
            ),
            (
                valid.replace("\"schema\":1", "\"schema\":true"),
                ReleaseManifestError::InvalidJson,
            ),
            (
                valid.replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
                ReleaseManifestError::InvalidJson,
            ),
            (
                valid.replace("\"schema\":1", "\"schema\":1,\"unknown\":1"),
                ReleaseManifestError::InvalidJson,
            ),
            (
                valid.replace("aarch64-apple-darwin", "x86_64-apple-darwin"),
                ReleaseManifestError::TargetMismatch,
            ),
            (
                valid.replace("\"V1\"", "\"V2\""),
                ReleaseManifestError::UnsupportedStateSchema,
            ),
            (
                valid.replace(
                    "\"lifecycle_lock_protocol\":1",
                    "\"lifecycle_lock_protocol\":2",
                ),
                ReleaseManifestError::UnsupportedLifecycleLock,
            ),
        ] {
            assert_eq!(
                parse_release_manifest(APPLICATION_ARCHIVES[0], source.as_bytes()),
                Err(error)
            );
        }
    }

    #[test]
    fn rejects_invalid_versions_digests_and_predecessors() {
        for version in ["", "v1.2.3", "01.2.3", "1.2", "1.2.3-"] {
            assert_eq!(
                parse(version, "[]"),
                Err(ReleaseManifestError::InvalidReleaseVersion)
            );
        }
        assert_eq!(
            parse("1.2.3", r#"["1.2.3"]"#),
            Err(ReleaseManifestError::InvalidPredecessor)
        );
        assert_eq!(
            parse("1.2.3", r#"["2.0.0"]"#),
            Err(ReleaseManifestError::InvalidPredecessor)
        );
        assert_eq!(
            parse("1.2.3", r#"["1.2.2","1.2.2"]"#),
            Err(ReleaseManifestError::DuplicatePredecessor)
        );

        let uppercase = String::from_utf8(manifest("1.2.3", "[]"))
            .unwrap()
            .replace(DIGEST, &DIGEST.to_uppercase());
        assert_eq!(
            parse_release_manifest(APPLICATION_ARCHIVES[0], uppercase.as_bytes()),
            Err(ReleaseManifestError::InvalidExecutableDigest)
        );
    }

    #[test]
    fn bounds_manifest_and_predecessor_count() {
        assert_eq!(
            parse_release_manifest(
                APPLICATION_ARCHIVES[0],
                &vec![b' '; APPLICATION_RELEASE_MANIFEST_MAX_BYTES + 1]
            ),
            Err(ReleaseManifestError::TooLarge)
        );
        let predecessors = (0..=RELEASE_MANIFEST_MAX_ROLLBACK_PREDECESSORS)
            .map(|patch| format!(r#""0.0.{patch}""#))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse("1.0.0", &format!("[{predecessors}]")),
            Err(ReleaseManifestError::TooManyPredecessors)
        );
    }

    #[test]
    fn rollback_requires_same_compiled_target() {
        let current = parse("1.2.3", r#"["1.2.2"]"#).unwrap();
        let other_target = String::from_utf8(manifest("1.2.2", "[]"))
            .unwrap()
            .replace("aarch64-apple-darwin", "x86_64-apple-darwin");
        let predecessor =
            parse_release_manifest(APPLICATION_ARCHIVES[1], other_target.as_bytes()).unwrap();
        assert!(!current.declares_rollback_compatibility_to(&predecessor));
    }

    #[test]
    fn build_metadata_does_not_invent_release_precedence() {
        let current = parse("1.2.3+new", r#"["1.2.3+old"]"#);
        assert_eq!(current, Err(ReleaseManifestError::InvalidPredecessor));
    }
}
