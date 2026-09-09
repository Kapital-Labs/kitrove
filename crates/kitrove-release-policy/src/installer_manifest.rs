use crate::release_manifest::{encode_sha256, parse_canonical_version, parse_sha256};
use crate::{APPLICATION_RELEASE_MANIFEST_MAX_BYTES, InstallerArchiveSpec, ReleaseManifestError};
use semver::Version;
use serde::{Deserialize, Serialize};

/// Bounded unauthenticated installer claims; deliberately no application compatibility fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedInstallerManifest {
    release_version: Version,
    target: &'static str,
    executable_sha256: [u8; 32],
}

impl ParsedInstallerManifest {
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
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawInstallerManifest {
    schema: u64,
    artifact_kind: String,
    release_version: String,
    target: String,
    executable_name: String,
    executable_sha256: String,
}

pub fn render_installer_manifest(
    spec: InstallerArchiveSpec,
    version: &Version,
    digest: [u8; 32],
) -> Result<Vec<u8>, ReleaseManifestError> {
    let bytes = serde_json::to_vec(&RawInstallerManifest {
        schema: 1,
        artifact_kind: "installer".into(),
        release_version: version.to_string(),
        target: spec.target().into(),
        executable_name: spec.executable_name().into(),
        executable_sha256: encode_sha256(digest),
    })
    .map_err(|_| ReleaseManifestError::InvalidJson)?;
    parse_installer_manifest(spec, &bytes)?;
    Ok(bytes)
}

pub fn parse_installer_manifest(
    spec: InstallerArchiveSpec,
    bytes: &[u8],
) -> Result<ParsedInstallerManifest, ReleaseManifestError> {
    if bytes.len() > APPLICATION_RELEASE_MANIFEST_MAX_BYTES {
        return Err(ReleaseManifestError::TooLarge);
    }
    let raw: RawInstallerManifest =
        serde_json::from_slice(bytes).map_err(|_| ReleaseManifestError::InvalidJson)?;
    if raw.schema != 1 {
        return Err(ReleaseManifestError::UnsupportedSchema);
    }
    if raw.artifact_kind != "installer" {
        return Err(ReleaseManifestError::InvalidArtifactKind);
    }
    if raw.target != spec.target() {
        return Err(ReleaseManifestError::TargetMismatch);
    }
    if raw.executable_name != spec.executable_name() {
        return Err(ReleaseManifestError::ExecutableNameMismatch);
    }
    Ok(ParsedInstallerManifest {
        release_version: parse_canonical_version(&raw.release_version)
            .ok_or(ReleaseManifestError::InvalidReleaseVersion)?,
        target: spec.target(),
        executable_sha256: parse_sha256(&raw.executable_sha256)
            .ok_or(ReleaseManifestError::InvalidExecutableDigest)?,
    })
}
