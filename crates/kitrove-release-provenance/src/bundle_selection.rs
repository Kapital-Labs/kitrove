use std::fmt;

use kitrove_release_policy::{
    ApplicationArchiveIntake, InspectedInstallerRelease, InstallerContainerSpec,
};
use sha2::{Digest as _, Sha256};

use crate::{
    APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES, ExpectedReleaseIdentity, ReleaseAttestationError,
    parse_bundle, verify_release_attestation,
};

pub const ATTESTATION_COLLECTION_MAX_RECORDS: usize = 32;
pub const ATTESTATION_COLLECTION_MAX_BYTES: usize =
    ATTESTATION_COLLECTION_MAX_RECORDS * APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleSelectionError {
    InvalidCollection,
    InvalidArchiveManifest,
    InvalidContainerSize,
    NoMatchingBundle,
    AmbiguousBundles,
}

impl fmt::Display for BundleSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCollection => {
                "attestation collection is malformed, unsupported or exceeds its bounds"
            }
            Self::InvalidArchiveManifest => "archive manifest does not match the selected release",
            Self::InvalidContainerSize => "installer image is empty or exceeds its bound",
            Self::NoMatchingBundle => {
                "no attestation authenticates the exact selected release archive"
            }
            Self::AmbiguousBundles => {
                "multiple attestations authenticate the selected release archive"
            }
        })
    }
}

impl std::error::Error for BundleSelectionError {}

/// Returns exact single-bundle JSON, not reusable application or filesystem authority.
pub fn select_application_attestation_bundle(
    intake: ApplicationArchiveIntake,
    expected: &ExpectedReleaseIdentity,
    collection: &[u8],
) -> Result<Vec<u8>, BundleSelectionError> {
    select_bundle(collection, |bundle| {
        verify_release_attestation(
            intake.spec().archive_name(),
            intake.archive_sha256(),
            expected,
            bundle,
        )
    })
    .map(<[u8]>::to_vec)
}

/// Installer selection never grants application replacement authority.
pub fn select_installer_attestation_bundle(
    inspected: &InspectedInstallerRelease,
    expected: &ExpectedReleaseIdentity,
    collection: &[u8],
) -> Result<Vec<u8>, BundleSelectionError> {
    inspected
        .validate_manifest(expected.release_version())
        .map_err(|_| BundleSelectionError::InvalidArchiveManifest)?;
    select_bundle(collection, |bundle| {
        verify_release_attestation(
            inspected.spec().archive_name(),
            inspected.archive_sha256(),
            expected,
            bundle,
        )
    })
    .map(<[u8]>::to_vec)
}

/// Select one exact image attestation without mounting or granting executable authority.
pub fn select_installer_container_attestation_bundle(
    spec: InstallerContainerSpec,
    image: &[u8],
    expected: &ExpectedReleaseIdentity,
    collection: &[u8],
) -> Result<Vec<u8>, BundleSelectionError> {
    crate::installer_container::validate_image_size(image.len())
        .map_err(|_| BundleSelectionError::InvalidContainerSize)?;
    let digest = Sha256::digest(image).into();
    select_bundle(collection, |bundle| {
        verify_release_attestation(spec.image_name(), digest, expected, bundle)
    })
    .map(<[u8]>::to_vec)
}

fn select_bundle(
    collection: &[u8],
    mut verify: impl FnMut(&[u8]) -> Result<(), ReleaseAttestationError>,
) -> Result<&[u8], BundleSelectionError> {
    if collection.is_empty() || collection.len() > ATTESTATION_COLLECTION_MAX_BYTES {
        return Err(BundleSelectionError::InvalidCollection);
    }
    let text =
        std::str::from_utf8(collection).map_err(|_| BundleSelectionError::InvalidCollection)?;
    let mut records = Vec::new();
    // Validate the whole framing/shape before starting bounded cryptographic work.
    for line in text.split_terminator('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty()
            || line.len() > APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES
            || records.len() == ATTESTATION_COLLECTION_MAX_RECORDS
        {
            return Err(BundleSelectionError::InvalidCollection);
        }
        let bytes = line.as_bytes();
        parse_bundle(bytes).map_err(|_| BundleSelectionError::InvalidCollection)?;
        records.push(bytes);
    }
    let mut selected = None;
    for record in records {
        if verify(record).is_ok() {
            if selected.is_some() {
                return Err(BundleSelectionError::AmbiguousBundles);
            }
            selected = Some(record);
        }
    }
    selected.ok_or(BundleSelectionError::NoMatchingBundle)
}

#[cfg(test)]
#[path = "bundle_selection_tests.rs"]
mod tests;
