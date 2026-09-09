use const_oid::ObjectIdentifier;
use der::{Decode, asn1::Utf8StringRef};
use sigstore_types::Bundle;
use x509_cert::{
    Certificate,
    ext::{
        Extension,
        pkix::{SubjectAltName, name::GeneralName},
    },
};

use crate::{AttestationPolicy, GITHUB_OIDC_ISSUER, ReleaseAttestationError};

pub(super) const OIDC_ISSUER_V2_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
pub(super) const BUILD_SIGNER_URI_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.9");
pub(super) const BUILD_SIGNER_DIGEST_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.10");
pub(super) const RUNNER_ENVIRONMENT_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.11");
pub(super) const SOURCE_REPOSITORY_URI_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.12");
pub(super) const SOURCE_REPOSITORY_DIGEST_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.13");
pub(super) const SOURCE_REPOSITORY_REF_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.14");
pub(super) const SOURCE_REPOSITORY_ID_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.15");
pub(super) const SOURCE_REPOSITORY_OWNER_URI_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.16");
pub(super) const SOURCE_REPOSITORY_OWNER_ID_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.17");
pub(super) const BUILD_CONFIG_URI_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.18");
pub(super) const BUILD_CONFIG_DIGEST_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.19");
pub(super) const BUILD_TRIGGER_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.20");
pub(super) const RUN_INVOCATION_URI_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.21");
pub(super) const SOURCE_REPOSITORY_VISIBILITY_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.22");
pub(super) const TOKEN_SUBJECT_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.24");

pub(super) const LEGACY_ISSUER_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
pub(super) const LEGACY_TRIGGER_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.2");
pub(super) const LEGACY_SOURCE_COMMIT_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.3");
pub(super) const LEGACY_WORKFLOW_NAME_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.4");
pub(super) const LEGACY_REPOSITORY_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.5");
pub(super) const LEGACY_SOURCE_REF_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.6");

pub(super) fn validate(
    bundle: &Bundle,
    policy: &AttestationPolicy<'_>,
) -> Result<String, ReleaseAttestationError> {
    let certificate = bundle
        .signing_certificate()
        .ok_or(ReleaseAttestationError::InvalidCertificateClaims)
        .and_then(|bytes| {
            Certificate::from_der(bytes.as_bytes())
                .map_err(|_| ReleaseAttestationError::InvalidCertificateClaims)
        })?;
    let Some((critical, SubjectAltName(names))) = certificate
        .tbs_certificate
        .get::<SubjectAltName>()
        .map_err(|_| ReleaseAttestationError::InvalidCertificateClaims)?
    else {
        return Err(ReleaseAttestationError::InvalidCertificateClaims);
    };
    let [GeneralName::UniformResourceIdentifier(identity)] = names.as_slice() else {
        return Err(ReleaseAttestationError::InvalidCertificateClaims);
    };
    if !critical || identity.as_str() != policy.signer_identity {
        return Err(ReleaseAttestationError::InvalidCertificateClaims);
    }
    for (oid, expected) in [
        (OIDC_ISSUER_V2_OID, GITHUB_OIDC_ISSUER),
        (BUILD_SIGNER_URI_OID, policy.signer_identity),
        (BUILD_SIGNER_DIGEST_OID, policy.source_commit),
        (RUNNER_ENVIRONMENT_OID, policy.runner_environment),
        (SOURCE_REPOSITORY_URI_OID, policy.repository_uri),
        (SOURCE_REPOSITORY_DIGEST_OID, policy.source_commit),
        (SOURCE_REPOSITORY_REF_OID, policy.source_ref),
        (SOURCE_REPOSITORY_ID_OID, policy.repository_id),
        (SOURCE_REPOSITORY_OWNER_URI_OID, policy.owner_uri),
        (SOURCE_REPOSITORY_OWNER_ID_OID, policy.owner_id),
        (BUILD_CONFIG_URI_OID, policy.signer_identity),
        (BUILD_CONFIG_DIGEST_OID, policy.source_commit),
        (BUILD_TRIGGER_OID, policy.build_trigger),
        (
            SOURCE_REPOSITORY_VISIBILITY_OID,
            policy.repository_visibility,
        ),
        (
            TOKEN_SUBJECT_OID,
            &format!("repo:{}:ref:{}", policy.repository_slug, policy.source_ref),
        ),
    ] {
        if extension_utf8(&certificate, oid)? != expected {
            return Err(ReleaseAttestationError::InvalidCertificateClaims);
        }
    }
    for (oid, expected) in [
        (LEGACY_ISSUER_OID, GITHUB_OIDC_ISSUER),
        (LEGACY_TRIGGER_OID, policy.build_trigger),
        (LEGACY_SOURCE_COMMIT_OID, policy.source_commit),
        (LEGACY_WORKFLOW_NAME_OID, policy.workflow_name),
        (LEGACY_REPOSITORY_OID, policy.repository_slug),
        (LEGACY_SOURCE_REF_OID, policy.source_ref),
    ] {
        if let Some(observed) = optional_raw_extension(&certificate, oid)? {
            if observed != expected {
                return Err(ReleaseAttestationError::InvalidCertificateClaims);
            }
        }
    }
    let run_invocation = extension_utf8(&certificate, RUN_INVOCATION_URI_OID)?;
    validate_run_invocation(policy.repository_uri, run_invocation)?;
    Ok(run_invocation.to_owned())
}

fn extension_utf8(
    certificate: &Certificate,
    oid: ObjectIdentifier,
) -> Result<&str, ReleaseAttestationError> {
    let extension = unique_noncritical_extension(certificate, oid)?
        .ok_or(ReleaseAttestationError::InvalidCertificateClaims)?;
    Utf8StringRef::from_der(extension.extn_value.as_bytes())
        .map(|value| value.as_str())
        .map_err(|_| ReleaseAttestationError::InvalidCertificateClaims)
}

fn unique_noncritical_extension(
    certificate: &Certificate,
    oid: ObjectIdentifier,
) -> Result<Option<&Extension>, ReleaseAttestationError> {
    let mut matches = certificate
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|extension| extension.extn_id == oid);
    let extension = matches.next();
    if matches.next().is_some() || extension.is_some_and(|value| value.critical) {
        return Err(ReleaseAttestationError::InvalidCertificateClaims);
    }
    Ok(extension)
}

fn optional_raw_extension(
    certificate: &Certificate,
    oid: ObjectIdentifier,
) -> Result<Option<&str>, ReleaseAttestationError> {
    let Some(extension) = unique_noncritical_extension(certificate, oid)? else {
        return Ok(None);
    };
    std::str::from_utf8(extension.extn_value.as_bytes())
        .map(Some)
        .map_err(|_| ReleaseAttestationError::InvalidCertificateClaims)
}

pub(super) fn validate_run_invocation(
    repository_uri: &str,
    invocation: &str,
) -> Result<(), ReleaseAttestationError> {
    let suffix = invocation
        .strip_prefix(repository_uri)
        .and_then(|value| value.strip_prefix("/actions/runs/"))
        .ok_or(ReleaseAttestationError::InvalidCertificateClaims)?;
    let (run, attempt) = suffix
        .split_once("/attempts/")
        .ok_or(ReleaseAttestationError::InvalidCertificateClaims)?;
    if !is_nonzero_decimal(run) || !is_nonzero_decimal(attempt) {
        return Err(ReleaseAttestationError::InvalidCertificateClaims);
    }
    Ok(())
}

fn is_nonzero_decimal(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())
}
