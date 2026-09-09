//! Shared exact release inputs for candidate and prior selections. No inferred pins.

use crate::release_intake::LocalReleaseRequest;
use kitrove_release_provenance::ExpectedReleaseIdentity;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

pub(super) struct ReleasePin {
    pub(super) expected: ExpectedReleaseIdentity,
    pub(super) digest: [u8; 32],
}

pub(super) struct ReleaseInput {
    pub(super) archive: PathBuf,
    pub(super) bundle: PathBuf,
    pub(super) pin: ReleasePin,
}

pub(super) fn take(values: &mut BTreeMap<String, OsString>, key: &str) -> Result<OsString, String> {
    values.remove(key).ok_or_else(|| format!("missing {key}"))
}

impl ReleasePin {
    pub(super) fn parse(
        values: &mut BTreeMap<String, OsString>,
        prefix: &str,
    ) -> Result<Self, String> {
        let tag = take(values, &format!("--{prefix}tag"))?;
        let commit = take(values, &format!("--{prefix}commit"))?;
        let expected = ExpectedReleaseIdentity::new(
            tag.to_str().ok_or("invalid tag")?,
            commit.to_str().ok_or("invalid commit")?,
        )
        .map_err(|_| "invalid exact release identity")?;
        let sha = take(values, &format!("--{prefix}sha256"))?;
        let sha = sha.to_str().ok_or("invalid SHA-256")?;
        if sha.len() != 64 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("SHA-256 must contain exactly 64 hexadecimal digits".into());
        }
        let mut digest = [0; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&sha[index * 2..index * 2 + 2], 16)
                .map_err(|_| "invalid SHA-256")?;
        }
        Ok(Self { expected, digest })
    }
}

impl ReleaseInput {
    pub(super) fn parse(
        values: &mut BTreeMap<String, OsString>,
        prefix: &str,
    ) -> Result<Self, String> {
        Ok(Self {
            archive: PathBuf::from(take(values, &format!("--{prefix}archive"))?),
            bundle: PathBuf::from(take(values, &format!("--{prefix}bundle"))?),
            pin: ReleasePin::parse(values, prefix)?,
        })
    }

    pub(super) fn authenticate(
        &self,
    ) -> Result<kitrove_release_provenance::AuthenticatedRecoveryMaterial, String> {
        LocalReleaseRequest {
            archive: &self.archive,
            bundle: &self.bundle,
            expected: &self.pin.expected,
            archive_sha256: self.pin.digest,
        }
        .authenticate()
        .map_err(|error| error.to_string())
    }
}
