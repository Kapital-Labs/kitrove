use std::fmt;

use serde::{Deserialize, Serialize};

#[cfg(any(unix, windows))]
use crate::StagingInput;
use kitrove_release_policy::{
    APPLICATION_ARCHIVE_LIMITS, ApplicationStateSchema, LifecycleLockProtocol,
    application_archive_for_target,
};
use kitrove_release_provenance::{ExpectedReleaseIdentity, PINNED_SIGSTORE_TRUST_ROOT_SHA256};

const OPERATION_RECORD_SCHEMA: u32 = 3;
pub(crate) const MAX_OPERATION_RECORD_BYTES: usize = 32 * 1024;
pub(crate) const MAX_DESTINATION_PATH_BYTES: usize = 2 * 1024;
const MAX_DESTINATION_PATH_HEX_BYTES: usize = MAX_DESTINATION_PATH_BYTES * 2;
const MAX_ANCESTRY_IDENTITIES: usize = 128;
const OPERATION_ID_RANDOM_BYTES: usize = 16;

#[cfg(any(unix, windows))]
#[allow(dead_code)]
// Historical record policy is distinct from live authority; filesystem inspection is separate.
#[path = "history_record.rs"]
pub(crate) mod history;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallerOperationPhase {
    Prepared,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NativeFileIdentityPlatform {
    Unix,
    Windows,
}

/// A complete, platform-tagged native identity for one filesystem object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFileIdentity {
    platform: NativeFileIdentityPlatform,
    filesystem_id: u64,
    file_id: [u8; 16],
}

impl NativeFileIdentity {
    #[cfg(unix)]
    pub(crate) const fn new(device: u64, file: u64) -> Self {
        let mut file_id = [0_u8; 16];
        let bytes = file.to_le_bytes();
        let mut index = 0;
        while index < bytes.len() {
            file_id[index] = bytes[index];
            index += 1;
        }
        Self {
            platform: NativeFileIdentityPlatform::Unix,
            filesystem_id: device,
            file_id,
        }
    }

    #[cfg(windows)]
    pub(crate) const fn new_windows(filesystem_id: u64, file_id: [u8; 16]) -> Self {
        Self {
            platform: NativeFileIdentityPlatform::Windows,
            filesystem_id,
            file_id,
        }
    }

    #[cfg(windows)]
    pub(crate) const fn maximum_windows() -> Self {
        Self::new_windows(u64::MAX, [u8::MAX; 16])
    }

    pub(crate) fn matches_target(self, target: &str) -> bool {
        match self.platform {
            NativeFileIdentityPlatform::Unix => is_unix_release_target(target),
            NativeFileIdentityPlatform::Windows => is_windows_release_target(target),
        }
    }

    pub(crate) fn is_valid(self) -> bool {
        match self.platform {
            NativeFileIdentityPlatform::Unix => {
                self.file_id[..8] != [0_u8; 8] && self.file_id[8..] == [0_u8; 8]
            }
            NativeFileIdentityPlatform::Windows => self.file_id != [0_u8; 16],
        }
    }
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyNativeFileIdentity {
    device: u64,
    file: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallerOperationData {
    schema: u32,
    phase: InstallerOperationPhase,
    operation_id: String,
    target: String,
    archive_name: String,
    archive_sha256: String,
    executable_name: String,
    executable_size: u64,
    executable_sha256: String,
    release_manifest_sha256: String,
    application_state_schema: String,
    lifecycle_lock_protocol: u64,
    release_tag: String,
    release_version: String,
    source_commit: String,
    signer_identity: String,
    attestation_bundle_sha256: String,
    trust_root_sha256: String,
    destination_path_hex: String,
    ancestry_identities: Vec<NativeFileIdentity>,
    state_identity: NativeFileIdentity,
    lock_identity: NativeFileIdentity,
    operation_identity: NativeFileIdentity,
    staged_identity: NativeFileIdentity,
}

/// An authenticated prepared record created only from verified release authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct InstallerOperationRecord(InstallerOperationData);

/// A bounded, strictly parsed record that does not grant installation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedInstallerOperationRecord(InstallerOperationData);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidInstallerOperationRecord {
    kind: InvalidInstallerOperationRecordKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvalidInstallerOperationRecordKind {
    Invalid,
    UnsupportedSchema(u32),
}

impl InvalidInstallerOperationRecord {
    const INVALID: Self = Self {
        kind: InvalidInstallerOperationRecordKind::Invalid,
    };

    const fn unsupported_schema(schema: u32) -> Self {
        Self {
            kind: InvalidInstallerOperationRecordKind::UnsupportedSchema(schema),
        }
    }

    #[must_use]
    #[cfg(any(unix, windows))]
    pub(crate) const fn is_legacy_schema(self) -> bool {
        matches!(
            self.kind,
            InvalidInstallerOperationRecordKind::UnsupportedSchema(1 | 2)
        )
    }
}

impl fmt::Display for InvalidInstallerOperationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid installer operation record")
    }
}

impl std::error::Error for InvalidInstallerOperationRecord {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallerOperationRecordWire<Identity> {
    schema: u32,
    phase: InstallerOperationPhase,
    operation_id: String,
    target: String,
    archive_name: String,
    archive_sha256: String,
    executable_name: String,
    executable_size: u64,
    executable_sha256: String,
    release_manifest_sha256: String,
    application_state_schema: String,
    lifecycle_lock_protocol: u64,
    release_tag: String,
    release_version: String,
    source_commit: String,
    signer_identity: String,
    attestation_bundle_sha256: String,
    trust_root_sha256: String,
    destination_path_hex: String,
    ancestry_identities: Vec<Identity>,
    state_identity: Identity,
    lock_identity: Identity,
    operation_identity: Identity,
    staged_identity: Identity,
}

type CurrentInstallerOperationRecordWire = InstallerOperationRecordWire<NativeFileIdentity>;
// Schema 2 uses the current field set but Unix-only two-word identities. Decode
// it only to distinguish retained predecessor state; it never grants authority.
type InstallerOperationRecordWireV2 = InstallerOperationRecordWire<LegacyNativeFileIdentity>;

// Schema 1 is decoded only to distinguish an exact retained predecessor record from
// unrelated hostile bytes. It can never be converted into installation authority.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallerOperationRecordWireV1 {
    schema: u32,
    phase: InstallerOperationPhase,
    operation_id: String,
    target: String,
    archive_name: String,
    archive_sha256: String,
    executable_name: String,
    executable_size: u64,
    executable_sha256: String,
    release_tag: String,
    release_version: String,
    source_commit: String,
    signer_identity: String,
    attestation_bundle_sha256: String,
    trust_root_sha256: String,
    destination_path_hex: String,
    ancestry_identities: Vec<LegacyNativeFileIdentity>,
    state_identity: LegacyNativeFileIdentity,
    lock_identity: LegacyNativeFileIdentity,
    operation_identity: LegacyNativeFileIdentity,
    staged_identity: LegacyNativeFileIdentity,
}

impl TryFrom<CurrentInstallerOperationRecordWire> for InstallerOperationData {
    type Error = InvalidInstallerOperationRecord;

    fn try_from(wire: CurrentInstallerOperationRecordWire) -> Result<Self, Self::Error> {
        let invalid = InvalidInstallerOperationRecord::INVALID;
        if wire.schema != OPERATION_RECORD_SCHEMA {
            return Err(InvalidInstallerOperationRecord::unsupported_schema(
                wire.schema,
            ));
        }
        let spec = application_archive_for_target(&wire.target).map_err(|_| invalid)?;
        let expected = ExpectedReleaseIdentity::new(&wire.release_tag, &wire.source_commit)
            .map_err(|_| invalid)?;
        let destination_component_count =
            destination_path_component_count(&wire.target, &wire.destination_path_hex)?;
        if wire.phase != InstallerOperationPhase::Prepared
            || !is_operation_id(&wire.operation_id)
            || wire.archive_name != spec.archive_name()
            || !is_lower_hex(&wire.archive_sha256, 64)
            || wire.executable_name != spec.executable_name()
            || wire.executable_size == 0
            || wire.executable_size > APPLICATION_ARCHIVE_LIMITS.max_entry_bytes
            || !is_lower_hex(&wire.executable_sha256, 64)
            || !is_lower_hex(&wire.release_manifest_sha256, 64)
            || wire.application_state_schema != ApplicationStateSchema::V1.as_str()
            || wire.lifecycle_lock_protocol != LifecycleLockProtocol::V1.version()
            || wire.release_version != expected.release_version().to_string()
            || wire.signer_identity != expected.signer_identity()
            || !is_lower_hex(&wire.attestation_bundle_sha256, 64)
            || wire.trust_root_sha256 != encode_hex(&PINNED_SIGSTORE_TRUST_ROOT_SHA256)
            || wire.ancestry_identities.len() != destination_component_count + 1
            || wire.ancestry_identities.len() > MAX_ANCESTRY_IDENTITIES
            || wire
                .ancestry_identities
                .iter()
                .any(|identity| !identity.is_valid() || !identity.matches_target(&wire.target))
            || !wire.state_identity.is_valid()
            || !wire.state_identity.matches_target(&wire.target)
            || !wire.lock_identity.is_valid()
            || !wire.lock_identity.matches_target(&wire.target)
            || !wire.operation_identity.is_valid()
            || !wire.operation_identity.matches_target(&wire.target)
            || !wire.staged_identity.is_valid()
            || !wire.staged_identity.matches_target(&wire.target)
        {
            return Err(invalid);
        }
        Ok(Self {
            schema: wire.schema,
            phase: wire.phase,
            operation_id: wire.operation_id,
            target: wire.target,
            archive_name: wire.archive_name,
            archive_sha256: wire.archive_sha256,
            executable_name: wire.executable_name,
            executable_size: wire.executable_size,
            executable_sha256: wire.executable_sha256,
            release_manifest_sha256: wire.release_manifest_sha256,
            application_state_schema: wire.application_state_schema,
            lifecycle_lock_protocol: wire.lifecycle_lock_protocol,
            release_tag: wire.release_tag,
            release_version: wire.release_version,
            source_commit: wire.source_commit,
            signer_identity: wire.signer_identity,
            attestation_bundle_sha256: wire.attestation_bundle_sha256,
            trust_root_sha256: wire.trust_root_sha256,
            destination_path_hex: wire.destination_path_hex,
            ancestry_identities: wire.ancestry_identities,
            state_identity: wire.state_identity,
            lock_identity: wire.lock_identity,
            operation_identity: wire.operation_identity,
            staged_identity: wire.staged_identity,
        })
    }
}

#[cfg(any(unix, windows))]
pub(crate) struct PreparedFilesystemEvidence<'a> {
    pub(crate) destination_path: &'a [u8],
    pub(crate) ancestry_identities: &'a [NativeFileIdentity],
    pub(crate) state_identity: NativeFileIdentity,
    pub(crate) lock_identity: NativeFileIdentity,
    pub(crate) operation_identity: NativeFileIdentity,
    pub(crate) staged_identity: NativeFileIdentity,
}

impl InstallerOperationRecord {
    #[cfg(any(unix, windows))]
    pub(crate) fn prepared(
        operation_id: String,
        input: &StagingInput<'_>,
        filesystem: PreparedFilesystemEvidence<'_>,
    ) -> Self {
        Self(InstallerOperationData {
            schema: OPERATION_RECORD_SCHEMA,
            phase: InstallerOperationPhase::Prepared,
            operation_id,
            target: input.target.to_owned(),
            archive_name: input.archive_name.to_owned(),
            archive_sha256: encode_hex(&input.archive_sha256),
            executable_name: input.executable_name.to_owned(),
            executable_size: input.executable_bytes.len() as u64,
            executable_sha256: encode_hex(&input.executable_sha256),
            release_manifest_sha256: encode_hex(&input.manifest_sha256),
            application_state_schema: input
                .manifest
                .application_state_schema()
                .as_str()
                .to_owned(),
            lifecycle_lock_protocol: input.manifest.lifecycle_lock_protocol().version(),
            release_tag: input.release_tag.to_owned(),
            release_version: input.release_version.clone(),
            source_commit: input.source_commit.to_owned(),
            signer_identity: input.signer_identity.to_owned(),
            attestation_bundle_sha256: encode_hex(&input.attestation_bundle_sha256),
            trust_root_sha256: encode_hex(&input.trust_root_sha256),
            destination_path_hex: encode_hex(filesystem.destination_path),
            ancestry_identities: filesystem.ancestry_identities.to_vec(),
            state_identity: filesystem.state_identity,
            lock_identity: filesystem.lock_identity,
            operation_identity: filesystem.operation_identity,
            staged_identity: filesystem.staged_identity,
        })
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.0.operation_id
    }

    #[must_use]
    pub const fn phase(&self) -> InstallerOperationPhase {
        self.0.phase
    }

    #[must_use]
    pub const fn staged_identity(&self) -> &NativeFileIdentity {
        &self.0.staged_identity
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn executable_name(&self) -> &str {
        &self.0.executable_name
    }

    #[cfg(any(unix, windows))]
    pub(crate) const fn executable_size(&self) -> u64 {
        self.0.executable_size
    }

    #[must_use]
    pub fn ancestry_identities(&self) -> &[NativeFileIdentity] {
        &self.0.ancestry_identities
    }

    #[must_use]
    pub const fn state_identity(&self) -> &NativeFileIdentity {
        &self.0.state_identity
    }

    #[must_use]
    pub const fn lock_identity(&self) -> &NativeFileIdentity {
        &self.0.lock_identity
    }

    #[must_use]
    pub const fn operation_identity(&self) -> &NativeFileIdentity {
        &self.0.operation_identity
    }

    /// Parses hostile durable bytes without granting authority to install them.
    pub fn parse_untrusted(
        bytes: &[u8],
    ) -> Result<UnverifiedInstallerOperationRecord, InvalidInstallerOperationRecord> {
        if bytes.len() > MAX_OPERATION_RECORD_BYTES {
            return Err(InvalidInstallerOperationRecord::INVALID);
        }
        match serde_json::from_slice::<CurrentInstallerOperationRecordWire>(bytes) {
            Ok(wire) if wire.schema == OPERATION_RECORD_SCHEMA => {
                Ok(UnverifiedInstallerOperationRecord(wire.try_into()?))
            }
            Ok(_) | Err(_) => Err(parse_legacy_schema(bytes)
                .map(InvalidInstallerOperationRecord::unsupported_schema)
                .unwrap_or(InvalidInstallerOperationRecord::INVALID)),
        }
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn matches_release(
        &self,
        input: &StagingInput<'_>,
    ) -> Result<(), InvalidInstallerOperationRecord> {
        // Reuse complete record construction; these stored filesystem fields are
        // comparison context only, not fresh filesystem validation.
        let destination_path = decode_path_hex(&self.0.destination_path_hex)?;
        let expected = Self::prepared(
            self.0.operation_id.clone(),
            input,
            PreparedFilesystemEvidence {
                destination_path: &destination_path,
                ancestry_identities: &self.0.ancestry_identities,
                state_identity: self.0.state_identity,
                lock_identity: self.0.lock_identity,
                operation_identity: self.0.operation_identity,
                staged_identity: self.0.staged_identity,
            },
        );
        if *self == expected {
            Ok(())
        } else {
            Err(InvalidInstallerOperationRecord::INVALID)
        }
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

fn parse_legacy_schema(bytes: &[u8]) -> Option<u32> {
    if serde_json::from_slice::<InstallerOperationRecordWireV2>(bytes)
        .ok()
        .is_some_and(|wire| wire.schema == 2)
    {
        Some(2)
    } else if serde_json::from_slice::<InstallerOperationRecordWireV1>(bytes)
        .ok()
        .is_some_and(|wire| wire.schema == 1)
    {
        Some(1)
    } else {
        None
    }
}

impl UnverifiedInstallerOperationRecord {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.0.operation_id
    }

    #[cfg(unix)]
    pub(crate) fn executable_name(&self) -> &str {
        &self.0.executable_name
    }

    #[cfg(any(unix, windows))]
    pub(crate) const fn executable_size(&self) -> u64 {
        self.0.executable_size
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn authenticate_prepared(
        self,
        input: &StagingInput<'_>,
        filesystem: PreparedFilesystemEvidence<'_>,
    ) -> Result<InstallerOperationRecord, InvalidInstallerOperationRecord> {
        let expected =
            InstallerOperationRecord::prepared(self.0.operation_id.clone(), input, filesystem);
        if self.0 == expected.0 {
            Ok(expected)
        } else {
            Err(InvalidInstallerOperationRecord::INVALID)
        }
    }
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut encoded, byte| {
            write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
            encoded
        },
    )
}

#[cfg(any(unix, windows))]
pub(crate) fn encode_operation_id(bytes: [u8; OPERATION_ID_RANDOM_BYTES]) -> String {
    encode_hex(&bytes)
}

pub(crate) fn is_operation_id(value: &str) -> bool {
    is_lower_hex(value, OPERATION_ID_RANDOM_BYTES * 2)
}

pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn destination_path_component_count(
    target: &str,
    value: &str,
) -> Result<usize, InvalidInstallerOperationRecord> {
    let bytes = decode_path_hex(value)?;
    if is_unix_release_target(target) {
        unix_path_component_count(&bytes)
    } else if is_windows_release_target(target) {
        windows_path_component_count(&bytes)
    } else {
        Err(InvalidInstallerOperationRecord::INVALID)
    }
}

fn decode_path_hex(value: &str) -> Result<Vec<u8>, InvalidInstallerOperationRecord> {
    if value.is_empty() || value.len() > MAX_DESTINATION_PATH_HEX_BYTES || value.len() % 2 != 0 {
        return Err(InvalidInstallerOperationRecord::INVALID);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Some(high << 4 | low)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(InvalidInstallerOperationRecord::INVALID)
}

fn unix_path_component_count(bytes: &[u8]) -> Result<usize, InvalidInstallerOperationRecord> {
    if bytes.first() != Some(&b'/') || bytes.contains(&0) {
        return Err(InvalidInstallerOperationRecord::INVALID);
    }
    let components = bytes[1..].split(|byte| *byte == b'/');
    let mut count = 0_usize;
    for component in components {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(InvalidInstallerOperationRecord::INVALID);
        }
        count = count
            .checked_add(1)
            .ok_or(InvalidInstallerOperationRecord::INVALID)?;
    }
    if count == 0 || count >= MAX_ANCESTRY_IDENTITIES {
        return Err(InvalidInstallerOperationRecord::INVALID);
    }
    Ok(count)
}

fn windows_path_component_count(bytes: &[u8]) -> Result<usize, InvalidInstallerOperationRecord> {
    if bytes.len() % 2 != 0 {
        return Err(InvalidInstallerOperationRecord::INVALID);
    }
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    if units.len() < 4
        || !is_ascii_drive_letter(units[0])
        || units[1] != b':' as u16
        || units[2] != b'\\' as u16
        || units.contains(&0)
        || std::char::decode_utf16(units.iter().copied()).any(|value| value.is_err())
    {
        return Err(InvalidInstallerOperationRecord::INVALID);
    }
    let mut count = 0_usize;
    for component in units[3..].split(|unit| *unit == b'\\' as u16) {
        if component.is_empty()
            || component == [b'.' as u16]
            || component == [b'.' as u16, b'.' as u16]
            || component.contains(&(b'/' as u16))
        {
            return Err(InvalidInstallerOperationRecord::INVALID);
        }
        count = count
            .checked_add(1)
            .ok_or(InvalidInstallerOperationRecord::INVALID)?;
    }
    if count == 0 || count >= MAX_ANCESTRY_IDENTITIES {
        return Err(InvalidInstallerOperationRecord::INVALID);
    }
    Ok(count)
}

const fn is_ascii_drive_letter(unit: u16) -> bool {
    (unit >= b'A' as u16 && unit <= b'Z' as u16) || (unit >= b'a' as u16 && unit <= b'z' as u16)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn is_unix_release_target(target: &str) -> bool {
    matches!(
        target,
        "aarch64-apple-darwin" | "x86_64-apple-darwin" | "x86_64-unknown-linux-gnu"
    )
}

fn is_windows_release_target(target: &str) -> bool {
    matches!(target, "x86_64-pc-windows-msvc")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows_path_hex(path: &[u16]) -> String {
        encode_hex(
            &path
                .iter()
                .copied()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn windows_destination_path_requires_bounded_absolute_utf16_shape() {
        let valid = "C:\\Users\\Owner\\bin".encode_utf16().collect::<Vec<_>>();
        assert_eq!(
            destination_path_component_count("x86_64-pc-windows-msvc", &windows_path_hex(&valid)),
            Ok(3),
        );

        for invalid in [
            "C:\\",
            "C:relative",
            "C:\\Users\\..\\bin",
            "C:\\Users\\.\\bin",
            "C:\\Users\\\\bin",
            "C:\\Users/bin",
            "\\\\server\\share\\bin",
        ] {
            let units = invalid.encode_utf16().collect::<Vec<_>>();
            assert!(
                destination_path_component_count(
                    "x86_64-pc-windows-msvc",
                    &windows_path_hex(&units),
                )
                .is_err(),
                "accepted invalid Windows path {invalid:?}",
            );
        }

        let unpaired_surrogate = [b'C' as u16, b':' as u16, b'\\' as u16, 0xd800];
        assert!(
            destination_path_component_count(
                "x86_64-pc-windows-msvc",
                &windows_path_hex(&unpaired_surrogate),
            )
            .is_err()
        );
    }
}
