use std::ffi::{OsStr, OsString};

#[cfg(unix)]
use crate::filesystem_identity::MetadataIdentity;
#[cfg(windows)]
use kitrove_windows_security::WindowsFileIdentity;

#[cfg(unix)]
type PlatformIdentity = MetadataIdentity;
#[cfg(windows)]
type PlatformIdentity = WindowsFileIdentity;

#[cfg(unix)]
const PREFIX: &str = ".kitrove-removed-v1-unix-";
#[cfg(windows)]
const PREFIX: &str = ".kitrove-removed-v1-windows-";
#[cfg(any(unix, windows))]
const CLEANUP_PENDING_PREFIX: &str = ".kitrove-cleanup-pending-v1-";
#[cfg(unix)]
const CLEANUP_BATCH_PREFIX: &str = ".kitrove-cleanup-v1-unix-";
#[cfg(windows)]
const CLEANUP_BATCH_PREFIX: &str = ".kitrove-cleanup-v1-windows-";
#[cfg(unix)]
const CLEANUP_LEAF_PREFIX: &str = ".kitrove-cleanup-leaf-v1-unix-";
#[cfg(windows)]
const CLEANUP_LEAF_PREFIX: &str = ".kitrove-cleanup-leaf-v1-windows-";
#[cfg(any(not(unix), test))]
const RETAINED_PREFIX: &str = ".kitrove-retained-v1-";
const NONCE_HEX_LEN: usize = 32;
#[cfg(any(unix, windows))]
const IDENTITY_HEX_LEN: usize = 16;
#[cfg(windows)]
const WINDOWS_FILE_ID_HEX_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemovedObjectKind {
    File,
    Directory,
}

impl RemovedObjectKind {
    const fn tag(self) -> char {
        match self {
            Self::File => 'f',
            Self::Directory => 'd',
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            b'f' => Some(Self::File),
            b'd' => Some(Self::Directory),
            _ => None,
        }
    }
}

/// A canonical removal name that can be bounded and recognized but grants no deletion authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(not(unix), test))]
pub(crate) struct RetainedTombstoneName {
    pub(crate) kind: RemovedObjectKind,
}

#[cfg(any(not(unix), test))]
impl RetainedTombstoneName {
    pub(crate) fn encode(self, nonce: &str) -> Option<OsString> {
        if !is_lower_hex(nonce, NONCE_HEX_LEN) {
            return None;
        }
        Some(OsString::from(format!(
            "{RETAINED_PREFIX}{}-{nonce}",
            self.kind.tag()
        )))
    }

    pub(crate) fn parse(name: &OsStr) -> Option<Self> {
        let name = name.to_str()?;
        let encoded = name.strip_prefix(RETAINED_PREFIX)?;
        let mut segments = encoded.split('-');
        let kind = RemovedObjectKind::from_tag(single_ascii_byte(segments.next()?)?)?;
        let nonce = segments.next()?;
        if segments.next().is_some() || !is_lower_hex(nonce, NONCE_HEX_LEN) {
            return None;
        }
        Some(Self { kind })
    }
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RemovalTombstoneName {
    pub(crate) kind: RemovedObjectKind,
    pub(crate) identity: PlatformIdentity,
}

#[cfg(any(unix, windows))]
impl RemovalTombstoneName {
    pub(crate) fn encode(self, nonce: &str) -> Option<OsString> {
        encode_identity_nonce(
            &format!("{PREFIX}{}-", self.kind.tag()),
            self.identity,
            nonce,
        )
    }

    pub(crate) fn parse(name: &OsStr) -> Option<Self> {
        let encoded = name.to_str()?.strip_prefix(PREFIX)?;
        let (kind, identity_nonce) = encoded.split_once('-')?;
        Some(Self {
            kind: RemovedObjectKind::from_tag(single_ascii_byte(kind)?)?,
            identity: parse_identity_nonce(identity_nonce)?,
        })
    }
}

/// A transient cleanup directory name. It is recoverable only while proven empty.
#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CleanupPendingName;

#[cfg(any(unix, windows))]
impl CleanupPendingName {
    pub(crate) fn encode(nonce: &str) -> Option<OsString> {
        is_lower_hex(nonce, NONCE_HEX_LEN)
            .then(|| OsString::from(format!("{CLEANUP_PENDING_PREFIX}{nonce}")))
    }

    pub(crate) fn parse(name: &OsStr) -> Option<Self> {
        let nonce = name.to_str()?.strip_prefix(CLEANUP_PENDING_PREFIX)?;
        is_lower_hex(nonce, NONCE_HEX_LEN).then_some(Self)
    }
}

/// A persisted cleanup batch whose directory identity is encoded in its name.
#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CleanupBatchName {
    pub(crate) identity: PlatformIdentity,
}

#[cfg(any(unix, windows))]
impl CleanupBatchName {
    pub(crate) fn encode(self, nonce: &str) -> Option<OsString> {
        encode_identity_nonce(CLEANUP_BATCH_PREFIX, self.identity, nonce)
    }

    pub(crate) fn parse(name: &OsStr) -> Option<Self> {
        let encoded = name.to_str()?.strip_prefix(CLEANUP_BATCH_PREFIX)?;
        Some(Self {
            identity: parse_identity_nonce(encoded)?,
        })
    }
}

/// A file evacuated from a validated tree into its private cleanup batch root.
#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CleanupLeafName {
    pub(crate) identity: PlatformIdentity,
}

#[cfg(any(unix, windows))]
impl CleanupLeafName {
    #[cfg(any(unix, test))]
    pub(crate) fn encode(self, nonce: &str) -> Option<OsString> {
        encode_identity_nonce(CLEANUP_LEAF_PREFIX, self.identity, nonce)
    }

    pub(crate) fn parse(name: &OsStr) -> Option<Self> {
        let encoded = name.to_str()?.strip_prefix(CLEANUP_LEAF_PREFIX)?;
        Some(Self {
            identity: parse_identity_nonce(encoded)?,
        })
    }
}

#[cfg(unix)]
fn encode_identity_nonce(
    prefix: &str,
    identity: MetadataIdentity,
    nonce: &str,
) -> Option<OsString> {
    if !is_lower_hex(nonce, NONCE_HEX_LEN) {
        return None;
    }
    Some(OsString::from(format!(
        "{prefix}{:0IDENTITY_HEX_LEN$x}-{:0IDENTITY_HEX_LEN$x}-{nonce}",
        identity.device, identity.inode,
    )))
}

#[cfg(unix)]
fn parse_identity_nonce(encoded: &str) -> Option<MetadataIdentity> {
    let mut segments = encoded.split('-');
    let device = parse_fixed_hex(segments.next()?)?;
    let inode = parse_fixed_hex(segments.next()?)?;
    let nonce = segments.next()?;
    if segments.next().is_some() || !is_lower_hex(nonce, NONCE_HEX_LEN) {
        return None;
    }
    Some(MetadataIdentity { device, inode })
}

#[cfg(windows)]
fn encode_identity_nonce(
    prefix: &str,
    identity: WindowsFileIdentity,
    nonce: &str,
) -> Option<OsString> {
    if !is_lower_hex(nonce, NONCE_HEX_LEN) {
        return None;
    }
    let file_id = data_encoding::HEXLOWER.encode(&identity.file_id);
    Some(OsString::from(format!(
        "{prefix}{:016x}-{file_id}-{nonce}",
        identity.volume_serial_number,
    )))
}

#[cfg(windows)]
fn parse_identity_nonce(encoded: &str) -> Option<WindowsFileIdentity> {
    let mut segments = encoded.split('-');
    let volume = parse_fixed_hex(segments.next()?)?;
    let encoded_file_id = segments.next()?;
    let nonce = segments.next()?;
    if segments.next().is_some()
        || !is_lower_hex(encoded_file_id, WINDOWS_FILE_ID_HEX_LEN)
        || !is_lower_hex(nonce, NONCE_HEX_LEN)
    {
        return None;
    }
    let file_id = data_encoding::HEXLOWER
        .decode(encoded_file_id.as_bytes())
        .ok()?
        .try_into()
        .ok()?;
    Some(WindowsFileIdentity {
        volume_serial_number: volume,
        file_id,
    })
}

fn single_ascii_byte(value: &str) -> Option<u8> {
    let bytes = value.as_bytes();
    (bytes.len() == 1).then_some(bytes[0])
}

#[cfg(any(unix, windows))]
fn parse_fixed_hex(value: &str) -> Option<u64> {
    if !is_lower_hex(value, IDENTITY_HEX_LEN) {
        return None;
    }
    u64::from_str_radix(value, 16).ok()
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "00112233445566778899aabbccddeeff";

    #[cfg(unix)]
    #[test]
    fn removal_tombstone_name_round_trips_exact_identity() {
        let expected = RemovalTombstoneName {
            kind: RemovedObjectKind::Directory,
            identity: MetadataIdentity {
                device: 0x0123_4567_89ab_cdef,
                inode: 0xfedc_ba98_7654_3210,
            },
        };
        let encoded = expected.encode(NONCE).unwrap();

        assert_eq!(RemovalTombstoneName::parse(&encoded), Some(expected));
        assert_eq!(
            encoded,
            ".kitrove-removed-v1-unix-d-0123456789abcdef-fedcba9876543210-00112233445566778899aabbccddeeff"
        );
    }

    #[cfg(unix)]
    #[test]
    fn removal_tombstone_name_rejects_noncanonical_or_extra_data() {
        for name in [
            ".kitrove-removed-v1-unix-f-0000000000000001-0000000000000002-ABCDEFABCDEFABCDEFABCDEFABCDEFAB",
            ".kitrove-removed-v1-unix-x-0000000000000001-0000000000000002-00112233445566778899aabbccddeeff",
            ".kitrove-removed-v1-unix-f-1-0000000000000002-00112233445566778899aabbccddeeff",
            ".kitrove-removed-v1-unix-f-0000000000000001-0000000000000002-00112233445566778899aabbccddeeff-extra",
        ] {
            assert_eq!(RemovalTombstoneName::parse(OsStr::new(name)), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn removal_tombstone_name_rejects_invalid_nonce() {
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::File,
            identity: MetadataIdentity {
                device: 1,
                inode: 2,
            },
        };

        assert_eq!(name.encode("too-short"), None);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_names_round_trip_and_reject_noncanonical_data() {
        let identity = MetadataIdentity {
            device: 0x0123_4567_89ab_cdef,
            inode: 0xfedc_ba98_7654_3210,
        };
        let pending = CleanupPendingName::encode(NONCE).unwrap();
        let batch = CleanupBatchName { identity }.encode(NONCE).unwrap();
        let leaf = CleanupLeafName { identity }.encode(NONCE).unwrap();

        assert_eq!(
            CleanupPendingName::parse(&pending),
            Some(CleanupPendingName)
        );
        assert_eq!(
            CleanupBatchName::parse(&batch),
            Some(CleanupBatchName { identity })
        );
        assert_eq!(
            CleanupLeafName::parse(&leaf),
            Some(CleanupLeafName { identity })
        );
        assert_eq!(
            pending,
            ".kitrove-cleanup-pending-v1-00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            batch,
            ".kitrove-cleanup-v1-unix-0123456789abcdef-fedcba9876543210-00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            leaf,
            ".kitrove-cleanup-leaf-v1-unix-0123456789abcdef-fedcba9876543210-00112233445566778899aabbccddeeff"
        );

        for malformed in [
            ".kitrove-cleanup-pending-v1-ABCDEFABCDEFABCDEFABCDEFABCDEFAB",
            ".kitrove-cleanup-pending-v1-00112233445566778899aabbccddeeff-extra",
        ] {
            assert_eq!(CleanupPendingName::parse(OsStr::new(malformed)), None);
        }
        for malformed in [
            ".kitrove-cleanup-v1-unix-1-fedcba9876543210-00112233445566778899aabbccddeeff",
            ".kitrove-cleanup-v1-unix-0123456789abcdef-fedcba9876543210-ABCDEFABCDEFABCDEFABCDEFABCDEFAB",
            ".kitrove-cleanup-v1-unix-0123456789abcdef-fedcba9876543210-00112233445566778899aabbccddeeff-extra",
        ] {
            assert_eq!(CleanupBatchName::parse(OsStr::new(malformed)), None);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_names_round_trip_complete_native_identity() {
        let identity = WindowsFileIdentity {
            volume_serial_number: 0x0123_4567_89ab_cdef,
            file_id: [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        };
        let tombstone = RemovalTombstoneName {
            kind: RemovedObjectKind::File,
            identity,
        }
        .encode(NONCE)
        .unwrap();
        let pending = CleanupPendingName::encode(NONCE).unwrap();
        let batch = CleanupBatchName { identity }.encode(NONCE).unwrap();
        let leaf = CleanupLeafName { identity }.encode(NONCE).unwrap();

        assert_eq!(
            RemovalTombstoneName::parse(&tombstone),
            Some(RemovalTombstoneName {
                kind: RemovedObjectKind::File,
                identity,
            })
        );
        assert_eq!(
            CleanupPendingName::parse(&pending),
            Some(CleanupPendingName)
        );
        assert_eq!(
            CleanupBatchName::parse(&batch),
            Some(CleanupBatchName { identity })
        );
        assert_eq!(
            CleanupLeafName::parse(&leaf),
            Some(CleanupLeafName { identity })
        );
        assert_eq!(
            tombstone,
            ".kitrove-removed-v1-windows-f-0123456789abcdef-00112233445566778899aabbccddeeff-00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            batch,
            ".kitrove-cleanup-v1-windows-0123456789abcdef-00112233445566778899aabbccddeeff-00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            leaf,
            ".kitrove-cleanup-leaf-v1-windows-0123456789abcdef-00112233445566778899aabbccddeeff-00112233445566778899aabbccddeeff"
        );

        for malformed in [
            ".kitrove-removed-v1-windows-f-0123456789abcdef-00112233445566778899aabbccddee-00112233445566778899aabbccddeeff",
            ".kitrove-removed-v1-windows-f-0123456789abcdef-00112233445566778899AABBCCDDEEFF-00112233445566778899aabbccddeeff",
            ".kitrove-removed-v1-windows-f-0123456789abcdef-00112233445566778899aabbccddeeff-00112233445566778899aabbccddeeff-extra",
        ] {
            assert_eq!(RemovalTombstoneName::parse(OsStr::new(malformed)), None);
        }
    }

    #[test]
    fn retained_tombstone_name_is_canonical_but_non_authoritative() {
        let expected = RetainedTombstoneName {
            kind: RemovedObjectKind::Directory,
        };
        let encoded = expected.encode(NONCE).unwrap();

        assert_eq!(RetainedTombstoneName::parse(&encoded), Some(expected));
        assert_eq!(
            encoded,
            ".kitrove-retained-v1-d-00112233445566778899aabbccddeeff"
        );
        for malformed in [
            ".kitrove-retained-v1-x-00112233445566778899aabbccddeeff",
            ".kitrove-retained-v1-f-ABCDEFABCDEFABCDEFABCDEFABCDEFAB",
            ".kitrove-retained-v1-f-00112233445566778899aabbccddeeff-extra",
        ] {
            assert_eq!(RetainedTombstoneName::parse(OsStr::new(malformed)), None);
        }
    }
}
