//! Bounded candidate binding, not signature verification or execution authority.
//!
//! Only thin, little-endian 64-bit executables with a single SHA-256 CodeDirectory
//! are supported. A trusted native verifier must still validate the publisher,
//! signature, timestamp and runtime policy. This digest does not bind the CMS
//! wrapper: a pathname check matching it alone cannot prove the captured wrapper
//! was inspected. Consumer readiness must remain a separate, stronger boundary.

use object::read::macho::{CodeSignature, MachHeader};
use object::{BigEndian, LittleEndian, macho};
use sha2::{Digest as _, Sha256};

const MAX_SIGNATURE: usize = 4 * 1024 * 1024;
const INVALID: &str = "unsupported or malformed Apple code-directory binding";

/// Captured signature fingerprints for comparison with a native verifier's output.
/// This is not a verified signature, provenance receipt or execution authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleSignatureCandidate {
    cdhash: [u8; 20],
    cms_sha256: [u8; 32],
}

impl AppleSignatureCandidate {
    pub fn cdhash(&self) -> &[u8; 20] {
        &self.cdhash
    }

    /// Hash of the raw CMS content, excluding the Mach-O blob wrapper header.
    pub fn cms_sha256(&self) -> &[u8; 32] {
        &self.cms_sha256
    }
}

struct ParsedCandidate {
    cdhash: [u8; 20],
    cms_sha256: Option<[u8; 32]>,
}

/// Capture both directory and CMS fingerprints without validating the signature.
/// An absent, empty or wrongly tagged CMS blob is refused. CMS syntax, trust,
/// timestamps and special slots still require independent native verification.
pub fn candidate_signature(
    bytes: &[u8],
    target: &str,
) -> Result<AppleSignatureCandidate, &'static str> {
    let parsed = parse_candidate(bytes, target)?;
    Ok(AppleSignatureCandidate {
        cdhash: parsed.cdhash,
        cms_sha256: parsed.cms_sha256.ok_or(INVALID)?,
    })
}

/// Derive the 20-byte SHA-256 CDHash candidate from captured executable bytes.
/// This checks ordinary code-page hashes, but does not authenticate CMS signatures
/// or special slots. Success must never be interpreted as native readiness.
pub fn candidate_cdhash(bytes: &[u8], target: &str) -> Result<[u8; 20], &'static str> {
    Ok(parse_candidate(bytes, target)?.cdhash)
}

fn parse_candidate(bytes: &[u8], target: &str) -> Result<ParsedCandidate, &'static str> {
    let (cpu, subtype) = match target {
        "aarch64-apple-darwin" => (macho::CPU_TYPE_ARM64, macho::CPU_SUBTYPE_ARM64_ALL),
        "x86_64-apple-darwin" => (macho::CPU_TYPE_X86_64, macho::CPU_SUBTYPE_X86_64_ALL),
        _ => return Err(INVALID),
    };
    if bytes.len() as u64 > crate::APPLICATION_ARCHIVE_LIMITS.max_entry_bytes {
        return Err(INVALID);
    }
    let header = macho::MachHeader64::<LittleEndian>::parse(bytes, 0).map_err(|_| INVALID)?;
    if !header.is_little_endian()
        || header.cputype(LittleEndian) != cpu
        || header.cpusubtype(LittleEndian) != subtype.into()
        || header.filetype(LittleEndian) != macho::MH_EXECUTE
        || header.ncmds(LittleEndian) > 1024
    {
        return Err(INVALID);
    }
    let mut commands = header
        .load_commands(LittleEndian, bytes, 0)
        .map_err(|_| INVALID)?;
    let mut signature = None;
    let mut command_bytes = 0usize;
    while let Some(command) = commands.next().map_err(|_| INVALID)? {
        command_bytes = command_bytes
            .checked_add(command.cmdsize() as usize)
            .ok_or(INVALID)?;
        if command.cmd() == macho::LC_CODE_SIGNATURE {
            if signature.is_some()
                || command.cmdsize() as usize
                    != size_of::<macho::LinkeditDataCommand<LittleEndian>>()
            {
                return Err(INVALID);
            }
            signature = Some(
                command
                    .data::<macho::LinkeditDataCommand<LittleEndian>>()
                    .map_err(|_| INVALID)?,
            );
        }
    }
    if command_bytes != header.sizeofcmds(LittleEndian) as usize {
        return Err(INVALID);
    }
    let signature = signature.ok_or(INVALID)?;
    let offset = signature.dataoff.get(LittleEndian) as usize;
    let length = signature.datasize.get(LittleEndian) as usize;
    if length > MAX_SIGNATURE
        || offset < size_of::<macho::MachHeader64<LittleEndian>>() + command_bytes
        || offset.checked_add(length) != Some(bytes.len())
    {
        return Err(INVALID);
    }
    bind_signature(&bytes[offset..], &bytes[..offset])
}

fn bind_signature(signature: &[u8], code: &[u8]) -> Result<ParsedCandidate, &'static str> {
    let parsed = CodeSignature::parse(signature).map_err(|_| INVALID)?;
    let length = parsed.header().length.get(BigEndian) as usize;
    let count = parsed.index().len();
    let table_end = size_of::<macho::CsSuperBlob>()
        + count
            .checked_mul(size_of::<macho::CsBlobIndex>())
            .ok_or(INVALID)?;
    if count == 0
        || count > 16
        || length < table_end
        || length > signature.len()
        || signature[length..].iter().any(|byte| *byte != 0)
    {
        return Err(INVALID);
    }
    let mut ranges = Vec::with_capacity(count);
    let mut slots = Vec::with_capacity(count);
    let mut result = None;
    let mut cms_sha256 = None;
    for blob in parsed.blobs() {
        let blob = blob.map_err(|_| INVALID)?;
        let start = blob.offset() as usize;
        let end = start.checked_add(blob.data().len()).ok_or(INVALID)?;
        if start < table_end
            || end > length
            || blob.data().len() < size_of::<macho::CsGenericBlob>()
            || slots.contains(&blob.slot())
            || ranges.iter().any(|&(a, b)| start < b && a < end)
            || blob.slot().is_alternate_codedirectory()
        {
            return Err(INVALID);
        }
        slots.push(blob.slot());
        ranges.push((start, end));
        if blob.slot() == macho::CSSLOT_SIGNATURESLOT {
            if blob.magic() != macho::CSMAGIC_BLOBWRAPPER || blob.contents().is_empty() {
                return Err(INVALID);
            }
            cms_sha256 = Some(Sha256::digest(blob.contents()).into());
        } else if blob.magic() == macho::CSMAGIC_BLOBWRAPPER {
            return Err(INVALID);
        }
        if blob.slot() != macho::CSSLOT_CODEDIRECTORY {
            if blob.magic() == macho::CSMAGIC_CODEDIRECTORY {
                return Err(INVALID);
            }
            continue;
        }
        let directory = blob.code_directory().map_err(|_| INVALID)?.ok_or(INVALID)?;
        let header = directory.header();
        if header.hash_type != macho::CS_HASHTYPE_SHA256
            || header.hash_size != 32
            || directory.version().0 < 0x20001
            || directory.version().0 > 0x20500
            || directory.scatter_offset().unwrap_or(0) != 0
            || directory.code_limit() != code.len() as u64
            || !(12..=16).contains(&header.page_size)
        {
            return Err(INVALID);
        }
        let page_size = 1usize << header.page_size;
        if header.n_code_slots.get(BigEndian) as usize != code.len().div_ceil(page_size) {
            return Err(INVALID);
        }
        for (index, page) in code.chunks(page_size).enumerate() {
            if directory.code_hash(index as u32).map_err(|_| INVALID)?
                != Sha256::digest(page).as_slice()
            {
                return Err(INVALID);
            }
        }
        let digest = Sha256::digest(blob.data());
        let mut cdhash = [0; 20];
        cdhash.copy_from_slice(&digest[..20]);
        result = Some(cdhash);
    }
    Ok(ParsedCandidate {
        cdhash: result.ok_or(INVALID)?,
        cms_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut bytes = Vec::new();
        for word in [
            0xfeed_facfu32,
            0x0100_000c,
            0,
            2,
            1,
            16,
            0,
            0,
            0x1d,
            16,
            48,
            100,
        ] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        let page_hash = Sha256::digest(&bytes);
        for word in [
            0xfade_0cc0u32,
            100,
            1,
            0,
            20,
            0xfade_0c02,
            80,
            0x20001,
            0,
            48,
            44,
            0,
            1,
            48,
        ] {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        bytes.extend_from_slice(&[32, 2, 0, 12]);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(b"app\0");
        bytes.extend_from_slice(&page_hash);
        bytes
    }

    #[test]
    fn candidate_matches_sha256_directory_prefix_without_granting_trust() {
        let bytes = fixture();
        let digest = Sha256::digest(&bytes[68..]);
        assert_eq!(
            candidate_cdhash(&bytes, "aarch64-apple-darwin")
                .unwrap()
                .as_slice(),
            &digest[..20]
        );
    }

    #[test]
    fn truncated_inputs_and_wrong_targets_fail_closed() {
        let bytes = fixture();
        for end in 0..bytes.len() {
            assert!(
                candidate_cdhash(&bytes[..end], "aarch64-apple-darwin").is_err(),
                "length {end}"
            );
        }
        for target in ["", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"] {
            assert!(candidate_cdhash(&bytes, target).is_err());
        }
    }

    #[test]
    fn malformed_layout_hashes_and_page_bytes_fail_closed() {
        let original = fixture();
        for (offset, value) in [
            (8, 2),    // unsupported architecture subtype
            (12, 1),   // non-executable
            (20, 17),  // load-command bytes disagree
            (40, 47),  // signature overlaps load commands
            (55, 99),  // superblob length excludes a byte
            (59, 17),  // too many slots
            (63, 1),   // CodeDirectory in wrong slot
            (67, 0),   // blob overlaps index
            (104, 31), // wrong hash size
            (105, 1),  // SHA-1 not accepted
            (107, 0),  // unbounded page mode
            (147, 0),  // mismatched code-page hash
            (24, 1),   // captured code changed, directory unchanged
        ] {
            let mut bytes = original.clone();
            bytes[offset] = value;
            assert!(
                candidate_cdhash(&bytes, "aarch64-apple-darwin").is_err(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn duplicate_overlapping_and_alternate_directories_are_rejected() {
        let fixture = fixture();
        let directory = &fixture[68..];
        for (slot, offset) in [(0u32, 108u32), (0x1000, 108), (0x10000, 28)] {
            let mut signature = Vec::new();
            for word in [0xfade_0cc0u32, 188, 2, 0, 28, slot, offset] {
                signature.extend_from_slice(&word.to_be_bytes());
            }
            signature.extend_from_slice(directory);
            signature.extend_from_slice(directory);
            assert!(bind_signature(&signature, &fixture[..48]).is_err());
        }
    }

    fn cms_fixture(cms: &[u8]) -> Vec<u8> {
        let original = fixture();
        let signature_length = 28 + 80 + 8 + cms.len() as u32;
        let mut bytes = original[..48].to_vec();
        bytes[44..48].copy_from_slice(&signature_length.to_le_bytes());
        let mut directory = original[68..].to_vec();
        directory[48..].copy_from_slice(&Sha256::digest(&bytes));
        for word in [0xfade_0cc0u32, signature_length, 2, 0, 28, 0x10000, 108] {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        bytes.extend_from_slice(&directory);
        bytes.extend_from_slice(&0xfade_0b01u32.to_be_bytes());
        bytes.extend_from_slice(&(8 + cms.len() as u32).to_be_bytes());
        bytes.extend_from_slice(cms);
        bytes
    }

    #[test]
    fn cms_substitution_changes_the_binding_even_with_identical_directory() {
        // Deliberately not a valid CMS signature: parsing must not claim trust.
        let first = cms_fixture(b"opaque-one");
        let second = cms_fixture(b"opaque-two");
        let a = candidate_signature(&first, "aarch64-apple-darwin").unwrap();
        let b = candidate_signature(&second, "aarch64-apple-darwin").unwrap();
        assert_eq!(a.cdhash(), b.cdhash());
        assert_ne!(a.cms_sha256(), b.cms_sha256());
        assert_eq!(
            a.cms_sha256().as_slice(),
            Sha256::digest(b"opaque-one").as_slice()
        );
    }

    #[test]
    fn cms_candidate_refuses_absent_empty_wrong_magic_and_wrong_slot() {
        let mut wrong_magic = cms_fixture(b"opaque");
        wrong_magic[48 + 108] ^= 1;
        let mut wrong_slot = cms_fixture(b"opaque");
        wrong_slot[48 + 23] = 1;
        for bytes in [fixture(), cms_fixture(b""), wrong_magic, wrong_slot] {
            assert!(candidate_signature(&bytes, "aarch64-apple-darwin").is_err());
        }
    }
}
