use std::cell::Cell;
use std::io::{self, Read};
use std::rc::Rc;

use xz4rust::XzDecoder;

use crate::{
    APPLICATION_ARCHIVE_LIMITS, APPLICATION_RELEASE_MANIFEST_NAME, ApplicationArchiveIntake,
    ApplicationArchiveSpec, ArchiveEntryKind, ArchiveEntrySummary, ArchiveFormat,
    ArchiveIntakeError, InspectedApplicationRelease,
    entry_policy::validate_application_archive_entry_summary,
    intake::checked_archive_size,
    intake::{ApplicationReleaseFile, CapturedApplicationRelease},
    validate_application_archive_entry_summaries,
};

const TAR_BLOCK_BYTES: u64 = 512;

/// Fully validates one immutable macOS or Linux application TAR/XZ snapshot.
pub fn inspect_tar_xz_application_archive(
    spec: ApplicationArchiveSpec,
    archive_bytes: &[u8],
) -> Result<ApplicationArchiveIntake, ArchiveIntakeError> {
    process_tar_xz_application_archive(spec, archive_bytes, false).map(|(intake, _)| intake)
}

pub(crate) fn extract_tar_xz_application_release(
    spec: ApplicationArchiveSpec,
    archive_bytes: &[u8],
) -> Result<InspectedApplicationRelease, ArchiveIntakeError> {
    let (intake, captured) = process_tar_xz_application_archive(spec, archive_bytes, true)?;
    captured
        .and_then(|captured| captured.into_inspected(intake))
        .ok_or(ArchiveIntakeError::InvalidTar)
}

fn process_tar_xz_application_archive(
    spec: ApplicationArchiveSpec,
    archive_bytes: &[u8],
    capture_release: bool,
) -> Result<(ApplicationArchiveIntake, Option<CapturedApplicationRelease>), ArchiveIntakeError> {
    if spec.format() != ArchiveFormat::TarXz {
        return Err(ArchiveIntakeError::UnsupportedFormat);
    }
    checked_archive_size(archive_bytes)?;
    preflight_xz_envelope(archive_bytes)?;

    let xz_failed = Rc::new(Cell::new(false));
    let tar_failed = Rc::new(Cell::new(false));
    let padding = Rc::new(Cell::new(None));
    let reader = CanonicalTarReader::new(
        BoundedXzReader::new(archive_bytes, Rc::clone(&xz_failed))?,
        Rc::clone(&padding),
        Rc::clone(&tar_failed),
    );
    let mut archive = tar::Archive::new(reader);
    let mut summaries = Vec::new();
    let mut declared_total = 0_u64;
    let executable_path = format!(
        "{}/{}",
        spec.archive_root().ok_or(ArchiveIntakeError::InvalidTar)?,
        spec.executable_name()
    );
    let manifest_path = format!(
        "{}/{}",
        spec.archive_root().ok_or(ArchiveIntakeError::InvalidTar)?,
        APPLICATION_RELEASE_MANIFEST_NAME
    );
    let mut captured = capture_release.then(CapturedApplicationRelease::default);
    {
        let entries = archive
            .entries()
            .map_err(|_| archive_error(&xz_failed))?
            .raw(true);
        for entry in entries {
            if summaries.len() >= APPLICATION_ARCHIVE_LIMITS.max_entries {
                return Err(crate::ArchivePolicyError::EntryLimit.into());
            }
            let mut entry = entry.map_err(|_| archive_error(&xz_failed))?;
            let entry_type = entry.header().entry_type();
            if entry_type.is_gnu_longname()
                || entry_type.is_gnu_longlink()
                || entry_type.is_pax_local_extensions()
                || entry_type.is_pax_global_extensions()
            {
                return Err(ArchiveIntakeError::UnsupportedTarMetadata);
            }
            if entry.header().as_gnu().is_none() && entry.header().as_ustar().is_none() {
                return Err(ArchiveIntakeError::InvalidTar);
            }

            let size = entry.size();
            let mode = entry
                .header()
                .mode()
                .map_err(|_| ArchiveIntakeError::InvalidTar)?;
            validate_canonical_numeric_fields(entry.header().as_bytes(), size, mode)?;
            let name = entry.path_bytes();
            if name.as_ref() != entry.header().path_bytes().as_ref() {
                return Err(ArchiveIntakeError::InvalidTar);
            }
            let is_executable = name.as_ref() == executable_path.as_bytes();
            let is_manifest = name.as_ref() == manifest_path.as_bytes();
            if is_manifest
                && (size == 0
                    || size
                        > u64::try_from(crate::APPLICATION_RELEASE_MANIFEST_MAX_BYTES)
                            .expect("manifest bound fits u64"))
            {
                return Err(crate::ArchivePolicyError::InvalidReleaseManifestSize.into());
            }
            let capture = capture_release && (is_executable || is_manifest);
            let kind = if entry_type.is_file() {
                ArchiveEntryKind::File
            } else if entry_type.is_dir() {
                ArchiveEntryKind::Directory
            } else if entry_type.is_symlink() || entry_type.is_hard_link() {
                ArchiveEntryKind::Link
            } else {
                ArchiveEntryKind::Special
            };
            let summary =
                ArchiveEntrySummary::from_utf8_name(&name, kind, size, Some(mode), false)?;
            validate_application_archive_entry_summary(&summary)?;
            declared_total = declared_total
                .checked_add(size)
                .filter(|total| *total <= APPLICATION_ARCHIVE_LIMITS.max_expanded_bytes)
                .ok_or(crate::ArchivePolicyError::ExpandedSize)?;
            summaries.push(summary);
            register_padding(&padding, entry.raw_file_position(), size)?;
            let mut payload = if capture {
                Some(Vec::with_capacity(
                    usize::try_from(size).map_err(|_| ArchiveIntakeError::InvalidTar)?,
                ))
            } else {
                None
            };
            consume_entry(&mut entry, size, &xz_failed, payload.as_mut())?;
            if let Some(payload) = payload {
                let captured = captured.as_mut().ok_or(ArchiveIntakeError::InvalidTar)?;
                captured.capture(
                    if is_executable {
                        ApplicationReleaseFile::Executable
                    } else {
                        ApplicationReleaseFile::Manifest
                    },
                    payload,
                );
            }
        }
    }

    let reader = archive.into_inner();
    if tar_failed.get() || padding.get().is_some() {
        return Err(ArchiveIntakeError::InvalidTar);
    }
    let mut reader = reader.into_inner();
    validate_tar_end(&mut reader)?;
    let shape = validate_application_archive_entry_summaries(spec, summaries)?;
    let intake = ApplicationArchiveIntake::from_validated_snapshot(spec, archive_bytes, shape)?;
    Ok((intake, captured))
}

fn archive_error(xz_failed: &Cell<bool>) -> ArchiveIntakeError {
    if xz_failed.get() {
        ArchiveIntakeError::InvalidXz
    } else {
        ArchiveIntakeError::InvalidTar
    }
}

fn register_padding(
    padding: &Cell<Option<(u64, u64)>>,
    data_start: u64,
    size: u64,
) -> Result<(), ArchiveIntakeError> {
    if padding.get().is_some() {
        return Err(ArchiveIntakeError::InvalidTar);
    }
    let data_end = data_start
        .checked_add(size)
        .ok_or(ArchiveIntakeError::InvalidTar)?;
    let padded_end = data_end
        .checked_add(TAR_BLOCK_BYTES - 1)
        .map(|end| end / TAR_BLOCK_BYTES * TAR_BLOCK_BYTES)
        .ok_or(ArchiveIntakeError::InvalidTar)?;
    if padded_end != data_end {
        padding.set(Some((data_end, padded_end)));
    }
    Ok(())
}

fn preflight_xz_envelope(bytes: &[u8]) -> Result<(), ArchiveIntakeError> {
    const HEADER_BYTES: usize = 12;
    const FOOTER_BYTES: usize = 12;
    let footer_start = bytes
        .len()
        .checked_sub(FOOTER_BYTES)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    let footer = &bytes[footer_start..];
    if bytes.get(..6) != Some(b"\xfd7zXZ\0")
        || bytes.get(6..8) != Some(&[0, 4])
        || footer.get(8..10) != Some(&[0, 4])
        || footer.get(10..12) != Some(b"YZ")
    {
        return Err(ArchiveIntakeError::InvalidXz);
    }
    let backward_size = u32::from_le_bytes(
        footer[4..8]
            .try_into()
            .map_err(|_| ArchiveIntakeError::InvalidXz)?,
    );
    let index_size = (u64::from(backward_size) + 1)
        .checked_mul(4)
        .filter(|size| *size <= APPLICATION_ARCHIVE_LIMITS.max_xz_index_bytes)
        .and_then(|size| usize::try_from(size).ok())
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    let index_start = footer_start
        .checked_sub(index_size)
        .filter(|start| *start >= HEADER_BYTES)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    if bytes.get(index_start) != Some(&0) {
        return Err(ArchiveIntakeError::InvalidXz);
    }
    let index_records = &bytes[index_start + 1..footer_start];
    let (blocks, mut record_position) = parse_xz_vli(index_records)?;
    if blocks > APPLICATION_ARCHIVE_LIMITS.max_xz_blocks {
        return Err(ArchiveIntakeError::InvalidXz);
    }
    let mut block_position = HEADER_BYTES;
    for _ in 0..blocks {
        let (unpadded_size, consumed) = parse_xz_vli(&index_records[record_position..])?;
        record_position = record_position
            .checked_add(consumed)
            .ok_or(ArchiveIntakeError::InvalidXz)?;
        let (_, consumed) = parse_xz_vli(&index_records[record_position..])?;
        record_position = record_position
            .checked_add(consumed)
            .ok_or(ArchiveIntakeError::InvalidXz)?;
        validate_xz_block_header(bytes, block_position, unpadded_size)?;
        let padded_size = unpadded_size
            .checked_add(3)
            .map(|size| size & !3)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or(ArchiveIntakeError::InvalidXz)?;
        block_position = block_position
            .checked_add(padded_size)
            .ok_or(ArchiveIntakeError::InvalidXz)?;
    }
    let index_crc_start = index_records
        .len()
        .checked_sub(4)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    if block_position != index_start
        || record_position > index_crc_start
        || index_records[record_position..index_crc_start]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(ArchiveIntakeError::InvalidXz);
    }
    Ok(())
}

fn validate_xz_block_header(
    bytes: &[u8],
    block_start: usize,
    unpadded_size: u64,
) -> Result<(), ArchiveIntakeError> {
    let encoded_size = *bytes
        .get(block_start)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    if encoded_size == 0 {
        return Err(ArchiveIntakeError::InvalidXz);
    }
    let header_size = (usize::from(encoded_size) + 1)
        .checked_mul(4)
        .filter(|size| u64::try_from(*size).is_ok_and(|size| size <= unpadded_size))
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    let fields_end = header_size
        .checked_sub(4)
        .filter(|end| *end >= 4)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    let header_end = block_start
        .checked_add(header_size)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    let header = bytes
        .get(block_start..header_end)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    let flags = header[1];
    if flags & 0x3c != 0 {
        return Err(ArchiveIntakeError::InvalidXz);
    }
    let mut position = 2;
    for present in [flags & 0x40 != 0, flags & 0x80 != 0] {
        if present {
            let _ = parse_xz_header_vli(header, &mut position, fields_end)?;
        }
    }
    let filters = usize::from(flags & 3) + 1;
    for index in 0..filters {
        let filter_id = parse_xz_header_vli(header, &mut position, fields_end)?;
        let properties_size = parse_xz_header_vli(header, &mut position, fields_end)?;
        let properties_size =
            usize::try_from(properties_size).map_err(|_| ArchiveIntakeError::InvalidXz)?;
        let properties_end = position
            .checked_add(properties_size)
            .filter(|end| *end <= fields_end)
            .ok_or(ArchiveIntakeError::InvalidXz)?;
        let properties = header
            .get(position..properties_end)
            .ok_or(ArchiveIntakeError::InvalidXz)?;
        position = properties_end;
        if index + 1 == filters {
            if filter_id != 0x21 || properties.len() != 1 {
                return Err(ArchiveIntakeError::InvalidXz);
            }
            let dictionary = lzma2_dictionary_size(properties[0])?;
            if dictionary > APPLICATION_ARCHIVE_LIMITS.max_xz_dictionary_bytes {
                return Err(ArchiveIntakeError::InvalidXz);
            }
        }
    }
    if header[position..fields_end].iter().any(|byte| *byte != 0) {
        return Err(ArchiveIntakeError::InvalidXz);
    }
    let block_end = block_start
        .checked_add(usize::try_from(unpadded_size).map_err(|_| ArchiveIntakeError::InvalidXz)?)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    let payload_end = block_end
        .checked_sub(8)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    if scan_lzma2_stream(bytes, header_end, payload_end)? != payload_end {
        return Err(ArchiveIntakeError::InvalidXz);
    }
    Ok(())
}

fn parse_xz_header_vli(
    header: &[u8],
    position: &mut usize,
    fields_end: usize,
) -> Result<u64, ArchiveIntakeError> {
    let remaining = header
        .get(*position..fields_end)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    let (value, consumed) = parse_xz_vli(remaining)?;
    *position = position
        .checked_add(consumed)
        .filter(|position| *position <= fields_end)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    Ok(value)
}

fn lzma2_dictionary_size(property: u8) -> Result<u64, ArchiveIntakeError> {
    if property > 40 {
        return Err(ArchiveIntakeError::InvalidXz);
    }
    Ok(if property == 40 {
        u64::from(u32::MAX)
    } else {
        u64::from(2 | u32::from(property & 1)) << (u32::from(property) / 2 + 11)
    })
}

/// Finds the physical end of one LZMA2 stream from its bounded chunk framing.
/// This performs no decompression; it prevents an index record from concealing
/// additional physical XZ blocks before the resource-bounded decoder runs.
fn scan_lzma2_stream(
    bytes: &[u8],
    mut position: usize,
    payload_end: usize,
) -> Result<usize, ArchiveIntakeError> {
    loop {
        let control = *bytes
            .get(position)
            .filter(|_| position < payload_end)
            .ok_or(ArchiveIntakeError::InvalidXz)?;
        position += 1;
        let payload_size = match control {
            0 => return Ok(position),
            1 | 2 => {
                let size = usize::from(be_u16(bytes, position)?) + 1;
                position += 2;
                size
            }
            0x80..=0xff => {
                position = position
                    .checked_add(2)
                    .ok_or(ArchiveIntakeError::InvalidXz)?;
                let size = usize::from(be_u16(bytes, position)?) + 1;
                position += 2;
                if control >= 0xc0 {
                    position = position
                        .checked_add(1)
                        .ok_or(ArchiveIntakeError::InvalidXz)?;
                }
                size
            }
            _ => return Err(ArchiveIntakeError::InvalidXz),
        };
        position = position
            .checked_add(payload_size)
            .filter(|position| *position <= payload_end)
            .ok_or(ArchiveIntakeError::InvalidXz)?;
    }
}

fn be_u16(bytes: &[u8], position: usize) -> Result<u16, ArchiveIntakeError> {
    let end = position
        .checked_add(2)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    let value = bytes
        .get(position..end)
        .ok_or(ArchiveIntakeError::InvalidXz)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn parse_xz_vli(bytes: &[u8]) -> Result<(u64, usize), ArchiveIntakeError> {
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().copied().take(9).enumerate() {
        let part = u64::from(byte & 0x7f)
            .checked_shl(u32::try_from(index * 7).map_err(|_| ArchiveIntakeError::InvalidXz)?)
            .ok_or(ArchiveIntakeError::InvalidXz)?;
        value = value
            .checked_add(part)
            .ok_or(ArchiveIntakeError::InvalidXz)?;
        if byte & 0x80 == 0 {
            if index != 0 && byte == 0 {
                return Err(ArchiveIntakeError::InvalidXz);
            }
            return Ok((value, index + 1));
        }
    }
    Err(ArchiveIntakeError::InvalidXz)
}

fn consume_entry(
    entry: &mut impl Read,
    declared_size: u64,
    xz_failed: &Cell<bool>,
    mut captured: Option<&mut Vec<u8>>,
) -> Result<(), ArchiveIntakeError> {
    if declared_size > APPLICATION_ARCHIVE_LIMITS.max_entry_bytes {
        return Err(crate::ArchivePolicyError::EntrySize.into());
    }
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = entry
            .read(&mut buffer)
            .map_err(|_| archive_error(xz_failed))?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .filter(|size| *size <= declared_size)
            .ok_or(ArchiveIntakeError::InvalidTar)?;
        if let Some(captured) = &mut captured {
            captured.extend_from_slice(&buffer[..read]);
        }
    }
    if observed != declared_size {
        return Err(ArchiveIntakeError::InvalidTar);
    }
    Ok(())
}

fn validate_tar_end(reader: &mut BoundedXzReader<'_>) -> Result<(), ArchiveIntakeError> {
    let mut trailing_zeros = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| ArchiveIntakeError::InvalidXz)?;
        if read == 0 {
            break;
        }
        if buffer[..read].iter().any(|byte| *byte != 0) {
            return Err(ArchiveIntakeError::InvalidTar);
        }
        trailing_zeros = trailing_zeros
            .checked_add(read as u64)
            .ok_or(ArchiveIntakeError::InvalidTar)?;
    }
    if trailing_zeros < TAR_BLOCK_BYTES
        || reader.total_out() % TAR_BLOCK_BYTES != 0
        || !reader.finished_exactly()
    {
        return Err(ArchiveIntakeError::InvalidTar);
    }
    Ok(())
}

fn validate_canonical_numeric_fields(
    header: &[u8; 512],
    parsed_size: u64,
    parsed_mode: u32,
) -> Result<(), ArchiveIntakeError> {
    let unsigned_checksum = header[..148]
        .iter()
        .chain(&header[156..])
        .try_fold(8_u64 * u64::from(b' '), |sum, byte| {
            sum.checked_add(u64::from(*byte))
        })
        .ok_or(ArchiveIntakeError::InvalidTar)?;
    if parse_octal(&header[124..136])? != parsed_size
        || u32::try_from(parse_octal(&header[100..108])?)
            .map_err(|_| ArchiveIntakeError::InvalidTar)?
            != parsed_mode
        || parse_octal(&header[148..156])? != unsigned_checksum
    {
        return Err(ArchiveIntakeError::InvalidTar);
    }
    Ok(())
}

fn parse_octal(field: &[u8]) -> Result<u64, ArchiveIntakeError> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(ArchiveIntakeError::InvalidTar);
    }
    let mut digits_started = false;
    let mut digits_ended = false;
    let mut value = 0_u64;
    for byte in field.iter().copied() {
        match byte {
            b' ' if !digits_started => {}
            b'0'..=b'7' if !digits_ended => {
                digits_started = true;
                value = value
                    .checked_mul(8)
                    .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                    .ok_or(ArchiveIntakeError::InvalidTar)?;
            }
            0 | b' ' if digits_started => digits_ended = true,
            _ => return Err(ArchiveIntakeError::InvalidTar),
        }
    }
    if !digits_started {
        return Err(ArchiveIntakeError::InvalidTar);
    }
    Ok(value)
}

struct BoundedXzReader<'a> {
    input: &'a [u8],
    input_position: usize,
    decoder: Box<XzDecoder<'static>>,
    total_out: u64,
    finished: bool,
    pending_error: bool,
    failed: Rc<Cell<bool>>,
}

impl<'a> BoundedXzReader<'a> {
    fn new(input: &'a [u8], failed: Rc<Cell<bool>>) -> Result<Self, ArchiveIntakeError> {
        let decoder_state_bytes = std::mem::size_of::<XzDecoder<'static>>() as u64;
        if APPLICATION_ARCHIVE_LIMITS
            .max_xz_dictionary_bytes
            .checked_add(decoder_state_bytes)
            .is_none_or(|total| total > APPLICATION_ARCHIVE_LIMITS.max_xz_decoder_memory_bytes)
        {
            return Err(ArchiveIntakeError::InvalidXz);
        }
        let max_dictionary = usize::try_from(APPLICATION_ARCHIVE_LIMITS.max_xz_dictionary_bytes)
            .map_err(|_| ArchiveIntakeError::InvalidXz)?;
        Ok(Self {
            input,
            input_position: 0,
            decoder: XzDecoder::in_heap_with_alloc_dict_size(4096, max_dictionary),
            total_out: 0,
            finished: false,
            pending_error: false,
            failed,
        })
    }

    fn total_out(&self) -> u64 {
        self.total_out
    }

    fn finished_exactly(&self) -> bool {
        self.finished && self.input_position == self.input.len() && !self.pending_error
    }

    fn invalid_xz(&self) -> io::Error {
        self.failed.set(true);
        io::Error::new(io::ErrorKind::InvalidData, "invalid release XZ stream")
    }
}

impl Read for BoundedXzReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.pending_error {
            return Err(self.invalid_xz());
        }
        if self.finished {
            return Ok(0);
        }

        loop {
            if self.input_position == self.input.len() {
                return Err(self.invalid_xz());
            }
            let result = self
                .decoder
                .decode(&self.input[self.input_position..], output)
                .map_err(|_| self.invalid_xz())?;
            self.input_position = self
                .input_position
                .checked_add(result.input_consumed())
                .ok_or_else(|| self.invalid_xz())?;
            self.total_out = self
                .total_out
                .checked_add(result.output_produced() as u64)
                .ok_or_else(|| self.invalid_xz())?;
            if self.total_out > APPLICATION_ARCHIVE_LIMITS.max_tar_stream_bytes {
                return Err(self.invalid_xz());
            }
            if result.is_end_of_stream() {
                self.finished = true;
                if self.input_position != self.input.len() {
                    if result.output_produced() == 0 {
                        return Err(self.invalid_xz());
                    }
                    self.pending_error = true;
                }
            } else if !result.made_progress() {
                return Err(self.invalid_xz());
            }
            if result.output_produced() != 0 || self.finished {
                return Ok(result.output_produced());
            }
        }
    }
}

struct CanonicalTarReader<'a> {
    inner: BoundedXzReader<'a>,
    position: u64,
    expected_padding: Rc<Cell<Option<(u64, u64)>>>,
    failed: Rc<Cell<bool>>,
}

impl<'a> CanonicalTarReader<'a> {
    fn new(
        inner: BoundedXzReader<'a>,
        expected_padding: Rc<Cell<Option<(u64, u64)>>>,
        failed: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            inner,
            position: 0,
            expected_padding,
            failed,
        }
    }

    fn into_inner(self) -> BoundedXzReader<'a> {
        self.inner
    }
}

impl Read for CanonicalTarReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(output)?;
        let end = self
            .position
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid TAR position"))?;
        if let Some((padding_start, padding_end)) = self.expected_padding.get() {
            let overlap_start = self.position.max(padding_start);
            let overlap_end = end.min(padding_end);
            if overlap_start < overlap_end {
                let start = usize::try_from(overlap_start - self.position)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                let finish = usize::try_from(overlap_end - self.position)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                if output[start..finish].iter().any(|byte| *byte != 0) {
                    self.failed.set(true);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TAR entry padding is nonzero",
                    ));
                }
            }
            if end >= padding_end {
                self.expected_padding.set(None);
            }
        }
        self.position = end;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::num::NonZeroU64;

    use lzma_rust2::{CheckType, FilterType, XzOptions, XzWriter};

    use super::*;
    use crate::{APPLICATION_ARCHIVES, BINARY_COMPANIONS};

    fn spec() -> ApplicationArchiveSpec {
        APPLICATION_ARCHIVES[0]
    }

    fn valid_tar() -> Vec<u8> {
        compress(&valid_tar_stream())
    }

    #[test]
    fn extracts_only_the_exact_validated_tar_release_files() {
        let bytes = valid_tar();
        let extracted =
            extract_tar_xz_application_release(spec(), &bytes).expect("valid TAR/XZ extraction");
        assert_eq!(extracted.executable_bytes(), b"executable");
        assert_eq!(extracted.manifest_bytes(), b"companion");
        assert_eq!(
            extracted.intake(),
            inspect_tar_xz_application_archive(spec(), &bytes).unwrap()
        );

        let root = spec().archive_root().unwrap();
        let mut invalid_tail = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut invalid_tail);
            append(&mut builder, &format!("{root}/"), &[], 0o755, true);
            append(
                &mut builder,
                &format!("{root}/{}", spec().executable_name()),
                b"executable",
                0o755,
                false,
            );
            for name in BINARY_COMPANIONS {
                append(
                    &mut builder,
                    &format!("{root}/{name}"),
                    b"companion",
                    0o644,
                    false,
                );
            }
            builder.finish().unwrap();
        }
        invalid_tail.push(1);
        assert_eq!(
            extract_tar_xz_application_release(spec(), &compress(&invalid_tail)),
            Err(ArchiveIntakeError::InvalidTar)
        );
    }

    fn valid_tar_stream() -> Vec<u8> {
        tar_stream_with_manifest(b"companion")
    }

    fn tar_stream_with_manifest(manifest: &[u8]) -> Vec<u8> {
        let mut tar = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar);
            append(
                &mut builder,
                &format!("{}/", spec().archive_root().unwrap()),
                &[],
                0o755,
                true,
            );
            for name in BINARY_COMPANIONS {
                append(
                    &mut builder,
                    &format!("{}/{name}", spec().archive_root().unwrap()),
                    if name == crate::APPLICATION_RELEASE_MANIFEST_NAME {
                        manifest
                    } else {
                        b"companion"
                    },
                    0o644,
                    false,
                );
            }
            append(
                &mut builder,
                &format!(
                    "{}/{}",
                    spec().archive_root().unwrap(),
                    spec().executable_name()
                ),
                b"executable",
                0o755,
                false,
            );
            builder.finish().unwrap();
        }
        tar
    }

    #[test]
    fn manifest_capture_enforces_its_exact_size_bound_before_allocation() {
        let exact = vec![b'x'; crate::APPLICATION_RELEASE_MANIFEST_MAX_BYTES];
        assert!(
            extract_tar_xz_application_release(
                spec(),
                &compress(&tar_stream_with_manifest(&exact))
            )
            .is_ok()
        );

        let oversized = vec![b'x'; crate::APPLICATION_RELEASE_MANIFEST_MAX_BYTES + 1];
        assert_eq!(
            extract_tar_xz_application_release(
                spec(),
                &compress(&tar_stream_with_manifest(&oversized))
            ),
            Err(ArchiveIntakeError::Policy(
                crate::ArchivePolicyError::InvalidReleaseManifestSize
            ))
        );
    }

    fn append(
        builder: &mut tar::Builder<&mut Vec<u8>>,
        path: &str,
        body: &[u8],
        mode: u32,
        directory: bool,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_entry_type(if directory {
            tar::EntryType::Directory
        } else {
            tar::EntryType::Regular
        });
        header.set_mode(mode);
        header.set_size(body.len() as u64);
        header.set_cksum();
        builder.append(&header, body).unwrap();
    }

    fn compress(tar: &[u8]) -> Vec<u8> {
        let mut writer = XzWriter::new(Vec::new(), XzOptions::with_preset(1)).unwrap();
        writer.write_all(tar).unwrap();
        writer.finish().unwrap()
    }

    fn compress_with_blocks(blocks: usize) -> Vec<u8> {
        let mut tar = valid_tar_stream();
        tar.resize(blocks * 4096, 0);
        let mut options = XzOptions::with_preset(0);
        options.lzma_options.dict_size = 4096;
        options.set_block_size(NonZeroU64::new(4096));
        let mut writer = XzWriter::new(Vec::new(), options).unwrap();
        writer.write_all(&tar).unwrap();
        writer.finish().unwrap()
    }

    fn replace_index_with_empty(mut xz: Vec<u8>) -> Vec<u8> {
        let footer_start = xz.len() - 12;
        let backward =
            u32::from_le_bytes(xz[footer_start + 4..footer_start + 8].try_into().unwrap());
        let index_size = (backward as usize + 1) * 4;
        xz.truncate(footer_start - index_size);
        let index = [0_u8; 4];
        xz.extend(index);
        xz.extend(zlib_rs::crc32::crc32(0, &index).to_le_bytes());
        let backward_and_flags = [1, 0, 0, 0, 0, 4];
        xz.extend(zlib_rs::crc32::crc32(0, &backward_and_flags).to_le_bytes());
        xz.extend(backward_and_flags);
        xz.extend(b"YZ");
        xz
    }

    #[test]
    fn accepts_and_binds_valid_snapshot() {
        let bytes = valid_tar();
        let intake = inspect_tar_xz_application_archive(spec(), &bytes).unwrap();
        assert_eq!(intake.spec(), spec());
        assert_eq!(intake.archive_size(), bytes.len() as u64);
        assert_eq!(intake.executable_size(), 10);
    }

    #[test]
    fn accepts_reviewed_bcj_filter_chain() {
        let mut options = XzOptions::with_preset(1);
        options.prepend_pre_filter(FilterType::BcjX86, 0);
        let mut writer = XzWriter::new(Vec::new(), options).unwrap();
        writer.write_all(&valid_tar_stream()).unwrap();
        let filtered = writer.finish().unwrap();
        assert!(inspect_tar_xz_application_archive(spec(), &filtered).is_ok());
    }

    #[test]
    fn accepts_reviewed_delta_filter_chain() {
        let mut options = XzOptions::with_preset(1);
        options.prepend_pre_filter(FilterType::Delta, 1);
        let mut writer = XzWriter::new(Vec::new(), options).unwrap();
        writer.write_all(&valid_tar_stream()).unwrap();
        let filtered = writer.finish().unwrap();
        assert!(inspect_tar_xz_application_archive(spec(), &filtered).is_ok());
    }

    #[test]
    fn rejects_wrong_format_truncation_and_trailing_stream() {
        let bytes = valid_tar();
        assert_eq!(
            inspect_tar_xz_application_archive(APPLICATION_ARCHIVES[3], &bytes),
            Err(ArchiveIntakeError::UnsupportedFormat)
        );
        assert!(inspect_tar_xz_application_archive(spec(), &bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(inspect_tar_xz_application_archive(spec(), &trailing).is_err());
    }

    #[test]
    fn rejects_corrupt_payload_and_nonzero_tar_tail() {
        let bytes = valid_tar();
        let mut corrupt = bytes.clone();
        corrupt[20] ^= 1;
        assert!(inspect_tar_xz_application_archive(spec(), &corrupt).is_err());

        let mut tar = vec![0_u8; 1024];
        tar[512] = 1;
        let invalid_tail = compress(&tar);
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &invalid_tail),
            Err(ArchiveIntakeError::InvalidTar)
        );
    }

    #[test]
    fn rejects_links_special_entries_and_unsafe_modes() {
        let root = spec().archive_root().unwrap();
        let mut tar = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar);
            let mut header = tar::Header::new_gnu();
            header.set_path(format!("{root}/link")).unwrap();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name("outside").unwrap();
            header.set_mode(0o777);
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, io::empty()).unwrap();
            builder.finish().unwrap();
        }
        assert!(matches!(
            inspect_tar_xz_application_archive(spec(), &compress(&tar)),
            Err(ArchiveIntakeError::Policy(
                crate::ArchivePolicyError::UnsupportedEntry
            ))
        ));

        let mut special = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut special);
            let mut header = tar::Header::new_gnu();
            header.set_path(format!("{root}/device")).unwrap();
            header.set_entry_type(tar::EntryType::Char);
            header.set_mode(0o600);
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, io::empty()).unwrap();
            builder.finish().unwrap();
        }
        assert!(matches!(
            inspect_tar_xz_application_archive(spec(), &compress(&special)),
            Err(ArchiveIntakeError::Policy(
                crate::ArchivePolicyError::UnsupportedEntry
            ))
        ));

        let mut unsafe_mode = valid_tar_stream();
        let executable_header = 512 + BINARY_COMPANIONS.len() * 1024;
        unsafe_mode[executable_header + 100..executable_header + 108].copy_from_slice(b"0004755\0");
        set_header_checksum(&mut unsafe_mode[executable_header..executable_header + 512]);
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &compress(&unsafe_mode)),
            Err(ArchiveIntakeError::Policy(
                crate::ArchivePolicyError::UnsafeMode
            ))
        );
    }

    #[test]
    fn rejects_extensions_noncanonical_numbers_and_missing_end_marker() {
        let mut extension = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut extension);
            let mut header = tar::Header::new_gnu();
            header.set_path("pax").unwrap();
            header.set_entry_type(tar::EntryType::XHeader);
            header.set_mode(0o644);
            let body = b"11 path=x\n";
            header.set_size(body.len() as u64);
            header.set_cksum();
            builder.append(&header, &body[..]).unwrap();
            builder.finish().unwrap();
        }
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &compress(&extension)),
            Err(ArchiveIntakeError::UnsupportedTarMetadata)
        );

        let mut base_256 = valid_tar_stream();
        base_256[100] = 0x80;
        set_header_checksum(&mut base_256[..512]);
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &compress(&base_256)),
            Err(ArchiveIntakeError::InvalidTar)
        );

        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &compress(&[0_u8; 512])),
            Err(ArchiveIntakeError::InvalidTar)
        );
    }

    #[test]
    fn rejects_nonzero_file_padding() {
        let mut tar = valid_tar_stream();
        let first_file_data = 1024;
        tar[first_file_data + b"companion".len()] = 1;
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &compress(&tar)),
            Err(ArchiveIntakeError::InvalidTar)
        );
    }

    #[test]
    fn rejects_legacy_signed_tar_checksum() {
        let mut tar = valid_tar_stream();
        tar[265] = 0xff;
        set_signed_header_checksum(&mut tar[..512]);
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &compress(&tar)),
            Err(ArchiveIntakeError::InvalidTar)
        );
    }

    #[test]
    fn rejects_concatenated_xz_streams() {
        let mut concatenated = valid_tar();
        concatenated.extend(valid_tar());
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &concatenated),
            Err(ArchiveIntakeError::InvalidXz)
        );
    }

    #[test]
    fn rejects_weak_check_and_oversized_index_declarations() {
        let tar = valid_tar_stream();
        let mut options = XzOptions::with_preset(1);
        options.set_check_sum_type(CheckType::None);
        let mut writer = XzWriter::new(Vec::new(), options).unwrap();
        writer.write_all(&tar).unwrap();
        let weak = writer.finish().unwrap();
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &weak),
            Err(ArchiveIntakeError::InvalidXz)
        );

        let mut oversized_index = valid_tar();
        let footer = oversized_index.len() - 12;
        oversized_index[footer + 4..footer + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &oversized_index),
            Err(ArchiveIntakeError::InvalidXz)
        );
        assert_eq!(parse_xz_vli(&[0x80, 0]), Err(ArchiveIntakeError::InvalidXz));
    }

    #[test]
    fn rejects_malformed_block_headers_without_panicking() {
        let mut zero_sized_header = valid_tar();
        zero_sized_header[12] = 0;
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &zero_sized_header),
            Err(ArchiveIntakeError::InvalidXz)
        );

        let truncated_multi_filter = [1, 3, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            validate_xz_block_header(&truncated_multi_filter, 0, 8),
            Err(ArchiveIntakeError::InvalidXz)
        );

        let mut oversized_properties = [0_u8; 16];
        oversized_properties[0] = 3;
        oversized_properties[2] = 0x21;
        oversized_properties[3..12]
            .copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(
            validate_xz_block_header(&oversized_properties, 0, 16),
            Err(ArchiveIntakeError::InvalidXz)
        );
    }

    #[test]
    fn dictionary_limit_matches_lzma2_properties() {
        assert_eq!(
            lzma2_dictionary_size(28).unwrap(),
            APPLICATION_ARCHIVE_LIMITS.max_xz_dictionary_bytes
        );
        assert!(
            lzma2_dictionary_size(29).unwrap() > APPLICATION_ARCHIVE_LIMITS.max_xz_dictionary_bytes
        );
        assert_eq!(
            lzma2_dictionary_size(41),
            Err(ArchiveIntakeError::InvalidXz)
        );
    }

    #[test]
    fn enforces_block_limit_and_rejects_a_forged_small_index() {
        let maximum = compress_with_blocks(APPLICATION_ARCHIVE_LIMITS.max_xz_blocks as usize);
        assert!(inspect_tar_xz_application_archive(spec(), &maximum).is_ok());

        let excess = compress_with_blocks(APPLICATION_ARCHIVE_LIMITS.max_xz_blocks as usize + 1);
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &excess),
            Err(ArchiveIntakeError::InvalidXz)
        );
        let forged = replace_index_with_empty(excess);
        assert_eq!(
            inspect_tar_xz_application_archive(spec(), &forged),
            Err(ArchiveIntakeError::InvalidXz)
        );
    }

    fn set_header_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    }

    fn set_signed_header_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum = header
            .iter()
            .map(|byte| i64::from(*byte as i8))
            .sum::<i64>();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    }
}
