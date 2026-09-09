use std::io::Cursor;
use std::ops::Range;

use zip::{CompressionMethod, ZipArchive};
use zlib_rs::{Inflate, InflateFlush, Status};

use crate::{
    APPLICATION_ARCHIVE_LIMITS, APPLICATION_RELEASE_MANIFEST_NAME, ApplicationArchiveIntake,
    ApplicationArchiveSpec, ArchiveEntryKind, ArchiveEntrySummary, ArchiveFormat,
    ArchiveIntakeError, InspectedApplicationRelease,
    intake::checked_archive_size,
    intake::{ApplicationReleaseFile, CapturedApplicationRelease},
    validate_application_archive_entry_summaries,
};

const END_BYTES: usize = 22;
const CENTRAL_BYTES: usize = 46;
const LOCAL_BYTES: usize = 30;
const UTF8_FLAG: u16 = 1 << 11;

#[derive(Clone, Debug)]
struct ZipEntryRecord {
    name: Vec<u8>,
    flags: u16,
    compression: u16,
    crc32: u32,
    compressed_size: u64,
    expanded_size: u64,
    local_start: u64,
    data: Range<usize>,
    mode: Option<u32>,
    kind: ArchiveEntryKind,
}

#[derive(Clone, Copy, Debug)]
struct ZipEndRecord {
    entries: usize,
    central_start: usize,
    central_end: usize,
}

/// Fully validates one immutable Windows application ZIP snapshot.
pub fn inspect_zip_application_archive(
    spec: ApplicationArchiveSpec,
    archive_bytes: &[u8],
) -> Result<ApplicationArchiveIntake, ArchiveIntakeError> {
    process_zip_application_archive(spec, archive_bytes, false).map(|(intake, _)| intake)
}

pub(crate) fn extract_zip_application_release(
    spec: ApplicationArchiveSpec,
    archive_bytes: &[u8],
) -> Result<InspectedApplicationRelease, ArchiveIntakeError> {
    let (intake, captured) = process_zip_application_archive(spec, archive_bytes, true)?;
    captured
        .and_then(|captured| captured.into_inspected(intake))
        .ok_or(ArchiveIntakeError::InvalidZip)
}

fn process_zip_application_archive(
    spec: ApplicationArchiveSpec,
    archive_bytes: &[u8],
    capture_release: bool,
) -> Result<(ApplicationArchiveIntake, Option<CapturedApplicationRelease>), ArchiveIntakeError> {
    if spec.format() != ArchiveFormat::Zip {
        return Err(ArchiveIntakeError::UnsupportedFormat);
    }
    checked_archive_size(archive_bytes)?;

    let end = parse_end_record(archive_bytes)?;
    let mut records = parse_central_records(archive_bytes, end)?;
    validate_local_records(archive_bytes, end, &mut records)?;
    cross_check_zip_library(archive_bytes, &records)?;

    let summaries = records
        .iter()
        .map(|record| {
            ArchiveEntrySummary::from_utf8_name(
                &record.name,
                record.kind,
                record.expanded_size,
                record.mode,
                record.flags & 1 != 0,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let shape = validate_application_archive_entry_summaries(spec, summaries)?;
    let captured = validate_payloads(
        archive_bytes,
        &records,
        capture_release.then_some([
            spec.executable_name().as_bytes(),
            APPLICATION_RELEASE_MANIFEST_NAME.as_bytes(),
        ]),
    )?;

    let intake = ApplicationArchiveIntake::from_validated_snapshot(spec, archive_bytes, shape)?;
    Ok((intake, captured))
}

fn parse_end_record(bytes: &[u8]) -> Result<ZipEndRecord, ArchiveIntakeError> {
    let end = bytes
        .len()
        .checked_sub(END_BYTES)
        .ok_or(ArchiveIntakeError::InvalidZip)?;
    let record = &bytes[end..];
    let entries = usize::from(le_u16(record, 8)?);
    let central_size =
        usize::try_from(le_u32(record, 12)?).map_err(|_| ArchiveIntakeError::InvalidZip)?;
    let central_start =
        usize::try_from(le_u32(record, 16)?).map_err(|_| ArchiveIntakeError::InvalidZip)?;
    let central_end = central_start
        .checked_add(central_size)
        .ok_or(ArchiveIntakeError::InvalidZip)?;
    if record.get(..4) != Some(b"PK\x05\x06")
        || le_u16(record, 4)? != 0
        || le_u16(record, 6)? != 0
        || entries != usize::from(le_u16(record, 10)?)
        || entries == usize::from(u16::MAX)
        || entries > APPLICATION_ARCHIVE_LIMITS.max_entries
        || le_u16(record, 20)? != 0
        || central_size
            > usize::try_from(APPLICATION_ARCHIVE_LIMITS.max_zip_central_directory_bytes)
                .map_err(|_| ArchiveIntakeError::InvalidZip)?
        || central_end != end
    {
        return Err(ArchiveIntakeError::InvalidZip);
    }
    Ok(ZipEndRecord {
        entries,
        central_start,
        central_end,
    })
}

fn parse_central_records(
    bytes: &[u8],
    end: ZipEndRecord,
) -> Result<Vec<ZipEntryRecord>, ArchiveIntakeError> {
    let mut records = Vec::with_capacity(end.entries);
    let mut cursor = end.central_start;
    for _ in 0..end.entries {
        let fixed_end = cursor
            .checked_add(CENTRAL_BYTES)
            .filter(|position| *position <= end.central_end)
            .ok_or(ArchiveIntakeError::InvalidZip)?;
        let fixed = &bytes[cursor..fixed_end];
        if fixed.get(..4) != Some(b"PK\x01\x02") {
            return Err(ArchiveIntakeError::InvalidZip);
        }
        let flags = le_u16(fixed, 8)?;
        let compression = le_u16(fixed, 10)?;
        let compressed_size = u64::from(le_u32(fixed, 20)?);
        let expanded_size = u64::from(le_u32(fixed, 24)?);
        let name_len = usize::from(le_u16(fixed, 28)?);
        let extra_len = usize::from(le_u16(fixed, 30)?);
        let comment_len = usize::from(le_u16(fixed, 32)?);
        let local_start = u64::from(le_u32(fixed, 42)?);
        let variable_end = fixed_end
            .checked_add(name_len)
            .and_then(|position| position.checked_add(extra_len))
            .and_then(|position| position.checked_add(comment_len))
            .filter(|position| *position <= end.central_end)
            .ok_or(ArchiveIntakeError::InvalidZip)?;
        if flags & !UTF8_FLAG != 0
            || !matches!(compression, 0 | 8)
            || compression == 0 && compressed_size != expanded_size
            || name_len > APPLICATION_ARCHIVE_LIMITS.max_path_bytes
            || compressed_size == u64::from(u32::MAX)
            || expanded_size == u64::from(u32::MAX)
            || local_start == u64::from(u32::MAX)
            || le_u16(fixed, 34)? != 0
            || extra_len != 0
            || comment_len != 0
        {
            return Err(if matches!(compression, 0 | 8) {
                ArchiveIntakeError::InvalidZip
            } else {
                ArchiveIntakeError::UnsupportedCompression
            });
        }
        let name = bytes[fixed_end..fixed_end + name_len].to_vec();
        let made_by = le_u16(fixed, 4)? >> 8;
        let external = le_u32(fixed, 38)?;
        let mode = zip_entry_mode(made_by, external)?;
        let kind = entry_kind(&name, mode);
        records.push(ZipEntryRecord {
            name,
            flags,
            compression,
            crc32: le_u32(fixed, 16)?,
            compressed_size,
            expanded_size,
            local_start,
            data: 0..0,
            mode,
            kind,
        });
        cursor = variable_end;
    }
    if cursor != end.central_end {
        return Err(ArchiveIntakeError::InvalidZip);
    }
    Ok(records)
}

fn validate_local_records(
    bytes: &[u8],
    end: ZipEndRecord,
    records: &mut [ZipEntryRecord],
) -> Result<(), ArchiveIntakeError> {
    let mut order = (0..records.len()).collect::<Vec<_>>();
    order.sort_unstable_by_key(|index| records[*index].local_start);
    let mut expected_start = 0_usize;
    for index in order {
        let record = &records[index];
        let local_start =
            usize::try_from(record.local_start).map_err(|_| ArchiveIntakeError::InvalidZip)?;
        if local_start != expected_start {
            return Err(ArchiveIntakeError::InvalidZip);
        }
        let fixed_end = local_start
            .checked_add(LOCAL_BYTES)
            .filter(|position| *position <= end.central_start)
            .ok_or(ArchiveIntakeError::InvalidZip)?;
        let fixed = &bytes[local_start..fixed_end];
        let name_len = usize::from(le_u16(fixed, 26)?);
        let extra_len = usize::from(le_u16(fixed, 28)?);
        let data_start = fixed_end
            .checked_add(name_len)
            .and_then(|position| position.checked_add(extra_len))
            .filter(|position| *position <= end.central_start)
            .ok_or(ArchiveIntakeError::InvalidZip)?;
        let data_end = data_start
            .checked_add(
                usize::try_from(record.compressed_size)
                    .map_err(|_| ArchiveIntakeError::InvalidZip)?,
            )
            .filter(|position| *position <= end.central_start)
            .ok_or(ArchiveIntakeError::InvalidZip)?;
        if fixed.get(..4) != Some(b"PK\x03\x04")
            || le_u16(fixed, 6)? != record.flags
            || le_u16(fixed, 8)? != record.compression
            || le_u32(fixed, 14)? != record.crc32
            || u64::from(le_u32(fixed, 18)?) != record.compressed_size
            || u64::from(le_u32(fixed, 22)?) != record.expanded_size
            || extra_len != 0
            || bytes.get(fixed_end..fixed_end + name_len) != Some(record.name.as_slice())
        {
            return Err(ArchiveIntakeError::InvalidZip);
        }
        records[index].data = data_start..data_end;
        expected_start = data_end;
    }
    if expected_start != end.central_start {
        return Err(ArchiveIntakeError::InvalidZip);
    }
    Ok(())
}

fn cross_check_zip_library(
    bytes: &[u8],
    records: &[ZipEntryRecord],
) -> Result<(), ArchiveIntakeError> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|_| ArchiveIntakeError::InvalidZip)?;
    if archive.offset() != 0
        || !archive.comment().is_empty()
        || archive.zip64_comment().is_some()
        || archive.len() != records.len()
    {
        return Err(ArchiveIntakeError::InvalidZip);
    }
    for (index, record) in records.iter().enumerate() {
        let entry = archive
            .by_index_raw(index)
            .map_err(|_| ArchiveIntakeError::InvalidZip)?;
        if entry.name_raw() != record.name
            || entry.header_start() != record.local_start
            || entry.data_start() != record.data.start as u64
            || entry.compressed_size() != record.compressed_size
            || entry.size() != record.expanded_size
            || entry.crc32() != record.crc32
            || entry.unix_mode() != record.mode
            || entry.encrypted() != (record.flags & 1 != 0)
            || entry.compression()
                != match record.compression {
                    0 => CompressionMethod::Stored,
                    8 => CompressionMethod::DEFLATE,
                    _ => return Err(ArchiveIntakeError::UnsupportedCompression),
                }
        {
            return Err(ArchiveIntakeError::InvalidZip);
        }
    }
    Ok(())
}

fn validate_payloads(
    bytes: &[u8],
    records: &[ZipEntryRecord],
    capture_names: Option<[&[u8]; 2]>,
) -> Result<Option<CapturedApplicationRelease>, ArchiveIntakeError> {
    let mut actual_total = 0_u64;
    let mut captured = capture_names.map(|_| CapturedApplicationRelease::default());
    for record in records {
        let input = bytes
            .get(record.data.clone())
            .ok_or(ArchiveIntakeError::InvalidZip)?;
        let capture = capture_names.is_some_and(|names| names.contains(&record.name.as_slice()));
        let mut output = if capture {
            Some(Vec::with_capacity(
                usize::try_from(record.expanded_size)
                    .map_err(|_| ArchiveIntakeError::InvalidZip)?,
            ))
        } else {
            None
        };
        let (expanded, crc) = match record.compression {
            0 => {
                if let Some(output) = &mut output {
                    output.extend_from_slice(input);
                }
                (input.len() as u64, zlib_rs::crc32::crc32(0, input))
            }
            8 => inflate_payload(
                input,
                record.expanded_size,
                &mut actual_total,
                output.as_mut(),
            )?,
            _ => return Err(ArchiveIntakeError::UnsupportedCompression),
        };
        if record.compression == 0 {
            actual_total = actual_total
                .checked_add(expanded)
                .filter(|total| *total <= APPLICATION_ARCHIVE_LIMITS.max_expanded_bytes)
                .ok_or(ArchiveIntakeError::InvalidZip)?;
        }
        if expanded != record.expanded_size || crc != record.crc32 {
            return Err(ArchiveIntakeError::InvalidZip);
        }
        if let Some(output) = output {
            let captured = captured.as_mut().ok_or(ArchiveIntakeError::InvalidZip)?;
            captured.capture(
                if record.name == capture_names.expect("capture names exist")[0] {
                    ApplicationReleaseFile::Executable
                } else {
                    ApplicationReleaseFile::Manifest
                },
                output,
            );
        }
    }
    Ok(captured)
}

fn inflate_payload(
    input: &[u8],
    declared_size: u64,
    actual_total: &mut u64,
    mut captured: Option<&mut Vec<u8>>,
) -> Result<(u64, u32), ArchiveIntakeError> {
    let mut inflater = Inflate::new(false, 15);
    let mut output = [0_u8; 64 * 1024];
    let mut crc = 0_u32;
    loop {
        let before_in = inflater.total_in();
        let before_out = inflater.total_out();
        let input_start = usize::try_from(before_in).map_err(|_| ArchiveIntakeError::InvalidZip)?;
        let status = inflater
            .decompress(&input[input_start..], &mut output, InflateFlush::Finish)
            .map_err(|_| ArchiveIntakeError::InvalidZip)?;
        let consumed = inflater.total_in() - before_in;
        let produced = inflater.total_out() - before_out;
        let produced_usize =
            usize::try_from(produced).map_err(|_| ArchiveIntakeError::InvalidZip)?;
        crc = zlib_rs::crc32::crc32(crc, &output[..produced_usize]);
        *actual_total = actual_total
            .checked_add(produced)
            .filter(|total| *total <= APPLICATION_ARCHIVE_LIMITS.max_expanded_bytes)
            .ok_or(ArchiveIntakeError::InvalidZip)?;
        if inflater.total_out() > declared_size
            || inflater.total_out() > APPLICATION_ARCHIVE_LIMITS.max_entry_bytes
        {
            return Err(ArchiveIntakeError::InvalidZip);
        }
        if let Some(captured) = &mut captured {
            captured.extend_from_slice(&output[..produced_usize]);
        }
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError if consumed != 0 || produced != 0 => {}
            Status::Ok | Status::BufError => return Err(ArchiveIntakeError::InvalidZip),
        }
    }
    if inflater.total_in() != input.len() as u64 {
        return Err(ArchiveIntakeError::InvalidZip);
    }
    Ok((inflater.total_out(), crc))
}

fn zip_entry_mode(system: u16, attributes: u32) -> Result<Option<u32>, ArchiveIntakeError> {
    match system {
        3 => Ok((attributes != 0).then_some(attributes >> 16)),
        0 => {
            // DOS writers may retain Unix regular-file bits. Never let those
            // hide a link or special file, or let DOS flags hide a directory.
            if attributes & 0xffff & !0x21 != 0
                || !matches!((attributes >> 16) & 0o170000, 0 | 0o100000)
            {
                return Err(ArchiveIntakeError::InvalidZip);
            }
            // Match zip::ZipFile::unix_mode's DOS regular-file interpretation.
            let mode = if attributes & 1 != 0 { 0o444 } else { 0o100664 };
            Ok((attributes != 0).then_some(mode))
        }
        _ => Err(ArchiveIntakeError::InvalidZip),
    }
}

fn entry_kind(name: &[u8], mode: Option<u32>) -> ArchiveEntryKind {
    match mode.map(|value| value & 0o170000) {
        Some(0o120000) => ArchiveEntryKind::Link,
        Some(0o040000) if name.ends_with(b"/") => ArchiveEntryKind::Directory,
        Some(0 | 0o100000) => ArchiveEntryKind::File,
        Some(_) => ArchiveEntryKind::Special,
        None if name.ends_with(b"/") => ArchiveEntryKind::Directory,
        None => ArchiveEntryKind::File,
    }
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, ArchiveIntakeError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(ArchiveIntakeError::InvalidZip)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, ArchiveIntakeError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ArchiveIntakeError::InvalidZip)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{APPLICATION_ARCHIVES, ArchivePolicyError, BINARY_COMPANIONS};
    use zip::write::SimpleFileOptions;
    use zlib_rs::{Deflate, DeflateFlush};

    fn valid_zip() -> Vec<u8> {
        stored_zip(BINARY_COMPANIONS.into_iter().chain(["kitrove.exe"]))
    }

    fn stored_zip(names: impl IntoIterator<Item = &'static str>) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut output);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .unix_permissions(0o644);
            for name in names {
                archive.start_file(name, options).unwrap();
                archive.write_all(b"payload").unwrap();
            }
            archive.finish().unwrap();
        }
        output.into_inner()
    }

    #[test]
    fn dos_file_attributes_match_the_library_without_hiding_special_entries() {
        for attributes in [0, 1, 0x20, 0x21, 0o100644 << 16, (0o100644 << 16) | 1] {
            let mut bytes = valid_zip();
            for index in 0..BINARY_COMPANIONS.len() + 1 {
                let central = signature(&bytes, b"PK\x01\x02", index);
                bytes[central + 5] = 0;
                bytes[central + 38..central + 42].copy_from_slice(&u32::to_le_bytes(attributes));
            }
            let extracted = extract_zip_application_release(APPLICATION_ARCHIVES[3], &bytes)
                .expect("DOS regular files must agree with the ZIP library");
            assert_eq!(extracted.executable_bytes(), b"payload");
        }
        for attributes in [0x10, 0x08, 0x40, 0x80, 0o120777 << 16, 0o020666 << 16] {
            let mut bytes = valid_zip();
            let central = signature(&bytes, b"PK\x01\x02", 0);
            bytes[central + 5] = 0;
            bytes[central + 38..central + 42].copy_from_slice(&u32::to_le_bytes(attributes));
            assert!(inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &bytes).is_err());
        }
        let mut unknown = valid_zip();
        let central = signature(&unknown, b"PK\x01\x02", 0);
        unknown[central + 5] = 11;
        assert!(inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &unknown).is_err());
    }

    #[test]
    fn extracts_only_the_exact_validated_zip_release_files() {
        for bytes in [valid_zip(), deflated_zip()] {
            let extracted = extract_zip_application_release(APPLICATION_ARCHIVES[3], &bytes)
                .expect("valid ZIP extraction");
            assert_eq!(extracted.executable_bytes(), b"payload");
            assert_eq!(extracted.manifest_bytes(), b"payload");
            assert_eq!(
                extracted.intake(),
                inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &bytes).unwrap()
            );
        }

        let mut later_corruption = stored_zip(["kitrove.exe"].into_iter().chain(BINARY_COMPANIONS));
        let later_local = signature(&later_corruption, b"PK\x03\x04", 1);
        let later_name_len = usize::from(u16::from_le_bytes([
            later_corruption[later_local + 26],
            later_corruption[later_local + 27],
        ]));
        later_corruption[later_local + LOCAL_BYTES + later_name_len] ^= 1;
        assert_eq!(
            extract_zip_application_release(APPLICATION_ARCHIVES[3], &later_corruption),
            Err(ArchiveIntakeError::InvalidZip)
        );
    }

    #[test]
    fn rejects_stored_executable_size_disagreement_before_capture() {
        let mut bytes = valid_zip();
        let local = signature(&bytes, b"PK\x03\x04", 5);
        let central = signature(&bytes, b"PK\x01\x02", 5);
        let old_central_start = signature(&bytes, b"PK\x01\x02", 0);
        bytes.insert(old_central_start, 0);
        let shifted_central = central + 1;
        let end = signature(&bytes, b"PK\x05\x06", 0);
        bytes[local + 18..local + 22].copy_from_slice(&8_u32.to_le_bytes());
        bytes[shifted_central + 20..shifted_central + 24].copy_from_slice(&8_u32.to_le_bytes());
        bytes[end + 16..end + 20]
            .copy_from_slice(&u32::try_from(old_central_start + 1).unwrap().to_le_bytes());
        assert_eq!(
            extract_zip_application_release(APPLICATION_ARCHIVES[3], &bytes),
            Err(ArchiveIntakeError::InvalidZip)
        );
    }

    fn deflated_zip() -> Vec<u8> {
        let files = BINARY_COMPANIONS
            .into_iter()
            .chain(["kitrove.exe"])
            .map(|name| (name, b"payload".as_slice()))
            .collect::<Vec<_>>();
        let mut output = Vec::new();
        let mut central = Vec::new();
        for (name, payload) in files {
            let local_start = output.len() as u32;
            let compressed = deflate(payload);
            let crc = zlib_rs::crc32::crc32(0, payload);
            output.extend_from_slice(b"PK\x03\x04");
            push_u16(&mut output, 20);
            push_u16(&mut output, 0);
            push_u16(&mut output, 8);
            output.extend_from_slice(&[0; 4]);
            push_u32(&mut output, crc);
            push_u32(&mut output, compressed.len() as u32);
            push_u32(&mut output, payload.len() as u32);
            push_u16(&mut output, name.len() as u16);
            push_u16(&mut output, 0);
            output.extend_from_slice(name.as_bytes());
            output.extend_from_slice(&compressed);

            central.extend_from_slice(b"PK\x01\x02");
            push_u16(&mut central, (3 << 8) | 20);
            push_u16(&mut central, 20);
            push_u16(&mut central, 0);
            push_u16(&mut central, 8);
            central.extend_from_slice(&[0; 4]);
            push_u32(&mut central, crc);
            push_u32(&mut central, compressed.len() as u32);
            push_u32(&mut central, payload.len() as u32);
            push_u16(&mut central, name.len() as u16);
            central.extend_from_slice(&[0; 8]);
            push_u32(&mut central, 0o100644 << 16);
            push_u32(&mut central, local_start);
            central.extend_from_slice(name.as_bytes());
        }
        let central_start = output.len() as u32;
        let central_size = central.len() as u32;
        output.extend_from_slice(&central);
        output.extend_from_slice(b"PK\x05\x06");
        output.extend_from_slice(&[0; 4]);
        let entry_count = u16::try_from(BINARY_COMPANIONS.len() + 1).unwrap();
        push_u16(&mut output, entry_count);
        push_u16(&mut output, entry_count);
        push_u32(&mut output, central_size);
        push_u32(&mut output, central_start);
        push_u16(&mut output, 0);
        output
    }

    fn deflate(input: &[u8]) -> Vec<u8> {
        let mut deflater = Deflate::new(6, false, 15);
        let mut result = Vec::new();
        let mut buffer = [0_u8; 64];
        loop {
            let before_in = deflater.total_in();
            let before_out = deflater.total_out();
            let status = deflater
                .compress(
                    &input[before_in as usize..],
                    &mut buffer,
                    DeflateFlush::Finish,
                )
                .unwrap();
            let produced = (deflater.total_out() - before_out) as usize;
            result.extend_from_slice(&buffer[..produced]);
            if status == Status::StreamEnd {
                break;
            }
            assert!(deflater.total_in() != before_in || produced != 0);
        }
        result
    }

    fn push_u16(output: &mut Vec<u8>, value: u16) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn signature(bytes: &[u8], value: &[u8; 4], occurrence: usize) -> usize {
        bytes
            .windows(4)
            .enumerate()
            .filter(|(_, window)| *window == value)
            .nth(occurrence)
            .map(|(offset, _)| offset)
            .unwrap()
    }

    #[test]
    fn fully_reads_and_hashes_exact_zip() {
        for bytes in [valid_zip(), deflated_zip()] {
            let result = inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &bytes).unwrap();
            assert_eq!(result.archive_size(), bytes.len() as u64);
            assert_eq!(result.spec(), APPLICATION_ARCHIVES[3]);
            let expected_digest: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(result.archive_sha256(), expected_digest);
            assert_eq!(result.executable_size(), 7);
        }
    }

    #[test]
    fn rejects_trailing_truncated_and_wrong_format_archives() {
        let mut trailing = valid_zip();
        trailing.push(0);
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &trailing),
            Err(ArchiveIntakeError::InvalidZip)
        );
        let mut truncated = valid_zip();
        truncated.pop();
        assert!(inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &truncated).is_err());
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[0], &valid_zip()),
            Err(ArchiveIntakeError::UnsupportedFormat)
        );
    }

    #[test]
    fn rejects_local_central_name_disagreement() {
        let mut bytes = valid_zip();
        let position = bytes
            .windows(9)
            .position(|window| window == b"README.md")
            .unwrap();
        bytes[position] = b'X';
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &bytes),
            Err(ArchiveIntakeError::InvalidZip)
        );
    }

    #[test]
    fn rejects_metadata_before_or_during_expansion() {
        let mut oversized = deflated_zip();
        let local = signature(&oversized, b"PK\x03\x04", 0);
        let central = signature(&oversized, b"PK\x01\x02", 0);
        let too_large = (APPLICATION_ARCHIVE_LIMITS.max_entry_bytes + 1) as u32;
        oversized[local + 22..local + 26].copy_from_slice(&too_large.to_le_bytes());
        oversized[central + 24..central + 28].copy_from_slice(&too_large.to_le_bytes());
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &oversized),
            Err(ArchiveIntakeError::Policy(ArchivePolicyError::EntrySize))
        );

        let mut dishonest = deflated_zip();
        let local = signature(&dishonest, b"PK\x03\x04", 0);
        let central = signature(&dishonest, b"PK\x01\x02", 0);
        dishonest[local + 22..local + 26].copy_from_slice(&6_u32.to_le_bytes());
        dishonest[central + 24..central + 28].copy_from_slice(&6_u32.to_le_bytes());
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &dishonest),
            Err(ArchiveIntakeError::InvalidZip)
        );
    }

    #[test]
    fn rejects_crc_flags_compression_ranges_and_duplicate_records() {
        let cases = [
            (14, 16, 1_u32),
            (6, 8, u32::from(1_u16 << 3)),
            (18, 20, u32::MAX - 1),
        ];
        for (local_field, central_field, value) in cases {
            let mut bytes = valid_zip();
            let local = signature(&bytes, b"PK\x03\x04", 0);
            let central = signature(&bytes, b"PK\x01\x02", 0);
            if local_field == 6 {
                bytes[local + local_field..local + local_field + 2]
                    .copy_from_slice(&(value as u16).to_le_bytes());
                bytes[central + central_field..central + central_field + 2]
                    .copy_from_slice(&(value as u16).to_le_bytes());
            } else {
                bytes[local + local_field..local + local_field + 4]
                    .copy_from_slice(&value.to_le_bytes());
                bytes[central + central_field..central + central_field + 4]
                    .copy_from_slice(&value.to_le_bytes());
            }
            assert!(inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &bytes).is_err());
        }

        let mut duplicate = valid_zip();
        for signature_value in [b"PK\x03\x04", b"PK\x01\x02"] {
            let header = signature(&duplicate, signature_value, 3);
            let name_offset = header
                + if signature_value == b"PK\x03\x04" {
                    30
                } else {
                    46
                };
            duplicate[name_offset..name_offset + 11].copy_from_slice(b"kitrove.exe");
        }
        assert!(inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &duplicate).is_err());
    }

    #[test]
    fn rejects_unsupported_compression_links_and_special_entries() {
        let mut unsupported = valid_zip();
        let local = signature(&unsupported, b"PK\x03\x04", 0);
        let central = signature(&unsupported, b"PK\x01\x02", 0);
        unsupported[local + 8..local + 10].copy_from_slice(&12_u16.to_le_bytes());
        unsupported[central + 10..central + 12].copy_from_slice(&12_u16.to_le_bytes());
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &unsupported),
            Err(ArchiveIntakeError::UnsupportedCompression)
        );

        for mode in [0o120777_u32, 0o020666_u32] {
            let mut bytes = valid_zip();
            let central = signature(&bytes, b"PK\x01\x02", 0);
            bytes[central + 38..central + 42].copy_from_slice(&(mode << 16).to_le_bytes());
            assert_eq!(
                inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &bytes),
                Err(ArchiveIntakeError::Policy(
                    ArchivePolicyError::UnsupportedEntry
                ))
            );
        }
    }

    #[test]
    fn rejects_payload_corruption_hidden_gaps_and_excess_entry_counts() {
        let mut corrupted = valid_zip();
        let local = signature(&corrupted, b"PK\x03\x04", 0);
        let name_len = usize::from(u16::from_le_bytes([
            corrupted[local + 26],
            corrupted[local + 27],
        ]));
        corrupted[local + LOCAL_BYTES + name_len] ^= 1;
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &corrupted),
            Err(ArchiveIntakeError::InvalidZip)
        );

        let mut overlap = valid_zip();
        let second_central = signature(&overlap, b"PK\x01\x02", 1);
        overlap[second_central + 42..second_central + 46].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &overlap),
            Err(ArchiveIntakeError::InvalidZip)
        );

        let mut gap = valid_zip();
        let old_end = gap.len() - END_BYTES;
        let old_central = usize::try_from(le_u32(&gap[old_end..], 16).unwrap()).unwrap();
        gap.insert(old_central, 0);
        let new_end = gap.len() - END_BYTES;
        gap[new_end + 16..new_end + 20]
            .copy_from_slice(&u32::try_from(old_central + 1).unwrap().to_le_bytes());
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &gap),
            Err(ArchiveIntakeError::InvalidZip)
        );

        let mut count = valid_zip();
        let end = count.len() - END_BYTES;
        count[end + 8..end + 10].copy_from_slice(&10_001_u16.to_le_bytes());
        count[end + 10..end + 12].copy_from_slice(&10_001_u16.to_le_bytes());
        assert_eq!(
            inspect_zip_application_archive(APPLICATION_ARCHIVES[3], &count),
            Err(ArchiveIntakeError::InvalidZip)
        );
    }
}
