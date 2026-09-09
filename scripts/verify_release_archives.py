#!/usr/bin/env python3
"""Validate Kitrove release archives without extracting them."""

from __future__ import annotations

import argparse
import bisect
import contextlib
import dataclasses
import hashlib
import json
import lzma
import os
import re
import stat
import struct
import sys
import tarfile
import tempfile
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Iterator

COPY_BUFFER_BYTES = 1024 * 1024
MAX_TAR_EXTENDED_METADATA_BYTES = 1024 * 1024
MAX_TAR_EXTENDED_METADATA_TOTAL_BYTES = 4 * 1024 * 1024
MAX_RELEASE_CONTROL_BYTES = 16 * 1024 * 1024
RELEASE_FAMILIES = {
    "application_archives": ("kitrove-cli", "kitrove"),
    "installer_archives": ("kitrove-installer", "kitrove-installer"),
}
RELEASE_TARGETS = frozenset({
    "aarch64-apple-darwin", "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
})

WINDOWS_RESERVED_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
    | {f"{prefix}{index}" for prefix in ("COM", "LPT") for index in range(1, 10)}
)
DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
ARCHIVE_LIKE_SUFFIXES = (".7z", ".rar", ".tar", ".tbz", ".tbz2", ".txz")


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate release policy key: {key!r}")
        result[key] = value
    return result


def parse_application_archive_policy(
    source: str,
) -> tuple[
    dict[str, tuple[str, str]], dict[str, str], frozenset[str], dict[str, int], str, int
]:
    try:
        policy = json.loads(source, object_pairs_hook=reject_duplicate_json_keys)
        if (
            not isinstance(policy, dict)
            or set(policy) != {
                "schema", "application_archives", "installer_archives",
                "binary_companions", "release_manifest", "limits"
            }
            or type(policy["schema"]) is not int
            or policy["schema"] != 1
        ):
            raise ValueError("unsupported release policy schema")
        companions = policy["binary_companions"]
        if (
            not isinstance(companions, list)
            or len(companions) != 6
            or any(not isinstance(name, str) or not name for name in companions)
            or len(set(companions)) != len(companions)
        ):
            raise ValueError("release policy contains invalid binary companions")
        release_manifest = policy["release_manifest"]
        if (
            not isinstance(release_manifest, dict)
            or set(release_manifest) != {"name", "max_bytes"}
            or not isinstance(release_manifest["name"], str)
            or not release_manifest["name"]
            or type(release_manifest["max_bytes"]) is not int
            or release_manifest["max_bytes"] != 16 * 1024
            or companions.count(release_manifest["name"]) != 1
        ):
            raise ValueError("release policy contains an invalid release manifest policy")
        limits = policy["limits"]
        expected_limits = {
            "max_archive_bytes": 256 * 1024 * 1024,
            "max_tar_stream_bytes": 512 * 1024 * 1024 + 10_000 * 1024,
            "max_xz_blocks": 1024,
            "max_xz_decoder_memory_bytes": 96 * 1024 * 1024,
            "max_xz_dictionary_bytes": 64 * 1024 * 1024,
            "max_xz_index_bytes": 32 * 1024,
            "max_zip_central_directory_bytes": 16 * 1024 * 1024,
            "max_entries": 10_000,
            "max_entry_bytes": 128 * 1024 * 1024,
            "max_expanded_bytes": 512 * 1024 * 1024,
            "max_path_bytes": 4_096,
            "max_component_bytes": 255,
        }
        if (
            not isinstance(limits, dict)
            or set(limits) != set(expected_limits)
            or any(type(value) is not int or value <= 0 for value in limits.values())
            or limits != expected_limits
        ):
            raise ValueError("release policy contains unsupported resource limits")
        result: dict[str, tuple[str, str]] = {}
        targets: dict[str, str] = {}
        for family, (package, binary) in RELEASE_FAMILIES.items():
            family_entries = policy[family]
            if not isinstance(family_entries, list) or len(family_entries) != 4:
                raise ValueError("release policy requires four archives per family")
            seen_targets: set[str] = set()
            for entry in family_entries:
                if (
                    not isinstance(entry, dict)
                    or set(entry) != {"target", "archive", "root", "executable", "format"}
                    or not isinstance(entry["target"], str)
                ):
                    raise ValueError("release archive policy contains an invalid target")
                target = entry["target"]
                if target not in RELEASE_TARGETS or target in seen_targets:
                    raise ValueError("release archive policy contains an unknown or duplicate target")
                seen_targets.add(target)
                windows = target == "x86_64-pc-windows-msvc"
                archive_format = "zip" if windows else "tar.xz"
                root = f"{package}-{target}"
                if (
                    entry.get("archive") != f"{root}.{archive_format}"
                    or entry.get("root") != (None if windows else root)
                    or entry.get("executable") != binary + (".exe" if windows else "")
                    or entry.get("format") != archive_format
                ):
                    raise ValueError("release archive policy crosses its artifact family")
                archive = entry["archive"]
                result[archive] = (entry["root"] or "", entry["executable"])
                targets[archive] = target
        return (
            result,
            targets,
            frozenset(companions),
            limits,
            release_manifest["name"],
            release_manifest["max_bytes"],
        )
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise RuntimeError(f"invalid canonical release policy: {error}") from error


def load_application_archive_policy(
) -> tuple[
    dict[str, tuple[str, str]], dict[str, str], frozenset[str], dict[str, int], str, int
]:
    policy_path = Path(__file__).resolve().parent.parent / "release" / "release-policy.json"
    try:
        return parse_application_archive_policy(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        raise RuntimeError(f"invalid canonical release policy: {error}") from error


(
    EXPECTED_BINARY_ARCHIVES,
    EXPECTED_BINARY_TARGETS,
    BINARY_COMPANIONS,
    RELEASE_LIMITS,
    RELEASE_MANIFEST_NAME,
    MAX_RELEASE_MANIFEST_BYTES,
) = load_application_archive_policy()
MAX_ARCHIVE_BYTES = RELEASE_LIMITS["max_archive_bytes"]
MAX_TAR_STREAM_BYTES = RELEASE_LIMITS["max_tar_stream_bytes"]
MAX_XZ_BLOCKS = RELEASE_LIMITS["max_xz_blocks"]
# cargo-dist 0.32 emits a 64 MiB dictionary whose decoder needs about 65 MiB.
XZ_MEMORY_LIMIT_BYTES = RELEASE_LIMITS["max_xz_decoder_memory_bytes"]
MAX_XZ_DICTIONARY_BYTES = RELEASE_LIMITS["max_xz_dictionary_bytes"]
MAX_XZ_INDEX_BYTES = RELEASE_LIMITS["max_xz_index_bytes"]
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = RELEASE_LIMITS["max_zip_central_directory_bytes"]
MAX_ENTRIES = RELEASE_LIMITS["max_entries"]
MAX_ENTRY_BYTES = RELEASE_LIMITS["max_entry_bytes"]
MAX_EXPANDED_BYTES = RELEASE_LIMITS["max_expanded_bytes"]
MAX_PATH_BYTES = RELEASE_LIMITS["max_path_bytes"]
MAX_COMPONENT_BYTES = RELEASE_LIMITS["max_component_bytes"]
EXPECTED_RELEASE_ARCHIVES = frozenset(EXPECTED_BINARY_ARCHIVES) | {"source.tar.gz"}
GENERATED_INSTALLERS = frozenset(
    f"{package}-installer.{extension}"
    for package, _ in RELEASE_FAMILIES.values()
    for extension in ("sh", "ps1")
)
EXPECTED_RELEASE_FILES = (
    EXPECTED_RELEASE_ARCHIVES
    | {f"{name}.sha256" for name in EXPECTED_RELEASE_ARCHIVES}
    | GENERATED_INSTALLERS | {"sha256.sum"}
)
SOURCE_ROOT = re.compile(
    r"^kitrove-cli-(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)
RELEASE_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64}) \*([A-Za-z0-9._-]+)$")
SHELL_INSTALLER_ARCHIVE_BLOCK = re.compile(
    r'^        "([^"\r\n]+)"\)\r?\n'
    r'((?:^            [^\r\n]*\r?\n)+)'
    r'^            ;;\r?$',
    re.MULTILINE,
)


class ArchiveValidationError(ValueError):
    """The archive cannot be published safely."""


@dataclasses.dataclass(frozen=True)
class ArchiveEntry:
    name: str
    kind: str
    size: int
    mode: int = 0
    encrypted: bool = False
    sha256: str | None = None
    bounded_contents: bytes | None = None


def normalized_member_key(name: str, is_directory: bool) -> str:
    parts = safe_member_parts(name, is_directory)
    return "/".join(part.lower() for part in parts)


def is_lossless_windows_component(component: str) -> bool:
    if (
        not component
        or component.endswith((" ", "."))
        or any(character in WINDOWS_FORBIDDEN for character in component)
    ):
        return False
    stem = component.split(".", 1)[0].rstrip(" .").upper()
    return stem not in WINDOWS_RESERVED_STEMS


def safe_member_parts(name: str, is_directory: bool) -> tuple[str, ...]:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ArchiveValidationError("archive member name is not valid UTF-8") from error
    if not name or len(encoded) > MAX_PATH_BYTES:
        raise ArchiveValidationError("archive member path is empty or too long")
    if "\\" in name or name.startswith(("/", "//")) or DRIVE_PREFIX.match(name):
        raise ArchiveValidationError(f"archive member has an unsafe path: {name!r}")
    if any(unicodedata.category(character) == "Cc" for character in name):
        raise ArchiveValidationError(f"archive member contains a control character: {name!r}")

    path = name[:-1] if is_directory and name.endswith("/") else name
    raw_parts = path.split("/")
    if (
        not path
        or any(part in {"", ".", ".."} for part in raw_parts)
        or PurePosixPath(path).is_absolute()
    ):
        raise ArchiveValidationError(f"archive member has an unsafe path: {name!r}")

    for part in raw_parts:
        if len(part) > MAX_COMPONENT_BYTES:
            raise ArchiveValidationError(f"archive member component is too long: {name!r}")
        if (
            not part.isascii()
            or not is_lossless_windows_component(part)
        ):
            raise ArchiveValidationError(
                f"archive member is ambiguous on a supported platform: {name!r}"
            )
    return tuple(raw_parts)


def validate_entries(entries: Iterable[ArchiveEntry]) -> list[ArchiveEntry]:
    accepted: list[ArchiveEntry] = []
    destinations: set[str] = set()
    file_destinations: set[str] = set()
    expanded_bytes = 0

    for entry in entries:
        if len(accepted) >= MAX_ENTRIES:
            raise ArchiveValidationError("archive exceeds the supported entry limit")
        if entry.kind not in {"file", "directory"}:
            raise ArchiveValidationError(
                f"archive contains unsupported {entry.kind} member: {entry.name!r}"
            )
        if entry.encrypted:
            raise ArchiveValidationError(f"archive contains an encrypted member: {entry.name!r}")
        if entry.size < 0 or entry.size > MAX_ENTRY_BYTES:
            raise ArchiveValidationError(
                f"archive member exceeds the supported size: {entry.name!r}"
            )
        if entry.kind == "directory" and entry.size != 0:
            raise ArchiveValidationError(
                f"archive directory has an unexpected payload: {entry.name!r}"
            )

        key = normalized_member_key(entry.name, entry.kind == "directory")
        if key in destinations:
            raise ArchiveValidationError(
                f"archive contains a duplicate cross-platform destination: {entry.name!r}"
            )
        destinations.add(key)
        if entry.kind == "file":
            file_destinations.add(key)
        expanded_bytes += entry.size
        if expanded_bytes > MAX_EXPANDED_BYTES:
            raise ArchiveValidationError("archive exceeds the supported expanded-size limit")
        accepted.append(entry)

    if not accepted or not any(entry.kind == "file" for entry in accepted):
        raise ArchiveValidationError("archive contains no files")
    ordered_destinations = sorted(destinations)
    for key in file_destinations:
        prefix = f"{key}/"
        candidate = bisect.bisect_left(ordered_destinations, prefix)
        if candidate < len(ordered_destinations) and ordered_destinations[candidate].startswith(
            prefix
        ):
            raise ArchiveValidationError(
                f"archive file conflicts with a child destination: {key!r}"
            )
    return accepted


def tar_entries(file: BinaryIO) -> Iterator[ArchiveEntry]:
    with tarfile.open(fileobj=file, mode="r:") as archive:
        for member in archive:
            if member.isdir():
                kind = "directory"
            elif member.isreg() and not getattr(member, "sparse", None):
                kind = "file"
            elif member.issym():
                kind = "symbolic link"
            elif member.islnk():
                kind = "hard link"
            else:
                kind = "special"
            if kind == "file":
                if member.size > MAX_ENTRY_BYTES:
                    raise ArchiveValidationError(
                        f"TAR member exceeds the supported size: {member.name!r}"
                    )
                payload = archive.extractfile(member)
                if payload is None:
                    raise ArchiveValidationError(
                        f"TAR member payload is unavailable: {member.name!r}"
                    )
                observed = 0
                digest = hashlib.sha256()
                bounded_contents = bytearray()
                retain_contents = PurePosixPath(member.name).name == RELEASE_MANIFEST_NAME
                while chunk := payload.read(COPY_BUFFER_BYTES):
                    observed += len(chunk)
                    if observed > member.size or observed > MAX_ENTRY_BYTES:
                        raise ArchiveValidationError(
                            f"TAR member expanded beyond its declared size: {member.name!r}"
                        )
                    digest.update(chunk)
                    if retain_contents and len(bounded_contents) <= MAX_RELEASE_MANIFEST_BYTES:
                        bounded_contents.extend(chunk[: MAX_RELEASE_MANIFEST_BYTES + 1 - len(bounded_contents)])
                if observed != member.size:
                    raise ArchiveValidationError(
                        f"TAR member did not match its declared size: {member.name!r}"
                    )
                yield ArchiveEntry(
                    member.name,
                    kind,
                    member.size,
                    member.mode,
                    sha256=digest.hexdigest(),
                    bounded_contents=bytes(bounded_contents) if retain_contents else None,
                )
            else:
                yield ArchiveEntry(member.name, kind, member.size, member.mode)


def write_bounded(output: BinaryIO, chunk: bytes, total: int) -> int:
    total += len(chunk)
    if total > MAX_TAR_STREAM_BYTES:
        raise ArchiveValidationError("TAR stream exceeds the supported expanded-size limit")
    output.write(chunk)
    return total


def decompress_xz(file: BinaryIO, output: BinaryIO) -> None:
    preflight_xz(file)
    file.seek(0)
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_XZ,
        memlimit=XZ_MEMORY_LIMIT_BYTES,
    )
    total = 0
    while compressed := file.read(COPY_BUFFER_BYTES):
        pending = compressed
        while pending or not decoder.needs_input:
            chunk = decoder.decompress(pending, max_length=COPY_BUFFER_BYTES)
            pending = b""
            total = write_bounded(output, chunk, total)
            if decoder.eof:
                if decoder.unused_data or file.read(1):
                    raise ArchiveValidationError("XZ archive contains trailing compressed data")
                return
    if not decoder.eof:
        raise ArchiveValidationError("XZ archive is truncated")


def preflight_xz(file: BinaryIO) -> None:
    file.seek(0, os.SEEK_END)
    size = file.tell()
    if size < 24:
        raise ArchiveValidationError("XZ archive is truncated")
    file.seek(0)
    header = read_exact(file, 12)
    file.seek(-12, os.SEEK_END)
    footer = read_exact(file, 12)
    if (
        header[:6] != b"\xfd7zXZ\0"
        or header[6:8] != b"\0\4"
        or footer[8:10] != b"\0\4"
        or footer[10:] != b"YZ"
    ):
        raise ArchiveValidationError("XZ archive does not use the required CRC64 envelope")
    index_size = (int.from_bytes(footer[4:8], "little") + 1) * 4
    if index_size > MAX_XZ_INDEX_BYTES or index_size > size - 24:
        raise ArchiveValidationError("XZ index exceeds the supported limit")
    index_start = size - 12 - index_size
    file.seek(index_start)
    index = read_exact(file, index_size)
    if index[0] != 0:
        raise ArchiveValidationError("XZ archive contains an invalid index")
    blocks, position = read_xz_vli(index, 1)
    if blocks > MAX_XZ_BLOCKS:
        raise ArchiveValidationError("XZ archive exceeds the supported block limit")
    block_position = 12
    for _ in range(blocks):
        unpadded_size, position = read_xz_vli(index, position)
        _, position = read_xz_vli(index, position)
        preflight_xz_block(file, block_position, unpadded_size)
        block_position += (unpadded_size + 3) & ~3
    if (
        block_position != index_start
        or position > len(index) - 4
        or any(index[position:-4])
    ):
        raise ArchiveValidationError("XZ archive index does not span its physical blocks")


def read_xz_vli(data: bytes, position: int) -> tuple[int, int]:
    value = 0
    for index in range(9):
        if position >= len(data):
            break
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            if index and byte == 0:
                break
            return value, position
    raise ArchiveValidationError("XZ archive contains an invalid index count")


def preflight_xz_block(file: BinaryIO, block_start: int, unpadded_size: int) -> None:
    file.seek(block_start)
    encoded_size = read_exact(file, 1)[0]
    if encoded_size == 0:
        raise ArchiveValidationError("XZ block header uses the reserved zero size")
    header_size = (encoded_size + 1) * 4
    if header_size > unpadded_size:
        raise ArchiveValidationError("XZ block header exceeds its index record")
    file.seek(block_start)
    header = read_exact(file, header_size)
    flags = header[1]
    if flags & 0x3C:
        raise ArchiveValidationError("XZ block contains reserved flags")
    position = 2
    for present in (flags & 0x40, flags & 0x80):
        if present:
            _, position = read_xz_vli(header[:-4], position)
    filters = (flags & 3) + 1
    for index in range(filters):
        filter_id, position = read_xz_vli(header[:-4], position)
        properties_size, position = read_xz_vli(header[:-4], position)
        properties_end = position + properties_size
        if properties_end > len(header) - 4:
            raise ArchiveValidationError("XZ block filter properties exceed its header")
        properties = header[position:properties_end]
        position = properties_end
        if index + 1 == filters:
            if filter_id != 0x21 or len(properties) != 1 or properties[0] > 40:
                raise ArchiveValidationError("XZ block does not end in canonical LZMA2")
            dictionary = xz_dictionary_size(properties[0])
            if dictionary > MAX_XZ_DICTIONARY_BYTES:
                raise ArchiveValidationError("XZ dictionary exceeds the supported limit")
    if any(header[position:-4]):
        raise ArchiveValidationError("XZ block header padding is nonzero")

    payload_end = block_start + unpadded_size - 8
    file.seek(block_start + header_size)
    while file.tell() < payload_end:
        control = read_exact(file, 1)[0]
        if control == 0:
            if file.tell() != payload_end:
                raise ArchiveValidationError("XZ index conceals additional block data")
            return
        if control in {1, 2}:
            payload_size = int.from_bytes(read_exact(file, 2), "big") + 1
        elif control >= 0x80:
            read_exact(file, 2)
            payload_size = int.from_bytes(read_exact(file, 2), "big") + 1
            if control >= 0xC0:
                read_exact(file, 1)
        else:
            raise ArchiveValidationError("XZ contains invalid LZMA2 framing")
        if file.tell() + payload_size > payload_end:
            raise ArchiveValidationError("XZ block payload exceeds its index record")
        file.seek(payload_size, os.SEEK_CUR)
    raise ArchiveValidationError("XZ block has no LZMA2 end marker")


def xz_dictionary_size(property: int) -> int:
    if property > 40:
        raise ArchiveValidationError("XZ contains an invalid LZMA2 dictionary property")
    if property == 40:
        return 2**32 - 1
    return (2 | (property & 1)) << (property // 2 + 11)


def decompress_gzip(file: BinaryIO, output: BinaryIO) -> None:
    decoder = zlib.decompressobj(wbits=31)
    total = 0
    while compressed := file.read(COPY_BUFFER_BYTES):
        pending = compressed
        while pending:
            chunk = decoder.decompress(pending, max_length=COPY_BUFFER_BYTES)
            pending = decoder.unconsumed_tail
            total = write_bounded(output, chunk, total)
            if decoder.eof:
                if decoder.unused_data or pending or file.read(1):
                    raise ArchiveValidationError("GZIP archive contains trailing compressed data")
                return
    if not decoder.eof:
        raise ArchiveValidationError("GZIP archive is truncated")


def parse_tar_number(field: bytes, *, canonical: bool = False) -> int:
    if field and field[0] & 0x80:
        raise ArchiveValidationError("TAR base-256 sizes are unsupported")
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if any(byte not in b"01234567" for byte in value):
        raise ArchiveValidationError("TAR header contains an invalid number")
    if canonical:
        suffix = field[len(field) - len(field.lstrip(b" ")) + len(value) :]
        if not value or any(byte not in b"\0 " for byte in suffix):
            raise ArchiveValidationError("TAR header contains a non-canonical number")
    try:
        return int(value or b"0", 8)
    except ValueError as error:
        raise ArchiveValidationError("TAR header contains an invalid size") from error


def read_exact(file: BinaryIO, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = file.read(size - len(chunks))
        if not chunk:
            raise ArchiveValidationError("TAR stream is truncated")
        chunks.extend(chunk)
    return bytes(chunks)


def discard_exact(file: BinaryIO, size: int) -> None:
    remaining = size
    while remaining:
        chunk = file.read(min(remaining, COPY_BUFFER_BYTES))
        if not chunk:
            raise ArchiveValidationError("TAR stream is truncated")
        remaining -= len(chunk)


def discard_zeroes(file: BinaryIO, size: int) -> None:
    remaining = size
    while remaining:
        chunk = file.read(min(remaining, COPY_BUFFER_BYTES))
        if not chunk:
            raise ArchiveValidationError("TAR stream is truncated")
        if any(chunk):
            raise ArchiveValidationError("TAR member padding is nonzero")
        remaining -= len(chunk)


def preflight_tar(file: BinaryIO, *, strict_application: bool = False) -> None:
    entries = 0
    expanded = 0
    extended_metadata = 0
    zero_blocks = 0
    while True:
        header = read_exact(file, 512)
        if not any(header):
            zero_blocks += 1
            if zero_blocks == 2:
                while trailing := file.read(COPY_BUFFER_BYTES):
                    if any(trailing):
                        raise ArchiveValidationError("TAR stream contains trailing data")
                return
            continue
        if zero_blocks:
            raise ArchiveValidationError("TAR stream contains an incomplete end marker")
        entries += 1
        if entries > MAX_ENTRIES:
            raise ArchiveValidationError("TAR exceeds the supported entry limit")
        member_type = header[156:157]
        ordinary_types = {b"\0", b"0", b"1", b"2", b"3", b"4", b"5", b"6"}
        extended_types = {b"x", b"g", b"L", b"K"}
        if member_type not in ordinary_types | extended_types:
            raise ArchiveValidationError("TAR contains unsupported extended metadata")
        if strict_application and (
            member_type in extended_types
            or header[257:265] not in {b"ustar\x0000", b"ustar  \0"}
        ):
            raise ArchiveValidationError("application TAR contains unsupported metadata")
        size = parse_tar_number(header[124:136], canonical=strict_application)
        if strict_application:
            parse_tar_number(header[100:108], canonical=True)
            expected_checksum = parse_tar_number(header[148:156], canonical=True)
            unsigned_checksum = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
            if expected_checksum != unsigned_checksum:
                raise ArchiveValidationError("TAR header checksum is not canonical unsigned form")
        if size > MAX_ENTRY_BYTES:
            raise ArchiveValidationError("TAR member exceeds the supported size")
        if member_type in {b"x", b"g"} and size > MAX_TAR_EXTENDED_METADATA_BYTES:
            raise ArchiveValidationError("TAR extended metadata exceeds the supported limit")
        if member_type in {b"L", b"K"} and size > MAX_PATH_BYTES + 1:
            raise ArchiveValidationError("TAR extended name exceeds the supported path limit")
        if member_type in extended_types:
            extended_metadata += size
            if extended_metadata > MAX_TAR_EXTENDED_METADATA_TOTAL_BYTES:
                raise ArchiveValidationError(
                    "TAR aggregate extended metadata exceeds the supported limit"
                )
        expanded += size
        if expanded > MAX_EXPANDED_BYTES:
            raise ArchiveValidationError("TAR exceeds the supported expanded-size limit")
        padded = (size + 511) // 512 * 512
        discard_exact(file, size)
        discard_zeroes(file, padded - size)


@contextlib.contextmanager
def prepared_tar(file: BinaryIO, path: Path) -> Iterator[BinaryIO]:
    with tempfile.TemporaryFile() as expanded:
        if path.name.endswith((".tar.gz", ".tgz")):
            decompress_gzip(file, expanded)
        elif path.name.endswith(".tar.xz"):
            decompress_xz(file, expanded)
        else:
            raise ArchiveValidationError(f"unsupported TAR compression: {path.name!r}")
        expanded.seek(0)
        preflight_tar(expanded, strict_application=path.name.endswith(".tar.xz"))
        expanded.seek(0)
        yield expanded


def zip_entries(archive: zipfile.ZipFile) -> Iterator[ArchiveEntry]:
    for member in archive.infolist():
        if member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise ArchiveValidationError(
                f"ZIP member uses unsupported compression: {member.filename!r}"
            )
        mode = member.external_attr >> 16
        file_type = stat.S_IFMT(mode)
        if member.create_system == 0:
            if member.external_attr & 0xffff & ~0x21 or file_type not in {0, stat.S_IFREG}:
                raise ArchiveValidationError("DOS ZIP attributes are not regular-file authority")
        elif member.create_system != 3:
            raise ArchiveValidationError("unsupported ZIP origin system")
        if member.is_dir():
            kind = "directory"
        elif file_type in {0, stat.S_IFREG}:
            kind = "file"
        elif file_type == stat.S_IFLNK:
            kind = "symbolic link"
        else:
            kind = "special"
        digest: str | None = None
        contents: bytes | None = None
        if kind == "file":
            observed = 0
            hasher = hashlib.sha256()
            retained = bytearray()
            retain_contents = member.filename == RELEASE_MANIFEST_NAME
            with archive.open(member) as payload:
                while chunk := payload.read(COPY_BUFFER_BYTES):
                    observed += len(chunk)
                    if observed > member.file_size or observed > MAX_ENTRY_BYTES:
                        raise ArchiveValidationError(
                            f"ZIP member expanded beyond its declared size: {member.filename!r}"
                        )
                    hasher.update(chunk)
                    if retain_contents and len(retained) <= MAX_RELEASE_MANIFEST_BYTES:
                        retained.extend(chunk[: MAX_RELEASE_MANIFEST_BYTES + 1 - len(retained)])
            if observed != member.file_size:
                raise ArchiveValidationError(
                    f"ZIP member did not match its declared size: {member.filename!r}"
                )
            digest = hasher.hexdigest()
            contents = bytes(retained) if retain_contents else None
        yield ArchiveEntry(
            member.filename,
            kind,
            member.file_size,
            mode,
            bool(member.flag_bits & 0x1),
            digest,
            contents,
        )


def preflight_zip(file: BinaryIO, size: int) -> None:
    if size < 22:
        raise ArchiveValidationError("ZIP archive is too short")
    tail_size = min(size, 22 + 65_535)
    file.seek(size - tail_size)
    tail = file.read(tail_size)
    relative = tail.rfind(b"PK\x05\x06")
    if relative < 0 or relative + 22 > len(tail):
        raise ArchiveValidationError("ZIP end-of-central-directory record is missing")
    eocd_offset = size - tail_size + relative
    (
        disk,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = struct.unpack_from("<HHHHIIH", tail, relative + 4)
    if relative + 22 + comment_size != len(tail):
        raise ArchiveValidationError("ZIP end record or comment is inconsistent")
    if disk != 0 or central_disk != 0 or disk_entries != total_entries:
        raise ArchiveValidationError("multi-disk ZIP archives are unsupported")
    if total_entries == 0 or total_entries > MAX_ENTRIES:
        raise ArchiveValidationError("ZIP exceeds the supported entry limit")
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise ArchiveValidationError("ZIP64 release archives are unsupported")
    if central_size > MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        raise ArchiveValidationError("ZIP central directory exceeds the supported limit")
    if central_offset + central_size > eocd_offset:
        raise ArchiveValidationError("ZIP central directory bounds are inconsistent")
    file.seek(0)
    if file.read(4) != b"PK\x03\x04":
        raise ArchiveValidationError("ZIP archive has an unexpected prefix")
    file.seek(0)


def archive_kind(path: Path) -> str:
    name = path.name
    if name.endswith((".tar.xz", ".tar.gz", ".tgz")):
        return "tar"
    if name.endswith(".zip"):
        return "zip"
    raise ArchiveValidationError(f"unsupported release archive type: {name!r}")


def validate_binary_shape(path: Path, entries: Iterable[ArchiveEntry]) -> None:
    try:
        stem, binary = EXPECTED_BINARY_ARCHIVES[path.name]
    except KeyError as error:
        raise ArchiveValidationError(f"unrecognized binary archive: {path.name!r}") from error
    is_zip = archive_kind(path) == "zip"
    expected_files = BINARY_COMPANIONS | {binary}
    expected_directory = set() if is_zip else {stem}
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    binary_entry: ArchiveEntry | None = None
    manifest_entry: ArchiveEntry | None = None

    for entry in entries:
        parts = safe_member_parts(entry.name, entry.kind == "directory")
        if is_zip:
            if len(parts) != 1:
                raise ArchiveValidationError("binary ZIP members must be at the archive root")
            relative = parts[0]
        else:
            if len(parts) == 1 and entry.kind == "directory":
                relative = ""
            elif len(parts) == 2 and parts[0] == stem:
                relative = parts[1]
            else:
                raise ArchiveValidationError(
                    "binary TAR members must be direct children of the archive root"
                )
        if entry.kind == "directory":
            observed_directories.add(parts[-1])
        else:
            observed_files.add(relative)
            if relative == binary:
                binary_entry = entry
            elif relative == RELEASE_MANIFEST_NAME:
                manifest_entry = entry

    if observed_files != expected_files or observed_directories != expected_directory:
        raise ArchiveValidationError("binary archive does not contain the exact release file set")
    if binary_entry is None or binary_entry.size == 0:
        raise ArchiveValidationError("binary archive contains an empty executable")
    if (
        manifest_entry is None
        or manifest_entry.size == 0
        or manifest_entry.size > MAX_RELEASE_MANIFEST_BYTES
    ):
        raise ArchiveValidationError("binary archive contains an invalid release manifest size")
    if not is_zip and binary_entry.mode & 0o111 == 0:
        raise ArchiveValidationError("Unix release binary is not executable")


def validate_binary_manifest(
    path: Path, entries: Iterable[ArchiveEntry], expected_release_version: str
) -> None:
    stem, binary = EXPECTED_BINARY_ARCHIVES[path.name]
    prefix = "" if archive_kind(path) == "zip" else f"{stem}/"
    indexed = {entry.name: entry for entry in entries}
    executable = indexed[prefix + binary]
    manifest_entry = indexed[prefix + RELEASE_MANIFEST_NAME]
    try:
        manifest = json.loads(
            (manifest_entry.bounded_contents or b"").decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ArchiveValidationError("release manifest is not exact supported JSON") from error
    installer = binary in {"kitrove-installer", "kitrove-installer.exe"}
    expected_keys = {"schema", "release_version", "target", "executable_sha256"} | (
        {"artifact_kind", "executable_name"} if installer else {
            "application_state_schema", "lifecycle_lock_protocol", "rollback_compatible_predecessors"
        }
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected_keys
        or type(manifest["schema"]) is not int
        or manifest["schema"] != 1
        or manifest["release_version"] != expected_release_version
        or manifest["target"] != EXPECTED_BINARY_TARGETS[path.name]
        or manifest["executable_sha256"] != executable.sha256
    ):
        raise ArchiveValidationError("release manifest is not bound to the staged executable")
    if installer:
        if manifest["artifact_kind"] != "installer" or manifest["executable_name"] != binary:
            raise ArchiveValidationError("release manifest does not describe this installer")
        return
    predecessors = manifest["rollback_compatible_predecessors"]
    if (
        manifest["application_state_schema"] != "V1"
        or type(manifest["lifecycle_lock_protocol"]) is not int
        or manifest["lifecycle_lock_protocol"] != 1
        or not isinstance(predecessors, list)
        or len(predecessors) > 64
        or any(not isinstance(value, str) or not RELEASE_VERSION.fullmatch(value) for value in predecessors)
        or len(set(predecessors)) != len(predecessors)
    ):
        raise ArchiveValidationError("release manifest is not bound to the staged executable")


def validate_source_shape(entries: Iterable[ArchiveEntry]) -> None:
    entries = list(entries)
    roots = {
        safe_member_parts(entry.name, entry.kind == "directory")[0] for entry in entries
    }
    if len(roots) != 1:
        raise ArchiveValidationError("source archive must contain exactly one root directory")
    root = roots.pop()
    if not SOURCE_ROOT.fullmatch(root):
        raise ArchiveValidationError("source archive root is not the versioned Kitrove package")
    root_entries = [
        entry
        for entry in entries
        if safe_member_parts(entry.name, entry.kind == "directory") == (root,)
    ]
    if len(root_entries) != 1 or root_entries[0].kind != "directory":
        raise ArchiveValidationError("source archive is missing its explicit root directory")
    if not any(
        len(safe_member_parts(entry.name, entry.kind == "directory")) > 1
        and entry.kind == "file"
        for entry in entries
    ):
        raise ArchiveValidationError("source archive contains no source files")


def validate_tar_modes(path: Path, entries: Iterable[ArchiveEntry]) -> None:
    entries = list(entries)
    for entry in entries:
        mode = entry.mode & 0o7777
        if mode & 0o7000 or mode & 0o002:
            raise ArchiveValidationError(
                f"TAR member has unsafe permission bits: {entry.name!r}"
            )
    if path.name not in EXPECTED_BINARY_ARCHIVES:
        return
    stem, binary = EXPECTED_BINARY_ARCHIVES[path.name]
    for entry in entries:
        parts = safe_member_parts(entry.name, entry.kind == "directory")
        relative = "" if len(parts) == 1 else parts[-1]
        expected = 0o755 if entry.kind == "directory" or relative == binary else 0o644
        if entry.mode & 0o7777 != expected:
            raise ArchiveValidationError(
                f"binary TAR member has unexpected permissions: {entry.name!r}"
            )


def secure_archive_open_supported() -> bool:
    return all(hasattr(os, name) for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW"))


@contextlib.contextmanager
def open_archive_nofollow(path: Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    if not secure_archive_open_supported():
        raise ArchiveValidationError(
            "release archive verification requires no-follow directory handles"
        )
    absolute = path.absolute()
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.open(absolute.anchor, directory_flags)
    file_fd: int | None = None
    try:
        for component in absolute.parent.parts[1:]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(absolute.name, file_flags, dir_fd=directory_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ArchiveValidationError(f"release archive is not a regular file: {path}")
        with os.fdopen(file_fd, "rb", closefd=True) as file:
            file_fd = None
            yield file, metadata
    except OSError as error:
        raise ArchiveValidationError(f"cannot securely open release archive {path}: {error}") from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def stable_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def copy_open_file(
    source: BinaryIO,
    source_metadata: os.stat_result,
    destination: Path,
    *,
    mode: int,
    max_bytes: int,
) -> str:
    if source_metadata.st_size <= 0 or source_metadata.st_size > max_bytes:
        raise ArchiveValidationError(
            f"release artifact has an unsupported size: {destination.name!r}"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        destination_fd = os.open(destination, flags, mode)
    except OSError as error:
        raise ArchiveValidationError(
            f"cannot create private staged artifact {destination.name!r}: {error}"
        ) from error
    observed = 0
    digest = hashlib.sha256()
    source.seek(0)
    with os.fdopen(destination_fd, "wb", closefd=True) as staged:
        while chunk := source.read(COPY_BUFFER_BYTES):
            observed += len(chunk)
            if observed > source_metadata.st_size or observed > max_bytes:
                raise ArchiveValidationError(
                    f"release artifact changed size while staging: {destination.name!r}"
                )
            staged.write(chunk)
            digest.update(chunk)
        staged.flush()
        os.fsync(staged.fileno())
    if observed != source_metadata.st_size:
        raise ArchiveValidationError(
            f"release artifact did not match its inspected size: {destination.name!r}"
        )
    return digest.hexdigest()


def digest_open_file(file: BinaryIO, expected_size: int) -> str:
    file.seek(0)
    remaining = expected_size
    digest = hashlib.sha256()
    while remaining:
        chunk = file.read(min(remaining, COPY_BUFFER_BYTES))
        if not chunk:
            raise ArchiveValidationError("archive changed size during verification")
        remaining -= len(chunk)
        digest.update(chunk)
    if file.read(1):
        raise ArchiveValidationError("archive changed size during verification")
    file.seek(0)
    return digest.hexdigest()


def validate_archive(
    path: Path,
    staged_path: Path | None = None,
    *,
    expected_sha256: str | None = None,
    expected_release_version: str | None = None,
) -> str | None:
    kind = archive_kind(path)
    staged_digest: str | None = None
    try:
        with open_archive_nofollow(path) as (file, initial_metadata):
            if initial_metadata.st_size == 0 or initial_metadata.st_size > MAX_ARCHIVE_BYTES:
                raise ArchiveValidationError(
                    f"archive has an unsupported compressed size: {path}"
                )
            if expected_sha256 is not None:
                if len(expected_sha256) != 64 or any(
                    byte not in "0123456789abcdef" for byte in expected_sha256
                ):
                    raise ArchiveValidationError("expected archive SHA-256 is invalid")
                if digest_open_file(file, initial_metadata.st_size) != expected_sha256:
                    raise ArchiveValidationError("archive does not match its expected SHA-256")
            if kind == "tar":
                with prepared_tar(file, path) as expanded:
                    entries = validate_entries(tar_entries(expanded))
            else:
                preflight_zip(file, initial_metadata.st_size)
                with zipfile.ZipFile(file) as archive:
                    entries = validate_entries(zip_entries(archive))
            if kind == "tar":
                validate_tar_modes(path, entries)
            if path.name == "source.tar.gz":
                validate_source_shape(entries)
            else:
                validate_binary_shape(path, entries)
                if expected_release_version is not None:
                    validate_binary_manifest(path, entries, expected_release_version)
            if staged_path is not None:
                staged_digest = copy_open_file(
                    file,
                    initial_metadata,
                    staged_path,
                    mode=0o644,
                    max_bytes=MAX_ARCHIVE_BYTES,
                )
            final_metadata = os.fstat(file.fileno())
            if stable_file_identity(initial_metadata) != stable_file_identity(final_metadata):
                raise ArchiveValidationError(f"archive changed during verification: {path}")
    except (
        EOFError,
        OSError,
        RuntimeError,
        lzma.LZMAError,
        tarfile.TarError,
        zipfile.BadZipFile,
        zlib.error,
    ) as error:
        raise ArchiveValidationError(f"archive is malformed: {path.name!r}") from error
    return staged_digest


def copy_release_control(source: Path, destination: Path) -> None:
    with open_archive_nofollow(source) as (file, initial_metadata):
        mode = 0o755 if source.name in GENERATED_INSTALLERS and source.suffix == ".sh" else 0o644
        copy_open_file(
            file,
            initial_metadata,
            destination,
            mode=mode,
            max_bytes=MAX_RELEASE_CONTROL_BYTES,
        )
        final_metadata = os.fstat(file.fileno())
        if stable_file_identity(initial_metadata) != stable_file_identity(final_metadata):
            raise ArchiveValidationError(f"release artifact changed while staging: {source.name!r}")


def parse_checksum_document(path: Path) -> dict[str, str]:
    try:
        source = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ArchiveValidationError(f"checksum document is unreadable: {path.name!r}") from error
    # cargo-dist 0.32 emits one canonical blank line after its checksum records.
    # Accept that exact producer form, as well as the conventional single newline,
    # while continuing to reject interior or repeated blank records.
    if source.endswith("\n\n") and not source.endswith("\n\n\n"):
        source = source[:-1]
    mappings: dict[str, str] = {}
    for line in source.splitlines():
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ArchiveValidationError(f"checksum document is malformed: {path.name!r}")
        digest, name = match.groups()
        if name in mappings:
            raise ArchiveValidationError(
                f"checksum document contains a duplicate filename: {path.name!r}"
            )
        mappings[name] = digest
    if not mappings:
        raise ArchiveValidationError(f"checksum document is empty: {path.name!r}")
    return mappings


def validate_staged_checksums(directory: Path, digests: dict[str, str]) -> None:
    for name, digest in digests.items():
        adjacent = parse_checksum_document(directory / f"{name}.sha256")
        if adjacent != {name: digest}:
            raise ArchiveValidationError(
                f"adjacent checksum does not match staged archive: {name!r}"
            )
    combined = parse_checksum_document(directory / "sha256.sum")
    if combined != digests:
        raise ArchiveValidationError(
            "combined checksum document does not match the exact staged archive set"
        )


def unique_installer_assignment(body: str, variable: str) -> str:
    values = re.findall(rf'^            {re.escape(variable)}="([^"\r\n]+)"\r?$', body, re.MULTILINE)
    if len(values) != 1:
        raise ArchiveValidationError(f"installer does not assign {variable} exactly once")
    return values[0]


def validate_staged_installers(directory: Path, digests: dict[str, str]) -> None:
    for package, binary in RELEASE_FAMILIES.values():
        archives = {
            name for name, (_, executable) in EXPECTED_BINARY_ARCHIVES.items()
            if executable in {binary, f"{binary}.exe"}
        }
        validate_family_installers(directory, digests, package, archives)


def validate_family_installers(
    directory: Path, digests: dict[str, str], package: str, archives: set[str]
) -> None:
    try:
        shell = (directory / f"{package}-installer.sh").read_text(encoding="utf-8")
        powershell = (directory / f"{package}-installer.ps1").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ArchiveValidationError("generated installer is unreadable") from error
    case_marker = '    case "$_artifact_name" in '
    if shell.count(case_marker) != 1:
        raise ArchiveValidationError("shell installer has no unique archive dispatch")
    case_start = shell.index(case_marker) + len(case_marker)
    case_end = shell.find("\n    esac", case_start)
    if case_end < 0:
        raise ArchiveValidationError("shell installer archive dispatch is incomplete")
    archive_dispatch = shell[case_start:case_end]
    observed_headers = re.findall(r"^        ([^\r\n]+)\)\r?$", archive_dispatch, re.MULTILINE)
    expected_headers = {f'"{name}"' for name in archives} | {"*"}
    if len(observed_headers) != len(expected_headers) or set(observed_headers) != expected_headers:
        raise ArchiveValidationError("shell installer has an inexact archive dispatch set")
    shell_mappings: dict[str, str] = {}
    for match in SHELL_INSTALLER_ARCHIVE_BLOCK.finditer(archive_dispatch):
        name, body = match.groups()
        if name not in archives:
            raise ArchiveValidationError("shell installer contains an unknown archive mapping")
        if name in shell_mappings:
            raise ArchiveValidationError("shell installer repeats an archive mapping")
        if unique_installer_assignment(body, "_checksum_style") != "sha256":
            raise ArchiveValidationError("shell installer uses an unsupported checksum")
        shell_mappings[name] = unique_installer_assignment(body, "_checksum_value")
    expected = {name: digests[name] for name in archives}
    if shell_mappings != expected:
        raise ArchiveValidationError(
            "shell installer archive-to-checksum mappings do not match staged archives"
        )

    windows_targets = {
        "aarch64-pc-windows-msvc",
        "x86_64-pc-windows-gnu",
        "x86_64-pc-windows-msvc",
    }
    windows_target = "x86_64-pc-windows-msvc"
    windows_name = next(
        name for name in archives if EXPECTED_BINARY_TARGETS[name] == windows_target
    )
    target_block = re.compile(
        r'^    "([^"\r\n]+)" = @\{\r?\n'
        r'(?P<body>.*?)'
        r'^    \}\r?$',
        re.MULTILINE | re.DOTALL,
    )
    platform_marker = "$platforms = @{"
    if powershell.count(platform_marker) != 1:
        raise ArchiveValidationError("PowerShell installer has no unique platform map")
    platform_start = powershell.index(platform_marker) + len(platform_marker)
    platform_end = powershell.find("\n  }\n\n  $arch", platform_start)
    if platform_end < 0:
        raise ArchiveValidationError("PowerShell installer platform map is incomplete")
    mappings: dict[str, tuple[str, str]] = {}
    for block in target_block.finditer(powershell[platform_start:platform_end]):
        target, body = block.group(1), block.group("body")
        if target in mappings:
            raise ArchiveValidationError("PowerShell installer repeats a platform mapping")
        artifact_names = re.findall(
            r'^      "artifact_name" = "([^"\r\n]+)"\r?$', body, re.MULTILINE
        )
        checksums = re.findall(r'^      "sha256" = "([0-9a-f]{64})"\r?$', body, re.MULTILINE)
        if len(artifact_names) != 1 or len(checksums) != 1:
            raise ArchiveValidationError("PowerShell platform mapping is incomplete")
        mappings[target] = (artifact_names[0], checksums[0])
    expected_windows = {target: (windows_name, digests[windows_name]) for target in windows_targets}
    if mappings != expected_windows:
        raise ArchiveValidationError("PowerShell installer has an inexact platform map")
    download_boundary = "  Invoke-DownloadFile -client $wc -url $url -path $dir_path\n"
    verification_sequence = download_boundary + (
        '  $expected_sha256 = $info["sha256"]\n'
        "  $observed_sha256 = (Get-FileHash -LiteralPath $dir_path -Algorithm SHA256).Hash.ToLowerInvariant()\n"
        "  if ($observed_sha256 -ne $expected_sha256) {\n"
        '    throw "downloaded archive checksum mismatch"\n'
        "  }\n"
    )
    if (
        powershell.count(download_boundary) != 1
        or powershell.count(verification_sequence) != 1
    ):
        raise ArchiveValidationError("PowerShell installer does not verify its downloaded archive")


def stage_release_directory(
    source: Path,
    destination: Path,
    archives: Iterable[Path],
    release_version: str,
) -> None:
    try:
        os.mkdir(destination, 0o700)
    except OSError as error:
        raise ArchiveValidationError(
            f"cannot create private publication staging directory: {error}"
        ) from error
    digests: dict[str, str] = {}
    for archive in archives:
        digest = validate_archive(
            archive,
            destination / archive.name,
            expected_release_version=(
                release_version if archive.name in EXPECTED_BINARY_ARCHIVES else None
            ),
        )
        if digest is None:
            raise ArchiveValidationError("staged archive did not produce a content digest")
        digests[archive.name] = digest
    for name in sorted(EXPECTED_RELEASE_FILES - EXPECTED_RELEASE_ARCHIVES):
        copy_release_control(source / name, destination / name)
    validate_staged_checksums(destination, digests)
    validate_staged_installers(destination, digests)
    directory_fd = os.open(
        destination,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def looks_like_archive(path: Path) -> bool:
    name = path.name.lower()
    return ".tar." in name or name.endswith(ARCHIVE_LIKE_SUFFIXES)


def discover_archives(inputs: Iterable[Path]) -> list[Path]:
    archives: set[Path] = set()
    for candidate in inputs:
        if candidate.is_dir():
            observed: set[str] = set()
            observed_files: set[str] = set()
            for child in candidate.iterdir():
                if child.is_symlink():
                    raise ArchiveValidationError(
                        f"release artifact path is a symbolic link: {child.name!r}"
                    )
                if not child.is_file():
                    raise ArchiveValidationError(
                        f"release directory contains a non-file entry: {child.name!r}"
                    )
                if child.name == "dist-manifest.json" or child.name.endswith(
                    "-dist-manifest.json"
                ):
                    continue
                observed_files.add(child.name)
                if child.name not in EXPECTED_RELEASE_FILES:
                    if looks_like_archive(child):
                        raise ArchiveValidationError(
                            f"unsupported release archive type: {child.name!r}"
                        )
                    raise ArchiveValidationError(
                        f"unrecognized release artifact: {child.name!r}"
                    )
                if child.name in EXPECTED_RELEASE_ARCHIVES:
                    observed.add(child.name)
                    archives.add(child)
            missing_files = EXPECTED_RELEASE_FILES - observed_files
            if missing_files:
                raise ArchiveValidationError(
                    f"release directory is missing expected artifacts: {sorted(missing_files)!r}"
                )
            missing = EXPECTED_RELEASE_ARCHIVES - observed
            if missing:
                raise ArchiveValidationError(
                    f"release directory is missing expected archives: {sorted(missing)!r}"
                )
        else:
            archives.add(candidate)
    if not archives:
        raise ArchiveValidationError("no release archives were supplied")
    return sorted(archives)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stage",
        type=Path,
        help="copy the exact verified publication set into a new private directory",
    )
    parser.add_argument(
        "--release-tag",
        help="canonical v-prefixed release version required for publication staging",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="archive files or containing directories")
    arguments = parser.parse_args(argv)
    try:
        archives = discover_archives(arguments.paths)
        if arguments.stage is not None:
            if len(arguments.paths) != 1 or not arguments.paths[0].is_dir():
                raise ArchiveValidationError("publication staging requires one release directory")
            if (
                arguments.release_tag is None
                or not arguments.release_tag.startswith("v")
                or not RELEASE_VERSION.fullmatch(arguments.release_tag[1:])
            ):
                raise ArchiveValidationError(
                    "publication staging requires a canonical v-prefixed release tag"
                )
            stage_release_directory(
                arguments.paths[0],
                arguments.stage,
                archives,
                arguments.release_tag[1:],
            )
        elif arguments.release_tag is not None:
            raise ArchiveValidationError("--release-tag is only valid with --stage")
        else:
            for path in archives:
                validate_archive(path)
                print(f"verified release archive: {path.name}")
    except ArchiveValidationError as error:
        print(f"release archive verification failed: {error}", file=sys.stderr)
        return 1
    if arguments.stage is None:
        print(f"release archive verification passed ({len(archives)} archives)")
    else:
        print(f"verified release publication set staged in {arguments.stage}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
