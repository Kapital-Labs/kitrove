#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import stat
import tarfile
import zipfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((REPOSITORY_ROOT / "release/release-policy.json").read_text(encoding="ascii"))
COMPANIONS = {name: name.encode("ascii") for name in POLICY["binary_companions"]}
RELEASE_MANIFEST_NAME = str(POLICY["release_manifest"]["name"])
EXPECTED_CASES = frozenset(
    {
        "valid_tar_xz",
        "valid_zip",
        "tar_unsafe_mode",
        "tar_traversal",
        "tar_extended_metadata",
        "tar_nonzero_padding",
        "tar_concatenated_xz",
        "zip_extra_entry",
        "zip_traversal",
        "zip_corrupt_crc",
    }
)


def representative_spec(format_name: str) -> dict[str, object]:
    candidates = sorted(
        (
            archive
            for archive in POLICY["application_archives"]
            if archive["format"] == format_name
        ),
        key=lambda archive: archive["target"],
    )
    if not candidates:
        raise RuntimeError(f"release policy has no {format_name} application archive")
    return candidates[0]


TAR_SPEC = representative_spec("tar.xz")
ZIP_SPEC = representative_spec("zip")
TAR_TARGET = str(TAR_SPEC["target"])
ZIP_TARGET = str(ZIP_SPEC["target"])
TAR_NAME = str(TAR_SPEC["archive"])
ZIP_NAME = str(ZIP_SPEC["archive"])


def tar_stream(*, executable_mode: int = 0o755, executable_name: str = "kitrove") -> bytes:
    root = str(TAR_SPEC["root"])
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
        directory = tarfile.TarInfo(f"{root}/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        for name, content in COMPANIONS.items():
            if name == RELEASE_MANIFEST_NAME:
                content = release_manifest(TAR_SPEC)
            add_tar_file(archive, f"{root}/{name}", content, 0o644)
        selected_executable = (
            executable_name if executable_name != "kitrove" else str(TAR_SPEC["executable"])
        )
        add_tar_file(archive, f"{root}/{selected_executable}", b"binary", executable_mode)
    return output.getvalue()


def add_tar_file(archive: tarfile.TarFile, name: str, content: bytes, mode: int) -> None:
    entry = tarfile.TarInfo(name)
    entry.size = len(content)
    entry.mode = mode
    archive.addfile(entry, io.BytesIO(content))


def compress_tar(content: bytes) -> bytes:
    return lzma.compress(content, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)


def release_manifest(spec: dict[str, object]) -> bytes:
    return json.dumps(
        {
            "schema": 1,
            "release_version": "1.2.3",
            "target": spec["target"],
            "executable_sha256": hashlib.sha256(b"binary").hexdigest(),
            "application_state_schema": "V1",
            "lifecycle_lock_protocol": 1,
            "rollback_compatible_predecessors": [],
        },
        separators=(",", ":"),
    ).encode("ascii")


def zip_archive(*, extra_name: str | None = None, corrupt_crc: bool = False) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in COMPANIONS.items():
            if name == RELEASE_MANIFEST_NAME:
                content = release_manifest(ZIP_SPEC)
            add_zip_file(archive, name, content)
        add_zip_file(archive, str(ZIP_SPEC["executable"]), b"binary")
        if extra_name is not None:
            add_zip_file(archive, extra_name, b"extra")
    content = bytearray(output.getvalue())
    if corrupt_crc:
        central = content.find(b"PK\x01\x02")
        if central < 0:
            raise RuntimeError("generated ZIP has no central directory")
        content[central + 16 : central + 20] = b"\0" * 4
    return bytes(content)


def add_zip_file(archive: zipfile.ZipFile, name: str, content: bytes) -> None:
    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.create_system = 3
    entry.external_attr = (stat.S_IFREG | 0o644) << 16
    archive.writestr(entry, content)


def pax_extension() -> bytes:
    entry = tarfile.TarInfo("metadata")
    entry.type = tarfile.XHDTYPE
    body = b"8 key=x\n"
    entry.size = len(body)
    return entry.tobuf(format=tarfile.GNU_FORMAT) + body + b"\0" * (512 - len(body))


def corpus() -> list[tuple[str, str, str, bool, bytes]]:
    nonzero_padding = bytearray(tar_stream())
    nonzero_padding[1024 + len(COMPANIONS["README.md"])] = 1
    valid_tar = compress_tar(tar_stream())
    valid_zip = zip_archive()
    return [
        ("valid_tar_xz", TAR_TARGET, TAR_NAME, True, valid_tar),
        ("valid_zip", ZIP_TARGET, ZIP_NAME, True, valid_zip),
        (
            "tar_unsafe_mode",
            TAR_TARGET,
            TAR_NAME,
            False,
            compress_tar(tar_stream(executable_mode=0o4755)),
        ),
        (
            "tar_traversal",
            TAR_TARGET,
            TAR_NAME,
            False,
            compress_tar(tar_stream(executable_name="../escape")),
        ),
        (
            "tar_extended_metadata",
            TAR_TARGET,
            TAR_NAME,
            False,
            compress_tar(pax_extension() + tar_stream()),
        ),
        (
            "tar_nonzero_padding",
            TAR_TARGET,
            TAR_NAME,
            False,
            compress_tar(nonzero_padding),
        ),
        (
            "tar_concatenated_xz",
            TAR_TARGET,
            TAR_NAME,
            False,
            valid_tar + valid_tar,
        ),
        (
            "zip_extra_entry",
            ZIP_TARGET,
            ZIP_NAME,
            False,
            zip_archive(extra_name="extra"),
        ),
        (
            "zip_traversal",
            ZIP_TARGET,
            ZIP_NAME,
            False,
            zip_archive(extra_name="../escape"),
        ),
        (
            "zip_corrupt_crc",
            ZIP_TARGET,
            ZIP_NAME,
            False,
            zip_archive(corrupt_crc=True),
        ),
    ]


def generated_files() -> dict[Path, bytes]:
    files: dict[Path, bytes] = {}
    manifest = []
    for case, target, archive_name, accepted, content in corpus():
        relative_archive = Path(case) / archive_name
        files[relative_archive] = content
        manifest.append(
            {
                "case": case,
                "target": target,
                "archive": relative_archive.as_posix(),
                "accepted": accepted,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    observed_cases = {case["case"] for case in manifest}
    if observed_cases != EXPECTED_CASES or len(manifest) != len(EXPECTED_CASES):
        raise RuntimeError("generated corpus does not contain the exact reviewed case inventory")
    files[Path("cases.json")] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
        "ascii"
    )
    return files


def write_corpus(destination: Path) -> None:
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError("corpus destination must be absent or empty")
    for relative, content in generated_files().items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def check_corpus(destination: Path) -> None:
    expected = generated_files()
    expected_directories = {path.parent for path in expected if path.parent != Path(".")}
    actual_files: set[Path] = set()
    actual_directories: set[Path] = set()
    for path in destination.rglob("*"):
        relative = path.relative_to(destination)
        if path.is_symlink():
            raise RuntimeError(f"checked-in corpus contains a symbolic link: {relative}")
        if path.is_dir():
            actual_directories.add(relative)
        elif path.is_file():
            if relative != Path("README.md"):
                actual_files.add(relative)
        else:
            raise RuntimeError(f"checked-in corpus contains a special file: {relative}")
    if actual_files != set(expected) or actual_directories != expected_directories:
        raise RuntimeError("checked-in corpus file inventory differs from its generator")
    for relative, content in expected.items():
        if (destination / relative).read_bytes() != content:
            raise RuntimeError(f"checked-in corpus differs from generator: {relative}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    if arguments.check:
        check_corpus(arguments.destination)
    else:
        write_corpus(arguments.destination)


if __name__ == "__main__":
    main()
