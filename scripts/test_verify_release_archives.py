#!/usr/bin/env python3

from __future__ import annotations

import gzip
import hashlib
import io
import json
import lzma
import os
import stat
import struct
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import verify_release_archives as verifier
import generate_release_archive_corpus as corpus_generator


COMPANIONS = {
    "README.md": b"readme",
    "CHANGELOG.md": b"changes",
    "LICENSE.md": b"license",
    "LICENSE-MIT": b"mit",
    "LICENSE-APACHE": b"apache",
    "kitrove-release.json": b"manifest",
}


def release_manifest(
    target: str, executable: bytes, version: str = "1.2.3", *, installer: bool = False
) -> bytes:
    return json.dumps(
        {
            "schema": 1,
            "release_version": version,
            "target": target,
            "executable_sha256": hashlib.sha256(executable).hexdigest(),
            **({
                "artifact_kind": "installer",
                "executable_name": "kitrove-installer" + (
                    ".exe" if target == "x86_64-pc-windows-msvc" else ""
                ),
            } if installer else {
                "application_state_schema": "V1",
                "lifecycle_lock_protocol": 1,
                "rollback_compatible_predecessors": [],
            }),
        },
        separators=(",", ":"),
    ).encode()


def write_tar(
    path: Path,
    files: dict[str, bytes],
    *,
    link: str | None = None,
    root_name: str | None = None,
    root_mode: int = 0o755,
    mode_overrides: dict[str, int] | None = None,
) -> None:
    stem = root_name or path.name.removesuffix(".tar.xz")
    mode_overrides = mode_overrides or {}
    write_mode = "w:gz" if path.name.endswith(".gz") else "w:xz"
    with tarfile.open(path, write_mode) as archive:
        root = tarfile.TarInfo(f"{stem}/")
        root.type = tarfile.DIRTYPE
        root.mode = root_mode
        archive.addfile(root)
        for name, content in files.items():
            entry = tarfile.TarInfo(f"{stem}/{name}")
            entry.size = len(content)
            entry.mode = mode_overrides.get(
                name, 0o755 if name in {"kitrove", "kitrove-installer"} else 0o644
            )
            archive.addfile(entry, io.BytesIO(content))
        if link is not None:
            entry = tarfile.TarInfo(f"{stem}/linked")
            entry.type = tarfile.SYMTYPE
            entry.linkname = link
            archive.addfile(entry)


def write_zip(path: Path, files: dict[str, bytes], *, symlink: bool = False) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        if symlink:
            entry = zipfile.ZipInfo("linked")
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, "outside")


def corrupt_zip_member(path: Path, name: str) -> None:
    with zipfile.ZipFile(path) as archive:
        member = archive.getinfo(name)
        offset = member.header_offset
    content = bytearray(path.read_bytes())
    name_length, extra_length = struct.unpack_from("<HH", content, offset + 26)
    payload = offset + 30 + name_length + extra_length
    content[payload + max(member.compress_size // 2, 0)] ^= 0xFF
    path.write_bytes(content)


def central_header_offset(content: bytes, name: str) -> int:
    expected = name.encode("utf-8")
    offset = 0
    while (offset := content.find(b"PK\x01\x02", offset)) >= 0:
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", content, offset + 28)
        observed = content[offset + 46 : offset + 46 + name_length]
        if observed == expected:
            return offset
        offset += 46 + name_length + extra_length + comment_length
    raise AssertionError(f"ZIP central header not found for {name!r}")


def corrupt_zip_crc(path: Path, name: str) -> None:
    content = bytearray(path.read_bytes())
    offset = central_header_offset(content, name)
    struct.pack_into("<I", content, offset + 16, 0)
    path.write_bytes(content)


def forge_zip_expanded_size(path: Path, name: str, size: int) -> None:
    content = bytearray(path.read_bytes())
    offset = central_header_offset(content, name)
    struct.pack_into("<I", content, offset + 24, size)
    path.write_bytes(content)


def corrupt_zip_local_name(path: Path, name: str) -> None:
    with zipfile.ZipFile(path) as archive:
        member = archive.getinfo(name)
    content = bytearray(path.read_bytes())
    name_length = struct.unpack_from("<H", content, member.header_offset + 26)[0]
    if name_length == 0:
        raise AssertionError("test ZIP member has no local name")
    content[member.header_offset + 30] ^= 0x01
    path.write_bytes(content)


def write_release_directory(root: Path) -> None:
    for name, (stem, binary) in verifier.EXPECTED_BINARY_ARCHIVES.items():
        path = root / name
        executable = b"binary"
        files = COMPANIONS | {
            binary: executable,
            verifier.RELEASE_MANIFEST_NAME: release_manifest(
                verifier.EXPECTED_BINARY_TARGETS[name], executable,
                installer=binary.startswith("kitrove-installer"),
            ),
        }
        if name.endswith(".zip"):
            write_zip(path, files)
        else:
            write_tar(path, files, root_name=stem)
    write_tar(
        root / "source.tar.gz",
        {"README.md": b"source"},
        root_name="kitrove-cli-1.2.3",
    )
    digests = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in verifier.EXPECTED_RELEASE_ARCHIVES
    }
    for name, digest in digests.items():
        (root / f"{name}.sha256").write_text(
            f"{digest} *{name}\n",
            encoding="ascii",
        )
    (root / "sha256.sum").write_text(
        "".join(f"{digests[name]} *{name}\n" for name in sorted(digests)),
        encoding="ascii",
    )
    checksum_files = {f"{name}.sha256" for name in digests} | {"sha256.sum"}
    for name in (
        verifier.EXPECTED_RELEASE_FILES
        - verifier.EXPECTED_RELEASE_ARCHIVES
        - checksum_files
    ):
        package = name.rsplit("-installer.", 1)[0]
        family_archives = {
            archive for archive in verifier.EXPECTED_BINARY_ARCHIVES
            if archive.startswith(f"{package}-")
        }
        if name.endswith(".sh"):
            blocks = "".join(
                f'        "{archive}")\n'
                '            _checksum_style="sha256"\n'
                f'            _checksum_value="{digests[archive]}"\n'
                "            ;;\n"
                for archive in sorted(family_archives)
            )
            (root / name).write_text(
                f'    case "$_artifact_name" in \n{blocks}'
                "        *)\n"
                "            ;;\n"
                "    esac\n",
                encoding="utf-8",
            )
        elif name.endswith(".ps1"):
            windows_name = next(
                archive
                for archive, target in verifier.EXPECTED_BINARY_TARGETS.items()
                if target == "x86_64-pc-windows-msvc" and archive in family_archives
            )
            blocks = "".join(
                f'    "{target}" = @{{\n'
                f'      "artifact_name" = "{windows_name}"\n'
                f'      "sha256" = "{digests[windows_name]}"\n'
                "    }\n"
                for target in [
                    "aarch64-pc-windows-msvc",
                    "x86_64-pc-windows-gnu",
                    "x86_64-pc-windows-msvc",
                ]
            )
            (root / name).write_text(
                f"$platforms = @{{\n{blocks}  }}\n\n  $arch = Get-TargetTriple\n"
                "  Invoke-DownloadFile -client $wc -url $url -path $dir_path\n"
                '  $expected_sha256 = $info["sha256"]\n'
                "  $observed_sha256 = (Get-FileHash -LiteralPath $dir_path -Algorithm SHA256).Hash.ToLowerInvariant()\n"
                "  if ($observed_sha256 -ne $expected_sha256) {\n"
                '    throw "downloaded archive checksum mismatch"\n'
                "  }\n",
                encoding="utf-8",
            )
        else:
            (root / name).write_bytes(b"control")


class ReleaseArchiveVerifierTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'release publication runs under Bash on Linux')
    def test_release_publication_preserves_arguments_and_stops_on_failure(self) -> None:
        workflow = (Path(__file__).resolve().parent.parent / '.github/workflows/release.yml').read_text()
        self.assertEqual(workflow.count('      - name: Create GitHub Release\n'), 1)
        step = workflow.split('      - name: Create GitHub Release\n')[1].split('\n  announce:')[0]
        script = textwrap.dedent(step.split('        run: |\n')[1])
        stub = 'gh() { printf "%s\\0" "$@" >> "$TEST_GH_ARGS"; return "$TEST_GH_EXIT"; }\n'
        for flag, client_exit, expected_calls in [('', 0, 2), ('--prerelease', 0, 2),
                                                   ('--repo other/repo', 0, 0), ('', 1, 1)]:
            with self.subTest(flag=flag, client_exit=client_exit), self.secure_temporary_directory() as temporary:
                root = Path(temporary).resolve()
                runner_temp = root / 'runner temp [literal]'
                runner_temp.mkdir()
                artifacts = root / 'verified-artifacts'
                artifacts.mkdir()
                (artifacts / 'artifact with spaces.zip').write_bytes(b'fixture')
                recorded = root / 'arguments'
                body = '-n\nLiteral $(touch injected) and `touch injected`\nbackslash \\ text'
                title = 'Title with spaces; $(touch injected)'
                result = subprocess.run(['/bin/bash', '-e', '-c', stub + script], cwd=root,
                    env={'PATH': '/usr/bin:/bin', 'RUNNER_TEMP': str(runner_temp),
                         'TEST_GH_ARGS': str(recorded), 'TEST_GH_EXIT': str(client_exit),
                         'RELEASE_TAG': 'v1.2.3', 'RELEASE_COMMIT': 'a' * 40,
                         'ANNOUNCEMENT_TITLE': title, 'ANNOUNCEMENT_BODY': body,
                         'PRERELEASE_FLAG': flag}, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, expected_calls == 2)
                self.assertEqual((runner_temp / 'notes.txt').read_text(), body + '\n')
                self.assertFalse((root / 'injected').exists())
                arguments = recorded.read_bytes().decode().split('\0')[:-1] if recorded.exists() else []
                expected = ['release', 'create', 'v1.2.3', '--draft', '--target', 'a' * 40,
                            '--title', title, '--notes-file', str(runner_temp / 'notes.txt')]
                if flag == '--prerelease':
                    expected.append(flag)
                expected.append('verified-artifacts/artifact with spaces.zip')
                if expected_calls == 2:
                    expected += ['release', 'edit', 'v1.2.3', '--draft=false']
                self.assertEqual(arguments, expected if expected_calls else [])

    def test_dos_zip_attributes_cannot_hide_nonregular_entries(self) -> None:
        cases = [
            (0, value, True)
            for value in [0, 1, 0x20, 0x21, 0o100644 << 16, (0o100644 << 16) | 1]
        ] + [
            (0, value, False)
            for value in [0x10, 0x08, 0x40, 0x80, 0o120777 << 16, 0o020666 << 16]
        ] + [(11, 0o100644 << 16, False)]
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            for system, attributes, accepted in cases:
                with self.subTest(system=system, attributes=attributes):
                    write_zip(path, COMPANIONS | {"kitrove.exe": b"binary"})
                    content = bytearray(path.read_bytes())
                    for name in COMPANIONS.keys() | {"kitrove.exe"}:
                        offset = central_header_offset(content, name)
                        content[offset + 5] = system
                        struct.pack_into("<I", content, offset + 38, attributes)
                    path.write_bytes(content)
                    if accepted:
                        verifier.validate_archive(path)
                    else:
                        with self.assertRaises(verifier.ArchiveValidationError):
                            verifier.validate_archive(path)

    def test_installer_manifests_bind_family_target_name_and_bytes(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            for name, (stem, binary) in verifier.EXPECTED_BINARY_ARCHIVES.items():
                if not binary.startswith("kitrove-installer"):
                    continue
                path = root / name
                target = verifier.EXPECTED_BINARY_TARGETS[name]
                valid = json.loads(release_manifest(target, b"binary", installer=True))
                mutations = [
                    {}, {"artifact_kind": "application"}, {"executable_name": "kitrove"},
                    {"target": "unknown"}, {"release_version": "1.2.4"},
                    {"executable_sha256": "0" * 64}, {"schema": True},
                    {"application_state_schema": "V1"},
                ]
                for mutation in mutations:
                    with self.subTest(archive=name, mutation=mutation):
                        files = COMPANIONS | {
                            binary: b"binary",
                            verifier.RELEASE_MANIFEST_NAME: json.dumps(valid | mutation).encode(),
                        }
                        if name.endswith(".zip"):
                            write_zip(path, files)
                        else:
                            write_tar(path, files, root_name=stem)
                        if mutation:
                            with self.assertRaises(verifier.ArchiveValidationError):
                                verifier.validate_archive(path, expected_release_version="1.2.3")
                        else:
                            verifier.validate_archive(path, expected_release_version="1.2.3")

    def test_release_policy_rejects_cross_family_aliases_and_missing_targets(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "release/release-policy.json").read_text()
        for family in verifier.RELEASE_FAMILIES:
            for mutation in (
                {"archive": "unrecognized.tar.xz"}, {"executable": "other-product"},
                {"root": "other-root"}, {"target": "unknown"}, {"format": "zip"},
                {"extra": True},
            ):
                policy = json.loads(source)
                policy[family][0].update(mutation)
                with self.subTest(family=family, mutation=mutation):
                    with self.assertRaises(RuntimeError):
                        verifier.parse_application_archive_policy(json.dumps(policy))
            policy = json.loads(source)
            policy[family][0] = policy[family][1]
            with self.assertRaises(RuntimeError):
                verifier.parse_application_archive_policy(json.dumps(policy))

    def test_generated_installers_cannot_cross_product_families(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            write_release_directory(root)
            digests = {
                name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                for name in verifier.EXPECTED_RELEASE_ARCHIVES
            }
            verifier.validate_staged_installers(root, digests)
            for extension in ("sh", "ps1"):
                destination = root / f"kitrove-installer-installer.{extension}"
                original = destination.read_bytes()
                destination.write_bytes((root / f"kitrove-cli-installer.{extension}").read_bytes())
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.validate_staged_installers(root, digests)
                destination.write_bytes(original)

    def test_python_matches_shared_archive_conformance_corpus(self) -> None:
        root = (
            Path(__file__).resolve().parents[1]
            / "crates/kitrove-release-policy/tests/fixtures/archive-conformance"
        )
        cases = json.loads((root / "cases.json").read_text(encoding="ascii"))
        corpus_generator.check_corpus(root)
        self.assertEqual(
            {case["case"] for case in cases},
            corpus_generator.EXPECTED_CASES,
        )
        self.assertEqual(len(cases), len(corpus_generator.EXPECTED_CASES))
        self.assertEqual(len({case["archive"] for case in cases}), len(cases))
        self.require_secure_archive_open()
        for case in cases:
            with self.subTest(case=case["case"]):
                archive = root / case["archive"]
                if case["accepted"]:
                    verifier.validate_archive(archive, expected_sha256=case["sha256"])
                else:
                    with self.assertRaises(verifier.ArchiveValidationError):
                        verifier.validate_archive(archive, expected_sha256=case["sha256"])

    def test_archive_expected_digest_is_checked_on_the_validation_handle(self) -> None:
        self.require_secure_archive_open()
        root = (
            Path(__file__).resolve().parents[1]
            / "crates/kitrove-release-policy/tests/fixtures/archive-conformance/valid_zip"
        )
        archive = root / "kitrove-cli-x86_64-pc-windows-msvc.zip"
        for invalid_digest in ["0" * 64, "A" * 64, "short"]:
            with self.subTest(invalid_digest=invalid_digest):
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.validate_archive(archive, expected_sha256=invalid_digest)

    def test_xz_dictionary_limit_matches_lzma2_properties(self) -> None:
        self.assertEqual(verifier.xz_dictionary_size(28), verifier.MAX_XZ_DICTIONARY_BYTES)
        self.assertGreater(verifier.xz_dictionary_size(29), verifier.MAX_XZ_DICTIONARY_BYTES)
        with self.assertRaises(verifier.ArchiveValidationError):
            verifier.xz_dictionary_size(41)

    def test_unsupported_archive_open_fails_before_filesystem_access(self) -> None:
        with mock.patch.object(verifier, "secure_archive_open_supported", return_value=False):
            with mock.patch.object(verifier.os, "open") as opened:
                with self.assertRaisesRegex(
                    verifier.ArchiveValidationError, "requires no-follow directory handles"
                ):
                    verifier.validate_archive(Path("kitrove-cli-x86_64-pc-windows-msvc.zip"))
                opened.assert_not_called()

    def require_secure_archive_open(self) -> None:
        if not verifier.secure_archive_open_supported():
            self.skipTest("the release verifier requires Unix no-follow directory handles")

    def secure_temporary_directory(self) -> tempfile.TemporaryDirectory[str]:
        self.require_secure_archive_open()
        return tempfile.TemporaryDirectory(dir=Path.cwd())

    def test_accepts_exact_binary_tar_and_zip(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            tar_path = root / "kitrove-cli-aarch64-apple-darwin.tar.xz"
            zip_path = root / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            write_tar(tar_path, COMPANIONS | {"kitrove": b"binary"})
            write_zip(zip_path, COMPANIONS | {"kitrove.exe": b"binary"})

            verifier.validate_archive(tar_path)
            verifier.validate_archive(zip_path)

    def test_release_policy_rejects_boolean_schema_and_duplicate_keys(self) -> None:
        valid = (
            Path(__file__).resolve().parent.parent / "release" / "release-policy.json"
        ).read_text(encoding="utf-8")
        invalid_sources = [
            valid.replace('"schema": 1', '"schema": true'),
            valid.replace('"schema": 1', '"schema": 1, "schema": 1'),
            valid.replace(
                '"target": "aarch64-apple-darwin"',
                '"target": "aarch64-apple-darwin", "target": "aarch64-apple-darwin"',
            ),
        ]
        for source in invalid_sources:
            with self.subTest(source=source[:80]):
                with self.assertRaises(RuntimeError):
                    verifier.parse_application_archive_policy(source)

    def test_accepts_one_versioned_source_root(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "source.tar.gz"
            write_tar(
                path,
                {"README.md": b"source"},
                root_name="kitrove-cli-1.2.3-alpha.1",
                root_mode=0o775,
                mode_overrides={"README.md": 0o664},
            )
            verifier.validate_archive(path)

    def test_rejects_traversal_absolute_drive_and_backslash_paths(self) -> None:
        hostile = ["../escape", "/absolute", "C:/drive", "folder\\escape", "a/./b"]
        for name in hostile:
            with self.subTest(name=name):
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.validate_entries([verifier.ArchiveEntry(name, "file", 1)])

    def test_rejects_non_ascii_names_and_all_unicode_controls(self) -> None:
        for name in ["Straße", "fullwidth-Ａ", "control\u0085name"]:
            with self.subTest(name=name):
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.validate_entries([verifier.ArchiveEntry(name, "file", 1)])

    def test_rejects_every_win32_forbidden_component_character(self) -> None:
        for character in verifier.WINDOWS_FORBIDDEN:
            with self.subTest(character=character):
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.validate_entries(
                        [verifier.ArchiveEntry(f"bad{character}name", "file", 1)]
                    )

    def test_rejects_normalized_win32_device_aliases(self) -> None:
        for name in [
            "CLOCK$", "CONIN$.exe", "CONOUT$", "CON .txt", "COM1 .log",
            "COM¹.txt", "COM²", "COM³.log", "LPT¹", "LPT².txt", "LPT³",
        ]:
            with self.subTest(name=name):
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.validate_entries([verifier.ArchiveEntry(name, "file", 1)])

    def test_rejects_links_and_special_entries(self) -> None:
        for kind in ["symbolic link", "hard link", "special"]:
            with self.subTest(kind=kind):
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.validate_entries([verifier.ArchiveEntry("member", kind, 0)])

    def test_rejects_cross_platform_aliases(self) -> None:
        aliases = [
            ("Readme", "README"),
            ("fullwidth-Ａ", "fullwidth-A"),
            ("Straße", "STRASSE"),
            ("name", "name."),
            ("safe", "NUL.txt"),
        ]
        for first, second in aliases:
            with self.subTest(first=first, second=second):
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.validate_entries(
                        [
                            verifier.ArchiveEntry(first, "file", 1),
                            verifier.ArchiveEntry(second, "file", 1),
                        ]
                    )

    def test_rejects_file_directory_prefix_conflicts_in_either_order(self) -> None:
        for entries in [
            [
                verifier.ArchiveEntry("parent", "file", 1),
                verifier.ArchiveEntry("parent/child", "file", 1),
            ],
            [
                verifier.ArchiveEntry("parent/child", "file", 1),
                verifier.ArchiveEntry("parent", "file", 1),
            ],
        ]:
            with self.subTest(entries=entries):
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.validate_entries(entries)

    def test_rejects_entry_and_aggregate_limits(self) -> None:
        with self.assertRaises(verifier.ArchiveValidationError):
            verifier.validate_entries(
                [verifier.ArchiveEntry("large", "file", verifier.MAX_ENTRY_BYTES + 1)]
            )

        exact_count = [
            verifier.ArchiveEntry(f"entry-{index}", "file", 0)
            for index in range(verifier.MAX_ENTRIES)
        ]
        verifier.validate_entries(exact_count)
        with self.assertRaises(verifier.ArchiveValidationError):
            verifier.validate_entries(
                exact_count + [verifier.ArchiveEntry("one-too-many", "file", 0)]
            )
        with self.assertRaises(verifier.ArchiveValidationError):
            verifier.validate_entries(
                [
                    verifier.ArchiveEntry("one", "file", verifier.MAX_ENTRY_BYTES),
                    verifier.ArchiveEntry("two", "file", verifier.MAX_ENTRY_BYTES),
                    verifier.ArchiveEntry("three", "file", verifier.MAX_ENTRY_BYTES),
                    verifier.ArchiveEntry("four", "file", verifier.MAX_ENTRY_BYTES),
                    verifier.ArchiveEntry("five", "file", 1),
                ]
            )

    def test_rejects_malformed_binary_shape_and_empty_binary(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            extra = root / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            write_zip(extra, COMPANIONS | {"kitrove.exe": b"binary", "extra": b"unexpected"})
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(extra)

            empty = root / "kitrove-cli-aarch64-apple-darwin.tar.xz"
            write_tar(empty, COMPANIONS | {"kitrove": b""})
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(empty)

    def test_release_manifest_size_is_bounded_at_the_shape_boundary(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            for size, accepted in [
                (verifier.MAX_RELEASE_MANIFEST_BYTES, True),
                (verifier.MAX_RELEASE_MANIFEST_BYTES + 1, False),
            ]:
                with self.subTest(size=size):
                    path = root / "kitrove-cli-x86_64-pc-windows-msvc.zip"
                    files = COMPANIONS | {
                        "kitrove.exe": b"binary",
                        verifier.RELEASE_MANIFEST_NAME: b"x" * size,
                    }
                    write_zip(path, files)
                    if accepted:
                        verifier.validate_archive(path)
                    else:
                        with self.assertRaises(verifier.ArchiveValidationError):
                            verifier.validate_archive(path)

    def test_publication_validation_binds_manifest_to_target_version_and_executable(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            path = root / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            target = verifier.EXPECTED_BINARY_TARGETS[path.name]
            for case, manifest in [
                ("valid", release_manifest(target, b"binary")),
                ("target", release_manifest("aarch64-apple-darwin", b"binary")),
                ("version", release_manifest(target, b"binary", "9.9.9")),
                ("executable", release_manifest(target, b"different")),
            ]:
                with self.subTest(case=case):
                    write_zip(
                        path,
                        COMPANIONS
                        | {"kitrove.exe": b"binary", verifier.RELEASE_MANIFEST_NAME: manifest},
                    )
                    if case == "valid":
                        verifier.validate_archive(path, expected_release_version="1.2.3")
                    else:
                        with self.assertRaises(verifier.ArchiveValidationError):
                            verifier.validate_archive(path, expected_release_version="1.2.3")

    def test_rejects_unsafe_binary_tar_permissions(self) -> None:
        cases = [
            (0o755, {"kitrove": 0o4755}),
            (0o777, {}),
            (0o755, {"README.md": 0o755}),
            (0o755, {"README.md": 0o664}),
        ]
        for root_mode, overrides in cases:
            with self.subTest(root_mode=root_mode, overrides=overrides):
                with self.secure_temporary_directory() as temporary:
                    path = Path(temporary) / "kitrove-cli-aarch64-apple-darwin.tar.xz"
                    write_tar(
                        path,
                        COMPANIONS | {"kitrove": b"binary"},
                        root_mode=root_mode,
                        mode_overrides=overrides,
                    )
                    with self.assertRaises(verifier.ArchiveValidationError):
                        verifier.validate_archive(path)

    def test_rejects_application_tar_extensions_and_nonzero_padding(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-aarch64-apple-darwin.tar.xz"
            write_tar(path, COMPANIONS | {"kitrove": b"binary"})
            tar_bytes = bytearray(lzma.decompress(path.read_bytes()))
            tar_bytes[1024 + len(COMPANIONS["README.md"])] = 1
            path.write_bytes(lzma.compress(tar_bytes, check=lzma.CHECK_CRC64))
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(path)

        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-aarch64-apple-darwin.tar.xz"
            write_tar(path, COMPANIONS | {"kitrove": b"binary"})
            extension = tarfile.TarInfo("metadata")
            extension.type = tarfile.XHDTYPE
            body = b"8 key=x\n"
            extension.size = len(body)
            extension_record = (
                extension.tobuf(format=tarfile.GNU_FORMAT)
                + body
                + b"\0" * (512 - len(body))
            )
            valid_application = lzma.decompress(path.read_bytes())
            path.write_bytes(
                lzma.compress(extension_record + valid_application, check=lzma.CHECK_CRC64)
            )
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(path)

            verifier.preflight_tar(
                io.BytesIO(extension_record + b"\0" * 1024),
                strict_application=False,
            )

            source = Path(temporary) / "source.tar.gz"
            write_tar(
                source,
                {"README.md": b"source"},
                root_name="kitrove-cli-1.2.3",
            )
            source_tar = gzip.decompress(source.read_bytes())
            source.write_bytes(gzip.compress(extension_record + source_tar))
            verifier.validate_archive(source)

    def test_accepts_reviewed_bcj_application_xz(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-aarch64-apple-darwin.tar.xz"
            write_tar(path, COMPANIONS | {"kitrove": b"binary"})
            raw = lzma.decompress(path.read_bytes())
            filters = [
                {"id": lzma.FILTER_X86},
                {"id": lzma.FILTER_LZMA2, "dict_size": 1024 * 1024},
            ]
            path.write_bytes(
                lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, filters=filters)
            )
            verifier.validate_archive(path)

    def test_accepts_reviewed_delta_application_xz(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-aarch64-apple-darwin.tar.xz"
            write_tar(path, COMPANIONS | {"kitrove": b"binary"})
            raw = lzma.decompress(path.read_bytes())
            filters = [
                {"id": lzma.FILTER_DELTA, "dist": 1},
                {"id": lzma.FILTER_LZMA2, "dict_size": 1024 * 1024},
            ]
            path.write_bytes(
                lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, filters=filters)
            )
            verifier.validate_archive(path)

    def test_rejects_reserved_zero_xz_block_header_size(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-aarch64-apple-darwin.tar.xz"
            write_tar(path, COMPANIONS | {"kitrove": b"binary"})
            archive = bytearray(path.read_bytes())
            archive[12] = 0
            path.write_bytes(archive)
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(path)

    def test_rejects_legacy_signed_application_tar_checksum(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-aarch64-apple-darwin.tar.xz"
            write_tar(path, COMPANIONS | {"kitrove": b"binary"})
            raw = bytearray(lzma.decompress(path.read_bytes()))
            raw[265] = 0xFF
            raw[148:156] = b" " * 8
            signed = sum(byte if byte < 128 else byte - 256 for byte in raw[:512])
            raw[148:156] = f"{signed:06o}\0 ".encode()
            path.write_bytes(lzma.compress(raw, check=lzma.CHECK_CRC64))
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(path)

    def test_rejects_corrupted_zip_payload(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            write_zip(path, COMPANIONS | {"kitrove.exe": b"A" * 4096})
            corrupt_zip_member(path, "kitrove.exe")
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(path)

    def test_rejects_zip_header_crc_and_size_inconsistencies(self) -> None:
        mutators = [corrupt_zip_crc, corrupt_zip_local_name]
        for mutate in mutators:
            with self.subTest(mutate=mutate.__name__):
                with self.secure_temporary_directory() as temporary:
                    path = Path(temporary) / "kitrove-cli-x86_64-pc-windows-msvc.zip"
                    write_zip(path, COMPANIONS | {"kitrove.exe": b"A" * 4096})
                    mutate(path, "kitrove.exe")
                    with self.assertRaises(verifier.ArchiveValidationError):
                        verifier.validate_archive(path)

        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            write_zip(path, COMPANIONS | {"kitrove.exe": b"A" * 4096})
            forge_zip_expanded_size(path, "kitrove.exe", 1)
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(path)

    def test_rejects_truncated_tar_payload(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "source.tar.gz"
            write_tar(
                path,
                {"payload": b"A" * 4096},
                root_name="kitrove-cli-1.2.3",
            )
            content = path.read_bytes()
            path.write_bytes(content[: len(content) // 2])
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(path)

    def test_rejects_oversized_pax_metadata_before_tar_parser(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "source.tar.gz"
            metadata = tarfile.TarInfo("pax-metadata")
            metadata.type = tarfile.XHDTYPE
            metadata.size = verifier.MAX_TAR_EXTENDED_METADATA_BYTES + 1
            with gzip.open(path, "wb") as archive:
                archive.write(metadata.tobuf(format=tarfile.USTAR_FORMAT))
                archive.write(b"\0" * 1024)
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(path)

    def test_rejects_zip_entry_count_before_zip_parser(self) -> None:
        with self.secure_temporary_directory() as temporary:
            path = Path(temporary) / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
                for index in range(verifier.MAX_ENTRIES + 1):
                    archive.writestr(f"entry-{index}", b"")
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(path)

    def test_rejects_real_tar_and_zip_symlinks(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            tar_path = root / "source.tar.xz"
            zip_path = root / "source.zip"
            write_tar(tar_path, {"file": b"content"}, link="../outside")
            write_zip(zip_path, {"file": b"content"}, symlink=True)
            for path in [tar_path, zip_path]:
                with self.subTest(path=path.name):
                    with self.assertRaises(verifier.ArchiveValidationError):
                        verifier.validate_archive(path)

    def test_rejects_archive_path_symlink(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            archive = root / "source.zip"
            link = root / "linked-source.zip"
            write_zip(archive, {"file": b"content"})
            try:
                link.symlink_to(archive)
            except OSError:
                self.skipTest("the test platform cannot create symbolic links")
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(link)

    def test_rejects_symlinked_containing_directory(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            actual = root / "actual"
            actual.mkdir()
            archive = actual / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            write_zip(archive, COMPANIONS | {"kitrove.exe": b"binary"})
            alias = root / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.validate_archive(alias / archive.name)

    def test_open_handle_is_stable_when_archive_name_is_replaced(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            path = root / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            moved = root / "moved.zip"
            write_zip(path, COMPANIONS | {"kitrove.exe": b"original"})
            with verifier.open_archive_nofollow(path) as (file, _):
                path.rename(moved)
                write_zip(path, COMPANIONS | {"kitrove.exe": b"replacement"})
                with zipfile.ZipFile(file) as archive:
                    self.assertEqual(archive.read("kitrove.exe"), b"original")

    def test_validate_archive_refuses_when_source_name_is_replaced(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            source = root / "kitrove-cli-x86_64-pc-windows-msvc.zip"
            moved = root / "moved.zip"
            staged = root / "staged.zip"
            write_zip(source, COMPANIONS | {"kitrove.exe": b"original"})
            validate_shape = verifier.validate_binary_shape

            def replace_after_verification(path: Path, entries: list[object]) -> None:
                validate_shape(path, entries)
                source.rename(moved)
                write_zip(source, COMPANIONS | {"kitrove.exe": b"replacement"})

            with self.assertRaises(verifier.ArchiveValidationError):
                with mock.patch.object(
                    verifier,
                    "validate_binary_shape",
                    side_effect=replace_after_verification,
                ):
                    verifier.validate_archive(source, staged)

    def test_directory_discovery_rejects_unknown_archive_types(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in verifier.EXPECTED_RELEASE_FILES:
                (root / name).write_bytes(b"placeholder")
            (root / "unexpected.tar.zst").write_bytes(b"not inspected")
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.discover_archives([root])

    def test_directory_discovery_requires_exact_release_archive_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in verifier.EXPECTED_RELEASE_FILES:
                (root / name).write_bytes(b"placeholder")
            self.assertEqual(
                {path.name for path in verifier.discover_archives([root])},
                verifier.EXPECTED_RELEASE_ARCHIVES,
            )

            (root / "kitrove-cli-unknown-target.tar.xz").write_bytes(b"unknown")
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.discover_archives([root])

            (root / "kitrove-cli-unknown-target.tar.xz").unlink()
            (root / "unexpected.dmg").write_bytes(b"unknown")
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.discover_archives([root])

    def test_directory_discovery_rejects_a_missing_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = "kitrove-cli-x86_64-pc-windows-msvc.zip"
            for name in verifier.EXPECTED_RELEASE_FILES - {missing}:
                (root / name).write_bytes(b"placeholder")
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.discover_archives([root])

    def test_complete_host_download_is_staged_without_control_manifests(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            source = root / "artifacts"
            destination = root / "verified-artifacts"
            source.mkdir()
            write_release_directory(source)
            (source / "dist-manifest.json").write_bytes(b"host manifest")
            (source / "linux-dist-manifest.json").write_bytes(b"build manifest")

            archives = verifier.discover_archives([source])
            verifier.stage_release_directory(source, destination, archives, "1.2.3")

            self.assertEqual(
                {path.name for path in destination.iterdir()},
                verifier.EXPECTED_RELEASE_FILES,
            )
            self.assertFalse((destination / "dist-manifest.json").exists())

    def test_staging_rejects_stale_or_misnamed_adjacent_checksums(self) -> None:
        archive_name = "source.tar.gz"
        for case in ["stale", "wrong-name"]:
            with self.subTest(case=case):
                with self.secure_temporary_directory() as temporary:
                    root = Path(temporary)
                    source = root / "artifacts"
                    destination = root / "verified-artifacts"
                    source.mkdir()
                    write_release_directory(source)
                    digest = hashlib.sha256((source / archive_name).read_bytes()).hexdigest()
                    if case == "stale":
                        digest = "0" * 64
                    filename = "wrong.tar.gz" if case == "wrong-name" else archive_name
                    (source / f"{archive_name}.sha256").write_text(
                        f"{digest} *{filename}\n",
                        encoding="ascii",
                    )
                    archives = verifier.discover_archives([source])
                    with self.assertRaises(verifier.ArchiveValidationError):
                        verifier.stage_release_directory(source, destination, archives, "1.2.3")

    def test_staging_rejects_inexact_combined_checksum_set(self) -> None:
        for case in ["missing", "extra", "duplicate", "stale"]:
            with self.subTest(case=case):
                with self.secure_temporary_directory() as temporary:
                    root = Path(temporary)
                    source = root / "artifacts"
                    destination = root / "verified-artifacts"
                    source.mkdir()
                    write_release_directory(source)
                    combined = source / "sha256.sum"
                    lines = combined.read_text(encoding="ascii").splitlines()
                    if case == "missing":
                        lines.pop()
                    elif case == "extra":
                        lines.append(f"{'0' * 64} *extra.tar.xz")
                    elif case == "duplicate":
                        lines.append(lines[0])
                    else:
                        _, filename = lines[0].split(" *", maxsplit=1)
                        lines[0] = f"{'0' * 64} *{filename}"
                    combined.write_text("\n".join(lines) + "\n", encoding="ascii")
                    archives = verifier.discover_archives([source])
                    with self.assertRaises(verifier.ArchiveValidationError):
                        verifier.stage_release_directory(source, destination, archives, "1.2.3")

    def test_staging_rejects_an_installer_with_a_mismatched_target_digest(self) -> None:
        with self.secure_temporary_directory() as temporary:
            root = Path(temporary)
            source = root / "artifacts"
            destination = root / "verified-artifacts"
            source.mkdir()
            write_release_directory(source)
            installer = source / "kitrove-cli-installer.sh"
            installer.write_text(
                installer.read_text(encoding="utf-8").replace(
                    next(iter(verifier.parse_checksum_document(source / "sha256.sum").values())),
                    "0" * 64,
                    1,
                ),
                encoding="utf-8",
            )
            archives = verifier.discover_archives([source])
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.stage_release_directory(source, destination, archives, "1.2.3")

    def test_staging_rejects_extra_shell_and_alternate_powershell_mappings(self) -> None:
        for case in [
            "extra-shell-arm",
            "redirected-powershell-alias",
            "neutralized-powershell-checksum",
            "unreachable-powershell-checksum",
        ]:
            with self.subTest(case=case), self.secure_temporary_directory() as temporary:
                root = Path(temporary)
                source = root / "artifacts"
                destination = root / "verified-artifacts"
                source.mkdir()
                write_release_directory(source)
                if case == "extra-shell-arm":
                    installer = source / "kitrove-cli-installer.sh"
                    installer.write_text(
                        installer.read_text(encoding="utf-8").replace(
                            "    esac\n",
                            '        "unexpected.tar.xz")\n'
                            '            _checksum_style="sha256"\n'
                            f'            _checksum_value="{"0" * 64}"\n'
                            "            ;;\n"
                            "    esac\n",
                        ),
                        encoding="utf-8",
                    )
                elif case == "redirected-powershell-alias":
                    installer = source / "kitrove-cli-installer.ps1"
                    installer.write_text(
                        installer.read_text(encoding="utf-8").replace(
                            '"aarch64-pc-windows-msvc"', '"malicious-windows-target"'
                        ),
                        encoding="utf-8",
                    )
                elif case == "neutralized-powershell-checksum":
                    installer = source / "kitrove-cli-installer.ps1"
                    installer.write_text(
                        installer.read_text(encoding="utf-8").replace(
                            "$observed_sha256 -ne $expected_sha256",
                            "$observed_sha256 -eq $expected_sha256",
                        ),
                        encoding="utf-8",
                    )
                else:
                    installer = source / "kitrove-cli-installer.ps1"
                    installer.write_text(
                        installer.read_text(encoding="utf-8").replace(
                            '  $expected_sha256 = $info["sha256"]',
                            '  return\n  $expected_sha256 = $info["sha256"]',
                        ),
                        encoding="utf-8",
                    )
                archives = verifier.discover_archives([source])
                with self.assertRaises(verifier.ArchiveValidationError):
                    verifier.stage_release_directory(source, destination, archives, "1.2.3")

    def test_checksum_parser_accepts_cargo_dist_terminal_blank_line(self) -> None:
        with self.secure_temporary_directory() as temporary:
            checksum = Path(temporary) / "sha256.sum"
            line = f"{'0' * 64} *archive.tar.xz"
            for terminator in ["\n", "\n\n"]:
                with self.subTest(repr(terminator)):
                    checksum.write_text(line + terminator, encoding="ascii")
                    self.assertEqual(
                        verifier.parse_checksum_document(checksum),
                        {"archive.tar.xz": "0" * 64},
                    )

    def test_checksum_parser_rejects_noncanonical_blank_lines(self) -> None:
        with self.secure_temporary_directory() as temporary:
            checksum = Path(temporary) / "sha256.sum"
            line = f"{'0' * 64} *archive.tar.xz"
            for source in [line + "\n\n\n", line + "\n\n" + line + "\n"]:
                with self.subTest(repr(source)):
                    checksum.write_text(source, encoding="ascii")
                    with self.assertRaises(verifier.ArchiveValidationError):
                        verifier.parse_checksum_document(checksum)


if __name__ == "__main__":
    unittest.main()
