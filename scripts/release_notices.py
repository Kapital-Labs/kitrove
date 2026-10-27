#!/usr/bin/env python3
"""Reproduce checked-in release notices; never extract or execute crate content."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
MAX_CRATE_BYTES = 64 * 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
PREFIXES = ("license", "copying", "copyright", "notice", "authors")
SHA256 = re.compile(r"[0-9a-f]{64}")


def regular_bytes(path: Path, maximum: int) -> bytes:
    # Inputs are local build prerequisites, not portable state. Refuse links and
    # special files; registry bytes are authenticated before archive decoding.
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("notice input must be a bounded regular file")
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("notice input identity changed")
        content = source.read(maximum + 1)
    after = path.lstat()
    if len(content) > maximum or (before.st_dev, before.st_ino, before.st_size,
                                  before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("notice input changed")
    return content


def safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or "\\" in value or
            any(part in ("", ".", "..") for part in value.split("/")) or
            any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("unsafe notice source path")
    return path


def is_material(path: PurePosixPath) -> bool:
    return (path.name.lower().startswith(PREFIXES) or
            any(part.lower() in ("licenses", "licences") for part in path.parts[:-1]))


def registry_materials(package: dict, locked: list) -> dict[str, bytes]:
    name, version, source = (package[key] for key in ("name", "version", "source"))
    matches = [p for p in locked if (p.get("name"), p.get("version"), p.get("source"))
               == (name, version, source)]
    if len(matches) != 1 or not SHA256.fullmatch(matches[0].get("checksum", "")):
        raise ValueError("missing unique locked crate checksum")
    directory = Path(package["manifest_path"]).parent
    if directory.name != f"{name}-{version}" or directory.parent.parent.name != "src":
        raise ValueError("unsupported Cargo registry layout")
    archive = directory.parent.parent.parent / "cache" / directory.parent.name / (directory.name + ".crate")
    content = regular_bytes(archive, MAX_CRATE_BYTES)
    if hashlib.sha256(content).hexdigest() != matches[0]["checksum"]:
        raise ValueError("crate checksum mismatch")
    materials = {}
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(content), mode="r|gz") as crate:
        for number, member in enumerate(crate):
            expanded += member.size
            if number >= 100_000 or expanded > 512 * 1024 * 1024:
                raise ValueError("crate exceeds notice inspection bounds")
            path = safe_relative(member.name)
            if path.parts[0] != directory.name:
                raise ValueError("crate root does not match its package")
            relative = PurePosixPath(*path.parts[1:])
            if not is_material(relative) or member.isdir():
                continue
            if not member.isfile() or not 0 < member.size <= MAX_TEXT_BYTES:
                raise ValueError("license material must be a nonempty bounded regular file")
            key = relative.as_posix()
            if key in materials:
                raise ValueError("duplicate crate notice material")
            leaf = crate.extractfile(member)
            if leaf is None:
                raise ValueError("missing crate notice bytes")
            materials[key] = leaf.read(MAX_TEXT_BYTES + 1)
    return materials


def vendored_materials(package: dict, root: Path) -> dict[str, bytes]:
    directory = Path(package["manifest_path"]).parent
    expected = root / "third_party" / package["name"]
    if directory != expected or directory.is_symlink():
        raise ValueError("unreviewed local third-party source")
    materials = {}
    for parent, directories, files in os.walk(directory, followlinks=False):
        for name in directories:
            if (Path(parent) / name).is_symlink():
                raise ValueError("vendored notice tree contains a link")
        for name in sorted(files):
            path = Path(parent) / name
            relative = path.relative_to(directory).as_posix()
            if is_material(safe_relative(relative)):
                materials[relative] = regular_bytes(path, MAX_TEXT_BYTES)
    return materials


def render_documents(inputs: dict, root: Path) -> dict[str, bytes]:
    metadata = inputs["metadata"]
    members = set(metadata["workspace_members"])
    packages = sorted((p for p in metadata["packages"] if p["id"] not in members),
                      key=lambda p: (p["name"], p["version"]))
    rows = [(p["name"], p["version"], p["license"]) for p in packages]
    if len({row[:2] for row in rows}) != len(rows):
        raise ValueError("ambiguous package identity in notice inventory")
    expected = ("package\tversion\tlicense\n" +
                "".join("\t".join(row) + "\n" for row in rows) +
                f"dependency license checks passed ({len(rows)} third-party packages inspected)\n")
    if inputs["inventory"] != expected:
        raise ValueError("inventory does not match the reviewed metadata graph")
    supplement_root = root / "release/license-supplements"
    supplements = json.loads(regular_bytes(supplement_root / "index.json", MAX_TEXT_BYTES))
    supplemental = {}
    for item in supplements:
        if set(item) != {"name", "version", "files", "provenance"}:
            raise ValueError("invalid notice supplement")
        key = (item["name"], item["version"])
        if key in supplemental or key not in {row[:2] for row in rows}:
            raise ValueError("duplicate or stale notice supplement")
        supplemental[key] = item
    used = set()
    texts = {}
    text_bytes = 0
    output = bytearray(b"Third-party license and attribution material\n"
                       b"Complete locked graph, including build/test/platform-only packages.\n"
                       b"Text IDs are SHA-256 of exact source bytes; identical text is stored once.\n\n")
    for package in packages:
        key = (package["name"], package["version"])
        output.extend((f"Package: {key[0]} {key[1]}\nDeclared license: {package['license']}\n").encode())
        if package["source"] is None:
            materials = vendored_materials(package, root)
            output.extend((f"Source: tracked third_party/{key[0]}\n").encode())
        elif package["source"].startswith("registry+"):
            materials = registry_materials(package, inputs["lock_packages"])
            locked = next(p for p in inputs["lock_packages"] if
                          (p.get("name"), p.get("version"), p.get("source")) ==
                          (key[0], key[1], package["source"]))
            output.extend((f"Source: {package['source']}\nCrate SHA-256: {locked['checksum']}\n").encode())
        else:
            raise ValueError("unsupported third-party notice source")
        if key in supplemental:
            item = supplemental[key]
            used.add(key)
            if not item["provenance"] or not item["files"]:
                raise ValueError("missing supplement provenance or material")
            for leaf in item["files"]:
                if set(leaf) != {"path", "sha256", "url"}:
                    raise ValueError("invalid supplement file")
                path = safe_relative(leaf["path"])
                url = leaf["url"]
                if not re.fullmatch(r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/[^\s]+", url):
                    raise ValueError("supplement requires a source-revision-bound URL")
                content = regular_bytes(supplement_root / path, MAX_TEXT_BYTES)
                if not SHA256.fullmatch(leaf["sha256"]) or hashlib.sha256(content).hexdigest() != leaf["sha256"]:
                    raise ValueError("supplement checksum mismatch")
                materials["supplement:" + path.as_posix()] = content
                output.extend((f"Supplement source: {url}\n").encode())
            output.extend((f"Supplement provenance: {item['provenance']}\n").encode())
        if not materials:
            raise ValueError(f"missing license material for {key[0]} {key[1]}")
        for path, content in sorted(materials.items()):
            if not content:
                raise ValueError("empty license material")
            content.decode("utf-8")  # Refuse lossy decoding, do not normalize license text.
            digest = hashlib.sha256(content).hexdigest()
            if digest not in texts:
                text_bytes += len(content)
                if text_bytes > MAX_BUNDLE_BYTES:
                    raise ValueError("license bundle exceeds its bound")
            texts[digest] = content
            output.extend((f"  SHA-256:{digest}\t{path}\n").encode())
        output.extend(b"\n")
    if used != set(supplemental):
        raise ValueError("unused notice supplement")
    for digest, content in sorted(texts.items()):
        output.extend((f"===== TEXT SHA-256:{digest} ({len(content)} bytes) =====\n").encode())
        output.extend(content)
        output.extend(b"\n===== END TEXT =====\n\n")
    if len(output) > MAX_BUNDLE_BYTES:
        raise ValueError("license bundle exceeds its bound")
    return {"THIRD_PARTY_LICENSE_INVENTORY.txt": expected.encode(),
            "THIRD_PARTY_LICENSES.txt": bytes(output)}


def persist_documents(documents: dict[str, bytes], root: Path, *, check: bool) -> None:
    if set(documents) - {"THIRD_PARTY_LICENSE_INVENTORY.txt", "THIRD_PARTY_LICENSES.txt"}:
        raise ValueError("unknown generated notice output")
    for name, content in documents.items():
        path = root / "release" / name
        if check:
            if regular_bytes(path, MAX_BUNDLE_BYTES) != content:
                raise ValueError("stale release notice document: " + name)
        else:
            if path.is_symlink() or (path.exists() and
                                    (not path.is_file() or path.stat().st_nlink != 1)):
                raise ValueError("refuse nonregular or aliased generated output")
            path.write_bytes(content)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    arguments = parser.parse_args()
    cargo = os.environ.get("CARGO", "cargo")
    result = subprocess.run([cargo, "xtask", "license-inputs"], cwd=ROOT,
                            capture_output=True, check=True, timeout=600,
                            env={**os.environ, "CARGO_NET_OFFLINE": "true"})
    documents = render_documents(json.loads(result.stdout), ROOT)
    persist_documents(documents, ROOT, check=arguments.check)
    print("release notice documents match the reviewed locked graph")


if __name__ == "__main__":
    main()
