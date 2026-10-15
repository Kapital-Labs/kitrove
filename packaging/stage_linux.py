#!/usr/bin/env python3
"""Stage fixed release bytes, without downloading or executing product code."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile


ARCHIVE_SHA256 = "49af3ff56c4614cd7ed1fae2aee6e32fcca520f228d2c2585b3e6bae7776db3c"
PREFIX = "kitrove-cli-x86_64-unknown-linux-gnu"
FILES = {
    "README.md", "CHANGELOG.md", "LICENSE.md", "LICENSE-MIT",
    "LICENSE-APACHE", "kitrove-release.json", "kitrove",
}
MAX_ARCHIVE = 100 * 1024 * 1024
MAX_MEMBER = 100 * 1024 * 1024
CONTROL = """Package: kitrove-rc
Version: 0.1.0~rc.4.2-1
Section: utils
Priority: optional
Architecture: amd64
Depends: libc6 (>= 2.34), libgcc-s1
Maintainer: Brandon Kaplan <Bkaplan31@gmail.com>
Homepage: https://kitrove.dev/
Description: Portable AI tool configuration and skills (release candidate)
 Manage selected skills and configuration across tools and computers.
 This experimental package owns the CLI only and preserves application data.
"""


def read_payload(archive):
    """Validate the pinned archive before creating any output files."""
    with Path(archive).open("rb") as handle:
        data = handle.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError("archive exceeds size limit")
    if hashlib.sha256(data).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("archive digest does not match reviewed RC4.2 pin")
    payload = {}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as bundle:
        for member in bundle:
            if member.name in seen:
                raise ValueError("duplicate archive member")
            seen.add(member.name)
            if member.name == PREFIX:
                if not member.isdir():
                    raise ValueError("archive root must be a directory")
                continue
            name = member.name.removeprefix(PREFIX + "/")
            if member.name != PREFIX + "/" + name or name not in FILES:
                raise ValueError("unexpected archive member")
            if not member.isfile() or member.size > MAX_MEMBER:
                raise ValueError("archive member is not a bounded regular file")
            if member.mode & 0o7000:
                raise ValueError("special file modes are forbidden")
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError("missing archive member bytes")
            payload[name] = stream.read(MAX_MEMBER + 1)
            if len(payload[name]) != member.size:
                raise ValueError("archive member length mismatch")
    if set(payload) != FILES:
        raise ValueError("incomplete archive inventory")
    # The digest pins metadata too; parsing catches accidental format assumptions.
    json.loads(payload["kitrove-release.json"])
    return payload


def stage(archive, destination):
    payload = read_payload(archive)
    root = Path(destination)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Preserve partial output on failure. A retry requires a fresh destination.
    leaves = {
        "DEBIAN/control": CONTROL.encode(),
        "usr/bin/kitrove": payload["kitrove"],
        "usr/share/doc/kitrove-rc/LICENSE.md": payload["LICENSE.md"],
        "usr/share/doc/kitrove-rc/LICENSE-MIT": payload["LICENSE-MIT"],
        "usr/share/doc/kitrove-rc/LICENSE-APACHE": payload["LICENSE-APACHE"],
    }
    for relative, content in leaves.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(content)
        path.chmod(0o755 if relative == "usr/bin/kitrove" else 0o644)
    for directory, _, _ in os.walk(root):
        Path(directory).chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("destination")
    arguments = parser.parse_args()
    stage(arguments.archive, arguments.destination)
