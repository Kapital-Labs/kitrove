"""Stage reviewed, hash-pinned package assets without downloading or signing."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


def inventory(path):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate inventory key")
            result[key] = value
        return result

    document = json.loads(Path(path).read_text(), object_pairs_hook=unique_object)
    if not isinstance(document, dict) or set(document) != {"version", "files"}:
        raise ValueError("Invalid package inventory")
    if type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("Unsupported package inventory version")
    files = document["files"]
    if not isinstance(files, list):
        raise ValueError("Invalid package file list")
    seen = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise ValueError("Invalid package entry")
        name = entry["path"]
        if not isinstance(name, str) or not re.fullmatch(r"packages/[A-Za-z0-9_./+~-]+", name):
            raise ValueError("Invalid package path")
        parts = name.split("/")
        if any(part in ("", ".", "..") for part in parts) or len(parts) < 3:
            raise ValueError("Noncanonical package path")
        if name in seen or any(name.startswith(old + "/") or old.startswith(name + "/") for old in seen):
            raise ValueError("Duplicate or conflicting package path")
        seen.add(name)
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("Invalid package digest")
        if type(entry["size"]) is not int or not 0 < entry["size"] <= 100_000_000:
            raise ValueError("Invalid package size")
    if sum(entry["size"] for entry in files) > 500_000_000:
        raise ValueError("Package inventory exceeds deployment budget")
    return files


def stage(inventory_path, payload_root, destination):
    files = inventory(inventory_path)
    if not files:
        if payload_root is not None:
            raise ValueError("No package payloads have been approved")
        return
    if payload_root is None:
        raise ValueError("Reviewed package payload directory is required")
    root = Path(payload_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid payload root")
    # Check the entire input tree before publishing any package bytes.
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("Nonregular payload entry")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != {entry["path"] for entry in files}:
        raise ValueError("Payload inventory mismatch")
    verified = []
    for entry in files:
        path = root.joinpath(*PurePosixPath(entry["path"]).parts)
        if path.stat().st_size != entry["size"]:
            raise ValueError("Package size mismatch")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Package digest mismatch")
        verified.append((entry["path"], data))
    output = Path(destination) / "packages"
    output.mkdir(exist_ok=False)
    for name, data in verified:
        target = Path(destination).joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Write the verified bytes rather than reopening a mutable input path.
        with target.open("xb") as stream:
            stream.write(data)
