"""Fetch pinned public package bytes and combine them with reviewed metadata."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import urllib.parse
import urllib.request

SOURCE = Path(__file__).resolve().parent
RELEASE = "https://github.com/Kapital-Labs/kitrove/releases/download/linux-packages-rc42-1/"
DOWNLOADS = {
    "packages/apt/pool/main/k/kitrove-rc/kitrove-rc_0.1.0.rc.4.2-1_amd64.deb": "kitrove-rc_0.1.0.rc.4.2-1_amd64.deb",
    "packages/rpm/Packages/kitrove-rc-0.1.0.rc.4.2-1.x86_64.rpm": "kitrove-rc-0.1.0.rc.4.2-1.x86_64.rpm",
    "packages/keys/kitrove-packages.asc": "kitrove-packages.asc",
}


class HTTPSReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != "https" or parsed.hostname not in
                {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
                or parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise ValueError("Unexpected package redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(asset, limit):
    opener = urllib.request.build_opener(HTTPSReleaseRedirect())
    with opener.open(RELEASE + asset, timeout=30) as response:
        return response.read(limit + 1)


def prepare(entries, metadata_root, destination, fetch=download):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    if not entries:
        return False
    expected = {entry["path"] for entry in entries}
    if not set(DOWNLOADS).issubset(expected):
        raise ValueError("Incomplete reviewed release inventory")
    metadata_root = Path(metadata_root)
    if metadata_root.is_symlink() or not metadata_root.is_dir():
        raise ValueError("Reviewed metadata directory is required")
    local_files = set()
    for path in metadata_root.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("Nonregular metadata entry")
        if path.is_file():
            local_files.add(path.relative_to(metadata_root).as_posix())
    if local_files != expected - set(DOWNLOADS):
        raise ValueError("Metadata inventory mismatch")
    destination.mkdir(parents=True, exist_ok=False)
    for entry in entries:
        name, size = entry["path"], entry["size"]
        if name in DOWNLOADS:
            data = fetch(DOWNLOADS[name], size)
        else:
            with (metadata_root / name).open("rb") as stream:
                data = stream.read(size + 1)
        if len(data) != size or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Package input does not match reviewed size/digest")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("package_assets", SOURCE / "package_assets.py")
    assets = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(assets)
    if prepare(assets.inventory(SOURCE / "package_inventory.json"), SOURCE / "package_metadata", args.destination):
        from verify_package_metadata import verify
        verify(args.destination)
