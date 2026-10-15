"""Copy only reviewed public assets to a new deployment directory."""
import argparse
import importlib.util
from pathlib import Path
import shutil

ASSETS = ("index.html", "docs/index.html", "styles.css", "app.js", "mark.svg")


def build(destination, package_payloads=None):
    source = Path(__file__).resolve().parent
    destination = Path(destination)
    # Refuse reuse so a previous deployment cannot contribute stale files.
    destination.mkdir(parents=True, exist_ok=False)
    for name in ASSETS:
        origin = source / name
        if origin.is_symlink() or not origin.is_file():
            raise ValueError(f"Not a regular site asset: {name}")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, target)
    (destination / "CNAME").write_text("kitrove.dev\n")
    (destination / ".nojekyll").write_text("")
    spec = importlib.util.spec_from_file_location("package_assets", source / "package_assets.py")
    package_assets = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package_assets)
    package_assets.stage(source / "package_inventory.json", package_payloads, destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--package-payloads", type=Path)
    args = parser.parse_args()
    build(args.destination, args.package_payloads)
