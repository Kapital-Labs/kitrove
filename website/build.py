"""Copy only reviewed public assets to a new deployment directory."""
import argparse
from pathlib import Path
import shutil

ASSETS = ("index.html", "docs/index.html", "styles.css", "app.js", "mark.svg")


def build(destination):
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    build(parser.parse_args().destination)
