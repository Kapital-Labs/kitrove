#!/usr/bin/env python3
"""Stage authenticated, fixed release bytes for an offline RPM build."""

import argparse
from pathlib import Path

from stage_linux import read_payload


def stage(archive, destination):
    payload = read_payload(archive)
    root = Path(destination)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for directory in ("SOURCES", "SPECS", "BUILD", "RPMS", "SRPMS"):
        (root / directory).mkdir(mode=0o700)
    for name in ("kitrove", "LICENSE.md", "LICENSE-MIT", "LICENSE-APACHE"):
        path = root / "SOURCES" / name
        with path.open("xb") as handle:
            handle.write(payload[name])
        path.chmod(0o755 if name == "kitrove" else 0o644)
    spec = Path(__file__).with_name("kitrove-rc.spec").read_bytes()
    with (root / "SPECS" / "kitrove-rc.spec").open("xb") as handle:
        handle.write(spec)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("destination")
    args = parser.parse_args()
    stage(args.archive, args.destination)
