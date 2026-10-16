"""Verify repository signatures and freshness before deployment, without secrets."""
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

PUBLIC_KEY_SHA256 = "5ac38737296e75cbabef85ab16de742a9dcf5abb487932f3f2adee4cf8a8aa07"
PRIMARY_FINGERPRINT = "0C0E4DE98C93CD1059995A3974386FFE8762A9E1"
APT = "packages/apt/dists/preview"
RPM = "packages/rpm/repodata"
MAX_AGE = timedelta(days=7)


def apt_freshness(data, now):
    fields = {}
    for line in data.decode("utf-8").splitlines():
        if line.startswith(("Date:", "Valid-Until:")):
            name, value = line.split(":", 1)
            if name in fields:
                raise ValueError("Duplicate APT date field")
            try:
                fields[name] = parsedate_to_datetime(value.strip())
            except (TypeError, ValueError) as error:
                raise ValueError("Invalid APT timestamp") from error
    if set(fields) != {"Date", "Valid-Until"}:
        raise ValueError("APT metadata requires Date and Valid-Until")
    issued, expires = fields["Date"], fields["Valid-Until"]
    if issued.tzinfo is None or expires.tzinfo is None:
        raise ValueError("APT timestamps must include timezone")
    if not issued <= now < expires or not timedelta(0) < expires - issued <= MAX_AGE:
        raise ValueError("APT metadata expired, future dated, or validity exceeds seven days")


def rpm_freshness(data, now):
    root = ET.fromstring(data)
    namespace = "{http://linux.duke.edu/metadata/repo}"
    records = root.findall(namespace + "data")
    if root.tag != namespace + "repomd" or not records:
        raise ValueError("Invalid RPM metadata inventory")
    for record in records:
        timestamps = record.findall(namespace + "timestamp")
        if len(timestamps) != 1 or not (timestamps[0].text or "").isdigit():
            raise ValueError("Invalid RPM metadata timestamp")
        issued = datetime.fromtimestamp(int(timestamps[0].text), timezone.utc)
        if not issued <= now < issued + MAX_AGE:
            raise ValueError("RPM metadata expired or future dated")


def verify(root, now=None):
    root = Path(root)
    now = now or datetime.now(timezone.utc)
    key = (root / "packages/keys/kitrove-packages.asc").read_bytes()
    if hashlib.sha256(key).hexdigest() != PUBLIC_KEY_SHA256:
        raise ValueError("Unreviewed package signing key")
    with tempfile.TemporaryDirectory(prefix="kitrove-public-key-") as temporary:
        home = Path(temporary)
        keyring = home / "keyring.gpg"
        subprocess.run(["gpg", "--batch", "--no-options", "--homedir", str(home),
                        "--output", str(keyring), "--dearmor"], input=key, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

        def signature(arguments):
            result = subprocess.run(["gpgv", "--homedir", str(home), "--keyring", str(keyring),
                                     "--status-fd", "1", *map(str, arguments)], check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            valid = [line.split() for line in result.stdout.decode("ascii").splitlines()
                     if line.startswith("[GNUPG:] VALIDSIG ")]
            if len(valid) != 1 or valid[0][-1] != PRIMARY_FINGERPRINT:
                raise ValueError("Unexpected repository signature identity")

        plaintext = home / "Release"
        signature([root / APT / "InRelease"])
        # gpgv verifies clearsigned input but does not extract its plaintext.
        subprocess.run(["gpg", "--batch", "--no-options", "--homedir", str(home),
                        "--no-default-keyring", "--keyring", str(keyring),
                        "--no-auto-key-retrieve", "--no-auto-key-import",
                        "--output", str(plaintext), "--decrypt", str(root / APT / "InRelease")],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        release = (root / APT / "Release").read_bytes()
        if plaintext.read_bytes() != release:
            raise ValueError("APT signed representations differ")
        signature([root / APT / "Release.gpg", root / APT / "Release"])
        signature([root / RPM / "repomd.xml.asc", root / RPM / "repomd.xml"])
        apt_freshness(release, now)
        rpm_freshness((root / RPM / "repomd.xml").read_bytes(), now)
