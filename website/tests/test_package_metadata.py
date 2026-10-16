"""Synthetic timestamp refusal cases, not native repository acceptance."""
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("verify_package_metadata", Path(__file__).resolve().parents[1] / "verify_package_metadata.py")
METADATA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(METADATA)


class MetadataFreshness(unittest.TestCase):
    now = datetime(2026, 10, 16, tzinfo=timezone.utc)

    def apt(self, issued, expires):
        return f"Date: {format_datetime(issued)}\nValid-Until: {format_datetime(expires)}\n".encode()

    def rpm(self, timestamp):
        return f'<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><timestamp>{timestamp}</timestamp></data></repomd>'.encode()

    def test_current_metadata(self):
        METADATA.apt_freshness(self.apt(self.now, self.now + timedelta(days=7)), self.now)
        METADATA.rpm_freshness(self.rpm(int(self.now.timestamp())), self.now)

    def test_apt_expiry_future_long_validity_and_reverse_refused(self):
        for issued, expires in ((self.now - timedelta(days=7), self.now),
                                (self.now + timedelta(seconds=1), self.now + timedelta(days=1)),
                                (self.now, self.now + timedelta(days=8)),
                                (self.now, self.now - timedelta(seconds=1))):
            with self.subTest(issued=issued, expires=expires), self.assertRaises(ValueError):
                METADATA.apt_freshness(self.apt(issued, expires), self.now)

    def test_missing_duplicate_naive_or_malformed_dates_refused(self):
        valid = self.apt(self.now, self.now + timedelta(days=1))
        for data in (b"", valid + b"Date: nonsense\n", b"Date: nonsense\nValid-Until: nonsense\n",
                     self.apt(self.now.replace(tzinfo=None), self.now.replace(tzinfo=None) + timedelta(days=1))):
            with self.subTest(data=data), self.assertRaises(ValueError):
                METADATA.apt_freshness(data, self.now)

    def test_rpm_expiry_future_missing_and_duplicate_refused(self):
        for timestamp in (int((self.now - timedelta(days=7)).timestamp()), int(self.now.timestamp()) + 1, "bad", ""):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                METADATA.rpm_freshness(self.rpm(timestamp), self.now)
        valid = self.rpm(int(self.now.timestamp()))
        duplicate = valid.replace(b"</timestamp>", b"</timestamp><timestamp>1</timestamp>")
        for data in (b"<repomd/>", duplicate):
            with self.assertRaises(ValueError):
                METADATA.rpm_freshness(data, self.now)

    def test_unreviewed_key_refused_before_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "packages/keys/kitrove-packages.asc"
            key.parent.mkdir(parents=True)
            key.write_bytes(b"not the reviewed public key")
            with self.assertRaisesRegex(ValueError, "Unreviewed"):
                METADATA.verify(root, self.now)


if __name__ == "__main__":
    unittest.main()
