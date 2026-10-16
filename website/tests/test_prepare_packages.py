"""Offline retrieval tests, using synthetic bytes rather than release evidence."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import urllib.request

SPEC = importlib.util.spec_from_file_location("prepare_packages", Path(__file__).resolve().parents[1] / "prepare_packages.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class PreparePackages(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.metadata = self.root / "metadata"
        self.metadata.mkdir()
        self.destination = self.root / "payload"
        self.data = {name: name.encode() for name in PREPARE.DOWNLOADS}
        self.data["packages/apt/dists/preview/InRelease"] = b"synthetic metadata"
        self.entries = [dict(path=name, size=len(data), sha256=hashlib.sha256(data).hexdigest()) for name, data in self.data.items()]
        for name, data in self.data.items():
            if name not in PREPARE.DOWNLOADS:
                path = self.metadata / name
                path.parent.mkdir(parents=True)
                path.write_bytes(data)
        self.calls = []

    def fetch(self, asset, size):
        self.calls.append((asset, size))
        name = next(name for name, value in PREPARE.DOWNLOADS.items() if value == asset)
        return self.data[name]

    def prepare(self):
        return PREPARE.prepare(self.entries, self.metadata, self.destination, self.fetch)

    def test_exact_bytes_and_no_overwrite(self):
        self.assertTrue(self.prepare())
        self.assertEqual(len(self.calls), 3)
        for name, data in self.data.items():
            self.assertEqual((self.destination / name).read_bytes(), data)
        with self.assertRaises(FileExistsError):
            self.prepare()

    def test_empty_inventory_needs_no_metadata_or_network(self):
        self.assertFalse(PREPARE.prepare([], self.root / "absent", self.destination, self.fetch))
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.calls, [])

    def test_incomplete_inventory_refused_before_download(self):
        self.entries.pop(0)
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.prepare()
        self.assertEqual(self.calls, [])

    def test_extra_missing_and_symlink_metadata_refused(self):
        path = self.metadata / "unexpected"
        path.write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            self.prepare()
        path.unlink()
        metadata = self.metadata / "packages/apt/dists/preview/InRelease"
        metadata.unlink()
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            self.prepare()
        metadata.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(ValueError, "Nonregular"):
            self.prepare()
        self.assertEqual(self.calls, [])

    def test_symlink_metadata_root_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.metadata, target_is_directory=True)
        with self.assertRaises(ValueError):
            PREPARE.prepare(self.entries, alias, self.destination, self.fetch)

    def test_same_size_tampering_and_oversize_refused(self):
        for data in (b"x" * self.entries[0]["size"], b"x" * (self.entries[0]["size"] + 1)):
            destination = self.root / ("case" + str(len(data)))
            with self.assertRaisesRegex(ValueError, "size/digest"):
                PREPARE.prepare(self.entries, self.metadata, destination, lambda asset, size: data)
            self.assertTrue(destination.is_dir())
            self.assertEqual(list(destination.iterdir()), [])

    def test_redirects_remain_https_and_allowlisted(self):
        handler = PREPARE.HTTPSReleaseRedirect()
        request = urllib.request.Request(PREPARE.RELEASE + "fixture")
        for url in ("http://github.com/file", "https://evil.example/file", "https://github.com.evil.example/file", "https://user@github.com/file", "https://github.com:444/file"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "Found", {}, url)
        redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/file")
        self.assertEqual(redirected.full_url, "https://release-assets.githubusercontent.com/file")


if __name__ == "__main__":
    unittest.main()
