"""Offline publication-boundary tests. Fixtures are not release evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("package_assets", ROOT / "package_assets.py")
ASSETS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSETS)


class PackageAssets(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload"
        self.file = self.payload / "packages/apt/Release"
        self.file.parent.mkdir(parents=True)
        self.file.write_bytes(b"synthetic signed-metadata fixture\n")
        self.entry = {"path": "packages/apt/Release", "sha256": hashlib.sha256(self.file.read_bytes()).hexdigest(), "size": self.file.stat().st_size}
        self.index = self.root / "inventory.json"
        self.write_index([self.entry])
        self.destination = self.root / "site"
        self.destination.mkdir()

    def write_index(self, entries):
        self.index.write_text(json.dumps({"version": 1, "files": entries}))

    def stage(self):
        ASSETS.stage(self.index, self.payload, self.destination)

    def test_exact_bytes_and_no_overwrite(self):
        self.stage()
        self.assertEqual((self.destination / self.entry["path"]).read_bytes(), self.file.read_bytes())
        with self.assertRaises(FileExistsError):
            self.stage()

    def test_extra_missing_tampered_and_symlink_inputs_refused(self):
        self.file.write_bytes(b"different")
        with self.assertRaises(ValueError):
            self.stage()
        self.file.unlink()
        with self.assertRaises(ValueError):
            self.stage()
        external = self.root / "external"
        external.write_bytes(b"fixture")
        self.file.symlink_to(external)
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse((self.destination / "packages").exists())

    def test_extra_file_refused(self):
        (self.payload / "unexpected").write_bytes(b"private fixture")
        with self.assertRaises(ValueError):
            self.stage()

    def test_same_size_digest_mismatch_refused(self):
        self.file.write_bytes(b"x" * self.entry["size"])
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.stage()
        self.assertFalse((self.destination / "packages").exists())

    def test_symlink_directory_and_root_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.payload, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "payload root"):
            ASSETS.stage(self.index, alias, self.destination)
        (self.payload / "linked").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Nonregular"):
            self.stage()

    def test_path_prefix_collision_refused(self):
        self.write_index([self.entry, dict(self.entry, path=self.entry["path"] + "/child")])
        with self.assertRaisesRegex(ValueError, "conflicting"):
            self.stage()

    def test_schema_and_path_refusals(self):
        for path in ("../secret", "/packages/a/b", "packages/../secret", "packages/a//b", "packages/a/./b", "packages/a\\b", "packages/a/%2e", "packages/a/"):
            with self.subTest(path=path):
                self.write_index([dict(self.entry, path=path)])
                with self.assertRaises(ValueError):
                    self.stage()
        for change in ({"size": True}, {"size": 0}, {"sha256": "bad"}, {"unreviewed": "field"}):
            self.write_index([dict(self.entry, **change)])
            with self.assertRaises(ValueError):
                self.stage()
        self.write_index([self.entry, self.entry])
        with self.assertRaises(ValueError):
            self.stage()
        self.index.write_text('{"version":1,"version":1,"files":[]}')
        with self.assertRaises(ValueError):
            self.stage()

    def test_empty_inventory_does_not_enable_publication(self):
        self.write_index([])
        ASSETS.stage(self.index, None, self.destination)
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse((self.destination / "packages").exists())

    def test_missing_payload_directory_refused(self):
        with self.assertRaises(ValueError):
            ASSETS.stage(self.index, None, self.destination)


if __name__ == "__main__":
    unittest.main()
