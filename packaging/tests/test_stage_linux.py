import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "stage_linux", Path(__file__).resolve().parents[1] / "stage_linux.py"
)
stage_linux = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage_linux)


class StageTests(unittest.TestCase):
    def archive(self, root, extra=None):
        archive = root / "fixture.tar.xz"
        with tarfile.open(archive, "w:xz") as bundle:
            for name in sorted(stage_linux.FILES):
                content = b"{}" if name.endswith(".json") else b"synthetic inert fixture"
                member = tarfile.TarInfo(stage_linux.PREFIX + "/" + name)
                member.size = len(content)
                member.mode = 0o755 if name == "kitrove" else 0o644
                bundle.addfile(member, io.BytesIO(content))
            if extra:
                bundle.addfile(extra)
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def test_fixed_production_pin(self):
        self.assertEqual(stage_linux.ARCHIVE_SHA256,
                         "49af3ff56c4614cd7ed1fae2aee6e32fcca520f228d2c2585b3e6bae7776db3c")

    def test_exact_inventory_modes_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, digest = self.archive(root)
            output = root / "package"
            with patch.object(stage_linux, "ARCHIVE_SHA256", digest):
                stage_linux.stage(archive, output)
                with self.assertRaises(FileExistsError):
                    stage_linux.stage(archive, output)
            files = {str(p.relative_to(output)) for p in output.rglob("*") if p.is_file()}
            self.assertEqual(files, {
                "DEBIAN/control", "usr/bin/kitrove",
                "usr/share/doc/kitrove-rc/LICENSE.md",
                "usr/share/doc/kitrove-rc/LICENSE-MIT",
                "usr/share/doc/kitrove-rc/LICENSE-APACHE",
            })
            self.assertEqual((output / "usr/bin/kitrove").stat().st_mode & 0o777, 0o755)
            self.assertEqual((output / "DEBIAN/control").stat().st_mode & 0o777, 0o644)
            self.assertEqual((output / "usr/bin/kitrove").read_bytes(), b"synthetic inert fixture")

    def test_bad_digest_creates_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, _ = self.archive(root)
            with self.assertRaisesRegex(ValueError, "digest"):
                stage_linux.stage(archive, root / "package")
            self.assertFalse((root / "package").exists())

    def test_links_and_extra_members_refused(self):
        for name, kind in [("../escape", tarfile.REGTYPE),
                           (stage_linux.PREFIX + "/kitrove", tarfile.SYMTYPE),
                           (stage_linux.PREFIX + "/extra", tarfile.REGTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = "/etc/passwd"
                archive, digest = self.archive(root, member)
                with patch.object(stage_linux, "ARCHIVE_SHA256", digest):
                    with self.assertRaises(ValueError):
                        stage_linux.stage(archive, root / "package")
                self.assertFalse((root / "package").exists())


if __name__ == "__main__":
    unittest.main()
