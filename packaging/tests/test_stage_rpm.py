import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGING = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGING))
SPEC = importlib.util.spec_from_file_location("stage_rpm", PACKAGING / "stage_rpm.py")
stage_rpm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage_rpm)


class RpmTests(unittest.TestCase):
    def test_exact_sources_and_no_overwrite(self):
        payload = {name: b"inert fixture" for name in
                   ("kitrove", "LICENSE.md", "LICENSE-MIT", "LICENSE-APACHE")}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rpm"
            with patch.object(stage_rpm, "read_payload", return_value=payload):
                stage_rpm.stage("unused", root)
                with self.assertRaises(FileExistsError):
                    stage_rpm.stage("unused", root)
            self.assertEqual({p.name for p in (root / "SOURCES").iterdir()}, set(payload))
            self.assertEqual((root / "SOURCES/kitrove").read_bytes(), b"inert fixture")
            self.assertEqual((root / "SOURCES/kitrove").stat().st_mode & 0o777, 0o755)

    def test_failed_authentication_creates_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rpm"
            with patch.object(stage_rpm, "read_payload", side_effect=ValueError("digest")):
                with self.assertRaises(ValueError):
                    stage_rpm.stage("unused", root)
            self.assertFalse(root.exists())

    def test_frozen_spec_has_no_runtime_scripts(self):
        spec = (PACKAGING / "kitrove-rc.spec").read_text()
        self.assertIn("Version: 0.1.0~rc.4.2\n", spec)
        self.assertIn("ExclusiveArch: x86_64\n", spec)
        self.assertIn("f9079cf2f0d280b92f6ce50846d5d05c6440dcd56b8efe688b252df35c33df3f", spec)
        directives = {line.split()[0] for line in spec.splitlines() if line.startswith("%")}
        self.assertEqual(directives, {"%global", "%description", "%prep", "%build",
                                     "%install", "%check", "%files", "%license",
                                     "%{_bindir}/kitrove"})


if __name__ == "__main__":
    unittest.main()
