from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1] / "winget"


class WingetPins(unittest.TestCase):
    def test_identity_and_version_are_consistent(self):
        files = list(ROOT.glob("*.yaml"))
        self.assertEqual(len(files), 3)
        for path in files:
            text = path.read_text()
            self.assertIn("PackageIdentifier: KapitalLabs.Kitrove.RC\n", text)
            self.assertIn("PackageVersion: 0.1.0-rc.4.2\n", text)
            self.assertIn("ManifestVersion: 1.10.0\n", text)

    def test_installer_is_exact_pinned_portable_archive(self):
        text = (ROOT / "KapitalLabs.Kitrove.RC.installer.yaml").read_text()
        self.assertEqual(text.splitlines()[1:], [
            "PackageIdentifier: KapitalLabs.Kitrove.RC",
            "PackageVersion: 0.1.0-rc.4.2",
            "InstallerType: zip",
            "NestedInstallerType: portable",
            "NestedInstallerFiles:",
            "  - RelativeFilePath: kitrove.exe",
            "    PortableCommandAlias: kitrove",
            "UpgradeBehavior: install",
            "Commands:",
            "  - kitrove",
            "Installers:",
            "  - Architecture: x64",
            "    InstallerUrl: https://github.com/Kapital-Labs/kitrove/releases/download/v0.1.0-rc.4.2/kitrove-cli-x86_64-pc-windows-msvc.zip",
            "    InstallerSha256: B570631B9C08A4CA3065589287B2B713B87D6F9250F41DA165CEAA54AFBA5B45",
            "ManifestType: installer",
            "ManifestVersion: 1.10.0",
        ])


if __name__ == "__main__":
    unittest.main()
