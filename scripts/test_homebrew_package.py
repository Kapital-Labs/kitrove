"""Freeze the initial tap candidate's pins and non-executing package surface.

This is a review tripwire, not a Ruby sandbox or artifact authenticator. Homebrew
parsing and native installation acceptance are separate operator checks.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CASK = ROOT / "release/homebrew/Casks/kitrove-rc.rb"


class HomebrewPackageTests(unittest.TestCase):
    def test_only_reviewed_declarative_package_surface(self):
        expected = '''cask "kitrove-rc" do
  version "0.1.0-rc.3"
  sha256 "49229e4d6c0eee3f7f711c42b50274a24a29dfa90768b1cedbed21e16b44b28e"

  url "https://github.com/Kapital-Labs/kitrove/releases/download/v#{version}/kitrove-cli-aarch64-apple-darwin.tar.xz"
  name "Kitrove Release Candidate"
  desc "Portable agent environment management"
  homepage "https://github.com/Kapital-Labs/kitrove"

  livecheck do
    skip "Release candidates require reviewed provenance and native acceptance"
  end

  depends_on arch: :arm64
  depends_on :macos

  binary "kitrove-cli-aarch64-apple-darwin/kitrove"

  caveats <<~EOS
    This is a prerelease. Homebrew manages this executable, not your Kitrove state.
    Do not point kitrove-installer at this Homebrew-managed installation.
    Clean-Mac offline first launch remains unverified.
  EOS
end
'''
        self.assertEqual(CASK.read_text(encoding="utf-8"), expected)

    def test_no_additional_package_definitions(self):
        files = sorted(path.relative_to(CASK.parent.parent).as_posix()
                       for path in CASK.parent.parent.rglob("*") if path.is_file())
        self.assertEqual(files, ["Casks/kitrove-rc.rb", "README.md"])


if __name__ == "__main__":
    unittest.main()
