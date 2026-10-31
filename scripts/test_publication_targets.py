"""Current publication selection is narrower than historical archive recognition."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hosted_apple_signing as signing
import verify_release_archives as verifier
from test_verify_release_archives import write_release_directory

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ['aarch64-apple-darwin', 'x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc']


class PublicationTargetsTests(unittest.TestCase):
    def test_current_policy_selects_exactly_three_targets(self):
        policy=json.loads((ROOT/'release/release-policy.json').read_text())
        self.assertEqual(policy.get('publication_targets'),TARGETS)

    def test_complete_publication_inventory_excludes_intel_but_single_archive_recognition_survives(self):
        self.assertEqual(len(verifier.EXPECTED_RELEASE_ARCHIVES),7)
        self.assertEqual(len(verifier.EXPECTED_RELEASE_ARTIFACTS),8)
        self.assertEqual(len(verifier.EXPECTED_RELEASE_FILES),21)
        self.assertFalse(any('x86_64-apple-darwin' in name for name in verifier.EXPECTED_RELEASE_FILES))
        self.assertIn('kitrove-cli-x86_64-apple-darwin.tar.xz',verifier.EXPECTED_BINARY_ARCHIVES)
        self.assertIn('kitrove-installer-x86_64-apple-darwin.dmg',verifier.EXPECTED_INSTALLER_CONTAINERS)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            write_release_directory(root)
            self.assertEqual(len(verifier.discover_archives([root])),8)
            intel=root/'kitrove-installer-x86_64-apple-darwin.dmg'
            intel.write_bytes(b'not a current publication artifact')
            with self.assertRaises(verifier.ArchiveValidationError):
                verifier.discover_archives([root])

    def test_hosted_intel_preparation_refuses_before_credentials_or_runner_access(self):
        with patch.dict(os.environ,{'DIST_TARGET':'x86_64-apple-darwin'},clear=True), \
             patch.object(signing,'signing_environment') as credentials:
            with self.assertRaisesRegex(RuntimeError,'Unsupported Apple target'):
                signing.prepare_release()
            credentials.assert_not_called()

    def test_publication_selection_cannot_be_widened_or_silently_shrunk(self):
        policy=json.loads((ROOT/'release/release-policy.json').read_text())
        for targets in ([], TARGETS[:2], TARGETS+['x86_64-apple-darwin'], TARGETS[::-1], TARGETS+[TARGETS[0]]):
            with self.subTest(targets=targets), self.assertRaises(RuntimeError):
                verifier.parse_application_archive_policy(json.dumps(dict(policy,publication_targets=targets)))
