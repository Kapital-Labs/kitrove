"""Synthetic rehearsal checks, without network, credentials or product execution."""
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import signing_rehearsal as rehearsal


ROOT = Path(__file__).resolve().parents[1]


class SigningRehearsalTests(unittest.TestCase):
    def environment(self):
        return dict(DIST_TARGET='aarch64-apple-darwin', GITHUB_SHA='a' * 40,
                    GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
                    GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY='Kapital-Labs/kitrove',
                    GITHUB_REF='refs/heads/main', RELEASE_TAG='v0.0.0',
                    GITHUB_WORKFLOW_REF='Kapital-Labs/kitrove/.github/workflows/signing-rehearsal.yml@refs/heads/main',
                    KITROVE_SIGNING_REHEARSAL_SHA='a' * 40)

    @patch.object(rehearsal.sys, 'platform', 'darwin')
    def test_every_context_field_fails_closed(self):
        env = self.environment()
        self.assertEqual(rehearsal.context(env), ('aarch64-apple-darwin', 'a' * 40))
        for key in env:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                rehearsal.context(dict(env, **{key: ''}))
        with self.assertRaises(RuntimeError):
            rehearsal.context(dict(env, DIST_TARGET='x86_64-pc-windows-msvc'))
        self.assertEqual(rehearsal.context(dict(env, KITROVE_REHEARSAL_SCOPE='mac-dmg'))[0], env['DIST_TARGET'])
        for scope in ('', 'all', 'MAC-DMG'):
            with self.assertRaises(RuntimeError):
                rehearsal.context(dict(env, KITROVE_REHEARSAL_SCOPE=scope))
        with patch.object(rehearsal.sys, 'platform', 'win32'), self.assertRaises(RuntimeError):
            rehearsal.context(dict(env, DIST_TARGET='x86_64-pc-windows-msvc', KITROVE_REHEARSAL_SCOPE='mac-dmg'))

    def fixture(self, directory, target):
        files = {}
        for name in rehearsal.handoff_names(target):
            path = directory / name
            path.write_bytes(b'fixture')
            files[name] = rehearsal.digest(path)
        path = directory / 'inventory.json'
        path.write_text(json.dumps(dict(source='a' * 40, target=target, files=files)), encoding='utf-8')
        return rehearsal.digest(path)

    def test_handoff_rejects_tampering_and_extra_files_for_every_target(self):
        for target in rehearsal.DIST_DIGESTS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                expected = self.fixture(directory, target)
                rehearsal.verify_handoff(directory, target, 'a' * 40, expected)
                for sha, value in [('b' * 40, expected), ('a' * 40, '0' * 64), ('a' * 40, '')]:
                    with self.assertRaises(RuntimeError):
                        rehearsal.verify_handoff(directory, target, sha, value)
                extra = directory / 'unexpected'
                extra.write_bytes(b'extra')
                with self.assertRaises(RuntimeError):
                    rehearsal.verify_handoff(directory, target, 'a' * 40, expected)
                extra.unlink()
                (directory / rehearsal.handoff_names(target)[0]).write_bytes(b'changed')
                with self.assertRaises(RuntimeError):
                    rehearsal.verify_handoff(directory, target, 'a' * 40, expected)

    def test_redirected_or_non_file_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaises(RuntimeError):
                rehearsal.digest(directory)
            source = directory / 'source'
            source.write_bytes(b'fixture')
            link = directory / 'link'
            try:
                link.symlink_to(source)
            except OSError:
                self.skipTest('Symlink creation unavailable')
            with self.assertRaises(RuntimeError):
                rehearsal.digest(link)

    def test_prebuilt_provision_and_evidence_use_only_release_tool_commands(self):
        for target in rehearsal.DIST_DIGESTS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary).resolve()
                handoff = directory / 'signing-input'
                handoff.mkdir()
                runner = directory / 'runner'
                runner.mkdir()
                expected = self.fixture(handoff, target)
                prior = Path.cwd()
                try:
                    os.chdir(directory)
                    with patch.dict(os.environ, RUNNER_TEMP=str(runner), EXPECTED_INVENTORY=expected,
                                    GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1'):
                        rehearsal.provision(target, 'a' * 40)
                        for name in rehearsal.archive_names(target):
                            self.assertEqual((directory / 'target/distrib' / name).read_bytes(), b'fixture')
                        # The real verifier is covered by canonical Rust/native tests.
                        # Here assert that no transferred product or Cargo build runs.
                        with patch.object(rehearsal, 'run') as commands:
                            rehearsal.verify(target, 'a' * 40)
                        for call in commands.call_args_list:
                            command = call.args
                            if command[0] == rehearsal.sys.executable:
                                self.assertEqual(command[1], 'scripts/verify_release_archives.py')
                            else:
                                self.assertTrue(Path(command[0]).name.startswith('kitrove-release-xtask'))
                                self.assertEqual(command[1], 'verify-application-release-bundle')
                        record = json.loads((directory / 'signing-evidence/evidence.json').read_text())
                        self.assertFalse(record['published'])
                        self.assertEqual(record['source'], 'a' * 40)
                        self.assertEqual(len(record['files']), 5)
                        with self.assertRaises(FileExistsError):
                            rehearsal.provision(target, 'a' * 40)
                finally:
                    os.chdir(prior)

    def test_mac_container_evidence_is_reverified_and_failure_has_no_success_record(self):
        for target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
            for failure in (None, 'extra', 'verification'):
                with self.subTest(target=target, failure=failure), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    archives = root / 'target/distrib'
                    archives.mkdir(parents=True)
                    runner = root / 'runner'
                    images = runner / 'kitrove-installer-dmg'
                    images.mkdir(parents=True)
                    image = f'kitrove-installer-{target}.dmg'
                    for name in (image, image + '.sha256'):
                        (images / name).write_bytes(b'synthetic only')
                    if failure == 'extra':
                        (images / 'unknown').write_bytes(b'extra')
                    for name in rehearsal.archive_names(target):
                        for leaf in (name, name + '.sha256'):
                            (archives / leaf).write_bytes(b'synthetic only')
                    (root / 'dist-manifest.json').write_bytes(b'fixture')
                    calls = []

                    def run(*args):
                        calls.append(args)
                        if args[1] == 'verify-installer-dmg':
                            self.assertEqual(args[2:], (
                                f'signing-evidence/kitrove-installer-{target}.tar.xz', target,
                                'v0.0.0', 'signing-evidence/dist-manifest.json',
                                f'signing-evidence/{image}'))
                            if failure == 'verification':
                                raise RuntimeError('synthetic native refusal')

                    prior = Path.cwd()
                    try:
                        os.chdir(root)
                        with patch.dict(os.environ, RUNNER_TEMP=str(runner), GITHUB_RUN_ID='1',
                                        GITHUB_RUN_ATTEMPT='1', KITROVE_REHEARSAL_SCOPE='mac-dmg'), \
                             patch.object(rehearsal, 'run', side_effect=run):
                            if failure:
                                with self.assertRaises(RuntimeError):
                                    rehearsal.verify(target, 'a' * 40)
                            else:
                                rehearsal.verify(target, 'a' * 40)
                        record = root / 'signing-evidence/evidence.json'
                        if failure:
                            self.assertFalse(record.exists())
                        else:
                            observed = json.loads(record.read_text())
                            self.assertEqual(observed['scope'], 'mac-dmg')
                            self.assertFalse(observed['published'])
                            self.assertEqual(len(observed['files']), 7)
                            self.assertEqual(observed['files'][image], rehearsal.digest(images / image))
                            self.assertEqual(calls[-1][1], 'verify-installer-dmg')
                    finally:
                        os.chdir(prior)

    def test_workflow_limits_authority_and_reuses_reviewed_helpers(self):
        driver = (ROOT / '.github/workflows/signing-rehearsal.yml').read_text()
        workflow = (ROOT / '.github/workflows/signing-rehearsal-target.yml').read_text()
        build = workflow.split('  build:\n', 1)[1]
        callers, sign = driver.split('  sign:\n', 1)
        self.assertIn('workflow_dispatch:', driver)
        self.assertNotIn('pull_request:', driver + workflow)
        self.assertNotIn('contents: write', driver + workflow)
        self.assertNotIn('attestations:', driver + workflow)
        self.assertNotIn('KITROVE_HOSTED_SIGNING_READY', driver + workflow)
        self.assertNotIn('secrets.', build)
        self.assertNotIn('id-token:', build)
        self.assertNotIn('secrets.', workflow + callers)
        self.assertNotIn('secrets: inherit', driver + workflow)
        self.assertNotIn('id-token:', callers)
        self.assertIn('value: ${{ jobs.build.outputs.inventory }}', workflow)
        self.assertIn('environment: release', sign)
        self.assertIn('EXPECTED_INVENTORY: ${{ needs[matrix.build].outputs.inventory }}', sign)
        self.assertIn('needs: [build-apple-silicon, build-intel, build-windows]', sign)
        for name, target in (
                ('build-apple-silicon', 'aarch64-apple-darwin'),
                ('build-intel', 'x86_64-apple-darwin'),
                ('build-windows', 'x86_64-pc-windows-msvc')):
            self.assertIn(f'  {name}:\n    uses: ./.github/workflows/signing-rehearsal-target.yml\n'
                          f'    with:\n      target: {target}\n    permissions:\n      contents: read', callers)
        matrices = [json.loads(value) for value in re.findall(r"'([\[][\{].*?[\]])'", sign)]
        self.assertEqual(matrices, [
            [{'target': 'aarch64-apple-darwin', 'build': 'build-apple-silicon'},
             {'target': 'x86_64-apple-darwin', 'build': 'build-intel'}],
            [{'target': 'aarch64-apple-darwin', 'build': 'build-apple-silicon'},
             {'target': 'x86_64-apple-darwin', 'build': 'build-intel'},
             {'target': 'x86_64-pc-windows-msvc', 'build': 'build-windows'}],
        ])
        self.assertIn("if: inputs.scope != 'mac-dmg'", callers)
        self.assertIn("needs.build-apple-silicon.result == 'success'", sign)
        self.assertIn("needs.build-intel.result == 'success'", sign)
        self.assertIn('always() && !cancelled() &&', sign)
        self.assertIn("inputs.scope == 'mac-dmg' && needs.build-windows.result == 'skipped'", sign)
        self.assertIn("KITROVE_PREPARE_DMG: ${{ inputs.scope == 'mac-dmg' && '1' || '' }}", sign)
        for secret in ('KITROVE_APPLE_P12_BASE64', 'KITROVE_APPLE_P12_PASSWORD',
                       'KITROVE_APPLE_ID', 'KITROVE_APPLE_TEAM_ID', 'KITROVE_GITHUB_NOTARIZATION'):
            self.assertEqual(sign.count('${{ secrets.' + secret + ' }}'), 1)
        for section in (driver, build, sign):
            self.assertIn('github.sha == vars.KITROVE_SIGNING_REHEARSAL_SHA', section)
        self.assertEqual((driver + workflow).count('retention-days: 1'), 2)
        positions = [sign.index(value) for value in (
            'signing_rehearsal.py provision', '-Stage Provision', 'hosted_apple_signing.py',
            'id: windows-login', '-Stage Sign', '-Stage Cleanup', 'signing_rehearsal.py verify',
            'uses: actions/upload-artifact@')]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("if: always() && runner.os == 'Windows' && steps.windows-login.outcome != 'skipped'", sign)
        release = (ROOT / '.github/workflows/release.yml').read_text()
        for value in rehearsal.DIST_DIGESTS.values():
            self.assertIn(value, release)
        for line in (driver + workflow).splitlines():
            if 'uses:' in line and './.github/' not in line:
                self.assertRegex(line, r'uses: [\w/-]+@[0-9a-f]{40}$')
