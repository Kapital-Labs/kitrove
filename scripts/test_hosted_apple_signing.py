"""No-network regression tests; never import a real identity or sign code."""
import contextlib
import io
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import hosted_apple_signing as signing


class HostedAppleSigningTests(unittest.TestCase):
    def scenario(self, failure=None, overrides=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name in ('kitrove-release-xtask', 'kitrove-apple-import'):
                (root / name).write_bytes(b'fixture, never executed')
            environment = dict(P12='archive-canary', P12_PASSWORD='wrapping-canary',
                APPLE_ID='account-canary', TEAM_ID='98RZ36ES7A', NOTARY_PASSWORD='notary-canary',
                RUNNER_TEMP=str(root), RUNNER_ENVIRONMENT='github-hosted',
                DIST_TARGET='aarch64-apple-darwin', RELEASE_TAG='v0.0.0')
            environment.update(overrides or {})
            original = [str(root / 'login keys.keychain-db'), str(root / 'System.keychain')]
            calls = []

            def native(args, payload=None, timeout=30, *, operation, env=None):
                self.assertIn(operation, signing.OPERATIONS)
                self.assertNotIn('P12_PASSWORD', os.environ)
                self.assertNotIn('NOTARY_PASSWORD', os.environ)
                calls.append(operation)
                if operation == 'Keychain search-list snapshot':
                    if failure == 'snapshot':
                        return types.SimpleNamespace(stdout=b'relative-path')
                    return types.SimpleNamespace(stdout=('\n'.join(json.dumps(x) for x in original)).encode())
                if operation == 'identity import':
                    values = json.loads(payload)
                    self.assertEqual(values['password'], 'wrapping-canary')
                    self.assertEqual(Path(values['path']).parent.parent, root)
                    Path(values['path']).touch()
                if operation.endswith('archive preparation'):
                    product = 'kitrove-cli' if operation.startswith('application') else 'kitrove-installer'
                    self.assertEqual(args, [str(root / 'kitrove-release-xtask'), 'prepare-platform-release',
                        f'target/distrib/{product}-aarch64-apple-darwin.tar.xz', 'aarch64-apple-darwin',
                        'v0.0.0', 'release/application-compatibility.json', 'dist-manifest.json'])
                    self.assertEqual(env['KITROVE_NOTARY_PROFILE'], 'kitrove-release')
                    self.assertTrue(Path(env['KITROVE_SIGNING_KEYCHAIN']).is_file())
                    for secret in ('P12', 'P12_PASSWORD', 'APPLE_ID', 'TEAM_ID', 'NOTARY_PASSWORD'):
                        self.assertNotIn(secret, env)
                if operation == 'Keychain search-list restoration':
                    self.assertEqual(args[-2:], original)
                if operation == 'Keychain cleanup':
                    self.assertEqual(Path(args[-1]).parent.parent, root)
                    Path(args[-1]).unlink()
                if failure == operation:
                    raise RuntimeError('synthetic failure')
                return types.SimpleNamespace(stdout=b'', stderr=b'')

            def authenticate(args, password):
                self.assertEqual(password, 'notary-canary')
                self.assertNotIn(password, args)
                self.assertIn('--keychain', args)
                if failure == 'authentication':
                    raise RuntimeError('synthetic failure')

            with patch.dict(os.environ, environment, clear=True), patch.object(signing.sys, 'platform', 'darwin'), \
                 patch.object(signing, 'native', side_effect=native), \
                 patch.object(signing, 'authenticate', side_effect=authenticate), \
                 contextlib.redirect_stdout(io.StringIO()):
                if failure or overrides:
                    with self.assertRaises((RuntimeError, KeyError)):
                        signing.prepare_release()
                else:
                    signing.prepare_release()
            if failure != 'snapshot' and not overrides:
                self.assertEqual(calls[-2:], ['Keychain search-list restoration', 'Keychain cleanup'])
            self.assertEqual(sorted(path.name for path in root.iterdir()),
                ['kitrove-apple-import', 'kitrove-release-xtask'])
            return calls

    def test_both_archives_share_one_credential_lifetime(self):
        calls = self.scenario()
        self.assertEqual(calls.count('identity import'), 1)
        self.assertEqual(calls[2:4], ['application archive preparation', 'installer archive preparation'])

    def test_failures_stop_preparation_and_always_attempt_cleanup(self):
        for operation in ('identity import', 'authentication', 'application archive preparation',
                          'installer archive preparation', 'Keychain search-list restoration'):
            with self.subTest(operation=operation):
                calls = self.scenario(operation)
                if operation == 'application archive preparation':
                    self.assertNotIn('installer archive preparation', calls)

    def test_invalid_snapshot_does_not_import(self):
        self.assertEqual(self.scenario('snapshot'), ['Keychain search-list snapshot'])

    def test_missing_credentials_or_wrong_host_never_start_native_tools(self):
        for overrides in ({'NOTARY_PASSWORD': ''}, {'TEAM_ID': 'wrong'},
                          {'RUNNER_ENVIRONMENT': 'self-hosted'}, {'DIST_TARGET': 'unknown'},
                          {'RELEASE_TAG': ''}):
            with self.subTest(overrides=overrides):
                self.assertEqual(self.scenario(overrides=overrides), [])

    def test_error_categories_never_echo_provider_bytes(self):
        for marker, category in ((b'errSecInternalComponent', 'security-internal'),
                                 (b'unable to build chain', 'certificate-chain'),
                                 (b'unknown', 'unclassified-native-failure')):
            output = io.StringIO()
            result = types.SimpleNamespace(returncode=1, stderr=marker + b' SECRET', stdout=b'SECRET')
            with patch.object(signing.subprocess, 'run', return_value=result), \
                 contextlib.redirect_stdout(output), self.assertRaises(RuntimeError):
                signing.native(['SECRET_ARG'], payload=b'SECRET_INPUT', operation='identity import')
            self.assertIn(category, output.getvalue())
            self.assertNotIn('SECRET', output.getvalue())

    def test_timeout_and_launch_errors_are_redacted(self):
        for error in (signing.subprocess.TimeoutExpired(['SECRET'], 1, output=b'SECRET'), OSError('SECRET')):
            output = io.StringIO()
            with patch.object(signing.subprocess, 'run', side_effect=error), \
                 contextlib.redirect_stdout(output), self.assertRaises(RuntimeError):
                signing.native(['SECRET'], operation='identity import')
            self.assertNotIn('SECRET', output.getvalue())

    def test_unknown_diagnostic_and_multiline_password_fail_without_output(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(RuntimeError):
                signing.native([], operation='SECRET')
            with self.assertRaises(RuntimeError):
                signing.authenticate([], 'SECRET\nvalue')
        self.assertEqual(output.getvalue(), '')

    @unittest.skipUnless(os.name == 'posix', 'native terminal protocol requires POSIX')
    def test_native_terminal_supplies_password_only_after_echo_is_disabled(self):
        import termios

        for accepted in (True, False):
            def child(_path, args):
                if 'terminal-canary' in args:
                    os._exit(3)
                attributes = termios.tcgetattr(0)
                attributes[3] &= ~termios.ECHO
                termios.tcsetattr(0, termios.TCSANOW, attributes)
                os.write(1, b'App-specific password: ')
                supplied = os.read(0, 256)
                os._exit(0 if accepted and supplied == b'terminal-canary\n' else 1)

            with self.subTest(accepted=accepted), patch.object(signing.os, 'execv', side_effect=child):
                if accepted:
                    signing.authenticate(['notarytool', 'store-credentials', 'fixture'], 'terminal-canary')
                else:
                    with self.assertRaises(RuntimeError):
                        signing.authenticate(['notarytool', 'store-credentials', 'fixture'], 'terminal-canary')

    def test_workflow_orders_compile_credentials_cleanup_and_attestation(self):
        workflow = (Path(__file__).resolve().parent.parent / '.github/workflows/release.yml').read_text()
        compile_step = workflow.index('Compile Apple signing helpers before exposing credentials')
        credential_step = workflow.index('Prepare both Apple release archives in an isolated Keychain')
        verification = workflow.index('      - id: verified-local')
        attestation = workflow.index('      - name: Attest the exact application archive')
        self.assertLess(compile_step, credential_step)
        self.assertLess(credential_step, verification)
        self.assertLess(verification, attestation)
        self.assertEqual(workflow.count('secrets.KITROVE_GITHUB_NOTARIZATION'), 1)
        self.assertIn('if [[ "$RUNNER_OS" == "Linux" ]]; then', workflow)


if __name__ == '__main__':
    unittest.main()
