"""Credential-free old-public-image control; no provider access or native signer."""
import hashlib
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class AppleTicketControlTests(unittest.TestCase):
    def module(self):
        path = ROOT / 'scripts/apple_ticket_control.py'
        self.assertTrue(path.is_file(), 'Read-only ticket control implementation missing')
        spec = importlib.util.spec_from_file_location('apple_ticket_control', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_manual_workflow_has_no_signing_or_credential_authority(self):
        path = ROOT / '.github/workflows/apple-ticket-control.yml'
        self.assertTrue(path.is_file(), 'Credential-free manual workflow missing')
        workflow = path.read_text()
        for value in ('workflow_dispatch:', 'contents: read', 'runs-on: macos-15',
                      'persist-credentials: false', 'python3 scripts/apple_ticket_control.py'):
            self.assertIn(value, workflow)
        for value in ('secrets.', 'id-token:', 'environment:', 'upload-artifact',
                      'stapler staple', '--sign', 'notarytool', 'sudo ', 'pfctl', 'inputs:'):
            self.assertNotIn(value, workflow)

    def test_control_inventory_is_exact_and_never_a_release_authority(self):
        control = self.module()
        self.assertEqual(control.IMAGES, (
            ('aarch64-apple-darwin', 'ee439d07703a45e3427f6d7c867653f9f15dc443d73a544bc891c968e002bda0'),
            ('x86_64-apple-darwin', '14d8fa5f8b4cb6c62c547b59a2604a814697e75c77aa1f0e05a591fd47472ed8'),
        ))

    def test_context_refuses_every_authority_expansion(self):
        control = self.module()
        valid = dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY='Kapital-Labs/kitrove',
            GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF='refs/heads/main',
            RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='macOS', RUNNER_ARCH='ARM64',
            GITHUB_WORKFLOW_REF='Kapital-Labs/kitrove/.github/workflows/apple-ticket-control.yml@refs/heads/main')
        self.assertTrue(control.valid_context(valid))
        for name in valid:
            with self.subTest(name=name):
                self.assertFalse(control.valid_context({**valid, name: 'SECRET'}))
        self.assertFalse(control.valid_context({**valid, 'KITROVE_HOSTED_SIGNING_READY': 'true'}))

    def test_main_stops_after_cancellation_or_unconfirmed_cleanup(self):
        control = self.module()
        env = dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY='Kapital-Labs/kitrove',
            GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF='refs/heads/main',
            RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='macOS', RUNNER_ARCH='ARM64', GITHUB_SHA='a' * 40,
            GITHUB_WORKFLOW_REF='Kapital-Labs/kitrove/.github/workflows/apple-ticket-control.yml@refs/heads/main')
        for category in ('native-cancelled', 'native-cleanup-unconfirmed'):
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, env, clear=True), \
                 patch.object(control.sys, 'argv', ['control']), \
                 patch.object(control.tempfile, 'mkdtemp', return_value=directory), \
                 patch.object(control, 'download_image', return_value=Path(directory) / 'fixture') as download, \
                 patch.object(control, 'check_image', side_effect=control.ControlError(category)), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(control.main(), 1)
            self.assertEqual(download.call_count, 1)

    def test_https_downgrade_is_refused_without_echo(self):
        control = self.module()
        with self.assertRaises(control.ControlError):
            control.HTTPSOnly().redirect_request(None, None, 302, '', {}, 'http://SECRET/')
        with self.assertRaises(control.ControlError):
            control.open_https('http://SECRET/')

    @unittest.skipUnless(os.name == 'posix', 'Mac control identities require POSIX no-follow')
    def test_linked_control_inputs_are_refused(self):
        control = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.dmg'
            path.write_bytes(b'fixture')
            alias = Path(directory) / 'alias.dmg'
            alias.symlink_to(path)
            with self.assertRaises(control.ControlError):
                control.identity(alias)
            alias.unlink()
            os.link(path, alias)
            with self.assertRaises(control.ControlError):
                control.identity(path)

    @unittest.skipUnless(os.name == 'posix', 'Mac control identities require POSIX no-follow')
    def test_process_timeout_cancellation_and_cleanup_are_closed(self):
        control = self.module()
        for error, category in ((control.ProcessTimeout('SECRET'), 'native-timeout'),
                                (control.ProcessCancelled('SECRET'), 'native-cancelled'),
                                (control.ProcessCleanupError('SECRET'), 'native-cleanup-unconfirmed')):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'fixture.dmg'
                path.write_bytes(b'fixture')
                with patch.object(control, 'run_owned', side_effect=error), \
                     self.assertRaises(control.ControlError) as result:
                    control.check_image(path, hashlib.sha256(b'fixture').hexdigest())
                self.assertEqual(result.exception.category, category)
                self.assertNotIn('SECRET', str(result.exception))

    def test_pinned_download_refuses_bad_hash_and_oversize_before_native_tools(self):
        control = self.module()
        for data in (b'wrong', b'x' * (control.MAX_IMAGE_BYTES + 1)):
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(control, 'open_https', return_value=io.BytesIO(data)), \
                     self.assertRaises(control.ControlError) as error:
                    control.download_image('aarch64-apple-darwin', '0' * 64, Path(directory))
                self.assertNotIn('SECRET', str(error.exception))
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_download_is_exclusive_and_pins_bytes_before_native_tools(self):
        control = self.module()
        data = b'synthetic known control'
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(control, 'open_https', return_value=io.BytesIO(data)):
            path = control.download_image('x86_64-apple-darwin', digest, Path(directory))
            self.assertEqual(path.read_bytes(), data)
            with patch.object(control, 'open_https', return_value=io.BytesIO(data)), \
                 self.assertRaises(control.ControlError):
                control.download_image('x86_64-apple-darwin', digest, Path(directory))
            self.assertEqual(path.read_bytes(), data)

    @unittest.skipUnless(os.name == 'posix', 'Mac control file identities require POSIX no-follow')
    def test_missing_pin_refuses_before_native_parser(self):
        control = self.module()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(control, 'run_owned', return_value=types.SimpleNamespace(returncode=0)) as run:
            path = Path(directory) / 'fixture.dmg'
            path.write_bytes(b'fixture')
            with self.assertRaises(control.ControlError):
                control.check_image(path)
            with self.assertRaises(control.ControlError):
                control.check_image(path, '0' * 64)
            run.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'Mac control file identities require POSIX no-follow')
    def test_native_failures_are_redacted_and_signature_precedes_ticket(self):
        control = self.module()
        for status in (0, 65, 68):
            calls = []
            def run(args, **kwargs):
                calls.append(args)
                return types.SimpleNamespace(returncode=(0 if len(calls) == 1 else status),
                    stdout=b'SECRET_PROVIDER', stderr=b'SECRET_PATH')
            with tempfile.TemporaryDirectory() as directory, patch.object(control, 'run_owned', side_effect=run):
                path = Path(directory) / 'fixture.dmg'
                path.write_bytes(b'fixture')
                result = control.check_image(path, hashlib.sha256(b'fixture').hexdigest())
            self.assertEqual(result, {'signature': 0, 'ticket': status, 'unchanged': True})
            self.assertEqual(calls[0][:3], ['/usr/bin/codesign', '--verify', '--strict'])
            self.assertEqual(calls[1][:4], ['/usr/bin/xcrun', 'stapler', 'validate', '-q'])
            self.assertNotIn('SECRET', str(result))

    @unittest.skipUnless(os.name == 'posix', 'Mac control file identities require POSIX no-follow')
    def test_signature_failure_and_late_mutation_refuse_further_checks(self):
        control = self.module()
        for mutate in (False, True):
            calls = []
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'fixture.dmg'
                path.write_bytes(b'fixture')
                def run(args, **kwargs):
                    calls.append(args)
                    if mutate:
                        path.write_bytes(b'changed')
                    return types.SimpleNamespace(returncode=0 if mutate else 1, stdout=b'', stderr=b'SECRET')
                with patch.object(control, 'run_owned', side_effect=run):
                    if mutate:
                        with self.assertRaises(control.ControlError):
                            control.check_image(path, hashlib.sha256(b'fixture').hexdigest())
                    else:
                        self.assertEqual(control.check_image(path, hashlib.sha256(b'fixture').hexdigest()), {'signature': 1, 'unchanged': True})
            self.assertEqual(len(calls), 1)

    @unittest.skipUnless(os.name == 'posix', 'Mac control file identities require POSIX no-follow')
    def test_transport_and_process_exception_messages_never_escape(self):
        control = self.module()
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(control, 'open_https', side_effect=OSError('SECRET_URL')), \
                 self.assertRaises(control.ControlError) as error:
                control.download_image('x86_64-apple-darwin', '0' * 64, Path(directory))
            self.assertNotIn('SECRET', str(error.exception))
            path = Path(directory) / 'fixture.dmg'
            path.write_bytes(b'fixture')
            with patch.object(control, 'run_owned', side_effect=OSError('SECRET_PATH')), \
                 self.assertRaises(control.ControlError) as error:
                control.check_image(path, hashlib.sha256(b'fixture').hexdigest())
            self.assertNotIn('SECRET', str(error.exception))


if __name__ == '__main__':
    unittest.main()
