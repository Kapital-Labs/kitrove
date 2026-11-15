"""Credential-free checks for the protected, non-signing authentication probe."""
import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import hosted_apple_notary_validation as validation
except ModuleNotFoundError:
    validation = None


class NotaryValidationTests(unittest.TestCase):
    def scenario(self, failure=None, overrides=None, failure_operation='authentication'):
        self.assertIsNotNone(validation)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'kitrove-notary-keychain').write_bytes(b'fixture, never executed')
            env = dict(GITHUB_REPOSITORY='Kapital-Labs/kitrove', GITHUB_EVENT_NAME='workflow_dispatch',
                GITHUB_REF='refs/heads/main', GITHUB_SHA='a' * 40, GITHUB_RUN_ATTEMPT='1',
                RUNNER_ENVIRONMENT='github-hosted', RUNNER_TEMP=str(root),
                KITROVE_DIAGNOSTIC_EXPECTED_SOURCE='a' * 40,
                KITROVE_NOTARY_VALIDATION_SHA='a' * 40, KITROVE_SIGNING_REHEARSAL_SHA='',
                KITROVE_HOSTED_SIGNING_READY='',
                APPLE_ID='account-canary', TEAM_ID='98RZ36ES7A', NOTARY_PASSWORD='password-canary')
            env.update(overrides or {})
            original = str(root / 'original keychain-db')
            calls = []

            def native(args, payload=None, timeout=30, *, operation, env=None):
                calls.append(operation)
                self.assertNotIn('NOTARY_PASSWORD', os.environ)
                self.assertNotIn('APPLE_ID', os.environ)
                if operation == 'Keychain search-list snapshot':
                    return type('Result', (), {'stdout': json.dumps(original).encode()})()
                if operation == 'notarization Keychain creation':
                    data = json.loads(payload)
                    self.assertEqual(set(data), {'path'})
                    Path(data['path']).touch()
                if operation == 'Keychain search-list restoration':
                    self.assertEqual(args[-1], original)
                if operation == 'Keychain cleanup':
                    Path(args[-1]).unlink()
                if failure is not None and operation == failure_operation:
                    raise failure

            def authenticate(args, password):
                calls.append('authentication')
                self.assertEqual(password, 'password-canary')
                self.assertNotIn(password, args)
                self.assertEqual(args[:3], ['notarytool', 'store-credentials', 'kitrove-validation'])
                self.assertIn('--keychain', args)
                self.assertIn('--validate', args)
                self.assertNotIn('--no-validate', args)
                if failure is not None and failure_operation == 'authentication':
                    raise failure

            @contextlib.contextmanager
            def scope():
                yield {'cancelled': False}

            with patch.dict(os.environ, env, clear=True), patch.object(validation.sys, 'platform', 'darwin'), \
                 patch.object(validation, 'native', side_effect=native), \
                 patch.object(validation, 'authenticate', side_effect=authenticate), \
                 patch.object(validation, 'cancellation_scope', side_effect=scope), \
                 contextlib.redirect_stdout(io.StringIO()):
                if overrides or failure is not None:
                    with self.assertRaises(RuntimeError):
                        validation.validate_credentials()
                else:
                    validation.validate_credentials()
            retained = [path for path in root.iterdir() if path.is_dir()]
            if failure is not None and isinstance(failure, validation.ProcessCleanupError):
                self.assertEqual(len(retained), 1)
                self.assertTrue((retained[0] / 'notary.keychain-db').is_file())
                self.assertNotIn('Keychain cleanup', calls)
                if failure_operation != 'Keychain search-list restoration':
                    self.assertNotIn('Keychain search-list restoration', calls)
            else:
                self.assertEqual(retained, [])
            return calls

    def test_one_authentication_in_empty_keychain_is_always_cleaned(self):
        self.assertEqual(self.scenario(), ['Keychain search-list snapshot',
            'notarization Keychain creation', 'authentication',
            'Keychain search-list restoration', 'Keychain cleanup'])

    def test_authentication_failure_still_restores_and_deletes(self):
        self.assertEqual(self.scenario(RuntimeError('synthetic failure'))[-2:],
            ['Keychain search-list restoration', 'Keychain cleanup'])

    def test_uncertain_process_cleanup_retains_private_state(self):
        self.assertIsNotNone(validation)
        for operation in ('notarization Keychain creation', 'authentication',
                          'Keychain search-list restoration'):
            self.scenario(validation.ProcessCleanupError(), failure_operation=operation)

    def test_creation_or_restoration_failure_cannot_report_success(self):
        for operation in ('notarization Keychain creation', 'Keychain search-list restoration'):
            self.assertEqual(self.scenario(RuntimeError('synthetic failure'),
                failure_operation=operation)[-1], 'Keychain cleanup')

    def test_every_manual_context_boundary_refuses_before_native_tools(self):
        for overrides in ({'GITHUB_REPOSITORY': 'other/repository'}, {'GITHUB_EVENT_NAME': 'push'},
                {'GITHUB_REF': 'refs/tags/v0.1.0-rc.5.13'}, {'GITHUB_RUN_ATTEMPT': '2'},
                {'GITHUB_SHA': ''}, {'KITROVE_DIAGNOSTIC_EXPECTED_SOURCE': 'b' * 40},
                {'KITROVE_NOTARY_VALIDATION_SHA': ''}, {'KITROVE_HOSTED_SIGNING_READY': 'true'},
                {'KITROVE_SIGNING_REHEARSAL_SHA': 'a' * 40},
                {'RUNNER_ENVIRONMENT': 'self-hosted'}, {'NOTARY_PASSWORD': ''},
                {'TEAM_ID': 'unknown'}, {'P12': 'unexpected-signing-key'},
                {'RUNNER_TEMP': 'relative-path'}):
            with self.subTest(overrides=overrides):
                self.assertEqual(self.scenario(overrides=overrides), [])

    def test_workflow_is_one_protected_credential_only_job(self):
        root = Path(__file__).resolve().parent.parent
        path = root / '.github/workflows/apple-notary-validation.yml'
        self.assertTrue(path.is_file())
        workflow = path.read_text()
        for token in ('workflow_dispatch:', 'environment: release', 'runs-on: macos-15',
                'github.run_attempt == 1', "github.ref == 'refs/heads/main'",
                'github.sha == inputs.expected_source',
                'github.sha == vars.KITROVE_NOTARY_VALIDATION_SHA',
                "vars.KITROVE_SIGNING_REHEARSAL_SHA == ''",
                "vars.KITROVE_HOSTED_SIGNING_READY == ''", 'persist-credentials: false'):
            self.assertIn(token, workflow)
        self.assertEqual(set(re.findall(r'secrets\.([A-Z_]+)', workflow)),
            {'KITROVE_APPLE_ID', 'KITROVE_APPLE_TEAM_ID', 'KITROVE_GITHUB_NOTARIZATION'})
        for forbidden in ('id-token:', 'upload-artifact', 'download-artifact', 'cargo ',
                          'codesign', 'stapler', 'notarytool submit', 'release create'):
            self.assertNotIn(forbidden, workflow)
        self.assertLess(workflow.index('Compile empty Keychain helper before credentials'),
                        workflow.index('Validate existing notarization credentials'))


if __name__ == '__main__':
    unittest.main()
