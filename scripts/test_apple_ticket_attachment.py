"""Closed native command tests, with synthetic bytes and no real Apple calls."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import apple_ticket_attachment as attachment
import apple_ticket_attachment_input as intake


@unittest.skipUnless(os.name == 'posix', 'native Apple path capture uses POSIX no-follow handles')
class AttachmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.original = self.root / 'image-original.dmg'
        self.original.write_bytes(b'exact synthetic accepted image')
        self.digest = hashlib.sha256(self.original.read_bytes()).hexdigest()
        self.patch = mock.patch.object(intake, 'IMAGE_SHA', self.digest)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.calls = []

    def invoke(self, args, **kwargs):
        self.calls.append(args)
        self.assertEqual(Path(args[-1]), self.root / 'image-copy.dmg')
        self.assertEqual(kwargs['timeout'], 45)
        self.assertEqual(set(kwargs['env']), {'PATH', 'LANG', 'LC_ALL', 'TMPDIR'})
        if args[0] == '/usr/bin/codesign':
            self.assertEqual(args[:5], ['/usr/bin/codesign', '--verify', '--strict', '-R', attachment.REQUIREMENT])
        elif args[2] == 'staple':
            self.assertEqual(args[:4], ['/usr/bin/xcrun', 'stapler', 'staple', '-v'])
            with Path(args[-1]).open('ab') as target:
                target.write(b' ticket')
        else:
            self.assertEqual(args[:4], ['/usr/bin/xcrun', 'stapler', 'validate', '-v'])
        return subprocess.CompletedProcess(args, 0, b'worked SECRET_PATH', b'')

    def run_diagnostic(self, invoke=None):
        return attachment.run_attachment(self.root, 'a' * 40, '1234', invoke or self.invoke)

    def test_only_copy_changes_and_one_attachment_occurs(self):
        result = self.run_diagnostic()
        self.assertEqual(result['outcome'], 'attached-and-validated')
        self.assertTrue(result['original_unchanged'])
        self.assertTrue(result['copy_changed'])
        self.assertEqual(hashlib.sha256(self.original.read_bytes()).hexdigest(), self.digest)
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(sum('staple' in call for call in self.calls), 1)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_staple_failure_retains_closed_cause_without_retry(self):
        def fail(args, **kwargs):
            if args[0] == '/usr/bin/xcrun':
                self.calls.append(args)
                return subprocess.CompletedProcess(args, 68,
                    b'NSURLErrorDomain Code=-1005 The network connection was lost. /SECRET', b'')
            return self.invoke(args, **kwargs)
        result = self.run_diagnostic(fail)
        self.assertEqual(result['outcome'], 'staple-failed')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(result['stages'][-1]['url_error_codes'], [-1005])
        self.assertIn('connection-lost', result['stages'][-1]['observations'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_bad_initial_signature_never_attaches(self):
        def fail(args, **kwargs):
            self.calls.append(args)
            return subprocess.CompletedProcess(args, 1, b'SECRET', b'')
        result = self.run_diagnostic(fail)
        self.assertEqual(result['outcome'], 'signature-before-failed')
        self.assertEqual(len(self.calls), 1)

    def test_new_attempt_cannot_reuse_private_invocation(self):
        self.run_diagnostic()
        with self.assertRaises(intake.Error):
            self.run_diagnostic()
        self.assertEqual(len(self.calls), 4)

    def test_changed_original_refuses_even_if_native_succeeds(self):
        def change(args, **kwargs):
            self.original.write_bytes(b'changed')
            return self.invoke(args, **kwargs)
        with self.assertRaises(intake.Error):
            self.run_diagnostic(change)

    def test_wrong_input_digest_refuses_before_any_tool(self):
        self.original.write_bytes(b'wrong')
        with self.assertRaises(intake.Error):
            self.run_diagnostic()
        self.assertEqual(self.calls, [])

    def test_timeout_or_cleanup_uncertainty_stops_sequence(self):
        for error, outcome in ((attachment.ProcessTimeout(), 'native-timeout'),
                               (attachment.ProcessCleanupError(), 'native-cleanup-unconfirmed'),
                               (attachment.ProcessCancelled(), 'native-cancelled')):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as root:
                directory = Path(root).resolve()
                (directory / 'image-original.dmg').write_bytes(self.original.read_bytes())
                calls = []
                def fail(args, **kwargs):
                    calls.append(args)
                    raise error
                result = attachment.run_attachment(directory, 'a' * 40, '1234', fail)
                self.assertEqual(result['outcome'], outcome)
                self.assertEqual(len(calls), 1)

    def test_unknown_error_is_not_turned_into_network_proof(self):
        result = attachment.classify(b'unknown SECRET_ACCOUNT /SECRET_PATH')
        self.assertEqual(result['observations'], [])
        self.assertEqual(result['url_error_codes'], [])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_classifier_bound_and_closed_domains(self):
        result = attachment.classify(b'CKErrorDomain Code=6 SECRET_DOMAIN Code=42 HTTP/3 503')
        self.assertEqual(result.get('native_error_codes'), [{'domain': 'CKErrorDomain', 'code': 6}])
        self.assertEqual(result['http_statuses'], [503])
        self.assertNotIn('SECRET', json.dumps(result))
        with self.assertRaises(intake.Error):
            attachment.classify(b'x' * (256 * 1024 + 1))

    def test_workflow_has_no_signing_or_publication_capability(self):
        path = Path(__file__).resolve().parents[1] / '.github/workflows/apple-ticket-attachment.yml'
        self.assertTrue(path.is_file(), 'missing dedicated manual diagnostic workflow')
        workflow = path.read_text()
        for required in ('workflow_dispatch:', 'runs-on: macos-15', 'contents: read',
                         'actions: read', 'persist-credentials: false', "github.actor == 'brandon-kaplan'",
                         'python3 scripts/apple_ticket_attachment.py fetch',
                         'python3 scripts/apple_ticket_attachment.py attach'):
            self.assertIn(required, workflow)
        for forbidden in ('secrets.', 'id-token:', 'environment:', 'upload-artifact',
                          'notarytool', 'codesign --sign', 'release.yml', 'workflow_call:', 'pull_request:'):
            self.assertNotIn(forbidden, workflow)
        native = workflow.split('      - name: Attach existing ticket once', 1)[1]
        self.assertNotIn('GITHUB_TOKEN:', native)


if __name__ == '__main__':
    unittest.main()
