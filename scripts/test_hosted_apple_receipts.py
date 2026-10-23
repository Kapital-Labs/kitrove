"""Synthetic receipt policy; never accesses signing credentials or providers."""
import json
import contextlib
import io
import os
import sys
import types
import unittest
from unittest.mock import patch

from hosted_apple_receipts import PREFIX, ReceiptError, safe_receipt_lines
import hosted_apple_signing as signing


SOURCE = 'a' * 40
TARGET = 'x86_64-apple-darwin'


class SafeReceiptTests(unittest.TestCase):
    def receipt(self, **changes):
        value = dict(schema_version=1, submission_id='12345678-1234-1234-1234-123456789abc',
            status='In Progress', artifact_sha256='b' * 64, target=TARGET, source_commit=SOURCE)
        value.update(changes)
        return PREFIX + json.dumps(value).encode()

    def parse(self, data):
        return safe_receipt_lines(data, source_commit=SOURCE, target=TARGET)

    def test_only_closed_receipt_survives_provider_noise(self):
        for status in ('Accepted', 'Invalid', 'Rejected', 'In Progress', 'Unavailable'):
            output = self.parse(b'SECRET_ACCOUNT /private/SECRET\n' + self.receipt(status=status))
            self.assertEqual(len(output), 1)
            self.assertEqual(json.loads(output[0][len(PREFIX):])['status'], status)
            self.assertNotIn('SECRET', output[0])
        self.assertEqual(self.parse(b'SECRET provider output'), [])

    def test_wrong_context_or_unbounded_values_are_refused_without_echo(self):
        for changes in ({'source_commit': 'c' * 40}, {'target': 'aarch64-apple-darwin'},
                        {'submission_id': 'SECRET'}, {'artifact_sha256': 'SECRET'},
                        {'status': 'SECRET'}, {'schema_version': True},
                        {'message': 'SECRET'}, {'status': ['Accepted']}):
            with self.subTest(changes=changes), self.assertRaises(ReceiptError) as error:
                self.parse(self.receipt(**changes))
            self.assertNotIn('SECRET', str(error.exception))
        for payload in (PREFIX + b'{bad SECRET', PREFIX + b'[' + b'[' * 3000,
                        b'\n'.join([self.receipt()] * 5), b'SECRET' * 50000):
            with self.assertRaises(ReceiptError):
                self.parse(payload)

    def test_duplicate_and_missing_fields_are_refused_before_any_output(self):
        raw = self.receipt()
        duplicate = raw[:-1] + b',"status":"Accepted"}'
        for payload in (duplicate, PREFIX + b'{}', raw + b'\n' + PREFIX + b'{bad}'):
            with self.assertRaises(ReceiptError):
                self.parse(payload)

    def test_native_forwards_bound_receipt_on_success_and_failure(self):
        for returncode, status in ((0, 'Accepted'), (1, 'In Progress'), (1, 'Unavailable')):
            output = io.StringIO()
            result = types.SimpleNamespace(returncode=returncode, stdout=b'SECRET',
                stderr=b'private SECRET provider detail\n' + self.receipt(status=status))
            with patch.object(signing, 'run_owned', return_value=result), contextlib.redirect_stdout(output):
                if returncode:
                    with self.assertRaises(RuntimeError):
                        signing.native(['fixture'], operation='installer archive preparation',
                            env=dict(KITROVE_NOTARY_SOURCE_COMMIT=SOURCE, DIST_TARGET=TARGET))
                else:
                    signing.native(['fixture'], operation='installer archive preparation',
                        env=dict(KITROVE_NOTARY_SOURCE_COMMIT=SOURCE, DIST_TARGET=TARGET))
            self.assertIn(PREFIX.decode(), output.getvalue())
            self.assertIn(status, output.getvalue())
            self.assertNotIn('SECRET', output.getvalue())

    def test_native_refuses_receipt_with_wrong_context_before_forwarding(self):
        output = io.StringIO()
        result = types.SimpleNamespace(returncode=0, stdout=b'SECRET',
            stderr=self.receipt(source_commit='c' * 40))
        with patch.object(signing, 'run_owned', return_value=result), \
             contextlib.redirect_stdout(output), self.assertRaises(ReceiptError):
            signing.native(['fixture'], operation='installer archive preparation',
                env=dict(KITROVE_NOTARY_SOURCE_COMMIT=SOURCE, DIST_TARGET=TARGET))
        self.assertNotIn(PREFIX.decode(), output.getvalue())
        self.assertNotIn('SECRET', output.getvalue())

    def test_timeout_and_cancellation_forward_only_validated_captured_receipt(self):
        for error_type in (signing.ProcessTimeout, signing.ProcessCancelled):
            error = error_type('Native operation stopped')
            error._captured_stderr = b'private SECRET provider detail\n' + self.receipt()
            output = io.StringIO()
            with patch.object(signing, 'run_owned', side_effect=error), \
                 contextlib.redirect_stdout(output), self.assertRaises(RuntimeError):
                signing.native(['fixture'], operation='installer archive preparation',
                    env=dict(KITROVE_NOTARY_SOURCE_COMMIT=SOURCE, DIST_TARGET=TARGET))
            self.assertIn(PREFIX.decode(), output.getvalue())
            self.assertNotIn('SECRET', output.getvalue())

    @unittest.skipUnless(os.name == 'posix', 'owned processes require POSIX')
    def test_real_timeout_retains_safe_receipt_emitted_before_later_stall(self):
        # No native signer: emit a synthetic receipt and stall in a harmless child.
        fixture = 'import sys,time; sys.stderr.buffer.write(bytes.fromhex(sys.argv[1])); sys.stderr.flush(); time.sleep(10)'
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(RuntimeError):
            signing.native([sys.executable, '-c', fixture, self.receipt().hex()], timeout=0.3,
                operation='installer archive preparation',
                env=dict(KITROVE_NOTARY_SOURCE_COMMIT=SOURCE, DIST_TARGET=TARGET))
        self.assertIn(PREFIX.decode(), output.getvalue())
        self.assertIn('[timeout]', output.getvalue())


if __name__ == '__main__':
    unittest.main()
