"""Synthetic exact-call evidence; no Apple calls or credentials."""
import json
import unittest

try:
    import hosted_apple_ticket as ticket
except ImportError:
    ticket = None


class HostedAppleTicketTests(unittest.TestCase):
    def record(self):
        return dict(schema_version=1, source_commit='a' * 40, target='aarch64-apple-darwin',
            operation='staple', native_exit=68, elapsed_ms=123, output_bounded=True,
            observations=['connection-lost'], http_statuses=[503],
            native_error_codes=[dict(domain='NSURLErrorDomain', code=-1005)])

    def test_bridge_returns_only_closed_exact_source_arm_records(self):
        self.assertIsNotNone(ticket)
        line = b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(self.record()).encode()
        safe = ticket.safe_lines(b'PRIVATE_CANARY\n' + line, source='a' * 40)
        self.assertEqual(len(safe), 1)
        self.assertEqual(json.loads(safe[0].split(' ', 1)[1]), self.record())
        self.assertNotIn('PRIVATE_CANARY', safe[0])

    def test_bridge_refuses_unbound_unknown_duplicate_and_overlarge_records(self):
        self.assertIsNotNone(ticket)
        variants = [dict(self.record(), source_commit='b' * 40),
            dict(self.record(), target='x86_64-apple-darwin'),
            dict(self.record(), provider_message='PRIVATE_CANARY'),
            dict(self.record(), observations=['PRIVATE_CANARY']),
            dict(self.record(), native_error_codes=[dict(domain='PRIVATE_CANARY', code=1)]),
            dict(self.record(), http_statuses=[600]), dict(self.record(), native_exit=True),
            dict(self.record(), elapsed_ms=-1)]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                ticket.safe_lines(b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(value).encode(), source='a' * 40)
        line = b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(self.record()).encode()
        for raw in (line + b'\n' + line, b'x' * 262145,
                    line.replace(b'"native_exit": 68', b'"native_exit": 68, "native_exit": 0')):
            with self.assertRaises(RuntimeError):
                ticket.safe_lines(raw, source='a' * 40)

    def test_real_wrapper_keeps_primary_failure_after_closed_ticket_evidence(self):
        self.assertIsNotNone(ticket)
        import contextlib
        import io
        import types
        from unittest.mock import patch
        import hosted_apple_signing as signing
        line = b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(self.record()).encode()
        result = types.SimpleNamespace(returncode=1, stdout=b'PRIVATE_CANARY',
            stderr=line + b'\nxtask failed: Apple ticket stapling failed; no release archive was prepared [native-exit=68]')
        env = dict(KITROVE_APPLE_TICKET_DIAGNOSTIC='1', KITROVE_NOTARY_SOURCE_COMMIT='a' * 40,
                   DIST_TARGET='aarch64-apple-darwin')
        with patch.object(signing, 'run_owned', return_value=result), contextlib.redirect_stdout(io.StringIO()) as capture:
            with self.assertRaises(RuntimeError):
                signing.native(['never-called'], operation='installer container preparation', env=env)
        self.assertIn('KITROVE_APPLE_TICKET_V1 ', capture.getvalue())
        self.assertIn('[native-exit=68]', capture.getvalue())
        self.assertNotIn('PRIVATE_CANARY', capture.getvalue())

    def test_validation_cannot_precede_attachment_or_follow_failed_attachment(self):
        first = self.record()
        second = dict(first, operation='validate', native_exit=0)
        def raw(values):
            return b'\n'.join(b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(v).encode() for v in values)
        for values in ([second], [second, first], [first, second]):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                ticket.safe_lines(raw(values), source='a' * 40)
        self.assertEqual(len(ticket.safe_lines(raw([dict(first, native_exit=0), second]), source='a' * 40)), 2)

    def test_explicit_post_cleanup_phase_accepts_only_one_validation_not_attachment(self):
        value = dict(self.record(), operation='validate')
        raw = b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(value).encode()
        self.assertEqual(len(ticket.safe_lines(raw, source='a' * 40, validation_only=True)), 1)
        raw = b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(self.record()).encode()
        with self.assertRaises(RuntimeError):
            ticket.safe_lines(raw, source='a' * 40, validation_only=True)

    def test_v2_router_keeps_loss_and_refuses_downgraded_mixed_or_reordered_validation(self):
        from test_hosted_apple_validation_evidence import record, raw
        staple = dict(self.record(), native_exit=0)
        attached = b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(staple).encode()
        validation = raw(record())
        result = ticket.safe_lines(attached + b'\n' + validation, source='a' * 40,
                                   require_validation_v2=True)
        self.assertEqual([json.loads(line.split(' ', 1)[1])['schema_version'] for line in result], [1, 2])
        self.assertEqual(json.loads(result[1].split(' ', 1)[1])['attempts'][0]['native_exit'], 68)
        legacy = b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(dict(staple, operation='validate')).encode()
        for payload in (attached + b'\n' + legacy, validation + b'\n' + attached,
                        attached + b'\n' + validation + b'\n' + legacy,
                        attached + b'\n' + validation + b'\n' + validation,
                        b'KITROVE_APPLE_TICKET_V3 {}'):
            with self.subTest(payload=payload[:32]), self.assertRaises(RuntimeError):
                ticket.safe_lines(payload, source='a' * 40, require_validation_v2=True)
        self.assertEqual(len(ticket.safe_lines(attached + b'\n' + legacy, source='a' * 40)), 2,
                         'historical V1 inspection remains explicit and unchanged')

    def test_ordinary_preparation_forwards_v2_even_when_full_verifier_fails(self):
        import contextlib
        import io
        import types
        from unittest.mock import patch
        import hosted_apple_signing as signing
        from test_hosted_apple_validation_evidence import record, raw
        value = record()
        for status in (0, 1):
            result = types.SimpleNamespace(returncode=status, stdout=b'PRIVATE_CANARY', stderr=raw(value))
            env = dict(KITROVE_NOTARY_SOURCE_COMMIT='a' * 40, DIST_TARGET='aarch64-apple-darwin')
            with patch.object(signing, 'run_owned', return_value=result), contextlib.redirect_stdout(io.StringIO()) as capture:
                if status:
                    with self.assertRaises(RuntimeError):
                        signing.native(['never-called'], operation='installer container preparation', env=env)
                else:
                    signing.native(['never-called'], operation='installer container preparation', env=env)
            self.assertIn('KITROVE_APPLE_TICKET_V2 ', capture.getvalue())
            self.assertNotIn('PRIVATE_CANARY', capture.getvalue())
