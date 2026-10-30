"""Portable closed owner-evidence tests; no native launch or provider request."""
import importlib
import importlib.util
import json
from pathlib import Path
import unittest

PREFIX = b'KITROVE_APPLE_OWNER_V1 '


def record(event, ordinal=1, **extra):
    value = dict(schema_version=1, ordinal=ordinal, event=event)
    if event == 'finish':
        value['cleanup_confirmed'] = True
    value.update(extra)
    return PREFIX + json.dumps(value).encode() + b'\n'


class OwnerEvidenceTests(unittest.TestCase):
    def test_rust_producer_golden_corpus_is_accepted_without_schema_relaxation(self):
        corpus = json.loads((Path(__file__).parent / 'fixtures/apple-owner-v1.json').read_text())
        self.assertEqual(len(corpus), 16)
        self.assertEqual(self.owner().validate_owner_evidence(
            ('\n'.join(corpus) + '\n').encode(), succeeded=True), 8)

    def owner(self):
        self.assertIsNotNone(importlib.util.find_spec('hosted_apple_owner'),
            'closed nested-owner evidence boundary is missing')
        return importlib.import_module('hosted_apple_owner')

    def test_balanced_evidence_is_cleanup_only_not_tool_success(self):
        owner = self.owner()
        raw = record('start') + record('finish') + record('start', 2) + record('finish', 2)
        self.assertEqual(owner.validate_owner_evidence(raw, succeeded=True), 2)
        self.assertEqual(owner.validate_owner_evidence(raw, succeeded=False), 2)
        self.assertEqual(owner.validate_owner_evidence(b'ordinary failure', succeeded=False), 0)
        with self.assertRaises(owner.OwnerEvidenceError):
            owner.validate_owner_evidence(b'', succeeded=True)

    def test_unknown_unbalanced_duplicate_and_out_of_order_records_refuse(self):
        owner = self.owner()
        invalid = [record('start'), record('finish'), record('start', 2),
            record('start') + record('start', 2),
            record('start') + record('finish', 2),
            record('start') + record('finish') + record('finish'),
            record('start') + record('finish') + record('start'),
            record('start') + record('finish', cleanup_confirmed=False),
            record('start', True), record('start', 0), record('start', 9),
            record('start', account='PRIVATE_CANARY'),
            b'KITROVE_APPLE_OWNER_V2 {}\n',
            PREFIX + b'{"schema_version":1,"ordinal":1,"ordinal":2,"event":"start"}\n']
        for raw in invalid:
            with self.subTest(raw_case=invalid.index(raw)), self.assertRaises(owner.OwnerEvidenceError):
                owner.validate_owner_evidence(raw, succeeded=False)

    def test_bounds_types_and_private_text_do_not_escape_errors(self):
        owner = self.owner()
        invalid = [b'x' * (256 * 1024 + 1), PREFIX + b'x' * 8193,
            PREFIX + b'PRIVATE_CANARY /private/path',
            record('start', schema_version=True), record('finish', cleanup_confirmed=1)]
        for raw in invalid:
            with self.assertRaises(owner.OwnerEvidenceError) as caught:
                owner.validate_owner_evidence(raw, succeeded=False)
            self.assertEqual(str(caught.exception), 'Nested native owner evidence refused')
            self.assertNotIn('PRIVATE_', repr(caught.exception))
            self.assertNotIn('/private', repr(caught.exception))
        for raw, succeeded in [('text', False), (b'', 0), (None, True)]:
            with self.assertRaises(owner.OwnerEvidenceError):
                owner.validate_owner_evidence(raw, succeeded=succeeded)

    def test_eight_serial_owners_are_bounded_and_native_text_is_ignored(self):
        owner = self.owner()
        raw = b'PRIVATE_PROVIDER_CANARY\n' + b''.join(
            record('start', i) + record('finish', i) for i in range(1, 9))
        self.assertEqual(owner.validate_owner_evidence(raw, succeeded=True), 8)
        with self.assertRaises(owner.OwnerEvidenceError):
            owner.validate_owner_evidence(raw + record('start', 9) + record('finish', 9), succeeded=True)


if __name__ == '__main__':
    unittest.main()
