"""Synthetic evidence only: no processes, native tools or provider requests."""
import copy
import json
from pathlib import Path
import unittest

import hosted_apple_validation_evidence as evidence

SOURCE, IMAGE = 'a' * 40, 'b' * 64


def record():
    first = dict(attempt=1, started_ms=0, finished_ms=100, native_exit=68,
        cleanup_confirmed=True, output_bounded=True, evidence_complete=True,
        observations=['connection-lost'], native_error_codes=[dict(domain='NSURLErrorDomain', code=-1005)],
        http_statuses=[], backoff_requested_ms=1000)
    second = dict(attempt=2, started_ms=1100, finished_ms=1200, native_exit=0,
        cleanup_confirmed=True, output_bounded=True, evidence_complete=True,
        observations=[], native_error_codes=[], http_statuses=[], backoff_requested_ms=None)
    return dict(schema_version=2, source_commit=SOURCE, target='aarch64-apple-darwin',
        operation='validate', image_sha256=IMAGE, native_exit=0, output_bounded=True,
        elapsed_ms=1200, budget_ms=60000, result='validated', refusal=None, attempts=[first, second])


def raw(value):
    return evidence.PREFIX + json.dumps(value, separators=(',', ':')).encode()


class ValidationEvidenceTests(unittest.TestCase):
    def parse(self, value):
        lines = evidence.safe_lines(raw(value), source=SOURCE, image_sha256=IMAGE)
        self.assertEqual(len(lines), 1)
        return json.loads(lines[0].split(' ', 1)[1])

    def test_recovered_trace_keeps_original_loss_and_exact_context(self):
        value = self.parse(record())
        self.assertTrue(evidence.ticket_validated(value, source=SOURCE, image_sha256=IMAGE),
                        'V2 retry evidence is not implemented')
        self.assertEqual(value['attempts'][0]['native_exit'], 68)
        self.assertEqual(value['attempts'][1]['native_exit'], 0)
        self.assertEqual(value['image_sha256'], IMAGE)

    def test_shared_rust_producer_fixture_is_identical_and_accepted(self):
        fixture = Path(__file__).parent / 'fixtures/apple-ticket-validation-v2.json'
        value = json.loads(fixture.read_text())
        self.assertEqual(value, record())
        self.assertEqual(self.parse(value), value)

    def test_unknown_fields_duplicate_keys_and_private_canaries_are_refused(self):
        value = record()
        value['PRIVATE_PROVIDER_CANARY'] = '/private/synthetic account@example.invalid'
        for data in (raw(value), raw(record()).replace(b'"schema_version":2',
                b'"schema_version":2,"schema_version":2')):
            with self.assertRaises(RuntimeError) as caught:
                evidence.safe_lines(data, source=SOURCE)
            self.assertEqual(str(caught.exception), 'Validation evidence refused')

    def test_attempt_count_order_deadline_and_closed_types_are_strict(self):
        values = []
        for key, item in [('schema_version', True), ('budget_ms', 60001), ('elapsed_ms', 60001),
                ('target', 'x86_64-apple-darwin'), ('operation', 'staple'), ('native_exit', True),
                ('source_commit', 'c' * 40), ('image_sha256', 'not-a-digest')]:
            value = record(); value[key] = item; values.append(value)
        for key, item in [('attempt', 1), ('started_ms', 1099), ('cleanup_confirmed', False),
                ('backoff_requested_ms', 1000), ('native_exit', 68)]:
            value = record(); value['attempts'][1][key] = item; values.append(value)
        value = record(); value['attempts'] *= 2; values.append(value)
        value = record(); value['attempts'].reverse(); values.append(value)
        for index, value in enumerate(values):
            with self.subTest(case=index), self.assertRaises(RuntimeError): self.parse(value)

    def test_denial_unknown_error_and_uncertain_cleanup_cannot_precede_success(self):
        for key, item in [('native_exit', 65), ('evidence_complete', False), ('cleanup_confirmed', False),
                ('output_bounded', False), ('http_statuses', [503]),
                ('observations', ['connection-lost', 'missing-stapled-ticket']),
                ('native_error_codes', [dict(domain='NSURLErrorDomain', code=-1200)]),
                ('native_error_codes', [dict(domain='UnrecognizedDomain', code=-1005)])]:
            value = record(); value['attempts'][0][key] = item
            with self.subTest(field=key, item=item), self.assertRaises(RuntimeError): self.parse(value)

    def test_refused_trace_with_native_zero_is_not_final_ticket_success(self):
        value = record(); value.update(result='refused', refusal='identity')
        self.assertFalse(evidence.ticket_validated(self.parse(value), source=SOURCE, image_sha256=IMAGE))

    def test_exhausted_trace_retains_three_failures_and_no_fourth(self):
        value = record()
        first, second = value['attempts']
        second = copy.deepcopy(first)
        second.update(attempt=2, started_ms=1100, finished_ms=1200, backoff_requested_ms=2000)
        third = copy.deepcopy(first)
        third.update(attempt=3, started_ms=3200, finished_ms=3300, backoff_requested_ms=None)
        value.update(native_exit=68, result='refused', refusal='exhausted', elapsed_ms=3300,
                     attempts=[first, second, third])
        self.assertFalse(evidence.ticket_validated(self.parse(value), source=SOURCE, image_sha256=IMAGE))

    def test_unparsed_or_wrong_context_record_cannot_mint_ticket_success(self):
        for value, source, image in [({'result': 'validated', 'refusal': None}, SOURCE, IMAGE),
                (record(), 'c' * 40, IMAGE), (record(), SOURCE, 'c' * 64)]:
            with self.assertRaises(RuntimeError):
                evidence.ticket_validated(value, source=source, image_sha256=image)

    def test_signalled_but_confirmed_cleaned_child_is_still_not_ticket_success(self):
        value = record()
        attempt = value['attempts'][1]
        attempt.update(attempt=1, started_ms=0, finished_ms=100, native_exit=None)
        value.update(native_exit=None, elapsed_ms=100, attempts=[attempt], result='refused', refusal='denied')
        parsed = self.parse(value)
        self.assertTrue(parsed['attempts'][0]['cleanup_confirmed'])
        self.assertFalse(evidence.ticket_validated(parsed, source=SOURCE, image_sha256=IMAGE))

    def test_source_image_duplicate_lines_and_byte_bounds_refuse(self):
        data = raw(record())
        for payload, source, image in [(data, 'c' * 40, IMAGE), (data, SOURCE, 'c' * 64),
                (data + b'\n' + data, SOURCE, IMAGE), (b'x' * (256 * 1024 + 1), SOURCE, IMAGE)]:
            with self.assertRaises(RuntimeError):
                evidence.safe_lines(payload, source=source, image_sha256=image)

    def test_impossible_attempt_or_requested_backoff_reserve_never_mints_a_valid_trace(self):
        zero = record()
        last = copy.deepcopy(zero['attempts'][-1])
        last.update(attempt=1, started_ms=0, finished_ms=0)
        zero.update(attempts=[last], elapsed_ms=0, budget_ms=0)
        late = record()
        late['attempts'][0]['finished_ms'] = 40001
        late['attempts'][1].update(started_ms=41001, finished_ms=41002)
        late['elapsed_ms'] = 41002
        backoff = record()
        first = backoff['attempts'][0]
        first['finished_ms'] = 39500
        backoff.update(attempts=[first], native_exit=68, elapsed_ms=39500,
                       result='refused', refusal='interrupted')
        for value in (zero, late, backoff):
            with self.subTest(budget=value['budget_ms']), self.assertRaises(RuntimeError):
                self.parse(value)
