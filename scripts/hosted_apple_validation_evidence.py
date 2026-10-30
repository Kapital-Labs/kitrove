"""Closed V2 reporting and expected-source/image-bound ticket-phase checks."""
import json
import re

from hosted_apple_ticket import DOMAINS, OBSERVATIONS

PREFIX = b'KITROVE_APPLE_TICKET_V2 '
ROOT = frozenset(('schema_version', 'source_commit', 'target', 'operation', 'image_sha256',
    'native_exit', 'output_bounded', 'elapsed_ms', 'budget_ms', 'result', 'refusal', 'attempts'))
ATTEMPT = frozenset(('attempt', 'started_ms', 'finished_ms', 'native_exit', 'cleanup_confirmed',
    'output_bounded', 'evidence_complete', 'observations', 'native_error_codes', 'http_statuses',
    'backoff_requested_ms'))
REASONS = frozenset(('deadline', 'identity', 'interrupted', 'unconfirmed', 'denied', 'exhausted'))


def require(value):
    if not value:
        raise RuntimeError('Validation evidence refused')


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def native_exit(value):
    return value is None or integer(value, 0, 255)


def retryable(attempt):
    errors = {(item['domain'], item['code']) for item in attempt['native_error_codes']}
    observations = set(attempt['observations'])
    return (attempt['native_exit'] == 68 and attempt['cleanup_confirmed']
        and attempt['output_bounded'] and attempt['evidence_complete']
        and 'connection-lost' in observations
        and observations <= {'connection-lost', 'cloudkit-unexpected-response'}
        and ('NSURLErrorDomain', -1005) in errors
        and errors <= {('NSURLErrorDomain', -1005), ('kCFErrorDomainCFNetwork', -1005)}
        and not attempt['http_statuses'])


def check_attempt(item, number, elapsed):
    require(type(item) is dict and set(item) == ATTEMPT)
    require(integer(item['attempt'], 1, 3) and item['attempt'] == number)
    require(integer(item['started_ms'], 0, elapsed)
        and integer(item['finished_ms'], item['started_ms'], elapsed))
    require(native_exit(item['native_exit']))
    require(all(type(item[key]) is bool for key in ('cleanup_confirmed', 'output_bounded', 'evidence_complete')))
    observations = item['observations']
    require(type(observations) is list and all(type(v) is str
        and v in OBSERVATIONS | {'signature-denied'} for v in observations))
    require(observations == sorted(set(observations)))
    statuses = item['http_statuses']
    require(type(statuses) is list and len(statuses) <= 32
        and all(integer(v, 100, 599) for v in statuses))
    require(statuses == sorted(set(statuses)))
    errors = item['native_error_codes']
    require(type(errors) is list and len(errors) <= 32)
    for error in errors:
        require(type(error) is dict and set(error) == {'domain', 'code'})
        require(type(error['domain']) is str and error['domain'] in DOMAINS
            and integer(error['code'], -999999, 999999))
    keys = [(e['domain'], e['code']) for e in errors]
    require(keys == sorted(set(keys)))
    require(item['output_bounded'] or not (observations or statuses or errors or item['evidence_complete']))
    backoff = item['backoff_requested_ms']
    require(backoff is None or (number < 3 and type(backoff) is int and backoff == number * 1000))


def check_record(value, source, image_sha256):
    require(type(value) is dict and set(value) == ROOT)
    require(type(value['schema_version']) is int and value['schema_version'] == 2)
    require(value['source_commit'] == source and value['target'] == 'aarch64-apple-darwin'
        and value['operation'] == 'validate')
    require(type(value['image_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['image_sha256']))
    require(image_sha256 is None or value['image_sha256'] == image_sha256)
    require(native_exit(value['native_exit']) and type(value['output_bounded']) is bool)
    require(integer(value['budget_ms'], 0, 60000)
        and integer(value['elapsed_ms'], 0, value['budget_ms']))
    require(value['result'] in ('validated', 'refused'))
    require(value['refusal'] is None or (type(value['refusal']) is str and value['refusal'] in REASONS))
    attempts = value['attempts']
    require(type(attempts) is list and len(attempts) <= 3)
    for number, item in enumerate(attempts, 1):
        check_attempt(item, number, value['elapsed_ms'])
        # Millisecond flooring may erase a fractional positive margin; never
        # accept a record that could not retain the unchanged20s reserve.
        require(value['budget_ms'] - item['started_ms'] >= 20000)
        if item['backoff_requested_ms'] is not None:
            require(value['budget_ms'] - item['finished_ms'] >= 20000 + item['backoff_requested_ms'])
        if number > 1:
            previous = attempts[number - 2]
            require(retryable(previous) and previous['backoff_requested_ms'] == (number - 1) * 1000)
            require(item['started_ms'] >= previous['finished_ms'] + previous['backoff_requested_ms'])
    require(value['native_exit'] == (attempts[-1]['native_exit'] if attempts else None))
    require(value['output_bounded'] == (bool(attempts) and all(a['output_bounded'] for a in attempts)))
    if value['result'] == 'validated':
        require(value['refusal'] is None and bool(attempts) and value['native_exit'] == 0
            and attempts[-1]['cleanup_confirmed'] and value['output_bounded']
            and attempts[-1]['backoff_requested_ms'] is None)
    else:
        require(value['refusal'] is not None)
        if not attempts:
            require(value['refusal'] in ('deadline', 'identity', 'unconfirmed'))
        if value['refusal'] == 'exhausted':
            require(len(attempts) == 3 and retryable(attempts[-1])
                and attempts[-1]['backoff_requested_ms'] is None)
    if attempts and attempts[-1]['backoff_requested_ms'] is not None:
        require(value['result'] == 'refused' and retryable(attempts[-1]))


def safe_lines(raw, *, source, image_sha256=None):
    require(type(raw) is bytes and len(raw) <= 256 * 1024)
    lines = [line[len(PREFIX):] for line in raw.splitlines() if line.startswith(PREFIX)]
    if not lines:
        return []
    require(type(source) is str and re.fullmatch('[0-9a-f]{40}', source) and len(lines) == 1)
    require(image_sha256 is None or (type(image_sha256) is str and re.fullmatch('[0-9a-f]{64}', image_sha256)))
    require(len(lines[0]) <= 16 * 1024)
    try:
        value = json.loads(lines[0], object_pairs_hook=unique)
        check_record(value, source, image_sha256)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise RuntimeError('Validation evidence refused') from None
    return [PREFIX.decode() + json.dumps(value, separators=(',', ':'), sort_keys=True)]


def ticket_validated(record, *, source, image_sha256):
    # Ticket phase only. The caller must also require the complete verifier's0
    # and all original signature, image, payload and provenance gates.
    require(type(source) is str and re.fullmatch('[0-9a-f]{40}', source))
    require(type(image_sha256) is str and re.fullmatch('[0-9a-f]{64}', image_sha256))
    try:
        check_record(record, source, image_sha256)
    except (ValueError, TypeError, KeyError, RecursionError):
        raise RuntimeError('Validation evidence refused') from None
    return record['result'] == 'validated' and record['refusal'] is None
