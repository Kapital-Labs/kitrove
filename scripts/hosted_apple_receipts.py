"""Closed, redacted bridge for reviewed xtask notarization receipt records."""
import json
import re
import uuid


PREFIX = b'KITROVE_NOTARY_RECEIPT_V1 '
MAX_STDERR_BYTES = 256 * 1024
MAX_RECORD_BYTES = 2048
MAX_RECORDS = 4
TARGETS = frozenset(('aarch64-apple-darwin', 'x86_64-apple-darwin'))
STATUSES = frozenset(('Accepted', 'Invalid', 'Rejected', 'In Progress', 'Unavailable'))


class ReceiptError(RuntimeError):
    def __init__(self):
        super().__init__('Notarization receipt evidence is invalid')


def valid_source(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value) is not None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError()
        result[key] = value
    return result


def safe_receipt_lines(stderr, *, source_commit, target):
    """Validate every recognized record before returning any printable lines.

    Provider messages outside the fixed prefix are discarded. No raw exception,
    account value, provider message or path may be returned by this function.
    """
    if not isinstance(stderr, bytes) or len(stderr) > MAX_STDERR_BYTES:
        raise ReceiptError()
    records = [line[len(PREFIX):] for line in stderr.splitlines() if line.startswith(PREFIX)]
    if not records:
        return []
    if len(records) > MAX_RECORDS or not valid_source(source_commit) or target not in TARGETS:
        raise ReceiptError()
    output = []
    for record in records:
        if len(record) > MAX_RECORD_BYTES:
            raise ReceiptError()
        try:
            receipt = json.loads(record, object_pairs_hook=_unique_object)
            if not isinstance(receipt, dict) or set(receipt) != {
                'schema_version', 'submission_id', 'status', 'artifact_sha256',
                'target', 'source_commit',
            }:
                raise ReceiptError()
            if type(receipt['schema_version']) is not int or receipt['schema_version'] != 1:
                raise ReceiptError()
            identifier = receipt['submission_id']
            if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
                raise ReceiptError()
            if not isinstance(receipt['status'], str) or receipt['status'] not in STATUSES:
                raise ReceiptError()
            digest = receipt['artifact_sha256']
            if not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None:
                raise ReceiptError()
            if receipt['source_commit'] != source_commit or receipt['target'] != target:
                raise ReceiptError()
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ReceiptError() from None
        output.append(PREFIX.decode('ascii') + json.dumps(receipt, separators=(',', ':'), sort_keys=True))
    return output
