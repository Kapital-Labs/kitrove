"""Closed nested-owner accounting, never native output or readiness authority."""
import json

PREFIX = b'KITROVE_APPLE_OWNER_V1 '
MAX_BYTES = 256 * 1024


class OwnerEvidenceError(RuntimeError):
    def __init__(self):
        super().__init__('Nested native owner evidence refused')


def require(value):
    if not value:
        raise OwnerEvidenceError()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def validate_owner_evidence(raw, *, succeeded):
    """Prove serial owner completion, not the tool's signature/ticket result."""
    require(type(raw) is bytes and len(raw) <= MAX_BYTES and type(succeeded) is bool)
    completed, active, count = 0, None, 0
    for line in raw.splitlines():
        if not line.startswith(b'KITROVE_APPLE_OWNER'):
            continue
        count += 1
        require(count <= 16 and line.startswith(PREFIX) and len(line) <= 8192)
        try:
            value = json.loads(line[len(PREFIX):], object_pairs_hook=unique)
            require(type(value) is dict and type(value.get('schema_version')) is int
                and value['schema_version'] == 1)
            event, ordinal = value.get('event'), value.get('ordinal')
            require(type(event) is str and event in ('start', 'finish'))
            require(type(ordinal) is int and 1 <= ordinal <= 8)
            if event == 'start':
                require(set(value) == {'schema_version', 'ordinal', 'event'})
                require(active is None and ordinal == completed + 1)
                active = ordinal
            else:
                require(set(value) == {'schema_version', 'ordinal', 'event', 'cleanup_confirmed'})
                require(active == ordinal and value['cleanup_confirmed'] is True)
                completed, active = ordinal, None
        except (ValueError, TypeError, KeyError, RecursionError, OwnerEvidenceError):
            raise OwnerEvidenceError() from None
    require(active is None and (not succeeded or completed > 0))
    return completed
