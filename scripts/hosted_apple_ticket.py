"""Closed bridge for actual preparation-call ticket evidence; never raw output."""
import json
import re

PREFIX = b'KITROVE_APPLE_TICKET_V1 '
DOMAINS = frozenset(('NSURLErrorDomain', 'kCFErrorDomainCFNetwork', 'CKErrorDomain',
    'CKInternalErrorDomain', 'NSCocoaErrorDomain', 'NSPOSIXErrorDomain', 'NSOSStatusErrorDomain'))
OBSERVATIONS = frozenset(('missing-stapled-ticket', 'ticket-validation-failed', 'connection-lost',
    'network-timeout', 'cloudkit-unexpected-response', 'record-not-found',
    'native-staple-success-text', 'native-validation-success-text'))

def require(value):
    if not value:
        raise RuntimeError('Ticket diagnostic evidence refused')

def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value

def safe_lines(raw, *, source, validation_only=False, require_validation_v2=False):
    """Route explicit versions; legacy inspection never supplies fresh V2 authority."""
    require(type(validation_only) is bool and type(require_validation_v2) is bool)
    require(type(raw) is bytes and len(raw) <= 256 * 1024)
    from hosted_apple_validation_evidence import PREFIX as V2, safe_lines as validation_lines
    markers = [line for line in raw.splitlines() if line.startswith(b'KITROVE_APPLE_TICKET_')]
    require(all(line.startswith((PREFIX, V2)) for line in markers))
    if not any(line.startswith(V2) for line in markers):
        legacy = legacy_lines(raw, source=source, validation_only=validation_only)
        if require_validation_v2:
            require(all(json.loads(line.split(' ', 1)[1])['operation'] == 'staple' for line in legacy))
        return legacy
    validations = validation_lines(raw, source=source)
    require(len(validations) == 1)
    if validation_only:
        require(len(markers) == 1 and markers[0].startswith(V2))
        return validations
    require(len(markers) == 2 and markers[0].startswith(PREFIX) and markers[1].startswith(V2))
    attachment = legacy_lines(markers[0], source=source)
    require(len(attachment) == 1 and json.loads(attachment[0].split(' ', 1)[1])['native_exit'] == 0)
    return attachment + validations


def legacy_lines(raw, *, source, validation_only=False):
    require(type(validation_only) is bool)
    require(isinstance(raw, bytes) and len(raw) <= 256 * 1024)
    lines = [line[len(PREFIX):] for line in raw.splitlines() if line.startswith(PREFIX)]
    if not lines:
        return []
    require(isinstance(source, str) and re.fullmatch('[0-9a-f]{40}', source) is not None and len(lines) <= 2)
    result, operations = [], set()
    for line in lines:
        require(len(line) <= 8192)
        try:
            value = json.loads(line, object_pairs_hook=unique)
            require(type(value) is dict and set(value) == {'schema_version', 'source_commit', 'target',
                'operation', 'native_exit', 'elapsed_ms', 'output_bounded', 'observations',
                'native_error_codes', 'http_statuses'})
            require(type(value['schema_version']) is int and value['schema_version'] == 1)
            require(value['source_commit'] == source and value['target'] == 'aarch64-apple-darwin')
            operation = value['operation']
            require(type(operation) is str and operation in ('staple', 'validate') and operation not in operations)
            operations.add(operation)
            code = value['native_exit']
            require(code is None or (type(code) is int and 0 <= code <= 255))
            require(type(value['elapsed_ms']) is int and 0 <= value['elapsed_ms'] <= 1500000)
            require(type(value['output_bounded']) is bool)
            observations = value['observations']
            require(type(observations) is list and all(type(v) is str and v in OBSERVATIONS for v in observations))
            require(observations == sorted(set(observations)))
            statuses = value['http_statuses']
            require(type(statuses) is list and len(statuses) <= 32 and all(type(v) is int and 100 <= v <= 599 for v in statuses))
            require(statuses == sorted(set(statuses)))
            errors = value['native_error_codes']
            require(type(errors) is list and len(errors) <= 32)
            for error in errors:
                require(type(error) is dict and set(error) == {'domain', 'code'})
                require(type(error['domain']) is str and error['domain'] in DOMAINS)
                require(type(error['code']) is int and -999999 <= error['code'] <= 999999)
            keys = [(e['domain'], e['code']) for e in errors]
            require(keys == sorted(set(keys)))
            require(value['output_bounded'] or not (observations or statuses or errors))
        except (ValueError, TypeError, KeyError, RecursionError):
            raise RuntimeError('Ticket diagnostic evidence refused') from None
        result.append(PREFIX.decode() + json.dumps(value, separators=(',', ':'), sort_keys=True))
    decoded = [json.loads(line.split(' ', 1)[1]) for line in result]
    if validation_only:
        require([value['operation'] for value in decoded] == ['validate'])
    else:
        require([value['operation'] for value in decoded] in (['staple'], ['staple', 'validate']))
        require(len(decoded) == 1 or decoded[0]['native_exit'] == 0)
    return result
