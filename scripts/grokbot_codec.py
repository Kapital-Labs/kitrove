"""Closed data boundary for the operator-only Grok command-server pilot."""
import json
import math
import re

MAX_FRAME = 16 * 1024
MAX_OUTPUT = 256 * 1024
TARGETS = ('claude', 'codex', 'pi', 'opencode')
_CODES = frozenset(('invalid_json', 'invalid_request', 'invalid_arguments',
    'invalid_result', 'unsupported_content', 'config_invalid', 'platform_unsupported',
    'cli_changed', 'cli_refused', 'cli_error_unrecognized', 'cli_launch_failed',
    'output_limit', 'timeout', 'cancelled', 'cleanup_unconfirmed', 'transport_closed',
    'transport_limit', 'recovery_or_unknown_state', 'internal'))


class PilotError(Exception):
    def __init__(self, code, *, cli_code=None, fatal=False):
        if code.removeprefix('pilot.') not in _CODES or not code.startswith('pilot.'):
            code, fatal, cli_code = 'pilot.internal', True, None
        self.code, self.cli_code, self.fatal = code, cli_code, fatal
        super().__init__(code)


def fail(code='invalid_result', *, fatal=False):
    raise PilotError('pilot.' + code, fatal=fatal)


def closed(value, required, optional=()):
    if (type(value) is not dict or not set(required) <= value.keys()
            or not value.keys() <= set(required) | set(optional)):
        fail()
    return value


def identifier(value):
    if type(value) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,95}', value):
        fail('invalid_arguments')
    if '..' in value:
        fail('invalid_arguments')
    return value


def digest(value):
    if type(value) is not str or not re.fullmatch(r'blake3:[0-9a-f]{64}', value):
        fail()


def decode(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out: fail('invalid_json')
            out[key] = value
        return out

    def nonfinite(_value):
        fail('invalid_json')

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=nonfinite)
        if type(value) is not dict: fail('invalid_json')
        pending = [(value, 0)]
        nodes = 0
        while pending:
            item, depth = pending.pop(); nodes += 1
            if depth > 32 or nodes > 8192: fail('invalid_json')
            if type(item) is float and not math.isfinite(item): fail('invalid_json')
            if type(item) is dict: pending.extend((v, depth+1) for v in item.values())
            elif type(item) is list: pending.extend((v, depth+1) for v in item)
        return value
    except (UnicodeError, ValueError, RecursionError):
        fail('invalid_json')


def count(value):
    if type(value) is not int or not 0 <= value <= 4096: fail()
    return value


def sequence(value, limit=128):
    if type(value) is not list or len(value) > limit: fail()
    return value
