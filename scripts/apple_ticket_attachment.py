"""Manual, credential-free ticket attachment on one existing diagnostic image."""
import hashlib
import json
import os
import platform
import re
import stat
import sys
import time
from datetime import datetime, timezone

import apple_ticket_attachment_input as intake
from apple_ticket_control import REQUIREMENT
from hosted_apple_process import ProcessTimeout, ProcessCancelled, ProcessCleanupError, run_owned

PHRASES = {
    'missing-stapled-ticket': b'does not have a ticket stapled',
    'ticket-validation-failed': b'could not validate ticket',
    'connection-lost': b'the network connection was lost',
    'network-timeout': b'the request timed out',
    'cloudkit-unexpected-response': b"cloudkit's response is inconsistent",
    'record-not-found': b'record not found',
    'native-staple-success-text': b'the staple and validate action worked',
    'native-validation-success-text': b'the validate action worked',
}

def classify(raw):
    if not isinstance(raw, bytes) or len(raw) > 256 * 1024:
        raise intake.Error('native-output-refused')
    return dict(observations=sorted(name for name, phrase in PHRASES.items() if phrase in raw.lower()),
        url_error_codes=sorted({int(code) for code in re.findall(rb'NSURLErrorDomain\s+Code=(-?[0-9]{1,5})\b', raw)}),
        http_statuses=sorted({int(code) for code in re.findall(rb'HTTP(?:\s+[Ss]tatus|/[123](?:\.[01])?)\s*[:=]?\s*([1-5][0-9]{2})\b', raw)}),
        native_error_codes=[{'domain': domain.decode('ascii'), 'code': int(code)}
            for domain, code in sorted(set(re.findall(
                rb'\b(NSURLErrorDomain|kCFErrorDomainCFNetwork|CKErrorDomain|CKInternalErrorDomain|NSCocoaErrorDomain|NSPOSIXErrorDomain|NSOSStatusErrorDomain)\s+Code=(-?[0-9]{1,6})\b', raw)))])

def run_attachment(directory, source, run_id, invoke):
    original = directory / 'image-original.dmg'
    initial = intake.snapshot(original)
    if initial[2] != intake.IMAGE_SHA or stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise intake.Error('binding-refused')
    record = dict(schema_version=1, control='existing-arm-ticket-attachment', consumer_source=source,
        consumer_run=run_id, producer_source=intake.PRODUCER_SOURCE, producer_run=intake.PRODUCER_RUN,
        artifact_id=intake.ARTIFACT_ID, input_sha256=intake.IMAGE_SHA, diagnostic_only=True,
        published=False, signing=False, new_submission=False, started_utc=datetime.now(timezone.utc).isoformat(),
        host_os=platform.mac_ver()[0], host_cpu=platform.machine(), stages=[], outcome='not-run')
    intake.write_new(directory / 'invocation.json', json.dumps(record, sort_keys=True).encode())
    copied = directory / 'image-copy.dmg'
    intake.write_new(copied, initial[0])
    if intake.snapshot(copied)[2] != intake.IMAGE_SHA:
        raise intake.Error('input-changed')
    env = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C', TMPDIR=str(directory))
    commands = (
        ('signature-before', ['/usr/bin/codesign', '--verify', '--strict', '-R', REQUIREMENT, str(copied)]),
        ('staple', ['/usr/bin/xcrun', 'stapler', 'staple', '-v', str(copied)]),
        ('signature-after', ['/usr/bin/codesign', '--verify', '--strict', '-R', REQUIREMENT, str(copied)]),
        ('validate', ['/usr/bin/xcrun', 'stapler', 'validate', '-v', str(copied)]),
    )
    try:
        for stage, command in commands:
            if intake.snapshot(original)[1:] != initial[1:]:
                raise intake.Error('input-changed')
            started = time.monotonic()
            completed = invoke(command, timeout=45, env=env)
            code = completed.returncode
            if type(code) is not int or not -255 <= code <= 255:
                raise intake.Error('native-status-refused')
            record['stages'].append(dict(stage=stage, native_exit=code,
                elapsed_seconds=round(time.monotonic() - started, 3),
                **classify(completed.stdout + b'\n' + completed.stderr)))
            if code != 0:
                record['outcome'] = stage + '-failed'
                break
        else:
            record['outcome'] = 'attached-and-validated'
    except ProcessTimeout:
        record['outcome'] = 'native-timeout'
    except ProcessCancelled:
        record['outcome'] = 'native-cancelled'
    except ProcessCleanupError:
        record['outcome'] = 'native-cleanup-unconfirmed'
    except OSError:
        record['outcome'] = 'native-launch-failed'
    finally:
        if intake.snapshot(original)[1:] != initial[1:]:
            raise intake.Error('input-changed')
        record['original_unchanged'] = True
    record['copy_sha256_after'] = intake.snapshot(copied)[2]
    record['copy_changed'] = record['copy_sha256_after'] != intake.IMAGE_SHA
    return record


def main():
    env = os.environ
    if sys.platform != 'darwin' or not intake.valid_context(env) or len(sys.argv) != 2 or sys.argv[1] not in ('fetch', 'attach'):
        raise intake.Error('invalid-context')
    checkout = run_owned(['/usr/bin/git', 'rev-parse', 'HEAD'], timeout=10,
                         env=dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C'))
    if checkout.returncode != 0 or checkout.stdout.strip() != env['GITHUB_SHA'].encode():
        raise intake.Error('invalid-context')
    if sys.argv[1] == 'fetch':
        intake.fetch(env)
        print('Pinned existing ARM input verified; no native ticket operation performed')
        return 0
    if env.get('GITHUB_TOKEN') or not intake.fresh(datetime.now(timezone.utc)):
        raise intake.Error('invalid-context')
    directory = intake.directory(env)
    data, _key, _digest = intake.snapshot(directory / 'input-binding.json')
    if intake.parse_json(data) != intake.binding(env):
        raise intake.Error('binding-refused')
    data, _key, digest = intake.snapshot(directory / 'diagnostic.json')
    if digest != intake.JSON_SHA:
        raise intake.Error('binding-refused')
    intake.validate_receipt(intake.parse_json(data))
    result = run_attachment(directory, env['GITHUB_SHA'], env['GITHUB_RUN_ID'], run_owned)
    print('KITROVE_ARM_ATTACHMENT_V1 ' + json.dumps(result, sort_keys=True))
    return 0 if result['outcome'] == 'attached-and-validated' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as error:
        category = str(error) if isinstance(error, intake.Error) and str(error) in {
            'invalid-context', 'metadata-refused', 'producer-refused', 'already-executed', 'zip-refused',
            'receipt-refused', 'download-refused', 'binding-refused', 'filesystem-refused', 'input-changed',
            'output-occupied', 'native-output-refused', 'native-status-refused'} else 'unclassified'
        print(json.dumps(dict(control='existing-arm-ticket-attachment', category=category, diagnostic_only=True)))
        raise SystemExit(1)
