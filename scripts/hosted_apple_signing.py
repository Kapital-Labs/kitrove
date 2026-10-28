"""Operator-only hosted Apple credential lifetime for existing archive preparation."""
import errno
import json
import os
import re
import select
import shlex
import shutil
import tempfile
import time
import sys
from contextlib import contextmanager
from pathlib import Path

from hosted_apple_process import (ProcessCancelled, ProcessCleanupError, ProcessTimeout,
    cancellation_scope, check_pending_cancellation, raise_if_cancelled, run_owned, stop_process_group)
from hosted_apple_receipts import ReceiptError, safe_receipt_lines, valid_source


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


OPERATIONS = frozenset(('identity import', 'Keychain cleanup',
    'Keychain search-list snapshot', 'Keychain search-list restoration',
    'application archive preparation', 'installer archive preparation', 'installer container preparation'))

# These match the reviewed xtask's fixed error labels, not provider diagnostics.
# Keep cleanup uncertainty first when an error contains both a primary failure
# and an unconfirmed detach. Output remains a constant category only.
DMG_FAILURE_MARKERS = (
    (b'dmg detach could not be confirmed', 'dmg-detach-unconfirmed'),
    (b'cannot remove empty dmg mountpoint', 'dmg-mountpoint-cleanup'),
    (b'installer disk image creation', 'dmg-create'),
    (b'apple container signing', 'dmg-sign'),
    (b'apple notarization returned an invalid result', 'notary-invalid-response'),
    (b'apple notarization was not accepted', 'notary-not-accepted'),
    (b'apple notarization (a timeout may leave a pending apple submission)', 'notary-submit-or-wait'),
    (b'apple ticket stapling', 'dmg-staple'),
    (b'apple ticket validation', 'dmg-staple-validation'),
    (b'apple signature and team verification', 'apple-signature-verification'),
    (b'apple signature inspection', 'apple-signature-inspection'),
    (b'disk image integrity verification', 'dmg-integrity'),
    (b'read-only dmg mount', 'dmg-mount'),
    (b'mounted dmg has an unexpected file inventory', 'dmg-payload-inventory'),
    (b'mounted dmg payload differs from prepared installer', 'dmg-payload-mismatch'),
    (b'dmg payload inventory changed', 'dmg-staged-inventory-changed'),
    (b'installer dmg payload changed', 'dmg-staged-payload-changed'),
    (b'cannot synchronize final dmg output', 'dmg-output-sync'),
    (b'cannot synchronize final dmg', 'dmg-image-sync'),
    (b'cannot create fresh dmg output directory', 'dmg-output-create'),
    (b'dmg output requires an absolute path with a canonical existing parent', 'dmg-output-path'),
)


def error_category(stderr):
    # Only these constant categories can leave the process. Never return a line,
    # substring, path, exception message or account value from provider output.
    lowered = stderr.lower()
    for marker, category in DMG_FAILURE_MARKERS + (
        (b'cannot open cargo-dist manifest directory:', 'manifest-directory'),
        (b'user interaction is not allowed', 'interaction-required'),
        (b'unable to build chain', 'certificate-chain'),
        (b'errsecinternalcomponent', 'security-internal'),
        (b'no identity found', 'identity-unavailable'),
        (b'the specified item could not be found', 'keychain-item-unavailable'),
        (b'timestamp service is not available', 'timestamp-service'),
    ):
        if marker in lowered:
            return category
    return 'unclassified-native-failure'


def ticket_failure_detail(stderr):
    """Forward only a complete fixed xtask ticket error, not provider diagnostics."""
    if not isinstance(stderr, bytes) or len(stderr) > 256 * 1024:
        return ''
    records = []
    for line in stderr.splitlines():
        match = re.fullmatch(
            rb'xtask failed: (?:Apple ticket (?:stapling|validation) failed; '
            rb'no release archive was prepared \[(native-exit=([1-9][0-9]{0,2})|native-termination)\]'
            rb'|cannot start Apple ticket (?:stapling|validation) '
            rb'\[(native-launch=(?:not-found|permission-denied|other))\])'
            rb'(?:; incomplete DMG output retained at [^\r\n]+)?', line)
        if match and (match[2] is None or int(match[2]) <= 255):
            records.append(match[1] or match[3])
    return ' [' + records[0].decode('ascii') + ']' if len(records) == 1 else ''


def forward_receipts(stderr, operation, env):
    if stderr is None or operation not in ('application archive preparation',
            'installer archive preparation', 'installer container preparation'):
        return
    context = env or {}
    try:
        receipts = safe_receipt_lines(stderr,
            source_commit=context.get('KITROVE_NOTARY_SOURCE_COMMIT'),
            target=context.get('DIST_TARGET'))
    except ReceiptError:
        print('Failed: ' + operation + ' [notary-receipt-invalid]', flush=True)
        raise
    for receipt in receipts:
        print(receipt, flush=True)


def native(args, payload=None, timeout=30, *, operation, env=None):
    require(operation in OPERATIONS, 'Unknown diagnostic operation')
    print('Starting: ' + operation, flush=True)
    try:
        result = run_owned(args, input=payload, timeout=timeout, env=env,
            ignore_prior_cancellation=operation in ('Keychain search-list restoration', 'Keychain cleanup'))
    except ProcessCleanupError as error:
        print('Failed: ' + operation + ' [process-cleanup-unconfirmed]', flush=True)
        print('Cleanup failure category: ' + error.category, flush=True)
        raise
    except ProcessCancelled as error:
        forward_receipts(getattr(error, '_captured_stderr', None), operation, env)
        print('Failed: ' + operation + ' [cancelled]', flush=True)
        raise
    except ProcessTimeout as error:
        forward_receipts(getattr(error, '_captured_stderr', None), operation, env)
        print('Failed: ' + operation + ' [timeout]', flush=True)
        raise RuntimeError('Native operation timed out') from None
    except OSError:
        print('Failed: ' + operation + ' [launch-failure]', flush=True)
        raise RuntimeError('Native operation could not start') from None
    forward_receipts(result.stderr, operation, env)
    if result.returncode != 0:
        detail = (ticket_failure_detail(result.stderr)
                  if operation == 'installer container preparation' else '')
        print('Failed: ' + operation + ' [' + error_category(result.stderr) + ']' + detail, flush=True)
        raise RuntimeError('Native operation failed')
    print('Passed: ' + operation, flush=True)
    return result


def authenticate(args, password):
    """Supply one password only after the native terminal disables echo."""
    require(password and '\n' not in password and '\r' not in password, 'Invalid credential')
    import pty
    import termios
    check_pending_cancellation()
    with cancellation_scope() as cancellation:
        check_pending_cancellation()
        _authenticate(args, password, pty, termios, cancellation)


def _authenticate(args, password, pty, termios, cancellation):
    pid, terminal = pty.fork()
    if pid == 0:
        try:
            # forkpty establishes a new session before executing the trusted tool.
            if os.getpgrp() != os.getpid():
                os._exit(1)
            os.execv('/usr/bin/xcrun', ['xcrun'] + args)
        finally:
            os._exit(1)
    output = bytearray()
    sent = False
    reaped = False
    deadline = time.monotonic() + 90
    try:
        while time.monotonic() < deadline:
            raise_if_cancelled(cancellation)
            if select.select([terminal], [], [], 0.1)[0]:
                try:
                    data = os.read(terminal, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    data = b''
                output.extend(data)
                require(len(output) <= 262144, 'Provider response exceeded limit')
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished:
                reaped = True
                require(sent and os.waitstatus_to_exitcode(status) == 0, 'Authentication failed')
                break
            if not sent and b'password' in output.lower():
                if not termios.tcgetattr(terminal)[3] & termios.ECHO:
                    payload = (password + '\n').encode()
                    require(os.write(terminal, payload) == len(payload), 'Incomplete credential input')
                    sent = True
        else:
            raise RuntimeError('Authentication timed out')
    finally:
        def reap():
            nonlocal reaped
            if not reaped:
                reaped = bool(os.waitpid(pid, os.WNOHANG)[0])
            return reaped

        try:
            stop_process_group(pid, reap)
        finally:
            os.close(terminal)
    raise_if_cancelled(cancellation)


@contextmanager
def signing_environment():
    require(sys.platform == 'darwin' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
        'Hosted Mac required')
    values = {name: os.environ.pop(name, '') for name in
        ('P12', 'P12_PASSWORD', 'APPLE_ID', 'TEAM_ID', 'NOTARY_PASSWORD')}
    require(all(values.values()) and values['TEAM_ID'] == '98RZ36ES7A', 'Credential setup invalid')
    runner = Path(os.environ['RUNNER_TEMP'])
    require(runner.is_absolute(), 'Absolute runner temporary directory required')
    snapshot = native(['/usr/bin/security', 'list-keychains', '-d', 'user'],
        operation='Keychain search-list snapshot').stdout
    original_keychains = shlex.split(snapshot.decode())
    require(original_keychains and all(Path(path).is_absolute() for path in original_keychains),
        'Invalid original Keychain search list')
    # Cleanup uncertainty must preserve this private directory: automatic temporary
    # directory deletion would race descendants that might still use the Keychain.
    directory = tempfile.mkdtemp(prefix='kitrove-release-signing-', dir=runner)
    cleanup_safe = True
    with cancellation_scope() as cancellation:
        keychain = Path(directory) / 'signing.keychain-db'
        try:
            native([str(runner / 'kitrove-apple-import')], json.dumps(dict(path=str(keychain),
                archive=values.pop('P12'), password=values.pop('P12_PASSWORD'))).encode(),
                operation='identity import')
            authenticate(['notarytool', 'store-credentials', 'kitrove-release',
                '--apple-id', values['APPLE_ID'], '--team-id', values['TEAM_ID'],
                '--keychain', str(keychain)], values.pop('NOTARY_PASSWORD'))
            child_env = dict(os.environ, KITROVE_NOTARY_PROFILE='kitrove-release',
                KITROVE_SIGNING_KEYCHAIN=str(keychain))
            yield child_env
        except ProcessCleanupError:
            cleanup_safe = False
            print('Failed: credential cleanup [process-cleanup-unconfirmed]', flush=True)
            raise
        finally:
            if cleanup_safe:
                try:
                    native(['/usr/bin/security', 'list-keychains', '-d', 'user', '-s'] + original_keychains,
                        operation='Keychain search-list restoration')
                except ProcessCleanupError:
                    cleanup_safe = False
                    raise
                finally:
                    if cleanup_safe:
                        if keychain.exists():
                            native(['/usr/bin/security', 'delete-keychain', str(keychain)], operation='Keychain cleanup')
                        require(not keychain.exists(), 'Temporary Keychain cleanup failed')
                        shutil.rmtree(directory)
        raise_if_cancelled(cancellation)


def prepare_release():
    container_mode = os.environ.get('KITROVE_PREPARE_DMG', '')
    require(container_mode in ('', '1'), 'Invalid container preparation mode')
    target = os.environ.get('DIST_TARGET', '')
    require(target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'), 'Unsupported Apple target')
    source = os.environ.get('GITHUB_SHA', '')
    require(valid_source(source), 'Invalid hosted source context')
    tag = os.environ.get('RELEASE_TAG', '')
    require(tag.startswith('v') and not any(char.isspace() for char in tag), 'Invalid release tag')
    runner = Path(os.environ['RUNNER_TEMP'])
    tool = runner / 'kitrove-release-xtask'
    # These are prebuilt reviewed tools, never product executables or caller-selected commands.
    for path in (tool, runner / 'kitrove-apple-import'):
        require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'Missing prebuilt signing tool')
    with signing_environment() as child_env:
        child_env['KITROVE_NOTARY_SOURCE_COMMIT'] = source
        for product, operation in (('kitrove-cli', 'application archive preparation'),
                                   ('kitrove-installer', 'installer archive preparation')):
            archive = f'target/distrib/{product}-{target}.tar.xz'
            native([str(tool), 'prepare-platform-release', archive, target, tag,
                'release/application-compatibility.json', 'dist-manifest.json'],
                operation=operation, env=child_env, timeout=1500)
        if container_mode == '1':
            native([str(tool), 'prepare-installer-dmg',
                f'target/distrib/kitrove-installer-{target}.tar.xz', target, tag,
                'dist-manifest.json', str(runner.resolve() / 'kitrove-installer-dmg')],
                operation='installer container preparation', env=child_env, timeout=1500)


if __name__ == '__main__':
    try:
        prepare_release()
    except Exception:
        print('Apple release preparation failed; provider diagnostics suppressed. No release published.')
        raise SystemExit(1)
