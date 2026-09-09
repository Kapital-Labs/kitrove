"""Operator-only hosted Apple credential lifetime for existing archive preparation."""
import errno
import json
import os
import select
import shlex
import signal
import subprocess
import tempfile
import time
import sys
from contextlib import contextmanager
from pathlib import Path



def require(condition, message):
    if not condition:
        raise RuntimeError(message)


OPERATIONS = frozenset(('identity import', 'Keychain cleanup',
    'Keychain search-list snapshot', 'Keychain search-list restoration',
    'application archive preparation', 'installer archive preparation'))


def error_category(stderr):
    # Only these constant categories can leave the process. Never return a line,
    # substring, path, exception message or account value from provider output.
    lowered = stderr.lower()
    for marker, category in (
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


def native(args, payload=None, timeout=30, *, operation, env=None):
    require(operation in OPERATIONS, 'Unknown diagnostic operation')
    print('Starting: ' + operation, flush=True)
    try:
        result = subprocess.run(args, input=payload, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired:
        print('Failed: ' + operation + ' [timeout]', flush=True)
        raise RuntimeError('Native operation timed out') from None
    except OSError:
        print('Failed: ' + operation + ' [launch-failure]', flush=True)
        raise RuntimeError('Native operation could not start') from None
    if result.returncode != 0:
        print('Failed: ' + operation + ' [' + error_category(result.stderr) + ']', flush=True)
        raise RuntimeError('Native operation failed')
    print('Passed: ' + operation, flush=True)
    return result


def authenticate(args, password):
    """Supply one password only after the native terminal disables echo."""
    require(password and '\n' not in password and '\r' not in password, 'Invalid credential')
    import pty
    import termios
    pid, terminal = pty.fork()
    if pid == 0:
        try:
            os.execv('/usr/bin/xcrun', ['xcrun'] + args)
        finally:
            os._exit(1)
    output = bytearray()
    sent = False
    reaped = False
    deadline = time.monotonic() + 90
    try:
        while time.monotonic() < deadline:
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
                return
            if not sent and b'password' in output.lower():
                if not termios.tcgetattr(terminal)[3] & termios.ECHO:
                    payload = (password + '\n').encode()
                    require(os.write(terminal, payload) == len(payload), 'Incomplete credential input')
                    sent = True
        raise RuntimeError('Authentication timed out')
    finally:
        if not reaped:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(terminal)


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
    with tempfile.TemporaryDirectory(prefix='kitrove-release-signing-', dir=runner) as directory:
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
        finally:
            try:
                native(['/usr/bin/security', 'list-keychains', '-d', 'user', '-s'] + original_keychains,
                    operation='Keychain search-list restoration')
            finally:
                if keychain.exists():
                    native(['/usr/bin/security', 'delete-keychain', str(keychain)], operation='Keychain cleanup')
            require(not keychain.exists(), 'Temporary Keychain cleanup failed')


def prepare_release():
    target = os.environ.get('DIST_TARGET', '')
    require(target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'), 'Unsupported Apple target')
    tag = os.environ.get('RELEASE_TAG', '')
    require(tag.startswith('v') and not any(char.isspace() for char in tag), 'Invalid release tag')
    runner = Path(os.environ['RUNNER_TEMP'])
    tool = runner / 'kitrove-release-xtask'
    # These are prebuilt reviewed tools, never product executables or caller-selected commands.
    for path in (tool, runner / 'kitrove-apple-import'):
        require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'Missing prebuilt signing tool')
    with signing_environment() as child_env:
        for product, operation in (('kitrove-cli', 'application archive preparation'),
                                   ('kitrove-installer', 'installer archive preparation')):
            archive = f'target/distrib/{product}-{target}.tar.xz'
            native([str(tool), 'prepare-platform-release', archive, target, tag,
                'release/application-compatibility.json', 'dist-manifest.json'],
                operation=operation, env=child_env, timeout=1500)


if __name__ == '__main__':
    try:
        prepare_release()
    except Exception:
        print('Apple release preparation failed; provider diagnostics suppressed. No release published.')
        raise SystemExit(1)
