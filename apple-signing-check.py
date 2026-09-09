"""One operator-approved hosted rehearsal; never signs or executes product code."""
import errno
import json
import os
import pty
import select
import signal
import subprocess
import tempfile
import termios
import time
from pathlib import Path

IDENTITY = 'Developer ID Application: Kapital Labs LLC (98RZ36ES7A)'
REQUIREMENT = ('=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
               'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
               'and certificate leaf[subject.OU] = "98RZ36ES7A"')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def native(args, payload=None, timeout=30):
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout, check=False)
    require(result.returncode == 0, 'Native operation failed')
    return result


def authenticate(args, password):
    """Supply one password only after the native terminal disables echo."""
    require(password and '\n' not in password and '\r' not in password, 'Invalid credential')
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


def rehearse():
    require(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'Hosted runner required')
    values = {name: os.environ.pop(name, '') for name in
        ('P12', 'P12_PASSWORD', 'APPLE_ID', 'TEAM_ID', 'NOTARY_PASSWORD')}
    require(all(values.values()) and values['TEAM_ID'] == '98RZ36ES7A', 'Credential setup invalid')
    runner = Path(os.environ['RUNNER_TEMP'])
    require(runner.is_absolute(), 'Absolute runner temporary directory required')
    with tempfile.TemporaryDirectory(prefix='kitrove-native-check-', dir=runner) as directory:
        root = Path(directory)
        keychain = root / 'signing.keychain-db'
        try:
            native([str(runner / 'import-identity')], json.dumps(dict(path=str(keychain),
                archive=values.pop('P12'), password=values.pop('P12_PASSWORD'))).encode())
            print('Temporary Keychain imported; ambient selectors restored.', flush=True)
            authenticate(['notarytool', 'store-credentials', 'kitrove-rehearsal',
                '--apple-id', values['APPLE_ID'], '--team-id', values['TEAM_ID'],
                '--keychain', str(keychain)], values.pop('NOTARY_PASSWORD'))
            print('Notarization profile stored and validated in temporary Keychain.', flush=True)
            executable = root / 'kitrove-signing-test'
            # The fixed harmless fixture was compiled before secrets were exposed.
            executable.write_bytes((runner / 'kitrove-signing-test').read_bytes())
            executable.chmod(0o700)
            native(['/usr/bin/codesign', '--force', '--sign', IDENTITY, '--keychain',
                str(keychain), '--options', 'runtime', '--timestamp', str(executable)], timeout=90)
            native(['/usr/bin/codesign', '--verify', '--strict', '-R', REQUIREMENT, str(executable)])
            detail = native(['/usr/bin/codesign', '--display', '--verbose=4', str(executable)]).stderr.decode()
            require(any(line.startswith('Timestamp=') and len(line) > 10 for line in detail.splitlines()),
                'Secure timestamp absent')
            require(any(line.startswith('CodeDirectory ') and '(runtime)' in line for line in detail.splitlines()),
                'Hardened runtime absent')
            print('Test executable signed and exact team, runtime and timestamp verified.', flush=True)
            archive = root / 'notary.zip'
            native(['/usr/bin/ditto', '-c', '-k', str(executable), str(archive)])
            response = native(['/usr/bin/xcrun', 'notarytool', 'submit', str(archive),
                '--keychain-profile', 'kitrove-rehearsal', '--keychain', str(keychain),
                '--wait', '--timeout', '10m', '--output-format', 'json'], timeout=660)
            submission = json.loads(response.stdout)
            require(submission.get('status') == 'Accepted' and submission.get('id'), 'Notarization not accepted')
            print('Test executable notarization Accepted. No product code executed or release published.', flush=True)
        finally:
            # The path belongs only to this unique directory. Never delete another
            # Keychain or an ambient store, even after an import failure.
            if keychain.exists():
                native(['/usr/bin/security', 'delete-keychain', str(keychain)])
            require(not keychain.exists(), 'Temporary Keychain cleanup failed')
            print('Temporary signing Keychain removed.', flush=True)


if __name__ == '__main__':
    try:
        rehearse()
    except Exception:
        print('Signing rehearsal failed; provider diagnostics suppressed. No release published.')
        raise SystemExit(1)
