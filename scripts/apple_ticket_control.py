"""Manual hosted read-only control of two pinned public RC4.2 images, never signing."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import urllib.request
from urllib.parse import urlsplit

from hosted_apple_process import ProcessCancelled, ProcessCleanupError, ProcessTimeout, run_owned

MAX_IMAGE_BYTES = 16 * 1024 * 1024
IMAGES = (
    ('aarch64-apple-darwin', 'ee439d07703a45e3427f6d7c867653f9f15dc443d73a544bc891c968e002bda0'),
    ('x86_64-apple-darwin', '14d8fa5f8b4cb6c62c547b59a2604a814697e75c77aa1f0e05a591fd47472ed8'),
)
REQUIREMENT = ('=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
    'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
    'and certificate leaf[subject.OU] = "98RZ36ES7A"')


class ControlError(RuntimeError):
    def __init__(self, category):
        allowed = {'download-failed', 'download-refused', 'filesystem-failed',
            'control-bytes-changed', 'native-launch-failed', 'native-timeout',
            'native-cancelled', 'native-cleanup-unconfirmed'}
        self.category = category if category in allowed else 'unclassified'
        super().__init__(self.category)


def valid_context(env):
    expected = dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY='Kapital-Labs/kitrove',
        GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF='refs/heads/main',
        RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='macOS', RUNNER_ARCH='ARM64',
        GITHUB_WORKFLOW_REF='Kapital-Labs/kitrove/.github/workflows/apple-ticket-control.yml@refs/heads/main')
    return (all(env.get(key) == value for key, value in expected.items())
        and not env.get('KITROVE_HOSTED_SIGNING_READY'))


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != 'https':
            raise ControlError('download-refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_https(url):
    if urlsplit(url).scheme != 'https':
        raise ControlError('download-refused')
    return urllib.request.build_opener(HTTPSOnly()).open(url, timeout=30)


def download_image(target, digest, directory):
    if target not in {value[0] for value in IMAGES} or not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ControlError('download-refused')
    leaf = 'kitrove-installer-' + target + '.dmg'
    url = 'https://github.com/Kapital-Labs/kitrove/releases/download/v0.1.0-rc.4.2/' + leaf
    try:
        with open_https(url) as response:
            data = response.read(MAX_IMAGE_BYTES + 1)
    except Exception:
        raise ControlError('download-failed') from None
    if not data or len(data) > MAX_IMAGE_BYTES or hashlib.sha256(data).hexdigest() != digest:
        raise ControlError('download-refused')
    path = directory / leaf
    try:
        with path.open('xb') as output:
            output.write(data)
    except OSError:
        raise ControlError('filesystem-failed') from None
    return path


def identity(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_IMAGE_BYTES:
                raise ControlError('control-bytes-changed')
            data = source.read(MAX_IMAGE_BYTES + 1)
            after = os.fstat(source.fileno())
        leaf = path.lstat()
        evidence = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if evidence(before) != evidence(after) or evidence(after) != evidence(leaf) or len(data) != after.st_size:
            raise ControlError('control-bytes-changed')
        return evidence(after), hashlib.sha256(data).hexdigest()
    except OSError:
        raise ControlError('filesystem-failed') from None


def check_image(path, expected_digest=None):
    before = identity(path)
    if expected_digest != before[1]:
        raise ControlError('control-bytes-changed')
    result = {}
    commands = (
        ('signature', ['/usr/bin/codesign', '--verify', '--strict', '-R', REQUIREMENT, str(path)]),
        ('ticket', ['/usr/bin/xcrun', 'stapler', 'validate', '-q', str(path)]),
    )
    for stage, command in commands:
        try:
            completed = run_owned(command, timeout=45)
        except ProcessCleanupError:
            raise ControlError('native-cleanup-unconfirmed') from None
        except ProcessCancelled:
            raise ControlError('native-cancelled') from None
        except ProcessTimeout:
            raise ControlError('native-timeout') from None
        except OSError:
            raise ControlError('native-launch-failed') from None
        if identity(path) != before:
            raise ControlError('control-bytes-changed')
        code = completed.returncode
        result[stage] = code if type(code) is int and 0 <= code <= 255 else 'terminated'
        if result[stage] != 0:
            break
    return {**result, 'unchanged': True}


def main():
    source = os.environ.get('GITHUB_SHA', '')
    if len(sys.argv) != 1 or not valid_context(os.environ) or not re.fullmatch(r'[0-9a-f]{40}', source):
        print(json.dumps({'control': 'public-rc42-readonly', 'category': 'invalid-context'}))
        return 1
    # Retain only public control inputs until ephemeral-runner destruction, including
    # after unconfirmed process cleanup. Never traverse/delete a possibly active input.
    try:
        directory = Path(tempfile.mkdtemp(prefix='kitrove-public-ticket-control-'))
    except OSError:
        print(json.dumps({'control': 'public-rc42-readonly', 'category': 'filesystem-failed'}))
        return 1
    records = []
    for target, digest in IMAGES:
        try:
            path = download_image(target, digest, directory)
            result = check_image(path, digest)
        except ControlError as error:
            result = {'category': error.category}
        records.append(dict(target=target, sha256=digest, **result))
        if result.get('category') in ('native-cancelled', 'native-cleanup-unconfirmed'):
            break
    print(json.dumps(dict(schema_version=1, control='public-rc42-readonly', source_commit=source, host_arch='ARM64',
        results=records), sort_keys=True))
    return 0 if all(value.get('signature') == 0 and value.get('ticket') == 0
                    and value.get('unchanged') is True for value in records) else 1


if __name__ == '__main__':
    raise SystemExit(main())
