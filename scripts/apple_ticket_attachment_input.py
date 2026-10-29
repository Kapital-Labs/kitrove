"""Pinned existing diagnostic input, never a release or signing authority."""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from urllib.error import HTTPError
from urllib.parse import urlsplit
import urllib.request
import zipfile

ARTIFACT_ID = 12860420656
ARTIFACT_NAME = 'apple-diagnostic-evidence-aarch64-apple-darwin-40786138222-1'
PRODUCER_SOURCE = 'd9ece29286888c35e0df98680830fe43f0fbe399'
ZIP_SHA = 'ede0cddda73a19c5929632230a24c846638b8469ce1533967108d1c375d9672a'
IMAGE_SHA = 'fc0dd09fd58de0e38a55abd31512232f54c53ab690bd0dc0e9cd9accadaeef12'
IMAGE_NAME = 'kitrove-installer-aarch64-apple-darwin.dmg'
MAX_IMAGE = 16 * 1024 * 1024
MAX_JSON = 32 * 1024
MAX_ZIP = 20 * 1024 * 1024
ZIP_SIZE = 5122054
JSON_SHA = '97dea4422b4eaca3ad2aba0d47805a9e40f5b66b7665fcc9354294f0f4828ee0'
EXPIRY = '2026-10-29T23:26:37Z'
WORKFLOW = '.github/workflows/apple-ticket-attachment.yml'
PRODUCER_RUN = 40786138222
REPOSITORY_ID = 1360443188
ARTIFACT_PATH = '/repos/Kapital-Labs/kitrove/actions/artifacts/' + str(ARTIFACT_ID)
RUN_PATH = '/repos/Kapital-Labs/kitrove/actions/runs/' + str(PRODUCER_RUN)
RUNS_PATH = '/repos/Kapital-Labs/kitrove/actions/workflows/apple-ticket-attachment.yml/runs?event=workflow_dispatch&per_page=2'

class Error(RuntimeError):
    pass

def valid_context(env):
    expected = dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY='Kapital-Labs/kitrove',
        GITHUB_REPOSITORY_ID=str(REPOSITORY_ID), GITHUB_EVENT_NAME='workflow_dispatch',
        GITHUB_REF='refs/heads/main', RUNNER_ENVIRONMENT='github-hosted',
        RUNNER_OS='macOS', RUNNER_ARCH='ARM64', GITHUB_ACTOR='brandon-kaplan',
        GITHUB_RUN_ATTEMPT='1', GITHUB_WORKFLOW_REF='Kapital-Labs/kitrove/' + WORKFLOW + '@refs/heads/main')
    return (all(env.get(key) == value for key, value in expected.items())
        and isinstance(env.get('GITHUB_SHA'), str)
        and re.fullmatch('[0-9a-f]{40}', env['GITHUB_SHA']) is not None
        and isinstance(env.get('GITHUB_RUN_ID'), str)
        and re.fullmatch('[1-9][0-9]{0,19}', env['GITHUB_RUN_ID']) is not None
        and not any(env.get(flag) for flag in ('KITROVE_HOSTED_SIGNING_READY', 'KITROVE_SIGNING_REHEARSAL_SHA')))

def validate_metadata(value, now):
    expected = dict(id=ARTIFACT_ID, name=ARTIFACT_NAME, size_in_bytes=ZIP_SIZE,
                    digest='sha256:' + ZIP_SHA, expires_at=EXPIRY)
    if not isinstance(value, dict) or any(value.get(key) != expected for key, expected in expected.items()) or value.get('expired') is not False:
        raise Error('metadata-refused')
    expected_run = dict(id=PRODUCER_RUN, head_branch='main', head_sha=PRODUCER_SOURCE,
                        repository_id=REPOSITORY_ID, head_repository_id=REPOSITORY_ID)
    run = value.get('workflow_run')
    if not isinstance(run, dict) or any(run.get(key) != expected for key, expected in expected_run.items()):
        raise Error('metadata-refused')
    if not fresh(now):
        raise Error('metadata-refused')

def validate_single_run(value, env):
    if (not isinstance(value, dict) or type(value.get('total_count')) is not int
            or value['total_count'] != 1 or not isinstance(value.get('workflow_runs'), list)
            or len(value['workflow_runs']) != 1):
        raise Error('already-executed')
    run = value['workflow_runs'][0]
    expected = dict(id=int(env['GITHUB_RUN_ID']), head_sha=env['GITHUB_SHA'],
        run_attempt=1, head_branch='main', event='workflow_dispatch', path=WORKFLOW)
    if (not isinstance(run, dict) or type(run.get('run_attempt')) is not int
            or any(run.get(key) != expected for key, expected in expected.items())):
        raise Error('already-executed')


def validate_producer(value):
    expected = dict(id=PRODUCER_RUN, run_attempt=1, head_sha=PRODUCER_SOURCE,
        head_branch='main', event='workflow_dispatch', status='completed', conclusion='failure',
        path='.github/workflows/apple-ticket-diagnostic.yml')
    if (not isinstance(value, dict) or type(value.get('run_attempt')) is not int
            or any(value.get(key) != expected for key, expected in expected.items())):
        raise Error('producer-refused')

def unpack_bounded(data):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_ZIP:
        raise Error('zip-refused')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) != 2 or {item.filename for item in entries} != {'diagnostic.json', IMAGE_NAME}:
                raise Error('zip-refused')
            result = {}
            for item in entries:
                kind = stat.S_IFMT(item.external_attr >> 16)
                limit = MAX_JSON if item.filename == 'diagnostic.json' else MAX_IMAGE
                if (item.is_dir() or kind not in (0, stat.S_IFREG) or item.create_system not in (0, 3)
                        or item.flag_bits & 1 or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or not 0 < item.file_size <= limit or not 0 <= item.compress_size <= MAX_ZIP):
                    raise Error('zip-refused')
                with archive.open(item) as source:
                    content = source.read(limit + 1)
                if len(content) != item.file_size or len(content) > limit:
                    raise Error('zip-refused')
                result[item.filename] = content
            return result
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
        raise Error('zip-refused') from None

def decode_archive(data):
    if len(data) != ZIP_SIZE or hashlib.sha256(data).hexdigest() != ZIP_SHA:
        raise Error('zip-refused')
    result = unpack_bounded(data)
    if (hashlib.sha256(result[IMAGE_NAME]).hexdigest() != IMAGE_SHA
            or hashlib.sha256(result['diagnostic.json']).hexdigest() != JSON_SHA):
        raise Error('zip-refused')
    try:
        record = json.loads(result['diagnostic.json'])
        validate_receipt(record)
    except (ValueError, TypeError):
        raise Error('receipt-refused') from None
    return result


def fresh(now):
    return now < datetime(2026, 10, 29, 23, 26, 37, tzinfo=timezone.utc)

def validate_receipt(value):
    expected = dict(source=PRODUCER_SOURCE, target='aarch64-apple-darwin', image_sha256=IMAGE_SHA)
    if (not isinstance(value, dict) or any(value.get(key) != expected for key, expected in expected.items())
            or value.get('cleanup_confirmed') is not True or value.get('diagnostic_only') is not True
            or value.get('published') is not False or not isinstance(value.get('receipts'), list)):
        raise Error('receipt-refused')
    matching = [receipt for receipt in value['receipts'] if isinstance(receipt, dict)
                and receipt.get('artifact_sha256') == IMAGE_SHA]
    if len(matching) != 1 or any(matching[0].get(key) != expected for key, expected in
            dict(status='Accepted', source_commit=PRODUCER_SOURCE, target='aarch64-apple-darwin').items()):
        raise Error('receipt-refused')

def valid_blob_url(value):
    try:
        parsed = urlsplit(value)
        return (parsed.scheme == 'https' and parsed.port in (None, 443)
            and parsed.username is None and parsed.password is None and not parsed.fragment
            and re.fullmatch(r'productionresultssa[0-9]+\.blob\.core\.windows\.net', parsed.hostname or '') is not None)
    except (ValueError, TypeError):
        return False

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_bytes(path, token, limit, opener=None):
    if (path not in (ARTIFACT_PATH, ARTIFACT_PATH + '/zip', RUN_PATH, RUNS_PATH)
            or not isinstance(token, str) or not token or len(token) > 8192
            or any(character in token for character in ('\r', '\n'))):
        raise Error('download-refused')
    client = opener or urllib.request.build_opener(NoRedirect())
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
               'User-Agent': 'Kitrove-existing-image-diagnostic', 'X-GitHub-Api-Version': '2022-11-28'}
    request = urllib.request.Request('https://api.github.com' + path, headers=headers)
    try:
        try:
            response = client.open(request, timeout=30)
        except HTTPError as error:
            location = error.headers.get('Location') if error.headers else None
            redirected = path == ARTIFACT_PATH + '/zip' and error.code == 302 and valid_blob_url(location)
            error.close()
            if not redirected:
                raise Error('download-refused') from None
            # This is a fresh request, not forwarding GitHub Authorization.
            response = client.open(urllib.request.Request(location,
                headers={'User-Agent': 'Kitrove-existing-image-diagnostic'}), timeout=30)
        with response:
            if response.getcode() != 200:
                raise Error('download-refused')
            result = response.read(limit + 1)
        if not result or len(result) > limit:
            raise Error('download-refused')
        return result
    except Exception:
        raise Error('download-refused') from None


def parse_json(data):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise Error('binding-refused')
            result[name] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, TypeError):
        raise Error('binding-refused') from None


def snapshot(path):
    key = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                        info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    try:
        if not path.is_absolute() or path.parent.resolve() != path.parent:
            raise Error('filesystem-refused')
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with os.fdopen(os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                   dir_fd=parent), 'rb') as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_IMAGE:
                    raise Error('filesystem-refused')
                data = source.read(MAX_IMAGE + 1)
                after = os.fstat(source.fileno())
                named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if key(before) != key(after) or key(after) != key(named) or len(data) != before.st_size:
                raise Error('input-changed')
            return data, key(named), hashlib.sha256(data).hexdigest()
        finally:
            os.close(parent)
    except OSError:
        raise Error('filesystem-refused') from None


def write_new(path, data):
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        raise Error('output-occupied') from None


def directory(env):
    root = Path(env.get('RUNNER_TEMP', ''))
    if not root.is_absolute() or root.resolve() != root or not root.is_dir():
        raise Error('filesystem-refused')
    return root / 'kitrove-existing-arm-ticket'


def binding(env):
    return dict(schema_version=1, consumer_source=env['GITHUB_SHA'], consumer_run=env['GITHUB_RUN_ID'],
        producer_source=PRODUCER_SOURCE, producer_run=PRODUCER_RUN, artifact_id=ARTIFACT_ID,
        zip_sha256=ZIP_SHA, image_sha256=IMAGE_SHA, diagnostic_sha256=JSON_SHA)


def fetch(env):
    if not valid_context(env):
        raise Error('invalid-context')
    token = env.pop('GITHUB_TOKEN', '')
    # There is no native child or token handoff in this fetch process.
    one_run = parse_json(api_bytes(RUNS_PATH, token, 128 * 1024))
    validate_single_run(one_run, env)
    validate_producer(parse_json(api_bytes(RUN_PATH, token, 128 * 1024)))
    validate_metadata(parse_json(api_bytes(ARTIFACT_PATH, token, 128 * 1024)), datetime.now(timezone.utc))
    files = decode_archive(api_bytes(ARTIFACT_PATH + '/zip', token, MAX_ZIP))
    token = None
    output = directory(env)
    try:
        output.mkdir(mode=0o700)
    except OSError:
        raise Error('output-occupied') from None
    write_new(output / 'image-original.dmg', files[IMAGE_NAME])
    write_new(output / 'diagnostic.json', files['diagnostic.json'])
    write_new(output / 'input-binding.json', json.dumps(binding(env), sort_keys=True).encode())
