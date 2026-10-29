"""Synthetic artifact intake tests; never downloads or invokes Apple tools."""
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError
import warnings
import zipfile

import apple_ticket_attachment_input as intake


class AttachmentInputTests(unittest.TestCase):
    def context(self):
        return dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY='Kapital-Labs/kitrove',
            GITHUB_REPOSITORY_ID='1360443188', GITHUB_EVENT_NAME='workflow_dispatch',
            GITHUB_REF='refs/heads/main', RUNNER_ENVIRONMENT='github-hosted',
            RUNNER_OS='macOS', RUNNER_ARCH='ARM64', GITHUB_ACTOR='brandon-kaplan',
            GITHUB_SHA='a' * 40, GITHUB_RUN_ID='1234', GITHUB_RUN_ATTEMPT='1',
            GITHUB_WORKFLOW_REF='Kapital-Labs/kitrove/.github/workflows/apple-ticket-attachment.yml@refs/heads/main')

    def metadata(self):
        return dict(id=intake.ARTIFACT_ID, name=intake.ARTIFACT_NAME,
            size_in_bytes=5122054, digest='sha256:' + intake.ZIP_SHA, expired=False,
            expires_at='2026-10-29T23:26:37Z', workflow_run=dict(id=40786138222,
                head_branch='main', head_sha=intake.PRODUCER_SOURCE,
                repository_id=1360443188, head_repository_id=1360443188))

    def zipped(self, entries):
        data = io.BytesIO()
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', message="Duplicate name: 'diagnostic.json'", category=UserWarning)
            with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for entry, body in entries:
                    archive.writestr(entry, body)
        return data.getvalue()

    def test_context_is_manual_main_actor_attempt_one_only(self):
        valid = self.context()
        self.assertTrue(intake.valid_context(valid))
        for field, value in ((key, 'wrong') for key in valid):
            with self.subTest(field=field):
                self.assertFalse(intake.valid_context({**valid, field: value}))
        for flag in ('KITROVE_HOSTED_SIGNING_READY', 'KITROVE_SIGNING_REHEARSAL_SHA'):
            self.assertFalse(intake.valid_context({**valid, flag: 'enabled'}))

    def test_metadata_binds_exact_producer_and_expiry(self):
        value = self.metadata()
        now = datetime(2026, 10, 29, 15, tzinfo=timezone.utc)
        self.assertIsNone(intake.validate_metadata(value, now))
        for key, bad in (('id', 42), ('name', 'other'), ('size_in_bytes', 0),
                         ('digest', 'sha256:' + '0' * 64), ('expired', True),
                         ('expires_at', '2026-11-01T00:00:00Z')):
            with self.subTest(key=key), self.assertRaises(intake.Error):
                intake.validate_metadata({**value, key: bad}, now)
        for key in value['workflow_run']:
            changed = copy.deepcopy(value)
            changed['workflow_run'][key] = 'wrong'
            with self.subTest(producer_key=key), self.assertRaises(intake.Error):
                intake.validate_metadata(changed, now)
        with self.assertRaises(intake.Error):
            intake.validate_metadata(value, datetime(2026, 10, 30, tzinfo=timezone.utc))

    def test_only_first_manual_workflow_run_can_fetch(self):
        env = self.context()
        run = dict(id=1234, head_sha=env['GITHUB_SHA'], run_attempt=1, head_branch='main',
                   event='workflow_dispatch', path='.github/workflows/apple-ticket-attachment.yml')
        self.assertIsNone(intake.validate_single_run(dict(total_count=1, workflow_runs=[run]), env))
        for count, runs in ((0, []), (2, [run, run]), (1, [{**run, 'run_attempt': 2}]),
                            (1, [{**run, 'head_sha': 'b' * 40}]), (1, [{**run, 'id': 999}])):
            with self.subTest(count=count, runs=runs), self.assertRaises(intake.Error):
                intake.validate_single_run(dict(total_count=count, workflow_runs=runs), env)

    def test_producer_attempt_and_source_are_exact(self):
        record = dict(id=40786138222, run_attempt=1, head_sha=intake.PRODUCER_SOURCE,
            head_branch='main', event='workflow_dispatch', status='completed', conclusion='failure',
            path='.github/workflows/apple-ticket-diagnostic.yml')
        self.assertIsNone(intake.validate_producer(record))
        for key in record:
            with self.subTest(key=key), self.assertRaises(intake.Error):
                intake.validate_producer({**record, key: 'wrong'})

    def test_bounded_zip_never_extracts_paths(self):
        data = self.zipped([('diagnostic.json', b'{}'), (intake.IMAGE_NAME, b'image')])
        self.assertEqual(intake.unpack_bounded(data), {'diagnostic.json': b'{}', intake.IMAGE_NAME: b'image'})
        for name in ('../image.dmg', '/absolute.dmg', 'nested/image.dmg', 'extra', 'diagnostic.json'):
            data = self.zipped([('diagnostic.json', b'{}'), (intake.IMAGE_NAME, b'image'), (name, b'x')])
            with self.subTest(name=name), self.assertRaises(intake.Error):
                intake.unpack_bounded(data)

    def test_symlinks_and_oversize_members_refuse(self):
        symlink = zipfile.ZipInfo(intake.IMAGE_NAME)
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for image, body in ((symlink, b'target'), (intake.IMAGE_NAME, b'x' * (intake.MAX_IMAGE + 1))):
            data = self.zipped([('diagnostic.json', b'{}'), (image, body)])
            with self.subTest(symlink=not isinstance(image, str)), self.assertRaises(intake.Error):
                intake.unpack_bounded(data)

    def test_zip_and_component_digests_are_not_optional(self):
        with self.assertRaises(intake.Error):
            intake.decode_archive(self.zipped([('diagnostic.json', b'{}'), (intake.IMAGE_NAME, b'image')]))

    def test_decode_positive_requires_both_pinned_components_and_accepted_receipt(self):
        image = b'synthetic image'
        image_sha = hashlib.sha256(image).hexdigest()
        metadata = json.dumps(dict(source=intake.PRODUCER_SOURCE, target='aarch64-apple-darwin',
            cleanup_confirmed=True, diagnostic_only=True, published=False, image_sha256=image_sha,
            receipts=[dict(status='Accepted', source_commit=intake.PRODUCER_SOURCE,
                           target='aarch64-apple-darwin', artifact_sha256=image_sha)])).encode()
        data = self.zipped([('diagnostic.json', metadata), (intake.IMAGE_NAME, image)])
        pins = dict(IMAGE_SHA=image_sha, JSON_SHA=hashlib.sha256(metadata).hexdigest(),
                    ZIP_SHA=hashlib.sha256(data).hexdigest(), ZIP_SIZE=len(data))
        with mock.patch.multiple(intake, **pins, create=True):
            self.assertEqual(intake.decode_archive(data)[intake.IMAGE_NAME], image)
            with mock.patch.object(intake, 'JSON_SHA', '0' * 64), self.assertRaises(intake.Error):
                intake.decode_archive(data)
            with mock.patch.object(intake, 'IMAGE_SHA', '0' * 64), self.assertRaises(intake.Error):
                intake.decode_archive(data)

    def test_native_step_also_refuses_after_expiry(self):
        self.assertTrue(intake.fresh(datetime(2026, 10, 29, 23, 26, 36, tzinfo=timezone.utc)))
        self.assertFalse(intake.fresh(datetime(2026, 10, 29, 23, 26, 37, tzinfo=timezone.utc)))

    def test_duplicate_json_keys_refuse(self):
        with self.assertRaises(intake.Error):
            intake.parse_json(b'{"source":1,"source":2}')

    @unittest.skipUnless(os.name == 'posix', 'POSIX bounded file intake')
    def test_snapshots_refuse_links_and_exclusive_writes_preserve_existing(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root).resolve()
            original = directory / 'original'
            intake.write_new(original, b'bytes')
            self.assertEqual(intake.snapshot(original)[2], hashlib.sha256(b'bytes').hexdigest())
            with self.assertRaises(intake.Error):
                intake.write_new(original, b'changed')
            linked = directory / 'linked'
            linked.symlink_to(original)
            with self.assertRaises(intake.Error):
                intake.snapshot(linked)
            self.assertEqual(original.read_bytes(), b'bytes')

    def test_accepted_receipt_must_match_exact_retained_image(self):
        record = dict(source=intake.PRODUCER_SOURCE, target='aarch64-apple-darwin',
            cleanup_confirmed=True, diagnostic_only=True, published=False,
            image_sha256=intake.IMAGE_SHA, receipts=[dict(status='Accepted',
                source_commit=intake.PRODUCER_SOURCE, target='aarch64-apple-darwin',
                artifact_sha256=intake.IMAGE_SHA)])
        self.assertIsNone(intake.validate_receipt(record))
        for key, bad in (('source', '0' * 40), ('target', 'x86_64-apple-darwin'),
                         ('cleanup_confirmed', False), ('published', True)):
            with self.subTest(key=key), self.assertRaises(intake.Error):
                intake.validate_receipt({**record, key: bad})
        for receipts in ([], record['receipts'] * 2, [{**record['receipts'][0], 'status': 'In Progress'}]):
            with self.assertRaises(intake.Error):
                intake.validate_receipt({**record, 'receipts': receipts})

    def test_redirect_cannot_leak_token_or_downgrade(self):
        self.assertTrue(intake.valid_blob_url('https://productionresultssa1.blob.core.windows.net/a?opaque=not-printed'))
        for url in ('http://productionresultssa1.blob.core.windows.net/a',
                    'https://evil.example/a', 'https://user:secret@productionresultssa1.blob.core.windows.net/a',
                    'https://productionresultssa1.blob.core.windows.net.evil.example/a',
                    'https://productionresultssa1.blob.core.windows.net:444/a'):
            with self.subTest(url=url):
                self.assertFalse(intake.valid_blob_url(url))

    def test_api_token_is_not_forwarded_to_blob(self):
        calls = []
        class Response(io.BytesIO):
            def getcode(self):
                return 200
        class Opener:
            def open(self, request, timeout):
                calls.append(request)
                if len(calls) == 1:
                    raise HTTPError(request.full_url, 302, 'SECRET',
                        {'Location': 'https://productionresultssa1.blob.core.windows.net/a?opaque=SECRET'}, io.BytesIO())
                return Response(b'zip bytes')
        result = intake.api_bytes(intake.ARTIFACT_PATH + '/zip', 'TOKEN_CANARY', 20, Opener())
        self.assertEqual(result, b'zip bytes')
        self.assertEqual(calls[0].get_header('Authorization'), 'Bearer TOKEN_CANARY')
        self.assertIsNone(calls[1].get_header('Authorization'))

    def test_download_errors_refuse_without_echo_or_fallback(self):
        calls = []
        class Opener:
            def open(self, request, timeout):
                calls.append(request)
                raise HTTPError(request.full_url, 500, 'SECRET_TOKEN /SECRET_PATH', {}, io.BytesIO())
        with self.assertRaises(intake.Error) as error:
            intake.api_bytes(intake.ARTIFACT_PATH, 'TOKEN_CANARY', 20, Opener())
        self.assertNotIn('SECRET', str(error.exception))
        self.assertEqual(len(calls), 1)

    def test_download_does_not_accept_arbitrary_api_path(self):
        with self.assertRaises(intake.Error):
            intake.api_bytes('/repos/other/repo/actions/artifacts/1/zip', 'TOKEN_CANARY', 20)

    @unittest.skipUnless(os.name == 'posix', 'POSIX private input staging')
    def test_fetch_authenticates_before_writing_and_never_runs_native_tools(self):
        env = self.context()
        own_run = dict(id=1234, head_sha=env['GITHUB_SHA'], run_attempt=1, head_branch='main',
                      event='workflow_dispatch', path=intake.WORKFLOW)
        producer = dict(id=intake.PRODUCER_RUN, run_attempt=1, head_sha=intake.PRODUCER_SOURCE,
            head_branch='main', event='workflow_dispatch', status='completed', conclusion='failure',
            path='.github/workflows/apple-ticket-diagnostic.yml')
        image = b'synthetic image'
        image_sha = hashlib.sha256(image).hexdigest()
        receipt = json.dumps(dict(source=intake.PRODUCER_SOURCE, target='aarch64-apple-darwin',
            cleanup_confirmed=True, diagnostic_only=True, published=False, image_sha256=image_sha,
            receipts=[dict(status='Accepted', source_commit=intake.PRODUCER_SOURCE,
                           target='aarch64-apple-darwin', artifact_sha256=image_sha)])).encode()
        archive = self.zipped([('diagnostic.json', receipt), (intake.IMAGE_NAME, image)])
        pins = dict(IMAGE_SHA=image_sha, JSON_SHA=hashlib.sha256(receipt).hexdigest(),
                    ZIP_SHA=hashlib.sha256(archive).hexdigest(), ZIP_SIZE=len(archive))
        metadata = self.metadata()
        metadata.update(size_in_bytes=len(archive), digest='sha256:' + pins['ZIP_SHA'])
        replies = {intake.RUNS_PATH: json.dumps(dict(total_count=1, workflow_runs=[own_run])).encode(),
            intake.RUN_PATH: json.dumps(producer).encode(), intake.ARTIFACT_PATH: json.dumps(metadata).encode(),
            intake.ARTIFACT_PATH + '/zip': archive}
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as root:
                run_env = dict(env, RUNNER_TEMP=str(Path(root).resolve()), GITHUB_TOKEN='TOKEN_CANARY')
                def api(path, token, limit):
                    self.assertEqual(token, 'TOKEN_CANARY')
                    result = replies[path]
                    return result + b'corrupt' if corrupt and path.endswith('/zip') else result
                with mock.patch.multiple(intake, **pins), mock.patch.object(intake, 'api_bytes', side_effect=api), \
                        mock.patch.object(intake, 'fresh', return_value=True):
                    if corrupt:
                        with self.assertRaises(intake.Error):
                            intake.fetch(run_env)
                        self.assertFalse(intake.directory(run_env).exists())
                    else:
                        intake.fetch(run_env)
                        output = intake.directory(run_env)
                        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                        self.assertEqual((output / 'image-original.dmg').read_bytes(), image)
                        self.assertEqual(intake.parse_json((output / 'input-binding.json').read_bytes()), intake.binding(run_env))
                        self.assertFalse((output / 'image-copy.dmg').exists())
                self.assertNotIn('GITHUB_TOKEN', run_env)


if __name__ == '__main__':
    unittest.main()
