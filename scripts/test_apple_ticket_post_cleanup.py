"""Actual post-cleanup errors stay distinct from preparation; no provider calls."""
import contextlib
import ast
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import apple_ticket_diagnostic as diagnostic


class PostCleanupEvidence(unittest.TestCase):
    def test_copy_fixtures_declare_posix_but_pure_verifier_stays_cross_platform(self):
        tree = ast.parse(Path(__file__).read_text())
        methods = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        for name in ('test_complete_success_requires_preparation_and_final_ticket_evidence',
                     'test_actual_post_cleanup_ticket_error_is_retained_without_raw_text'):
            guards = [d for d in methods[name].decorator_list if isinstance(d, ast.Call)
                and ast.unparse(d.func) == 'unittest.skipUnless' and d.args
                and ast.unparse(d.args[0]) == "os.name == 'posix'"]
            self.assertEqual(len(guards), 1, 'POSIX descriptor fixture must declare its platform')
        self.assertEqual(methods['test_final_container_check_forwards_its_actual_validation_record_without_signing'].decorator_list, [])

    @unittest.skipUnless(os.name == 'posix', 'POSIX-only diagnostic')
    def test_complete_success_requires_preparation_and_final_ticket_evidence(self):
        for missing in (True, False):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                images = root / 'runner/kitrove-installer-dmg'
                images.mkdir(parents=True)
                (images / 'kitrove-installer-aarch64-apple-darwin.dmg').write_bytes(b'fixture')
                def record(operation):
                    return dict(schema_version=1, source_commit='a' * 40, target='aarch64-apple-darwin',
                        operation=operation, native_exit=0, elapsed_ms=1, output_bounded=True,
                        observations=[], http_statuses=[], native_error_codes=[])
                def prepare(*, cleanup_observer):
                    if not missing:
                        for operation in ('staple', 'validate'):
                            print('KITROVE_APPLE_TICKET_V1 ' + json.dumps(record(operation)))
                    cleanup_observer()
                commands = []
                def native(args, **kwargs):
                    commands.append(args)
                    stderr = b''
                    if 'verify-installer-dmg' in args:
                        stderr = b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(record('validate')).encode()
                    return types.SimpleNamespace(returncode=0, stdout=b'', stderr=stderr)
                prior = Path.cwd()
                try:
                    os.chdir(root)
                    with patch.dict(os.environ, RUNNER_TEMP=str(root / 'runner'), RELEASE_TAG='v0.1.0-rc.5.3'), \
                         patch.object(diagnostic.signing, 'prepare_release', side_effect=prepare), \
                         patch.object(diagnostic, 'run_owned', side_effect=native), \
                         contextlib.redirect_stdout(io.StringIO()):
                        status = diagnostic.sign('aarch64-apple-darwin', 'a' * 40)
                    self.assertEqual(status, 1 if missing else 0)
                    result = json.loads((root / 'diagnostic-evidence/diagnostic.json').read_text())
                    self.assertEqual(result['post_cleanup_container_ticket_calls'], [record('validate')])
                    self.assertEqual(sum('verify-installer-dmg' in args for args in commands), 1)
                    self.assertFalse(result['published'])
                finally:
                    os.chdir(prior)

    @unittest.skipUnless(os.name == 'posix', 'POSIX-only diagnostic')
    def test_actual_post_cleanup_ticket_error_is_retained_without_raw_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            images = root / 'runner/kitrove-installer-dmg'
            images.mkdir(parents=True)
            leaf = 'kitrove-installer-aarch64-apple-darwin.dmg'
            (images / leaf).write_bytes(b'fixture, never mounted or executed')
            def prepare(*, cleanup_observer):
                self.assertEqual(os.environ['KITROVE_APPLE_TICKET_DIAGNOSTIC'], '1')
                cleanup_observer()
                raise RuntimeError('PRIVATE_CANARY')
            def native(args, **kwargs):
                self.assertNotIn('KITROVE_APPLE_TICKET_DIAGNOSTIC', os.environ)
                if args[0] == '/usr/bin/xcrun':
                    return types.SimpleNamespace(returncode=65, stdout=b'PRIVATE_CANARY',
                        stderr=b'NSURLErrorDomain Code=-1005 The network connection was lost /private/SECRET')
                return types.SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
            prior = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, RUNNER_TEMP=str(root / 'runner')), \
                     patch.object(diagnostic.signing, 'prepare_release', side_effect=prepare), \
                     patch.object(diagnostic, 'run_owned', side_effect=native), \
                     contextlib.redirect_stdout(io.StringIO()) as capture:
                    self.assertEqual(diagnostic.sign('aarch64-apple-darwin', 'a' * 40), 1)
                record = json.loads((root / 'diagnostic-evidence/diagnostic.json').read_text())
                self.assertEqual(record.get('post_cleanup_ticket_call', {}).get('native_error_codes'),
                    [dict(domain='NSURLErrorDomain', code=-1005)])
                self.assertFalse(record['preparation_succeeded'])
                self.assertNotIn('PRIVATE_CANARY', json.dumps(record) + capture.getvalue())
                self.assertNotIn('SECRET', json.dumps(record) + capture.getvalue())
            finally:
                os.chdir(prior)

    def test_final_container_check_forwards_its_actual_validation_record_without_signing(self):
        function = getattr(diagnostic, 'native_container_status', None)
        self.assertIsNotNone(function, 'final native ticket evidence is missing')
        for status in (0, 68):
            value = dict(schema_version=1, source_commit='a' * 40, target='aarch64-apple-darwin',
                operation='validate', native_exit=status, elapsed_ms=123, output_bounded=True,
                observations=[], http_statuses=[], native_error_codes=[])
            result = types.SimpleNamespace(returncode=0 if status == 0 else 1, stdout=b'PRIVATE_CANARY',
                stderr=b'KITROVE_APPLE_TICKET_V1 ' + json.dumps(value).encode())
            args = ['/trusted/source-tool', 'verify-installer-dmg', 'fixture']
            with patch.object(diagnostic, 'run_owned', return_value=result) as owned:
                code, records = function(args, 'a' * 40)
            self.assertEqual(code, result.returncode)
            self.assertEqual(records, [value])
            self.assertEqual(owned.call_count, 1)
            self.assertEqual(owned.call_args[0][0], args)
            self.assertIs(owned.call_args.kwargs.get('nested_ticket_owner'), True)
            env = owned.call_args[1]['env']
            self.assertEqual(env['KITROVE_NOTARY_SOURCE_COMMIT'], 'a' * 40)
            self.assertEqual(env['KITROVE_APPLE_TICKET_DIAGNOSTIC'], '1')
            self.assertNotIn('PRIVATE_CANARY', json.dumps(records))
        with patch.object(diagnostic, 'run_owned', return_value=types.SimpleNamespace(returncode=0, stdout=b'', stderr=b'')):
            with self.assertRaises(RuntimeError):
                function(args, 'a' * 40)
