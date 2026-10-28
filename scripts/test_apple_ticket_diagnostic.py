"""Synthetic nonpublishing diagnostic controls; never sign or contact Apple."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

try:
    import apple_ticket_diagnostic as diagnostic
except ImportError:
    diagnostic = None

ROOT = Path(__file__).resolve().parents[1]


class AppleTicketDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(diagnostic, 'missing closed diagnostic helper')

    def environment(self):
        return dict(DIST_TARGET='x86_64-apple-darwin', GITHUB_SHA='a' * 40,
            KITROVE_SIGNING_REHEARSAL_SHA='a' * 40, RUNNER_ARCH='ARM64',
            GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
            GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY='Kapital-Labs/kitrove',
            GITHUB_REF='refs/heads/main',
            GITHUB_WORKFLOW_REF='Kapital-Labs/kitrove/.github/workflows/apple-ticket-diagnostic.yml@refs/heads/main')

    def test_context_refuses_every_missing_field_and_production_activation(self):
        with patch.object(diagnostic.sys, 'platform', 'darwin'):
            env = self.environment()
            self.assertEqual(diagnostic.context(env), (env['DIST_TARGET'], env['GITHUB_SHA']))
            for key in env:
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    diagnostic.context(dict(env, **{key: ''}))
            for changes in ({'RUNNER_ARCH': 'X64'}, {'DIST_TARGET': 'x86_64-pc-windows-msvc'},
                            {'KITROVE_HOSTED_SIGNING_READY': 'false'}):
                with self.assertRaises(RuntimeError):
                    diagnostic.context(dict(env, **changes))

    def test_version_is_bound_to_source_and_existing_catalog_not_caller(self):
        self.assertEqual(diagnostic.version_tag(ROOT), 'v0.1.0-rc.5.3')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'release').mkdir()
            (root / 'Cargo.toml').write_text('[workspace.package]\nversion = "0.1.0-rc.5.3"\n')
            (root / 'release/application-compatibility.json').write_text('{"releases":[]}')
            with self.assertRaises(RuntimeError):
                diagnostic.version_tag(root)

    @unittest.skipUnless(os.name == 'posix', 'POSIX-only diagnostic')
    def test_regular_copy_refuses_symlink_extra_link_and_nonfile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            leaf = 'kitrove-installer-x86_64-apple-darwin.dmg'
            (source / leaf).write_bytes(b'fixture, never mounted')
            dest = root / 'copy'
            expected = diagnostic.copy_image(source, leaf, dest)
            self.assertEqual(expected, diagnostic.rehearsal.digest(dest))
            for kind in ('symlink', 'hardlink', 'directory'):
                target = root / kind
                if kind == 'symlink':
                    target.symlink_to(source, target_is_directory=True)
                elif kind == 'hardlink':
                    target.mkdir()
                    os.link(source / leaf, target / leaf)
                else:
                    target.mkdir()
                    (target / leaf).mkdir()
                with self.subTest(kind=kind), self.assertRaises((OSError, RuntimeError)):
                    diagnostic.copy_image(target, leaf, root / ('copy-' + kind))

    def test_failure_without_cleanup_never_creates_upload_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            prior = Path.cwd()
            try:
                os.chdir(temporary)
                with patch.object(diagnostic.signing, 'prepare_release', side_effect=RuntimeError('SECRET')):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(diagnostic.sign('x86_64-apple-darwin', 'a' * 40), 1)
                self.assertFalse(Path('diagnostic-evidence').exists())
                self.assertNotIn('SECRET', output.getvalue())
            finally:
                os.chdir(prior)

    @unittest.skipUnless(os.name == 'posix', 'POSIX-only diagnostic')
    def test_failure_after_cleanup_retains_only_exact_image_and_closed_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            images = root / 'runner/kitrove-installer-dmg'
            images.mkdir(parents=True)
            leaf = 'kitrove-installer-x86_64-apple-darwin.dmg'
            (images / leaf).write_bytes(b'fixture, never mounted')
            (root / 'runner/SECRET.keychain-db').write_bytes(b'PRIVATE_CANARY')

            def prepare(*, cleanup_observer):
                print('PRIVATE_CANARY/account/path')
                print('Failed: installer container preparation [dmg-staple-validation] [native-exit=65]')
                cleanup_observer()
                raise RuntimeError('PRIVATE_CANARY')

            prior = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, RUNNER_TEMP=str(root / 'runner')), \
                     patch.object(diagnostic.signing, 'prepare_release', side_effect=prepare), \
                     patch.object(diagnostic, 'run_owned', return_value=types.SimpleNamespace(returncode=0)):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(diagnostic.sign('x86_64-apple-darwin', 'a' * 40), 1)
                evidence = root / 'diagnostic-evidence'
                self.assertEqual({p.name for p in evidence.iterdir()}, {'diagnostic.json', leaf})
                record = json.loads((evidence / 'diagnostic.json').read_text())
                self.assertFalse(record['preparation_succeeded'])
                self.assertFalse(record['published'])
                self.assertTrue(record['cleanup_confirmed'])
                self.assertEqual(record['ticket_exit'], 0)
                self.assertEqual(record['failure_detail'], 'native-exit=65')
                self.assertEqual(record['failed_operation'], 'installer container preparation')
                self.assertEqual(record['failure_category'], 'dmg-staple-validation')
                self.assertNotIn('PRIVATE_CANARY', json.dumps(record) + output.getvalue())
            finally:
                os.chdir(prior)

    def test_unconfirmed_copy_never_gets_an_uploadable_image_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            prior = Path.cwd()
            def prepare(*, cleanup_observer):
                cleanup_observer()
                raise RuntimeError('PRIVATE_CANARY')
            def partial(_directory, _leaf, destination):
                destination.write_bytes(b'incomplete fixture')
                raise RuntimeError('PRIVATE_CANARY')
            try:
                os.chdir(root)
                with patch.dict(os.environ, RUNNER_TEMP=str(root)), \
                     patch.object(diagnostic.signing, 'prepare_release', side_effect=prepare), \
                     patch.object(diagnostic, 'copy_image', side_effect=partial), \
                     patch.object(diagnostic, 'run_owned') as native:
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(diagnostic.sign('x86_64-apple-darwin', 'a' * 40), 1)
                native.assert_not_called()
                evidence = root / 'diagnostic-evidence'
                self.assertFalse((evidence / 'kitrove-installer-x86_64-apple-darwin.dmg').exists())
                self.assertTrue((evidence / 'diagnostic.json').is_file())
                self.assertNotIn('PRIVATE_CANARY', output.getvalue())
            finally:
                os.chdir(prior)

    def test_native_status_discards_all_provider_output(self):
        result = types.SimpleNamespace(returncode=65, stdout=b'PRIVATE_CANARY', stderr=b'PRIVATE_CANARY')
        with patch.object(diagnostic, 'run_owned', return_value=result), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(diagnostic.native_status(['/usr/bin/xcrun', 'stapler', 'validate']), 65)
        self.assertEqual(output.getvalue(), '')

    @unittest.skipUnless(os.name == 'posix', 'POSIX-only diagnostic')
    def test_post_control_cancel_or_image_alias_never_marks_evidence_ready(self):
        for failure in ('cancelled', 'uncertain', 'hardlink', 'symlink', 'replacement'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                images = root / 'runner/kitrove-installer-dmg'
                images.mkdir(parents=True)
                leaf = 'kitrove-installer-x86_64-apple-darwin.dmg'
                (images / leaf).write_bytes(b'fixture, never mounted')
                (root / 'private-fixture').write_bytes(b'PRIVATE_CANARY')
                output_file = root / 'outputs'
                output_file.touch()
                def prepare(*, cleanup_observer):
                    cleanup_observer()
                    raise RuntimeError('PRIVATE_CANARY')
                def native(args, **_kwargs):
                    if failure == 'cancelled':
                        raise diagnostic.ProcessCancelled()
                    if failure == 'uncertain':
                        raise diagnostic.ProcessCleanupError()
                    if args[0] == '/usr/bin/codesign':
                        image = Path(args[-1])
                        if failure == 'hardlink':
                            os.link(image, root / 'alias')
                        elif failure == 'symlink':
                            image.unlink()
                            image.symlink_to(root / 'private-fixture')
                        else:
                            replacement = root / 'replacement'
                            replacement.write_bytes(image.read_bytes())
                            os.replace(replacement, image)
                    return types.SimpleNamespace(returncode=0)
                prior = Path.cwd()
                try:
                    os.chdir(root)
                    with patch.dict(os.environ, RUNNER_TEMP=str(root / 'runner'),
                                    GITHUB_OUTPUT=str(output_file)), \
                         patch.object(diagnostic.signing, 'prepare_release', side_effect=prepare), \
                         patch.object(diagnostic, 'run_owned', side_effect=native), \
                         contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(diagnostic.sign('x86_64-apple-darwin', 'a' * 40), 1)
                    self.assertFalse((root / 'diagnostic-evidence/diagnostic.json').exists())
                    self.assertEqual(output_file.read_text(), '')
                    self.assertNotIn('PRIVATE_CANARY', output.getvalue())
                finally:
                    os.chdir(prior)

    def test_manual_workflow_has_no_publish_oidc_or_production_activation(self):
        workflow = (ROOT / '.github/workflows/apple-ticket-diagnostic.yml').read_text()
        self.assertTrue((ROOT / '.github/workflows/apple-ticket-diagnostic-build.yml').is_file(),
                        'credential-free named build outputs required')
        build = (ROOT / '.github/workflows/apple-ticket-diagnostic-build.yml').read_text()
        self.assertIn('workflow_dispatch:', workflow)
        self.assertIn('environment: release', workflow)
        self.assertIn('github.sha == vars.KITROVE_SIGNING_REHEARSAL_SHA', workflow)
        self.assertIn('retention-days: 1', workflow)
        self.assertIn('if: always() && !cancelled()', workflow)
        self.assertNotIn('id-token:', workflow)
        self.assertNotIn('contents: write', workflow)
        self.assertNotIn('secrets: inherit', workflow)
        self.assertNotIn('release.yml', workflow)
        self.assertNotIn('tags:', workflow)
        self.assertEqual((workflow + build).count('runs-on: macos-15'), 2)
        self.assertIn('EXPECTED_INVENTORY: ${{ needs[matrix.build].outputs.inventory }}', workflow)
        self.assertIn('value: ${{ jobs.build.outputs.inventory }}', build)
        self.assertIn('needs: [build-arm, build-intel]', workflow)
        self.assertNotIn('secrets.', build)
        self.assertIn("steps.diagnostic.outputs.evidence_ready == 'true'", workflow)
        self.assertIn('diagnostic-evidence/kitrove-installer-${{ matrix.target }}.dmg', workflow)

    def test_cancelled_preparation_stops_before_copy_or_native_control(self):
        with tempfile.TemporaryDirectory() as temporary:
            prior = Path.cwd()
            try:
                os.chdir(temporary)
                def cancelled(*, cleanup_observer):
                    cleanup_observer()
                    raise diagnostic.ProcessCancelled()
                with patch.object(diagnostic.signing, 'prepare_release', side_effect=cancelled), \
                     patch.object(diagnostic, 'copy_image', return_value='a' * 64) as copy, \
                     patch.dict(os.environ, RUNNER_TEMP=temporary), \
                     patch.object(diagnostic, 'run_owned', return_value=types.SimpleNamespace(returncode=0)):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(diagnostic.sign('x86_64-apple-darwin', 'a' * 40), 1)
                    copy.assert_not_called()
                self.assertFalse(Path('diagnostic-evidence').exists())
            finally:
                os.chdir(prior)
