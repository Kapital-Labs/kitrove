"""Credential-free regressions for the production build-manifest handoff."""
import fnmatch
import os
import json
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseBuildWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / '.github/workflows/release.yml').read_text()
        self.local = self.workflow.split('  build-local-artifacts:\n', 1)[1].split(
            '  build-global-artifacts:\n', 1)[0]

    @unittest.skipUnless(os.name == 'posix', 'executes the explicit Bash publication body')
    def test_publication_requires_reviewed_version_notes_before_any_github_write(self):
        step = self.workflow.split('      - name: Create GitHub Release\n', 1)[1].split(
            '\n  announce:', 1)[0]
        self.assertNotIn('announcement_github_body', step)
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        stub = 'gh() { printf "%s\\n" "$*" >> calls; }\n'
        for kind in ('missing', 'empty', 'symlink', 'valid'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                notes = root / 'release/notes/v0.1.0-rc.5.md'
                notes.parent.mkdir(parents=True)
                (root / 'tmp').mkdir()
                (root / 'verified-artifacts').mkdir()
                (root / 'verified-artifacts/archive').write_text('verified fixture')
                if kind == 'empty':
                    notes.touch()
                elif kind == 'symlink':
                    (root / 'other').write_text('not accepted')
                    notes.symlink_to(root / 'other')
                elif kind == 'valid':
                    notes.write_text('Reviewed notes, not executable: $(touch injected)\n')
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', stub + script],
                    cwd=root, env={**os.environ, 'RELEASE_TAG': 'v0.1.0-rc.5',
                    'RELEASE_COMMIT': 'a' * 40, 'RUNNER_TEMP': str(root / 'tmp'),
                    'ANNOUNCEMENT_TITLE': 'RC5', 'PRERELEASE_FLAG': '--prerelease'},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, kind == 'valid', result.stderr)
                self.assertFalse((root / 'injected').exists())
                if kind == 'valid':
                    self.assertEqual((root / 'tmp/notes.txt').read_text(),
                        notes.read_text() + '\nRelease source commit: `' + 'a' * 40 + '`\n')
                    calls = (root / 'calls').read_text().splitlines()
                    self.assertEqual(len(calls), 2)
                    self.assertIn('--draft --target ' + 'a' * 40, calls[0])
                    self.assertIn('--notes-file ' + str(root / 'tmp/notes.txt'), calls[0])
                    self.assertEqual(calls[1], 'release edit v0.1.0-rc.5 --draft=false')
                else:
                    self.assertFalse((root / 'calls').exists())

    def test_native_staging_handoff_without_signing_credentials(self):
        step = self.local.split('      - id: verified-local\n', 1)[1].split(
            '      - name: Attest the exact application archive', 1)[0]
        self.assertIn('        shell: bash\n', step)
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        self.assertIn('cargo xtask create-release-staging', script)
        for key, value in [('path', 'cli.zip'), ('installer_path', 'installer.zip')]:
            script = script.replace('${{ steps.application-archive.outputs.' + key + ' }}', value)
        # Use the real native directory creator; stub only the artifact verifiers.
        # Their archive/manifest validation has separate tests with real bundles.
        binary = ROOT / 'target/debug' / ('xtask.exe' if os.name == 'nt' else 'xtask')
        # Match Actions' Git Bash, not a potentially installed WSL bash.exe.
        bash = str(Path(os.environ['ProgramFiles']) / 'Git/bin/bash.exe') if os.name == 'nt' else 'bash'
        subprocess.run(['cargo', 'build', '--locked', '-p', 'xtask'], cwd=ROOT,
                       check=True, capture_output=True, timeout=300)
        stub = '''cargo() {
          if [[ "$2" == "create-release-staging" ]]; then "$STAGING_TOOL" "$2";
          else printf '%s\\n' "$*" >> calls; fi
        }
        '''
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ('cli.zip', 'installer.zip', 'cli.zip.sha256', 'installer.zip.sha256'):
                (directory / name).write_text(name)
            (directory / 'dist-manifest.json').write_text(json.dumps({'fixture': True}))
            env = {**os.environ, 'STAGING_TOOL': binary.as_posix(),
                   'RUNNER_OS': 'Windows', 'DIST_TARGET': 'x86_64-pc-windows-msvc',
                   'RELEASE_TAG': 'v0.1.0-rc.1.1', 'BUILD_MANIFEST_NAME':
                   'verified-local-artifacts/windows-dist-manifest.json',
                   'GITHUB_OUTPUT': 'outputs'}
            result = subprocess.run([bash, '-e', '-o', 'pipefail', '-c', stub + script],
                                    cwd=directory, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = directory / 'verified-local-artifacts'
            self.assertEqual(sorted(p.name for p in staged.iterdir()), [
                'cli.zip', 'cli.zip.sha256', 'installer.zip', 'installer.zip.sha256',
                'windows-dist-manifest.json'])
            for name in ('cli.zip', 'installer.zip', 'cli.zip.sha256', 'installer.zip.sha256'):
                self.assertEqual((staged / name).read_bytes(), (directory / name).read_bytes())
            self.assertEqual((staged / 'windows-dist-manifest.json').read_bytes(),
                             (directory / 'dist-manifest.json').read_bytes())
            self.assertEqual(len((directory / 'calls').read_text().splitlines()), 4)
            self.assertEqual((directory / 'outputs').read_text().splitlines(), [
                'staged_path=verified-local-artifacts/cli.zip',
                'installer_staged_path=verified-local-artifacts/installer.zip'])
            # A retry must stop before any copy/verification, never reuse staging.
            before = (directory / 'calls').read_bytes()
            again = subprocess.run([bash, '-e', '-o', 'pipefail', '-c', stub + script],
                                   cwd=directory, env=env, capture_output=True, timeout=30)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual((directory / 'calls').read_bytes(), before)

    def test_plan_is_evidence_not_imported_artifact_authority(self):
        plan = self.workflow.split('  build-local-artifacts:\n', 1)[0]
        name = plan.split('name: release-plan-dist-manifest', 1)
        self.assertEqual(len(name), 2)
        self.assertFalse(fnmatch.fnmatch('release-plan-dist-manifest', 'artifacts-*'))
        self.assertNotIn('artifacts-plan-dist-manifest', self.workflow)
        self.assertNotIn('actions/download-artifact@', self.local)
        self.assertIn('matrix: ${{ fromJson(needs.plan.outputs.val).ci.github.artifacts_matrix }}', self.local)
        for job, following in (('build-global-artifacts', 'host'), ('host', 'announce')):
            section = self.workflow.split(f'  {job}:\n', 1)[1].split(
                f'  {following}:\n', 1)[0]
            self.assertIn('pattern: artifacts-*', section)

    @unittest.skipUnless(os.name == 'posix', 'executes the explicit Bash workflow body')
    def test_build_passes_tag_and_stops_before_success_on_failure(self):
        step = self.local.split('      - name: Build artifacts\n', 1)[1].split(
            '      - id: application-archive', 1)[0]
        self.assertIn('        shell: bash\n', step)
        script = textwrap.dedent(step.split('        run: |\n', 1)[1]).replace(
            '${{ matrix.dist_args }}', '--artifacts=local --target=x86_64-pc-windows-msvc')
        stub = 'dist() { printf "%s\\0" "$@" > "$ARGS"; printf "{}"; return "$RESULT"; }\n'
        for code in (0, 7):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temporary:
                args = Path(temporary) / 'args'
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', stub + script],
                    cwd=temporary, env={**os.environ, 'RELEASE_TAG': 'v0.1.0-rc.1',
                                       'ARGS': str(args), 'RESULT': str(code)},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code)
                self.assertEqual(args.read_bytes().split(b'\0')[:-1], [
                    b'build', b'--tag=v0.1.0-rc.1', b'--print=linkage',
                    b'--output-format=json', b'--artifacts=local',
                    b'--target=x86_64-pc-windows-msvc'])
                self.assertEqual('dist ran successfully' in result.stdout, code == 0)
                self.assertEqual((Path(temporary) / 'dist-manifest.json').read_text(), '{}')
