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

    def test_reviewed_notice_check_precedes_build_and_credentials(self):
        check = 'cargo xtask release-notices'
        self.assertIn(check, self.local)
        self.assertLess(self.local.index('cargo fetch --locked'), self.local.index(check))
        for following in ('dist build --tag=', 'python3 scripts/hosted_apple_signing.py',
                          'uses: azure/login@'):
            self.assertLess(self.local.index(check), self.local.index(following))
        config = (ROOT / 'dist-workspace.toml').read_text()
        for path in ('THIRD_PARTY_NOTICES.md', 'release/THIRD_PARTY_LICENSE_INVENTORY.txt',
                     'release/THIRD_PARTY_LICENSES.txt'):
            self.assertIn('"' + path + '"', config)

    @unittest.skipUnless(os.name == 'posix', 'executes the explicit Bash workflow body')
    def test_dist_tool_matches_reviewed_host_not_artifact_cpu(self):
        step = self.local.split('      - name: Install dist\n', 1)[1].split(
            '      - name: Install dist on Windows\n', 1)[0]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        stub = '''curl() { printf '%s\\n' "$*" >> calls; }
        shasum() { cat > digest; printf 'checksum\\n' >> calls; return "$CHECKSUM_RESULT"; }
        sha256sum() { shasum "$@"; }
        tar() { printf 'extract\\n' >> calls; }
        install() { printf '%s\\n' "$*" >> calls; }
        '''
        arm = 'aarch64-apple-darwin'
        intel = 'x86_64-apple-darwin'
        linux = 'x86_64-unknown-linux-gnu'
        cases = [
            ('macOS', 'ARM64', arm, arm),
            ('macOS', 'ARM64', intel, arm),
            ('Linux', 'X64', linux, linux),
            ('macOS', 'X64', intel, None),
            ('macOS', 'ARM64', linux, None),
            ('Linux', 'X64', intel, None),
            ('Linux', 'ARM64', linux, None),
            ('Windows', 'X64', intel, None),
            ('macOS', 'ARM64', intel + ';touch injected', None),
        ]
        for runner_os, arch, target, host in cases:
            for checksum in (0, 8):
                with self.subTest(os=runner_os, arch=arch, target=target, checksum=checksum), \
                        tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', stub + script],
                        cwd=root, env={'PATH': os.environ['PATH'], 'HOME': temporary,
                        'RUNNER_TEMP': temporary, 'RUNNER_OS': runner_os, 'RUNNER_ARCH': arch,
                        'DIST_TARGET': target, 'GITHUB_PATH': str(root / 'path'),
                        'CHECKSUM_RESULT': str(checksum)}, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, host is not None and checksum == 0,
                                     result.stderr)
                    self.assertFalse((root / 'injected').exists())
                    calls = root / 'calls'
                    if host is None:
                        self.assertFalse(calls.exists(), 'refuse before download or installation')
                        continue
                    observed = calls.read_text()
                    self.assertIn(f'/v0.32.0/cargo-dist-{host}.tar.xz', observed)
                    expected = ('aa343b2ff78ec2981f17a65140250c5ad6062c74072163f68c5c2686d94763a7'
                                if runner_os == 'macOS' else
                                'eb52f9fae0d0506774e9f1801c1168f87fa2c87a45e2d64d3ae7c89401929946')
                    self.assertEqual((root / 'digest').read_text(),
                                     f'{expected}  {root}/cargo-dist.tar.xz\n')
                    self.assertEqual('extract\n' in observed, checksum == 0)
                    self.assertEqual((root / 'path').exists(), checksum == 0)
                    if checksum == 0:
                        self.assertIn(f'cargo-dist-{host}/dist', observed)

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
        stub = '''cargo() {
          printf '%s\\n' "$*" >> "$CALLS"
          case "$*" in
            'fetch --locked') return "$FETCH_RESULT" ;;
            'xtask release-notices') return "$NOTICE_RESULT" ;;
            *) return 99 ;;
          esac
        }
        dist() { printf "%s\\0" "$@" > "$ARGS"; printf "{}"; return "$RESULT"; }
        '''
        for fetch, notices, code in ((0, 0, 0), (0, 0, 7), (9, 0, 0), (0, 8, 0)):
            with self.subTest(fetch=fetch, notices=notices, code=code), \
                    tempfile.TemporaryDirectory() as temporary:
                args = Path(temporary) / 'args'
                calls = Path(temporary) / 'calls'
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', stub + script],
                    cwd=temporary, env={**os.environ, 'RELEASE_TAG': 'v0.1.0-rc.1',
                                       'ARGS': str(args), 'CALLS': str(calls), 'RESULT': str(code),
                                       'FETCH_RESULT': str(fetch), 'NOTICE_RESULT': str(notices)},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, fetch or notices or code)
                self.assertEqual(calls.read_text().splitlines(), ['fetch --locked'] +
                                 ([] if fetch else ['xtask release-notices']))
                self.assertEqual('dist ran successfully' in result.stdout,
                                 fetch == notices == code == 0)
                if fetch or notices:
                    self.assertFalse(args.exists(), 'preflight failure must not reach dist')
                    self.assertFalse((Path(temporary) / 'dist-manifest.json').exists())
                    continue
                self.assertEqual(args.read_bytes().split(b'\0')[:-1], [
                    b'build', b'--tag=v0.1.0-rc.1', b'--print=linkage',
                    b'--output-format=json', b'--artifacts=local',
                    b'--target=x86_64-pc-windows-msvc'])
                self.assertEqual((Path(temporary) / 'dist-manifest.json').read_text(), '{}')
