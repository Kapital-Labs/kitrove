"""Credential-free regressions for the production build-manifest handoff."""
import fnmatch
import os
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
