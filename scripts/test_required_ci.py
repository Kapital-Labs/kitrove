"""Exercise the exact inline summary used by branch protection, without a runner."""

import json
import os
from pathlib import Path
from contextlib import redirect_stdout
from io import StringIO
import unittest
from unittest.mock import patch


WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml'
JOBS = ('changes', 'governance', 'pull-request-ci', 'pull-request-msrv',
        'pull-request-os', 'ci', 'msrv', 'advisory-audit')


class RequiredCiTests(unittest.TestCase):
    def run_gate(self, event, jobs):
        workflow = WORKFLOW.read_text()
        block = workflow.split("          python3 - <<'PY'\n", 1)[1].split('          PY\n', 1)[0]
        script = '\n'.join(line[10:] for line in block.splitlines())
        with patch.dict(os.environ, {'CI_EVENT': event, 'CI_NEEDS': json.dumps(jobs)}):
            with redirect_stdout(StringIO()):
                try:
                    exec(compile(script, str(WORKFLOW), 'exec'), {})
                except SystemExit as error:
                    return error.code if isinstance(error.code, int) else 1
        return 0

    def selected(self, event, source, sensitive):
        jobs = {name: {'result': 'skipped'} for name in JOBS}
        jobs['changes'] = {'result': 'success', 'outputs': {
            'source': str(source).lower(), 'os-sensitive': str(sensitive).lower(),
        }}
        if not source:
            selected = ('governance',)
        elif event == 'pull_request':
            selected = ('pull-request-ci', 'pull-request-msrv')
            if sensitive:
                selected += ('pull-request-os',)
        else:
            selected = ('ci', 'msrv', 'advisory-audit')
        for name in selected:
            jobs[name]['result'] = 'success'
        return jobs

    def test_all_selected_paths_and_every_job_result(self):
        for event in ('push', 'pull_request'):
            for source in (False, True):
                for sensitive in (False, True):
                    jobs = self.selected(event, source, sensitive)
                    self.assertEqual(self.run_gate(event, jobs), 0)
                    for name in JOBS:
                        original = jobs[name]['result']
                        for result in ('success', 'skipped', 'failure', 'cancelled', 'unknown'):
                            with self.subTest(event=event, source=source, sensitive=sensitive,
                                              job=name, result=result):
                                jobs[name]['result'] = result
                                self.assertEqual(self.run_gate(event, jobs) == 0, result == original)
                        jobs[name]['result'] = original

    def test_missing_or_unknown_inventory_and_outputs_fail_closed(self):
        for name in JOBS:
            jobs = self.selected('push', True, True)
            del jobs[name]
            self.assertNotEqual(self.run_gate('push', jobs), 0)
        jobs = self.selected('push', True, True)
        jobs['unexpected'] = {'result': 'success'}
        self.assertNotEqual(self.run_gate('push', jobs), 0)
        for field in ('source', 'os-sensitive'):
            for value in (None, '', 'TRUE', 'unknown'):
                jobs = self.selected('push', True, True)
                jobs['changes']['outputs'][field] = value
                self.assertNotEqual(self.run_gate('push', jobs), 0)
        self.assertNotEqual(self.run_gate('workflow_dispatch', self.selected('push', True, True)), 0)

    def test_summary_always_runs_and_waits_for_exact_dependencies(self):
        summary = WORKFLOW.read_text().split('  required-ci:\n', 1)[1].split('  windows-signing-build:', 1)[0]
        self.assertIn("if: always() && (github.event_name == 'push' || github.event_name == 'pull_request')", summary)
        self.assertIn('needs: [' + ', '.join(JOBS) + ']', summary)
        self.assertIn('CI_NEEDS: ${{ toJSON(needs) }}', summary)
        self.assertIn("name: ${{ github.event_name == 'workflow_dispatch' && 'Supplemental CI summary' || 'Required CI' }}", summary)
        self.assertNotIn('uses:', summary)

    def test_automatic_update_prs_remain_disabled(self):
        config = WORKFLOW.parents[1] / 'dependabot.yml'
        limits = [line.strip() for line in config.read_text().splitlines()
                  if line.strip().startswith('open-pull-requests-limit:')]
        self.assertEqual(limits, ['open-pull-requests-limit: 0'] * 2)

    def test_windows_pr_validation_includes_canonical_runtime_tests(self):
        job = WORKFLOW.read_text().split('  pull-request-os:\n', 1)[1].split('  ci:\n', 1)[0]
        self.assertIn("timeout-minutes: ${{ matrix.os == 'windows-latest' && 30 || 20 }}", job)
        self.assertIn('rustup toolchain install stable --profile minimal --component clippy,rustfmt', job)
        self.assertIn(
            "      - name: Run canonical Windows validation\n"
            "        if: runner.os == 'Windows'\n"
            "        run: cargo ci\n", job)
        self.assertIn(
            "      - name: Check every workspace target on this operating system\n"
            "        if: runner.os != 'Windows'\n"
            "        run: cargo check --locked --workspace --all-targets\n", job)
        self.assertNotIn('cargo test --locked -p kitrove-installer\n', job)


if __name__ == '__main__':
    unittest.main()
