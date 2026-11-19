"""Owned-process and operator-boundary tests. Fixtures never use a personal CLI."""
import hashlib
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from grokbot_codec import PilotError
from grokbot_process import MARKER, PilotConfig, run_cli
from grokbot_process import _stop


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'WNOWAIT'), 'POSIX pilot only')
class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kitrove-grokbot-process-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        for role in ['bin', 'collection', 'home', 'state', '.git']:
            (self.root/role).mkdir(mode=0o700)
        (self.root/'.kitrove-grokbot-pilot').write_bytes(MARKER)
        self.tool = self.root/'bin/kitrove'

    def fixture(self, source):
        self.tool.write_text('#!' + sys.executable + '\n' + source)
        self.tool.chmod(0o700)
        config = self.root/'config.json'
        config.write_text(json.dumps({'schema_version': 1, 'root': str(self.root),
            'cli_sha256': hashlib.sha256(self.tool.read_bytes()).hexdigest(),
            'data_policy': 'synthetic-only'})); config.chmod(0o600)
        return PilotConfig.load(str(config))

    def test_closed_stdin_scrubbed_environment_and_unchanged_fixture(self):
        config = self.fixture('import os,sys,json\n'
            'assert not sys.stdin.buffer.read()\n'
            'assert "PILOT_PRIVATE_CANARY" not in os.environ\n'
            'assert sys.argv[1:4] == ["--json-errors","pack","list"]\n'
            'print(json.dumps({"home":os.environ["HOME"]}))\n')
        before = {str(p): (p.stat().st_mtime_ns, p.read_bytes())
                  for p in self.root.rglob('*') if p.is_file()}
        with patch.dict(os.environ, {'PILOT_PRIVATE_CANARY': 'never-export'}):
            code, out, err = run_cli(config, ['pack', 'list'])
        self.assertEqual((code, err), (0, b''))
        self.assertEqual(json.loads(out)['home'], str(self.root/'home'))
        self.assertEqual(before, {str(p): (p.stat().st_mtime_ns, p.read_bytes())
                                 for p in self.root.rglob('*') if p.is_file()})

    def test_changed_binary_refuses_before_launch(self):
        config = self.fixture('raise RuntimeError("must not launch")\n')
        self.tool.write_text('changed')
        with self.assertRaises(PilotError) as caught: run_cli(config, ['pack', 'list'])
        self.assertEqual(caught.exception.code, 'pilot.cli_changed')

    def test_unsupported_platform_refuses_before_reading_config(self):
        with patch('grokbot_process.os.name', 'nt'), self.assertRaises(PilotError) as caught:
            PilotConfig.load('/not-read')
        self.assertEqual(caught.exception.code, 'pilot.platform_unsupported')

    def test_config_mode_is_refused(self):
        self.fixture('print("ok")\n')
        (self.root/'config.json').chmod(0o644)
        with self.assertRaises(PilotError): PilotConfig.load(str(self.root/'config.json'))

    def test_internal_symlink_is_refused(self):
        self.fixture('print("ok")\n')
        (self.root/'home/linked').symlink_to(self.root/'state', target_is_directory=True)
        with self.assertRaises(PilotError): PilotConfig.load(str(self.root/'config.json'))

    def test_recovery_control_entry_stops_without_deleting_evidence(self):
        config = self.fixture('raise RuntimeError("must not launch")\n')
        control = self.root/'state/.kitrove'; control.mkdir(mode=0o700)
        journal = control/'atomic-apply-journal.json'; journal.write_bytes(b'retain-evidence')
        with self.assertRaises(PilotError) as caught: run_cli(config, ['pack', 'list'])
        self.assertEqual(caught.exception.code, 'pilot.recovery_or_unknown_state')
        self.assertEqual(journal.read_bytes(), b'retain-evidence')

    def test_output_flood_is_bounded_and_no_result_is_returned(self):
        config = self.fixture('import os\nwhile True: os.write(1,b"x"*32768)\n')
        with self.assertRaises(PilotError) as caught: run_cli(config, ['pack', 'list'])
        self.assertEqual(caught.exception.code, 'pilot.output_limit')

    def test_timeout_and_cancellation_terminate_owned_child(self):
        config = self.fixture('import time\ntime.sleep(60)\n')
        with patch('grokbot_process.RUN_SECONDS', 0.15), self.assertRaises(PilotError) as caught:
            run_cli(config, ['pack', 'list'])
        self.assertEqual(caught.exception.code, 'pilot.timeout')
        with self.assertRaises(PilotError) as caught:
            run_cli(config, ['pack', 'list'], lambda: True)
        self.assertEqual(caught.exception.code, 'pilot.cancelled')

    def test_descendant_holding_pipes_is_stopped_before_error_returns(self):
        sentinel = self.root/'descendant.pid'
        config = self.fixture('import os,time,signal\n'
            'signal.signal(signal.SIGTERM,lambda _s,_f:None)\n'
            'child=os.fork()\n'
            'if child==0:\n'
            ' signal.signal(signal.SIGTERM,signal.SIG_DFL)\n'
            ' open("descendant.pid","w").write(str(os.getpid()))\n'
            ' time.sleep(60)\n'
            'else:\n'
            ' os.waitpid(child,0)\n')
        # The parent is ready before fork; the child restores its termination
        # disposition before publishing the cancellation handshake.
        with self.assertRaises(PilotError) as caught:
            run_cli(config, ['pack', 'list'], lambda: sentinel.exists() and bool(sentinel.read_text().strip()))
        self.assertEqual(caught.exception.code, 'pilot.cancelled')
        self.assertTrue(sentinel.exists())
        with self.assertRaises(ProcessLookupError): os.kill(int(sentinel.read_text()), 0)

    def test_cleanup_failure_is_fatal_and_not_success(self):
        config = self.fixture('print("ok")\n')
        with patch('grokbot_process._stop', side_effect=PilotError('pilot.cleanup_unconfirmed', fatal=True)):
            # This fault is injected only after launch; reap the exact owned direct
            # child afterward rather than leaking a test process.
            real_popen = subprocess.Popen
            owned = []
            def launch(*args, **kwargs):
                p = real_popen(*args, **kwargs); owned.append(p); return p
            try:
                with patch('grokbot_process.subprocess.Popen', side_effect=launch), self.assertRaises(PilotError) as caught:
                    run_cli(config, ['pack', 'list'])
                self.assertTrue(caught.exception.fatal)
            finally:
                for child in owned: child.wait(timeout=2)

    def test_no_group_signal_can_follow_reaping_the_ownership_anchor(self):
        events = []
        class Child:
            pid = 999999999
            def wait(self, timeout): events.append('reaped')
        def group(_pid, number):
            if 'reaped' in events:
                self.assertEqual(number, 0, 'numeric group reused after ownership was reaped')
                raise ProcessLookupError()
            events.append(number)
        with patch('grokbot_process.os.waitid', return_value=None), patch('grokbot_process.os.killpg', side_effect=group):
            _stop(Child())
        self.assertEqual(events, [signal.SIGTERM, signal.SIGKILL, 'reaped'])

    def test_denied_group_probe_cannot_be_reported_as_disappearance(self):
        class Child:
            pid = 999999999
            def wait(self, timeout): pass
        with patch('grokbot_process.os.waitid', return_value=None), patch(
                'grokbot_process.os.killpg', side_effect=PermissionError(errno.EPERM, 'private')):
            with self.assertRaises(PilotError) as caught: _stop(Child())
        self.assertEqual(caught.exception.code, 'pilot.cleanup_unconfirmed')
        self.assertTrue(caught.exception.fatal)


if __name__ == '__main__':
    unittest.main()
