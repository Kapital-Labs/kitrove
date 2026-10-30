"""Owned harmless processes test strict nested accounting; never signing tools."""
import inspect
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import hosted_apple_process as process

START = b'KITROVE_APPLE_OWNER_V1 {"schema_version":1,"ordinal":1,"event":"start"}\n'
FINISH = b'KITROVE_APPLE_OWNER_V1 {"schema_version":1,"ordinal":1,"event":"finish","cleanup_confirmed":true}\n'


@unittest.skipUnless(os.name == 'posix', 'POSIX process ownership fixture')
class NestedOwnerTests(unittest.TestCase):
    def owned(self, script, timeout=3, **kwargs):
        self.assertIn('nested_ticket_owner', inspect.signature(process.run_owned).parameters,
            'outer supervisor cannot yet account for a nested ticket owner')
        return process.run_owned([sys.executable, '-c', script], timeout=timeout,
            nested_ticket_owner=True, **kwargs)

    def test_confirmed_success_and_confirmed_native_failure_remain_distinct(self):
        for code in (0, 1):
            with self.subTest(code=code):
                result = self.owned('import os,sys; os.write(2, ' + repr(START + FINISH) +
                    '); sys.exit(' + str(code) + ')')
                self.assertEqual(result.returncode, code)

    def test_success_without_proof_or_unfinished_owner_refuses_cleanup(self):
        for raw in (b'', START, START + b'PRIVATE_CANARY'):
            with self.assertRaises(process.ProcessCleanupError) as caught:
                self.owned('import os; os.write(2, ' + repr(raw) + ')')
            self.assertEqual(caught.exception.category, 'nested-owner-unconfirmed')
            self.assertNotIn('PRIVATE_', repr(caught.exception))

    def test_timeout_and_abnormal_outer_exit_never_grant_nested_cleanup(self):
        with self.assertRaises(process.ProcessCleanupError):
            self.owned('import os,time; os.write(2, ' + repr(START) + '); time.sleep(30)', timeout=0.2)
        with self.assertRaises(process.ProcessCleanupError):
            self.owned('import os,signal; os.kill(os.getpid(), signal.SIGTERM)')

    def test_existing_single_pass_failure_before_owner_starts_stays_a_failure(self):
        result = self.owned('raise SystemExit(7)')
        self.assertEqual(result.returncode, 7)

    def test_cancellation_never_claims_unfinished_nested_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'ready'
            stopped = threading.Event()
            def interrupt():
                while not stopped.wait(0.01):
                    if ready.exists():
                        os.kill(os.getpid(), signal.SIGTERM)
                        return
            thread = threading.Thread(target=interrupt)
            script = ('import os,pathlib,time; os.write(2, ' + repr(START) + '); '
                'pathlib.Path(' + repr(str(ready)) + ').touch(); time.sleep(30)')
            thread.start()
            try:
                with self.assertRaises(process.ProcessCleanupError) as caught:
                    self.owned(script)
                self.assertEqual(caught.exception.category, 'nested-owner-unconfirmed')
            finally:
                stopped.set()
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_closed_reader_rejects_duplicate_truncated_and_excess_evidence(self):
        for raw in (START + FINISH + FINISH, START + FINISH[:-2], b'x' * (256 * 1024 + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(process.ProcessCleanupError):
                self.owned('import os; raw=' + repr(raw) + '; '
                    '[(os.write(2, raw[i:i+4096])) for i in range(0,len(raw),4096)]')

    def test_parent_supplies_one_absolute_monotonic_deadline(self):
        observed = []
        original = time.clock_gettime_ns
        def clock(clock_id):
            self.assertEqual(clock_id, time.CLOCK_MONOTONIC)
            value = original(clock_id)
            observed.append(value)
            return value
        script = ('import os; os.write(2, ' + repr(START + FINISH) + '); '
            'print(os.environ["KITROVE_NATIVE_TICKET_DEADLINE_NS"])')
        environment = dict(os.environ, KITROVE_NATIVE_TICKET_DEADLINE_NS='untrusted-inherited-value')
        with patch.object(process.time, 'clock_gettime_ns', side_effect=clock):
            result = self.owned(script, timeout=2, env=environment)
        deadline = int(result.stdout)
        self.assertTrue(observed)
        self.assertEqual(deadline, observed[0] + 2_000_000_000)
        self.assertEqual(environment['KITROVE_NATIVE_TICKET_DEADLINE_NS'], 'untrusted-inherited-value')

    def test_late_result_cannot_pass_after_absolute_deadline(self):
        clock = [1_000_000_000]
        original = process.validate_owner_evidence
        def late_evidence(*args, **kwargs):
            result = original(*args, **kwargs)
            clock[0] += 2_000_000_000
            return result
        with patch.object(process.time, 'clock_gettime_ns', side_effect=lambda _clock: clock[0]), \
             patch.object(process, 'validate_owner_evidence', side_effect=late_evidence):
            with self.assertRaises(process.ProcessCleanupError):
                self.owned('import os; os.write(2, ' + repr(START + FINISH) + ')', timeout=1)

    def test_invalid_strict_flags_refuse_before_launch(self):
        for value, ignore in [(1, False), ('true', False), (True, True)]:
            with patch.object(process.subprocess, 'Popen') as launch:
                with self.assertRaises(ValueError):
                    process.run_owned(['must-not-launch'], timeout=1,
                        nested_ticket_owner=value, ignore_prior_cancellation=ignore)
                launch.assert_not_called()

    def test_shared_deadline_remains_exact_integer_nanoseconds(self):
        with patch.object(process.time, 'clock_gettime_ns', return_value=1_000_000_000_000_001):
            env, deadline = process._nested_deadline(1, {})
        self.assertIs(type(deadline), int)
        self.assertEqual(deadline, 1_000_001_000_000_001)
        self.assertEqual(env['KITROVE_NATIVE_TICKET_DEADLINE_NS'], str(deadline))

    def test_outer_interruption_refuses_while_a_real_nested_group_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / 'owned-fixture.pid'
            script = ('import os,pathlib,subprocess,sys,time; '
                'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"],'
                'start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,'
                'stderr=subprocess.DEVNULL,env={}); '
                'pathlib.Path(' + repr(str(pid_file)) + ').write_text(str(child.pid)); '
                'os.write(2,' + repr(START) + '); time.sleep(30)')
            try:
                with self.assertRaises(process.ProcessCleanupError) as caught:
                    self.owned(script, timeout=1, env={})
                self.assertEqual(caught.exception.category, 'nested-owner-unconfirmed')
                self.assertTrue(pid_file.exists())
                # This fixture intentionally demonstrates the ownership boundary:
                # killing the outer group is NOT proof the inner one disappeared.
                os.killpg(int(pid_file.read_text()), 0)
            finally:
                if pid_file.exists():
                    group = int(pid_file.read_text())
                    # Exactly one real signal while this fixture's live child
                    # still pins its group; subsequent calls only query absence.
                    try:
                        os.killpg(group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            os.killpg(group, 0)
                        except ProcessLookupError:
                            break
                        except PermissionError:
                            pass
                        self.assertLess(time.monotonic(), deadline, 'fixture cleanup not confirmed')
                        time.sleep(0.01)


if __name__ == '__main__':
    unittest.main()
