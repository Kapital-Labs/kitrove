"""Real harmless process trees; no credentials, signing tools or network access."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import hosted_apple_process as process


@unittest.skipUnless(os.name == 'posix', 'owned process groups require POSIX')
class HostedAppleProcessTests(unittest.TestCase):
    def test_success_and_stdin_round_trip(self):
        result = process.run_owned([sys.executable, '-c',
            'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.write("err")'],
            input=b'private-input', timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'private-input')
        self.assertEqual(result.stderr, b'err')

    def test_timeout_reaps_direct_child_and_restores_signal_handlers(self):
        previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        children = []
        original = subprocess.Popen

        def launch(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(process.subprocess, 'Popen', side_effect=launch):
            with self.assertRaisesRegex(process.ProcessTimeout, '^Native operation timed out$'):
                process.run_owned([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.2)
        self.assertIsNotNone(children[0].returncode)
        for number, handler in previous.items():
            self.assertEqual(signal.getsignal(number), handler)

    def test_timeout_and_cancellation_retain_bounded_stderr_only_privately(self):
        record = dict(schema_version=1, submission_id='12345678-1234-1234-1234-123456789abc',
            status='Accepted', artifact_sha256='b' * 64, target='x86_64-apple-darwin',
            source_commit='a' * 40)
        evidence = b'KITROVE_NOTARY_RECEIPT_V1 ' + json.dumps(record).encode() + b'\nPRIVATE_PROVIDER_CANARY\n'
        for cancel in (False, True):
            with self.subTest(cancel=cancel), tempfile.TemporaryDirectory() as directory:
                ready = Path(directory) / 'ready'
                script = ('import os,pathlib,sys,time; os.write(2, ' + repr(evidence) + '); '
                    'pathlib.Path(sys.argv[1]).touch(); time.sleep(30)')
                stop = threading.Event()

                def interrupt():
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline:
                        if stop.wait(0.01):
                            return
                    if ready.exists() and not stop.is_set():
                        os.kill(os.getpid(), signal.SIGTERM)

                thread = threading.Thread(target=interrupt) if cancel else None
                if thread:
                    thread.start()
                try:
                    expected = process.ProcessCancelled if cancel else process.ProcessTimeout
                    with self.assertRaises(expected) as caught:
                        process.run_owned([sys.executable, '-c', script, str(ready)],
                            timeout=5 if cancel else 0.5)
                finally:
                    stop.set()
                    if thread:
                        thread.join()
                self.assertEqual(caught.exception._captured_stderr, evidence)
                for representation in (str(caught.exception), repr(caught.exception), str(caught.exception.args)):
                    self.assertNotIn('PRIVATE_PROVIDER_CANARY', representation)
                    self.assertNotIn('KITROVE_NOTARY_RECEIPT', representation)

    def test_oversized_or_unconfirmed_stderr_is_never_attached(self):
        script = 'import os,time; os.write(2, b"PRIVATE_CANARY" * 30000); time.sleep(30)'
        with self.assertRaises(process.ProcessTimeout) as caught:
            process.run_owned([sys.executable, '-c', script], timeout=0.5)
        self.assertIsNone(caught.exception._captured_stderr)
        self.assertNotIn('PRIVATE_CANARY', repr(caught.exception))

        original = process.stop_process_group

        def uncertain_after_real_cleanup(*args, **kwargs):
            original(*args, **kwargs)
            raise process.ProcessCleanupError('Native process cleanup could not be confirmed')

        with patch.object(process, 'stop_process_group', side_effect=uncertain_after_real_cleanup):
            with self.assertRaises(process.ProcessCleanupError) as caught:
                process.run_owned([sys.executable, '-c',
                    'import os,time; os.write(2, b"PRIVATE_CANARY"); time.sleep(30)'], timeout=0.3)
        self.assertFalse(hasattr(caught.exception, '_captured_stderr'))
        self.assertNotIn('PRIVATE_CANARY', repr(caught.exception))

    def test_post_stop_drain_is_bounded_and_unavailable_on_drain_failure(self):
        child = unittest.mock.Mock()
        child.communicate.side_effect = subprocess.TimeoutExpired('PRIVATE_CANARY', 0.25,
            stderr=b'PRIVATE_CANARY')
        self.assertIsNone(process._drain_stopped_stderr(child))
        child.communicate.assert_called_once_with(timeout=process.POST_STOP_DRAIN_SECONDS)

    def test_unconfirmed_cleanup_has_only_constant_diagnostic(self):
        output = io.StringIO()
        with patch.object(process, '_group_exists', return_value=True), \
             patch.object(process.os, 'killpg'), contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(process.ProcessCleanupError,
                    '^Native process cleanup could not be confirmed$'):
                process.stop_process_group(123456789, lambda: True, term_seconds=0, kill_seconds=0)
        self.assertEqual(output.getvalue(), '')

    def test_pending_cancellation_refuses_next_launch_but_allows_cleanup(self):
        with self.assertRaises(process.ProcessCancelled):
            with process.cancellation_scope() as state:
                state['cancelled'] = True
                with self.assertRaises(process.ProcessCancelled):
                    process.run_owned([sys.executable, '-c', 'raise Exception("must not execute")'], timeout=3)
                result = process.run_owned([sys.executable, '-c', 'pass'], timeout=3,
                    ignore_prior_cancellation=True)
                self.assertEqual(result.returncode, 0)

    def test_cancellation_during_result_construction_propagates_to_credential_scope(self):
        original = subprocess.CompletedProcess

        def cancelled_result(*args, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            return original(*args, **kwargs)

        with self.assertRaises(process.ProcessCancelled):
            with process.cancellation_scope() as credential_lifetime:
                with patch.object(process.subprocess, 'CompletedProcess', side_effect=cancelled_result):
                    with self.assertRaises(process.ProcessCancelled) as caught:
                        process.run_owned([sys.executable, '-c',
                            'import os; os.write(2, b"PRIVATE_CANARY")'], timeout=3)
                self.assertEqual(caught.exception._captured_stderr, b'PRIVATE_CANARY')
                self.assertNotIn('PRIVATE_CANARY', repr(caught.exception))
                self.assertTrue(credential_lifetime['cancelled'])
                with self.assertRaises(process.ProcessCancelled):
                    process.run_owned([sys.executable, '-c', 'pass'], timeout=3)
                result = process.run_owned([sys.executable, '-c', 'pass'], timeout=3,
                    ignore_prior_cancellation=True)
                self.assertEqual(result.returncode, 0)

    @unittest.skipUnless(sys.platform == 'darwin', 'Mac orphan reaping is part of this hosted Mac policy')
    def test_timeout_and_cancellation_kill_term_ignoring_descendant(self):
        # The parent and descendant ignore TERM. KILL escalation must stop both,
        # including a descendant that inherited no communicate() pipe handles.
        for number in (None, signal.SIGTERM, signal.SIGINT):
            with self.subTest(cancellation=number), tempfile.TemporaryDirectory() as directory:
                child_pid = Path(directory) / 'child.pid'
                fixture = '''
import os, signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([sys.executable, '-c',
    'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
open(sys.argv[1], 'w').write(str(child.pid))
time.sleep(30)
'''
                stop = threading.Event()

                def cancel():
                    deadline = time.monotonic() + 5
                    while not child_pid.exists() and time.monotonic() < deadline:
                        if stop.wait(0.01):
                            return
                    if not stop.wait(0.1):
                        os.kill(os.getpid(), number)

                thread = threading.Thread(target=cancel) if number else None
                if thread:
                    thread.start()
                try:
                    expected = process.ProcessCancelled if number else process.ProcessTimeout
                    with self.assertRaises(expected):
                        process.run_owned([sys.executable, '-c', fixture, str(child_pid)],
                            timeout=5 if number else 0.5)
                finally:
                    stop.set()
                    if thread:
                        thread.join()
                pid = int(child_pid.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)

    @unittest.skipUnless(sys.platform == 'darwin', 'Mac orphan reaping is part of this hosted Mac policy')
    def test_success_still_terminates_surviving_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            child_pid = Path(directory) / 'child.pid'
            fixture = '''
import pathlib, subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c',
    'import os,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
    'open(sys.argv[1], "w").write(str(os.getpid())); time.sleep(30)', sys.argv[1]],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
while not pathlib.Path(sys.argv[1]).exists():
    time.sleep(0.01)
print('complete')
'''
            result = process.run_owned([sys.executable, '-c', fixture, str(child_pid)], timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'complete\n')
            with self.assertRaises(ProcessLookupError):
                os.kill(int(child_pid.read_text()), 0)


if __name__ == '__main__':
    unittest.main()
