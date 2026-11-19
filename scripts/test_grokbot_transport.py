"""Actual stdio lifecycle, cancellation and privacy tests, with disposable tools."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import unittest

import test_grokbot_process as fixtures
from test_grokbot_readonly import pack, plan, HASH


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'WNOWAIT'), 'POSIX pilot only')
class TransportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ProcessTests()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.pending = bytearray()

    def start(self, body):
        self.fixture.fixture(body)
        entry = Path(__file__).with_name('grokbot_readonly.py')
        self.server = subprocess.Popen([sys.executable, '-E', '-s', '-B', str(entry),
            '--config', str(self.root/'config.json')], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'PILOT_PRIVATE_CANARY': 'not-exported'})
        os.set_blocking(self.server.stdout.fileno(), False)
        self.addCleanup(self.stop)
        self.send({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'isolated-test', 'version': '1'}}})
        self.assertIn('result', self.receive())
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def stop(self):
        if self.server.poll() is None:
            self.server.terminate()
            self.server.wait(timeout=5)
        self.server.stdin.close(); self.server.stdout.close(); self.server.stderr.close()

    def send(self, message):
        self.server.stdin.write(json.dumps(message).encode()+b'\n'); self.server.stdin.flush()

    def receive(self):
        deadline = time.monotonic()+5
        with selectors.DefaultSelector() as selector:
            selector.register(self.server.stdout, selectors.EVENT_READ)
            while b'\n' not in self.pending:
                self.assertLess(time.monotonic(), deadline, 'bounded test response deadline')
                if not selector.select(0.05): continue
                chunk = os.read(self.server.stdout.fileno(), 65536)
                self.assertTrue(chunk, 'server ended before a protocol response')
                self.pending.extend(chunk); self.assertLessEqual(len(self.pending), 65536)
        line, _, rest = self.pending.partition(b'\n'); self.pending = bytearray(rest)
        return json.loads(line)

    def call(self, name, args, request_id=2):
        self.send({'jsonrpc': '2.0', 'id': request_id, 'method': 'tools/call',
                   'params': {'name': name, 'arguments': args}})
        return self.receive()

    def test_full_stdio_pack_preview_without_exporting_private_cli_fields(self):
        component = {'id': 'review-notes', 'revision': HASH, 'kind': 'asset',
                     'asset_kind': 'skill', 'direct': True, 'parents': ['starter-review']}
        inspect = {'schema_version': 1, 'operation': 'pack_inspect', 'pack': pack(), 'components': [component]}
        listing = {'schema_version': 1, 'operation': 'pack_list', 'packs': [pack()]}
        body = ('import sys,json,os\nassert "PILOT_PRIVATE_CANARY" not in os.environ\n'
                f'listing={listing!r}\ninspection={inspect!r}\nplan={plan()!r}\n'
                'value=inspection if sys.argv[2:4]==["pack","inspect"] else '
                '(listing if sys.argv[2:4]==["pack","list"] else plan)\nprint(json.dumps(value))\n')
        self.start(body)
        self.assertEqual(self.call('list_packs', {})['result']['structuredContent']['packs'][0]['member_count'], 1)
        out = self.call('preview_pack', {'pack_id': 'starter-review', 'target': 'opencode'}, 3)
        self.assertEqual(out['result']['structuredContent']['action_counts'], {'install': 1})
        self.assertNotIn('DO-NOT-EXPORT', json.dumps(out))
        self.assertNotIn(HASH, json.dumps(out))
        refused = self.call('apply', {}, 4)
        self.assertIn('error', refused)

    def test_unknown_child_output_is_terminal_and_never_echoed(self):
        self.start('import sys\nsys.stderr.write("PRIVATE-CANARY /secret/path")\nraise SystemExit(7)\n')
        result = self.call('list_packs', {})
        self.assertTrue(result['result']['isError'])
        self.assertNotIn('PRIVATE-CANARY', json.dumps(result))
        self.assertEqual(self.server.wait(timeout=5), 1)

    def test_cancel_active_call_and_signal_shutdown_stop_the_owned_child(self):
        body = 'import os,time\nopen("active.pid","w").write(str(os.getpid()))\ntime.sleep(60)\n'
        self.start(body)
        self.send({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                   'params': {'name': 'list_packs', 'arguments': {}}})
        pid_file = self.root/'active.pid'; deadline = time.monotonic()+5
        while not pid_file.exists() or not pid_file.read_text().strip():
            self.assertLess(time.monotonic(), deadline); time.sleep(0.01)
        self.send({'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': 2}})
        result = self.receive()
        self.assertEqual(result['result']['structuredContent']['code'], 'pilot.cancelled')
        with self.assertRaises(ProcessLookupError): os.kill(int(pid_file.read_text()), 0)
        pid_file.unlink()
        self.send({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                   'params': {'name': 'list_packs', 'arguments': {}}})
        deadline = time.monotonic()+5
        while not pid_file.exists() or not pid_file.read_text().strip():
            self.assertLess(time.monotonic(), deadline); time.sleep(0.01)
        self.server.send_signal(signal.SIGTERM)
        self.assertEqual(self.server.wait(timeout=5), 0)
        with self.assertRaises(ProcessLookupError): os.kill(int(pid_file.read_text()), 0)

    def test_oversized_input_closes_without_launching_cli(self):
        self.start('open("must-not-run","w").write("bad")\n')
        self.server.stdin.write(b'x'*17000+b'\n'); self.server.stdin.flush()
        self.assertEqual(self.server.wait(timeout=5), 1)
        self.assertFalse((self.root/'must-not-run').exists())

    def test_eof_while_running_cleans_the_child_before_shutdown(self):
        self.start('import os,time\nopen("active.pid","w").write(str(os.getpid()))\ntime.sleep(60)\n')
        self.send({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                   'params': {'name': 'list_packs', 'arguments': {}}})
        pid_file = self.root/'active.pid'; deadline = time.monotonic()+5
        while not pid_file.exists() or not pid_file.read_text().strip():
            self.assertLess(time.monotonic(), deadline); time.sleep(0.01)
        identity = int(pid_file.read_text())
        self.server.stdin.close()
        self.assertEqual(self.server.wait(timeout=5), 0)
        with self.assertRaises(ProcessLookupError): os.kill(identity, 0)

    def test_startup_preserves_the_closed_refusal_category_without_private_details(self):
        self.fixture.fixture('print("PRIVATE-CANARY")\n')
        self.fixture.tool.write_text('changed verified executable')
        entry = Path(__file__).with_name('grokbot_readonly.py')
        result = subprocess.run([sys.executable, '-E', '-s', '-B', str(entry),
            '--config', str(self.root/'config.json')], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'pilot.cli_changed\n')

    def test_unfinished_frame_has_a_bound_without_launching_cli(self):
        self.start('open("must-not-run","w").write("bad")\n')
        self.server.stdin.write(b'{"jsonrpc":'); self.server.stdin.flush()
        self.assertEqual(self.server.wait(timeout=10), 1)
        self.assertFalse((self.root/'must-not-run').exists())
        self.assertEqual(self.server.stderr.read(), b'pilot.transport_limit\n')


if __name__ == '__main__':
    unittest.main()
