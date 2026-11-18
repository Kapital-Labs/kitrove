"""Bounded terminal-test failures retain evidence without replaying control bytes."""
import ast
from pathlib import Path
import types
import unittest
from unittest.mock import Mock

FIXTURE = Path(__file__).resolve().parents[1] / 'crates/kitrove-cli/tests/fixtures/menu_terminal.py'


class MenuTerminalDiagnostics(unittest.TestCase):
    def session(self):
        # Load only the class, never the fixture's CLI invocations or environment.
        tree = ast.parse(FIXTURE.read_text())
        tree.body = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Session']
        clock = Mock()
        clock.monotonic.return_value = 10.0
        terminal = types.SimpleNamespace(tcgetattr=Mock(return_value=[0, 0, 0, 65, 0, 0, [1, 0]]), VMIN=0, VTIME=1, error=type('TerminalError', (Exception,), {}))
        namespace = dict(time=clock, termios=terminal, os=Mock(), select=Mock())
        exec(compile(tree, str(FIXTURE), 'exec'), namespace)
        session = namespace['Session'].__new__(namespace['Session'])
        session.started = 1.0
        session.inputs = []
        session.output = b''
        session.slave = 12
        session.master = 11
        session.process = Mock()
        session.process.poll.return_value = 3
        return session, namespace

    def test_deadline_keeps_escaped_bounded_output_and_exit_mode_input_context(self):
        session, ns = self.session()
        session.output = b'OMITTED_PREFIX' + b'x' * 5000 + b'\x1b[2Ksynthetic menu'
        for _ in range(25):
            session.send(b'\x1b[B')
        ns['time'].monotonic.side_effect = [10.0, 16.0, 16.0]
        with self.assertRaises(AssertionError) as error:
            session.wait_for(lambda: False, b'> [2] Skills needing review')
        message = str(error.exception)
        self.assertIn('Skills needing review', message)
        self.assertIn('child_exit', message)
        self.assertIn('vtime', message)
        self.assertIn('1b5b42', message)
        self.assertIn('\\x1b', message)
        self.assertNotIn('\x1b', message)
        self.assertNotIn('OMITTED_PREFIX', message)
        self.assertEqual(len(session.inputs), 16)
        self.assertLess(len(message), 6000)
        ns['os'].killpg.assert_not_called()

    def test_terminal_read_failure_retains_numeric_error_not_exception_text(self):
        session, ns = self.session()
        ns['select'].select.return_value = ([11], [], [])
        ns['os'].read.side_effect = OSError(5, 'PRIVATE_ERROR_TEXT')
        with self.assertRaises(AssertionError) as error:
            session.wait_for(lambda: False, b'expected menu')
        self.assertIn('terminal read errno=5', str(error.exception))
        self.assertNotIn('PRIVATE_ERROR_TEXT', str(error.exception))

    def test_closed_terminal_fails_with_context_without_spinning_until_timeout(self):
        session, ns = self.session()
        ns['select'].select.return_value = ([11], [], [])
        ns['os'].read.return_value = b''
        ns['time'].monotonic.side_effect = [10.0, 10.0, 16.0, 16.0]
        with self.assertRaisesRegex(AssertionError, 'terminal closed'):
            session.wait_for(lambda: False, b'expected menu')
        self.assertEqual(ns['os'].read.call_count, 1)

    def test_trace_is_bounded_and_missing_terminal_mode_does_not_mask_failure(self):
        session, ns = self.session()
        session.send(b'x' * 1000)
        for error in (OSError(9, 'PRIVATE_ERROR_TEXT'), ns['termios'].error(9, 'PRIVATE_ERROR_TEXT')):
            ns['termios'].tcgetattr.side_effect = error
            message = session.failure(b'expected', 'deadline')
            self.assertEqual(len(session.inputs[0][1]), 32)
            self.assertEqual(session.inputs[0][2], 1000)
            self.assertIn("'mode_errno': 9", message)
            self.assertNotIn('PRIVATE_ERROR_TEXT', message)
        ns['os'].write.assert_called_once_with(11, b'x' * 1000)
