"""POSIX process-group lifetime for trusted operator-only Apple signing tools."""
import errno
import os
import signal
import subprocess
import threading
import time
from contextlib import contextmanager

_cancellations = []

class ProcessCleanupError(RuntimeError):
    """The signing group may still hold credentials; preserve its private state."""

    _CATEGORIES = frozenset(('probe-denied', 'probe-interrupted', 'probe-os-error',
                            'cleanup-deadline', 'unclassified'))

    def __init__(self, _message=None, *, category='unclassified'):
        super().__init__('Native process cleanup could not be confirmed')
        self._category = category

    @property
    def category(self):
        value = self._category
        return value if isinstance(value, str) and value in self._CATEGORIES else 'unclassified'


class ProcessCancelled(RuntimeError):
    def __init__(self, _message=None):
        super().__init__('Native operation cancelled')
        self._captured_stderr = None


class ProcessTimeout(RuntimeError):
    def __init__(self, _message=None):
        super().__init__('Native operation timed out')
        self._captured_stderr = None


@contextmanager
def cancellation_scope():
    """Queue cancellation while child ownership and cleanup are being established."""
    if os.name != 'posix' or threading.current_thread() is not threading.main_thread():
        raise RuntimeError('Native process ownership requires the POSIX main thread')
    state = {'cancelled': False}

    def cancel(_number, _frame):
        state['cancelled'] = True
        # Propagate into the credential lifetime even if the signal lands after a
        # child's final cancellation check, while its return value is constructed.
        for active in _cancellations:
            active['cancelled'] = True

    previous = {}
    completed = False
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, cancel)
        _cancellations.append(state)
        yield state
        completed = True
    finally:
        if _cancellations and _cancellations[-1] is state:
            _cancellations.pop()
        for number, handler in previous.items():
            signal.signal(number, handler)
        if completed:
            raise_if_cancelled(state)


def raise_if_cancelled(state):
    if state['cancelled']:
        raise ProcessCancelled('Native operation cancelled')


def check_pending_cancellation():
    for state in _cancellations:
        raise_if_cancelled(state)


def _group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError as error:
        category = ('probe-denied' if error.errno in (errno.EPERM, errno.EACCES) else
                    'probe-interrupted' if error.errno == errno.EINTR else 'probe-os-error')
        raise ProcessCleanupError(category=category) from None


def stop_process_group(group, reap, *, term_seconds=1.0, kill_seconds=3.0):
    """Stop the owned group, reap its direct child, and require group disappearance.

    The trusted child must retain the session/group established by its launcher.
    This is not containment of hostile same-user processes or detached system daemons.
    """
    uncertain = None

    def probe():
        nonlocal uncertain
        try:
            present = _group_exists(group)
            uncertain = None
            return present
        except ProcessCleanupError as error:
            if error.category != 'probe-denied':
                raise
            # Darwin can deny a probe of a zombie-only group. Denial proves
            # neither presence nor absence; keep reaping within the same bound.
            uncertain = error
            return None

    try:
        for number, duration in ((signal.SIGTERM, term_seconds), (signal.SIGKILL, kill_seconds)):
            if probe() is True:
                try:
                    os.killpg(group, number)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + duration
            while True:
                direct_done = reap()
                present = probe()
                if direct_done and present is False:
                    return
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
        raise uncertain or ProcessCleanupError(category='cleanup-deadline')
    except ProcessCleanupError:
        raise
    except (OSError, ChildProcessError):
        raise ProcessCleanupError('Native process cleanup could not be confirmed') from None


MAX_CAPTURED_STDERR_BYTES = 256 * 1024
POST_STOP_DRAIN_SECONDS = 0.25


def _drain_stopped_stderr(process):
    """Retain bounded evidence privately; this never grants operation success."""
    try:
        _stdout, stderr = process.communicate(timeout=POST_STOP_DRAIN_SECONDS)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    if isinstance(stderr, bytes) and len(stderr) <= MAX_CAPTURED_STDERR_BYTES:
        return stderr
    return None


def run_owned(args, *, input=None, timeout, env=None, ignore_prior_cancellation=False):
    """Collect a tool result only after its whole owned process group is stopped."""
    cleanup_confirmed = False
    captured_stderr = None
    try:
        if not ignore_prior_cancellation:
            check_pending_cancellation()
        with cancellation_scope() as cancellation:
            if not ignore_prior_cancellation:
                check_pending_cancellation()
            process = subprocess.Popen(args, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True)
            try:
                deadline = time.monotonic() + timeout
                pending_input = input
                while True:
                    raise_if_cancelled(cancellation)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProcessTimeout()
                    try:
                        stdout, stderr = process.communicate(input=pending_input, timeout=min(remaining, 0.1))
                        break
                    except subprocess.TimeoutExpired:
                        # communicate retains its partial input/output state across retries.
                        pending_input = None
            finally:
                try:
                    stop_process_group(process.pid, lambda: process.poll() is not None)
                    cleanup_confirmed = True
                    captured_stderr = _drain_stopped_stderr(process)
                finally:
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
            raise_if_cancelled(cancellation)
            return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    except (ProcessTimeout, ProcessCancelled) as error:
        # Keep provider bytes out of exception args, repr and user-facing output.
        # Only the separately reviewed receipt bridge may inspect this private data.
        if cleanup_confirmed:
            error._captured_stderr = captured_stderr
        raise
