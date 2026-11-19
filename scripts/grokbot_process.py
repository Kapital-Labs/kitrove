"""Bounded POSIX execution of an operator-pinned CLI, never arbitrary Bot commands."""
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time

from grokbot_codec import MAX_FRAME, MAX_OUTPUT, PilotError, closed, decode, fail

RUN_SECONDS = 10.0
MARKER = b'kitrove-grokbot-synthetic-only/v1\n'


def _stamp(path):
    s = path.lstat()
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns


def _regular(path, *, private=False):
    s = path.lstat()
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1
            or s.st_mode & (0o077 if private else 0o022)):
        fail('config_invalid', fatal=True)
    return s


def _sha(path):
    _regular(path)
    before = _stamp(path)
    with path.open('rb') as stream:
        data = stream.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024 or _stamp(path) != before:
        fail('cli_changed', fatal=True)
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class PilotConfig:
    root: Path
    sha256: str
    identities: tuple

    @property
    def executable(self):
        return self.root / 'bin/kitrove'

    @classmethod
    def load(cls, path):
        if (os.name != 'posix' or not hasattr(os, 'waitid') or not hasattr(os, 'WNOWAIT')
                or signal.getsignal(signal.SIGCHLD) not in (signal.SIG_DFL, None)):
            fail('platform_unsupported', fatal=True)
        try:
            config_path = Path(path)
            _regular(config_path, private=True)
            if config_path.resolve() != config_path: fail('config_invalid', fatal=True)
            with config_path.open('rb') as stream: raw = stream.read(MAX_FRAME + 1)
            if len(raw) > MAX_FRAME: fail('config_invalid', fatal=True)
            data = closed(decode(raw), ('schema_version', 'root', 'cli_sha256', 'data_policy'))
            if (type(data['schema_version']) is not int or data['schema_version'] != 1
                    or data['data_policy'] != 'synthetic-only'
                    or type(data['cli_sha256']) is not str or len(data['cli_sha256']) != 64
                    or any(x not in '0123456789abcdef' for x in data['cli_sha256'])
                    or type(data['root']) is not str):
                fail('config_invalid', fatal=True)
            root = Path(data['root'])
            if not root.is_absolute() or root.resolve() != root or config_path != root/'config.json':
                fail('config_invalid', fatal=True)
            roles = ('', 'bin', 'collection', 'home', 'state', '.git')
            identities = tuple((role, _stamp(root/role)[:2]) for role in roles)
            config = cls(root, data['cli_sha256'], identities)
            config.revalidate()
            return config
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            fail('config_invalid', fatal=True)

    def revalidate(self):
        try:
            if self.root.resolve() != self.root: fail('config_invalid', fatal=True)
            for parent in self.root.parents:
                entry = parent.lstat()
                if (entry.st_uid not in (0, os.getuid()) or not stat.S_ISDIR(entry.st_mode)
                        or entry.st_mode & 0o022 and not entry.st_mode & stat.S_ISVTX):
                    fail('config_invalid', fatal=True)
            s = self.root.lstat()
            if not stat.S_ISDIR(s.st_mode) or s.st_mode & 0o077: fail('config_invalid', fatal=True)
            for role, identity in self.identities:
                p = self.root/role; s = p.lstat()
                if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid()
                        or s.st_mode & 0o022 or _stamp(p)[:2] != identity):
                    fail('config_invalid', fatal=True)
            nodes = 0
            def walk_error(_error):
                fail('config_invalid', fatal=True)
            for directory, dirs, files in os.walk(self.root, followlinks=False, onerror=walk_error):
                for name in dirs + files:
                    nodes += 1; p = Path(directory)/name; s = p.lstat()
                    if nodes > 4096 or s.st_uid != os.getuid() or s.st_mode & 0o022: fail('config_invalid', fatal=True)
                    if not stat.S_ISDIR(s.st_mode):
                        _regular(p)
                        if s.st_size > 64 * 1024 * 1024: fail('config_invalid', fatal=True)
            marker = self.root/'.kitrove-grokbot-pilot'
            _regular(marker)
            with marker.open('rb') as stream:
                if stream.read(len(MARKER)+1) != MARKER: fail('config_invalid', fatal=True)
            # This pilot understands only the clean RC5.18 fixture control layout.
            # Unknown entries and any recovery evidence stop it; it never repairs
            # or deletes a journal. Quarantined retired files are retained data.
            for role, lock in (('state', 'lifecycle.lock'), ('collection', 'environment.lock')):
                control = self.root/role/'.kitrove'
                if control.exists():
                    for child in control.iterdir():
                        if child.name == lock and child.is_file() and child.stat().st_size == 0:
                            continue
                        if role == 'collection' and child.name == 'removal-quarantine' and child.is_dir():
                            continue
                        fail('recovery_or_unknown_state', fatal=True)
            if _sha(self.executable) != self.sha256: fail('cli_changed', fatal=True)
        except OSError:
            fail('config_invalid', fatal=True)


def _unreaped(process):
    try:
        return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except (OSError, ChildProcessError):
        fail('cleanup_unconfirmed', fatal=True)


def _stop(process):
    # WNOWAIT reserves the direct child's PID through the last group signal.
    # Never signal a numeric group after reaping that ownership anchor.
    _unreaped(process)
    for number in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, number)
        except ProcessLookupError:
            pass
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EACCES): fail('cleanup_unconfirmed', fatal=True)
        if number == signal.SIGTERM: time.sleep(0.1)
    try:
        process.wait(timeout=1.0)
        deadline = time.monotonic() + 1.0
        while True:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            except OSError as error:
                if error.errno not in (errno.EPERM, errno.EACCES, errno.EINTR): break
            if time.monotonic() >= deadline: break
            time.sleep(0.02)
    except (OSError, subprocess.TimeoutExpired):
        pass
    fail('cleanup_unconfirmed', fatal=True)


def run_cli(config, arguments, cancelled=lambda: False):
    config.revalidate()
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(config.root/'home'),
        'USERPROFILE': str(config.root/'home'), 'KITROVE_STATE_HOME': str(config.root/'state'),
        'LANG': 'C', 'LC_ALL': 'C', 'NO_COLOR': '1', 'GIT_TERMINAL_PROMPT': '0'}
    try:
        process = subprocess.Popen([str(config.executable), '--json-errors', *arguments,
            '--environment', str(config.root/'collection'), '--json'], cwd=config.root,
            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
    except OSError:
        fail('cli_launch_failed', fatal=True)
    buffers = {1: bytearray(), 2: bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for stream, channel in ((process.stdout, 1), (process.stderr, 2)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, channel)
            deadline = time.monotonic() + RUN_SECONDS
            while True:
                if cancelled(): fail('cancelled')
                if time.monotonic() >= deadline: fail('timeout')
                for key, _events in selector.select(0.05):
                    data = os.read(key.fd, 32768)
                    if not data: selector.unregister(key.fileobj); continue
                    if sum(map(len, buffers.values())) + len(data) > MAX_OUTPUT: fail('output_limit')
                    buffers[key.data].extend(data)
                if _unreaped(process) is not None and not selector.get_map(): break
    except OSError:
        fail('cli_launch_failed', fatal=True)
    finally:
        try:
            _stop(process)
        finally:
            process.stdout.close(); process.stderr.close()
    config.revalidate()
    return process.returncode, bytes(buffers[1]), bytes(buffers[2])
