"""Exercise only the supplied source-built CLI in disposable synthetic homes."""
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time

BINARY = str(Path(sys.argv[1]).resolve(strict=True))
# The Rust fixture owner supplies the existing repository's trusted temp root.
FIXTURE_BASE = Path(sys.argv[2]).resolve(strict=True)


class Session:
    def __init__(self, root, args):
        self.root = root
        self.env = os.environ.copy()
        for name in ("KITROVE_ENV", "XDG_DATA_HOME"):
            self.env.pop(name, None)
        self.env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                        KITROVE_STATE_HOME=str(root / "state"), NO_COLOR="1",
                        TERM="xterm-256color")
        (root / "home").mkdir(exist_ok=True)
        self.master, self.slave = pty.openpty()
        self.original = termios.tcgetattr(self.slave)
        self.process = subprocess.Popen([BINARY, *args], cwd=root, env=self.env,
                                        stdin=self.slave, stdout=self.slave,
                                        stderr=self.slave, start_new_session=True)
        self.output = b""

    def until(self, marker):
        self.wait_for(lambda: marker in self.output, marker)

    def prompt(self, marker):
        def complete():
            start = self.output.rfind(marker)
            return start >= 0 and b"\n> " in self.output[start:]
        self.wait_for(complete, marker)

    def wait_for(self, complete, marker):
        deadline = time.monotonic() + 5
        while not complete():
            if time.monotonic() >= deadline:
                raise AssertionError("menu did not advance without Enter: " + repr(marker))
            ready, _, _ = select.select([self.master], [], [], 0.1)
            if ready:
                self.output += os.read(self.master, 65536)

    def send(self, value):
        os.write(self.master, value)

    def restored(self):
        observed = termios.tcgetattr(self.slave)
        # Darwin sets PENDIN when canonical input is restored (kernel retype state),
        # not an input/echo/signal policy bit. All other flags/cc/speeds stay exact.
        self.original[3] &= ~termios.PENDIN
        observed[3] &= ~termios.PENDIN
        assert observed == self.original, "terminal mode not restored: " + repr((self.original, observed))

    def menu_ready(self):
        deadline = time.monotonic() + 5
        while termios.tcgetattr(self.slave)[3] & termios.ICANON:
            if time.monotonic() >= deadline:
                raise AssertionError("numbered menu never enabled immediate input")
            time.sleep(0.01)

    def finish(self, expected):
        assert self.process.wait(timeout=5) == expected
        self.restored()

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        os.close(self.master)
        os.close(self.slave)


def initial_menu():
    with tempfile.TemporaryDirectory(prefix="kitrove-menu-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        session = Session(root, ["init"])
        try:
            session.until(b"Choose 1-5:")
            session.menu_ready()
            session.send(b"1")
            session.until(b"Where should your portable collection live?")
            session.restored()
            session.send(b"q\n")
            session.finish(1)
            assert not (root / "state").exists()
            assert not (root / "home/Kitrove").exists()
        finally:
            session.close()


def quit_menu(key):
    with tempfile.TemporaryDirectory(prefix="kitrove-menu-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        session = Session(root, ["init"])
        try:
            session.until(b"Choose 1-5:")
            session.menu_ready()
            session.send(key)
            session.finish(1)
            assert not (root / "state").exists()
        finally:
            session.close()


def configuration_menu(key):
    with tempfile.TemporaryDirectory(prefix="kitrove-menu-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        (root / "home").mkdir()
        env = os.environ.copy()
        env.pop("KITROVE_ENV", None)
        env.pop("XDG_DATA_HOME", None)
        env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                   KITROVE_STATE_HOME=str(root / "state"))
        subprocess.run([BINARY, "init", "--environment", str(root / "collection"),
                        "--machine-id", "menu-test"], cwd=root, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        session = Session(root, ["configure", "--environment", str(root / "collection")])
        try:
            session.until(b"Existing collection path")
            session.send(b"\n")
            session.until(b"Choose 1-5 [5]:")
            session.menu_ready()
            session.send(key)
            session.finish(0)
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            assert before == after, "navigation changed synthetic collection bytes"
        finally:
            session.close()


def adoption_decision(key, adopt, source_answer=b"from pi\n"):
    with tempfile.TemporaryDirectory(prefix="kitrove-adoption-menu-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        skill = root / "home/.pi/agent/skills/alpha/SKILL.md"
        skill.parent.mkdir(parents=True)
        original = b"---\nname: alpha\ndescription: Synthetic menu fixture.\n---\nKeep native instructions.\n"
        skill.write_bytes(original)
        env = os.environ.copy()
        for name in ("KITROVE_ENV", "XDG_DATA_HOME"):
            env.pop(name, None)
        env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                   KITROVE_STATE_HOME=str(root / "state"))
        subprocess.run([BINARY, "init", "--environment", str(root / "collection"),
                        "--machine-id", "menu-test"], cwd=root, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        session = Session(root, ["configure", "--environment", str(root / "collection")])
        try:
            session.until(b"Existing collection path")
            session.send(b"\n")
            session.until(b"Choose 1-5 [5]:")
            session.menu_ready()
            session.send(b"1")
            session.until(b"? Choose skills")
            session.restored()
            session.send(source_answer)
            session.prompt(b"Adoption preview")
            session.menu_ready()
            session.output = b""
            session.send(key)
            if key == b"s":
                session.prompt(b"? Choose skills")
                session.restored()
                session.send(b"n\n")
            elif key == b"d":
                session.prompt(b"Adopt these skills?")
                session.menu_ready()
                session.output = b""
                session.send(b"n")
            elif key.startswith(b"r"):
                session.prompt(b"Adopt this skill?")
                session.menu_ready()
                session.output = b""
                session.send(b"n")
            if adopt:
                session.until(b"Adopted 1 skills")
            session.prompt(b"Choose 1-5 [5]:")
            session.menu_ready()
            session.send(b"5")
            session.finish(0)
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            if adopt:
                assert "alpha" in (root / "collection/kitrove.toml").read_text()
                assert not (root / "home/.agents/skills/alpha").exists(), "adoption is not Apply"
            else:
                assert before == after, "a navigation/skip choice changed fixture bytes"
            assert skill.read_bytes() == original
        finally:
            session.close()


initial_menu()
print("PASS: 1 advances immediately; path stays line based; cancellation restores terminal")
for key in (b"q", b"\x03", b"\x04", b"\x1b"):
    quit_menu(key)
print("PASS: q/Ctrl-C/Ctrl-D/Escape cancel immediately and restore terminal")
for key in (b"5", b"\r", b"\n"):
    configuration_menu(key)
print("PASS: 5/Enter finish immediately without changing fixture bytes")
for key in (b"y", b"\r", b"y\r"):
    adoption_decision(key, True)
print("PASS: single y or Enter adopts only the displayed preview without another key")
for key in (b"n", b"s", b"d", b"r", b"r\r"):
    adoption_decision(key, False)
print("PASS: n/s/d/r act immediately without adoption; native fixture bytes unchanged")
adoption_decision(b"n", False, source_answer=b"from pi\n\n")
print("PASS: a pasted trailing Enter cannot confirm a not-yet-displayed preview")
