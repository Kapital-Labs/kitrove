"""Exercise only the supplied source-built CLI in disposable synthetic homes."""
import os
import fcntl
import struct
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
    def __init__(self, root, args, cwd=None, term="xterm-256color", columns=100):
        self.root = root
        self.env = os.environ.copy()
        for name in ("KITROVE_ENV", "XDG_DATA_HOME"):
            self.env.pop(name, None)
        self.env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                        KITROVE_STATE_HOME=str(root / "state"), NO_COLOR="1",
                        TERM=term)
        (root / "home").mkdir(exist_ok=True)
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, columns, 0, 0))
        self.original = termios.tcgetattr(self.slave)
        self.process = subprocess.Popen([BINARY, *args], cwd=cwd or root, env=self.env,
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


def duplicate_source_decision(key, adopt):
    with tempfile.TemporaryDirectory(prefix="kitrove-source-menu-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        skill = root / "home/.claude/skills/shared/SKILL.md"
        skill.parent.mkdir(parents=True)
        original = b"---\nname: shared\ndescription: Synthetic source choice.\n---\nKeep native bytes.\n"
        skill.write_bytes(original)
        env = os.environ.copy()
        for name in ("KITROVE_ENV", "XDG_DATA_HOME"):
            env.pop(name, None)
        env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                   KITROVE_STATE_HOME=str(root / "state"))
        subprocess.run([BINARY, "init", "--environment", str(root / "collection"),
                        "--machine-id", "source-test"], cwd=root, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        session = Session(root, ["configure", "--environment", str(root / "collection")])
        try:
            session.prompt(b"Existing collection path")
            session.send(b"\n")
            session.prompt(b"Choose 1-5 [5]:")
            session.menu_ready()
            session.send(b"1")
            session.prompt(b"? Choose skills")
            session.send(b"all\n")
            session.prompt(b"Choose a tool's copies to preview")
            session.menu_ready()
            assert b"1. claude (1 selected copy)" in session.output
            assert b"Omitted:" not in session.output
            session.output = b""
            session.send(key)
            session.prompt(b"Adopt these skills?")
            session.menu_ready()
            # Choosing a source (even with a trailing Enter) cannot approve it.
            assert before == {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            session.output = b""
            session.send(b"y" if adopt else b"n")
            session.prompt(b"Choose 1-5 [5]:")
            session.menu_ready()
            session.send(b"5")
            session.finish(0)
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            if adopt:
                assert "shared" in (root / "collection/kitrove.toml").read_text()
                assert not (root / "home/.agents/skills/shared").exists()
            else:
                assert before == after
            assert skill.read_bytes() == original
        finally:
            session.close()


def scan_inventory_menu():
    with tempfile.TemporaryDirectory(prefix="kitrove-scan-menu-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        skills = root / "home/.claude/skills"
        for index in range(1, 15):
            name = f"ready-{index:02}"
            skill = skills / name / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text(f"---\nname: {name}\ndescription: Synthetic scan fixture.\n---\nSkill.\n")
        broken = skills / "broken" / "SKILL.md"
        broken.parent.mkdir()
        broken.write_text("---\nname: [broken\ndescription: Malformed YAML fixture.\n---\nSkill.\n")
        before = {p.relative_to(root): p.read_bytes() for p in skills.glob("*/SKILL.md")}
        session = Session(root, ["scan", "--harness", "claude", "--scope", "user"])
        try:
            session.prompt(b"Next action")
            assert b"15 skills listed" in session.output
            assert b"Ready to preview (14)" in session.output, session.output
            assert b"Skills needing review (1)" in session.output, session.output
            assert b"ready-01" not in session.output
            assert b"skill metadata could not be read" not in session.output
            session.menu_ready()
            session.output = b""
            session.send(b"1")
            session.prompt(b"Browse skills")
            assert b"ready-01" in session.output
            assert b"ready-13" not in session.output
            session.menu_ready()
            session.output = b""
            session.send(b"n")
            session.prompt(b"Browse skills")
            assert b"ready-13" in session.output
            session.menu_ready()
            session.output = b""
            session.send(b"\r")
            session.prompt(b"Next action")
            session.menu_ready()
            session.output = b""
            session.send(b"2")
            session.prompt(b"Browse skills")
            assert b"broken" in session.output
            assert b"skill metadata could not be read" in session.output
            session.menu_ready()
            session.output = b""
            session.send(b"b")
            session.prompt(b"Next action")
            session.menu_ready()
            session.output = b""
            session.send(b"d")
            session.prompt(b"Next action")
            assert b"Findings (grouped)" in session.output
            session.menu_ready()
            session.send(b"q")
            session.finish(3)
            after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            assert before == after, "inventory navigation changed the fixture"
            assert not (root / "state").exists()
        finally:
            session.close()



def scan_arrow_navigation(quit_from_group=False):
    with tempfile.TemporaryDirectory(prefix="kitrove-scan-arrows-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        skills = root / "home/.pi/agent/skills"
        for name, contents in [("good", "---\nname: good\ndescription: Fixture.\n---\nSkill.\n"),
                               ("broken", "---\nname: [bad\n---\n")]:
            p = skills / name / "SKILL.md"
            p.parent.mkdir(parents=True)
            p.write_text(contents)
        session = Session(root, ["scan", "--harness", "pi", "--scope", "user"])
        try:
            session.prompt(b"Next action")
            session.menu_ready()
            assert b"Up/Down to move" in session.output
            assert b"\x1b[1;" not in session.output, "NO_COLOR must suppress color"
            session.output = b""
            # Terminal escape sequences may arrive in separate reads.
            for fragment in [b"\x1b", b"[", b"B"]:
                session.send(fragment)
                time.sleep(0.02)
            session.until(b"> [2] Skills needing review")
            session.send(b"\r")
            session.prompt(b"Browse skills")
            assert b"broken" in session.output
            session.menu_ready()
            if quit_from_group:
                session.output = b""
                session.send(b"\x1b[A")
                session.until(b"> [q] Quit")
                session.send(b"\r")
                session.finish(3)
                assert not (root / "state").exists()
                return
            session.output = b""
            session.send(b"b")
            session.prompt(b"Next action")
            session.menu_ready()
            # An uncompleted Escape exits promptly and restores exact terminal flags.
            session.send(b"\x1b")
            session.finish(3)
            assert not (root / "state").exists()
        finally:
            session.close()


def scan_issues_and_rescan():
    with tempfile.TemporaryDirectory(prefix="kitrove-scan-issues-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        supplied = root / "supplied"
        skill = supplied / "broken/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text("---\nname: [bad\n---\n")
        # A filtered-out tool must never appear after retry.
        other = root / "home/.claude/skills/unselected/SKILL.md"
        other.parent.mkdir(parents=True)
        other.write_text("---\nname: unselected\ndescription: Excluded.\n---\nSkill.\n")
        session = Session(root, ["scan", "--harness", "pi", "--scope", "user", "--root", "pi:user:" + str(supplied)])
        try:
            session.prompt(b"Next action")
            session.menu_ready()
            skill.unlink()
            skill.parent.rmdir()
            session.output = b""
            session.send(b"r")
            session.prompt(b"Next action")
            assert b"0 skills listed" in session.output, session.output
            assert b"unselected" not in session.output
            assert b"[a]" not in session.output
            session.menu_ready()
            session.send(b"\r")  # empty scan defaults to Quit, never another scan
            session.finish(0)
            assert not (root / "state").exists()
        finally:
            session.close()
    with tempfile.TemporaryDirectory(prefix="kitrove-folder-issue-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        (root / "home/.pi/agent").mkdir(parents=True)
        target = root / "regular"
        target.mkdir()
        linked = root / "home/.pi/agent/skills"
        linked.symlink_to(target, target_is_directory=True)
        session = Session(root, ["scan", "--harness", "pi", "--scope", "user"])
        try:
            session.prompt(b"Next action")
            session.menu_ready()
            assert b"0 skills listed" in session.output
            assert b"(missing)" not in session.output
            session.send(b"i")
            session.prompt(b"After checking the folder")
            session.menu_ready()
            assert b"folder could not be scanned" in session.output
            assert b"kitrove scan --harness pi --scope user --verbose" in session.output
            linked.unlink()
            linked.mkdir()
            session.output = b""
            session.send(b"r")
            session.prompt(b"Next action")
            session.menu_ready()
            assert b"scan issues" not in session.output
            session.send(b"q")
            session.finish(0)
            assert not (root / "state").exists()
        finally:
            session.close()


def scan_collect_menu(adopt, context="user", fresh=False, stale=False, cancel=False):
    with tempfile.TemporaryDirectory(prefix="kitrove-scan-collect-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        scan_args = ["scan", "--harness", "claude", "--scope", "user"]
        source = root / "home/.claude/skills/scan-skill/SKILL.md"
        if context == "project":
            project = root / "project"
            (project / ".git").mkdir(parents=True)
            source = project / ".claude/skills/scan-skill/SKILL.md"
            scan_args = ["scan", "--harness", "claude", "--scope", "project", "--project-root", str(project)]
        elif context == "explicit":
            supplied = root / "supplied"
            source = supplied / "scan-skill/SKILL.md"
            scan_args += ["--root", "claude:user:" + str(supplied)]
        source.parent.mkdir(parents=True)
        original = b"---\nname: scan-skill\ndescription: Scan collection fixture.\n---\nKeep source bytes.\n"
        source.write_bytes(original)
        unrelated = root / "home/.agents/skills/other-tool/SKILL.md"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text("---\nname: other-tool\ndescription: Excluded harness.\n---\nNot selected.\n")
        env = os.environ.copy()
        for name in ("KITROVE_ENV", "XDG_DATA_HOME"):
            env.pop(name, None)
        env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"), KITROVE_STATE_HOME=str(root / "state"))
        if not fresh:
            subprocess.run([BINARY, "init", "--environment", str(root / "collection"), "--machine-id", "scan-test"],
                           cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            scan_args += ["--environment", str(root / "collection")]
        before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        session = Session(root, scan_args, cwd=root / "project" if context == "project" else root)
        try:
            session.prompt(b"Next action")
            session.menu_ready()
            assert b"[a] Add skills to collection" in session.output, (context, session.output)
            if context == "user":
                session.send(b"1")
                session.prompt(b"Browse skills")
                assert b"[a] Add skills to collection" in session.output, "scan must offer a direct collection handoff"
                session.menu_ready()
            session.output = b""
            session.send(b"a\nyes\n" if cancel else b"a")
            session.prompt(b"Where should your portable collection live?")
            assert not (root / "yes").exists(), "queued input escaped the scan menu"
            if cancel:
                session.send(b"q\n")
                session.finish(3)
                assert before == {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                return
            if fresh:
                session.send(str(root / "collection").encode() + b"\n")
                session.prompt(b"Name this computer")
                session.send(b"scan-new\n")
                session.prompt(b"Create an empty collection")
                session.send(b"y\n")
            else:
                session.send(b"\n")
                session.prompt(b"Continue setup with this existing collection?")
                session.send(b"y\n")
            session.prompt(b"Choose skills to collect")
            assert b"other-tool" not in session.output, "handoff widened the harness filter"
            assert b"1 selectable" in session.output, session.output
            preview_before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            session.send(b"\n")
            session.prompt(b"Adopt these skills?")
            session.menu_ready()
            assert preview_before == {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}, "preview must not mutate"
            if not fresh:
                assert before == preview_before, "existing collection handoff must not mutate"
            session.output = b""
            if stale:
                source.write_bytes(original + b"Changed after preview.\n")
            session.send(b"y" if adopt else b"n")
            if adopt and not stale:
                session.prompt(b"Next: add the collected skills to a tool?")
                session.menu_ready()
                session.send(b"n")
            session.until(b"Previously confirmed steps are retained" if stale else b"Collection step finished.")
            session.finish(1 if stale else 3)
            manifest = (root / "collection/kitrove.toml").read_text()
            if adopt and not stale:
                assert "scan-skill" in manifest and "other-tool" not in manifest
                assert b"No files changed" not in session.output
            elif not stale:
                assert preview_before == {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            else:
                assert "scan-skill" not in manifest, "stale source was adopted"
                assert b"Previously confirmed steps are retained" in session.output
            assert source.read_bytes() == original + (b"Changed after preview.\n" if stale else b"")
            state = (root / "state/state.json").read_text()
            assert '"trust": {}' in state and '"receipts": {}' in state
        finally:
            session.close()


def tool_first_application(tool, *, project=False, approve=True, stale=False, change_collection=False):
    import json
    import shutil
    with tempfile.TemporaryDirectory(prefix="kitrove-tool-apply-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        source = root / "home/.pi/agent/skills/alpha/SKILL.md"
        source.parent.mkdir(parents=True)
        original = b"---\nname: alpha\ndescription: Synthetic tool installation.\n---\nReview the diff.\n"
        source.write_bytes(original)
        session = Session(root, ["init"])
        try:
            def answer(marker, value, immediate=False):
                session.prompt(marker)
                if immediate:
                    session.menu_ready()
                else:
                    session.restored()
                session.output = b""
                session.send(value)
            answer(b"Choose 1-5:", b"1", True)
            answer(b"Where should your portable collection live?", str(root / "collection").encode() + b"\n")
            answer(b"Name this computer", b"tools-test\n")
            answer(b"y/yes confirms", b"y\n")
            answer(b"Choose skills to collect", b"from pi\n")
            answer(b"Adopt these skills?", b"y", True)
            session.until(b"Adopted 1 skills")
            # Only the synthetic source is removed to create an empty Pi destination too.
            assert source.read_bytes() == original
            shutil.rmtree(source.parent)
            answer(b"Choose 1-5 [5]:", b"2", True)
            answer(b"Which AI tools", str(tool).encode() + b"\r", True)
            answer(b"Where should these items", b"2" if project else b"1", True)
            if project:
                answer(b"Absolute project folder", str(root).encode() + b"\n")
            if change_collection:
                session.prompt(b"Which saved items")
                beta = root / "home/.pi/agent/skills/beta/SKILL.md"
                beta.parent.mkdir(parents=True)
                beta.write_bytes(b"---\nname: beta\ndescription: Concurrent fixture addition.\n---\nKeep beta.\n")
                result = subprocess.run([BINARY, "adopt", "beta", "--harness", "pi", "--scope", "user", "--environment", str(root / "collection"), "--json"], cwd=root, env=session.env, input=b"yes\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                assert result.returncode == 0, result.stderr
            answer(b"Which saved items", b"\n")
            if change_collection:
                session.until(b"the collection changed during selection")
                session.finish(1)
                local = json.loads((root / "state/state.json").read_text())
                assert not local["receipts"] and not local["trust"]
                assert not (root / "home/.config/opencode/skills/alpha").exists()
                return
            session.prompt(b"Add the previewed items?")
            session.menu_ready()
            assert b"Absolute trusted" not in session.output
            destination = {
                1: ".claude/skills", 2: ".agents/skills",
                3: ".pi/skills" if project else ".pi/agent/skills",
                4: ".opencode/skills" if project else ".config/opencode/skills",
            }[tool]
            target = (root if project else root / "home") / destination / "alpha/SKILL.md"
            if stale:
                target.parent.mkdir(parents=True)
                target.write_bytes(b"Unmanaged content created after the preview.\n")
            session.output = b""
            session.send(b"y\r" if approve else b"\r")
            if stale:
                session.until(b"Previously confirmed steps are retained")
                session.finish(1)
                assert target.read_bytes() == b"Unmanaged content created after the preview.\n"
            else:
                session.prompt(b"Choose 1-5 [5]:")
                session.menu_ready()
                session.send(b"5")
                session.finish(0)
                assert target.exists() == approve
                if approve:
                    assert b"Review the diff." in target.read_bytes()
                    assert b"Files added" in session.output
            local = json.loads((root / "state/state.json").read_text())
            assert bool(local["receipts"]) == (approve and not stale)
            assert not local["trust"]
        finally:
            session.close()


for tool in (1, 2, 3, 4):
    tool_first_application(tool)
tool_first_application(4, project=True)
tool_first_application(4, approve=False)
tool_first_application(4, stale=True)
tool_first_application(4, change_collection=True)
print("PASS: all four tool-first journeys preserve separate apply approval; project scope, Enter skip, stale destination and terminal restoration verified")


for adopt in (False, True):
    scan_collect_menu(adopt)
scan_collect_menu(True, context="project")
scan_collect_menu(True, context="explicit")
scan_collect_menu(True, fresh=True)
scan_collect_menu(False, fresh=True)
scan_collect_menu(False, cancel=True)
scan_collect_menu(True, stale=True)
print("PASS: scan handoff preserves harness/project/explicit roots; preview/skip/cancel/stale sources keep existing bytes; initialization and adoption have separate approvals")


scan_inventory_menu()
print("PASS: scan sections and pages open without Enter; diagnostics are on demand; scan stays read-only")
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
for key, adopt in ((b"1", False), (b"1", True), (b"1\r", False)):
    duplicate_source_decision(key, adopt)
print("PASS: duplicate-source keys preview immediately; only separate approval adopts; read-ahead cannot approve")


def bare_apply_pack(approve):
    import json
    import shutil
    with tempfile.TemporaryDirectory(prefix="kitrove-bare-apply-", dir=FIXTURE_BASE) as tmp:
        root = Path(tmp).resolve()
        env = os.environ.copy()
        for name in ("KITROVE_ENV", "XDG_DATA_HOME"):
            env.pop(name, None)
        env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"), KITROVE_STATE_HOME=str(root / "state"), NO_COLOR="1", TERM="xterm-256color")
        source = root / "home/.pi/agent/skills/alpha/SKILL.md"
        source.parent.mkdir(parents=True)
        source.write_text("---\nname: alpha\ndescription: Synthetic pack member.\n---\nReview changes.\n")
        def command(args, input=None):
            done = subprocess.run([BINARY, *args, "--environment", str(root / "collection"), "--json"],
                                  env=env, cwd=root, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            assert done.returncode == 0, done.stderr
            return json.loads(done.stdout)
        command(["init", "--machine-id", "pack-user"])
        command(["adopt", "alpha", "--harness", "pi", "--scope", "user"], b"yes\n")
        command(["pack", "create", "--authored", "--pack", "z-review", "--member", "alpha"], b"yes\n")
        shutil.rmtree(source.parent)
        before = (root / "state/state.json").read_bytes()
        session = Session(root, ["apply", "--environment", str(root / "collection")])
        try:
            def answer(marker, value, immediate=False):
                session.prompt(marker)
                if immediate:
                    session.menu_ready()
                else:
                    session.restored()
                session.output = b""
                session.send(value)
            answer(b"Existing collection path", b"\n")
            answer(b"Which AI tools", b"4", True)
            answer(b"Where should these items", b"1", True)
            session.prompt(b"Which saved items")
            assert b"1. z-review [Pack" in session.output
            assert b"2. alpha [Skill]" in session.output
            session.send(b"1\n")
            answer(b"Add the previewed items?", b"y" if approve else b"\r", True)
            session.finish(0)
            target = root / "home/.config/opencode/skills/alpha/SKILL.md"
            assert target.exists() == approve
            state = json.loads((root / "state/state.json").read_text())
            assert bool(state["pack_applications"]) == approve
            assert not state["trust"]
            if not approve:
                assert (root / "state/state.json").read_bytes() == before
        finally:
            session.close()


bare_apply_pack(True)
bare_apply_pack(False)
print("PASS: bare interactive apply selects packs directly, keeps approval separate and restores terminal mode")

scan_arrow_navigation()
scan_arrow_navigation(quit_from_group=True)
scan_issues_and_rescan()


def scan_plain_fallback():
    for term, columns in [("dumb", 100), ("xterm-256color", 40)]:
        with tempfile.TemporaryDirectory(prefix="kitrove-scan-plain-", dir=FIXTURE_BASE) as tmp:
            root = Path(tmp).resolve()
            session = Session(root, ["scan", "--harness", "pi", "--scope", "user"], term=term, columns=columns)
            try:
                session.prompt(b"Next action")
                session.menu_ready()
                assert b"Up/Down" not in session.output
                assert b"\x1b" not in session.output
                assert b"> [q] Quit" in session.output
                session.send(b"\r")
                session.finish(0)
                assert not (root / "state").exists()
            finally:
                session.close()


scan_plain_fallback()
