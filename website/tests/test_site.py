"""Offline checks for the public static site; run from any working directory."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, unquote
import unittest
import importlib.util
import tempfile
import shutil

ROOT = Path(__file__).resolve().parents[1]


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.ids = []
        self.refs = []
        self.tags = []
        self.text = []
        self.feed(path.read_text())

    def handle_data(self, data):
        self.text.append(data)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if "id" in attrs:
            self.ids.append(attrs["id"])
        for key in ("href", "src"):
            if key in attrs:
                self.refs.append(attrs[key])


class SiteTests(unittest.TestCase):
    def test_deployment_inventory_and_no_reuse(self):
        with tempfile.TemporaryDirectory() as temp:
            # Static build semantics stay offline; package staging has separate tests.
            fixture = Path(temp) / "source"
            fixture.mkdir()
            for name in ("build.py", "package_assets.py", "index.html", "docs/index.html", "styles.css", "app.js", "mark.svg"):
                target = fixture / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            (fixture / "package_inventory.json").write_text('{"version":1,"files":[]}')
            spec = importlib.util.spec_from_file_location("site_build", fixture / "build.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            target = Path(temp) / "public"
            module.build(target)
            self.assertEqual(
                {str(path.relative_to(target)) for path in target.rglob("*") if path.is_file()},
                set(module.ASSETS) | {"CNAME", ".nojekyll"},
            )
            self.assertEqual((target / "CNAME").read_text(), "kitrove.dev\n")
            with self.assertRaises(FileExistsError):
                module.build(target)

    def test_local_links_and_fragments(self):
        for path in ROOT.rglob("*.html"):
            page = Page(path)
            self.assertEqual(len(page.ids), len(set(page.ids)), path)
            for ref in page.refs:
                url = urlsplit(ref)
                if url.scheme or url.netloc:
                    self.assertEqual(url.scheme, "https", ref)
                    continue
                target = (path.parent / unquote(url.path)).resolve() if url.path else path
                if target.is_dir():
                    target /= "index.html"
                self.assertTrue(target.is_relative_to(ROOT), ref)
                self.assertTrue(target.is_file(), str(target))
                if url.fragment:
                    self.assertIn(unquote(url.fragment), Page(target).ids, ref)

    def test_accessible_document_basics(self):
        for path in ROOT.rglob("*.html"):
            tags = Page(path).tags
            self.assertEqual(sum(tag == "h1" for tag, _ in tags), 1)
            self.assertTrue(any(tag == "html" and attrs.get("lang") == "en" for tag, attrs in tags))
            self.assertTrue(any(tag == "meta" and attrs.get("name") == "viewport" for tag, attrs in tags))
            for tag, attrs in tags:
                if tag == "img":
                    self.assertIn("alt", attrs)
                if tag == "script":
                    self.assertFalse(attrs.get("src", "").startswith("http"))

    def test_current_distribution_claims(self):
        home = (ROOT / "index.html").read_text()
        visible = " ".join(" ".join(Page(ROOT / "index.html").text).split())
        self.assertIn("brew install --cask kapital-labs/tap/kitrove-rc", home)
        self.assertIn("v0.1.0-rc.5.5", home)
        self.assertNotIn("v0.1.0-rc.4.1", home)
        self.assertIn("Apple Silicon Macs only", home)
        for command in ("winget install", "choco install", "apt install", "dnf install"):
            self.assertNotIn(command, home)
        self.assertIn("RC4.2 WinGet submission is not an RC5.5 install path", visible)
        self.assertIn("No Chocolatey package is published", visible)
        self.assertIn("RC4.2 signed APT or DNF repository", visible)
        self.assertIn("docs/LINUX-INSTALL.md", home)

    def test_release_and_acceptance_boundaries(self):
        for relative in ("index.html", "docs/index.html"):
            page = ROOT / relative
            source = page.read_text()
            visible = " ".join(" ".join(Page(page).text).split())
            self.assertIn("RC5.5", visible)
            self.assertIn("RC4.2", visible)
            self.assertIn("RC4.2 WinGet submission is not an RC5.5 install path", visible)
            self.assertIn("#ubuntu--apt", source)
            self.assertIn("#fedora--dnf", source)
            self.assertIn("fresh-install evaluation", visible)
            self.assertIn("new isolated collection", visible)
            self.assertIn("not a supported in-place upgrade", visible)
            self.assertIn("Intel Macs are unsupported", visible)
            self.assertIn("clean-Mac", visible)
            self.assertIn("live agent-tool execution", visible)
            self.assertIn("concurrent sync", visible)
            self.assertNotIn("winget install", source)
        docs = " ".join(" ".join(Page(ROOT / "docs/index.html").text).split())
        self.assertIn("authored packs", docs)
        self.assertIn("Cloud-provider sync is roadmap work", docs)

    def test_exact_preview_links_and_verification_before_execution(self):
        release = "https://github.com/Kapital-Labs/kitrove/releases/tag/v0.1.0-rc.5.5"
        versioned = "https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.5/"
        for relative in ("index.html", "docs/index.html"):
            page = Page(ROOT / relative)
            self.assertIn(release, page.refs)
            self.assertIn(versioned + "docs/INSTALLER.md", page.refs)
            self.assertIn(versioned + "release/notes/v0.1.0-rc.5.5.md", page.refs)
            visible = " ".join(" ".join(page.text).split())
            self.assertIn("Verify before running", visible)
            self.assertIn("Homebrew", visible)
            self.assertIn("do not install RC5.5", visible)
            self.assertNotIn("Intel Mac and Windows", visible)
            self.assertNotIn("curl |", visible)
            self.assertNotIn("iex", visible)


if __name__ == "__main__":
    unittest.main()
