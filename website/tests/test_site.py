"""Offline checks for the public static site; run from any working directory."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, unquote
import unittest
import importlib.util
import tempfile

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
        spec = importlib.util.spec_from_file_location("site_build", ROOT / "build.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temp:
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
        self.assertIn("v0.1.0-rc.4.1", home)
        self.assertIn("Apple Silicon Macs only", home)
        for command in ("winget install", "choco install", "apt install", "dnf install"):
            self.assertNotIn(command, home)
        self.assertIn("have not published a WinGet or Chocolatey package", visible)
        self.assertIn("have not published APT, DNF", visible)


if __name__ == "__main__":
    unittest.main()
