"""Reproducible, credential-free third-party release document tests."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


class ReleaseNoticesTests(unittest.TestCase):
    def load_generator(self):
        path = Path(__file__).with_name("release_notices.py")
        self.assertTrue(path.is_file(), "release notice generator is required")
        spec = importlib.util.spec_from_file_location("release_notices", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self, root, files=None):
        files = {"LICENSE-MIT": b"Copyright fixture\nMIT terms\n",
                 "nested/NOTICE": b"Attribution\n"} if files is None else files
        registry = root / "registry"
        source = registry / "src/test/sample-1.0.0"
        source.mkdir(parents=True)
        archive = registry / "cache/test/sample-1.0.0.crate"
        archive.parent.mkdir(parents=True)
        with tarfile.open(archive, "w:gz") as output:
            for name, content in files.items():
                item = tarfile.TarInfo("sample-1.0.0/" + name)
                item.size = len(content)
                output.addfile(item, io.BytesIO(content))
        origin = "registry+https://example.invalid/index"
        inputs = {
            "metadata": {"workspace_members": [], "packages": [{
                "id": "sample-id", "name": "sample", "version": "1.0.0",
                "source": origin, "license": "MIT",
                "manifest_path": str(source / "Cargo.toml"),
            }]},
            "lock_packages": [{"name": "sample", "version": "1.0.0", "source": origin,
                               "checksum": hashlib.sha256(archive.read_bytes()).hexdigest()}],
            "inventory": "package\tversion\tlicense\nsample\t1.0.0\tMIT\n"
                         "dependency license checks passed (1 third-party packages inspected)\n",
        }
        (root / "release/license-supplements").mkdir(parents=True)
        (root / "release/license-supplements/index.json").write_text("[]\n")
        return inputs, archive

    def test_materials_are_complete_deterministic_and_path_private(self):
        module = self.load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, _ = self.fixture(root)
            observed = module.render_documents(inputs, root)
            self.assertEqual(observed, module.render_documents(inputs, root))
            self.assertEqual(observed["THIRD_PARTY_LICENSE_INVENTORY.txt"],
                             inputs["inventory"].encode())
            texts = observed["THIRD_PARTY_LICENSES.txt"]
            self.assertIn(b"Copyright fixture\nMIT terms\n", texts)
            self.assertIn(b"Attribution\n", texts)
            self.assertIn(b"nested/NOTICE", texts)
            self.assertIn(inputs["lock_packages"][0]["checksum"].encode(), texts)
            self.assertNotIn(temporary.encode(), texts)

    def test_wrong_crate_checksum_and_wrong_inventory_refuse(self):
        module = self.load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, archive = self.fixture(root)
            original = archive.read_bytes()
            archive.write_bytes(original + b"changed")
            with mock.patch.object(module.tarfile, "open", side_effect=AssertionError("decoded before authentication")):
                with self.assertRaisesRegex(ValueError, "checksum"):
                    module.render_documents(inputs, root)
            archive.write_bytes(original)
            inputs["inventory"] = inputs["inventory"].replace("1.0.0", "0.0.0")
            with self.assertRaisesRegex(ValueError, "inventory"):
                module.render_documents(inputs, root)

    def test_missing_material_and_unknown_supplement_refuse(self):
        module = self.load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, _ = self.fixture(root, {"src/lib.rs": b"not license text"})
            with self.assertRaisesRegex(ValueError, "missing"):
                module.render_documents(inputs, root)
            supplements = root / "release/license-supplements/index.json"
            supplements.write_text('[{"name":"unknown","version":"1"}]')
            with self.assertRaises(ValueError):
                module.render_documents(inputs, root)

    def test_duplicate_text_retains_all_path_references(self):
        module = self.load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, _ = self.fixture(root, {"LICENSE": b"same terms\n",
                                            "nested/NOTICE": b"same terms\n"})
            text = module.render_documents(inputs, root)["THIRD_PARTY_LICENSES.txt"]
            self.assertEqual(text.count(b"same terms\n"), 1)
            self.assertIn(b"LICENSE", text)
            self.assertIn(b"nested/NOTICE", text)

    def test_reference_rows_put_explicit_checksum_before_source_path(self):
        module = self.load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            content = b"Copyright fixture\nMIT terms\n"
            inputs, _ = self.fixture(root, {"winapi/LICENSE-MIT": content})
            text = module.render_documents(inputs, root)["THIRD_PARTY_LICENSES.txt"]
            digest = hashlib.sha256(content).hexdigest().encode()
            self.assertIn(b"  SHA-256:" + digest + b"\twinapi/LICENSE-MIT\n", text)
            self.assertIn(content, text)

    def test_supplement_requires_pinned_hash_and_retains_exact_source(self):
        module = self.load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, _ = self.fixture(root, {"src/lib.rs": b"code"})
            supplements = root / "release/license-supplements"
            text = b"Copyright missing-upstream-file fixture\nTerms\n"
            (supplements / "MIT.txt").write_bytes(text)
            source = "https://raw.githubusercontent.com/example/project/" + "a" * 40 + "/LICENSE"
            index = [{"name": "sample", "version": "1.0.0", "provenance": "fixture source",
                      "files": [{"path": "MIT.txt", "sha256": hashlib.sha256(text).hexdigest(),
                                 "url": source}]}]
            (supplements / "index.json").write_text(json.dumps(index))
            observed = module.render_documents(inputs, root)["THIRD_PARTY_LICENSES.txt"]
            self.assertIn(text, observed)
            self.assertIn(source.encode(), observed)
            (supplements / "MIT.txt").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum"):
                module.render_documents(inputs, root)

    def test_check_and_write_refuse_redirected_outputs_and_detect_stale_bytes(self):
        module = self.load_generator()
        self.assertTrue(hasattr(module, "persist_documents"), "safe document persistence is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "release").mkdir()
            documents = {"THIRD_PARTY_LICENSES.txt": b"reviewed"}
            module.persist_documents(documents, root, check=False)
            module.persist_documents(documents, root, check=True)
            output = root / "release/THIRD_PARTY_LICENSES.txt"
            output.write_bytes(b"stale")
            with self.assertRaisesRegex(ValueError, "stale"):
                module.persist_documents(documents, root, check=True)
            if hasattr(__import__('os'), 'symlink'):
                try:
                    output.unlink()
                    output.symlink_to(root / "absent")
                except OSError:
                    self.skipTest("symlink creation unavailable for this user")
                with self.assertRaises(ValueError):
                    module.persist_documents(documents, root, check=False)
                self.assertFalse((root / "absent").exists())

    def test_notice_generation_forces_offline_cargo(self):
        module = self.load_generator()
        with mock.patch.object(module.subprocess, "run") as run, \
                mock.patch.object(module, "render_documents", return_value={}), \
                mock.patch("sys.argv", ["release_notices.py", "--check"]):
            run.return_value.stdout = b"{}"
            module.main()
            self.assertEqual(run.call_args.kwargs.get("env", {}).get("CARGO_NET_OFFLINE"), "true")

    def test_crate_path_link_empty_and_non_utf8_materials_refuse(self):
        module = self.load_generator()
        for kind in ("traversal", "link", "empty", "non-utf8"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                inputs, archive = self.fixture(root)
                with tarfile.open(archive, "w:gz") as output:
                    member = tarfile.TarInfo("sample-1.0.0/" +
                                            ("../LICENSE" if kind == "traversal" else "LICENSE"))
                    body = b"\xff" if kind == "non-utf8" else b"terms"
                    if kind == "link":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "../../outside"
                        output.addfile(member)
                    else:
                        body = b"" if kind == "empty" else body
                        member.size = len(body)
                        output.addfile(member, io.BytesIO(body))
                inputs["lock_packages"][0]["checksum"] = hashlib.sha256(archive.read_bytes()).hexdigest()
                with self.assertRaises(ValueError):
                    module.render_documents(inputs, root)
                self.assertFalse((root / "outside").exists())

    def test_document_output_names_are_closed(self):
        module = self.load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "release").mkdir()
            with self.assertRaises(ValueError):
                module.persist_documents({"../unmanaged": b"refuse"}, root, check=False)
            self.assertFalse((root / "unmanaged").exists())


if __name__ == "__main__":
    unittest.main()
