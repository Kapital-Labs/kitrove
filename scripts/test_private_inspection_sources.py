"""Shared lifecycle implementation stays private; never launch native tools."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PrivateInspectionSources(unittest.TestCase):
    def test_probe_uses_one_shared_private_source_for_each_mechanic(self):
        source = (ROOT / 'crates/kitrove-version-probe/src/lib.rs').read_text()
        for name in ('unix_process', 'bounded_output', 'inspection_failure'):
            with self.subTest(name=name):
                declaration = re.search(
                    r'#\[path = "([^"]+)"\]\s*mod ' + name + r';', source)
                self.assertIsNotNone(declaration, 'mechanic must resolve to shared private source')
                actual = (ROOT / 'crates/kitrove-version-probe/src' / declaration[1]).resolve()
                expected = ROOT / 'support/native-inspection/src' / (name + '.rs')
                self.assertEqual(actual, expected)
                self.assertTrue(actual.is_file())
                self.assertFalse((ROOT / 'crates/kitrove-version-probe/src' / (name + '.rs')).exists())
                text = actual.read_text()
                self.assertNotRegex(text, r'(?m)^pub (?:fn|struct|enum|mod|trait)\b')
                self.assertNotIn('unsafe {', text)

    def test_probe_specific_output_tests_are_not_in_shared_production_source(self):
        path = ROOT / 'support/native-inspection/src/bounded_output.rs'
        self.assertTrue(path.is_file(), 'shared output source is missing')
        text = path.read_text()
        self.assertNotIn('crate::ProbeError', text)
        self.assertNotIn('crate::MAX_PROBE_OUTPUT_BYTES', text)
        source = (ROOT / 'crates/kitrove-version-probe/src/lib.rs').read_text()
        self.assertIn('#[path = "bounded_output_tests.rs"]', source)


if __name__ == '__main__':
    unittest.main()
