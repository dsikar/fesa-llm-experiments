import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from check_public_tree import findings
from render_baseline import render
from verify_baseline import exact_half, holm, verify, wilson


class PublicArtifacts(unittest.TestCase):
    def setUp(self):
        self.value = json.loads((ROOT / "results/public/pilot-v2.json").read_text())

    def test_export_verifies(self):
        verify(self.value)

    def test_rejects_wrong_accuracy(self):
        self.value["datasets"]["phishing"]["conditions"]["c1_zero_a"]["accuracy"] = 0.99
        with self.assertRaises(ValueError):
            verify(self.value)

    def test_rejects_incomplete_results(self):
        self.value["datasets"]["ransomware"]["conditions"]["c3_few_bal_a"]["errors"] = 1
        with self.assertRaises(ValueError):
            verify(self.value)

    def test_rejects_extra_metadata(self):
        self.value["infrastructure"] = "not a public field"
        with self.assertRaises(ValueError):
            verify(self.value)

    def test_rejects_inconsistent_transitions(self):
        self.value["datasets"]["ransomware"]["label_order_predictions"]["few"]["transitions"]["01"] = 8
        with self.assertRaises(ValueError):
            verify(self.value)

    def test_report_is_generated(self):
        self.assertEqual(render(self.value), (ROOT / "docs/PILOT_V2.md").read_text())

    def test_statistical_reference_values(self):
        self.assertEqual(exact_half(50, 100), 1)
        self.assertEqual(exact_half(0, 9), 2/512)
        self.assertEqual([round(v, 8) for v in holm([0.01, 0.04, 0.03])], [0.03, 0.06, 0.06])
        self.assertAlmostEqual(wilson(50, 100)[0], 0.4038315303659956)

    def test_disclosure_checker_detects_constructed_fixtures(self):
        examples = ["ghp_"+"x"*30, "/"+"users"+"/"+"example"+"/secret", "aczd"+"123", "gpu"+"99"]
        for text in examples:
            with self.subTest(text_type=type(text).__name__):
                self.assertTrue(findings("docs/example.md", text))

    def test_disclosure_checker_rejects_raw_locations(self):
        self.assertTrue(findings("private/record.txt", "synthetic"))
        self.assertTrue(findings("results/record.json", "{}"))
        self.assertFalse(findings("results/public/aggregate.json", "{}"))


if __name__ == "__main__":
    unittest.main()
