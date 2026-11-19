import json
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import fesa_prompts as prompts


def synthetic_record(dataset, index=0):
    config, _, _ = prompts.load_policy()
    names = config["datasets"][dataset]["included"]
    values = {name: 0 for name in names}
    values[names[0]] = index
    return {"features": values}


def synthetic_demonstrations(dataset, count):
    return [dict(synthetic_record(dataset, i+1), label=i % 2) for i in range(count)]


class DomainPrompts(unittest.TestCase):
    def test_frozen_inventory_covers_all_columns(self):
        config, dictionary, frozen = prompts.load_policy()
        self.assertEqual(len(frozen), 6)
        for domain, total, included in (("phishing", 20, 8), ("malware", 74, 12)):
            entries = [e for e in dictionary["features"] if e["dataset"] == domain]
            self.assertEqual(len(entries), total)
            self.assertEqual(len(config["datasets"][domain]["included"]), included)
            self.assertTrue(all(e["source"] and e["reason"] and e["evidence"] for e in entries))

    def test_domains_have_correct_subjects_and_targets(self):
        p = prompts.render_prompt("phishing", synthetic_record("phishing"))["prompt"]
        m = prompts.render_prompt("malware", synthetic_record("malware"))["prompt"]
        self.assertIn("website", p)
        self.assertIn("phishing (1)", p)
        self.assertIn("Windows Portable Executable (PE) file", m)
        self.assertNotIn("website", m)
        self.assertNotIn("phishing", m)
        self.assertIn("malicious (1)", m)

    def test_query_label_and_metadata_cannot_enter_prompt(self):
        for domain in ("phishing", "malware"):
            query = synthetic_record(domain)
            base = prompts.render_prompt(domain, query)
            query.update(label="UNSEEN_QUERY_ANSWER", label_true=1, row_id="UNSEEN_ID", source="UNSEEN_LOCATION")
            enriched = prompts.render_prompt(domain, query)
            self.assertEqual(base, enriched)
            self.assertNotIn("UNSEEN", enriched["prompt"])

    def test_target_columns_inside_features_are_rejected(self):
        for name in ("Class", "Category", "Family", "label", "label_true", "CLASS_LABEL", "cLaSs"):
            query = synthetic_record("malware")
            query["features"][name] = 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                prompts.render_prompt("malware", query)

    def test_known_excluded_values_cannot_enter_prompt(self):
        query = synthetic_record("malware")
        for name in ("md5", "sha1", "processes_malicious", "files_malicious", "network_threats"):
            query["features"][name] = "DO_NOT_INCLUDE_THIS_VALUE"
        bundle = prompts.render_prompt("malware", query)
        self.assertNotIn("DO_NOT_INCLUDE", bundle["prompt"])
        self.assertNotIn("processes_malicious", bundle["prompt"])
        self.assertEqual(len(bundle["excluded_feature_names"]["query"]), 5)

    def test_unknown_or_missing_features_fail_closed(self):
        query = synthetic_record("phishing")
        query["features"]["unsupported_column"] = 0
        with self.assertRaises(ValueError):
            prompts.render_prompt("phishing", query)
        query = synthetic_record("phishing")
        query["features"].pop("NumDots")
        with self.assertRaises(ValueError):
            prompts.render_prompt("phishing", query)

    def test_numeric_encoding_is_exact_and_canonical(self):
        for value in (32, 32.0, "32", "0x20", " 0X20 "):
            self.assertEqual(prompts.unsigned(value, 32), 32)
        self.assertEqual(prompts.unsigned(str(2**64-1), 64), 2**64-1)
        query = synthetic_record("malware")
        query["features"]["SizeOfCode"] = "0x20"
        bundle = prompts.render_prompt("malware", query)
        self.assertIn("SizeOfCode = 32", bundle["prompt"])
        self.assertNotIn("0x20", bundle["prompt"])

    def test_invalid_numeric_values_rejected_without_echoing_values(self):
        invalid = [True, False, -1, 1.5, float("nan"), float("inf"), float(2**53),
                   2**32, None, "?", "NaN", "-1", "0xnothex", "SENSITIVE_INJECTED_TEXT", []]
        for value in invalid:
            query = synthetic_record("phishing")
            query["features"]["NumDots"] = value
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError) as error:
                prompts.render_prompt("phishing", query)
            self.assertNotIn("SENSITIVE_INJECTED_TEXT", str(error.exception))

    def test_unusual_integer_pe_values_are_preserved(self):
        query = synthetic_record("malware")
        query["features"]["SectionAlignment"] = 3
        self.assertIn("SectionAlignment = 3", prompts.render_prompt("malware", query)["prompt"])

    def test_label_order_changes_only_declared_clause(self):
        config, _, _ = prompts.load_policy()
        for domain in ("phishing", "malware"):
            for count in (0, 4, 10):
                query = synthetic_record(domain)
                examples = synthetic_demonstrations(domain, count)
                a = prompts.render_prompt(domain, query, examples, "A")["prompt"]
                b = prompts.render_prompt(domain, query, examples, "B")["prompt"]
                spec = config["datasets"][domain]
                self.assertEqual(a.replace(spec["label_order_a"], spec["label_order_b"]), b)

    def test_zero_four_ten_examples_and_labels(self):
        for count in (0, 4, 10):
            bundle = prompts.render_prompt("phishing", synthetic_record("phishing"),
                                            synthetic_demonstrations("phishing", count))
            self.assertEqual(bundle["demonstration_count"], count)
            self.assertEqual(bundle["demonstration_labels"], [i % 2 for i in range(count)])
            self.assertEqual(bundle["prompt"].count("\nAnswer: "), count)
            self.assertEqual(bundle["prompt_sha256"], prompts.sha(bundle["prompt"].encode()))

    def test_bad_demonstration_labels_and_balance_are_rejected(self):
        for invalid in (True, "0", None, 2):
            examples = synthetic_demonstrations("phishing", 4)
            examples[0]["label"] = invalid
            with self.assertRaises(ValueError):
                prompts.render_prompt("phishing", synthetic_record("phishing"), examples)
        examples = synthetic_demonstrations("phishing", 4)
        examples[0]["label"] = 1
        with self.assertRaises(ValueError):
            prompts.render_prompt("phishing", synthetic_record("phishing"), examples)

    def test_duplicate_projected_vectors_are_rejected(self):
        for duplicate_query in (True, False):
            examples = synthetic_demonstrations("malware", 4)
            examples[1]["features"] = dict((synthetic_record("malware") if duplicate_query else examples[0])["features"])
            with self.assertRaises(ValueError):
                prompts.render_prompt("malware", synthetic_record("malware"), examples)

    def test_invalid_domain_order_and_count_are_rejected(self):
        for domain, order, count in (("unknown", "A", 0), ("phishing", "unknown", 0), ("phishing", "A", 2)):
            with self.assertRaises(ValueError):
                prompts.render_prompt(domain, synthetic_record("phishing"),
                                      synthetic_demonstrations("phishing", count), order)

    def test_changed_frozen_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in prompts.FREEZE_FILES+("configs/prompt-v1.sha256",):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, path)
            (root / "prompts/phishing-v1.txt").write_text("changed")
            with self.assertRaises(ValueError):
                prompts.render_prompt("phishing", synthetic_record("phishing"), root=root)

    def test_private_exact_prompt_is_owner_only_and_immutable(self):
        bundle = prompts.render_prompt("phishing", synthetic_record("phishing"))
        with tempfile.TemporaryDirectory() as td:
            path = prompts.save_private_prompt(bundle, td)
            second = prompts.save_private_prompt(bundle, td)
            self.assertNotEqual(path, second)
            self.assertEqual(json.loads(path.read_text()), bundle)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_private_symlink_and_broad_permissions_are_rejected(self):
        bundle = prompts.render_prompt("malware", synthetic_record("malware"))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            other = root / "public"
            other.mkdir()
            (root / "private").symlink_to(other, target_is_directory=True)
            with self.assertRaises(ValueError):
                prompts.save_private_prompt(bundle, root)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "private").mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                prompts.save_private_prompt(bundle, root)

    def test_tampered_prompt_digest_cannot_be_saved(self):
        bundle = prompts.render_prompt("malware", synthetic_record("malware"))
        bundle["prompt"] += "changed"
        with tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
            prompts.save_private_prompt(bundle, td)

    def test_cli_renders_offline_and_writes_only_private_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in prompts.FREEZE_FILES+("configs/prompt-v1.sha256",):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, path)
            query = synthetic_record("malware")
            query["label"] = "DO_NOT_LEAK_QUERY_LABEL"
            input_path = root / "input.json"
            input_path.write_text(json.dumps(query))
            result = subprocess.run([sys.executable, "-B", "scripts/render_prompt.py",
                                     "--dataset", "malware", "--input", str(input_path)],
                                    cwd=root, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.startswith("Saved exact prompt privately: private/prompts/"))
            self.assertNotIn("SizeOfCode", result.stdout)
            files = list((root / "private/prompts").glob("*.json"))
            self.assertEqual(len(files), 1)
            self.assertNotIn("DO_NOT_LEAK_QUERY_LABEL", files[0].read_text())


if __name__ == "__main__":
    unittest.main()
