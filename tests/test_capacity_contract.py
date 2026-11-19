"""Synthetic end-to-end checks for the capacity output contract. No model calls."""

import copy
import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from capacity_contract import (  # noqa: E402
    ACCOUNTING_POLICY,
    AMENDMENTS,
    CONDITION_FIELD_NAMES,
    CapacityContractError,
    PREDICTION_FIELDS,
    PRIVATE_CONDITION_FIELDS,
    _design,
    _prediction,
    assemble_public_condition,
    canonical_json,
    export_public_aggregate,
    render_table,
    schema_documents,
    synthetic_public_aggregate,
    validate_aggregate,
    validate_planning_inventory,
    validate_public_condition,
    write_synthetic_layout,
)
from check_public_tree import findings  # noqa: E402
from verify_baseline import wilson  # noqa: E402

FIXTURE = ROOT / "tests/fixtures/capacity/synthetic-aggregate.json"
PLAN = ROOT / "results/public/capacity-plan.json"


def close(actual, expected):
    if not math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-12):
        raise AssertionError(f"{actual} != {expected}")


class CapacityContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = synthetic_public_aggregate()
        cls.by_id = {condition["condition_id"]: condition for condition in cls.document["conditions"]}

    def condition(self, feature, dataset="synthetic-phish", split="split-heldout", demos=0, order="a", replicate=1):
        condition_id = f"cap-{dataset}-{split}-{feature}-d{demos}-{order}-r{replicate}"
        return self.by_id[condition_id]

    def test_fixture_file_matches_the_builder(self):
        self.assertEqual(FIXTURE.read_text(), canonical_json(self.document))
        reloaded = json.loads(FIXTURE.read_text())
        validate_aggregate(reloaded)
        self.assertEqual(render_table(reloaded), render_table(self.document))

    def test_schemas_match_the_field_contract(self):
        documents = schema_documents()
        for name, document in documents.items():
            self.assertEqual((ROOT / "schemas" / name).read_text(), canonical_json(document))
        self.assertEqual(documents["capacity-aggregate-v1.schema.json"]["required"], list(self.document))
        private = documents["capacity-condition-private-v1.schema.json"]
        self.assertEqual(set(private["required"]), set(CONDITION_FIELD_NAMES) | set(PRIVATE_CONDITION_FIELDS))
        self.assertEqual(documents["capacity-prediction-private-v1.schema.json"]["required"], list(PREDICTION_FIELDS))
        self.assertIn("incomplete", private["properties"]["status"]["enum"])
        self.assertIn("running", private["properties"]["status"]["enum"])
        public_status = documents["capacity-aggregate-v1.schema.json"]["properties"]["conditions"]["items"]["properties"]["status"]["enum"]
        self.assertIn("incomplete", public_status)
        self.assertNotIn("running", public_status)
        self.assertEqual(self.document["amendment_ids"], list(AMENDMENTS))
        self.assertEqual(self.document["accounting_policy"], ACCOUNTING_POLICY)
        self.assertTrue(self.document["synthetic"])
        self.assertTrue(self.document["not_an_experiment"])
        self.assertEqual(self.document["model_requests_made"], 0)
        self.assertIn("SYNTHETIC FIXTURE", self.document["disclaimer"])
        self.assertFalse((ROOT / "results/public/capacity-results.json").exists())

    def test_table_is_deterministic_and_keeps_arms_distinct(self):
        flipped = copy.deepcopy(self.document)
        flipped["conditions"].reverse()
        self.assertEqual(render_table(self.document), render_table(flipped))
        self.assertEqual(render_table(self.document), render_table(self.document))
        rendered = render_table(self.document)
        self.assertEqual(rendered.count("\n| phishing |"), 11)
        self.assertEqual(rendered.count("\n| malware |"), 1)
        for fragment in (
            "features-max", "features-reduced", "split-dev", "split-heldout",
            "| 0 | B |", "| 4 | A |", "| 0 | A | 2 |",
        ):
            self.assertIn(fragment, rendered)
        self.assertEqual(len(self.document["conditions"]), 12)
        self.assertEqual(len({tuple(condition[name] for name in (
            "dataset_id", "dataset_version", "split_id", "feature_set_id",
            "demonstration_count", "label_order", "replicate",
        )) for condition in self.document["conditions"]}), 12)

    def test_complete_metrics_are_recomputed_from_confusion_counts(self):
        condition = self.condition("features-max")
        tn, fp, fn, tp = 3, 1, 1, 3
        valid = tn + fp + fn + tp
        self.assertEqual([condition[name] for name in ("tn", "fp", "fn", "tp")], [tn, fp, fn, tp])
        self.assertEqual(condition["n_valid_predictions"], valid)
        self.assertEqual(condition["n_queries_planned"], 8)
        close(condition["accuracy"], (tn + tp) / valid)
        close(condition["benign_recall"], tn / (tn + fp))
        close(condition["malicious_recall"], tp / (fn + tp))
        close(condition["balanced_accuracy"], (condition["benign_recall"] + condition["malicious_recall"]) / 2)
        precision = tp / (tp + fp)
        close(condition["malicious_precision"], precision)
        close(condition["malicious_f1"], 2 * precision * condition["malicious_recall"] / (precision + condition["malicious_recall"]))
        close(condition["false_positive_rate"], fp / (tn + fp))
        close(condition["false_positive_rate"], 1 - condition["benign_recall"])
        close(condition["completion_rate"], 1.0)
        low, high = wilson(tn + tp, valid)
        close(condition["accuracy_ci95_low"], low)
        close(condition["accuracy_ci95_high"], high)
        self.assertTrue(condition["paired_analysis_eligible"])
        self.assertFalse(condition["pairing_established_by_aggregate"])
        self.assertEqual(condition["n_requests_made"], condition["n_attempted"])
        self.assertIn("0.7500 [", render_table(self.document))

    def test_undefined_precision_is_null_and_zero_recall_stays_zero(self):
        condition = self.condition("features-max", dataset="synthetic-malware")
        self.assertEqual([condition["tn"], condition["fp"], condition["fn"], condition["tp"]], [2, 0, 2, 0])
        self.assertIsNone(condition["malicious_precision"])
        self.assertIsNone(condition["malicious_f1"])
        self.assertEqual(condition["malicious_recall"], 0.0)
        self.assertEqual(condition["benign_recall"], 1.0)
        self.assertEqual(condition["false_positive_rate"], 0.0)
        close(condition["accuracy"], 0.5)
        close(condition["balanced_accuracy"], 0.5)
        self.assertEqual(
            condition["undefined_metric_reasons"]["malicious_precision"],
            "undefined because no query was predicted malicious",
        )
        self.assertIn("malicious precision or recall", condition["undefined_metric_reasons"]["malicious_f1"])
        self.assertNotIn("malicious_recall", condition["undefined_metric_reasons"])
        self.assertTrue(condition["paired_analysis_eligible"])
        self.assertIn("— / 0.0000 / —", render_table(self.document))
        self.assertEqual(condition["label_mapping"], {"benign": "Benign", "malicious": "Malware"})

    def test_incomplete_failed_blocked_and_planned_cells(self):
        incomplete = self.condition("features-incomplete-demo")
        self.assertEqual(incomplete["status"], "incomplete")
        self.assertEqual(incomplete["n_queries_planned"], 5)
        self.assertEqual(incomplete["n_valid_predictions"], 2)
        self.assertEqual(incomplete["n_parse_failures"], 1)
        self.assertEqual(incomplete["n_context_overflows"], 1)
        self.assertEqual(incomplete["n_context_overflows_sent"], 1)
        self.assertEqual(incomplete["n_context_overflows_preflight"], 0)
        self.assertEqual(incomplete["n_truncated"], 1)
        self.assertEqual(incomplete["n_other_failures"], 0)
        self.assertEqual(incomplete["n_failures"], 3)
        self.assertEqual(incomplete["n_not_attempted"], 0)
        self.assertEqual(incomplete["n_open"], 0)
        self.assertEqual(incomplete["n_attempted"], 5)
        self.assertEqual(incomplete["n_requests_made"], 6)
        self.assertEqual(incomplete["n_responses"], 4)
        self.assertEqual(incomplete["metric_denominator"], 2)
        close(incomplete["completion_rate"], 2 / 5)
        close(incomplete["accuracy"], 1.0)
        self.assertIsNone(incomplete["malicious_recall"])
        self.assertIsNone(incomplete["balanced_accuracy"])
        self.assertEqual(
            incomplete["undefined_metric_reasons"]["malicious_recall"],
            "undefined because n_malicious_evaluated is 0",
        )
        self.assertFalse(incomplete["paired_analysis_eligible"])
        self.assertEqual(incomplete["context_fit_status"], "overflow")

        failed = self.condition("features-failed-demo")
        self.assertEqual(failed["n_valid_predictions"], 0)
        self.assertEqual(failed["n_parse_failures"], 3)
        self.assertEqual(failed["n_failures"], 3)
        self.assertEqual(failed["n_attempted"], 3)
        self.assertEqual(failed["completion_rate"], 0.0)
        self.assertIsNone(failed["accuracy"])
        self.assertEqual(failed["undefined_metric_reasons"]["accuracy"], "undefined because n_valid_predictions is 0")
        self.assertNotIn("completion_rate", failed["undefined_metric_reasons"])
        self.assertFalse(failed["paired_analysis_eligible"])

        blocked = self.condition("features-blocked-demo")
        self.assertEqual(blocked["n_attempted"], 0)
        self.assertEqual(blocked["n_requests_made"], 0)
        self.assertEqual(blocked["n_context_overflows_preflight"], 3)
        self.assertEqual(blocked["n_failures"], 3)
        self.assertEqual(blocked["n_valid_predictions"], 0)
        self.assertEqual([blocked["tn"], blocked["fp"], blocked["fn"], blocked["tp"]], [0, 0, 0, 0])
        self.assertEqual(blocked["completion_rate"], 0.0)
        self.assertIsNone(blocked["accuracy"])
        self.assertEqual(blocked["context_fit_status"], "overflow")
        self.assertFalse(blocked["paired_analysis_eligible"])

        planned = self.condition("features-unfrozen")
        self.assertEqual(planned["status"], "planned")
        self.assertIsNone(planned["n_attempted"])
        self.assertIsNone(planned["n_queries_planned"])
        self.assertIsNone(planned["accuracy"])
        self.assertEqual(planned["undefined_metric_reasons"]["accuracy"], "not observed; condition is planned")
        self.assertEqual(planned["observation_source"], "not_run")
        self.assertFalse(planned["accounting_closed"])
        self.assertFalse(planned["paired_analysis_eligible"])

    def test_duplicate_conflict_ceiling_is_not_the_query_count(self):
        condition = self.condition("features-max")
        groups = [(5, 0), (2, 1), (0, 1), (1, 0)]
        audited = sum(benign + malicious for benign, malicious in groups)
        unavoidable = sum(min(benign, malicious) for benign, malicious in groups)
        excess = sum(size - 1 for size in (benign + malicious for benign, malicious in groups) if size > 1)
        duplicate_groups = sum(1 for benign, malicious in groups if benign + malicious > 1)
        conflict_groups = sum(1 for benign, malicious in groups if benign and malicious)
        conflict_rows = sum(benign + malicious for benign, malicious in groups if benign and malicious)
        self.assertEqual(audited, 10)
        self.assertNotEqual(audited, condition["n_queries_planned"])
        self.assertEqual(condition["n_rows_audited"], audited)
        self.assertEqual(condition["n_unique_vectors"], 4)
        self.assertEqual(condition["n_duplicate_groups"], duplicate_groups)
        self.assertEqual(condition["n_duplicate_rows_excess"], excess)
        self.assertEqual(condition["n_rows_in_duplicate_groups"], excess + duplicate_groups)
        self.assertEqual(condition["n_conflicting_groups"], conflict_groups)
        self.assertEqual(condition["n_rows_in_conflicting_groups"], conflict_rows)
        self.assertEqual(condition["n_unavoidable_errors"], unavoidable)
        close(condition["empirical_accuracy_ceiling"], 1 - unavoidable / audited)
        self.assertEqual(condition["ceiling_population_scope"], "synthetic-source-population")
        self.assertEqual(condition["audit_matching"], "exact")
        self.assertEqual(condition["cross_split_overlap_groups"], 0)
        self.assertEqual(condition["cross_split_overlap_rows"], 0)
        self.assertIn("0.9000 (synthetic-source-population; exact)", render_table(self.document))

    def test_rejects_bad_counts_eligibility_and_null_confusion(self):
        main = copy.deepcopy(self.condition("features-max"))
        main["n_failures"] = 1
        with self.assertRaises(CapacityContractError):
            validate_public_condition(main)

        confused = copy.deepcopy(self.condition("features-max"))
        confused["tn"] = 9
        with self.assertRaises(CapacityContractError):
            validate_public_condition(confused)

        wrong_accuracy = copy.deepcopy(self.condition("features-max"))
        wrong_accuracy["accuracy"] = 0.5
        with self.assertRaises(CapacityContractError):
            validate_public_condition(wrong_accuracy)

        integer_rate = copy.deepcopy(self.condition("features-failed-demo"))
        integer_rate["completion_rate"] = 0
        with self.assertRaises(CapacityContractError):
            validate_public_condition(integer_rate)

        incomplete = copy.deepcopy(self.condition("features-incomplete-demo"))
        incomplete["paired_analysis_eligible"] = True
        with self.assertRaisesRegex(CapacityContractError, "paired eligibility"):
            validate_public_condition(incomplete)

        paired = copy.deepcopy(self.condition("features-max"))
        paired["pairing_established_by_aggregate"] = True
        with self.assertRaisesRegex(CapacityContractError, "pairing"):
            validate_public_condition(paired)

        planned = copy.deepcopy(self.condition("features-unfrozen"))
        planned["n_attempted"] = 0
        with self.assertRaisesRegex(CapacityContractError, "must be null"):
            validate_public_condition(planned)

        blocked = copy.deepcopy(self.condition("features-blocked-demo"))
        blocked["n_attempted"] = None
        with self.assertRaisesRegex(CapacityContractError, "n_attempted is required"):
            validate_public_condition(blocked)

        ceiling = copy.deepcopy(self.condition("features-max"))
        ceiling["empirical_accuracy_ceiling"] = 1.0
        with self.assertRaises(CapacityContractError):
            validate_public_condition(ceiling)

        duplicate = copy.deepcopy(self.document)
        copied = copy.deepcopy(duplicate["conditions"][0])
        copied["condition_id"] = duplicate["conditions"][1]["condition_id"]
        copied["feature_set_id"] = "features-other"
        duplicate["conditions"].append(copied)
        with self.assertRaisesRegex(CapacityContractError, "duplicate condition_id"):
            validate_aggregate(duplicate)

        collapsed = copy.deepcopy(self.document)
        copied = copy.deepcopy(collapsed["conditions"][0])
        copied["condition_id"] = "cap-synthetic-phish-split-heldout-features-max-d0-a-r9"
        collapsed["conditions"].append(copied)
        with self.assertRaisesRegex(CapacityContractError, "duplicate arm"):
            validate_aggregate(collapsed)

        extra = copy.deepcopy(self.condition("features-max"))
        extra["private_artifact_reference"] = "capacity/runs/synthetic-capacity-demo"
        with self.assertRaisesRegex(CapacityContractError, "allowlist"):
            validate_public_condition(extra)

    def test_known_dataset_labels_and_retry_accounting(self):
        phishing = copy.deepcopy(self.condition("features-max"))
        phishing["dataset_id"] = "git-evo"
        with self.assertRaisesRegex(CapacityContractError, "FeSAD registration"):
            validate_public_condition(phishing)

        malware = copy.deepcopy(self.condition("features-max", dataset="synthetic-malware"))
        malware["dataset_id"] = "hussain-deduplicated"
        malware["n_source_columns"] = 77
        malware["n_non_label_attributes"] = 74
        malware["n_attributes_input"] = 74
        malware["input_attribute_names"] = [f"h{index:02d}" for index in range(73)] + ["Family"]
        malware["excluded_attribute_names"] = []
        malware["exclusion_reasons"] = {}
        with self.assertRaisesRegex(CapacityContractError, "label column is used as a model input"):
            validate_public_condition(malware)

        wrong_labels = copy.deepcopy(self.condition("features-max", dataset="synthetic-malware"))
        wrong_labels["dataset_id"] = "hussain-deduplicated"
        wrong_labels["label_columns_excluded"] = ["Class"]
        with self.assertRaisesRegex(CapacityContractError, "label columns"):
            validate_public_condition(wrong_labels)

        condition_id = "cap-synthetic-phish-split-heldout-features-retry-d0-a-r1"
        design = _design(condition_id, "features-retry", "complete", budget=5, planned_labels=["benign", "malicious"])
        rows = [
            _prediction("synthetic-capacity-demo", condition_id, 0, "benign", "valid", "benign", attempts=3),
            _prediction("synthetic-capacity-demo", condition_id, 1, "malicious", "valid", "malicious", attempts=1),
        ]
        retried = assemble_public_condition(design, rows)
        self.assertEqual(retried["n_queries_planned"], 2)
        self.assertEqual(retried["n_valid_predictions"], 2)
        self.assertEqual(retried["n_attempted"], 2)
        self.assertEqual(retried["n_requests_made"], 4)
        self.assertEqual(retried["n_failures"], 0)
        rows[1]["query_id"] = rows[0]["query_id"]
        with self.assertRaisesRegex(CapacityContractError, "duplicate query_id"):
            assemble_public_condition(design, rows)

    def test_export_strips_private_evidence_and_refuses_relabelling(self):
        from capacity_contract import build_synthetic_run
        run = build_synthetic_run()
        secret_path = "/" + "home/" + "example/" + "secret.csv"
        token = "ghp_" + ("x" * 30)
        host = "http://" + "gpu" + "99.internal/v1"
        prompt = "SYNTHETIC PROMPT BODY do-not-publish-row-77"
        run["predictions"][0]["raw_prompt"] = prompt
        run["conditions"][0]["endpoint"] = host
        for row in run["predictions"]:
            if row["condition_id"] == run["conditions"][0]["condition_id"]:
                row["endpoint"] = host
        run["conditions"][0]["secret_path"] = secret_path
        run["conditions"][0]["access_token"] = token
        exported = export_public_aggregate(run)
        serialized = canonical_json(exported)
        for secret in (secret_path, token, host, prompt, "synthetic-query-", "synthetic-membership-", "synthetic-template-hash"):
            self.assertNotIn(secret, serialized)
        self.assertFalse(findings("results/public/capacity-synthetic.json", serialized))
        self.assertEqual(exported["artifact_type"], "synthetic_fixture")
        self.assertNotIn("predictions", exported)
        leaked = copy.deepcopy(run)
        leaked["conditions"][0]["status_reason"] = leaked["conditions"][0]["status_reason"] + " " + prompt
        with self.assertRaisesRegex(CapacityContractError, "private evidence"):
            export_public_aggregate(leaked)
        relabelled = copy.deepcopy(build_synthetic_run())
        relabelled["evidence_class"] = "observed"
        relabelled["model_requests_made"] = 1
        with self.assertRaises(CapacityContractError):
            export_public_aggregate(relabelled)

    def test_layout_roundtrip_stays_out_of_the_public_tree(self):
        from capacity_contract import build_synthetic_run
        run = build_synthetic_run()
        with tempfile.TemporaryDirectory() as tmp:
            directory = write_synthetic_layout(tmp, run)
            self.assertTrue((directory / "conditions.jsonl").is_file())
            self.assertTrue((directory / "predictions.jsonl").is_file())
            audit = Path(tmp) / "capacity" / "audits" / "synthetic-audit-features-max" / "groups.json"
            self.assertIn("synthetic-group-features-max-00", audit.read_text())
            conditions = [json.loads(line) for line in (directory / "conditions.jsonl").read_text().splitlines()]
            predictions = [json.loads(line) for line in (directory / "predictions.jsonl").read_text().splitlines()]
            restored = dict(run)
            restored["conditions"] = conditions
            restored["predictions"] = predictions
            self.assertEqual(canonical_json(export_public_aggregate(restored)), canonical_json(self.document))
        with self.assertRaisesRegex(CapacityContractError, "results"):
            write_synthetic_layout(ROOT / "results", run)
        observed = dict(run)
        observed["evidence_class"] = "observed"
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(CapacityContractError, "synthetic"):
                write_synthetic_layout(tmp, observed)

    def test_planning_inventory_renders_registered_maxima(self):
        plan = json.loads(PLAN.read_text())
        validate_planning_inventory(plan)
        rendered = render_table(plan)
        for maximum in ("45", "26", "20", "16", "48", "74"):
            self.assertIn(f"| {maximum} |", rendered)
        self.assertIn("Planning inventory. No observed classification metrics.", rendered)
        self.assertNotIn("0.5000", rendered)
        self.assertIn(rendered.strip(), (ROOT / "docs/CAPACITY_RESULTS.md").read_text())
        self.assertEqual(plan["model_requests_made"], 0)

    def test_cli_renders_the_synthetic_table(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/render_capacity.py"), "--synthetic"],
            check=True, capture_output=True, text=True,
        )
        self.assertEqual(completed.stdout, render_table(self.document))
        self.assertIn("SYNTHETIC FIXTURE", completed.stdout)

    def test_disclosure_allowlist_is_exact(self):
        self.assertFalse(findings("schemas/capacity-aggregate-v1.schema.json", '{"$schema": "x"}'))
        self.assertTrue(findings("schemas/capacity-aggregate-v1.schema.json", "{}"))
        self.assertFalse(findings("tests/fixtures/capacity/synthetic-aggregate.json", "SYNTHETIC FIXTURE"))
        self.assertTrue(findings("tests/fixtures/capacity/synthetic-aggregate.json", "{}"))
        self.assertTrue(findings("tests/fixtures/capacity/other.json", "SYNTHETIC FIXTURE"))
        self.assertFalse(findings("results/public/aggregate.json", "{}"))


if __name__ == "__main__":
    unittest.main()
