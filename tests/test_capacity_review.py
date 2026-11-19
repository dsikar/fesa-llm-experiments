"""Adversarial review regressions; synthetic evidence only, no model calls."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import capacity_contract as c


class CapacityReview(unittest.TestCase):
    def setUp(self):
        self.run = c.build_synthetic_run()
        self.condition = self.run["conditions"][0]
        self.rows = [r for r in self.run["predictions"]
                     if r["condition_id"] == self.condition["condition_id"]]
        self.design = c._design(self.condition["condition_id"], "features-max", "complete", budget=8,
                                planned_labels=["benign"] * 4 + ["malicious"] * 4)

    def reject_export(self, run, message):
        with self.assertRaisesRegex(c.CapacityContractError, message):
            c.export_public_aggregate(run)

    def test_frozen_totals_cannot_be_replaced_by_results(self):
        self.design.update(n_queries_planned=200, n_benign_planned=100, n_malicious_planned=100)
        original = copy.deepcopy(self.design)
        with self.assertRaisesRegex(c.CapacityContractError, "frozen plan"):
            c.assemble_public_condition(self.design, self.rows)
        self.assertEqual(self.design, original)

    def test_dropped_and_balanced_subsets_cannot_appear_complete(self):
        for rows in (self.rows[:-1], self.rows[1:4] + self.rows[5:], []):
            with self.subTest(size=len(rows)):
                with self.assertRaises(c.CapacityContractError):
                    c.assemble_public_condition(self.design, rows)

    def test_same_size_replacements_and_identity_changes_are_rejected(self):
        for name, value in (("query_id", "unexpected-query"), ("row_identity", "unexpected-row"),
                            ("membership_hash", "unexpected-membership")):
            rows = copy.deepcopy(self.rows)
            rows[0][name] = value
            with self.subTest(field=name):
                with self.assertRaisesRegex(c.CapacityContractError, "frozen plan"):
                    c.assemble_public_condition(self.design, rows)
        rows = copy.deepcopy(self.rows)
        rows[0]["gold_label"], rows[4]["gold_label"] = "malicious", "benign"
        with self.assertRaisesRegex(c.CapacityContractError, "frozen plan"):
            c.assemble_public_condition(self.design, rows)

    def test_altered_class_coverage_and_extra_rows_are_rejected(self):
        rows = copy.deepcopy(self.rows)
        rows[-1]["gold_label"] = "benign"
        with self.assertRaisesRegex(c.CapacityContractError, "frozen plan"):
            c.assemble_public_condition(self.design, rows)
        extra = c._prediction(self.condition["run_id"], self.condition["condition_id"], 99,
                              "benign", "valid", "benign")
        with self.assertRaisesRegex(c.CapacityContractError, "frozen plan"):
            c.assemble_public_condition(self.design, self.rows + [extra])

    def test_private_frozen_plan_is_required_and_validated(self):
        for change in (None, [], self.condition["planned_queries"][:-1]):
            record = copy.deepcopy(self.condition)
            record["planned_queries"] = change
            with self.assertRaises(c.CapacityContractError):
                c.validate_private_condition(record)
        record = copy.deepcopy(self.condition)
        record["planned_queries"][1] = copy.deepcopy(record["planned_queries"][0])
        with self.assertRaisesRegex(c.CapacityContractError, "duplicate planned"):
            c.validate_private_condition(record)

    def test_wrong_run_and_orphan_predictions_are_rejected(self):
        for row in self.run["predictions"]:
            row["run_id"] = "unrelated-run"
        self.reject_export(self.run, "prediction run_id")
        run = c.build_synthetic_run()
        orphan = copy.deepcopy(run["predictions"][0])
        orphan.update(condition_id="undeclared-condition", query_id="orphan-query")
        run["predictions"].append(orphan)
        self.reject_export(run, "orphan prediction")
        run = c.build_synthetic_run()
        run["conditions"][0]["run_id"] = "unrelated-run"
        self.reject_export(run, "condition run_id")

    def test_absent_evidence_and_dropped_rows_cannot_skip_reconciliation(self):
        for field in ("predictions", "audits"):
            for value in (None, "not-a-list"):
                run = copy.deepcopy(self.run)
                run[field] = value
                self.reject_export(run, "evidence-backed export")
            run = copy.deepcopy(self.run)
            del run[field]
            self.reject_export(run, "evidence-backed export")
        for rows in ([], self.run["predictions"][1:]):
            run = copy.deepcopy(self.run)
            run["predictions"] = rows
            self.reject_export(run, "predictions|frozen plan")
        # Aggregate-only validation is explicit and still supported.
        c.validate_aggregate(c.export_public_aggregate(self.run))

    def test_demonstration_order_and_private_settings_must_match(self):
        for name, value in (("demonstration_ids", ["unexpected-demo"]),
                            ("endpoint", "unexpected-endpoint"),
                            ("serving_session_id", "unexpected-session")):
            run = copy.deepcopy(self.run)
            run["predictions"][0][name] = value
            self.reject_export(run, "disagrees with condition")
        run = copy.deepcopy(self.run)
        row = next(r for r in run["predictions"] if r["demonstration_ids"])
        row["demonstration_ids"].reverse()
        self.reject_export(run, "demonstration_ids")
        run = copy.deepcopy(self.run)
        run["conditions"][0]["decoding"]["max_output_tokens"] += 1
        self.reject_export(run, "decoding output limit")

    def test_duplicate_and_replacement_prediction_exports_are_rejected(self):
        self.run["predictions"].append(copy.deepcopy(self.rows[0]))
        self.reject_export(self.run, "duplicate query_id")
        for name in c.PLAN_QUERY_FIELDS:
            run = c.build_synthetic_run()
            if name == "gold_label":
                run["predictions"][0][name] = "malicious"
            else:
                run["predictions"][0][name] = "unexpected-identity"
            self.reject_export(run, "frozen plan")

    def test_request_totals_cannot_be_tampered_with(self):
        self.run["predictions"][0]["attempt_count"] += 1
        self.reject_export(self.run, "request")
        run = c.build_synthetic_run()
        run["model_requests_made"] = 1
        self.reject_export(run, "run request rollup")
        run = c.build_synthetic_run()
        run["conditions"][0]["n_benign_planned"] -= 1
        run["conditions"][0]["n_malicious_planned"] += 1
        self.reject_export(run, "class coverage|exceed the plan")

    def running_condition(self):
        # Seven terminal results and one outstanding query in the frozen plan.
        rows = copy.deepcopy(self.rows)
        rows[-1] = c._prediction(self.condition["run_id"], self.condition["condition_id"], 7,
                                "malicious", "not_attempted", attempts=0,
                                input_tokens=None, latency=None)
        design = dict(self.design, status="incomplete")
        public = c.assemble_public_condition(design, rows)
        public.update(status="running", accounting_closed=False, n_not_attempted=0, n_open=1,
                      paired_analysis_eligible=False)
        public["timestamps"]["closed_at"] = None
        public["unavailable_reasons"] = c.expected_unavailable(public)
        return c._private_condition(public, [], self.design["planned_queries"])

    def test_running_is_valid_privately_and_rejected_publicly(self):
        running = self.running_condition()
        c.validate_private_condition(running)
        with self.assertRaisesRegex(c.CapacityContractError, "status"):
            c.validate_public_condition(c.project_public_condition(running))
        for field, value in (("n_open", 0), ("n_open", 2), ("accounting_closed", True),
                             ("paired_analysis_eligible", True), ("n_requests_made", 0),
                             ("n_valid_predictions", 8), ("accuracy", 0.0)):
            bad = copy.deepcopy(running)
            bad[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(c.CapacityContractError):
                    c.validate_private_condition(bad)
        bad = copy.deepcopy(running)
        bad["timestamps"]["closed_at"] = "2026-11-19T00:00:01Z"
        with self.assertRaises(c.CapacityContractError):
            c.validate_private_condition(bad)

    def test_running_can_account_for_an_outstanding_sent_request(self):
        running = self.running_condition()
        running["n_attempted"] += 1
        running["n_requests_made"] += 1
        for name in ("input_tokens_min", "input_tokens_median", "input_tokens_max",
                     "latency_seconds_total"):
            running[name] = None
        running["unavailable_reasons"] = c.expected_unavailable(running)
        c.validate_private_condition(running)
        for field in ("n_attempted", "n_requests_made"):
            bad = copy.deepcopy(running)
            bad[field] += 1
            with self.assertRaises(c.CapacityContractError):
                c.validate_private_condition(bad)

    def test_fresh_running_snapshot_accepts_zero_terminal_results(self):
        rows = [c._prediction(self.condition["run_id"], self.condition["condition_id"], i,
                              q["gold_label"], "not_attempted", attempts=0,
                              input_tokens=None, latency=None)
                for i, q in enumerate(self.design["planned_queries"])]
        public = c.assemble_public_condition(dict(self.design, status="blocked"), rows)
        public.update(status="running", accounting_closed=False, n_not_attempted=0, n_open=8)
        public["timestamps"]["closed_at"] = None
        public["unavailable_reasons"] = c.expected_unavailable(public)
        running = c._private_condition(public, [], self.design["planned_queries"])
        c.validate_private_condition(running)
        Draft202012Validator(c.condition_schema(private=True)).validate(running)
        self.assertIsNone(running["accuracy"])
        self.assertEqual(running["undefined_metric_reasons"]["accuracy"],
                         "undefined because n_valid_predictions is 0")
        self.assertEqual(running["completion_rate"], 0.0)

    def test_observed_running_does_not_require_a_publication_revision(self):
        running = self.running_condition()
        running["observation_source"] = "observed"
        running["unavailable_reasons"] = c.expected_unavailable(running)
        c.validate_private_condition(running)
        self.assertEqual(running["unavailable_reasons"]["reviewed_aggregate_revision"],
                         "condition has not closed")

    def test_independent_schema_validation_of_all_statuses_and_records(self):
        schemas = {name: json.loads((ROOT / "schemas" / name).read_text())
                   for name in c.schema_documents()}
        for schema in schemas.values():
            Draft202012Validator.check_schema(schema)
        aggregate = Draft202012Validator(schemas["capacity-aggregate-v1.schema.json"])
        private = Draft202012Validator(schemas["capacity-condition-private-v1.schema.json"])
        prediction = Draft202012Validator(schemas["capacity-prediction-private-v1.schema.json"])
        aggregate.validate(c.export_public_aggregate(self.run))
        statuses = set()
        for record in self.run["conditions"] + [self.running_condition()]:
            private.validate(record)
            c.validate_private_condition(record)
            statuses.add(record["status"])
        self.assertEqual(statuses, set(c.PRIVATE_STATUSES))
        for record in self.run["predictions"]:
            prediction.validate(record)
        Draft202012Validator(schemas["capacity-plan-v1.schema.json"]).validate(
            json.loads((ROOT / "results/public/capacity-plan.json").read_text()))
        with tempfile.TemporaryDirectory() as tmp:
            directory = c.write_synthetic_layout(tmp, self.run)
            Draft202012Validator(schemas["evidence-run-v1.schema.json"]).validate(
                json.loads((directory / "run.json").read_text()))
        bad = copy.deepcopy(self.condition)
        bad["exclusion_reasons"] = []
        with self.assertRaises(ValidationError):
            private.validate(bad)
        bad = c.export_public_aggregate(self.run)
        bad["conditions"][0]["status"] = "running"
        with self.assertRaises(ValidationError):
            aggregate.validate(bad)
        bad = copy.deepcopy(self.rows[0])
        bad["attempt_count"] = -1
        with self.assertRaises(ValidationError):
            prediction.validate(bad)
        bad = copy.deepcopy(self.condition)
        bad["planned_queries"][0]["gold_label"] = "unknown"
        with self.assertRaises(ValidationError):
            private.validate(bad)

    def test_binary_conflict_and_duplicate_size_bounds(self):
        bad = c.project_public_condition(self.condition)
        bad.update(n_unavoidable_errors=2, empirical_accuracy_ceiling=0.8)
        with self.assertRaisesRegex(c.CapacityContractError, "conflict bounds"):
            c.validate_public_condition(bad)
        # Non-conflicting duplicate groups also require at least two rows each.
        bad = c.project_public_condition(self.condition)
        bad.update(n_rows_in_conflicting_groups=7, n_unavoidable_errors=1)
        with self.assertRaisesRegex(c.CapacityContractError, "too few rows"):
            c.validate_public_condition(bad)
        bad = c.project_public_condition(self.condition)
        bad.update(n_conflicting_groups=2, n_unavoidable_errors=2,
                   n_rows_in_conflicting_groups=4, empirical_accuracy_ceiling=0.8)
        with self.assertRaisesRegex(c.CapacityContractError, "all duplicate groups"):
            c.validate_public_condition(bad)
        bad = c.project_public_condition(self.condition)
        bad.update(n_duplicate_groups=4, n_rows_in_duplicate_groups=10)
        # This passes size bounds but leaves no singleton vectors, so is feasible.
        c.validate_public_condition(bad)
        bad.update(n_duplicate_groups=4, n_duplicate_rows_excess=2, n_unique_vectors=8,
                   n_rows_in_duplicate_groups=6)
        with self.assertRaisesRegex(c.CapacityContractError, "at least two rows"):
            c.validate_public_condition(bad)

    def test_audit_evidence_is_required_and_summaries_are_recomputed(self):
        self.run["audits"] = []
        self.reject_export(self.run, "audit evidence missing")
        for field, value in (("groups", []), ("condition_id", "orphan-condition"),
                             ("matching", "unknown")):
            run = c.build_synthetic_run()
            run["audits"][0][field] = value
            self.reject_export(run, "audit")
        run = c.build_synthetic_run()
        run["audits"].append(copy.deepcopy(run["audits"][0]))
        self.reject_export(run, "duplicate audit")
        run = c.build_synthetic_run()
        # Feasible aggregate arithmetic, inconsistent with the registered groups.
        record = run["conditions"][0]
        record.update(n_rows_in_conflicting_groups=4, n_unavoidable_errors=2,
                      empirical_accuracy_ceiling=0.8)
        c.validate_public_condition(c.project_public_condition(record))
        self.reject_export(run, "disagrees with audit evidence")
        run = c.build_synthetic_run()
        run["audits"][0]["groups"][1].update(n_benign=1, n_malicious=2)
        c.export_public_aggregate(run)  # Same exact summary is valid.
        run["audits"][0]["groups"][1].update(n_benign=0, n_malicious=3)
        self.reject_export(run, "disagrees with audit evidence")
        run = c.build_synthetic_run()
        run["audits"][0]["groups"][0]["n_benign"] = -1
        self.reject_export(run, "group counts")


if __name__ == "__main__":
    unittest.main()
