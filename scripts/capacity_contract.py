#!/usr/bin/env python3
"""Attribute-count evidence contract for issue #7.

The module freezes the capacity aggregate, private condition and private
prediction records. It validates denominator arithmetic, renders the results
table and projects a private run onto a public allowlist.

Issue #5 owns immutable storage, atomic writes, resume and cross-session
retry policy. This module is the schema and validation boundary that store
should call. It does not call a model or write observed runs.

Synthetic fixtures are labelled SYNTHETIC FIXTURE. They are not experiments.
"""

import json
import math
import re
from pathlib import Path

from check_public_tree import RULES
from verify_baseline import wilson

SCHEMA_VERSION = 1
AGGREGATE_SCHEMA_ID = "capacity-aggregate-v1"
CONDITION_SCHEMA_ID = "capacity-condition-v1"
PREDICTION_SCHEMA_ID = "capacity-prediction-v1"
PLAN_SCHEMA_ID = "capacity-plan-v1"
EVIDENCE_SCHEMA_ID = "evidence-run-v1"
ACCOUNTING_POLICY = "capacity-accounting-v1"
FREEZE_ID = "capacity-output-contract-v1"
EXPERIMENT = "capacity-attribute-count"
DESIGN_ISSUE = 7
DESIGN_DOC = "docs/CAPACITY_RESULTS.md"
DESIGN_REQUEST = "docs/requests/06-capacity-output-contract.md"
GENERATOR = "scripts/capacity_contract.py"
PAIRING_EVIDENCE = "private_predictions_required"
SYNTHETIC_BANNER = "SYNTHETIC FIXTURE"
REVIEWED_BANNER = "REVIEWED AGGREGATE"
SYNTHETIC_DISCLAIMER = (
    "SYNTHETIC FIXTURE. Not an observed experiment. No model was called. "
    "Counts exercise the contract only."
)
REVIEWED_DISCLAIMER = (
    "Reviewed aggregate of observed conditions. Pairing is not established by these counts."
)
AMENDMENTS = (
    "accounting-buckets-v1",
    "status-incomplete-v1",
    "pairing-not-proven-v1",
    "observation-source-v1",
)
PUBLIC_STATUSES = ("planned", "blocked", "incomplete", "failed", "complete")
PRIVATE_STATUSES = PUBLIC_STATUSES + ("running",)
DATASET_TYPES = ("phishing", "malware")
RESULT_ARMS = ("pending", "audited_generalization", "diagnostic")
LABEL_ORDERS = ("A", "B")
DISPOSITIONS = (
    "valid", "parse_failure", "context_overflow", "truncated",
    "other_failure", "not_attempted",
)
CONTEXT_FIT = ("fit", "overflow", "not_checked")
TRUNCATION = ("reject_truncated", "not_applicable")
OVERFLOW_STAGES = ("none", "preflight", "sent")
AUDIT_MATCHING = ("exact", "approximate")
OBSERVATION_SOURCES = ("synthetic_fixture", "observed", "not_run")
GOLD_LABELS = ("benign", "malicious")
ISO_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
IDENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,119}$")
RELATIVE_REF = re.compile(r"^[a-z0-9][a-z0-9./_-]{0,160}$")
ERROR_TOKEN = re.compile(r"^[a-z0-9_-]{1,40}$")
CLOSE_REL = 1e-9
CLOSE_ABS = 1e-12

# FeSAD registration used by the planning inventory. Provenance and label
# polarity remain issue #8. These checks only stop the ids from drifting.
KNOWN_DATASETS = {
    "git-evo": {
        "display": "Git Evo", "dataset_type": "phishing",
        "n_source_columns": 46, "n_non_label_attributes": 45,
        "label_columns_excluded": ["Class"],
        "n_source_train_rows": 72814, "n_source_test_rows": 15833, "n_source_rows": 88647,
    },
    "mendeley-evo": {
        "display": "Mendeley Evo", "dataset_type": "phishing",
        "n_source_columns": 27, "n_non_label_attributes": 26,
        "label_columns_excluded": ["Class"],
        "n_source_train_rows": 9466, "n_source_test_rows": 1964, "n_source_rows": 11430,
    },
    "kaggle-evo": {
        "display": "Kaggle Evo", "dataset_type": "phishing",
        "n_source_columns": 21, "n_non_label_attributes": 20,
        "label_columns_excluded": ["Class"],
        "n_source_train_rows": 7558, "n_source_test_rows": 2078, "n_source_rows": 9636,
    },
    "kaggle-gen": {
        "display": "Kaggle Gen", "dataset_type": "phishing",
        "n_source_columns": 17, "n_non_label_attributes": 16,
        "label_columns_excluded": ["Class"],
        "n_source_train_rows": 7558, "n_source_test_rows": 2078, "n_source_rows": 9636,
    },
    "kaggle-mod-base-set": {
        "display": "Kaggle ModBaseSet", "dataset_type": "phishing",
        "n_source_columns": 49, "n_non_label_attributes": 48,
        "label_columns_excluded": ["Class"],
        "n_source_train_rows": 7922, "n_source_test_rows": 2078, "n_source_rows": 10000,
    },
    "hussain-deduplicated": {
        "display": "Hussain deduplicated", "dataset_type": "malware",
        "n_source_columns": 77, "n_non_label_attributes": 74,
        "label_columns_excluded": ["Class", "Category", "Family"],
        "n_source_train_rows": None, "n_source_test_rows": None, "n_source_rows": 21752,
    },
}
PLAN_NULL_FIELDS = (
    "n_attributes_input", "n_queries_planned", "accuracy", "balanced_accuracy",
    "malicious_precision", "malicious_recall", "malicious_f1", "false_positive_rate",
    "completion_rate", "n_conflicting_groups", "empirical_accuracy_ceiling",
)
PLAN_CONDITION_FIELDS = (
    "dataset_id", "dataset_type", "n_source_columns", "n_non_label_attributes",
    "label_columns_excluded", "n_source_train_rows", "n_source_test_rows", "n_source_rows",
    "n_attributes_input", "n_queries_planned", "status", "status_reason",
    "accuracy", "balanced_accuracy", "malicious_precision", "malicious_recall",
    "malicious_f1", "false_positive_rate", "completion_rate", "n_conflicting_groups",
    "empirical_accuracy_ceiling",
)
PLAN_STATUS_REASON = "Dataset audit, feature policy, split and run design not yet frozen"

METRIC_FIELDS = (
    "accuracy", "accuracy_ci95_low", "accuracy_ci95_high", "balanced_accuracy",
    "malicious_precision", "malicious_recall", "benign_recall", "malicious_f1",
    "false_positive_rate", "completion_rate",
)
AUDIT_FIELDS = (
    "n_rows_audited", "n_unique_vectors", "n_duplicate_groups", "n_duplicate_rows_excess",
    "n_rows_in_duplicate_groups", "n_conflicting_groups", "n_rows_in_conflicting_groups",
    "n_unavoidable_errors", "empirical_accuracy_ceiling", "ceiling_population_scope",
    "audit_matching",
)
CROSS_SPLIT_FIELDS = ("cross_split_overlap_groups", "cross_split_overlap_rows")
TOKEN_FIELDS = ("input_tokens_min", "input_tokens_median", "input_tokens_max", "output_tokens_total")
ARM_FIELDS = (
    "dataset_id", "dataset_version", "split_id", "feature_set_id",
    "demonstration_count", "label_order", "replicate",
)
OUTCOME_COUNT_FIELDS = (
    "n_attempted", "n_responses", "n_valid_predictions", "n_failures", "n_parse_failures",
    "n_context_overflows", "n_context_overflows_preflight", "n_context_overflows_sent",
    "n_truncated", "n_other_failures", "n_not_attempted", "n_open",
    "n_benign_evaluated", "n_malicious_evaluated", "tn", "fp", "fn", "tp",
    "n_predicted_benign", "n_predicted_malicious", "metric_denominator",
)

# kind is int, float, str, bool, strings, string_map, label_map, timestamps, reasons, amendments
# Nullable fields use reason maps. Metric nulls use undefined_metric_reasons.
CONDITION_FIELDS = (
    ("schema_version", "int", False, "Condition schema version. Always 1 for this freeze."),
    ("schema_id", "str", False, "Condition schema id, capacity-condition-v1."),
    ("run_id", "str", False, "Run identifier. Synthetic ids start with synthetic-."),
    ("condition_id", "str", False, "Unique condition identifier. One results-table row."),
    ("dataset_id", "str", False, "Dataset identifier. Known FeSAD ids carry registered maxima."),
    ("dataset_type", "str", False, "phishing or malware."),
    ("dataset_version", "str", False, "Dataset, variant and version label. Required so arms stay distinct."),
    ("split_id", "str", False, "Split identifier. Required so arms stay distinct."),
    ("feature_set_id", "str", False, "Exact feature-set identifier, not a count alone."),
    ("feature_policy", "str", False, "Feature-policy id."),
    ("model_id", "str", True, "Public model id. Null only while planned."),
    ("model_revision", "str", True, "Model revision. Null only while planned."),
    ("tokenizer_revision", "str", True, "Tokenizer revision. Null only while planned."),
    ("code_revision", "str", False, "Code revision that produced the row. Synthetic rows use a sentinel."),
    ("template_version", "str", True, "Prompt template version. Null only while planned."),
    ("config_revision", "str", True, "Config revision. Null only while planned."),
    ("result_arm", "str", False, "pending, audited_generalization, or diagnostic."),
    ("observation_source", "str", False, "synthetic_fixture, observed, or not_run."),
    ("n_source_columns", "int", True, "Columns in the source table, including label columns."),
    ("label_columns_excluded", "strings", False, "Label and target-metadata columns forbidden as inputs."),
    ("n_non_label_attributes", "int", True, "Raw maximum of non-label attributes. Distinct from the supplied count."),
    ("n_attributes_input", "int", True, "Attributes actually supplied to the model. Zero would mean a measured empty input."),
    ("input_attribute_names", "strings", True, "Ordered model-visible attribute names. Length equals n_attributes_input."),
    ("excluded_attribute_names", "strings", True, "Non-label attributes withheld from the input."),
    ("exclusion_reasons", "string_map", True, "Map of excluded non-label attribute name to reason."),
    ("encoding_policy", "str", True, "Encoding and canonicalization policy."),
    ("missing_value_policy", "str", True, "Missing-value policy."),
    ("identity_or_verdict_features_present", "bool", True, "True when the arm retains identifier or detector-verdict features."),
    ("label_mapping", "label_map", True, "Map of benign and malicious to the source label strings."),
    ("demonstration_count", "int", False, "Balanced demonstration count for this arm."),
    ("label_order", "str", False, "A lists malicious first. B lists benign first."),
    ("demonstration_order_policy", "str", True, "How demonstrations are ordered inside the prompt."),
    ("selection_seed", "int", True, "Seed used to select queries and demonstrations."),
    ("replicate", "int", False, "Replicate number, starting at 1."),
    ("schedule_id", "str", True, "Execution-schedule id. Not a cluster job id."),
    ("sampling_policy", "str", True, "Sampling policy for the query population."),
    ("population_scope", "str", True, "Query population this condition scores."),
    ("n_queries_planned", "int", True, "Planned queries in this cell."),
    ("n_benign_planned", "int", True, "Planned queries with benign gold labels."),
    ("n_malicious_planned", "int", True, "Planned queries with malicious gold labels."),
    ("status", "str", False, "planned, blocked, incomplete, failed, or complete."),
    ("status_reason", "str", False, "Why the condition has this status."),
    ("accounting_policy", "str", False, "capacity-accounting-v1."),
    ("accounting_closed", "bool", False, "True when every planned query has one terminal disposition."),
    ("n_attempted", "int", True, "Planned queries with at least one request. Retries do not add queries."),
    ("n_responses", "int", True, "Queries that returned a response body."),
    ("n_valid_predictions", "int", True, "Queries scored with a parsed label."),
    ("n_failures", "int", True, "Terminal failures: parse, context, truncation and other. Excludes retries and not-attempted queries."),
    ("n_parse_failures", "int", True, "Queries whose terminal disposition is parse_failure."),
    ("n_context_overflows", "int", True, "Queries whose terminal disposition is context_overflow."),
    ("n_context_overflows_preflight", "int", True, "Context overflows blocked before a request was sent."),
    ("n_context_overflows_sent", "int", True, "Context overflows discovered after a request was sent."),
    ("n_truncated", "int", True, "Truncated responses. They are not scored."),
    ("n_other_failures", "int", True, "Terminal transport or server failures after retries were exhausted."),
    ("n_not_attempted", "int", True, "Queries with a terminal not_attempted disposition."),
    ("n_open", "int", True, "Queries without a terminal disposition. Zero when accounting is closed."),
    ("n_benign_evaluated", "int", True, "Valid predictions with a benign gold label."),
    ("n_malicious_evaluated", "int", True, "Valid predictions with a malicious gold label."),
    ("tn", "int", True, "Benign gold predicted benign."),
    ("fp", "int", True, "Benign gold predicted malicious."),
    ("fn", "int", True, "Malicious gold predicted benign."),
    ("tp", "int", True, "Malicious gold predicted malicious."),
    ("n_predicted_benign", "int", True, "Valid predictions labelled benign. Equals tn+fn."),
    ("n_predicted_malicious", "int", True, "Valid predictions labelled malicious. Equals fp+tp."),
    ("accuracy", "float", True, "Accuracy on valid predictions."),
    ("accuracy_ci95_low", "float", True, "Lower Wilson 95% bound for accuracy."),
    ("accuracy_ci95_high", "float", True, "Upper Wilson 95% bound for accuracy."),
    ("balanced_accuracy", "float", True, "Mean of benign and malicious recall."),
    ("malicious_precision", "float", True, "Precision of the malicious prediction."),
    ("malicious_recall", "float", True, "Recall of the malicious class."),
    ("benign_recall", "float", True, "Recall of the benign class."),
    ("malicious_f1", "float", True, "Harmonic mean of malicious precision and recall."),
    ("false_positive_rate", "float", True, "False positive rate. Equals 1-benign recall when both are defined."),
    ("completion_rate", "float", True, "n_valid_predictions / n_queries_planned."),
    ("metric_denominator", "int", True, "Denominator for accuracy: n_valid_predictions."),
    ("undefined_metric_reasons", "reasons", False, "Reason for each null classification or completion metric."),
    ("unavailable_reasons", "reasons", False, "Reason for each other null field."),
    ("n_rows_audited", "int", True, "Rows in the audited population. Not the query count."),
    ("n_unique_vectors", "int", True, "Distinct projected vectors, including singletons."),
    ("n_duplicate_groups", "int", True, "Vectors that occur more than once."),
    ("n_duplicate_rows_excess", "int", True, "sum(size-1) over duplicate groups."),
    ("n_rows_in_duplicate_groups", "int", True, "sum(size) over duplicate groups."),
    ("n_conflicting_groups", "int", True, "Duplicate vectors that carry both labels."),
    ("n_rows_in_conflicting_groups", "int", True, "Rows belonging to conflicting groups."),
    ("n_unavoidable_errors", "int", True, "sum of min(n_g0, n_g1) over vectors."),
    ("empirical_accuracy_ceiling", "float", True, "1 - unavoidable_errors / n_rows_audited for the named population."),
    ("ceiling_population_scope", "str", True, "Population the ceiling describes. Not a general capacity bound."),
    ("audit_matching", "str", True, "exact or approximate. Approximate audits stay labelled."),
    ("cross_split_overlap_groups", "int", True, "Vector groups that appear in more than one split."),
    ("cross_split_overlap_rows", "int", True, "Rows in cross-split overlap groups."),
    ("context_limit_tokens", "int", True, "Serving context limit used for the preflight."),
    ("max_output_tokens", "int", True, "Maximum completion tokens."),
    ("input_tokens_min", "int", True, "Minimum input tokens over attempted queries with token observations."),
    ("input_tokens_median", "float", True, "Median input tokens. Even counts use the mean of the two central values."),
    ("input_tokens_max", "int", True, "Maximum input tokens over attempted queries with token observations."),
    ("output_tokens_total", "int", True, "Sum of output tokens over received responses."),
    ("latency_seconds_total", "float", True, "Sum of per-query latency. Retries are included in the query total, not as extra queries."),
    ("n_requests_budgeted", "int", True, "Request budget for this condition, including allowed retries."),
    ("n_requests_made", "int", True, "Requests issued, including retries. Simulated fixtures still set model_requests_made to 0 at the top level."),
    ("context_fit_status", "str", True, "fit, overflow, or not_checked."),
    ("truncation_policy", "str", True, "reject_truncated or not_applicable. Truncated outputs are not scored."),
    ("design_issue", "int", False, "GitHub issue that froze this output contract."),
    ("analysis_revision", "str", False, "Analysis revision id."),
    ("freeze_id", "str", False, "Output-contract freeze id."),
    ("reviewed_aggregate_revision", "str", True, "Revision of a reviewed publication. Null for synthetic fixtures."),
    ("timestamps", "timestamps", False, "Registration and close times in UTC, second resolution."),
    ("amendment_ids", "amendments", False, "Contract amendments this row implements."),
    ("paired_analysis_eligible", "bool", False, "Numeric gate for a future paired test. Not proof of pairing."),
    ("pairing_established_by_aggregate", "bool", False, "Always false. Pairing evidence stays in private predictions."),
)

CONDITION_FIELD_NAMES = tuple(name for name, _, _, _ in CONDITION_FIELDS)
NULLABLE_FIELDS = tuple(name for name, _, nullable, _ in CONDITION_FIELDS if nullable)
AGGREGATE_FIELDS = (
    "schema_version", "schema_id", "artifact_type", "evidence_banner", "evidence_class",
    "synthetic", "not_an_experiment", "experiment", "design_issue", "design_doc",
    "design_request", "accounting_policy", "freeze_id", "code_revision", "analysis_revision",
    "reviewed_aggregate_revision", "amendment_ids", "model_requests_made", "pairing_evidence",
    "generator", "disclaimer", "unavailable_reasons", "conditions",
)
PRIVATE_CONDITION_FIELDS = (
    "record_type", "private_artifact_reference", "decoding", "demonstration_ids",
    "serving_session_id", "endpoint", "prompt_template_sha256", "planned_queries",
)
PLAN_QUERY_FIELDS = ("query_id", "row_identity", "gold_label", "membership_hash")
PREDICTION_FIELDS = (
    "schema_version", "schema_id", "record_type", "run_id", "condition_id", "query_id",
    "row_identity", "pair_group_id", "gold_label", "terminal_disposition", "attempt_count",
    "context_overflow_stage", "parsed_prediction", "response_received", "truncated",
    "input_tokens", "output_tokens", "latency_seconds", "prompt_sha256", "response_sha256",
    "membership_hash", "demonstration_ids", "raw_prompt_ref", "raw_response_ref",
    "serving_session_id", "endpoint", "error_name",
)
SENSITIVE_KEYS = {
    "private_artifact_reference", "query_id", "row_identity", "pair_group_id",
    "membership_hash", "prompt_sha256", "response_sha256", "raw_prompt", "raw_response",
    "raw_prompt_ref", "raw_response_ref", "serving_session_id", "endpoint",
    "demonstration_ids", "decoding", "prompt_template_sha256", "groups", "planned_queries",
}
RUN_WHEN_FIELDS = (
    "model_id", "model_revision", "tokenizer_revision", "template_version", "config_revision",
    "n_source_columns", "n_non_label_attributes", "n_attributes_input", "input_attribute_names",
    "excluded_attribute_names", "exclusion_reasons", "encoding_policy", "missing_value_policy",
    "identity_or_verdict_features_present", "label_mapping", "demonstration_order_policy",
    "selection_seed", "schedule_id", "sampling_policy", "population_scope", "n_queries_planned",
    "n_benign_planned", "n_malicious_planned", "context_limit_tokens", "max_output_tokens",
    "n_requests_budgeted", "n_requests_made", "context_fit_status", "truncation_policy",
) + OUTCOME_COUNT_FIELDS

TABLE_HEADERS = (
    "Type", "Dataset / variant / version", "Split", "Feature set", "Demos", "Order", "Rep",
    "Raw maximum", "Actual supplied", "Queries", "Accuracy (Wilson 95% CI)", "Balanced accuracy",
    "Malicious precision / recall / F1", "Benign recall", "FPR", "Completion",
    "Conflicts (groups / rows)", "Ceiling", "Status",
)
RIGHT_ALIGNED = {4, 6, 7, 8, 9}


class CapacityContractError(ValueError):
    """The capacity record breaks the frozen contract."""


def require(condition, message):
    if not condition:
        raise CapacityContractError(message)


def close(actual, expected):
    require(type(actual) is float and type(expected) is float, f"non-float comparison: {actual!r} vs {expected!r}")
    require(math.isfinite(actual) and math.isfinite(expected), "non-finite metric")
    require(math.isclose(actual, expected, rel_tol=CLOSE_REL, abs_tol=CLOSE_ABS),
            f"arithmetic mismatch: {actual} != {expected}")


def canonical_json(document):
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _nonempty(value, label):
    require(type(value) is str and value.strip() != "", f"{label} must be a non-empty string")
    return value


def _ident(value, label):
    _nonempty(value, label)
    require(IDENT.fullmatch(value) is not None, f"{label} is not a searchable identifier")
    return value


def _int(value, label, minimum=0):
    require(type(value) is int and not isinstance(value, bool), f"{label} must be an integer")
    require(value >= minimum, f"{label} is below {minimum}")
    return value


def _float(value, label):
    require(type(value) is float and math.isfinite(value), f"{label} must be a finite float")
    return value


def _rate(value, label):
    _float(value, label)
    require(0.0 <= value <= 1.0, f"{label} is outside [0, 1]")
    return value


def _strings(value, label):
    require(type(value) is list, f"{label} must be a list")
    for item in value:
        _nonempty(item, label)
    return value


def _string_map(value, label):
    require(type(value) is dict, f"{label} must be an object")
    for key, item in value.items():
        _nonempty(key, label)
        _nonempty(item, label)
    return value


def check_disclosure(text, where):
    for name, pattern in RULES.items():
        require(re.search(pattern, text) is None, f"{where} matches disclosure rule {name}")


def median(values):
    xs = sorted(values)
    count = len(xs)
    require(count > 0, "median of an empty sample")
    if count % 2:
        return float(xs[count // 2])
    return (float(xs[count // 2 - 1]) + float(xs[count // 2])) / 2.0


def f1(precision, recall):
    if precision is None or recall is None:
        return None
    if precision == 0.0 and recall == 0.0:
        return 0.0
    return (2.0 * precision * recall) / (precision + recall)


def expected_metrics(condition):
    """Return metric name to float or None, derived only from counts."""
    valid = condition["n_valid_predictions"]
    planned = condition["n_queries_planned"]
    result = {name: None for name in METRIC_FIELDS}
    if valid is None or planned is None:
        return result
    result["completion_rate"] = float(valid) / float(planned)
    if valid == 0:
        return result
    tn, fp, fn, tp = condition["tn"], condition["fp"], condition["fn"], condition["tp"]
    benign_n = tn + fp
    malicious_n = fn + tp
    predicted_malicious = tp + fp
    accuracy = float(tn + tp) / float(valid)
    low, high = wilson(tn + tp, valid)
    benign_recall = None if benign_n == 0 else float(tn) / float(benign_n)
    malicious_recall = None if malicious_n == 0 else float(tp) / float(malicious_n)
    precision = None if predicted_malicious == 0 else float(tp) / float(predicted_malicious)
    balanced = None
    if benign_recall is not None and malicious_recall is not None:
        balanced = (benign_recall + malicious_recall) / 2.0
    false_positive = None if benign_n == 0 else float(fp) / float(benign_n)
    result.update({
        "accuracy": accuracy,
        "accuracy_ci95_low": low,
        "accuracy_ci95_high": high,
        "balanced_accuracy": balanced,
        "malicious_precision": precision,
        "malicious_recall": malicious_recall,
        "benign_recall": benign_recall,
        "malicious_f1": f1(precision, malicious_recall),
        "false_positive_rate": false_positive,
    })
    return result


def metric_reasons(condition, metrics):
    valid = condition["n_valid_predictions"]
    reasons = {}
    if valid is None or condition["n_queries_planned"] is None:
        for name, value in metrics.items():
            if value is None:
                reasons[name] = "not observed; condition is planned"
        return reasons
    if valid == 0:
        for name, value in metrics.items():
            if value is None:
                reasons[name] = "undefined because n_valid_predictions is 0"
        return reasons
    if metrics["benign_recall"] is None:
        reasons["benign_recall"] = "undefined because n_benign_evaluated is 0"
        reasons["false_positive_rate"] = "undefined because n_benign_evaluated is 0"
    if metrics["malicious_recall"] is None:
        reasons["malicious_recall"] = "undefined because n_malicious_evaluated is 0"
    if metrics["balanced_accuracy"] is None:
        reasons["balanced_accuracy"] = "undefined because a class recall is undefined"
    if metrics["malicious_precision"] is None:
        reasons["malicious_precision"] = "undefined because no query was predicted malicious"
    if metrics["malicious_f1"] is None:
        reasons["malicious_f1"] = "undefined because malicious precision or recall is undefined"
    return reasons


def summarize_groups(groups):
    rows = unique = duplicate_groups = excess = rows_dup = 0
    conflict_groups = rows_conflict = unavoidable = 0
    for n0, n1 in groups:
        require(type(n0) is int and type(n1) is int and n0 >= 0 and n1 >= 0, "group counts must be non-negative integers")
        size = n0 + n1
        require(size > 0, "empty vector group")
        rows += size
        unique += 1
        if size > 1:
            duplicate_groups += 1
            excess += size - 1
            rows_dup += size
        if n0 > 0 and n1 > 0:
            conflict_groups += 1
            rows_conflict += size
            unavoidable += min(n0, n1)
    require(rows > 0, "audit population is empty")
    return {
        "n_rows_audited": rows,
        "n_unique_vectors": unique,
        "n_duplicate_groups": duplicate_groups,
        "n_duplicate_rows_excess": excess,
        "n_rows_in_duplicate_groups": rows_dup,
        "n_conflicting_groups": conflict_groups,
        "n_rows_in_conflicting_groups": rows_conflict,
        "n_unavoidable_errors": unavoidable,
        "empirical_accuracy_ceiling": 1.0 - (float(unavoidable) / float(rows)),
    }


def _check_audit_identity(condition, label):
    values = [condition[name] for name in AUDIT_FIELDS]
    if all(value is None for value in values):
        return
    require(all(value is not None for value in values), f"{label}: partial duplicate audit")
    rows = condition["n_rows_audited"]
    unique = condition["n_unique_vectors"]
    duplicate_groups = condition["n_duplicate_groups"]
    excess = condition["n_duplicate_rows_excess"]
    rows_dup = condition["n_rows_in_duplicate_groups"]
    conflict_groups = condition["n_conflicting_groups"]
    rows_conflict = condition["n_rows_in_conflicting_groups"]
    unavoidable = condition["n_unavoidable_errors"]
    require(rows >= 1, f"{label}: audited population is empty")
    require(unique >= 1 and unique + excess == rows, f"{label}: duplicate excess does not partition the audit")
    require(0 <= duplicate_groups <= unique, f"{label}: duplicate group count is inconsistent")
    require(rows_dup == excess + duplicate_groups, f"{label}: rows in duplicate groups do not match excess")
    require(rows_dup >= 2 * duplicate_groups, f"{label}: duplicate groups need at least two rows each")
    require(rows_dup <= rows, f"{label}: duplicate rows exceed the audit")
    if duplicate_groups == 0:
        require(excess == 0 and rows_dup == 0 and unique == rows, f"{label}: singleton audit still records duplicates")
    require(0 <= conflict_groups <= duplicate_groups, f"{label}: conflicting groups are not a subset of duplicate groups")
    if conflict_groups == 0:
        require(unavoidable == 0 and rows_conflict == 0, f"{label}: conflicts are recorded without conflicting groups")
    else:
        require(rows_conflict >= 2 * conflict_groups, f"{label}: conflicting group is smaller than two rows")
        require(rows_conflict <= rows_dup - 2 * (duplicate_groups - conflict_groups),
                f"{label}: conflicting rows leave too few rows for other duplicate groups")
        require(conflict_groups <= unavoidable and 2 * unavoidable <= rows_conflict,
                f"{label}: unavoidable errors are outside the conflict bounds")
    if conflict_groups == duplicate_groups:
        require(rows_conflict == rows_dup, f"{label}: all duplicate groups conflict but their row counts differ")
    require(condition["audit_matching"] in AUDIT_MATCHING, f"{label}: audit matching is not labelled")
    _nonempty(condition["ceiling_population_scope"], f"{label}: ceiling population")
    close(condition["empirical_accuracy_ceiling"], 1.0 - (float(unavoidable) / float(rows)))
    cross = [condition[name] for name in CROSS_SPLIT_FIELDS]
    if all(value is None for value in cross):
        return
    require(all(type(value) is int for value in cross), f"{label}: partial cross-split audit")
    groups, nrows = cross
    require(0 <= groups <= nrows, f"{label}: cross-split rows are below the group count")
    if groups == 0:
        require(nrows == 0, f"{label}: cross-split rows without groups")


def _typed_condition_values(condition, label, statuses):
    require(type(condition) is dict, f"{label}: condition must be an object")
    require(set(condition) == set(CONDITION_FIELD_NAMES), f"{label}: condition fields do not match the public allowlist")
    for name, kind, nullable, _ in CONDITION_FIELDS:
        value = condition[name]
        if value is None:
            require(nullable, f"{label}: {name} cannot be null")
            continue
        if kind == "int":
            _int(value, f"{label}: {name}")
        elif kind == "float":
            _rate(value, f"{label}: {name}") if name in METRIC_FIELDS or name == "empirical_accuracy_ceiling" else _float(value, f"{label}: {name}")
        elif kind == "str":
            _nonempty(value, f"{label}: {name}")
        elif kind == "bool":
            require(type(value) is bool, f"{label}: {name} must be a boolean")
        elif kind == "strings":
            _strings(value, f"{label}: {name}")
        elif kind == "string_map" or kind == "reasons":
            _string_map(value, f"{label}: {name}")
        elif kind == "label_map":
            require(type(value) is dict and set(value) == {"benign", "malicious"}, f"{label}: label_mapping keys")
            require(value["benign"] != value["malicious"], f"{label}: label mapping collapses the classes")
            _nonempty(value["benign"], f"{label}: benign label")
            _nonempty(value["malicious"], f"{label}: malicious label")
        elif kind == "timestamps":
            require(type(value) is dict and set(value) == {"registered_at", "closed_at"}, f"{label}: timestamps")
            require(ISO_TIME.fullmatch(value["registered_at"]) is not None, f"{label}: registered_at")
            if value["closed_at"] is not None:
                require(ISO_TIME.fullmatch(value["closed_at"]) is not None, f"{label}: closed_at")
        elif kind == "amendments":
            require(value == list(AMENDMENTS), f"{label}: amendment ids")
        else:
            raise CapacityContractError(f"unknown field kind {kind}")
    require(condition["schema_version"] == SCHEMA_VERSION, f"{label}: schema_version")
    require(condition["schema_id"] == CONDITION_SCHEMA_ID, f"{label}: schema_id")
    require(condition["status"] in statuses, f"{label}: status")
    require(condition["dataset_type"] in DATASET_TYPES, f"{label}: dataset_type")
    require(condition["result_arm"] in RESULT_ARMS, f"{label}: result_arm")
    require(condition["observation_source"] in OBSERVATION_SOURCES, f"{label}: observation_source")
    require(condition["label_order"] in LABEL_ORDERS, f"{label}: label_order")
    require(condition["accounting_policy"] == ACCOUNTING_POLICY, f"{label}: accounting_policy")
    require(condition["design_issue"] == DESIGN_ISSUE, f"{label}: design_issue")
    require(condition["freeze_id"] == FREEZE_ID, f"{label}: freeze_id")
    require(condition["pairing_established_by_aggregate"] is False, f"{label}: aggregate counts cannot establish pairing")
    _ident(condition["run_id"], f"{label}: run_id")
    _ident(condition["condition_id"], f"{label}: condition_id")
    _ident(condition["dataset_id"], f"{label}: dataset_id")
    _ident(condition["dataset_version"], f"{label}: dataset_version")
    _ident(condition["split_id"], f"{label}: split_id")
    _ident(condition["feature_set_id"], f"{label}: feature_set_id")
    require(condition["replicate"] >= 1, f"{label}: replicate")
    if condition["audit_matching"] is not None:
        require(condition["audit_matching"] in AUDIT_MATCHING, f"{label}: audit_matching")
    if condition["context_fit_status"] is not None:
        require(condition["context_fit_status"] in CONTEXT_FIT, f"{label}: context_fit_status")
    if condition["truncation_policy"] is not None:
        require(condition["truncation_policy"] in TRUNCATION, f"{label}: truncation_policy")
    if condition["input_tokens_min"] is not None:
        require(condition["input_tokens_max"] is not None and condition["input_tokens_min"] <= condition["input_tokens_max"],
                f"{label}: input token bounds")
    if condition["latency_seconds_total"] is not None:
        require(condition["latency_seconds_total"] >= 0.0, f"{label}: latency")


def _check_known_dataset(condition, label):
    known = KNOWN_DATASETS.get(condition["dataset_id"])
    if known is None:
        return
    require(condition["dataset_type"] == known["dataset_type"], f"{label}: dataset_type does not match the FeSAD registration")
    require(condition["label_columns_excluded"] == known["label_columns_excluded"],
            f"{label}: label columns do not match the FeSAD registration")
    for name in ("n_source_columns", "n_non_label_attributes"):
        if condition[name] is not None:
            require(condition[name] == known[name], f"{label}: {name} does not match the FeSAD registration")


def _check_feature_partition(condition, label):
    labels = set(condition["label_columns_excluded"])
    require(len(labels) == len(condition["label_columns_excluded"]), f"{label}: duplicate label columns")
    names = condition["input_attribute_names"]
    excluded = condition["excluded_attribute_names"]
    reasons = condition["exclusion_reasons"]
    supplied = condition["n_attributes_input"]
    raw = condition["n_non_label_attributes"]
    if names is not None:
        require(len(names) == len(set(names)), f"{label}: duplicate input attributes")
        require(set(names).isdisjoint(labels), f"{label}: a label column is used as a model input")
    if excluded is not None:
        require(len(excluded) == len(set(excluded)), f"{label}: duplicate excluded attributes")
        require(set(excluded).isdisjoint(labels), f"{label}: a label column is listed as an excluded attribute")
    if names is not None and excluded is not None:
        require(set(names).isdisjoint(excluded), f"{label}: an attribute is both supplied and excluded")
    if supplied is not None and names is not None:
        require(len(names) == supplied, f"{label}: input name count does not match n_attributes_input")
    if raw is not None and supplied is not None and names is not None and excluded is not None and reasons is not None:
        require(supplied <= raw, f"{label}: supplied attributes exceed the raw maximum")
        require(len(excluded) == raw - supplied, f"{label}: exclusions do not account for the raw maximum")
        require(set(reasons) == set(excluded), f"{label}: exclusion reasons do not match excluded names")
    source = condition["n_source_columns"]
    if source is not None and raw is not None:
        require(source == raw + len(condition["label_columns_excluded"]),
                f"{label}: source columns do not equal non-label attributes plus label columns")


def _check_accounting(condition, label):
    status = condition["status"]
    if status == "planned":
        require(condition["accounting_closed"] is False, f"{label}: a planned condition is not closed")
        require(condition["result_arm"] == "pending", f"{label}: planned result arm")
        require(condition["identity_or_verdict_features_present"] is None, f"{label}: planned verdict flag")
        require(condition["paired_analysis_eligible"] is False, f"{label}: planned paired eligibility")
        require(condition["observation_source"] == "not_run", f"{label}: planned observation source")
        require(condition["timestamps"]["closed_at"] is None, f"{label}: planned close time")
        for name in OUTCOME_COUNT_FIELDS:
            require(condition[name] is None, f"{label}: planned {name} must be null, not zero")
        for name in METRIC_FIELDS:
            require(condition[name] is None, f"{label}: planned {name} must be null")
        planned_metrics = expected_metrics(condition)
        require(condition["undefined_metric_reasons"] == metric_reasons(condition, planned_metrics),
                f"{label}: planned metric reasons")
        query_fields = ("n_queries_planned", "n_benign_planned", "n_malicious_planned")
        present = [condition[name] is not None for name in query_fields]
        require(all(present) or not any(present), f"{label}: partial planned query counts")
        if all(present):
            _check_plan_counts(condition, label)
        return
    running = status == "running"
    require(status in PRIVATE_STATUSES, f"{label}: status")
    require(condition["accounting_closed"] is (not running), f"{label}: accounting closure disagrees with status")
    if running:
        require(condition["n_open"] is not None and condition["n_open"] > 0, f"{label}: running needs open queries")
        require(condition["timestamps"]["closed_at"] is None, f"{label}: running close time")
    else:
        require(condition["timestamps"]["closed_at"] is not None, f"{label}: closed condition needs closed_at")
    require(condition["observation_source"] in {"synthetic_fixture", "observed"}, f"{label}: observation source")
    for name in RUN_WHEN_FIELDS:
        require(condition[name] is not None, f"{label}: {name} is required once the condition leaves planned")
    _check_plan_counts(condition, label)
    _check_partition(condition, label, closed=not running)
    _check_confusion(condition, label)
    _check_status_shape(condition, label)
    _check_metric_values(condition, label)
    _check_context(condition, label)


def _check_plan_counts(condition, label):
    planned = condition["n_queries_planned"]
    benign = condition["n_benign_planned"]
    malicious = condition["n_malicious_planned"]
    for name in ("n_queries_planned", "n_benign_planned", "n_malicious_planned"):
        _int(condition[name], f"{label}: {name}", minimum=1)
    require(planned > 0 and benign > 0 and malicious > 0, f"{label}: both classes must be planned")
    require(benign + malicious == planned, f"{label}: planned class counts do not sum to n_queries_planned")


def _check_partition(condition, label, *, closed=True):
    planned = condition["n_queries_planned"]
    parts = (
        condition["n_valid_predictions"] + condition["n_parse_failures"] + condition["n_context_overflows"]
        + condition["n_truncated"] + condition["n_other_failures"] + condition["n_not_attempted"]
        + condition["n_open"]
    )
    require(parts == planned, f"{label}: terminal dispositions do not partition n_queries_planned")
    if closed:
        require(condition["n_open"] == 0, f"{label}: closed accounting still has open queries")
    require(condition["n_context_overflows"] == condition["n_context_overflows_preflight"] + condition["n_context_overflows_sent"],
            f"{label}: context overflows are not split into preflight and sent")
    failures = (
        condition["n_parse_failures"] + condition["n_context_overflows"] + condition["n_truncated"]
        + condition["n_other_failures"]
    )
    require(condition["n_failures"] == failures, f"{label}: n_failures double-counts or drops a diagnostic category")
    attempted = (
        condition["n_valid_predictions"] + condition["n_parse_failures"] + condition["n_truncated"]
        + condition["n_other_failures"] + condition["n_context_overflows_sent"]
    )
    if closed:
        require(condition["n_attempted"] == attempted, f"{label}: n_attempted does not match requests at query level")
    else:
        require(attempted <= condition["n_attempted"] <= attempted + condition["n_open"],
                f"{label}: running attempts exceed terminal and open queries")
    responses = condition["n_valid_predictions"] + condition["n_parse_failures"] + condition["n_truncated"]
    require(condition["n_responses"] == responses, f"{label}: n_responses does not match received bodies")
    require(condition["n_requests_made"] >= condition["n_attempted"], f"{label}: requests are below attempted queries")
    if condition["n_attempted"] == 0:
        require(condition["n_requests_made"] == 0, f"{label}: requests were recorded without an attempted query")
    require(condition["n_requests_budgeted"] >= condition["n_requests_made"], f"{label}: requests exceed the condition budget")
    require(condition["metric_denominator"] == condition["n_valid_predictions"], f"{label}: metric denominator")


def _check_confusion(condition, label):
    tn, fp, fn, tp = condition["tn"], condition["fp"], condition["fn"], condition["tp"]
    require(tn + fp == condition["n_benign_evaluated"], f"{label}: benign confusion counts")
    require(fn + tp == condition["n_malicious_evaluated"], f"{label}: malicious confusion counts")
    require(tn + fp + fn + tp == condition["n_valid_predictions"], f"{label}: confusion counts do not equal valid predictions")
    require(condition["n_benign_evaluated"] + condition["n_malicious_evaluated"] == condition["n_valid_predictions"],
            f"{label}: evaluated class counts")
    require(condition["n_predicted_benign"] == tn + fn, f"{label}: predicted benign")
    require(condition["n_predicted_malicious"] == fp + tp, f"{label}: predicted malicious")
    require(condition["n_benign_evaluated"] <= condition["n_benign_planned"], f"{label}: benign evaluations exceed the plan")
    require(condition["n_malicious_evaluated"] <= condition["n_malicious_planned"], f"{label}: malicious evaluations exceed the plan")


def _eligible(condition):
    return (
        condition["status"] == "complete"
        and condition["result_arm"] == "audited_generalization"
        and condition["identity_or_verdict_features_present"] is False
        and condition["n_valid_predictions"] == condition["n_queries_planned"]
        and condition["n_failures"] == 0
        and condition["n_not_attempted"] == 0
        and condition["n_open"] == 0
    )


def _check_status_shape(condition, label):
    status = condition["status"]
    valid = condition["n_valid_predictions"]
    planned = condition["n_queries_planned"]
    if condition["result_arm"] == "diagnostic":
        require(condition["identity_or_verdict_features_present"] is True, f"{label}: diagnostic arm flag")
    elif condition["result_arm"] == "audited_generalization":
        require(condition["identity_or_verdict_features_present"] is False, f"{label}: generalization arm flag")
    else:
        require(False, f"{label}: closed conditions cannot use the pending arm")
    require(condition["paired_analysis_eligible"] is _eligible(condition), f"{label}: paired eligibility")
    if status == "complete":
        require(valid == planned and condition["n_failures"] == 0 and condition["n_not_attempted"] == 0,
                f"{label}: complete condition does not score every planned query")
        require(condition["n_benign_evaluated"] == condition["n_benign_planned"], f"{label}: complete benign coverage")
        require(condition["n_malicious_evaluated"] == condition["n_malicious_planned"], f"{label}: complete malicious coverage")
    elif status == "incomplete":
        require(0 < valid < planned, f"{label}: incomplete condition needs a proper subset of valid predictions")
    elif status == "failed":
        require(valid == 0 and condition["n_attempted"] > 0, f"{label}: failed condition shape")
    elif status == "blocked":
        require(valid == 0 and condition["n_attempted"] == 0 and condition["n_requests_made"] == 0,
                f"{label}: blocked condition shape")
        require(condition["n_parse_failures"] == 0 and condition["n_truncated"] == 0
                and condition["n_other_failures"] == 0 and condition["n_context_overflows_sent"] == 0,
                f"{label}: blocked condition records a sent request")


def _check_metric_values(condition, label):
    metrics = expected_metrics(condition)
    reasons = metric_reasons(condition, metrics)
    require(set(condition["undefined_metric_reasons"]) == set(reasons), f"{label}: undefined metric reasons")
    for name, expected in metrics.items():
        actual = condition[name]
        if expected is None:
            require(actual is None, f"{label}: {name} must be null")
            require(condition["undefined_metric_reasons"][name] == reasons[name], f"{label}: reason for {name}")
        else:
            require(name not in condition["undefined_metric_reasons"], f"{label}: {name} has a reason but a value")
            close(actual, expected)
    if condition["accuracy"] is not None:
        require(condition["accuracy_ci95_low"] <= condition["accuracy"] <= condition["accuracy_ci95_high"],
                f"{label}: Wilson interval does not cover accuracy")
    if condition["benign_recall"] is not None and condition["false_positive_rate"] is not None:
        close(condition["false_positive_rate"], 1.0 - condition["benign_recall"])


def _check_context(condition, label):
    overflows = condition["n_context_overflows"]
    attempted = condition["n_attempted"]
    if overflows > 0:
        require(condition["context_fit_status"] == "overflow", f"{label}: context fit status")
    elif attempted > 0:
        require(condition["context_fit_status"] == "fit", f"{label}: context fit status")
    else:
        require(condition["context_fit_status"] == "not_checked", f"{label}: context fit status")
    if condition["n_truncated"] > 0:
        require(condition["truncation_policy"] == "reject_truncated", f"{label}: truncation policy")
    require(condition["context_limit_tokens"] > 0 and condition["max_output_tokens"] > 0, f"{label}: token limits")
    _check_token_nulls(condition, label)


def _token_expectation(condition):
    """Return the canonical null/not-null pattern. Values themselves need predictions to recompute."""
    if condition["status"] == "planned":
        return {name: "planned" for name in TOKEN_FIELDS + ("latency_seconds_total",)}
    if condition["n_attempted"] == 0:
        return {
            "input_tokens_min": "no-request",
            "input_tokens_median": "no-request",
            "input_tokens_max": "no-request",
            "output_tokens_total": "no-response",
            "latency_seconds_total": "no-request",
        }
    # Non-null means the observations were complete. Null means the named gap.
    pattern = {}
    input_missing = condition["input_tokens_min"] is None
    require(all((condition[name] is None) == input_missing for name in ("input_tokens_min", "input_tokens_median", "input_tokens_max")),
            "partial input token summary")
    for name in ("input_tokens_min", "input_tokens_median", "input_tokens_max"):
        pattern[name] = "incomplete-input" if input_missing else "present"
    pattern["output_tokens_total"] = "incomplete-output" if condition["output_tokens_total"] is None else "present"
    if condition["n_responses"] == 0 and condition["output_tokens_total"] is None:
        pattern["output_tokens_total"] = "no-response"
    pattern["latency_seconds_total"] = "incomplete-latency" if condition["latency_seconds_total"] is None else "present"
    return pattern


def _check_token_nulls(condition, label):
    pattern = _token_expectation(condition)
    reasons = {
        "planned": "not observed; condition is planned",
        "no-request": "not measured because no request was made",
        "no-response": "not measured because no response was received",
        "incomplete-input": "incomplete token observations",
        "incomplete-output": "incomplete token observations",
        "incomplete-latency": "incomplete latency observations",
    }
    for name, state in pattern.items():
        if state == "present":
            require(condition[name] is not None, f"{label}: {name}")
            require(name not in condition["unavailable_reasons"], f"{label}: {name} reason")
        else:
            require(condition[name] is None, f"{label}: {name} must be null")
            require(condition["unavailable_reasons"].get(name) == reasons[state], f"{label}: reason for {name}")


def expected_unavailable(condition):
    reasons = {}
    audit_missing = all(condition[name] is None for name in AUDIT_FIELDS)
    cross_missing = all(condition[name] is None for name in CROSS_SPLIT_FIELDS)
    for name in NULLABLE_FIELDS:
        if name in METRIC_FIELDS or condition[name] is not None:
            continue
        if name in AUDIT_FIELDS:
            if audit_missing:
                reasons[name] = "audit not available"
            else:
                raise CapacityContractError(f"{condition['condition_id']}: {name} is null inside a partial audit")
        elif name in CROSS_SPLIT_FIELDS:
            if cross_missing and audit_missing:
                reasons[name] = "audit not available"
            elif cross_missing:
                reasons[name] = "cross-split audit not run"
        elif name in TOKEN_FIELDS or name == "latency_seconds_total":
            continue
        elif condition["status"] == "planned":
            reasons[name] = "not observed; condition is planned"
        elif name == "reviewed_aggregate_revision" and condition["status"] == "running":
            reasons[name] = "condition has not closed"
        elif name == "reviewed_aggregate_revision":
            require(condition["observation_source"] != "observed", "observed rows need a reviewed revision")
            reasons[name] = "synthetic fixture is not a reviewed publication"
        else:
            raise CapacityContractError(f"{condition['condition_id']}: {name} is null without a frozen reason")
    if audit_missing:
        for name in AUDIT_FIELDS:
            reasons[name] = "audit not available"
    if condition["timestamps"]["closed_at"] is None:
        reasons["timestamps.closed_at"] = "condition has not closed"
    token_reasons = {
        "planned": "not observed; condition is planned",
        "no-request": "not measured because no request was made",
        "no-response": "not measured because no response was received",
        "incomplete-input": "incomplete token observations",
        "incomplete-output": "incomplete token observations",
        "incomplete-latency": "incomplete latency observations",
    }
    if condition["status"] != "planned":
        for name, state in _token_expectation(condition).items():
            if state != "present":
                reasons[name] = token_reasons[state]
    else:
        for name in TOKEN_FIELDS + ("latency_seconds_total",):
            reasons[name] = "not observed; condition is planned"
    return reasons


def validate_public_condition(condition):
    return _validate_condition(condition, PUBLIC_STATUSES)


def _validate_condition(condition, statuses):
    label = condition.get("condition_id", "<missing condition>") if type(condition) is dict else "<condition>"
    _typed_condition_values(condition, label, statuses)
    _check_known_dataset(condition, label)
    _check_feature_partition(condition, label)
    _check_accounting(condition, label)
    _check_audit_identity(condition, label)
    unavailable = expected_unavailable(condition)
    require(condition["unavailable_reasons"] == unavailable, f"{label}: unavailable reasons do not match the null fields")
    if condition["status"] != "planned":
        _check_context(condition, label)
    return condition


def _arm_key(condition):
    return tuple(condition[name] for name in ARM_FIELDS)


def validate_aggregate(document):
    require(type(document) is dict, "aggregate must be an object")
    require(set(document) == set(AGGREGATE_FIELDS), "aggregate fields do not match the public allowlist")
    require(document["schema_version"] == SCHEMA_VERSION, "schema_version")
    require(document["schema_id"] == AGGREGATE_SCHEMA_ID, "schema_id")
    require(document["experiment"] == EXPERIMENT, "experiment")
    require(document["design_issue"] == DESIGN_ISSUE, "design_issue")
    require(document["design_doc"] == DESIGN_DOC and document["design_request"] == DESIGN_REQUEST, "design links")
    require(document["accounting_policy"] == ACCOUNTING_POLICY, "accounting_policy")
    require(document["freeze_id"] == FREEZE_ID, "freeze_id")
    require(document["generator"] == GENERATOR, "generator")
    require(document["pairing_evidence"] == PAIRING_EVIDENCE, "pairing evidence")
    require(document["amendment_ids"] == list(AMENDMENTS), "amendment ids")
    require(document["analysis_revision"] and document["code_revision"], "revisions")
    kind = document["artifact_type"]
    require(kind in {"synthetic_fixture", "reviewed_aggregate"}, "artifact_type")
    if kind == "synthetic_fixture":
        require(document["evidence_class"] == "synthetic", "evidence_class")
        require(document["synthetic"] is True and document["not_an_experiment"] is True, "synthetic flags")
        require(document["evidence_banner"] == SYNTHETIC_BANNER, "synthetic banner")
        require(document["disclaimer"] == SYNTHETIC_DISCLAIMER, "synthetic disclaimer")
        require(document["model_requests_made"] == 0, "synthetic aggregate records model requests")
        require(document["reviewed_aggregate_revision"] is None, "synthetic reviewed revision")
        require(document["unavailable_reasons"] == {
            "reviewed_aggregate_revision": "synthetic fixture is not a reviewed publication",
        }, "synthetic top-level reasons")
    else:
        require(document["evidence_class"] == "observed", "evidence_class")
        require(document["synthetic"] is False and document["not_an_experiment"] is False, "reviewed flags")
        require(document["evidence_banner"] == REVIEWED_BANNER, "reviewed banner")
        require(document["disclaimer"] == REVIEWED_DISCLAIMER, "reviewed disclaimer")
        require(type(document["model_requests_made"]) is int and document["model_requests_made"] > 0,
                "reviewed aggregate has no model requests")
        _nonempty(document["reviewed_aggregate_revision"], "reviewed revision")
        require(document["unavailable_reasons"] == {}, "reviewed top-level reasons")
    require(type(document["conditions"]) is list and document["conditions"], "conditions")
    seen_ids = set()
    seen_arms = set()
    for condition in document["conditions"]:
        validate_public_condition(condition)
        require(condition["condition_id"] not in seen_ids, "duplicate condition_id")
        require(_arm_key(condition) not in seen_arms, "duplicate arm; feature set, split, demonstrations, order or replicate collapsed")
        seen_ids.add(condition["condition_id"])
        seen_arms.add(_arm_key(condition))
        require(condition["code_revision"] == document["code_revision"], "condition code_revision")
        require(condition["analysis_revision"] == document["analysis_revision"], "condition analysis_revision")
        require(condition["freeze_id"] == document["freeze_id"], "condition freeze_id")
        if kind == "synthetic_fixture":
            require(condition["run_id"].startswith("synthetic-"), "synthetic run_id")
            require(condition["observation_source"] in {"synthetic_fixture", "not_run"}, "synthetic observation source")
            require(condition["code_revision"] == "synthetic-not-a-commit", "synthetic code revision sentinel")
        else:
            require(not condition["run_id"].startswith("synthetic-"), "reviewed run uses a synthetic id")
            require(condition["observation_source"] in {"observed", "not_run"}, "reviewed observation source")
            require(condition["reviewed_aggregate_revision"] == document["reviewed_aggregate_revision"],
                    "condition reviewed revision")
    check_disclosure(canonical_json(document), "aggregate")
    return document


def validate_planning_inventory(document):
    require(type(document) is dict and set(document) == {
        "schema_version", "artifact_type", "model_requests_made", "conditions",
    }, "planning inventory fields")
    require(document["schema_version"] == SCHEMA_VERSION, "planning schema_version")
    require(document["artifact_type"] == "planning_inventory", "planning artifact_type")
    require(document["model_requests_made"] == 0, "planning inventory records model requests")
    require(type(document["conditions"]) is list, "planning conditions")
    require(len(document["conditions"]) == len(KNOWN_DATASETS), "planning arm count")
    for condition, (dataset_id, known) in zip(document["conditions"], KNOWN_DATASETS.items()):
        require(set(condition) == set(PLAN_CONDITION_FIELDS), f"{dataset_id}: planning fields")
        require(condition["dataset_id"] == dataset_id, "planning dataset order")
        require(condition["dataset_type"] == known["dataset_type"], f"{dataset_id}: type")
        require(condition["n_source_columns"] == known["n_source_columns"], f"{dataset_id}: columns")
        require(condition["n_non_label_attributes"] == known["n_non_label_attributes"], f"{dataset_id}: raw maximum")
        require(condition["label_columns_excluded"] == known["label_columns_excluded"], f"{dataset_id}: labels")
        require(condition["n_source_train_rows"] == known["n_source_train_rows"], f"{dataset_id}: train rows")
        require(condition["n_source_test_rows"] == known["n_source_test_rows"], f"{dataset_id}: test rows")
        require(condition["n_source_rows"] == known["n_source_rows"], f"{dataset_id}: rows")
        require(condition["status"] == "planned", f"{dataset_id}: status")
        require(condition["status_reason"] == PLAN_STATUS_REASON, f"{dataset_id}: status reason")
        for name in PLAN_NULL_FIELDS:
            require(condition[name] is None, f"{dataset_id}: {name} must stay null in the planning inventory")
    return document


def _prediction_flags(row, label):
    disposition = row["terminal_disposition"]
    require(disposition in DISPOSITIONS, f"{label}: disposition")
    require(row["context_overflow_stage"] in OVERFLOW_STAGES, f"{label}: context stage")
    require(row["gold_label"] in GOLD_LABELS, f"{label}: gold label")
    attempt = row["attempt_count"]
    stage = row["context_overflow_stage"]
    parsed = row["parsed_prediction"]
    if disposition == "valid":
        require(parsed in GOLD_LABELS and row["response_received"] is True and row["truncated"] is False, f"{label}: valid flags")
        require(attempt >= 1 and stage == "none", f"{label}: valid attempt")
    elif disposition == "parse_failure":
        require(parsed is None and row["response_received"] is True and row["truncated"] is False, f"{label}: parse flags")
        require(attempt >= 1 and stage == "none", f"{label}: parse attempt")
    elif disposition == "truncated":
        require(parsed is None and row["response_received"] is True and row["truncated"] is True, f"{label}: truncated flags")
        require(attempt >= 1 and stage == "none", f"{label}: truncated attempt")
    elif disposition == "context_overflow":
        require(parsed is None and row["response_received"] is False and row["truncated"] is False, f"{label}: context flags")
        if stage == "preflight":
            require(attempt == 0, f"{label}: preflight overflow was sent")
        elif stage == "sent":
            require(attempt >= 1, f"{label}: sent overflow has no attempt")
        else:
            require(False, f"{label}: context overflow stage")
    elif disposition == "other_failure":
        require(parsed is None and row["response_received"] is False and row["truncated"] is False, f"{label}: other failure flags")
        require(attempt >= 1 and stage == "none", f"{label}: other failure attempt")
    else:
        require(parsed is None and row["response_received"] is False and row["truncated"] is False, f"{label}: not-attempted flags")
        require(attempt == 0 and stage == "none", f"{label}: not-attempted attempt")
    if row["input_tokens"] is not None:
        _int(row["input_tokens"], f"{label}: input_tokens")
        require(attempt >= 1, f"{label}: tokens without an attempt")
    if row["output_tokens"] is not None:
        _int(row["output_tokens"], f"{label}: output_tokens")
        require(row["response_received"] is True, f"{label}: output tokens without a response")
    if row["latency_seconds"] is not None:
        _float(row["latency_seconds"], f"{label}: latency")
        require(row["latency_seconds"] >= 0.0 and attempt >= 1, f"{label}: latency")
    if row["error_name"] is not None:
        require(ERROR_TOKEN.fullmatch(row["error_name"]) is not None, f"{label}: error_name")
    else:
        require(disposition == "valid", f"{label}: failure needs an error_name")


def validate_prediction(row):
    require(type(row) is dict and set(row) == set(PREDICTION_FIELDS), "prediction fields")
    label = row.get("query_id", "<prediction>")
    require(row["schema_version"] == SCHEMA_VERSION and row["schema_id"] == PREDICTION_SCHEMA_ID, f"{label}: schema")
    require(row["record_type"] == "prediction", f"{label}: record_type")
    for name in ("run_id", "condition_id", "query_id", "row_identity"):
        _ident(row[name], f"{label}: {name}")
    require(type(row["attempt_count"]) is int and row["attempt_count"] >= 0, f"{label}: attempt_count")
    require(type(row["response_received"]) is bool and type(row["truncated"]) is bool, f"{label}: flags")
    if row["parsed_prediction"] is not None:
        require(row["parsed_prediction"] in GOLD_LABELS, f"{label}: parsed prediction")
    if row["pair_group_id"] is not None:
        _ident(row["pair_group_id"], f"{label}: pair_group_id")
    for name in ("prompt_sha256", "response_sha256", "membership_hash", "raw_prompt_ref",
                 "raw_response_ref", "serving_session_id", "endpoint"):
        if row[name] is not None:
            _nonempty(row[name], f"{label}: {name}")
            require("\n" not in row[name] and ".." not in row[name], f"{label}: {name}")
    require(type(row["demonstration_ids"]) is list, f"{label}: demonstration_ids")
    for item in row["demonstration_ids"]:
        _ident(item, f"{label}: demonstration_id")
    _prediction_flags(row, label)
    return row


def counts_from_predictions(rows):
    require(type(rows) is list and rows, "predictions")
    seen = set()
    counts = {name: 0 for name in (
        "n_attempted", "n_responses", "n_valid_predictions", "n_parse_failures", "n_context_overflows",
        "n_context_overflows_preflight", "n_context_overflows_sent", "n_truncated", "n_other_failures",
        "n_not_attempted", "n_open", "n_benign_evaluated", "n_malicious_evaluated", "tn", "fp", "fn", "tp",
        "n_requests_made",
    )}
    benign = malicious = 0
    input_tokens = []
    output_tokens = []
    latency = []
    input_gap = output_gap = latency_gap = False
    for row in rows:
        validate_prediction(row)
        require(row["query_id"] not in seen, "duplicate query_id")
        seen.add(row["query_id"])
        disposition = row["terminal_disposition"]
        counts["n_requests_made"] += row["attempt_count"]
        if row["attempt_count"] > 0:
            counts["n_attempted"] += 1
            if row["input_tokens"] is None:
                input_gap = True
            else:
                input_tokens.append(row["input_tokens"])
            if row["latency_seconds"] is None:
                latency_gap = True
            else:
                latency.append(row["latency_seconds"])
        if row["gold_label"] == "benign":
            benign += 1
        else:
            malicious += 1
        if disposition == "valid":
            counts["n_valid_predictions"] += 1
            counts["n_responses"] += 1
            if row["gold_label"] == "benign":
                counts["n_benign_evaluated"] += 1
                counts["tn" if row["parsed_prediction"] == "benign" else "fp"] += 1
            else:
                counts["n_malicious_evaluated"] += 1
                counts["tp" if row["parsed_prediction"] == "malicious" else "fn"] += 1
        elif disposition == "parse_failure":
            counts["n_parse_failures"] += 1
            counts["n_responses"] += 1
        elif disposition == "truncated":
            counts["n_truncated"] += 1
            counts["n_responses"] += 1
        elif disposition == "context_overflow":
            counts["n_context_overflows"] += 1
            if row["context_overflow_stage"] == "preflight":
                counts["n_context_overflows_preflight"] += 1
            else:
                counts["n_context_overflows_sent"] += 1
        elif disposition == "other_failure":
            counts["n_other_failures"] += 1
        else:
            counts["n_not_attempted"] += 1
        if row["response_received"]:
            if row["output_tokens"] is None:
                output_gap = True
            else:
                output_tokens.append(row["output_tokens"])
    counts["n_failures"] = (
        counts["n_parse_failures"] + counts["n_context_overflows"] + counts["n_truncated"]
        + counts["n_other_failures"]
    )
    counts["n_predicted_benign"] = counts["tn"] + counts["fn"]
    counts["n_predicted_malicious"] = counts["fp"] + counts["tp"]
    counts["n_benign_planned"] = benign
    counts["n_malicious_planned"] = malicious
    counts["n_queries_planned"] = len(rows)
    tokens = {
        "input_tokens_min": None if input_gap or not input_tokens else min(input_tokens),
        "input_tokens_median": None if input_gap or not input_tokens else median(input_tokens),
        "input_tokens_max": None if input_gap or not input_tokens else max(input_tokens),
        "output_tokens_total": None if output_gap or not output_tokens else sum(output_tokens),
        "latency_seconds_total": None if latency_gap or not latency else float(sum(latency)),
    }
    if counts["n_responses"] == 0:
        tokens["output_tokens_total"] = None
    return counts, tokens


def _blank_condition(design):
    condition = {name: None for name in CONDITION_FIELD_NAMES}
    condition.update(design)
    condition["schema_version"] = SCHEMA_VERSION
    condition["schema_id"] = CONDITION_SCHEMA_ID
    condition["accounting_policy"] = ACCOUNTING_POLICY
    condition["design_issue"] = DESIGN_ISSUE
    condition["freeze_id"] = FREEZE_ID
    condition["amendment_ids"] = list(AMENDMENTS)
    condition["pairing_established_by_aggregate"] = False
    condition["undefined_metric_reasons"] = {}
    condition["unavailable_reasons"] = {}
    return condition


def _apply_audit(condition, audit):
    for name in AUDIT_FIELDS + CROSS_SPLIT_FIELDS:
        condition[name] = None
    if audit is None:
        return
    summary = summarize_groups(audit["groups"])
    condition.update(summary)
    condition["ceiling_population_scope"] = audit["population_scope"]
    condition["audit_matching"] = audit["matching"]
    if "cross_split_overlap_groups" in audit:
        condition["cross_split_overlap_groups"] = audit["cross_split_overlap_groups"]
        condition["cross_split_overlap_rows"] = audit["cross_split_overlap_rows"]


def _derive_status(counts):
    valid = counts["n_valid_predictions"]
    planned = counts["n_queries_planned"]
    if valid == planned:
        return "complete"
    if valid == 0 and counts["n_attempted"] == 0:
        return "blocked"
    if valid == 0:
        return "failed"
    return "incomplete"


def _context_fit(counts):
    if counts["n_context_overflows"] > 0:
        return "overflow"
    if counts["n_attempted"] > 0:
        return "fit"
    return "not_checked"


def _validate_frozen_plan(condition):
    """Membership is a registered private input, never inferred from results."""
    planned = condition.get("planned_queries")
    if condition.get("n_queries_planned") is None:
        require(planned is None, "unfrozen plan must have null planned_queries")
        return
    _check_plan_counts(condition, condition["condition_id"])
    require(type(planned) is list, "frozen planned_queries required")
    require(len(planned) == condition["n_queries_planned"], "frozen plan size")
    seen = set()
    for query in planned:
        require(type(query) is dict and set(query) == set(PLAN_QUERY_FIELDS), "planned query fields")
        for name in ("query_id", "row_identity"):
            _ident(query[name], f"planned {name}")
        require(query["gold_label"] in GOLD_LABELS, "planned gold label")
        _nonempty(query["membership_hash"], "planned membership_hash")
        require(query["query_id"] not in seen, "duplicate planned query_id")
        seen.add(query["query_id"])
    require(sum(q["gold_label"] == "benign" for q in planned) == condition["n_benign_planned"],
            "frozen plan class coverage")


def _assert_frozen_predictions(condition, rows, counts):
    _validate_frozen_plan(condition)
    for name in ("n_queries_planned", "n_benign_planned", "n_malicious_planned"):
        require(condition.get(name) == counts[name], f"{name} differs from frozen plan")
    expected = {q["query_id"]: q for q in condition["planned_queries"]}
    require(set(expected) == {row["query_id"] for row in rows}, "query membership differs from frozen plan")
    for row in rows:
        require(all(row[name] == expected[row["query_id"]][name] for name in PLAN_QUERY_FIELDS),
                "query identity or class differs from frozen plan")


def assemble_public_condition(design, predictions, audit=None):
    """Build a public condition against a frozen private plan and dispositions."""
    _validate_frozen_plan(design)
    condition = _blank_condition(design)
    status = condition["status"]
    if status == "planned":
        require(predictions is None, "planned condition cannot carry predictions")
        condition["accounting_closed"] = False
        condition["result_arm"] = "pending"
        condition["observation_source"] = "not_run"
        condition["paired_analysis_eligible"] = False
        condition["timestamps"] = {"registered_at": design["timestamps"]["registered_at"], "closed_at": None}
        condition["undefined_metric_reasons"] = metric_reasons(condition, expected_metrics(condition))
    else:
        require(type(predictions) is list, "closed condition needs predictions")
        counts, tokens = counts_from_predictions(predictions)
        _assert_frozen_predictions(design, predictions, counts)
        derived = _derive_status(counts)
        require(status == derived, f"{condition.get('condition_id')}: status {status} does not match predictions ({derived})")
        for name in OUTCOME_COUNT_FIELDS:
            if name == "metric_denominator":
                continue
            if name in counts:
                condition[name] = counts[name]
        condition["n_requests_made"] = counts["n_requests_made"]
        condition["metric_denominator"] = counts["n_valid_predictions"]
        condition["n_open"] = 0
        condition["accounting_closed"] = True
        condition.update(tokens)
        condition["context_fit_status"] = _context_fit(counts)
        metrics = expected_metrics(condition)
        condition.update(metrics)
        condition["undefined_metric_reasons"] = metric_reasons(condition, metrics)
        condition["paired_analysis_eligible"] = _eligible(condition)
        for name in ("run_id", "condition_id"):
            require(all(row[name] == condition[name] for row in predictions), f"{name} differs inside a condition")
    _apply_audit(condition, audit)
    condition["unavailable_reasons"] = expected_unavailable(condition)
    ordered = {name: condition[name] for name in CONDITION_FIELD_NAMES}
    return validate_public_condition(ordered)


def _collect_strings(value, found):
    if type(value) is str and len(value) >= 8:
        found.add(value)
    elif type(value) is dict:
        for item in value.values():
            _collect_strings(item, found)
    elif type(value) is list:
        for item in value:
            _collect_strings(item, found)


RUN_KEYS = set(AGGREGATE_FIELDS) | {
    "conditions", "predictions", "audits", "evidence_class", "evidence_banner", "run_id",
    "issue_5_interface", "model_requests_made",
}
AUDIT_KEYS = {
    "schema_version", "record_type", "audit_id", "condition_id", "matching", "population_scope",
    "groups", "cross_split_overlap_groups", "cross_split_overlap_rows", "n_benign", "n_malicious",
    "membership_hash",
}
RECORD_KEYS = {
    "conditions": set(CONDITION_FIELD_NAMES) | set(PRIVATE_CONDITION_FIELDS),
    "predictions": set(PREDICTION_FIELDS),
    "audits": AUDIT_KEYS,
}


def _walk_public_value(value, found):
    if type(value) is dict:
        for key, child in value.items():
            if key in SENSITIVE_KEYS:
                _collect_strings(child, found)
            else:
                _walk_public_value(child, found)
    elif type(value) is list:
        for child in value:
            _walk_public_value(child, found)


def _walk_record(record, allowed, found):
    for key, child in record.items():
        if key == "planned_queries" and type(child) is list:
            for query in child:
                for name in PLAN_QUERY_FIELDS:
                    if name != "gold_label":
                        _collect_strings(query[name], found)
            continue
        if key in SENSITIVE_KEYS or key not in allowed:
            _collect_strings(child, found)
            continue
        child_allowed = RECORD_KEYS.get(key)
        if child_allowed is not None and type(child) is list:
            for item in child:
                if type(item) is dict:
                    _walk_record(item, child_allowed, found)
        else:
            _walk_public_value(child, found)


def collect_sensitive_strings(value, found=None):
    """Collect private strings that the public aggregate must not contain.

    Nested public maps, such as exclusion reasons and timestamps, stay public.
    Unknown keys on a run, condition, prediction or audit are private, as are
    identifiers, hashes, prompts, sessions and membership lists.
    """
    if found is None:
        found = set()
    if type(value) is dict:
        _walk_record(value, RUN_KEYS, found)
    return found


def project_public_condition(condition):
    require(type(condition) is dict, "condition")
    missing = [name for name in CONDITION_FIELD_NAMES if name not in condition]
    require(not missing, "condition is missing public fields: " + ", ".join(missing))
    return {name: condition[name] for name in CONDITION_FIELD_NAMES}


def export_public_aggregate(run):
    """Project a private run onto the public aggregate allowlist.

    Synthetic runs stay synthetic. This refuses to relabel them as reviewed.
    """
    require(type(run) is dict, "run")
    evidence_class = run.get("evidence_class")
    require(evidence_class in {"synthetic", "observed"}, "evidence_class")
    kind = "synthetic_fixture" if evidence_class == "synthetic" else "reviewed_aggregate"
    if kind == "reviewed_aggregate":
        require(not str(run.get("run_id", "")).startswith("synthetic-"),
                "synthetic evidence cannot be exported as a reviewed aggregate")
        require(type(run.get("model_requests_made")) is int and run["model_requests_made"] > 0,
                "reviewed export needs observed model requests")
        _nonempty(run.get("reviewed_aggregate_revision"), "reviewed revision")
    require(run.get("schema_version") == SCHEMA_VERSION and run.get("schema_id") == EVIDENCE_SCHEMA_ID, "run schema")
    require(run.get("design_issue") == DESIGN_ISSUE and run.get("issue_5_interface") == "validate_then_store", "run interface")
    _ident(run.get("run_id"), "run_id")
    for name in ("conditions", "predictions", "audits"):
        require(type(run.get(name)) is list, f"evidence-backed export requires {name}")
    private_conditions = []
    for record in run["conditions"]:
        require(type(record) is dict and set(CONDITION_FIELD_NAMES + PRIVATE_CONDITION_FIELDS) <= set(record), "private condition fields")
        condition = {name: record[name] for name in CONDITION_FIELD_NAMES + PRIVATE_CONDITION_FIELDS}
        validate_private_condition(condition)
        require(condition["run_id"] == run["run_id"], "condition run_id")
        private_conditions.append(condition)
    require(len({c["condition_id"] for c in private_conditions}) == len(private_conditions), "duplicate condition_id")
    _assert_prediction_rollup(private_conditions, run["predictions"], run["run_id"])
    _assert_audit_rollup(private_conditions, run["audits"])
    requests = sum(c["n_requests_made"] or 0 for c in private_conditions)
    _int(run.get("model_requests_made"), "model_requests_made")
    require(run["model_requests_made"] == (0 if evidence_class == "synthetic" else requests), "run request rollup")
    sensitive = collect_sensitive_strings(run)
    conditions = [project_public_condition(condition) for condition in run["conditions"]]
    conditions.sort(key=_arm_key)
    document = {
        "schema_version": SCHEMA_VERSION,
        "schema_id": AGGREGATE_SCHEMA_ID,
        "artifact_type": kind,
        "evidence_banner": SYNTHETIC_BANNER if kind == "synthetic_fixture" else REVIEWED_BANNER,
        "evidence_class": evidence_class,
        "synthetic": kind == "synthetic_fixture",
        "not_an_experiment": kind == "synthetic_fixture",
        "experiment": EXPERIMENT,
        "design_issue": DESIGN_ISSUE,
        "design_doc": DESIGN_DOC,
        "design_request": DESIGN_REQUEST,
        "accounting_policy": ACCOUNTING_POLICY,
        "freeze_id": FREEZE_ID,
        "code_revision": run["code_revision"],
        "analysis_revision": run["analysis_revision"],
        "reviewed_aggregate_revision": None if kind == "synthetic_fixture" else run["reviewed_aggregate_revision"],
        "amendment_ids": list(AMENDMENTS),
        "model_requests_made": 0 if kind == "synthetic_fixture" else run["model_requests_made"],
        "pairing_evidence": PAIRING_EVIDENCE,
        "generator": GENERATOR,
        "disclaimer": SYNTHETIC_DISCLAIMER if kind == "synthetic_fixture" else REVIEWED_DISCLAIMER,
        "unavailable_reasons": (
            {"reviewed_aggregate_revision": "synthetic fixture is not a reviewed publication"}
            if kind == "synthetic_fixture" else {}
        ),
        "conditions": conditions,
    }
    serialized = canonical_json(document)
    for secret in sensitive:
        require(secret not in serialized, "public aggregate contains private evidence")
    return validate_aggregate(document)


def _assert_prediction_rollup(conditions, predictions, run_id):
    grouped = {}
    declared = {c["condition_id"] for c in conditions}
    for record in predictions:
        require(type(record) is dict and set(PREDICTION_FIELDS) <= set(record), "prediction fields")
        row = {name: record[name] for name in PREDICTION_FIELDS}
        validate_prediction(row)
        require(row["run_id"] == run_id, "prediction run_id")
        require(row["condition_id"] in declared, "orphan prediction condition_id")
        grouped.setdefault(row["condition_id"], []).append(row)
    for condition in conditions:
        public = project_public_condition(condition)
        rows = grouped.get(public["condition_id"], [])
        if public["status"] == "planned":
            require(not rows, "planned condition has predictions")
            continue
        counts, tokens = counts_from_predictions(rows)
        _assert_frozen_predictions(condition, rows, counts)
        for row in rows:
            for name in ("demonstration_ids", "serving_session_id", "endpoint"):
                require(row[name] == condition[name], f"prediction {name} disagrees with condition")
        for name in OUTCOME_COUNT_FIELDS:
            if name in counts:
                require(public[name] == counts[name], f"{public['condition_id']}: {name} does not match predictions")
        require(public["n_requests_made"] == counts["n_requests_made"], "request rollup")
        require(public["n_queries_planned"] == counts["n_queries_planned"], "query rollup")
        for name, value in tokens.items():
            if value is None:
                require(public[name] is None, name)
            elif type(value) is float:
                close(public[name], value)
            else:
                require(public[name] == value, name)


def _assert_audit_rollup(conditions, audits):
    declared = {c["condition_id"]: c for c in conditions}
    seen = set()
    audit_ids = set()
    for audit in audits:
        require(type(audit) is dict, "audit record")
        require(audit.get("schema_version") == SCHEMA_VERSION and audit.get("record_type") == "duplicate_audit", "audit schema")
        _ident(audit.get("audit_id"), "audit_id")
        require(audit["audit_id"] not in audit_ids, "duplicate audit_id")
        audit_ids.add(audit["audit_id"])
        cid = audit.get("condition_id")
        require(cid in declared and cid not in seen, "orphan or duplicate audit condition_id")
        seen.add(cid)
        require(audit.get("matching") in AUDIT_MATCHING, "audit matching")
        _nonempty(audit.get("population_scope"), "audit population_scope")
        groups = audit.get("groups")
        require(type(groups) is list and groups, "audit groups")
        hashes = set()
        pairs = []
        for group in groups:
            require(type(group) is dict and {"n_benign", "n_malicious", "membership_hash"} <= set(group), "audit group fields")
            _nonempty(group["membership_hash"], "audit group membership_hash")
            require(group["membership_hash"] not in hashes, "duplicate audit group membership_hash")
            hashes.add(group["membership_hash"])
            pairs.append((group["n_benign"], group["n_malicious"]))
        summary = dict(declared[cid])
        _apply_audit(summary, dict(audit, groups=pairs))
        _check_audit_identity(summary, cid)
        for name in AUDIT_FIELDS + CROSS_SPLIT_FIELDS:
            require(declared[cid][name] == summary[name], f"{cid}: {name} disagrees with audit evidence")
    for cid, condition in declared.items():
        require((condition["n_rows_audited"] is not None) == (cid in seen), "audit evidence missing or unclaimed")


def _fmt_rate(value):
    if value is None:
        return "—"
    return f"{value:.4f}"


def _fmt_count(value, pending):
    if value is None:
        return "pending" if pending else "—"
    return str(value)


def _dataset_cell(condition, planning):
    dataset_id = condition["dataset_id"]
    display = KNOWN_DATASETS.get(dataset_id, {}).get("display")
    if planning:
        label = f"{display} ({dataset_id})" if display else dataset_id
        return f"{label} / version pending"
    version = condition["dataset_version"]
    if display:
        return f"{display} ({dataset_id}) / {version}"
    return f"{dataset_id} / {version}"


def _row_cells(condition, planning):
    pending = planning or condition.get("status") == "planned"
    if planning:
        queries = "pending"
        accuracy = "—"
        balanced = benign = fpr = completion = "—"
        prf = "— / — / —"
        conflicts = "pending"
        ceiling = "—"
        supplied = "pending"
        split = feature = order = "pending"
        demos = rep = "pending"
        raw = str(condition["n_non_label_attributes"])
        status = condition["status"]
    else:
        queries = _fmt_count(condition["n_queries_planned"], True) if condition["n_valid_predictions"] is None else (
            f"{condition['n_valid_predictions']}/{condition['n_queries_planned']}"
        )
        if condition["accuracy"] is None:
            accuracy = "—"
        else:
            accuracy = (
                f"{condition['accuracy']:.4f} [{condition['accuracy_ci95_low']:.4f}, "
                f"{condition['accuracy_ci95_high']:.4f}]"
            )
        balanced = _fmt_rate(condition["balanced_accuracy"])
        benign = _fmt_rate(condition["benign_recall"])
        fpr = _fmt_rate(condition["false_positive_rate"])
        completion = _fmt_rate(condition["completion_rate"])
        prf = " / ".join(_fmt_rate(condition[name]) for name in (
            "malicious_precision", "malicious_recall", "malicious_f1"))
        if condition["n_conflicting_groups"] is None:
            conflicts = "pending" if pending else "—"
        else:
            conflicts = f"{condition['n_conflicting_groups']} / {condition['n_rows_in_conflicting_groups']}"
        if condition["empirical_accuracy_ceiling"] is None:
            ceiling = "—"
        else:
            ceiling = (
                f"{condition['empirical_accuracy_ceiling']:.4f} "
                f"({condition['ceiling_population_scope']}; {condition['audit_matching']})"
            )
        supplied = _fmt_count(condition["n_attributes_input"], pending)
        split = condition["split_id"]
        feature = condition["feature_set_id"]
        demos = str(condition["demonstration_count"])
        order = condition["label_order"]
        rep = str(condition["replicate"])
        raw = _fmt_count(condition["n_non_label_attributes"], pending)
        status = condition["status"]
    return [
        condition["dataset_type"], _dataset_cell(condition, planning), split, feature, demos, order, rep,
        raw, supplied, queries, accuracy, balanced, prf, benign, fpr, completion, conflicts, ceiling, status,
    ]


def render_table(document):
    planning = document.get("artifact_type") == "planning_inventory"
    if planning:
        validate_planning_inventory(document)
        banner = "Planning inventory. No observed classification metrics."
        rows = document["conditions"]
    else:
        validate_aggregate(document)
        banner = document["disclaimer"]
        rows = sorted(document["conditions"], key=_arm_key)
    align = ["---:" if index in RIGHT_ALIGNED else "---" for index in range(len(TABLE_HEADERS))]
    lines = [banner, "", "| " + " | ".join(TABLE_HEADERS) + " |", "|" + "|".join(align) + "|"]
    for condition in rows:
        cells = _row_cells(condition, planning)
        require(len(cells) == len(TABLE_HEADERS), "table width")
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


def validate_private_condition(condition):
    require(type(condition) is dict, "private condition")
    extras = set(PRIVATE_CONDITION_FIELDS)
    require(set(condition) == set(CONDITION_FIELD_NAMES) | extras, "private condition fields")
    public = project_public_condition(condition)
    _validate_condition(public, PRIVATE_STATUSES)
    _validate_frozen_plan(condition)
    require(condition["record_type"] == "condition", "record_type")
    if public["status"] == "planned":
        require(condition["decoding"] is None, "planned decoding")
        require(condition["demonstration_ids"] == [], "planned demonstrations")
    else:
        require(type(condition["decoding"]) is dict and set(condition["decoding"]) == {
            "temperature", "top_p", "max_output_tokens", "seed",
        }, "decoding")
        _float(condition["decoding"]["temperature"], "temperature")
        _float(condition["decoding"]["top_p"], "top_p")
        _int(condition["decoding"]["max_output_tokens"], "decoding max_output_tokens", minimum=1)
        _int(condition["decoding"]["seed"], "seed")
        require(type(condition["demonstration_ids"]) is list, "demonstration_ids")
        require(len(condition["demonstration_ids"]) == public["demonstration_count"], "demonstration count")
        require(len(set(condition["demonstration_ids"])) == len(condition["demonstration_ids"]), "duplicate demonstration_id")
        require(condition["decoding"]["max_output_tokens"] == public["max_output_tokens"], "decoding output limit")
        for item in condition["demonstration_ids"]:
            _ident(item, "demonstration_id")
    reference = condition["private_artifact_reference"]
    _nonempty(reference, "private_artifact_reference")
    require(RELATIVE_REF.fullmatch(reference) is not None and ".." not in reference and not reference.startswith("/"),
            "private_artifact_reference must be a relative id")
    for name in ("serving_session_id", "endpoint", "prompt_template_sha256"):
        if condition[name] is not None:
            _nonempty(condition[name], name)
    return condition


def _assert_layout_anchor(anchor):
    resolved = Path(anchor).resolve()
    require("results" not in resolved.parts, "evidence layout cannot be rooted in results/")
    require(resolved.exists() and resolved.is_dir(), "evidence anchor is not a directory")
    return resolved


def run_directory(anchor, run_id):
    _ident(run_id, "run_id")
    root = _assert_layout_anchor(anchor)
    return root / "capacity" / "runs" / run_id


def audit_directory(anchor, audit_id):
    _ident(audit_id, "audit_id")
    root = _assert_layout_anchor(anchor)
    return root / "capacity" / "audits" / audit_id


def write_synthetic_layout(anchor, run):
    """Write the #5 directory layout for a synthetic run. Refuses observed evidence."""
    require(run.get("evidence_class") == "synthetic", "only synthetic fixtures can use this writer")
    require(str(run.get("run_id", "")).startswith("synthetic-"), "synthetic run_id")
    export_public_aggregate(run)
    directory = run_directory(anchor, run["run_id"])
    directory.mkdir(parents=True, exist_ok=False)
    header = {
        "schema_version": SCHEMA_VERSION,
        "schema_id": EVIDENCE_SCHEMA_ID,
        "evidence_class": "synthetic",
        "evidence_banner": SYNTHETIC_BANNER,
        "run_id": run["run_id"],
        "design_issue": DESIGN_ISSUE,
        "issue_5_interface": "validate_then_store",
        "model_requests_made": 0,
        "layout": {
            "run_file": "run.json",
            "conditions_file": "conditions.jsonl",
            "predictions_file": "predictions.jsonl",
            "audit_dir": "capacity/audits/<audit_id>/groups.json",
        },
    }
    (directory / "run.json").write_text(canonical_json(header))
    with (directory / "conditions.jsonl").open("w", encoding="utf-8") as handle:
        for condition in run["conditions"]:
            validate_private_condition(condition)
            handle.write(json.dumps(condition, ensure_ascii=False) + "\n")
    with (directory / "predictions.jsonl").open("w", encoding="utf-8") as handle:
        for row in run["predictions"]:
            validate_prediction(row)
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    for audit in run.get("audits", []):
        target = audit_directory(anchor, audit["audit_id"])
        target.mkdir(parents=True, exist_ok=False)
        (target / "groups.json").write_text(canonical_json(audit))
    return directory


def _schema_field(name, kind, nullable):
    def maybe(schema):
        if not nullable:
            return schema
        return {"anyOf": [{"type": "null"}, schema]}

    enums = {
        "dataset_type": list(DATASET_TYPES),
        "status": list(PUBLIC_STATUSES),
        "result_arm": list(RESULT_ARMS),
        "label_order": list(LABEL_ORDERS),
        "observation_source": list(OBSERVATION_SOURCES),
        "context_fit_status": list(CONTEXT_FIT),
        "truncation_policy": list(TRUNCATION),
        "audit_matching": list(AUDIT_MATCHING),
    }
    if name in enums:
        return maybe({"type": "string", "enum": enums[name]})
    if name == "schema_id":
        return {"type": "string", "const": CONDITION_SCHEMA_ID}
    if name == "accounting_policy":
        return {"type": "string", "const": ACCOUNTING_POLICY}
    if name == "freeze_id":
        return {"type": "string", "const": FREEZE_ID}
    if name == "pairing_established_by_aggregate":
        return {"type": "boolean", "const": False}
    if name == "design_issue":
        return {"type": "integer", "const": DESIGN_ISSUE}
    if name == "schema_version":
        return {"type": "integer", "const": SCHEMA_VERSION}
    if kind == "int":
        return maybe({"type": "integer", "minimum": 0})
    if kind == "float":
        schema = {"type": "number"}
        if name in METRIC_FIELDS or name == "empirical_accuracy_ceiling":
            schema.update({"minimum": 0, "maximum": 1})
        else:
            schema["minimum"] = 0
        return maybe(schema)
    if kind == "str":
        return maybe({"type": "string", "minLength": 1})
    if kind == "bool":
        return maybe({"type": "boolean"})
    if kind == "strings":
        return maybe({"type": "array", "items": {"type": "string", "minLength": 1}})
    if kind in {"string_map", "reasons"}:
        return maybe({"type": "object", "additionalProperties": {"type": "string", "minLength": 1}})
    if kind == "label_map":
        return maybe({
            "type": "object",
            "additionalProperties": False,
            "required": ["benign", "malicious"],
            "properties": {
                "benign": {"type": "string", "minLength": 1},
                "malicious": {"type": "string", "minLength": 1},
            },
        })
    if kind == "timestamps":
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["registered_at", "closed_at"],
            "properties": {
                "registered_at": {"type": "string", "pattern": ISO_TIME.pattern},
                "closed_at": {"anyOf": [{"type": "null"}, {"type": "string", "pattern": ISO_TIME.pattern}]},
            },
        }
    if kind == "amendments":
        return {"type": "array", "prefixItems": [{"const": item} for item in AMENDMENTS], "minItems": len(AMENDMENTS), "maxItems": len(AMENDMENTS)}
    raise CapacityContractError(kind)


def condition_schema(private):
    properties = {}
    for name, kind, nullable, description in CONDITION_FIELDS:
        schema = _schema_field(name, kind, nullable)
        schema["description"] = description
        if private and name == "status":
            schema = {"type": "string", "enum": list(PRIVATE_STATUSES), "description": description + " Private records may also be running."}
        properties[name] = schema
    required = list(CONDITION_FIELD_NAMES)
    if private:
        properties.update({
            "planned_queries": {"anyOf": [
                {"type": "null"},
                {"type": "array", "items": {
                    "type": "object", "additionalProperties": False,
                    "required": list(PLAN_QUERY_FIELDS),
                    "properties": {name: ({"enum": list(GOLD_LABELS)} if name == "gold_label" else
                                          {"type": "string", "minLength": 1}) for name in PLAN_QUERY_FIELDS},
                }},
            ]},
            "record_type": {"type": "string", "const": "condition"},
            "private_artifact_reference": {"type": "string", "minLength": 1, "description": "Relative evidence id. Not a public field."},
            "decoding": {"anyOf": [
                {"type": "null"},
                {"type": "object", "additionalProperties": False, "required": ["temperature", "top_p", "max_output_tokens", "seed"],
                 "properties": {
                     "temperature": {"type": "number"},
                     "top_p": {"type": "number"},
                     "max_output_tokens": {"type": "integer", "minimum": 1},
                     "seed": {"type": "integer", "minimum": 0},
                 }},
            ]},
            "demonstration_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
            "serving_session_id": {"anyOf": [{"type": "null"}, {"type": "string", "minLength": 1}]},
            "endpoint": {"anyOf": [{"type": "null"}, {"type": "string", "minLength": 1}]},
            "prompt_template_sha256": {"anyOf": [{"type": "null"}, {"type": "string", "minLength": 1}]},
        })
        required = list(CONDITION_FIELD_NAMES) + list(PRIVATE_CONDITION_FIELDS)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/dsikar/fesa-llm-experiments/schemas/" + (
            "capacity-condition-private-v1.schema.json" if private else "capacity-condition-public-v1.schema.json"
        ),
        "title": "Capacity private condition v1" if private else "Capacity public condition v1",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def prediction_schema():
    descriptions = {
        "query_id": "Private query identity. Stripped by the public exporter.",
        "row_identity": "Private source-row identity. Stripped by the public exporter.",
        "pair_group_id": "Private pairing key. Aggregate counts do not prove pairing.",
        "membership_hash": "Private duplicate-group membership hash. Not published.",
        "prompt_sha256": "Hash of the exact rendered prompt. Treated as membership-identifying.",
        "response_sha256": "Hash of the raw response. Not published.",
        "demonstration_ids": "Private demonstration identities used for this query.",
        "raw_prompt_ref": "Relative private prompt artifact name.",
        "raw_response_ref": "Relative private response artifact name.",
        "terminal_disposition": "Exactly one terminal bucket for this planned query.",
        "attempt_count": "Requests for this query, including retries. The query still counts once.",
    }
    properties = {}
    for name in PREDICTION_FIELDS:
        if name in {"schema_version"}:
            properties[name] = {"type": "integer", "const": SCHEMA_VERSION}
        elif name == "schema_id":
            properties[name] = {"const": PREDICTION_SCHEMA_ID}
        elif name == "record_type":
            properties[name] = {"const": "prediction"}
        elif name in {"response_received", "truncated"}:
            properties[name] = {"type": "boolean"}
        elif name in {"attempt_count", "input_tokens", "output_tokens"}:
            properties[name] = {"anyOf": [{"type": "null"}, {"type": "integer", "minimum": 0}]} if name != "attempt_count" else {"type": "integer", "minimum": 0}
        elif name == "latency_seconds":
            properties[name] = {"anyOf": [{"type": "null"}, {"type": "number", "minimum": 0}]}
        elif name == "gold_label":
            properties[name] = {"type": "string", "enum": list(GOLD_LABELS)}
        elif name == "parsed_prediction":
            properties[name] = {"anyOf": [{"type": "null"}, {"type": "string", "enum": list(GOLD_LABELS)}]}
        elif name == "terminal_disposition":
            properties[name] = {"type": "string", "enum": list(DISPOSITIONS)}
        elif name == "context_overflow_stage":
            properties[name] = {"type": "string", "enum": list(OVERFLOW_STAGES)}
        elif name == "demonstration_ids":
            properties[name] = {"type": "array", "items": {"type": "string", "minLength": 1}}
        elif name in {"pair_group_id", "prompt_sha256", "response_sha256", "membership_hash",
                      "raw_prompt_ref", "raw_response_ref", "serving_session_id", "endpoint", "error_name"}:
            properties[name] = {"anyOf": [{"type": "null"}, {"type": "string", "minLength": 1}]}
        else:
            properties[name] = {"type": "string", "minLength": 1}
        if name in descriptions:
            properties[name]["description"] = descriptions[name]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/dsikar/fesa-llm-experiments/schemas/capacity-prediction-private-v1.schema.json",
        "title": "Capacity private prediction v1",
        "description": "One planned query. Retries stay on this record through attempt_count.",
        "type": "object",
        "additionalProperties": False,
        "required": list(PREDICTION_FIELDS),
        "properties": properties,
    }


def aggregate_schema():
    condition = condition_schema(False)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/dsikar/fesa-llm-experiments/schemas/capacity-aggregate-v1.schema.json",
        "title": "Capacity aggregate v1",
        "description": (
            "Public allowlist for one capacity publication. Arithmetic, null reasons, "
            "accounting identities and paired-eligibility gates are enforced by "
            "scripts/capacity_contract.py. Synthetic fixtures are not observed results. "
            "results/public/capacity-results.json is reserved for a later reviewed aggregate."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": list(AGGREGATE_FIELDS),
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "schema_id": {"const": AGGREGATE_SCHEMA_ID},
            "artifact_type": {"enum": ["synthetic_fixture", "reviewed_aggregate"]},
            "evidence_banner": {"enum": [SYNTHETIC_BANNER, REVIEWED_BANNER]},
            "evidence_class": {"enum": ["synthetic", "observed"]},
            "synthetic": {"type": "boolean"},
            "not_an_experiment": {"type": "boolean"},
            "experiment": {"const": EXPERIMENT},
            "design_issue": {"const": DESIGN_ISSUE},
            "design_doc": {"const": DESIGN_DOC},
            "design_request": {"const": DESIGN_REQUEST},
            "accounting_policy": {"const": ACCOUNTING_POLICY},
            "freeze_id": {"const": FREEZE_ID},
            "code_revision": {"type": "string", "minLength": 1},
            "analysis_revision": {"type": "string", "minLength": 1},
            "reviewed_aggregate_revision": {"anyOf": [{"type": "null"}, {"type": "string", "minLength": 1}]},
            "amendment_ids": condition["properties"]["amendment_ids"],
            "model_requests_made": {"type": "integer", "minimum": 0},
            "pairing_evidence": {"const": PAIRING_EVIDENCE},
            "generator": {"const": GENERATOR},
            "disclaimer": {"type": "string", "minLength": 1},
            "unavailable_reasons": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
            "conditions": {"type": "array", "minItems": 1, "items": condition},
        },
    }


def plan_schema():
    nullable_int = {"anyOf": [{"type": "null"}, {"type": "integer"}]}
    item_properties = {
        "dataset_id": {"type": "string"},
        "dataset_type": {"enum": list(DATASET_TYPES)},
        "n_source_columns": {"type": "integer", "minimum": 1},
        "n_non_label_attributes": {"type": "integer", "minimum": 0},
        "label_columns_excluded": {"type": "array", "items": {"type": "string"}},
        "n_source_train_rows": nullable_int,
        "n_source_test_rows": nullable_int,
        "n_source_rows": {"type": "integer", "minimum": 0},
        "status": {"const": "planned"},
        "status_reason": {"type": "string", "minLength": 1},
    }
    for name in PLAN_NULL_FIELDS:
        item_properties[name] = {"type": "null"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/dsikar/fesa-llm-experiments/schemas/capacity-plan-v1.schema.json",
        "title": "Capacity planning inventory v1",
        "description": "Not an observed-results aggregate. Observed metrics in the frozen inventory stay null.",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "artifact_type", "model_requests_made", "conditions"],
        "properties": {
            "schema_version": {"const": 1},
            "artifact_type": {"const": "planning_inventory"},
            "model_requests_made": {"const": 0},
            "conditions": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": list(PLAN_CONDITION_FIELDS),
                    "properties": item_properties,
                },
            },
        },
    }


def evidence_run_schema():
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/dsikar/fesa-llm-experiments/schemas/evidence-run-v1.schema.json",
        "title": "Evidence run layout v1",
        "description": (
            "Interface for issue #5. #5 stores these records immutably and handles resume. "
            "#7 validates them and exports the public allowlist. This writer does not run inference."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "schema_id", "evidence_class", "run_id", "design_issue", "issue_5_interface", "layout"],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "schema_id": {"const": EVIDENCE_SCHEMA_ID},
            "evidence_class": {"enum": ["synthetic", "observed"]},
            "evidence_banner": {"type": "string"},
            "run_id": {"type": "string", "minLength": 1},
            "design_issue": {"const": DESIGN_ISSUE},
            "issue_5_interface": {"const": "validate_then_store"},
            "model_requests_made": {"type": "integer", "minimum": 0},
            "layout": {
                "type": "object",
                "additionalProperties": False,
                "required": ["run_file", "conditions_file", "predictions_file", "audit_dir"],
                "properties": {
                    "run_file": {"const": "run.json"},
                    "conditions_file": {"const": "conditions.jsonl"},
                    "predictions_file": {"const": "predictions.jsonl"},
                    "audit_dir": {"const": "capacity/audits/<audit_id>/groups.json"},
                },
            },
            "conditions": {"type": "array", "items": {"$ref": "capacity-condition-private-v1.schema.json"}},
            "predictions": {"type": "array", "items": {"$ref": "capacity-prediction-private-v1.schema.json"}},
        },
    }


def schema_documents():
    return {
        "capacity-aggregate-v1.schema.json": aggregate_schema(),
        "capacity-condition-private-v1.schema.json": condition_schema(True),
        "capacity-prediction-private-v1.schema.json": prediction_schema(),
        "capacity-plan-v1.schema.json": plan_schema(),
        "evidence-run-v1.schema.json": evidence_run_schema(),
    }


def write_schemas(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name, document in schema_documents().items():
        (directory / name).write_text(canonical_json(document))


def _private_condition(public, demonstrations, planned_queries):
    private = dict(public)
    private["planned_queries"] = planned_queries
    private["record_type"] = "condition"
    private["private_artifact_reference"] = f"capacity/runs/{public['run_id']}"
    private["demonstration_ids"] = list(demonstrations)
    private["serving_session_id"] = None
    private["endpoint"] = None
    private["prompt_template_sha256"] = "synthetic-template-hash"
    if public["status"] == "planned":
        private["decoding"] = None
        private["demonstration_ids"] = []
        private["prompt_template_sha256"] = None
    else:
        private["decoding"] = {"temperature": 0.0, "top_p": 1.0, "max_output_tokens": 32, "seed": 0}
    return private


def _prediction(run_id, condition_id, index, gold, disposition="valid", parsed=None, attempts=1,
                stage="none", input_tokens=100, output_tokens=10, latency=0.5, demonstrations=()):
    response = disposition in {"valid", "parse_failure", "truncated"}
    if disposition != "valid":
        parsed = None
    if stage == "preflight":
        attempts = 0
        input_tokens = None
        latency = None
    if not response:
        output_tokens = None
    error = None if disposition == "valid" else disposition.replace("_", "-")
    return {
        "schema_version": SCHEMA_VERSION,
        "schema_id": PREDICTION_SCHEMA_ID,
        "record_type": "prediction",
        "run_id": run_id,
        "condition_id": condition_id,
        "query_id": f"synthetic-query-{condition_id}-{index:02d}",
        "row_identity": f"synthetic-row-{condition_id}-{index:02d}",
        "pair_group_id": f"synthetic-pair-{condition_id}",
        "gold_label": gold,
        "terminal_disposition": disposition,
        "attempt_count": attempts,
        "context_overflow_stage": stage,
        "parsed_prediction": parsed,
        "response_received": response,
        "truncated": disposition == "truncated",
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "latency_seconds": latency,
        "prompt_sha256": f"synthetic-prompt-hash-{condition_id}-{index:02d}",
        "response_sha256": None if not response else f"synthetic-response-hash-{condition_id}-{index:02d}",
        "membership_hash": f"synthetic-membership-{condition_id}-{index:02d}",
        "demonstration_ids": list(demonstrations),
        "raw_prompt_ref": f"prompts/{condition_id}/{index:02d}.txt",
        "raw_response_ref": None if not response else f"responses/{condition_id}/{index:02d}.txt",
        "serving_session_id": None,
        "endpoint": None,
        "error_name": error,
    }


def _design(condition_id, feature_set, status, *, dataset="synthetic-phish", dataset_type="phishing",
            split="split-heldout", demos=0, order="A", replicate=1, raw=6, supplied=None,
            labels=None, names=None, excluded=None, reasons=None, verdict=False, arm=None,
            population="synthetic-heldout-queries", budget=None, limit=4096, policy="synthetic-policy-v0",
            planned_labels=None):
    if labels is None:
        labels = ["Class"] if dataset_type == "phishing" else ["Class", "Category", "Family"]
    if supplied is None:
        supplied = raw
    if names is None:
        names = [f"attr_{index:02d}" for index in range(supplied)]
    if excluded is None:
        excluded = [f"attr_{index:02d}" for index in range(supplied, raw)]
    if reasons is None:
        reasons = {name: "synthetic nested exclusion" for name in excluded}
    if arm is None:
        arm = "audited_generalization" if status != "planned" else "pending"
    closed = None if status == "planned" else "2026-11-19T00:00:01Z"
    return {
        "run_id": "synthetic-capacity-demo",
        "planned_queries": None if planned_labels is None else [
            {"query_id": f"synthetic-query-{condition_id}-{index:02d}",
             "row_identity": f"synthetic-row-{condition_id}-{index:02d}",
             "gold_label": gold,
             "membership_hash": f"synthetic-membership-{condition_id}-{index:02d}"}
            for index, gold in enumerate(planned_labels)
        ],
        "n_queries_planned": None if planned_labels is None else len(planned_labels),
        "n_benign_planned": None if planned_labels is None else planned_labels.count("benign"),
        "n_malicious_planned": None if planned_labels is None else planned_labels.count("malicious"),
        "condition_id": condition_id,
        "dataset_id": dataset,
        "dataset_type": dataset_type,
        "dataset_version": "synthetic-v0",
        "split_id": split,
        "feature_set_id": feature_set,
        "feature_policy": policy,
        "model_id": None if status == "planned" else "synthetic-model",
        "model_revision": None if status == "planned" else "synthetic-model-revision-v0",
        "tokenizer_revision": None if status == "planned" else "synthetic-tokenizer-v0",
        "code_revision": "synthetic-not-a-commit",
        "template_version": None if status == "planned" else "synthetic-template-v0",
        "config_revision": None if status == "planned" else "synthetic-config-v0",
        "result_arm": arm,
        "observation_source": "not_run" if status == "planned" else "synthetic_fixture",
        "n_source_columns": None if status == "planned" else raw + len(labels),
        "label_columns_excluded": labels,
        "n_non_label_attributes": None if status == "planned" else raw,
        "n_attributes_input": None if status == "planned" else supplied,
        "input_attribute_names": None if status == "planned" else names,
        "excluded_attribute_names": None if status == "planned" else excluded,
        "exclusion_reasons": None if status == "planned" else reasons,
        "encoding_policy": None if status == "planned" else "canonical-decimal",
        "missing_value_policy": None if status == "planned" else "reject-missing",
        "identity_or_verdict_features_present": None if status == "planned" else verdict,
        "label_mapping": None if status == "planned" else (
            {"benign": "Benign", "malicious": "Malware"} if dataset_type == "malware"
            else {"benign": "0", "malicious": "1"}
        ),
        "demonstration_count": demos,
        "label_order": order,
        "demonstration_order_policy": None if status == "planned" else (
            "not-applicable" if demos == 0 else "fixed-listed-order"
        ),
        "selection_seed": None if status == "planned" else 0,
        "replicate": replicate,
        "schedule_id": None if status == "planned" else "synthetic-not-scheduled",
        "sampling_policy": None if status == "planned" else "synthetic-not-a-sample",
        "population_scope": None if status == "planned" else population,
        "status": status,
        "status_reason": {
            "planned": "synthetic arm named only to keep the row distinct; no queries observed",
            "complete": "synthetic closed accounting; every planned query scored",
            "incomplete": "synthetic closed accounting; only a subset of queries scored",
            "failed": "synthetic closed accounting; no query produced a valid prediction",
            "blocked": "synthetic preflight context overflow; no request was sent",
        }[status],
        "n_requests_budgeted": budget,
        "context_limit_tokens": None if status == "planned" else limit,
        "max_output_tokens": None if status == "planned" else 32,
        "truncation_policy": None if status == "planned" else "reject_truncated",
        "analysis_revision": "synthetic-analysis-v1",
        "reviewed_aggregate_revision": None,
        "timestamps": {"registered_at": "2026-11-19T00:00:00Z", "closed_at": closed},
    }


def _valid_rows(run_id, condition_id, pairs, demonstrations, token_start=100):
    rows = []
    for index, (gold, parsed) in enumerate(pairs):
        rows.append(_prediction(
            run_id, condition_id, index, gold, "valid", parsed, attempts=1,
            input_tokens=token_start + 10 * index, demonstrations=demonstrations,
        ))
    return rows


def build_synthetic_run():
    """Return a private synthetic run covering the contract cases. No model is called."""
    run_id = "synthetic-capacity-demo"
    audits = []
    conditions = []
    predictions = []

    def add(feature, status, pairs, **kwargs):
        demonstrations = kwargs.pop("demonstrations", [])
        audit = kwargs.pop("audit", None)
        demos = kwargs.pop("demos", 0)
        condition_id = "cap-" + "-".join([
            kwargs.get("dataset", "synthetic-phish"), kwargs.get("split", "split-heldout"), feature,
            f"d{demos}", kwargs.get("order", "A").lower(), f"r{kwargs.get('replicate', 1)}",
        ])
        design = _design(condition_id, feature, status, demos=demos, **kwargs)
        if design["n_requests_budgeted"] is None and status != "planned":
            design["n_requests_budgeted"] = len(pairs) if pairs is not None else 0
        public = assemble_public_condition(design, pairs, audit)
        private = _private_condition(public, demonstrations, design["planned_queries"])
        conditions.append(private)
        if pairs:
            predictions.extend(pairs)
        if audit is not None:
            audits.append({
                "schema_version": SCHEMA_VERSION,
                "record_type": "duplicate_audit",
                "audit_id": "synthetic-audit-" + feature,
                "condition_id": condition_id,
                "matching": audit["matching"],
                "population_scope": audit["population_scope"],
                "groups": [
                    {"n_benign": n0, "n_malicious": n1, "membership_hash": f"synthetic-group-{feature}-{index:02d}"}
                    for index, (n0, n1) in enumerate(audit["groups"])
                ],
                "cross_split_overlap_groups": audit.get("cross_split_overlap_groups"),
                "cross_split_overlap_rows": audit.get("cross_split_overlap_rows"),
            })
        return condition_id

    main_id = "cap-synthetic-phish-split-heldout-features-max-d0-a-r1"
    main_pairs = _valid_rows(run_id, main_id, [
        ("benign", "benign"), ("benign", "benign"), ("benign", "benign"), ("benign", "malicious"),
        ("malicious", "malicious"), ("malicious", "malicious"), ("malicious", "malicious"), ("malicious", "benign"),
    ], [])
    main_audit = {
        "matching": "exact",
        "population_scope": "synthetic-source-population",
        "groups": [(5, 0), (2, 1), (0, 1), (1, 0)],
        "cross_split_overlap_groups": 0,
        "cross_split_overlap_rows": 0,
    }
    add("features-max", "complete", main_pairs, budget=8, audit=main_audit, planned_labels=["benign"] * 4 + ["malicious"] * 4)

    reduced_names = ["attr_00", "attr_01"]
    reduced_excluded = ["attr_02", "attr_03", "attr_04", "attr_05"]
    reduced_id = "cap-synthetic-phish-split-heldout-features-reduced-d0-a-r1"
    add("features-reduced", "complete", _valid_rows(run_id, reduced_id, [
        ("benign", "benign"), ("malicious", "malicious"),
    ], []), supplied=2, names=reduced_names, excluded=reduced_excluded, budget=2, planned_labels=["benign", "malicious"])

    diagnostic_id = "cap-synthetic-phish-split-heldout-features-diagnostic-d0-a-r1"
    add("features-diagnostic", "complete", _valid_rows(run_id, diagnostic_id, [
        ("benign", "benign"), ("malicious", "malicious"),
    ], []), verdict=True, arm="diagnostic", budget=2, planned_labels=["benign", "malicious"])

    incomplete_id = "cap-synthetic-phish-split-heldout-features-incomplete-demo-d0-a-r1"
    incomplete_rows = [
        _prediction(run_id, incomplete_id, 0, "benign", "valid", "benign", input_tokens=100),
        _prediction(run_id, incomplete_id, 1, "benign", "valid", "benign", input_tokens=110),
        _prediction(run_id, incomplete_id, 2, "benign", "parse_failure", input_tokens=120),
        _prediction(run_id, incomplete_id, 3, "malicious", "context_overflow", attempts=2, stage="sent", input_tokens=130),
        _prediction(run_id, incomplete_id, 4, "malicious", "truncated", input_tokens=140),
    ]
    add("features-incomplete-demo", "incomplete", incomplete_rows, budget=10, planned_labels=["benign"] * 3 + ["malicious"] * 2)

    failed_id = "cap-synthetic-phish-split-heldout-features-failed-demo-d0-a-r1"
    add("features-failed-demo", "failed", [
        _prediction(run_id, failed_id, 0, "benign", "parse_failure", input_tokens=100),
        _prediction(run_id, failed_id, 1, "malicious", "parse_failure", input_tokens=110),
        _prediction(run_id, failed_id, 2, "malicious", "parse_failure", input_tokens=120),
    ], budget=3, planned_labels=["benign", "malicious", "malicious"])

    blocked_id = "cap-synthetic-phish-split-heldout-features-blocked-demo-d0-a-r1"
    add("features-blocked-demo", "blocked", [
        _prediction(run_id, blocked_id, index, gold, "context_overflow", stage="preflight")
        for index, gold in enumerate(("benign", "benign", "malicious"))
    ], budget=3, limit=512, planned_labels=["benign", "benign", "malicious"])

    add("features-unfrozen", "planned", None, raw=6)

    precision_id = "cap-synthetic-malware-split-heldout-features-max-d0-a-r1"
    malware_names = ["m_00", "m_01", "m_02", "m_03"]
    add("features-max", "complete", _valid_rows(run_id, precision_id, [
        ("benign", "benign"), ("benign", "benign"), ("malicious", "benign"), ("malicious", "benign"),
    ], []), dataset="synthetic-malware", dataset_type="malware", raw=4, names=malware_names, budget=4, planned_labels=["benign", "benign", "malicious", "malicious"])

    for split, demos, order, replicate, feature in (
        ("split-dev", 0, "A", 1, "features-max"),
        ("split-heldout", 4, "A", 1, "features-max"),
        ("split-heldout", 0, "B", 1, "features-max"),
        ("split-heldout", 0, "A", 2, "features-max"),
    ):
        demos_ids = [f"synthetic-demo-{split}-{order.lower()}-{index:02d}" for index in range(demos)]
        condition_id = "cap-" + "-".join([
            "synthetic-phish", split, feature, f"d{demos}", order.lower(), f"r{replicate}",
        ])
        add(feature, "complete", _valid_rows(run_id, condition_id, [
            ("benign", "benign"), ("malicious", "malicious"),
        ], demos_ids), split=split, demos=demos, order=order, replicate=replicate,
           demonstrations=demos_ids, budget=2, planned_labels=["benign", "malicious"])

    run = {
        "schema_version": SCHEMA_VERSION,
        "schema_id": EVIDENCE_SCHEMA_ID,
        "evidence_class": "synthetic",
        "evidence_banner": SYNTHETIC_BANNER,
        "run_id": run_id,
        "design_issue": DESIGN_ISSUE,
        "issue_5_interface": "validate_then_store",
        "code_revision": "synthetic-not-a-commit",
        "analysis_revision": "synthetic-analysis-v1",
        "model_requests_made": 0,
        "conditions": conditions,
        "predictions": predictions,
        "audits": audits,
    }
    for condition in conditions:
        validate_private_condition(condition)
    return run


def synthetic_public_aggregate():
    return export_public_aggregate(build_synthetic_run())
