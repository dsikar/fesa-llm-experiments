"""Offline preflight, scheduling and paired inference for issue #3. No model access."""
import hashlib
import json
import random
import re
import sys
import tomllib
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fesa_prompts import load_policy, project_features, render_prompt, verify_freeze
from verify_baseline import exact_half, holm, wilson
from check_public_tree import RULES

FREEZE_FILES = ("configs/label-order-v1.toml", "scripts/label_order.py", "scripts/analyze_label_order.py", "scripts/verify_baseline.py")
META_KEYS = {"run_id", "serving_session_id", "model_id", "model_revision", "tokenizer_revision", "code_revision", "decoding"}
DESIGN_KEYS = {"split_id", "queries", "demonstrations"}
QUERY_KEYS = {"query_id", "label", "features"}
DEMO_KEYS = {"demo_id", "label", "features"}
MANIFEST_KEYS = {"schema_version", "design_version", "evidence_class", "metadata", "execution_sha256", "datasets", "requests"}
CELL_KEYS = {"split_id", "queries", "demonstrations", "prompt_pairs"}
ROW_EXTRA = {"status", "prediction", "attempt_count"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identifier(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", value) is not None


def binary(value):
    return type(value) is int and value in (0, 1)


def checksum(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def load_design():
    records = {}
    for line in (ROOT / "configs/label-order-v1.sha256").read_text().splitlines():
        sha, name = line.split("  ", 1)
        require(name not in records and checksum(sha), "invalid label-order freeze")
        records[name] = sha
    require(set(records) == set(FREEZE_FILES), "label-order freeze file coverage differs")
    for name, expected in records.items():
        require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, "label-order design changed; amend and refreeze before requests")
    verify_freeze()
    return tomllib.loads((ROOT / "configs/label-order-v1.toml").read_text())


def validate_metadata(metadata):
    require(type(metadata) is dict and set(metadata) == META_KEYS, "execution metadata fields differ")
    for key in META_KEYS - {"decoding"}:
        require(identifier(metadata[key]), "execution metadata needs explicit searchable revisions/session identifiers")
    require(type(metadata["decoding"]) is dict and metadata["decoding"], "decoding must be explicitly frozen")
    canonical(metadata)  # Reject non-finite JSON values; exact decoding semantics belong to #5.


def render_pair(dataset, query, demonstrations):
    """Return both exact bundles; verify instruction clause is the sole text change."""
    a = render_prompt(dataset, query, demonstrations, "A")
    b = render_prompt(dataset, query, demonstrations, "B")
    config, _, _ = load_policy()
    clause = config["datasets"][dataset]
    old, new = clause["label_order_a"], clause["label_order_b"]
    require(a["prompt"].count(old) == 1 and b["prompt"].count(new) == 1, "ambiguous instruction label clause")
    require(a["prompt"].replace(old, new, 1) == b["prompt"], "A/B prompts differ beyond the label clause")
    for key in ("dataset", "demonstration_count", "demonstration_labels", "frozen_artifact_sha256", "excluded_feature_names"):
        require(a[key] == b[key], "A/B input policy or demonstrations changed")
    return a, b


def _validate_dataset(cell, plan, *, include_prompts=True):
    require(type(cell) is dict and set(cell) == CELL_KEYS, "manifest dataset fields differ")
    require(identifier(cell["split_id"]), "missing frozen split id")
    queries, demos = cell["queries"], cell["demonstrations"]
    require(type(queries) is list and len(queries) == plan["queries_per_dataset"], "query count differs from frozen design")
    require(all(type(q) is dict and set(q) == {"query_id", "label"} and identifier(q["query_id"]) and binary(q["label"]) for q in queries), "invalid query identity/label")
    require(len({q["query_id"] for q in queries}) == len(queries), "duplicate frozen query id")
    require(sum(q["label"] == 0 for q in queries) == plan["queries_per_class"], "query class counts differ from frozen design")
    require(type(demos) is list and len(demos) == max(plan["demonstration_counts"]), "need exactly ten frozen demonstrations")
    require(all(type(d) is dict and set(d) == {"demo_id", "label"} and identifier(d["demo_id"]) and binary(d["label"]) for d in demos), "invalid demonstration identity/label")
    require(len({d["demo_id"] for d in demos}) == len(demos), "duplicate demonstration id")
    require({q["query_id"] for q in queries}.isdisjoint(d["demo_id"] for d in demos), "query/demo identity overlap")
    for count in plan["demonstration_counts"]:
        require(sum(d["label"] == 0 for d in demos[:count]) == count // 2, "nested demonstrations must be balanced")
    if not include_prompts:
        return
    pairs = cell["prompt_pairs"]
    require(type(pairs) is list and len(pairs) == len(queries) * len(plan["demonstration_counts"]), "missing prompt pairs")
    expected = [(q["query_id"], count) for q in queries for count in plan["demonstration_counts"]]
    for pair, (qid, count) in zip(pairs, expected):
        require(type(pair) is dict and set(pair) == {"query_id", "demonstration_count", "A", "B"}, "prompt-pair fields differ")
        require(pair["query_id"] == qid and type(pair["demonstration_count"]) is int and pair["demonstration_count"] == count, "prompt pairs reordered or relabelled")
        require(checksum(pair["A"]) and checksum(pair["B"]) and pair["A"] != pair["B"], "invalid A/B prompt hashes")


def scheduled_requests(datasets, execution_sha256, plan=None):
    """Shuffle paired query blocks; exactly half A-first within each dataset/count."""
    if plan is None:
        plan = load_design()
    rng = random.Random(plan["schedule_seed"])
    n, block = plan["queries_per_dataset"], plan["query_block_size"]
    require(n % block == 0 and (n // block) % 2 == 0, "counterbalancing requires an even number of equal blocks")
    blocks = []
    for dataset in plan["datasets"]:
        for count in plan["demonstration_counts"]:
            first = ["A"] * (n // block // 2) + ["B"] * (n // block // 2)
            rng.shuffle(first)
            blocks.extend((dataset, count, index, order) for index, order in enumerate(first))
    rng.shuffle(blocks)
    hashes = {domain: {(p["query_id"], p["demonstration_count"]): p for p in cell["prompt_pairs"]} for domain, cell in datasets.items()}
    result = []
    for block_index, (dataset, count, index, first) in enumerate(blocks):
        orders = (first, "B" if first == "A" else "A")
        for order in orders:
            for q in datasets[dataset]["queries"][index * block:(index + 1) * block]:
                result.append({
                    "request_id": f"request-{len(result):04d}", "block_id": block_index,
                    "dataset": dataset, "demonstration_count": count, "label_order": order,
                    "query_id": q["query_id"], "gold_label": q["label"],
                    "prompt_sha256": hashes[dataset][q["query_id"], count][order],
                    "execution_sha256": execution_sha256,
                })
    require(len(result) == plan["request_budget"], "schedule request count differs from frozen budget")
    return result


def build_manifest(datasets, metadata, *, evidence_class):
    """Build private registration from #4 data; save its digest before collection.

    The caller owns private storage (#5). No model requests or file writes occur.
    """
    plan = load_design()
    validate_metadata(metadata)
    require(evidence_class in {"synthetic", "observed"}, "declare synthetic or observed evidence")
    require(type(datasets) is dict and set(datasets) == set(plan["datasets"]), "dataset matrix differs from frozen design")
    config, dictionary, _ = load_policy()
    frozen = {}
    for domain in plan["datasets"]:
        source = datasets[domain]
        require(type(source) is dict and set(source) == DESIGN_KEYS, "dataset source fields differ")
        queries, demos = source["queries"], source["demonstrations"]
        require(type(queries) is list and type(demos) is list, "query/demo pools must be lists")
        require(all(type(q) is dict and set(q) == QUERY_KEYS for q in queries), "query source fields differ")
        require(all(type(d) is dict and set(d) == DEMO_KEYS for d in demos), "demonstration source fields differ")
        projected = [canonical(project_features(r, domain, config, dictionary)[0]) for r in queries + demos]
        require(len(set(projected)) == len(projected), "duplicate projected vector across query/demo pools; resolve under #4")
        cell = {
            "split_id": source["split_id"],
            "queries": [{k: q[k] for k in ("query_id", "label")} for q in queries],
            "demonstrations": [{k: d[k] for k in ("demo_id", "label")} for d in demos],
            "prompt_pairs": [],
        }
        _validate_dataset(cell, plan, include_prompts=False)
        for query in queries:
            for count in plan["demonstration_counts"]:
                a, b = render_pair(domain, query, demos[:count])
                cell["prompt_pairs"].append({"query_id": query["query_id"], "demonstration_count": count, "A": a["prompt_sha256"], "B": b["prompt_sha256"]})
        _validate_dataset(cell, plan)
        frozen[domain] = cell
    execution = digest({"metadata": metadata, "design_version": plan["design_version"], "prompt_freeze": verify_freeze()})
    result = {"schema_version": 1, "design_version": plan["design_version"], "evidence_class": evidence_class, "metadata": metadata, "execution_sha256": execution, "datasets": frozen, "requests": scheduled_requests(frozen, execution, plan)}
    validate_manifest(result)
    return result


def validate_manifest(manifest):
    plan = load_design()
    require(type(manifest) is dict and set(manifest) == MANIFEST_KEYS, "manifest fields differ")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and manifest["design_version"] == plan["design_version"], "manifest version differs")
    require(manifest["evidence_class"] in {"synthetic", "observed"}, "manifest evidence class")
    validate_metadata(manifest["metadata"])
    expected_execution = digest({"metadata": manifest["metadata"], "design_version": plan["design_version"], "prompt_freeze": verify_freeze()})
    require(manifest["execution_sha256"] == expected_execution, "execution metadata changed")
    require(type(manifest["datasets"]) is dict and set(manifest["datasets"]) == set(plan["datasets"]), "manifest dataset matrix differs")
    for cell in manifest["datasets"].values():
        _validate_dataset(cell, plan)
    require(canonical(manifest["requests"]) == canonical(scheduled_requests(manifest["datasets"], expected_execution, plan)), "schedule, query membership/order or prompt hashes differ")
    return plan


def paired_statistics(gold, left, right):
    require(type(gold) is list and type(left) is list and type(right) is list and len(gold) == len(left) == len(right) > 0, "unaligned paired vectors")
    require(all(binary(x) for vector in (gold, left, right) for x in vector), "paired labels must be binary integers")
    transitions = {key: 0 for key in ("00", "01", "10", "11")}
    correctness = {key: 0 for key in ("both_correct", "left_only_correct", "right_only_correct", "both_wrong")}
    for y, a, b in zip(gold, left, right):
        transitions[f"{a}{b}"] += 1
        correctness[("both_correct" if b == y else "left_only_correct") if a == y else ("right_only_correct" if b == y else "both_wrong")] += 1
    n = len(gold)
    flips = transitions["01"] + transitions["10"]
    b, c = correctness["left_only_correct"], correctness["right_only_correct"]
    return {
        "n_paired": n, "transitions": transitions, "correctness": correctness,
        "left_correct": correctness["both_correct"] + b, "right_correct": correctness["both_correct"] + c,
        "accuracy_delta_right_minus_left": (c - b) / n,
        "accuracy_p_raw": exact_half(b, b + c),
        "flips": flips, "flip_rate": flips / n, "flip_rate_wilson95": list(wilson(flips, n)),
        "prediction_change_observed": flips > 0,
        "malicious_rate_delta_right_minus_left": (transitions["01"] - transitions["10"]) / n,
        "directional_p_raw": exact_half(transitions["01"], flips),
    }


def _cell_statistics(gold, predictions):
    tn = sum(y == 0 and p == 0 for y, p in zip(gold, predictions))
    fp = sum(y == 0 and p == 1 for y, p in zip(gold, predictions))
    fn = sum(y == 1 and p == 0 for y, p in zip(gold, predictions))
    tp = sum(y == 1 and p == 1 for y, p in zip(gold, predictions))
    n = len(gold)
    return {"n": n, "valid": n, "completion_rate": 1.0, "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp}, "accuracy": (tn + tp) / n, "accuracy_wilson95": list(wilson(tn + tp, n)), "benign_recall": tn / (tn + fp), "malicious_recall": tp / (fn + tp), "false_positive_rate": fp / (tn + fp), "predicted_benign": tn + fn, "predicted_malicious": fp + tp}


def analyze(manifest, rows, *, registered_manifest_sha256):
    """Reject incomplete/unregistered evidence before computing any inference."""
    require(checksum(registered_manifest_sha256) and digest(manifest) == registered_manifest_sha256, "manifest differs from privately registered digest")
    plan = validate_manifest(manifest)
    require(type(rows) is list and len(rows) == plan["request_budget"], "incomplete or extra responses: inferential analysis rejected")
    expected = {r["request_id"]: r for r in manifest["requests"]}
    seen = set()
    by_cell = {}
    for row in rows:
        require(type(row) is dict and set(row) == set(next(iter(expected.values()))) | ROW_EXTRA, "response fields differ")
        rid = row["request_id"]
        require(type(rid) is str and rid in expected and rid not in seen, "unexpected or duplicate response id")
        seen.add(rid)
        require(canonical({key: row[key] for key in expected[rid]}) == canonical(expected[rid]), "response does not match frozen query, prompt, schedule or serving metadata")
        require(type(row["attempt_count"]) is int and row["attempt_count"] == 1, "retry/attempt count differs from the zero-retry design")
        require(row["status"] == "valid" and binary(row["prediction"]), "failed/unparseable response: inferential analysis rejected; retain diagnostics under #5")
        key = row["dataset"], row["demonstration_count"], row["label_order"]
        by_cell.setdefault(key, {})[row["query_id"]] = row["prediction"]
    label_pairs, count_pairs, cells = [], [], []
    for domain in plan["datasets"]:
        queries = manifest["datasets"][domain]["queries"]
        gold = [q["label"] for q in queries]
        vectors = {}
        for count in plan["demonstration_counts"]:
            for order in plan["label_orders"]:
                vector = [by_cell[domain, count, order][q["query_id"]] for q in queries]
                vectors[count, order] = vector
                cells.append({"dataset": domain, "demonstration_count": count, "label_order": order, **_cell_statistics(gold, vector)})
            label_pairs.append({"dataset": domain, "demonstration_count": count, "left": "A", "right": "B", **paired_statistics(gold, vectors[count, "A"], vectors[count, "B"])})
        for order in plan["label_orders"]:
            for left, right in combinations(plan["demonstration_counts"], 2):
                stats = paired_statistics(gold, vectors[left, order], vectors[right, order])
                count_pairs.append({"dataset": domain, "label_order": order, "left": left, "right": right, **{k: v for k, v in stats.items() if k in {"n_paired", "correctness", "left_correct", "right_correct", "accuracy_delta_right_minus_left", "accuracy_p_raw"}}})
    families = ((label_pairs, "accuracy", plan["accuracy_family"]), (label_pairs, "directional", plan["directional_family"]), (count_pairs, "accuracy", plan["count_accuracy_family"]))
    for comparisons, test, family in families:
        for comparison, adjusted in zip(comparisons, holm([c[f"{test}_p_raw"] for c in comparisons])):
            comparison[f"{test}_family"] = family
            comparison[f"{test}_p_holm"] = adjusted
            comparison[f"{test}_reject_at_alpha"] = adjusted <= plan["alpha"]
    result = {
        "schema_version": 1, "design_version": plan["design_version"],
        "design_issue": 3, "feature_policy": plan["feature_policy"], "template_version": plan["template_version"],
        "model": {key: manifest["metadata"][key] for key in ("model_id", "model_revision", "tokenizer_revision", "code_revision")},
        "evidence_class": manifest["evidence_class"],
        "disclaimer": "SYNTHETIC FIXTURE; no model called" if manifest["evidence_class"] == "synthetic" else "Observed paired evidence; one serving session and one demonstration selection; no deployment claim",
        "request_count": len(rows), "distinct_query_count": len(plan["datasets"]) * plan["queries_per_dataset"],
        "alpha": plan["alpha"], "multiplicity_policy": plan["correction"],
        "interpretation": "Report observed flips separately. Nonsignificant accuracy or directional tests do not establish invariance/equivalence. Separate Holm families do not control a combined family across all claims.",
        "cells": cells, "label_order_comparisons": label_pairs, "count_accuracy_comparisons": count_pairs,
    }

    serialized = canonical(result)
    require(all(re.search(pattern, serialized) is None for pattern in RULES.values()), "public aggregate metadata matches a disclosure rule")
    return result
