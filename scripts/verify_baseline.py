#!/usr/bin/env python3
"""Verify public aggregate arithmetic. No private files or network required."""
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONDITIONS = ("c1_zero_a", "c2_zero_b", "c3_few_bal_a", "c4_few_bal_b")
REFERENCES = ("v1_zero", "v1_few")
PAIRS = ((CONDITIONS[0], CONDITIONS[1]), (CONDITIONS[2], CONDITIONS[3]),
         (CONDITIONS[0], CONDITIONS[2]), (CONDITIONS[1], CONDITIONS[3]),
         ("v1_few", CONDITIONS[2]))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def close(actual, expected):
    require(math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-12),
            f"arithmetic mismatch: {actual} != {expected}")


def exact_half(k, n):
    if n == 0:
        return 1.0
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(min(k, n-k)+1)) / 2**n)


def holm(values):
    result = [0.0] * len(values)
    previous = 0.0
    for rank, i in enumerate(sorted(range(len(values)), key=values.__getitem__)):
        previous = max(previous, (len(values)-rank)*values[i])
        result[i] = min(1.0, previous)
    return result


def wilson(k, n):
    z = 1.959963984540054
    center = (k/n + z*z/(2*n))/(1+z*z/n)
    half = z*math.sqrt((k/n)*(1-k/n)/n+z*z/(4*n*n))/(1+z*z/n)
    return max(0.0, center-half), min(1.0, center+half)


def verify(value):
    require(set(value) == {"schema_version", "experiment", "date", "model", "v2_response_count",
                          "v2_distinct_query_count", "historical_reference_response_count", "datasets"},
            "unexpected public top-level fields")
    require(value["schema_version"] == 1 and value["experiment"] == "pilot-v2", "wrong experiment")
    require(value["date"] == "2026-11-19", "wrong pilot date")
    require(value["model"] == "QuantTrio/Qwen3-235B-A22B-Instruct-2507-AWQ", "wrong public model ID")
    require(set(value["datasets"]) == {"phishing", "ransomware"}, "unexpected datasets")
    responses = references = distinct = 0
    for dataset, data in value["datasets"].items():
        require(set(data) == {"query_class_counts", "conditions", "historical_references",
                              "paired_accuracy_tests", "label_order_predictions", "historical_zero_prediction_flips"},
                f"unexpected fields for {dataset}")
        require(data["query_class_counts"] == {"benign": 50, "malicious": 50}, "wrong class counts")
        distinct += sum(data["query_class_counts"].values())
        require(set(data["conditions"]) == set(CONDITIONS), "missing conditions")
        require(set(data["historical_references"]) == set(REFERENCES), "missing historical references")
        cells = dict(data["conditions"], **data["historical_references"])
        for name, stats in cells.items():
            require(set(stats) == {"complete", "n", "scored", "correct", "accuracy", "wilson95",
                                   "binom_p_vs_0.5", "pred_counts", "degenerate", "per_class_recall",
                                   "errors", "unparseable", "confusion_matrix"}, "unexpected cell fields")
            matrix = stats["confusion_matrix"]
            require(set(matrix) == {"tn", "fp", "fn", "tp"}, "invalid confusion matrix")
            require(all(type(x) is int and x >= 0 for x in matrix.values()), "invalid confusion counts")
            tn, fp, fn, tp = [matrix[k] for k in ("tn", "fp", "fn", "tp")]
            require(tn+fp == fn+tp == 50, "confusion matrix has wrong class totals")
            require(stats["complete"] is True and stats["n"] == stats["scored"] == 100
                    and stats["errors"] == stats["unparseable"] == 0, "incomplete pilot cell")
            require(stats["correct"] == tn+tp, "wrong correct count")
            require(stats["pred_counts"] == {"0": tn+fn, "1": fp+tp}, "wrong prediction counts")
            require(stats["degenerate"] == (max(tn+fn, fp+tp) >= 95), "wrong degeneracy flag")
            close(stats["accuracy"], (tn+tp)/100)
            require(set(stats["per_class_recall"]) == {"0", "1"}, "wrong recall labels")
            close(stats["per_class_recall"]["0"], tn/50)
            close(stats["per_class_recall"]["1"], tp/50)
            require(len(stats["wilson95"]) == 2, "wrong interval")
            for a, b in zip(stats["wilson95"], wilson(tn+tp, 100)):
                close(a, b)
            close(stats["binom_p_vs_0.5"], exact_half(tn+tp, 100))
            if name in CONDITIONS:
                responses += 100
            else:
                references += 100
        paired = data["paired_accuracy_tests"]
        require(set(paired) == {f"{a}__vs__{b}" for a, b in PAIRS}, "wrong paired-test family")
        for a, b in PAIRS:
            test = paired[f"{a}__vs__{b}"]
            require(set(test) == {"b", "c", "p_raw", "p_holm"}, "unexpected paired-test fields")
            require(type(test["b"]) is int and type(test["c"]) is int
                    and 0 <= test["b"]+test["c"] <= 100 and min(test["b"], test["c"]) >= 0,
                    "invalid paired discordance counts")
            require(test["b"]-test["c"] == cells[a]["correct"]-cells[b]["correct"], "paired count inconsistency")
            close(test["p_raw"], exact_half(test["b"], test["b"]+test["c"]))
        for test, adjusted in zip(paired.values(), holm([t["p_raw"] for t in paired.values()])):
            close(test["p_holm"], adjusted)
        changes = data["label_order_predictions"]
        require(set(changes) == {"zero", "few"}, "wrong transition family")
        for mode, a, b in (("zero", CONDITIONS[0], CONDITIONS[1]), ("few", CONDITIONS[2], CONDITIONS[3])):
            change = changes[mode]
            require(set(change) == {"n_paired", "transitions", "flips", "flip_rate", "prediction_change_observed",
                                    "malicious_rate_delta_b_minus_a", "directional_p_raw", "directional_p_holm",
                                    "directional_label_shift_detected"}, "unexpected transition fields")
            t = change["transitions"]
            require(set(t) == {"00", "01", "10", "11"} and all(type(x) is int and x >= 0 for x in t.values()), "invalid transitions")
            require(sum(t.values()) == change["n_paired"] == 100, "wrong transition total")
            require(t["00"]+t["01"] == cells[a]["pred_counts"]["0"] and
                    t["00"]+t["10"] == cells[b]["pred_counts"]["0"], "transition margins disagree")
            require(change["flips"] == t["01"]+t["10"], "wrong flip count")
            close(change["flip_rate"], change["flips"]/100)
            require(change["prediction_change_observed"] == (change["flips"] > 0), "wrong sensitivity flag")
            close(change["malicious_rate_delta_b_minus_a"], (t["01"]-t["10"])/100)
            close(change["directional_p_raw"], exact_half(t["01"], change["flips"]))
        for change, adjusted in zip(changes.values(), holm([t["directional_p_raw"] for t in changes.values()])):
            close(change["directional_p_holm"], adjusted)
            require(change["directional_label_shift_detected"] == (adjusted < 0.05), "wrong shift flag")
        flips = data["historical_zero_prediction_flips"]
        require(set(flips) == {"n_paired", "flips", "rate"} and flips["n_paired"] == 100
                and type(flips["flips"]) is int and 0 <= flips["flips"] <= 100, "invalid historical flips")
        close(flips["rate"], flips["flips"]/100)
    require(responses == value["v2_response_count"] == 800, "wrong response count")
    require(distinct == value["v2_distinct_query_count"] == 200, "wrong distinct-query count")
    require(references == value["historical_reference_response_count"] == 400, "wrong historical count")


if __name__ == "__main__":
    verify(json.loads((ROOT / "results/public/pilot-v2.json").read_text()))
    print("Verified public aggregate arithmetic: 8 conditions, 800 responses, 200 distinct query rows.")
