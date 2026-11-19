#!/usr/bin/env python3
"""Render the public pilot discussion from the checked aggregate JSON."""
import argparse
import json
from pathlib import Path

from verify_baseline import CONDITIONS, verify

ROOT = Path(__file__).resolve().parent.parent


def render(value):
    verify(value)
    lines = ["# Pilot v2 results", "", "Date: 2026-11-19. Model: `"+value["model"]+"`.", "",
             "Two datasets × 100 query rows × four conditions = **800 responses from 200 distinct query rows**. Each dataset contains 50 benign and 50 malicious rows. Historical v1 references add 400 earlier responses and are not included in the 800.", "",
             "| Dataset | Zero A | Zero B | Balanced four-shot A | Balanced four-shot B |",
             "|---|---:|---:|---:|---:|"]
    for name, data in value["datasets"].items():
        lines.append("| "+name+" | "+" | ".join(f"{100*data['conditions'][c]['accuracy']:.0f}%" for c in CONDITIONS)+" |")
    lines += ["", "A lists malicious first; B lists benign first. Four-shot means two labelled benign and two labelled malicious demonstrations before one unlabelled query.", "",
              "| Dataset / condition | Benign correct | Malicious correct | Total correct | Wilson 95% accuracy interval |",
              "|---|---:|---:|---:|---|"]
    for name, data in value["datasets"].items():
        for condition, stats in data["conditions"].items():
            m, ci = stats["confusion_matrix"], stats["wilson95"]
            lines.append(f"| {name} / {condition} | {m['tn']}/50 | {m['tp']}/50 | {stats['correct']}/100 | {100*ci[0]:.1f}–{100*ci[1]:.1f}% |")
    lines += ["", "## Interpretation", "",
              "- Every phishing condition predicted malicious for all 100 rows. Its 50% accuracy is the always-malicious baseline, not evidence of discrimination.",
              "- Ransomware zero-shot also predicted malicious for every row. Four demonstrations reduced false positives: benign recall became 50% in A and 32% in B; malicious recall remained 100% on this sample.",
              "- Ransomware four-shot A and B meet the original same-order accuracy criteria against zero-shot (paired McNemar Holm p = 2.980232e-7 and 0.0001220703).",
              "- The ransomware label-order comparison changed nine predictions from benign to malicious, all losing accuracy. Accuracy-test Holm p = 0.01171875; secondary directional-label-shift Holm p = 0.0078125.",
              "- Balanced four-shot A scored 75%, compared with 76% for the historical unbalanced v1 few-shot arm; paired Holm p = 1.0. Balancing corrected the design without demonstrating a performance improvement.",
              "- No C1-versus-historical-zero prediction flips were observed. This does not establish general determinism.", "",
              "## Limits", "",
              "One model, 100 balanced rows per dataset, fixed cell sequence and no repeated conditions. The malware prompt retained website/phishing wording for historical comparability. Feature leakage and prediction-time availability remain unaudited. Instruction-order sensitivity cannot be cleanly separated from time/batch effects in this design. These are exploratory method findings, not deployment or natural-prevalence claims. No final-layer embeddings were collected in these classification runs.", "",
              "## Audit trail", "",
              "A pre-run code audit identified incomplete-result handling, missing-response bias, prediction-reversal detection and row-pairing validation problems. Fixes and an analysis amendment preceded the run. The original 50 checks and 16 added audit tests passed in the private workspace and cluster environment. Qwen subsequently reviewed the work and independently recomputed the private row-based results. This is AI-assisted verification, not external peer review.", "",
              "Public arithmetic is reproducible with `python3 scripts/verify_baseline.py`. Private records, prompts, row-level responses, identities, infrastructure metadata and original logs are not redistributed. The public checker verifies aggregate consistency; the pairing itself was checked against private artifacts.", "",
              "[Aggregate JSON](../results/public/pilot-v2.json) · [Next experiment](EXPERIMENT_PLAN.md) · [History](HISTORY.md)", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render(json.loads((ROOT / "results/public/pilot-v2.json").read_text()))
    target = ROOT / "docs/PILOT_V2.md"
    if args.check:
        if not target.is_file() or target.read_text() != expected:
            raise SystemExit("Baseline report differs from the generated aggregate report")
        print("Baseline report matches the aggregate JSON.")
    else:
        target.write_text(expected)
