# Pilot v2 results

Date: 2026-11-19. Model: `QuantTrio/Qwen3-235B-A22B-Instruct-2507-AWQ`.

Two datasets × 100 query rows × four conditions = **800 responses from 200 distinct query rows**. Each dataset contains 50 benign and 50 malicious rows. Historical v1 references add 400 earlier responses and are not included in the 800.

| Dataset | Zero A | Zero B | Balanced four-shot A | Balanced four-shot B |
|---|---:|---:|---:|---:|
| phishing | 50% | 50% | 50% | 50% |
| ransomware | 50% | 50% | 75% | 66% |

A lists malicious first; B lists benign first. Four-shot means two labelled benign and two labelled malicious demonstrations before one unlabelled query.

| Dataset / condition | Benign correct | Malicious correct | Total correct | Wilson 95% accuracy interval |
|---|---:|---:|---:|---|
| phishing / c1_zero_a | 0/50 | 50/50 | 50/100 | 40.4–59.6% |
| phishing / c2_zero_b | 0/50 | 50/50 | 50/100 | 40.4–59.6% |
| phishing / c3_few_bal_a | 0/50 | 50/50 | 50/100 | 40.4–59.6% |
| phishing / c4_few_bal_b | 0/50 | 50/50 | 50/100 | 40.4–59.6% |
| ransomware / c1_zero_a | 0/50 | 50/50 | 50/100 | 40.4–59.6% |
| ransomware / c2_zero_b | 0/50 | 50/50 | 50/100 | 40.4–59.6% |
| ransomware / c3_few_bal_a | 25/50 | 50/50 | 75/100 | 65.7–82.5% |
| ransomware / c4_few_bal_b | 16/50 | 50/50 | 66/100 | 56.3–74.5% |

## Interpretation

- Every phishing condition predicted malicious for all 100 rows. Its 50% accuracy is the always-malicious baseline, not evidence of discrimination.
- Ransomware zero-shot also predicted malicious for every row. Four demonstrations reduced false positives: benign recall became 50% in A and 32% in B; malicious recall remained 100% on this sample.
- Ransomware four-shot A and B meet the original same-order accuracy criteria against zero-shot (paired McNemar Holm p = 2.980232e-7 and 0.0001220703).
- The ransomware label-order comparison changed nine predictions from benign to malicious, all losing accuracy. Accuracy-test Holm p = 0.01171875; secondary directional-label-shift Holm p = 0.0078125.
- Balanced four-shot A scored 75%, compared with 76% for the historical unbalanced v1 few-shot arm; paired Holm p = 1.0. Balancing corrected the design without demonstrating a performance improvement.
- No C1-versus-historical-zero prediction flips were observed. This does not establish general determinism.

## Limits

One model, 100 balanced rows per dataset, fixed cell sequence and no repeated conditions. The malware prompt retained website/phishing wording for historical comparability. Feature leakage and prediction-time availability remain unaudited. Instruction-order sensitivity cannot be cleanly separated from time/batch effects in this design. These are exploratory method findings, not deployment or natural-prevalence claims. No final-layer embeddings were collected in these classification runs.

## Audit trail

A pre-run code audit identified incomplete-result handling, missing-response bias, prediction-reversal detection and row-pairing validation problems. Fixes and an analysis amendment preceded the run. The original 50 checks and 16 added audit tests passed in the private workspace and cluster environment. Qwen subsequently reviewed the work and independently recomputed the private row-based results. This is AI-assisted verification, not external peer review.

Public arithmetic is reproducible with `python3 scripts/verify_baseline.py`. Private records, prompts, row-level responses, identities, infrastructure metadata and original logs are not redistributed. The public checker verifies aggregate consistency; the pairing itself was checked against private artifacts.

[Aggregate JSON](../results/public/pilot-v2.json) · [Next experiment](EXPERIMENT_PLAN.md) · [History](HISTORY.md)
