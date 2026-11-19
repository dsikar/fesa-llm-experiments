# Run paired maximum-attribute classification and publish feature-count metrics

Issue: [#10](https://github.com/dsikar/fesa-llm-experiments/issues/10).

Measure classification performance versus available input information for the current Qwen model. Use the front-loaded table and JSON contract in [docs/CAPACITY_RESULTS.md](../CAPACITY_RESULTS.md). This is an extension to #2, with a separately frozen matrix; do not retrospectively alter the primary-v1 experiment or pilot.

- [ ] Cover Git/Mendeley/Kaggle Evo/Gen/ModBaseSet phishing and deduplicated Hussain malware, subject to verified provenance/labels/sufficient independent rows. Start with the maximum non-label feature set, document audited exclusions and report actual supplied counts.
- [ ] Use the audited label-safe policies, excluding Class from ARFF inputs and Class/Category/Family from Hussain. Separate any identity/verdict diagnostic result from audited generalization results.
- [ ] Compare maximum versus applicable conservative and preregistered nested feature subsets on the same frozen held-out queries. Select subsets using development data only. Cross-source Kaggle variants alone are not paired feature-count evidence.
- [ ] Freeze 0/4/10 balanced demonstrations, A/B label orders, query/demo memberships, seeds, replicates, model/tokenizer revision, decoding, execution schedule, paired tests/multiplicity family and total request budget. Disclose infeasible cells; no performance-guided query selection.
- [ ] Preflight exact full prompts with the actual tokenizer and serving context/output budget. Save token counts and overflow diagnostics. No silent truncation, attribute dropping or cross-session retries.
- [ ] Capture exact prompts, target labels, predictions, raw responses, failures, timing/context information and immutable evidence through #5. Include duplicate/conflict strata and audited population ceilings in the aggregate report.
- [ ] Generate dataset type / dataset variant / attribute count / metrics tables from validated JSON. Report confusion matrices, uncertainty, precision/recall/F1, balanced accuracy, FPR, completion, paired feature/count/order effects and all planned failures/null results.
- [ ] Interpret results as performance versus supplied attributes/context under this design; distinguish representation-induced ambiguity from model error and avoid claims about intrinsic parameter capacity.

Acceptance: the frozen matrix is fully accounted for, private row evidence validates pairing/completeness, reviewed public JSON regenerates the report, and all deviations/failures are visible. Execution begins only after prerequisites and the final request budget/design are frozen. The illustrative six-variant maximum-only 0/4/10 × A/B × 200-query matrix is 7,200 requests before extra policies/replicates; it is not yet a run commitment.

Dependencies: output contract, maximum-feature dataset audit and collision study, plus #2–#5 readiness. No model execution is part of creating this planning ticket.


## Related tickets

- [#7 — Define the attribute-count results table and JSON evidence contract](https://github.com/dsikar/fesa-llm-experiments/issues/7)
- [#8 — Inventory FeSAD datasets and freeze maximum non-label feature policies](https://github.com/dsikar/fesa-llm-experiments/issues/8)
- [#9 — Measure feature-reduction duplicates, conflicting labels and empirical ceilings](https://github.com/dsikar/fesa-llm-experiments/issues/9)
- [#10 — Run paired maximum-attribute classification and publish feature-count metrics](https://github.com/dsikar/fesa-llm-experiments/issues/10)
