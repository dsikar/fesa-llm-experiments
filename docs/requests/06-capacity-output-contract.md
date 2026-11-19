# Define the attribute-count results table and JSON evidence contract

Issue: [#7](https://github.com/dsikar/fesa-llm-experiments/issues/7).

Make the target output concrete before collecting any more data. Implement the contract in [docs/CAPACITY_RESULTS.md](../CAPACITY_RESULTS.md), with the [planning inventory](../../results/public/capacity-plan.json) clearly distinguished from observed results.

- [ ] Implement a versioned aggregate JSON schema, private condition/prediction schema, validator and deterministic Markdown table renderer.
- [ ] Include dataset type AND dataset/variant/version, actual input count and raw maximum, feature names/policy, split, model revision, demonstration count, A/B order, replicate and complete denominators.
- [ ] Capture confusion counts, accuracy/Wilson interval, balanced accuracy, per-class recall, malicious precision/F1, FPR, completion, token/context/failure metrics and duplicate/conflict counts/ceiling. Record null and reason for undefined/unavailable quantities.
- [ ] Save reviewed machine-readable results at `results/public/capacity-results.json`; complete private evidence at `private/capacity/runs/<run_id>/`. Extend #5 rather than making a competing run store.
- [ ] Account for every planned cell/query, including failed/blocked/context-overflow cells. Validate denominators and reject incomplete paired inference.
- [ ] Add synthetic end-to-end validation of successful, incomplete, undefined-metric and failed conditions; recompute table metrics from counts; use an allowlist exporter and prevent private disclosure.

Acceptance: a synthetic run generates the requested dataset type / attribute count / metrics table from validated JSON, with no manual edits. JSON, report, code and design revisions are linked. Freeze the contract before any new feature-count run. No inference in this ticket.

Dependencies: coordinate #5. Enables the dataset audit, collision study and maximum-attribute experiment.


## Related tickets

- [#7 — Define the attribute-count results table and JSON evidence contract](https://github.com/dsikar/fesa-llm-experiments/issues/7)
- [#8 — Inventory FeSAD datasets and freeze maximum non-label feature policies](https://github.com/dsikar/fesa-llm-experiments/issues/8)
- [#9 — Measure feature-reduction duplicates, conflicting labels and empirical ceilings](https://github.com/dsikar/fesa-llm-experiments/issues/9)
- [#10 — Run paired maximum-attribute classification and publish feature-count metrics](https://github.com/dsikar/fesa-llm-experiments/issues/10)
