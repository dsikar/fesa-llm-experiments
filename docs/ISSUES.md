# Experiment issues

Milestone: [v3: prompt and demonstration-count experiment](https://github.com/dsikar/fesa-llm-experiments/milestone/1).

| Step | Issue | Specification |
|---|---|---|
| 1 | [#1 — Use domain-correct prompts and documented feature definitions](https://github.com/dsikar/fesa-llm-experiments/issues/1) | [Versioned request](requests/01-domain-prompts.md) |
| 2 | [#2 — Compare 0, 4 and 10 balanced demonstrations](https://github.com/dsikar/fesa-llm-experiments/issues/2) | [Versioned request](requests/02-demonstration-count.md) |
| 3 | [#3 — Counterbalance instruction label order and report prediction transitions](https://github.com/dsikar/fesa-llm-experiments/issues/3) | [Versioned request](requests/03-label-order.md) |
| 4 | [#4 — Freeze fresh held-out queries and a disjoint demonstration pool](https://github.com/dsikar/fesa-llm-experiments/issues/4) | [Versioned request](requests/04-held-out-data.md) |
| 5 | [#5 — Save immutable experiment evidence and publish reviewed aggregates](https://github.com/dsikar/fesa-llm-experiments/issues/5) | [Versioned request](requests/05-artifact-trail.md) |

Step 2 requires steps 1, 3, 4 and 5 before model requests. Steps 1, 3 and 4 can be prepared alongside the evidence infrastructure in step 5. Changes to the experimental design must be recorded before collection.

The issues describe planned work. The completed pilot is documented separately in [PILOT_V2.md](PILOT_V2.md).

## Attribute-count extension

Front-loaded [target table and JSON contract](CAPACITY_RESULTS.md); [machine-readable planned arms](../results/public/capacity-plan.json). The #7 schema, validator, renderer and synthetic tests are implemented. Issue #7 stays open for review. No new model requests. GitHub #6 was already used by the merged prompt PR, so these tickets start at #7.

| Issue | Specification | Depends on |
|---|---|---|
| [#7 — Define the attribute-count results table and JSON evidence contract](https://github.com/dsikar/fesa-llm-experiments/issues/7) | [Versioned request](requests/06-capacity-output-contract.md) | #5 coordination |
| [#8 — Inventory FeSAD datasets and freeze maximum non-label feature policies](https://github.com/dsikar/fesa-llm-experiments/issues/8) | [Versioned request](requests/07-capacity-dataset-audit.md) | #7; #1/#4/#5 coordination |
| [#9 — Measure feature-reduction duplicates, conflicting labels and empirical ceilings](https://github.com/dsikar/fesa-llm-experiments/issues/9) | [Versioned request](requests/08-capacity-collisions.md) | #7/#8; #4/#5 coordination |
| [#10 — Run paired maximum-attribute classification and publish feature-count metrics](https://github.com/dsikar/fesa-llm-experiments/issues/10) | [Versioned request](requests/09-capacity-experiment.md) | #7–#9 and #2–#5 readiness |

## Coding-agent benchmark

[#11 — Benchmark coding agents across providers for correctness, speed, cost and supervision](https://github.com/dsikar/fesa-llm-experiments/issues/11): [versioned design and target output](requests/10-agent-benchmark.md). Covers Anthropic, Google, DeepSeek, Alibaba/Qwen and Mistral, with Grok/Codex reference configurations. Separate from the classification experiments; no trials have run. Coordinates evidence conventions with #5/#7 and leaves Grok’s active #7 implementation in place.
