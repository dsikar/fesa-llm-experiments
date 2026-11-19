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
