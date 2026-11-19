# Experiment history

| Date | Event | Evidence |
|---|---|---|
| 2026-11-19 | Pilot v2 audited before execution; incomplete-result handling, pairing validation and label-order analysis needed fixes | [Audit summary](PILOT_V2.md#audit-trail) |
| 2026-11-19 | Fixes tested; analysis amendment frozen before collection | 50 regression checks and 16 audit tests passed in the private workspace and cluster environment |
| 2026-11-19 | Eight pilot conditions completed, 800 responses, no request or parsing failures | [Aggregate results](../results/public/pilot-v2.json) |
| 2026-11-19 | Qwen review accepted the fixes and independently recomputed the private row-based analysis | [Review scope](PILOT_V2.md#audit-trail) |
| 2026-11-19 | Public repository prepared; next experiment split into five issues | [Issue index](ISSUES.md) |
| 2026-11-19 | Issue 1: domain prompts and conservative feature policy implemented; 28 offline tests pass | [Delivery and limits](ISSUE_1_DELIVERY.md) |
| 2026-11-19 | Attribute-count extension planned in issues #7–#10; six dataset variants inventoried, private copies preserved, table/JSON contract specified; zero new requests | [Output contract](CAPACITY_RESULTS.md) |
| 2026-11-19 | Cross-provider coding-agent benchmark specified in #11, covering accepted work, elapsed time, cost and supervision; no benchmark trials run | [Benchmark design](requests/10-agent-benchmark.md) |
| 2026-11-19 | Issue #3 pre-run design/tools implemented: counterbalanced A/B blocks, fixed exact-test families, strict private registration and synthetic reversal checks; zero new requests | [Design and limits](LABEL_ORDER.md) |

Original raw evidence remains in the private experiment workspace. These historical results precede this repository's initial commit. The Git history records the public export and subsequent work; it is not a retrospective preregistration of the pilot.

The [pilot-v2-public-baseline tag](https://github.com/dsikar/fesa-llm-experiments/tree/pilot-v2-public-baseline) fixes the initial public export. Future implementations should reference their issue in commits and link the frozen design, reviewed aggregate results and analysis revision in the issue before closure.
