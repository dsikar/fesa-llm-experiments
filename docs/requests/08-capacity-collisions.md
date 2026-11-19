# Measure feature-reduction duplicates, conflicting labels and empirical ceilings

Issue: [#9](https://github.com/dsikar/fesa-llm-experiments/issues/9).

Determine how much label information is lost when attributes are removed, before attributing classification failures to the model. Follow [docs/CAPACITY_RESULTS.md](../CAPACITY_RESULTS.md).

- [ ] Audit all six dataset variants at maximum non-label attributes, maximum audited attributes, applicable 8/12 primary-v1 projections and preregistered nested smaller subsets. Locate and link earlier reduction-test artifacts; if incompatible, state that rather than claiming reproduction.
- [ ] Audit raw and exact model-visible vectors after canonicalization/encoding/precision/missing-value transformations. Record exact feature-set identities and ordered attributes, not count alone. Approximate matching is a separate analysis.
- [ ] Count rows, unique vectors, duplicate groups, excess duplicates, rows in duplicate groups, conflicting 0/1 groups and rows in conflicting groups; preserve per-group label counts and memberships privately.
- [ ] Compute unavoidable errors = sum(min(n_g0,n_g1)) and empirical deterministic accuracy ceiling = 1 - unavoidable_errors/N. Specify source/split/query population and distinguish it from a general capacity bound.
- [ ] Check within/across source splits and related variants, query/demo pools and earlier pilot evidence. Do not mistake renamed files or hashes in a feature vector for genuine information-preserving deduplication.
- [ ] Preregister how conflicts are retained/quarantined and how duplicate groups govern split assignment. No silent label repair, majority voting or deletion. Report raw and any filtered population separately.
- [ ] For paired feature-count arms, keep the same query rows and enforce group disjointness under every compared projection. Report insufficient independent groups/class counts instead of relaxing the split silently.
- [ ] Save searchable private JSON group evidence and reviewed aggregate JSON/table; implement meaningful synthetic tests for identical same-label rows, contradictory rows, projection-induced collisions, encoding collisions and train/test leakage.

Acceptance: reproducible audit and comparison table across datasets/feature sets, with conflict/duplicate definitions, empirical ceilings, private evidence references and a freezeable split/conflict policy. No model calls or claims that low-dimensional collisions alone measure model capacity.

Dependencies: dataset/feature audit and output contract; coordinates #4/#5. Required before maximum-attribute inference.


## Related tickets

- [#7 — Define the attribute-count results table and JSON evidence contract](https://github.com/dsikar/fesa-llm-experiments/issues/7)
- [#8 — Inventory FeSAD datasets and freeze maximum non-label feature policies](https://github.com/dsikar/fesa-llm-experiments/issues/8)
- [#9 — Measure feature-reduction duplicates, conflicting labels and empirical ceilings](https://github.com/dsikar/fesa-llm-experiments/issues/9)
- [#10 — Run paired maximum-attribute classification and publish feature-count metrics](https://github.com/dsikar/fesa-llm-experiments/issues/10)
