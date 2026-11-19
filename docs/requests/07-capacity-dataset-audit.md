# Inventory FeSAD datasets and freeze maximum non-label feature policies

Issue: [#8](https://github.com/dsikar/fesa-llm-experiments/issues/8).

Use [docs/CAPACITY_RESULTS.md](../CAPACITY_RESULTS.md) as the output contract. Local copies and a checksum inventory are already held in ignored private storage; third-party records must not enter the public tree.

- [ ] Inventory all ten top-level ARFF files (Git Evo, Mendeley Evo, Kaggle Evo/Gen/ModBaseSet train/test pairs) and the deduplicated Hussain CSV. Preserve originals, checksums, row counts, source split membership, acquisition and provenance/terms. Generated year/family malware partitions are derivatives, not independent datasets; catalogue separately if needed.
- [ ] Verify task/domain and label polarity per source: FeSAD registers the ARFF pairs as phishing. Do not infer ransomware from the directory or source nickname.
- [ ] Assert the Hussain tail is exactly Class, Category, Family; retain these privately as targets/grouping metadata and exclude ALL THREE from every prompt, feature description, transform and token count input. Reject target aliases, reordered/unexpected schemas and query-target leakage. Binary target: Benign/Malware, not ransomware-only.
- [ ] Start from maximum non-label inputs: Git 45, Mendeley 26, Kaggle Evo 20, Gen 16, ModBaseSet 48, Hussain 74. These are local-file maxima, not proof of upstream full dimensionality. Record all attribute names and exact encoding/missing-value policies.
- [ ] Audit identifiers (including hashes), possible security-verdict proxies and target-derived columns. Report each exclusion and distinguish raw maximum, diagnostic identity/verdict-containing arms and maximum audited input count. Never silently inherit the 8/12 primary-v1 subset or call label-only removal proof against leakage.
- [ ] Add versioned full-feature renderers/adapters with verified numeric/categorical/hex handling and schema tests; retain the frozen primary-v1 unchanged. Test query label non-disclosure and all three Hussain labels even when nested/renamed in input mappings.
- [ ] Record relationship/overlap among Kaggle variants; locate earlier dimensionality-reduction evidence without assuming disjointness or nesting.

Acceptance: reproducible inventory, public aggregate dataset table, private provenance/checksums, verified target mappings, complete versioned inclusion/exclusion lists, synthetic leakage tests and compatible rendering of every retained source row. Unresolved provenance or encodings are explicit blockers, not guessed definitions. No model calls.

Dependencies: output contract; #1, #4 and #5. Supplies the collision study and maximum-attribute run.


## Related tickets

- [#7 — Define the attribute-count results table and JSON evidence contract](https://github.com/dsikar/fesa-llm-experiments/issues/7)
- [#8 — Inventory FeSAD datasets and freeze maximum non-label feature policies](https://github.com/dsikar/fesa-llm-experiments/issues/8)
- [#9 — Measure feature-reduction duplicates, conflicting labels and empirical ceilings](https://github.com/dsikar/fesa-llm-experiments/issues/9)
- [#10 — Run paired maximum-attribute classification and publish feature-count metrics](https://github.com/dsikar/fesa-llm-experiments/issues/10)
