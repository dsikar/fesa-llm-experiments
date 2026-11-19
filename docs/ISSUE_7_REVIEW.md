# Issue #7 independent review

Verdict: no blocking findings remain in this reviewed implementation. Ready for integration; issue #7 remains open and unmerged. No real model calls or classification results were produced.

Grok's original commit was `ba8c782`. The second Codex session reconciled main and fixed the five findings in `3e3e85b`. Independent rechecking rejected the previously accepted bad cases and accepted the corrected schema instances. A follow-up on the review branch also fixes publication of runs blocked before any request was sent.

| Finding | Independent verification |
|---|---|
| Results overwrote the frozen query plan | A 200-query plan with eight results is rejected; dropped rows and balanced subsets cannot become complete; replacement identities/labels are rejected |
| Export accepted unrelated private evidence | Wrong run ids, orphan conditions, changed demonstration order/settings, absent evidence and inconsistent request totals are rejected |
| Schema rejected its own planned fixture | Independent Draft 2020-12 validation passes aggregate, private condition/prediction, planning and run-header examples; invalid cases are rejected |
| Private running state was unreachable | Valid fresh/partial running snapshots pass privately; running conditions remain invalid public results |
| Conflict bounds allowed impossible ceilings | Impossible binary minority counts fail; evidence-backed export recomputes summaries/ceilings from private group counts |
| Additional review: all-blocked runs were unpublishable | Zero-request observed preflight failures can be exported with zero completion; all-planned inventories cannot masquerade as observed results; aggregate request totals reconcile |

## Checks

- All **60 offline tests pass**, including 18 review regressions.
- Historical aggregate arithmetic and generated baseline report pass.
- The primary-v1 prompt freeze passes and its files are unchanged.
- Public-tree disclosure and whitespace checks pass for the reviewed files.
- An independent synthetic recheck exercises both mixed-result and zero-request observed export paths in memory. It publishes no observed artifact.

The original 42 tests were insufficient; retain the new regression and independent schema checks in CI. Test dependencies are pinned in `requirements-test.txt`. Runtime prompt tools remain model-free and the original baseline remains intact.

Pairing, dataset provenance, grouping correctness, immutable registration and actual serving evidence still require #4/#5/#8/#9 as applicable. An internally consistent aggregate is not proof that its source evidence is true. Real results at `results/public/capacity-results.json` have not been created. The independent #3 implementation is a separate PR.
