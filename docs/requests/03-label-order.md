# Counterbalance instruction label order and report prediction transitions

## Problem

In the previous ransomware pilot, the two instruction label orders scored 75% and 66%. Accuracy alone can miss a complete reversal of binary predictions.

## Work

- [ ] Provide A (malicious first) and B (benign first) templates differing only in the label clause.
- [ ] Keep demonstration order fixed within each count; distinguish instruction order from demonstration order.
- [ ] Pair the exact same held-out queries across A and B.
- [ ] Save full 00/01/10/11 prediction-transition counts and flip rates separately from paired correctness.
- [ ] Predeclare accuracy and directional-shift tests with their correction families.
- [ ] Counterbalance/randomize execution blocks or predeclare repetitions to assess time/batch effects; freeze the request budget.
- [ ] Test synthetic all-1 vs all-0 predictions and symmetric flips; nonsignificant accuracy must not be reported as invariance.

## Acceptance

Synthetic tests pass; every demonstration-count condition reports accuracy effects, directional effects and observed flips separately. Report fixed-order/time limitations where replication is absent.

## Dependencies

Coordinate with steps 1, 2 and 5 before collection.

## Implementation delivery

The pre-collection implementation is available in [LABEL_ORDER.md](../LABEL_ORDER.md), the additive `label-order-v1` configuration/freeze and the offline scheduling/analysis tools. It fixes 20-query counterbalanced A/B blocks, the 2,400-request primary matrix with no retries, exact paired tests and separate Holm families. It rejects incomplete or mismatched private registrations/evidence and reports full prediction transitions separately from correctness.

Synthetic verification: 39 tests pass across the repository, including the new complete-reversal, symmetric-flip, fixed-family, schedule and evidence-integrity checks. Historical pilot aggregates/reports and the primary-v1 freeze remain unchanged. No model requests were made.

This supplies the prospective implementation/design gate for review. Actual condition reports remain pending #2 collection after #4/#5 readiness; issue #3 stays open until that reporting acceptance is met. The implementation does not depend on Grok's unmerged #7 branch.
