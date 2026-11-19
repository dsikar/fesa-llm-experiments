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
