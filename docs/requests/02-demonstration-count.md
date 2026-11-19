# Compare 0, 4 and 10 balanced demonstrations

## Question

Does demonstration count improve classification when prompt, feature set, model, query rows and decoding are fixed?

## Work

- [ ] Implement 0, 4 (2+2) and 10 (5+5) labelled demonstrations per query.
- [ ] Select examples deterministically from a separate frozen pool; nest the four within the ten and save identities/order privately.
- [ ] Keep both label orders and the same held-out rows in every paired condition.
- [ ] Freeze selection seeds, replication policy, execution schedule and total request budget before running.
- [ ] Register paired comparisons (0 vs 4, 0 vs 10, 4 vs 10) and multiplicity correction before collection.
- [ ] Execute only complete, validated cells; record failures separately and publish null as well as positive results.

## Acceptance

All planned conditions have traceable artifacts and an aggregate report with confusion matrices, accuracy intervals, per-class recall, false-positive rates, completion rates and adjusted paired comparisons. Report demonstration-selection variance if repetitions are included; otherwise state that only one selection was tested.

The proposed first matrix is two datasets × three counts × two label orders × 200 queries = 2,400 responses from 400 distinct query rows. Any change or replication changes the preregistered budget.

## Dependencies

Steps 1, 3, 4 and 5 must be ready before inference.
