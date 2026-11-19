# Freeze fresh held-out queries and a disjoint demonstration pool

## Problem

The previous query rows have been inspected and used to guide prompt changes. They are development data, not fresh confirmation data.

## Work

- [ ] Identify dataset versions, provenance, permitted use and local acquisition instructions without redistributing records.
- [ ] Exclude every previous query row and previous demonstration from the new query split.
- [ ] Deduplicate records and use entity/family/capture grouping where supported; document limitations where grouping is unavailable.
- [ ] Freeze a separate development/demonstration pool and held-out queries; proposed query count is 200 per dataset, balanced 100+100.
- [ ] Save split seeds, identities and fingerprints privately before any model-based selection or querying.
- [ ] Assert query/demo disjointness and reuse identical ordered queries in all paired conditions.
- [ ] Keep any natural-prevalence evaluation separate from the balanced experiment.

## Acceptance

A reproducible split specification and tests reject overlap, duplicates and identity/order changes. Public documentation contains only provenance, procedure and aggregate class counts; real records and membership-identifying hashes remain private.

## Dependencies

Coordinate the feature/leakage review with step 1 and artifact storage with step 5. Complete before step 2 runs.
