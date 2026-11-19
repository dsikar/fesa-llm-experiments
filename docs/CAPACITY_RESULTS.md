# Attribute-count experiment: output contract first

Status: output contract frozen as `capacity-output-contract-v1`; no new model requests and no observed classification results. This extends the demonstration-count experiment without changing the frozen primary-v1 policy or historical pilot results. Here attributes means input features, not model weights. The study measures classification performance versus supplied information; it does not estimate the model's intrinsic parameter capacity.

Issue [#7](https://github.com/dsikar/fesa-llm-experiments/issues/7) freezes the schema, validator, table renderer and allowlist exporter. It does not close the issue, run inference, or execute #8, #9 or #10. Issue #5 still owns immutable storage, atomic writes, resume and cross-session retries. This contract is the validation boundary that store should call.

## Target report

One row per dataset version × split × exact feature set × demonstration count × instruction order × replicate. Never merge Kaggle variants or datasets just because the domain and feature count match. Results must be generated from machine-readable aggregates, not manually transcribed.

The planning table below is generated from [capacity-plan.json](../results/public/capacity-plan.json). Regenerate it with `python3 scripts/render_capacity.py --planning`. It is an inventory, not a results file.

<!-- BEGIN GENERATED PLANNING TABLE -->
Planning inventory. No observed classification metrics.

| Type | Dataset / variant / version | Split | Feature set | Demos | Order | Rep | Raw maximum | Actual supplied | Queries | Accuracy (Wilson 95% CI) | Balanced accuracy | Malicious precision / recall / F1 | Benign recall | FPR | Completion | Conflicts (groups / rows) | Ceiling | Status |
|---|---|---|---|---:|---|---:|---:|---:|---:|---|---|---|---|---|---|---|---|---|
| phishing | Git Evo (git-evo) / version pending | pending | pending | pending | pending | pending | 45 | pending | pending | — | — | — / — / — | — | — | — | pending | — | planned |
| phishing | Mendeley Evo (mendeley-evo) / version pending | pending | pending | pending | pending | pending | 26 | pending | pending | — | — | — / — / — | — | — | — | pending | — | planned |
| phishing | Kaggle Evo (kaggle-evo) / version pending | pending | pending | pending | pending | pending | 20 | pending | pending | — | — | — / — / — | — | — | — | pending | — | planned |
| phishing | Kaggle Gen (kaggle-gen) / version pending | pending | pending | pending | pending | pending | 16 | pending | pending | — | — | — / — / — | — | — | — | pending | — | planned |
| phishing | Kaggle ModBaseSet (kaggle-mod-base-set) / version pending | pending | pending | pending | pending | pending | 48 | pending | pending | — | — | — / — / — | — | — | — | pending | — | planned |
| malware | Hussain deduplicated (hussain-deduplicated) / version pending | pending | pending | pending | pending | pending | 74 | pending | pending | — | — | — / — / — | — | — | — | pending | — | planned |
<!-- END GENERATED PLANNING TABLE -->

Counts were read from the local files. ARFFs contain one additional Class column. Hussain contains 77 columns: exclude **Class, Category and Family**, including from feature descriptions and derived inputs. Its binary task is benign versus malware, not ransomware-only. FeSAD registers all five ARFF pairs as phishing; verify provenance and 0/1 polarity per source before inference. The provided variants are not automatically nested, paired, or independent, and they may already be reduced versions of an upstream dataset.

`Raw maximum` is `n_non_label_attributes`. `Actual supplied` is `n_attributes_input`. They are different quantities. Label order A lists the malicious label first; B lists the benign label first. Queries are shown as valid/planned. A Wilson cell is accuracy followed by the 95% interval. Malicious precision, recall and F1 stay in that order, and a null component is an em dash rather than zero. The ceiling cell names the audited population and whether matching was exact or approximate.

## Artifact layout

| Path | Role |
|---|---|
| `schemas/capacity-aggregate-v1.schema.json` | Public aggregate allowlist and field types |
| `schemas/capacity-condition-private-v1.schema.json` | Private condition record, including in-progress `running` |
| `schemas/capacity-prediction-private-v1.schema.json` | One planned query, with retries on `attempt_count` |
| `schemas/capacity-plan-v1.schema.json` | Planning inventory, distinct from observed results |
| `schemas/evidence-run-v1.schema.json` | Directory contract shared with #5 |
| `results/public/capacity-plan.json` | Current planning inventory. Metrics are null |
| `results/public/capacity-results.json` | Reserved for a later reviewed observed aggregate. Not created |
| `tests/fixtures/capacity/synthetic-aggregate.json` | Labelled synthetic fixture. Not an experiment |
| `private/capacity/runs/<run_id>/run.json` | Private run header |
| `private/capacity/runs/<run_id>/conditions.jsonl` | Private condition records |
| `private/capacity/runs/<run_id>/predictions.jsonl` | Private per-query records |
| `private/capacity/audits/<audit_id>/groups.json` | Private duplicate membership |

Search by `run_id`, `condition_id`, `dataset_id`, `split_id` and `feature_set_id`. A condition id should stay a single path segment, `cap-<dataset>-<split>-<feature-set>-d<count>-<order>-r<replicate>`. Issue #5 writes these files immutably. `scripts/capacity_contract.py` validates them. `write_synthetic_layout` only writes fixtures whose `evidence_class` is `synthetic` and refuses a root under `results/`.

No observed metric may be copied from a planning null. `results/public/capacity-results.json` stays ignored until a reviewed observed aggregate is published on purpose. Synthetic output keeps `artifact_type: synthetic_fixture`, `synthetic: true`, `not_an_experiment: true`, `model_requests_made: 0` and the banner `SYNTHETIC FIXTURE`.

## Required fields

Each public condition carries the fields below. The JSON Schemas and `scripts/capacity_contract.py` list them in one order. Null means unavailable or undefined and requires a reason. Zero means a measured zero. Metric nulls use `undefined_metric_reasons`. Every other null uses `unavailable_reasons`.

| Field group | Required contents |
|---|---|
| Identity | schema_version, schema_id, run_id, condition_id, dataset_id, dataset_type (`phishing` or `malware`), dataset_version, split_id, feature_set_id, feature_policy, model_id, model_revision, tokenizer_revision, code_revision, template_version, config_revision, result_arm, observation_source |
| Inputs | n_source_columns, label_columns_excluded, n_non_label_attributes, n_attributes_input, input_attribute_names, excluded_attribute_names, exclusion_reasons, encoding_policy, missing_value_policy, identity_or_verdict_features_present, label_mapping |
| Design | demonstration_count, label_order (`A` or `B`), demonstration_order_policy, selection_seed, replicate, schedule_id, sampling_policy, population_scope, n_queries_planned, n_benign_planned, n_malicious_planned |
| Outcomes | status, status_reason, accounting_policy, accounting_closed, n_attempted, n_responses, n_valid_predictions, n_failures, n_parse_failures, n_context_overflows, n_context_overflows_preflight, n_context_overflows_sent, n_truncated, n_other_failures, n_not_attempted, n_open, n_benign_evaluated, n_malicious_evaluated, tn, fp, fn, tp, n_predicted_benign, n_predicted_malicious |
| Metrics | accuracy, accuracy_ci95_low, accuracy_ci95_high (Wilson), balanced_accuracy, malicious_precision, malicious_recall, benign_recall, malicious_f1, false_positive_rate, completion_rate, metric_denominator, undefined_metric_reasons, unavailable_reasons |
| Information loss | n_rows_audited, n_unique_vectors, n_duplicate_groups, n_duplicate_rows_excess, n_rows_in_duplicate_groups, n_conflicting_groups, n_rows_in_conflicting_groups, n_unavoidable_errors, empirical_accuracy_ceiling, ceiling_population_scope, audit_matching, cross_split_overlap_groups, cross_split_overlap_rows |
| Cost/context | context_limit_tokens, max_output_tokens, input_tokens_min, input_tokens_median, input_tokens_max, output_tokens_total, latency_seconds_total, n_requests_budgeted, n_requests_made, context_fit_status, truncation_policy |
| Evidence | design_issue, analysis_revision, freeze_id, reviewed_aggregate_revision, timestamps, amendment_ids, paired_analysis_eligible, pairing_established_by_aggregate |

`result_arm` is `pending`, `audited_generalization` or `diagnostic`. A diagnostic arm has `identity_or_verdict_features_present: true` and cannot be eligible for paired inference. `observation_source` is `not_run`, `synthetic_fixture` or `observed`.

Private condition records add `planned_queries`, `private_artifact_reference`, `decoding`, `demonstration_ids`, `serving_session_id`, `endpoint` and `prompt_template_sha256`. Private predictions add the query id, row identity, pair-group id, prompt and response hashes, membership hash, raw artifact names and per-query attempt count. Those names are not on the public allowlist.

`planned_queries` is registered before collecting predictions. It contains one object per query with `query_id`, `row_identity`, `gold_label` and `membership_hash`. Its length and class totals must match the registered planned counts. It is null only for an unfrozen planned cell. The builder and private exporter require exactly one disposition per frozen query, including explicit failures or `not_attempted` records; missing rows are rejected. Query identities, membership hashes and class labels must match the frozen list even when a substituted result set has the same size and class balance. Issue #5 owns immutable persistence of this registration.

Known FeSAD ids keep the registered column counts when those fields are present: Git Evo 46/45, Mendeley Evo 27/26, Kaggle Evo 21/20, Kaggle Gen 17/16, Kaggle ModBaseSet 49/48, Hussain 77/74. Hussain's excluded label columns are exactly Class, Category and Family, and none of them may appear in the model input. Provenance and 0/1 polarity remain #8. This check does not verify them.

## Statuses and nulls

Public statuses are `planned`, `blocked`, `incomplete`, `failed` and `complete`. Private in-progress records may also be `running`; a public aggregate rejects them. Running snapshots require a frozen plan, positive `n_open`, open accounting, no close timestamp and false paired eligibility. Terminal dispositions plus open queries partition the plan. Attempted queries include terminal attempts and up to `n_open` outstanding sent queries; request totals must cover those attempts and stay within budget. Confusion counts and metrics describe valid terminal results available so far. Missing token/latency observations carry the same explicit reasons as closed records. An observed running snapshot does not yet require a reviewed publication revision.

| Status | Accounting | What the metrics mean |
|---|---|---|
| planned | Open. Outcome counts are null, not zero | Nothing was observed |
| blocked | Closed. No request was sent | Completion is measured zero. Classification metrics are null |
| failed | Closed. At least one query was attempted and none was valid | Completion is measured zero. Classification metrics are null |
| incomplete | Closed. Some but not all planned queries are valid | Descriptive metrics use `n_valid_predictions`. Not eligible for paired inference |
| complete | Closed. Every planned query is a valid prediction and class coverage matches the plan | Classification metrics use the full plan. Precision and F1 may still be null |
| running | Private only. `n_open` > 0 | Not publishable |

`completion_rate = n_valid_predictions / n_queries_planned` when both counts exist. `metric_denominator` is `n_valid_predictions` for the classification metrics. Accuracy, its Wilson interval, recall, balanced accuracy, precision, F1 and FPR are null when their own denominator is zero:

- accuracy and the Wilson bounds when `n_valid_predictions` is 0
- benign recall and FPR when no benign query was evaluated
- malicious recall when no malicious query was evaluated
- balanced accuracy when either class recall is undefined
- malicious precision when no query was predicted malicious
- malicious F1 when precision or malicious recall is undefined

A defined zero stays a float `0.0`. An undefined quantity stays null with the frozen reason string. Both precision and recall defined as zero produce F1 `0.0`, because that is a measured zero rather than a missing denominator. Wilson intervals use the same z (`1.959963984540054`) and the same `math.isclose` tolerance as `scripts/verify_baseline.py`: relative `1e-9`, absolute `1e-12`.

## Failure accounting

Policy id: `capacity-accounting-v1`. For a closed condition the planned queries partition without overlap:

```text
n_queries_planned
  = n_valid_predictions
  + n_parse_failures
  + n_context_overflows
  + n_truncated
  + n_other_failures
  + n_not_attempted
  + n_open
```

`n_open` is 0 when accounting is closed. `n_context_overflows = n_context_overflows_preflight + n_context_overflows_sent`. `n_failures` is the sum of parse failures, context overflows, truncations and other failures. It does not include retries, not-attempted queries or open queries. `n_attempted` counts a query once when at least one request was sent. Preflight context overflows are failures and are not attempts. `n_responses` counts queries that returned a body: valid, parse failure and truncation. `n_requests_made` is the sum of per-query `attempt_count` and may exceed `n_attempted` when a query was retried. A public aggregate can only check `n_requests_made >= n_attempted`; the private predictions are what show the exact retry total.

Truncated responses use policy `reject_truncated` and are not scored. Context fit is `overflow` when any query's terminal disposition is context overflow, `fit` when a request was sent and none overflowed, and `not_checked` when nothing was sent. Input-token median is the middle value, or the mean of the two central values when the count is even. Missing token or latency observations null the whole summary rather than publishing a partial one.

## Duplicate and conflict accounting

For each exact projected vector g, count n_g0 and n_g1. A duplicate group has size >1; a conflicting group contains both labels. Duplicate excess = sum(size-1); rows in duplicate groups = sum(size), which are different measures. Unavoidable errors = sum(min(n_g0,n_g1)); empirical deterministic accuracy ceiling = sum(max(n_g0,n_g1)) / N = 1 - unavoidable_errors/N. This is a ceiling for the audited empirical distribution under identical visible input and no record identity, not a bound on all future data or stochastic responses. State the population (source, split, or held-out sample) for every ceiling.

Binary minority counts must satisfy `n_conflicting_groups <= n_unavoidable_errors` and `2 * n_unavoidable_errors <= n_rows_in_conflicting_groups`. Each duplicate group needs at least two rows; conflict rows must leave enough rows for all other duplicate groups. If all duplicate groups conflict, their row totals must agree. These are aggregate feasibility checks; they cannot establish the underlying group memberships.

The audited row count is not the query count. A ceiling without `ceiling_population_scope` and `audit_matching` (`exact` or `approximate`) is invalid. Approximate matching stays labelled and is not treated as exact. Cross-split overlap is a separate pair of counts. Membership hashes and per-group row lists stay under `private/capacity/audits/`.

Audit raw non-label vectors and exact model-visible vectors after encoding, rounding, missing-value treatment and feature selection. Use exact numeric canonicalization; any approximate matching is separately labelled. Audit both within and across source splits and variants, including prior pilot queries/demonstrations. Do not repair contradictory labels by majority vote or remove hard cases silently. Freeze a policy before inference, preserving the raw audit; any conflict-free subset is a separately reported population. Group identical vectors across all compared feature projections when freezing paired query/demo splits, or document infeasibility and report separate unpaired analyses.

Supplied names, excluded names and exclusion reasons must partition `n_non_label_attributes` once a condition leaves `planned`. Label columns cannot appear in either list. That is the check against silent feature dropping. It does not prove the remaining features are free of leakage.

## Pairing

`paired_analysis_eligible` is true only for a complete `audited_generalization` arm whose verdict/identifier flag is false and whose every planned query is a valid prediction. Incomplete, failed, blocked, planned and diagnostic arms are ineligible. Eligibility is a numeric gate. `pairing_established_by_aggregate` is always false. Pair-group ids live on private predictions. Aggregate counts do not prove that two arms share rows.

## Exporter

`validate_aggregate` validates an aggregate without private evidence. `export_public_aggregate` is the evidence-backed path: conditions, predictions and audits must all be present as lists (an empty audit list is valid only when no audit is claimed). It validates the private condition and prediction interfaces, run and condition membership, frozen query and class coverage, ordered demonstration ids, session/endpoint agreement and decoding output limit. It reconciles all condition request totals, including retries; observed run totals must equal their sum. A reviewed run blocked in preflight can have zero model requests; its blocked conditions and zero completion remain reportable. At least one condition must have observed preflight or request evidence: an entirely unrun plan cannot be relabelled as results. Synthetic per-condition request counts are simulated and the actual run request total remains zero. Orphan or duplicate records are rejected. Audit summaries and ceilings must exactly match recomputation from validated per-group binary label counts, with unique group membership hashes and matching population/method metadata. This checks supplied evidence consistency; provenance, the correctness of vector grouping and cross-arm pairing still need private review.

The exporter then copies the public field list and drops everything else: private paths, row and query identities, pair ids, demonstration ids, membership hashes, prompt and response hashes, raw prompts and responses, decoding, session ids and endpoints. It then scans the projected JSON for those private strings and for the disclosure patterns in `scripts/check_public_tree.py`. A synthetic run cannot be relabelled as a reviewed aggregate. Public top-level fields link issue 7, `docs/CAPACITY_RESULTS.md`, `docs/requests/06-capacity-output-contract.md`, the accounting policy and the freeze id.

## Contract amendments

These ids are required on every v1 aggregate. They record decisions made while freezing the contract, before any feature-count request.

| Amendment | Change |
|---|---|
| `accounting-buckets-v1` | Adds `n_other_failures`, `n_not_attempted`, `n_open`, and the preflight/sent split of context overflows so retries and diagnostic categories are not double-counted |
| `status-incomplete-v1` | Adds public status `incomplete` for a closed condition with a proper subset of valid predictions. `failed` is reserved for zero valid predictions |
| `pairing-not-proven-v1` | Adds the eligibility flag and forces `pairing_established_by_aggregate` false |
| `observation-source-v1` | Labels each row `not_run`, `synthetic_fixture` or `observed` so a fixture cannot be read as a result |

## Maximum-attribute design

Start with every available non-label attribute (45/26/20/16/48/74), not the conservative 8/12 configuration. Audit meanings, labels, identifiers and potential detector-verdict proxies individually. Confirmed target-derived fields cannot enter the valid classification arm. Any exclusion must be named and justified, with the raw maximum and actual supplied count both reported. If identifier/verdict-containing diagnostic arms are retained, label their limitations and keep them separate from the audited generalization result. Removing only the three named labels does not establish absence of leakage.

Version additional encodings/adapters rather than editing primary-v1. Preserve categorical/hex values explicitly; record transformations and never guess mappings. Compare maximum versus existing and preregistered nested smaller feature subsets on the same held-out queries when valid. Select subsets on development data, never held-out accuracy. Different Kaggle variants alone cannot establish a causal feature-count effect. Freeze demonstration selection/count, both A/B orders, decoding, seeds, model revision, context fit, blocked execution schedule, multiplicity family and request budget with #2–#5 before inference. Keep each dataset's examples in its own disjoint pool. Tokenizer preflight must cover the largest full prompt; context failures are results, not a reason to quietly reduce attributes.

For planning, six dataset variants × three demonstration counts × two label orders × 200 queries = 7,200 requests for one maximum-feature policy and one replicate, if all six qualify. This is illustrative, not an approved/frozen run budget; additional feature policies and replicates multiply it. No inference is authorized by this contract.

## Reproduce the synthetic table

The fixture calls no model. Its per-condition `n_requests_made` values are simulated accounting counts. The aggregate's `model_requests_made` is 0.

```bash
python3 scripts/render_capacity.py --synthetic
python3 scripts/render_capacity.py --planning
python3 -m pip install -r requirements-test.txt
python3 -m unittest tests.test_capacity_contract tests.test_capacity_review -v
```

## Verification

Updated on 2026-11-19 after the five review fixes and reconciliation with main `cf8af15`. Issue #7 remains open and the implementation remains unmerged pending review. Test dependencies are pinned in `requirements-test.txt` and installed explicitly in CI. The original 42 tests alone did not catch the review findings; the added regressions exercise frozen membership, evidence reconciliation, schema instances, running snapshots and conflict bounds. No model was called. `results/public/capacity-results.json` was not created. Primary-v1 files, `results/public/pilot-v2.json`, `docs/PILOT_V2.md` and `results/public/capacity-plan.json` were not edited.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/verify_baseline.py
python3 scripts/render_baseline.py --check
python3 -c "from fesa_prompts import verify_freeze; verify_freeze()"
# After staging only the reviewed public files for this change:
python3 scripts/check_public_tree.py
git diff --cached --check
```

| Command | Outcome |
|---|---|
| `python3 -m unittest discover -s tests -v` | 60 tests, OK, including 18 review regressions and independent Draft 2020-12 validation |
| `python3 scripts/verify_baseline.py` | Exit 0. Verified public aggregate arithmetic: 8 conditions, 800 responses, 200 distinct query rows. |
| `python3 scripts/render_baseline.py --check` | Exit 0. Baseline report matches the aggregate JSON. |
| `python3 -c "from fesa_prompts import verify_freeze; verify_freeze()"` | Exit 0. Freeze check returned without error. |
| `python3 scripts/check_public_tree.py` | Public-tree checks passed for the staged public tree; manual review still required. |
| `git diff --cached --check` | No whitespace errors. |

The staged disclosure scan found the path `results/public/capacity-results.json` only as the reserved name in docs, schemas and tests. The file is absent. The scan found no credentials, home paths, email addresses, GPU hostnames or `private/datasets` paths.

## Limits

The synthetic fixture checks the contract. It is not a pilot, a capacity estimate, or evidence about Qwen. Pairing, provenance, label polarity, collision membership and the real request budget are still open. #8, #9 and #10 have not been executed. A public aggregate cannot by itself prove row pairing, retry history or token totals; those checks use the private predictions. The illustrative 7,200-request matrix is not authorized.

## Related tickets

- [#7 — Define the attribute-count results table and JSON evidence contract](https://github.com/dsikar/fesa-llm-experiments/issues/7)
- [#8 — Inventory FeSAD datasets and freeze maximum non-label feature policies](https://github.com/dsikar/fesa-llm-experiments/issues/8)
- [#9 — Measure feature-reduction duplicates, conflicting labels and empirical ceilings](https://github.com/dsikar/fesa-llm-experiments/issues/9)
- [#10 — Run paired maximum-attribute classification and publish feature-count metrics](https://github.com/dsikar/fesa-llm-experiments/issues/10)
