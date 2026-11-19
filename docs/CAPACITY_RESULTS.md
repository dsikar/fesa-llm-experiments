# Attribute-count experiment: output contract first

Status: planning; no new model requests or classification results. This extends the demonstration-count experiment without changing the frozen primary-v1 policy or historical pilot results. Here attributes means input features, not model weights. The study measures classification performance versus supplied information; it does not estimate the model's intrinsic parameter capacity.

## Target report

One row per dataset version × split × exact feature set × demonstration count × instruction order × replicate. Never merge Kaggle variants or datasets just because the domain and feature count match. Results must be generated from machine-readable aggregates, not manually transcribed.

| Type | Dataset / variant | Maximum non-label attributes | Actual supplied | Queries | Accuracy (95% CI) | Balanced accuracy | Malicious precision / recall / F1 | FPR | Completion | Conflicting groups / rows | Status |
|---|---|---:|---:|---:|---|---|---|---|---|---|---|
| phishing | Git Evo | 45 | pending | pending | — | — | — | — | — | pending | planned |
| phishing | Mendeley Evo | 26 | pending | pending | — | — | — | — | — | pending | planned |
| phishing | Kaggle Evo | 20 | pending | pending | — | — | — | — | — | pending | planned |
| phishing | Kaggle Gen | 16 | pending | pending | — | — | — | — | — | pending | planned |
| phishing | Kaggle ModBaseSet | 48 | pending | pending | — | — | — | — | — | pending | planned |
| malware | Hussain deduplicated | 74 | pending | pending | — | — | — | — | — | pending | planned |

Counts were read from the local files. ARFFs contain one additional Class column. Hussain contains 77 columns: exclude **Class, Category and Family**, including from feature descriptions and derived inputs. Its binary task is benign versus malware, not ransomware-only. FeSAD registers all five ARFF pairs as phishing; verify provenance and 0/1 polarity per source before inference. The provided variants are not automatically nested, paired, or independent, and they may already be reduced versions of an upstream dataset.

## JSON locations and required fields

[capacity-plan.json](../results/public/capacity-plan.json) is the current machine-readable inventory of planned dataset arms, with null measurements. Future reviewed results go to `results/public/capacity-results.json` with `schema_version` and a `conditions` array. Private complete records go to `private/capacity/runs/<run_id>/conditions.jsonl` and `predictions.jsonl`; duplicate membership goes to `private/capacity/audits/`. The exporter/schema/renderer are deliverables of the output-contract ticket; these future files do not yet exist. Issue #5 supplies general evidence storage. No observed metric may be filled from a planned placeholder.

Each condition aggregate must contain these fields (null means unavailable, with a reason; zero means measured zero):

| Field group | Required contents |
|---|---|
| Identity | schema_version, run_id, condition_id, dataset_id, dataset_type (`phishing` or `malware`), dataset_version, split_id, feature_set_id, feature_policy, model_id, model_revision, tokenizer_revision, code_revision, template_version, config_revision |
| Inputs | n_source_columns, label_columns_excluded, n_non_label_attributes, n_attributes_input, input_attribute_names, excluded_attribute_names, exclusion_reasons, encoding_policy, missing_value_policy, identity_or_verdict_features_present, label_mapping |
| Design | demonstration_count, label_order, demonstration_order_policy, selection_seed, replicate, schedule_id, sampling_policy, population_scope, n_queries_planned, n_benign_planned, n_malicious_planned |
| Outcomes | status (`planned`, `blocked`, `running`, `complete`, `failed`), status_reason, n_attempted, n_responses, n_valid_predictions, n_failures, n_parse_failures, n_context_overflows, n_truncated, n_benign_evaluated, n_malicious_evaluated, tn, fp, fn, tp, n_predicted_benign, n_predicted_malicious |
| Metrics | accuracy, accuracy_ci95_low, accuracy_ci95_high (Wilson), balanced_accuracy, malicious_precision, malicious_recall, benign_recall, malicious_f1, false_positive_rate, completion_rate, metric_denominator, undefined_metric_reasons |
| Information loss | n_rows_audited, n_unique_vectors, n_duplicate_groups, n_duplicate_rows_excess, n_rows_in_duplicate_groups, n_conflicting_groups, n_rows_in_conflicting_groups, n_unavoidable_errors, empirical_accuracy_ceiling, ceiling_population_scope, cross_split_overlap_groups, cross_split_overlap_rows |
| Cost/context | context_limit_tokens, max_output_tokens, input_tokens_min/median/max, output_tokens_total, latency_seconds_total, n_requests_budgeted, n_requests_made, context_fit_status, truncation_policy |
| Evidence | private_artifact_reference (private only), reviewed_aggregate_revision, design_issue, analysis_revision, freeze_id, timestamps, amendment_ids |

Metrics on valid predictions use n_valid_predictions; completion_rate = n_valid_predictions / n_queries_planned. Require tn+fp+fn+tp = n_valid_predictions and disjoint accounting for every planned query. An incomplete condition may have descriptive metrics with explicit denominator, but fails paired inferential analysis. Undefined precision/recall/F1 is null with a reason, not silently zero. Publish failed and blocked conditions, including context overflows; no silent feature dropping, truncation, selective retries or missing cells. Public exports allowlist aggregates and public design identifiers; remove paths, row identifiers, exact real prompts/responses and membership-identifying hashes. Store private decoding, serving-session, exact inputs and full response evidence under #5. Freeze the final schema and calculation conventions before requests.

## Duplicate and conflict accounting

For each exact projected vector g, count n_g0 and n_g1. A duplicate group has size >1; a conflicting group contains both labels. Duplicate excess = sum(size-1); rows in duplicate groups = sum(size), which are different measures. Unavoidable errors = sum(min(n_g0,n_g1)); empirical deterministic accuracy ceiling = sum(max(n_g0,n_g1)) / N = 1 - unavoidable_errors/N. This is a ceiling for the audited empirical distribution under identical visible input and no record identity, not a bound on all future data or stochastic responses. State the population (source, split, or held-out sample) for every ceiling.

Audit raw non-label vectors and exact model-visible vectors after encoding, rounding, missing-value treatment and feature selection. Use exact numeric canonicalization; any approximate matching is separately labelled. Audit both within and across source splits and variants, including prior pilot queries/demonstrations. Do not repair contradictory labels by majority vote or remove hard cases silently. Freeze a policy before inference, preserving the raw audit; any conflict-free subset is a separately reported population. Group identical vectors across all compared feature projections when freezing paired query/demo splits, or document infeasibility and report separate unpaired analyses.

## Maximum-attribute design

Start with every available non-label attribute (45/26/20/16/48/74), not the conservative 8/12 configuration. Audit meanings, labels, identifiers and potential detector-verdict proxies individually. Confirmed target-derived fields cannot enter the valid classification arm. Any exclusion must be named and justified, with the raw maximum and actual supplied count both reported. If identifier/verdict-containing diagnostic arms are retained, label their limitations and keep them separate from the audited generalization result. Removing only the three named labels does not establish absence of leakage.

Version additional encodings/adapters rather than editing primary-v1. Preserve categorical/hex values explicitly; record transformations and never guess mappings. Compare maximum versus existing and preregistered nested smaller feature subsets on the same held-out queries when valid. Select subsets on development data, never held-out accuracy. Different Kaggle variants alone cannot establish a causal feature-count effect. Freeze demonstration selection/count, both A/B orders, decoding, seeds, model revision, context fit, blocked execution schedule, multiplicity family and request budget with #2–#5 before inference. Keep each dataset's examples in its own disjoint pool. Tokenizer preflight must cover the largest full prompt; context failures are results, not a reason to quietly reduce attributes.

For planning, six dataset variants × three demonstration counts × two label orders × 200 queries = 7,200 requests for one maximum-feature policy and one replicate, if all six qualify. This is illustrative, not an approved/frozen run budget; additional feature policies and replicates multiply it. No inference is authorized by this planning change.


## Related tickets

- [#7 — Define the attribute-count results table and JSON evidence contract](https://github.com/dsikar/fesa-llm-experiments/issues/7)
- [#8 — Inventory FeSAD datasets and freeze maximum non-label feature policies](https://github.com/dsikar/fesa-llm-experiments/issues/8)
- [#9 — Measure feature-reduction duplicates, conflicting labels and empirical ceilings](https://github.com/dsikar/fesa-llm-experiments/issues/9)
- [#10 — Run paired maximum-attribute classification and publish feature-count metrics](https://github.com/dsikar/fesa-llm-experiments/issues/10)
