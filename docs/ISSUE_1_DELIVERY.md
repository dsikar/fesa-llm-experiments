# Issue 1: domain prompts and feature policy

Issue: [#1](https://github.com/dsikar/fesa-llm-experiments/issues/1). Model requests made in this work: **zero**.

Implemented separate phishing and executable-file malware templates, sourced definitions, strict numeric conversion, a feature allowlist and owner-only exact-prompt storage. The malware target is benign versus malicious executable, not ransomware versus benign.

| Domain | Inventoried input fields | Primary fields | Excluded fields | Existing records checked | Schema-compatible |
|---|---:|---:|---:|---:|---:|
| Phishing | 20 | 8 | 12 | 116 | 116 |
| Malware | 74 | 12 | 62 | 116 | 116 |

The 116 records per domain are the already-used 100 query rows plus 16 demonstration-pool rows. These are development-schema checks, not new classification results or held-out evaluation. Labels and model correctness were not used to choose features. Real records and record-identifying hashes are not published.

## What was excluded

The [complete feature inventory](FEATURE_POLICY.md) records the evidence and reason for each decision. Primary phishing inputs are direct URL counts/lengths. Unresolved binary polarity, rule-code mappings, keyword matching and ratio conventions are excluded. Malware inputs use standard numeric PE-header measurements; file hashes, class/category/family labels, possible detector-verdict proxies, unverified counters, symbolic/legacy mappings and section-specific mappings are excluded.

Compatibility validation found four unsupported hex-like `AddressOfEntryPoint` encodings among the 116 existing malware records. The field was removed from every primary prompt; those records were retained. No conversion or missing-value meaning was guessed. This adjustment preceded the release freeze and any v3 inference.

The local malware source matches the publisher's file checksum. The phishing feature-family definitions are sourced, while the exact lineage of the derived split remains unresolved. That limitation is explicit and must be addressed in dataset preparation under issue #4. Excluded features may be reconsidered only through a documented, versioned amendment with verified provenance; this implementation makes no claim that all possible leakage has been ruled out.

## Validation and evidence

- **28 offline tests pass:** 9 existing public-artifact tests plus 19 prompt tests.
- Tests cover domain wording, query-label non-disclosure, excluded/unknown features, numeric precision and bounds, A/B clause-only changes, balanced 0/4/10 demonstrations, duplicate projected vectors, freeze tampering, CLI behaviour and private file permissions.
- Exact prompts for one existing query per domain were saved in ignored owner-only storage. Private validation metadata records the compatibility counts. No real prompt text or record was staged for publication.
- [Frozen artifact hashes](../configs/prompt-v1.sha256) identify the two templates, primary config, feature dictionary, renderer and CLI. Rendering refuses edits to these artifacts without an explicit freeze update.
- [Synthetic examples](PROMPT_EXAMPLES.md) show the actual template layout without real records.
- Original pilot aggregates and reports remain unchanged.

Run `python3 -m unittest discover -s tests -v` and the commands in [PROMPTS.md](PROMPTS.md) to verify offline. Public checks do not require private records or model access.

## Remaining work

Issue #2 runs the demonstration-count experiment; #3 completes the execution-order/analysis design; #4 freezes fresh, disjoint queries and verifies dataset-level lineage; #5 captures responses and run-wide evidence. This issue supplies prompt construction and private prompt bundles, not the complete future inference runner.

The feature subset changed alongside the instruction wording. Future comparisons against the historical pilot must describe both changes; they cannot isolate a wording effect by themselves.
