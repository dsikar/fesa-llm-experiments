# Domain prompts

Issue: [#1](https://github.com/dsikar/fesa-llm-experiments/issues/1).

`domain-v1` provides separate website-phishing and Windows-executable malware instructions. `primary-v1` contains 8 direct URL measurements for phishing and 12 numeric static PE measurements for malware. Meanings, encodings and exclusions are documented in [FEATURE_POLICY.md](FEATURE_POLICY.md).

## Frozen artifacts

[Primary configuration](../configs/primary.toml), [feature inventory](../configs/features.toml), [phishing template](../prompts/phishing-v1.txt) and [malware template](../prompts/malware-v1.txt) are versioned together with the renderer. [prompt-v1.sha256](../configs/prompt-v1.sha256) records their exact public source hashes. Rendering fails if these files change without an explicit version/freeze update. These are hashes of public code/configuration, not dataset records.

Templates include definitions once, optional labelled examples, then a single unlabelled query. Label order A versus B changes only the declared class-description clause. Demonstration count/order/selection remains an experiment factor, not a hidden prompt edit.

Numeric values are rendered as exact decimal integers. Hexadecimal PE values are converted without floating-point parsing. Known excluded fields are projected out; target-like keys inside a feature mapping and unexpected or missing columns are rejected. A query record's label and other outer metadata are never accessed by the renderer. Demonstration labels are explicit and validated separately.

This deliberately narrower input specification differs from the historical pilot. Do not attribute a v2-to-v3 accuracy change solely to wording or demonstration count: the feature set also changed. No v3 model requests have been made.

## Offline use

Requires Python 3.11 or later; uses only the standard library (`string.Template`, `tomllib`, JSON and file I/O). There is no model or network client in this renderer.

Place a query JSON record with a `features` mapping in ignored private storage. An optional demonstration JSON file is a list of 4 or 10 records, each with `features` and integer `label` (0 benign, 1 phishing/malicious). Queries and demonstrations must not share identical projected feature vectors. Full split/entity disjointness remains issue #4.

```bash
python3 scripts/render_prompt.py --dataset phishing --input private/query.json
python3 scripts/render_prompt.py --dataset malware --input private/query.json --demonstrations private/demonstrations.json --label-order B
```

Each invocation saves a unique exact-prompt bundle under ignored `private/prompts/`. Directories require owner-only access and files are created with mode 0600. No prompt text is printed to the terminal. The bundle contains template/policy versions, source hashes, demonstration labels, excluded-column names, the exact prompt and its digest. It omits outer query labels, paths and identities. Do not commit these bundles.

Experiment-wide raw-response capture, split manifests, run/session handling and reviewed aggregate export remain issue #5; rendering a prompt alone does not implement that full trail.

## Examples and validation

[PROMPT_EXAMPLES.md](PROMPT_EXAMPLES.md) contains handmade, synthetic zero-shot examples. They are not actual records, replayed model requests or evidence of detection performance.

Run all offline tests:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_public_tree.py
```

The source-policy checks do not prove feature-extractor lineage, label validity, natural deployment prevalence or the absence of all possible leakage. Unresolved mappings are excluded or documented for dataset-level verification before inference.
