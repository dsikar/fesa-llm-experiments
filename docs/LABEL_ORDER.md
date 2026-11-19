# Label-order design and offline analysis: issue #3

The implementation supplies the pre-collection design/tests gate for [#3](https://github.com/dsikar/fesa-llm-experiments/issues/3). No model requests have been made. Held-out data, provenance and group-disjoint splitting remain #4; immutable private evidence capture, serving configuration and safe publication remain #5; demonstration-count execution remains #2. Issue #7 is separate and is not imported or modified by this implementation.

## Fixed primary design

[Configuration](../configs/label-order-v1.toml) and [source hashes](../configs/label-order-v1.sha256) fix the additive `label-order-v1` design. The original primary-v1 prompt files and hashes are unchanged. Any amendment to this schedule, matrix or analysis must be dated, versioned and frozen before requests; regenerate the new design hashes intentionally. `load_design()` rejects edited design/code artifacts and verifies the original prompt freeze too.

| Factor | Frozen value |
|---|---|
| Domains | phishing; malware (binary benign/malicious) |
| Feature/template policy | primary-v1 / domain-v1, from #1 |
| Held-out queries | 200 per domain, 100 benign + 100 malicious; same identities/gold labels in every condition |
| Demonstrations | 0, 4 or 10; one frozen balanced selection per domain; first four of the ordered ten form the four-shot arm |
| Instruction order | A malicious first; B benign first; only the instruction label clause changes |
| Replicates | one selection and one serving session; no repeated conditions |
| Execution | 20-query blocks; paired A/B blocks adjacent; block order randomized with seed 20261119 |
| Counterbalance | per domain/count, ten paired blocks: exactly five A-first and five B-first |
| Request budget | 2 domains × 3 counts × 2 orders × 200 = **2,400**; 400 distinct queries |
| Retries | zero; preserve any failure and reject incomplete inferential analysis |

Queries inside each paired block retain their registered order. The shuffled schedule is frozen in the private manifest before collection. Results may arrive out of order: analysis matches them by the frozen request/query identities, never by response-file position. Randomized block order means the whole-run query stream is not source-file order; each A/B block uses exactly the same queries in the same order. Demonstration order stays fixed across A/B and query blocks.

Counterbalancing reduces systematic A-first and time-position confounding; it does not prove independent requests or eliminate drift. Record serving sessions, timestamps, schedule deviations and run failures through #5. Multiple sessions cannot be pooled under this design. Restarting after a failure requires a documented new run/amendment, not silent retry. Changes to maximum features/dataset variants under #10 require a separately versioned matrix and budget; the six-variant plan is not silently substituted here.

## Separate questions and declared tests

For every domain × demonstration count, report the complete 00/01/10/11 transition table, where the first digit is A and the second B; 0 means benign and 1 malicious. Report flips = 01 + 10, flip rate with descriptive Wilson 95% interval, observed-change flag and malicious-prediction-rate delta B−A = (01−10)/N.

Keep a separate correctness table: both correct, A-only correct, B-only correct, both wrong. Accuracy delta B−A = (B-only−A-only)/N. An exact two-sided McNemar test conditions on the number of accuracy-discordant pairs. An exact two-sided binomial directional-shift test conditions on the number of prediction flips. With no discordances/flips, the corresponding p-value is 1.0. No asymptotic approximation is used.

| Family | Number of tests | Multiplicity policy |
|---|---:|---|
| Primary label-order accuracy | 2 domains × 3 counts = 6 | Holm across all six, alpha 0.05 |
| Secondary directional prediction shift | 2 domains × 3 counts = 6 | Separate Holm family across all six, alpha 0.05 |
| Demonstration-count accuracy | 2 domains × 2 orders × (0 vs 4, 0 vs 10, 4 vs 10) = 12 | Holm across all twelve, alpha 0.05 |

Separate Holm families do not provide a single combined familywise error guarantee across all claims. Both raw and adjusted p-values, family identifiers and effect directions are retained; do not select comparisons after seeing results. Wilson intervals are descriptive, not multiplicity-adjusted. The exact tests assume appropriately independent query units; #4 must justify that assumption through its sampling/group policy. Entity/family dependence remaining within a query sample requires a prospective group-aware analysis amendment or descriptive-only reporting, not an independence claim inferred from unique row ids.

**Nonsignificant accuracy does not mean prediction invariance.** A can predict all 1 and B all 0 on a balanced sample: both score 50% while every prediction flips. Symmetric 01/10 flips can also have no directional shift. Report the transitions in either case. No equivalence margin, invariance test, deployment claim or demonstration-selection variance estimate is provided by this one-selection design.

Each cell additionally reports its confusion matrix, prediction counts, accuracy/Wilson interval, per-class recall, FPR and completion. Missing/failed cells produce no inferential output; private failure diagnostics are a separate #5 artifact. Incomplete data must not be rescued by shrinking a denominator or dropping a planned family member.

## Private registration and evidence interface

`scripts/label_order.py` is a model-free library. It provides:

- `render_pair(dataset, query, demonstrations)`: renders both exact prompts using the frozen #1 renderer and verifies that only the single label clause changes. Save the returned exact bundles privately through #5.
- `build_manifest(datasets, metadata, evidence_class=...)`: validates two 200-row balanced query sets and ten ordered balanced demonstrations per domain; rejects identity overlap and identical projected feature vectors across query/demo pools; records A/B prompt hashes and the complete 2,400-request schedule. It never writes files or queries a model.
- `digest(manifest)`: canonical JSON SHA-256. Save this digest with an authoritative private pre-run registration, separately from mutable result files. The analyzer requires that pre-existing value; computing a new digest of altered data after collection is not registration.
- `analyze(manifest, rows, registered_manifest_sha256=...)`: validates the frozen membership, schedule, prompt hashes and common execution fingerprint, then returns aggregates. Duplicate, missing, foreign, altered or failed responses are rejected before computing a p-value. Response receipt order may differ from execution order.

`datasets` has exactly `phishing` and `malware`. Each maps to `{split_id, queries, demonstrations}`. A query is `{query_id, label, features}`; a demonstration is `{demo_id, label, features}`. Labels are integer 0/1, never booleans or strings. The features mapping follows primary-v1. Do not place targets in it. The registered first four demonstrations must contain 2+2 labels; the ten must contain 5+5. Query/demo grouping and source provenance are not established by this interface's id/vector checks; they remain #4.

`metadata` has exactly `run_id`, `serving_session_id`, `model_id`, `model_revision`, `tokenizer_revision`, `code_revision`, `decoding`. Revisions and session identifiers must be explicit; decoding is a nonempty finite JSON mapping. The serving runner must freeze and validate supported decoding settings under #5. The manifest execution fingerprint binds these common settings and the prompt freeze, while per-request hashes bind the actual prompt. This checks submitted evidence against registration; it cannot prove a remote server used those settings without trustworthy #5 capture.

Each result copies its registered request entry and adds `status`, integer `attempt_count` (exactly 1 for accepted evidence under the zero-retry policy) and integer `prediction` (0/1 for valid results). Include failed response records with nonvalid status rather than omitting them; inference will reject the run and #5 retains their diagnostics. `evidence_class` is `synthetic` for examples and `observed` for a future real run registration; a registration alone is not an observed experiment.

Store manifests, their registration digests, schedules, exact prompts and per-request evidence under ignored owner-only `private/label-order/runs/<run_id>/`, or link them from #5's immutable run store. Do not publish membership hashes, row ids or manifest digests. The CLI emits only domain/count/order aggregates, public model/code revision fields and fixed interpretation text; #5 remains responsible for reviewing and linking a public release to the model, code and design revisions.

```bash
python3 scripts/analyze_label_order.py \
  --manifest private/label-order/runs/RUN/manifest.json \
  --registered-manifest-sha256 PREVIOUSLY_REGISTERED_CANONICAL_DIGEST \
  --predictions private/label-order/runs/RUN/predictions.jsonl
```

The example paths are placeholders; no real run files or public results are created by this change. CLI rejection prints a generic diagnostic without echoing private paths or raw records. Synthetic tests construct complete manifests, simulate responses, exercise the CLI and check the resulting aggregates without a model call.

## Readiness and validation

Run `python3 -m unittest discover -s tests -v` and the established README baseline/publication checks. The synthetic suite covers full prediction reversal with equal accuracy, symmetric flips, separate correctness/direction effects, exact tests and fixed Holm families, deterministic balanced blocks, unchanged demonstrations, missing/extra/duplicate rows, failures, malformed labels, changed metadata, altered/shrunk registrations, query/demo overlap and safe CLI output.

The #3 implementation/design gate can be reviewed independently of #4/#5. Issue #3's final acceptance also requires actual per-condition transition/accuracy reports after #2 runs. Keep that distinction visible: there are no new classification results here, and the completed implementation does not by itself authorize collection.
