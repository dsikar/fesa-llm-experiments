# Next experiment: prompt specification and demonstration count

Status: proposed; execution is tracked in the five linked issues. No v3 responses have been collected.

## Question

With a fixed, domain-correct prompt, does increasing the number of balanced labelled demonstrations improve classification? Does the effect depend on the order in which benign and malicious labels are described?

## Five steps

1. Correct the task wording and document feature meanings from verified dataset definitions. Website features use a phishing instruction; executable-file features use a malware instruction. Review identifiers and detection-derived fields for prediction-time availability and leakage before freezing the primary feature set.
2. Compare 0, 4 and 10 demonstrations. Four means 2 benign + 2 malicious; ten means 5 + 5. Use the same frozen demonstration pool across paired conditions; nest the four examples within the ten and record their order. Freeze selection seeds and any replication policy before requests.
3. Retain both instruction label orders. A describes malicious first; B describes benign first. Within each demonstration-count condition, change only that clause. Distinguish this manipulation from demonstration order, which stays fixed.
4. Use fresh held-out query rows, disjoint from all earlier query rows and demonstration pools. Detect exact duplicates and use entity/family/capture grouping where supported. Existing pilot rows are development data. Freeze identities, class counts and split hashes before querying; never select query rows using model performance.
5. Save separate immutable run artifacts: exact prompts, demonstration identities, token/decoding settings, model revision, raw responses, parsed predictions, correctness, failures, seeds, code version and artifact hashes. Keep private evidence locally; export reviewed aggregates. Publish null results and failed-run status as well as improvements.

## Proposed first matrix

| Factor | Values |
|---|---|
| Dataset | Phishing; ransomware/malware |
| Demonstrations per request | 0; 4; 10 |
| Instruction label order | A; B |
| Queries per dataset | Proposed: 200, balanced 100 benign / 100 malicious |

This is 12 conditions × 200 queries = **2,400 responses from 400 distinct query rows**. Each row is queried six times. This count assumes one demonstration selection; any repetitions require an updated frozen request budget. Query rows and demonstrations are separate.

Keep model, features, decoding and prompt structure fixed across the count/order comparisons. If prompt or feature-set changes are evaluated directly, register them as an additional factor with their own budget. The previous pilot is a historical reference, not a clean causal comparison for a rewritten prompt.

## Analysis to freeze before running

- Confusion matrices, accuracy with Wilson intervals, benign and malicious recall, false-positive rate, prediction counts and completion rate.
- Paired accuracy comparisons with a declared multiple-testing family; paired prediction transitions and flip rates reported separately.
- Planned count comparisons: 0 vs 4, 0 vs 10 and 4 vs 10 within dataset and label order. Specify Holm correction and the treatment of any repetitions before requests.
- Reject incomplete or misaligned runs for inferential analysis. Save failure diagnostics separately; avoid silent retries or mixing serving sessions.
- Counterbalance/randomize execution blocks or repeat conditions to assess time/batch effects; freeze the chosen schedule and budget first.
- Report descriptive pilot results without claims of deployment readiness or broad generalization. Balanced-sample accuracy does not describe natural deployment prevalence.

Final-layer embeddings and geometric analysis remain follow-on work; the classification pilot did not collect them.
