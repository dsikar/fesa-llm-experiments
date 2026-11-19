# Publication boundary

This repository is a curated public export, separate from the private experiment workspace.

Included:

- Research plans, issue specifications and generic scheduler instructions.
- Aggregate counts, metrics, confidence intervals and paired-test contingency counts.
- A deterministic aggregate verifier and synthetic tests.

Excluded:

- Source datasets, sampled records, row identities and file hashes identifying individual records.
- Exact prompts containing real feature records, raw model responses and embeddings.
- API keys, authentication files, private keys and environment files.
- Internal hostnames, endpoint addresses, account identifiers, job IDs, local paths and infrastructure manifests.
- Unfiltered logs, private worklogs, archived patches and private audit documents.

The public aggregate JSON is projected onto an explicit set of fields. It is not a copy of the private analysis file. Public checks recompute metrics from aggregate counts; they cannot independently establish row pairing or rerun private-data inference.

The capacity contract uses the same rule. `scripts/capacity_contract.py` exports an allowlist. Schemas live in `schemas/` and are tracked by exact path. `tests/fixtures/capacity/synthetic-aggregate.json` is a labelled fixture, not an observed result. `results/public/capacity-results.json` stays ignored until a reviewed observed aggregate is published. Private run directories, JSONL prediction logs and dataset files stay ignored.

Before publishing a change:

1. Review the staged diff and file list.
2. Run the offline tests, baseline verifier and public-tree checker.
3. Review any new artifact for data/credential disclosure and redistribution terms. The automated checker is an additional check, not proof that arbitrary content is safe.

Dataset acquisition, licensing and feature provenance must be documented before future data releases. No third-party dataset is redistributed here. Public results should retain their limitations and links to the experiment's issue and code revision.
