# Save immutable experiment evidence and publish reviewed aggregates

## Problem

Each result needs a traceable link to its condition, input split, prompt, model and code. Public release must exclude sensitive records and infrastructure details.

## Work

- [ ] Define run/condition/row identifiers and schema before inference.
- [ ] Privately save exact rendered prompts, demonstration identities, raw responses, parsed predictions, ground truth, correctness, failures and decoding settings.
- [ ] Record model/tokenizer revisions, code commit, seeds, template/config versions, execution schedule and private artifact hashes.
- [ ] Write atomically; separate failed attempts; validate completeness, pairing, model/session and configuration before analysis or resume.
- [ ] Preserve earlier runs; do not silently overwrite outputs or retry across sessions.
- [ ] Link GitHub issues, implementation commits, frozen design and run reports; record plan amendments before collection.
- [ ] Add an allowlist-based aggregate exporter, disclosure checks and synthetic public tests.
- [ ] Publish all planned condition summaries, confusion matrices, uncertainty and paired comparisons, including null findings and failed-condition status.

## Acceptance

A synthetic end-to-end run demonstrates capture, failure handling, resume validation, offline verification and aggregate export. A public artifact links back to its issue and code revision while revealing no raw records, sample identifiers, credentials, internal addresses or local paths. Audit/commit dates must distinguish prospective registration from retrospective publication.

This issue covers classification evidence. Final-layer embedding collection remains separate follow-on work and must not be reported as already completed.

## Dependencies

Required infrastructure for steps 1–4 before new model requests.
