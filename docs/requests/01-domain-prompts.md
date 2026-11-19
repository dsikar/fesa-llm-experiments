# Use domain-correct prompts and documented feature definitions

## Problem

The previous malware conditions used website/phishing wording, and feature encodings were not explained. A demonstration-count experiment needs a fixed, documented input specification.

## Work

- [x] Add separate phishing and executable-file classification templates.
- [x] Verify feature meanings and encodings against dataset documentation; record sources and uncertainties.
- [x] Audit identifiers and fields derived from security-tool verdicts for leakage and prediction-time availability.
- [x] Freeze a primary feature set; remove identifiers and unsupported/label-derived features from the primary prompt or document a justified separate condition.
- [x] Record template versions and exact rendered prompts privately.
- [x] Add synthetic prompt tests checking correct domain wording and that query labels never enter the prompt.

## Acceptance

Reviewed templates, sourced feature dictionary, declared feature exclusions, synthetic tests and a frozen configuration linked from the experiment plan. No real records or sample hashes in public fixtures. Retain old pilot results as historical references.

## Dependencies

Coordinate with steps 3 and 5; complete before step 2 collects responses.

## Delivery

[Implementation and validation](../ISSUE_1_DELIVERY.md). The audit supports a conservative 8-field phishing / 12-field malware configuration; unresolved encodings are excluded rather than guessed. Dataset lineage and fresh splits remain step 4. No new inference results are claimed.
