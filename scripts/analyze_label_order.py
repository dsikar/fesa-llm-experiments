#!/usr/bin/env python3
"""Analyze complete private issue-3 evidence; emit only aggregate counts/metrics."""
import argparse
import json
from pathlib import Path

from label_order import analyze


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True, help='Frozen private registration JSON')
    parser.add_argument('--registered-manifest-sha256', required=True, help='Canonical manifest digest saved privately BEFORE collection')
    parser.add_argument('--predictions', type=Path, required=True, help='Private query response JSONL, including failure records')
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text())
        rows = [json.loads(line) for line in args.predictions.read_text().splitlines() if line.strip()]
        result = analyze(manifest, rows, registered_manifest_sha256=args.registered_manifest_sha256)
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, 'Analysis rejected: invalid, incomplete or mismatched private evidence. Retain diagnostics privately; inspect using the offline library.\n')
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
