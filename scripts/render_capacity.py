#!/usr/bin/env python3
"""Render the capacity results table from validated JSON.

The planning inventory and the synthetic fixture are not observed results.
`results/public/capacity-results.json` is reserved for a later reviewed aggregate.
"""

import argparse
import json
import sys
from pathlib import Path

from capacity_contract import (
    CapacityContractError,
    render_table,
    synthetic_public_aggregate,
    validate_aggregate,
    validate_planning_inventory,
)

ROOT = Path(__file__).resolve().parent.parent


def load_document(path):
    document = json.loads(Path(path).read_text())
    if document.get("artifact_type") == "planning_inventory":
        validate_planning_inventory(document)
    else:
        validate_aggregate(document)
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description="Render a capacity results table.")
    parser.add_argument("source", nargs="?", help="Aggregate or planning JSON")
    parser.add_argument("--synthetic", action="store_true", help="Render the labelled synthetic fixture")
    parser.add_argument("--planning", action="store_true", help="Render results/public/capacity-plan.json")
    parser.add_argument("--check", type=Path, help="Fail when this Markdown file differs from the render")
    args = parser.parse_args(argv)
    selected = sum(bool(item) for item in (args.source, args.synthetic, args.planning))
    if selected != 1:
        parser.error("pass exactly one of SOURCE, --synthetic or --planning")
    if args.synthetic:
        document = synthetic_public_aggregate()
    elif args.planning:
        document = load_document(ROOT / "results/public/capacity-plan.json")
    else:
        document = load_document(args.source)
    rendered = render_table(document)
    if args.check:
        actual = args.check.read_text() if args.check.is_file() else ""
        if actual != rendered:
            raise SystemExit("capacity table differs from the generated render")
        print(f"Capacity table matches {args.check}.")
        return
    sys.stdout.write(rendered)


if __name__ == "__main__":
    try:
        main()
    except CapacityContractError as exc:
        raise SystemExit(f"capacity contract: {exc}") from exc
