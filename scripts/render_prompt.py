#!/usr/bin/env python3
"""Render an exact prompt offline and save it only in ignored private storage."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from fesa_prompts import render_prompt, save_private_prompt


def read_json(path):
    path = Path(path)
    if path.stat().st_size > 2_000_000:
        raise ValueError("input is too large for a prompt record")
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=("phishing", "malware"), required=True)
    parser.add_argument("--input", required=True, help="local JSON record with a features mapping")
    parser.add_argument("--demonstrations", help="local JSON list of 4 or 10 labelled records")
    parser.add_argument("--label-order", choices=("A", "B"), default="A")
    args = parser.parse_args()
    try:
        query = read_json(args.input)
        examples = read_json(args.demonstrations) if args.demonstrations else []
        if not isinstance(examples, list):
            raise ValueError("demonstrations must be a JSON list")
        bundle = render_prompt(args.dataset, query, examples, args.label_order)
        path = save_private_prompt(bundle)
    except (ValueError, OSError, KeyError) as exc:
        # JSON decoding errors can contain record fragments; suppress their details.
        if isinstance(exc, json.JSONDecodeError):
            raise SystemExit("Invalid local JSON input") from None
        raise SystemExit(f"Prompt rendering failed: {exc}") from None
    print(f"Saved exact prompt privately: {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
