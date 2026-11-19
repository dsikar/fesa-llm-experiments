#!/usr/bin/env python3
"""Check tracked text for likely credentials, private paths and raw artifacts."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = {
    "GitHub credential": r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{30,})\b",
    "cloud access key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "private key": r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    "credential assignment": r"(?im)^\s*(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{12,}['\"]",
    "private absolute path": r"/(?:home|users|mnt/scratch/users)/[A-Za-z0-9_.-]+",
    "cluster account": r"\baczd\d+\b",
    "internal node": r"\b(?:gpu|login)\d+(?:\.[A-Za-z0-9.-]+)?\b",
    "private address": r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
    "personal email": r"\b[A-Za-z0-9._%+-]+@(?!users\.noreply\.github\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
}


def findings(path, text):
    path = Path(path)
    errors = [name for name, pattern in RULES.items() if re.search(pattern, text)]
    if path.parts[0] in {"data", "private", "local", "runs", "logs", "audit-artifacts"}:
        errors.append("private artifact directory")
    if path.suffix.lower() in {".pt", ".pth", ".npy", ".npz", ".safetensors", ".arff", ".jsonl", ".csv", ".bin", ".exe", ".dll", ".log", ".pem", ".key"}:
        errors.append("raw/binary artifact extension")
    if path.suffix.lower() == ".json" and path.parts[:2] != ("results", "public"):
        errors.append("unreviewed JSON location")
    return errors


def main():
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    paths = [p.decode() for p in result.stdout.split(b"\0") if p]
    if not paths:
        raise SystemExit("No tracked files to review")
    errors = []
    for name in paths:
        content = subprocess.run(["git", "show", f":{name}"], cwd=ROOT,
                                 capture_output=True, text=True, check=True).stdout
        errors += [f"{name}: {rule}" for rule in findings(name, content)]
    if errors:
        raise SystemExit("Public-tree check failed:\n"+"\n".join(errors))
    print(f"Public-tree checks passed for {len(paths)} tracked text files; manual review still required.")


if __name__ == "__main__":
    main()
