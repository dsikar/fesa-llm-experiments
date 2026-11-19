"""Offline, versioned domain prompts with a conservative feature allowlist."""
import hashlib
import json
import math
import os
import re
import stat
import string
import tomllib
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FREEZE_FILES = (
    "configs/primary.toml", "configs/features.toml",
    "prompts/phishing-v1.txt", "prompts/malware-v1.txt",
    "fesa_prompts.py", "scripts/render_prompt.py",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_freeze(root=ROOT):
    root = Path(root)
    recorded = {}
    for line in (root / "configs/prompt-v1.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        if name in recorded or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid prompt freeze record")
        recorded[name] = digest
    if set(recorded) != set(FREEZE_FILES):
        raise ValueError("prompt freeze does not cover the expected files")
    for name, digest in recorded.items():
        if sha((root / name).read_bytes()) != digest:
            raise ValueError(f"frozen prompt artifact changed: {name}")
    return recorded


def load_policy(root=ROOT):
    root = Path(root)
    frozen = verify_freeze(root)
    config = tomllib.loads((root / "configs/primary.toml").read_text())
    dictionary = tomllib.loads((root / config["dictionary"]).read_text())
    if config["policy_version"] != dictionary["policy_version"]:
        raise ValueError("policy and dictionary versions differ")
    if set(config["datasets"]) != {"phishing", "malware"}:
        raise ValueError("unexpected dataset domains")
    for dataset, definition in config["datasets"].items():
        entries = [e for e in dictionary["features"] if e["dataset"] == dataset]
        names = [e["name"] for e in entries]
        included = definition["included"]
        if len(set(names)) != len(names) or len(set(included)) != len(included):
            raise ValueError("duplicate feature definitions")
        if set(included) != {e["name"] for e in entries if e["status"] == "include"}:
            raise ValueError("primary configuration and feature dictionary disagree")
    return config, dictionary, frozen


def unsigned(value, bits):
    """Parse exact unsigned decimal/hex data, never arbitrary prompt text."""
    if type(value) is int:
        number = value
    elif type(value) is float:
        if not math.isfinite(value) or not value.is_integer() or abs(value) > 2**53-1:
            raise ValueError("expected a losslessly representable integer")
        number = int(value)
    elif type(value) is str and re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", value.strip()):
        text = value.strip()
        if len(text) > 80:
            raise ValueError("integer representation too long")
        number = int(text, 16 if text.lower().startswith("0x") else 10)
    else:
        raise ValueError("expected an unsigned integer measurement")
    if not 0 <= number < 2**bits:
        raise ValueError("measurement outside its unsigned field width")
    return number


def project_features(record, dataset, config, dictionary):
    if type(record) is not dict or type(record.get("features")) is not dict:
        raise ValueError("expected a record with a features mapping")
    features = record["features"]
    forbidden = {s.casefold() for s in config["forbidden_feature_keys"]}
    if any(not isinstance(k, str) or k.casefold() in forbidden for k in features):
        raise ValueError("target-like key is forbidden inside features")
    entries = {e["name"]: e for e in dictionary["features"] if e["dataset"] == dataset}
    if set(features)-set(entries):
        raise ValueError("unexpected feature names; update the reviewed schema first")
    included = config["datasets"][dataset]["included"]
    if set(included)-set(features):
        raise ValueError("record is missing required primary features")
    projected = {}
    for name in included:
        try:
            projected[name] = unsigned(features[name], entries[name]["bits"])
        except ValueError:
            # Do not echo raw values into errors or public logs.
            raise ValueError(f"invalid measurement for {name}") from None
    return projected, sorted(set(features)-set(included))


def render_prompt(dataset, query, demonstrations=(), label_order="A", root=ROOT):
    if dataset not in {"phishing", "malware"} or label_order not in {"A", "B"}:
        raise ValueError("unknown domain or label order")
    config, dictionary, frozen = load_policy(root)
    if len(demonstrations) not in config["demonstration_counts"]:
        raise ValueError("expected 0, 4 or 10 demonstrations")
    projected, excluded = project_features(query, dataset, config, dictionary)
    rows, labels = [], []
    seen = {json.dumps(projected, sort_keys=True)}
    omitted = {"query": excluded, "demonstrations": []}
    for example in demonstrations:
        label = example.get("label") if type(example) is dict else None
        if type(label) is not int or label not in (0, 1):
            raise ValueError("each demonstration requires an explicit binary label")
        features, dropped = project_features(example, dataset, config, dictionary)
        fingerprint = json.dumps(features, sort_keys=True)
        if fingerprint in seen:
            raise ValueError("duplicate primary feature vectors in query/demonstrations")
        seen.add(fingerprint)
        rows.append(features)
        labels.append(label)
        omitted["demonstrations"].append(dropped)
    if labels and labels.count(0) != labels.count(1):
        raise ValueError("demonstrations must be class-balanced")
    definition = config["datasets"][dataset]
    entries = {e["name"]: e for e in dictionary["features"] if e["dataset"] == dataset}
    definitions = "\n".join(f"{name}: {entries[name]['definition']}" for name in definition["included"])
    def measurements(values):
        return "\n".join(f"{name} = {values[name]}" for name in definition["included"])
    examples = ""
    if rows:
        examples = "Labeled examples:\n"+"\n\n".join(
            f"Example {i+1}:\n{measurements(row)}\nAnswer: {label}"
            for i, (row, label) in enumerate(zip(rows, labels)))+"\n\n"
    template = string.Template((Path(root) / definition["template"]).read_text())
    prompt = template.substitute(label_clause=definition[f"label_order_{label_order.lower()}"],
                                 definitions=definitions, examples=examples,
                                 query_features=measurements(projected))
    return {"schema_version": 1, "policy_version": config["policy_version"],
            "template_version": config["template_version"], "dataset": dataset,
            "label_order": label_order, "demonstration_count": len(rows),
            "demonstration_labels": labels, "frozen_artifact_sha256": frozen,
            "excluded_feature_names": omitted,
            "prompt_sha256": sha(prompt.encode()), "prompt": prompt}


def save_private_prompt(bundle, root=ROOT):
    """Write one immutable private bundle with owner-only access."""
    root = Path(root).resolve()
    if sha(bundle["prompt"].encode()) != bundle["prompt_sha256"]:
        raise ValueError("prompt digest mismatch")
    directory = root
    for part in ("private", "prompts"):
        directory = directory / part
        if directory.is_symlink():
            raise ValueError("private artifact directories cannot be symlinks")
        directory.mkdir(mode=0o700, exist_ok=True)
        if stat.S_IMODE(directory.stat().st_mode) & 0o077:
            raise ValueError("private artifact directories must have owner-only permissions")
    target = directory / f"{uuid.uuid4().hex}.json"
    content = (json.dumps(bundle, indent=2, allow_nan=False)+"\n").encode()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target
