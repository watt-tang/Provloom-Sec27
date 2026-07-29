#!/usr/bin/env python3
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

def main():
    if len(sys.argv) != 2:
        print("usage: freeze_split.py <benchmark_v3>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    rows = [json.loads(line) for line in (root / "manifest.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    grouped = defaultdict(list)
    for row in rows:
        key = row.get("counterfactual_pair_id") or row.get("scenario_family") or row["sample_id"]
        grouped[key].append(row["sample_id"])
    split_rows = {"development": [], "blind-heldout": [], "challenge-heldout": []}
    for key in sorted(grouped):
        bucket = hashlib.sha256(key.encode("utf-8")).hexdigest()
        target = "development" if int(bucket[:2], 16) < 39 else "blind-heldout" if int(bucket[:2], 16) < 193 else "challenge-heldout"
        split_rows[target].extend(sorted(grouped[key]))
    for name, ids in split_rows.items():
        (root / "splits" / f"{name}.txt").write_text("".join(f"{sid}\n" for sid in sorted(ids)), encoding="utf-8")
    digest = hashlib.sha256()
    for name in ["development", "blind-heldout", "challenge-heldout"]:
        digest.update((root / "splits" / f"{name}.txt").read_bytes())
    print(json.dumps({"split_hash": digest.hexdigest(), "counts": {k: len(v) for k, v in split_rows.items()}}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
