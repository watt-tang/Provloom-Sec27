#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


EXPECTED_OUTCOMES = {
    "confirmed_violation": 398,
    "benign_lookalike": 179,
    "trusted_allowed": 120,
    "review_coverage": 79,
}


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "provbench")
    rows = [
        json.loads(line)
        for line in (root / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    errors: list[str] = []

    if len(rows) != 776:
        errors.append(f"total={len(rows)} expected=776")

    by_outcome = Counter(row.get("expected_policy_outcome") for row in rows)
    if dict(by_outcome) != EXPECTED_OUTCOMES:
        errors.append(f"outcomes={dict(by_outcome)} expected={EXPECTED_OUTCOMES}")

    for key, expected in {
        "multi_file": 199,
        "llm_mediated": 316,
        "network_or_external": 579,
    }.items():
        actual = sum(1 for row in rows if row.get(key))
        if actual != expected:
            errors.append(f"{key}={actual} expected={expected}")

    pairs: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        pid = row.get("counterfactual_pair_id")
        if pid:
            pairs[pid].append(row)
        for key in ["sample_path", "fixture_path", "ground_truth_path"]:
            path = root / row[key]
            if not path.exists():
                errors.append(f"missing {key} for {row.get('sample_id')}: {path}")

    complete_pairs = 0
    for members in pairs.values():
        outcomes = sorted(member.get("expected_policy_outcome") for member in members)
        if outcomes == ["benign_lookalike", "confirmed_violation"]:
            complete_pairs += 1
    if complete_pairs != 142:
        errors.append(f"complete_counterfactual_pairs={complete_pairs} expected=142")

    if errors:
        print("ProvBench validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("ProvBench validation passed")
    print(f"total={len(rows)}")
    print(f"outcomes={dict(by_outcome)}")
    print("complete_counterfactual_pairs=142")
    print("multi_file=199 llm_mediated=316 network_or_external=579")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
