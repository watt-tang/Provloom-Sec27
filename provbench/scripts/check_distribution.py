#!/usr/bin/env python3
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

def main():
    if len(sys.argv) != 2:
        print("usage: check_distribution.py <provbench>", file=sys.stderr)
        return 2
    rows = []
    manifest = Path(sys.argv[1]) / "manifest.jsonl"
    if manifest.exists():
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    pair_outcomes = defaultdict(set)
    for row in rows:
        pair_id = row.get("counterfactual_pair_id")
        if pair_id:
            pair_outcomes[pair_id].add(row.get("expected_policy_outcome"))
    report = {
        "total": len(rows),
        "by_family": dict(Counter(r["risk_family"] for r in rows)),
        "by_outcome": dict(Counter(r["expected_policy_outcome"] for r in rows)),
        "multi_file": sum(r.get("multi_file", False) for r in rows),
        "llm_mediated": sum(r.get("llm_mediated", False) for r in rows),
        "network_or_external": sum(r.get("network_or_external", False) for r in rows),
        "counterfactual_pairs": len({r.get("counterfactual_pair_id") for r in rows if r.get("counterfactual_pair_id")}),
        "complete_counterfactual_pairs": sum(
            {"confirmed_violation", "benign_lookalike"}.issubset(outcomes)
            for outcomes in pair_outcomes.values()
        ),
    }
    out = Path(sys.argv[1]) / "reports" / "distribution-report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
