#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def main():
    if len(sys.argv) != 3:
        print("usage: replay_sample.py <benchmark_v3> <sample_id>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    sid = sys.argv[2]
    fixture = json.loads((root / "fixtures" / sid / "fixture.json").read_text(encoding="utf-8"))
    replay = fixture["replay_expectation"]
    result = {
        "sample_id": sid,
        "exit_code": replay.get("exit_code", 0),
        "timeout": replay.get("timeout", False),
        "observed_operations": replay.get("observed_operations", []),
        "fixture_mutations": replay.get("fixture_mutations", []),
        "mock_network_records": replay.get("mock_network_records", []),
        "coverage_condition": replay.get("coverage_condition", "covered"),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
