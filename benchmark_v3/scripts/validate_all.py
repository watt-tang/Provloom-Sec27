#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

def run(cmd):
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode

def main():
    if len(sys.argv) != 2:
        print("usage: validate_all.py <benchmark_v3>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    helper = Path("/root/.codex/skills/benchmark-v3-author/scripts")
    rows = [json.loads(line) for line in (root / "manifest.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    failures = 0
    for row in rows:
        failures += run([str(helper / "validate_sample.py"), str(root), row["sample_id"]]) != 0
    failures += run([str(helper / "validate_ground_truth.py"), str(root)]) != 0
    failures += run([str(helper / "validate_safety.py"), str(root)]) != 0
    failures += run([str(root / "scripts" / "check_distribution.py"), str(root)]) != 0
    if failures:
        print(f"validation failed: {failures} failing checks")
        return 1
    print(f"validation passed: {len(rows)} samples")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
