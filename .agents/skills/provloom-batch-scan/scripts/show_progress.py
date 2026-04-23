#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Show progress for the latest ProvLoom batch scan.")
    parser.add_argument("--log-dir", default="/mnt/e/log3")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    progress_path = Path(args.log_dir).expanduser().resolve() / "progress.json"
    if not progress_path.exists():
        print(f"Progress file not found: {progress_path}", file=sys.stderr)
        return 2

    data = json.loads(progress_path.read_text(encoding="utf-8"))
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0

    totals = data.get("totals", {})
    active_count = len(data.get("active_skills", []))
    print(
        f"{data.get('status')} | {data.get('phase')} | "
        f"done {totals.get('processed', 0)}/{totals.get('discovered', 0)} | "
        f"completed {totals.get('completed', 0)} | "
        f"skipped {totals.get('skipped', 0)} | "
        f"failed {totals.get('failed', 0)} | "
        f"active {active_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
