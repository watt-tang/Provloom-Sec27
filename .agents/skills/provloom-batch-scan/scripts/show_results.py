#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Show recent results for the latest ProvLoom batch scan.")
    parser.add_argument("--log-dir", default="/mnt/e/log3")
    parser.add_argument("--tail", type=int, default=5)
    parser.add_argument("--summary", action="store_true")
    return parser.parse_args()


def load_results(results_path: Path) -> list[dict]:
    rows: list[dict] = []
    if not results_path.exists():
        return rows
    for line in results_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def main() -> int:
    args = parse_args()
    log_dir = Path(args.log_dir).expanduser().resolve()
    results_path = log_dir / "results.jsonl"
    rows = load_results(results_path)
    if not rows:
        print(f"No results found in: {results_path}", file=sys.stderr)
        return 2

    if args.summary:
        status_counts: dict[str, int] = {}
        for row in rows:
            status = row.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
        print(json.dumps({"count": len(rows), "status_counts": status_counts}, ensure_ascii=False, indent=2))
        return 0

    tail_count = max(1, args.tail)
    for row in rows[-tail_count:]:
        print(
            json.dumps(
                {
                    "finished_at": row.get("finished_at"),
                    "status": row.get("status"),
                    "risk_level_name": row.get("risk_level_name"),
                    "risk_score": row.get("risk_score"),
                    "name": row.get("name"),
                    "skill_root": row.get("skill_root"),
                },
                ensure_ascii=False,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
