from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.reporting.risk_mapper import enrich_log_payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill Log JSON files with human-readable risk fields.")
    parser.add_argument("target", nargs="?", default=str(REPO_ROOT / "Log"))
    args = parser.parse_args()

    target = Path(args.target).resolve()
    files = sorted(target.glob("*.json")) if target.is_dir() else [target]

    updated = 0
    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        enriched = enrich_log_payload(payload)
        path.write_text(json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8")
        updated += 1

    print(json.dumps({"updated": updated, "target": str(target)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
