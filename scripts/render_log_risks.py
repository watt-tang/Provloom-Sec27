from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.reporting.risk_mapper import enrich_log_payload


def render_log(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload = enrich_log_payload(payload)
    result = payload.get("result") or {}
    return {
        "execution_id": payload.get("execution_id"),
        "status": payload.get("status"),
        "risk_score": result.get("risk_score"),
        "risk_level_name": result.get("risk_level_name"),
        "primary_risk": (result.get("primary_risk") or {}).get("name"),
        "risk_summary": result.get("risk_summary"),
        "risk_names": [item.get("name") for item in result.get("risk_labels", [])],
        "log_file": str(path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Render Log/*.json into a human-readable risk summary.")
    parser.add_argument("targets", nargs="*", help="Log JSON files or directories. Defaults to ./Log")
    args = parser.parse_args()

    targets = args.targets or [str(REPO_ROOT / "Log")]
    files: list[Path] = []
    for raw_target in targets:
        path = Path(raw_target).resolve()
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            files.append(path)

    summaries = [render_log(path) for path in files]
    print(json.dumps({"count": len(summaries), "logs": summaries}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
