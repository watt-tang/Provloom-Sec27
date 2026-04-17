from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.backend.log_writer import ExecutionLogWriter


def main() -> int:
    log_dir = REPO_ROOT / "Log"
    writer = ExecutionLogWriter(log_dir=str(log_dir))
    renamed: list[dict[str, str]] = []

    for path in sorted(log_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        execution_id = payload.get("execution_id")
        request = payload.get("request") or {}
        if not execution_id:
            continue
        target = writer.get_log_path(execution_id, request)
        if path == target:
            continue
        if target.exists():
            path.unlink()
            continue
        path.rename(target)
        renamed.append({"from": str(path.name), "to": str(target.name)})

    print(json.dumps({"renamed": renamed, "count": len(renamed)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
