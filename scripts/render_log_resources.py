from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def render_log(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = payload.get("result") or {}
    resources = result.get("resource_usage") or {}
    return {
        "execution_id": payload.get("execution_id"),
        "status": payload.get("status"),
        "memory_limit": resources.get("memory_limit_bytes"),
        "memory_limit_human": _format_bytes(resources.get("memory_limit_bytes")),
        "memory_peak": resources.get("memory_peak_bytes"),
        "memory_peak_human": resources.get("memory_peak_human"),
        "writable_layer_human": resources.get("writable_layer_human"),
        "skill_bundle_human": resources.get("skill_bundle_human"),
        "artifacts_human": resources.get("artifacts_human"),
        "estimated_total_disk_human": resources.get("estimated_total_disk_human"),
        "log_file": str(path),
    }


def _format_bytes(value: int | None) -> str | None:
    if value is None:
        return None
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Render container memory and disk usage from Log JSON files.")
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
