from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.instruction.orchestrator import analyze_instruction_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Run deterministic static instruction-analysis benchmark cases.")
    parser.add_argument("--cases-root", default="benchmark_instruction/cases")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    cases_root = Path(args.cases_root)
    rows = [run_case(case_dir) for case_dir in sorted(cases_root.iterdir()) if case_dir.is_dir()]
    summary = {
        "case_count": len(rows),
        "passed": sum(1 for row in rows if row["passed"]),
        "failed": sum(1 for row in rows if not row["passed"]),
        "cases": rows,
    }
    payload = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if summary["failed"] == 0 else 1


def run_case(case_dir: Path) -> dict[str, Any]:
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    result = analyze_instruction_bundle(case_dir)
    validated = {path.path_type for path in result.validated_paths}
    partial = {path.path_type for path in result.partial_paths}
    expected_validated = set(expected.get("validated_paths", []))
    expected_absent = set(expected.get("absent_validated_paths", []))
    expected_partial = set(expected.get("partial_paths", []))
    requires_abstention = bool(expected.get("requires_abstention", False))
    failures: list[str] = []
    if not expected_validated <= validated:
        failures.append(f"missing_validated={sorted(expected_validated - validated)}")
    if expected_absent & validated:
        failures.append(f"unexpected_validated={sorted(expected_absent & validated)}")
    if not expected_partial <= partial:
        failures.append(f"missing_partial={sorted(expected_partial - partial)}")
    if requires_abstention and not result.abstention_reasons:
        failures.append("missing_abstention")
    return {
        "case_id": case_dir.name,
        "passed": not failures,
        "failures": failures,
        "validated_paths": sorted(validated),
        "partial_paths": sorted(partial),
        "abstention_reasons": result.abstention_reasons,
        "risk_status": result.summary.get("risk_status"),
        "risk_level": result.summary.get("risk_level"),
    }


if __name__ == "__main__":
    raise SystemExit(main())
