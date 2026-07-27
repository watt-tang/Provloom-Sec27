from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.static.failure_attribution import FailureAttributor
from app.static.static_config import StaticAnalysisConfig
from app.static.static_report import analyze_static_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Attribute false negatives from a Static deterministic evaluation report.")
    parser.add_argument("--eval-report", required=True)
    parser.add_argument("--config", default="")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--output-md", default="")
    parser.add_argument("--report-only", action="store_true", help="attribute from saved evaluation rows without re-running the analyzer")
    args = parser.parse_args()

    report = json.loads(Path(args.eval_report).read_text(encoding="utf-8"))
    config = StaticAnalysisConfig.load(args.config)
    config.llm_enabled = False
    attributor = FailureAttributor()
    rows = [row for row in report.get("per_sample", []) if row.get("label") == "malicious" and not row.get("predicted_violation")]
    attributions = []
    for row in rows:
        payload: dict[str, Any] = {}
        if not args.report_only:
            try:
                payload = analyze_static_bundle(row["skill_path"], config=config).to_dict()
            except Exception as exc:
                row = {**row, "coverage_states": ["analysis_error"], "analysis_error": str(exc)}
        attributions.append(attributor.attribute(row, payload).to_dict())
    output = {"summary": _summary(attributions), "attributions": attributions}
    if args.output_json:
        Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_json).write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.output_md:
        Path(args.output_md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_md).write_text(_markdown(output), encoding="utf-8")
    print(json.dumps(output["summary"], ensure_ascii=False, indent=2))
    return 0


def _summary(attributions: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(attributions)
    by_reason = Counter(item["primary_failure_reason"] for item in attributions)
    by_component = Counter(item["recommended_component"] for item in attributions)
    table: dict[str, dict[str, Any]] = {}
    for reason, count in by_reason.items():
        group = [item for item in attributions if item["primary_failure_reason"] == reason]
        vectors = Counter(item["attack_vector"] for item in group)
        table[reason] = {
            "count": count,
            "percentage": count / total if total else 0.0,
            "CI": vectors.get("CI", 0),
            "PI": vectors.get("PI", 0),
            "MIXED": vectors.get("MIXED", 0),
            "unknown": vectors.get("unknown", 0),
            "representative_cases": [item["skill_id"] for item in group[:5]],
        }
    return {
        "false_negative_count": total,
        "failure_reason_distribution": table,
        "recommended_component_counts": dict(by_component),
        "attack_vector_counts": dict(Counter(item["attack_vector"] for item in attributions)),
        "behavior_counts": dict(Counter(item["behavior_id"] for item in attributions)),
    }


def _markdown(output: dict[str, Any]) -> str:
    summary = output["summary"]
    lines = ["# Static False Negative Attribution", "", f"- False negatives: `{summary['false_negative_count']}`", "", "## Failure Reasons", "", "| Failure reason | Count | Percentage | CI | PI | MIXED |", "|---|---:|---:|---:|---:|---:|"]
    for reason, row in sorted(summary["failure_reason_distribution"].items(), key=lambda item: (-item[1]["count"], item[0])):
        lines.append(f"| `{reason}` | {row['count']} | {row['percentage']:.2%} | {row['CI']} | {row['PI']} | {row['MIXED']} |")
    lines.extend(["", "## Representative Cases", ""])
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in output["attributions"]:
        grouped[item["primary_failure_reason"]].append(item)
    for reason, items in sorted(grouped.items()):
        lines.append(f"### {reason}")
        for item in items[:5]:
            lines.append(f"- `{item['skill_id']}` vector=`{item['attack_vector']}` behavior=`{item['behavior_id']}` component=`{item['recommended_component']}` stage=`{item['highest_recovered_stage']}`")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
