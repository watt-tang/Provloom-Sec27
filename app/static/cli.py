from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from app.static.static_config import StaticAnalysisConfig
from app.static.static_report import StaticAnalysisResult, analyze_static_bundle


ARTIFACTS_ROOT = Path("artifacts/static-runs")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="provloom static", description="ProvLoom static instruction analysis CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="analyze static skill artifacts")
    run_p.add_argument("skill_path")
    run_p.add_argument("--skill-file", default="SKILL.md")
    run_p.add_argument("--run-id", default="")
    run_p.add_argument("--config", default="")

    artifacts_p = sub.add_parser("artifacts", help="print loaded/ignored artifact records")
    artifacts_p.add_argument("run_id")

    actions_p = sub.add_parser("actions", help="print extracted grounded actions")
    actions_p.add_argument("run_id")

    entities_p = sub.add_parser("entities", help="print resolved static entities")
    entities_p.add_argument("run_id")

    graph_p = sub.add_parser("graph", help="print instruction provenance graph")
    graph_p.add_argument("run_id")
    graph_p.add_argument("--summary", action="store_true")

    explain_p = sub.add_parser("explain", help="print static chains and explanations")
    explain_p.add_argument("run_id")

    validate_p = sub.add_parser("validate-config", help="validate static analysis config")
    validate_p.add_argument("--config", default="")

    export_p = sub.add_parser("export", help="export a saved static report")
    export_p.add_argument("run_id")
    export_p.add_argument("--format", choices=["json", "md"], default="json")

    args = parser.parse_args(argv)
    if args.command == "run":
        return _run(args)
    if args.command == "artifacts":
        return _print_json(_load(args.run_id).get("static_artifacts_v2", []))
    if args.command == "actions":
        return _print_json(_load(args.run_id).get("extracted_actions", []))
    if args.command == "entities":
        return _print_json(_load(args.run_id).get("resolved_entities", []))
    if args.command == "graph":
        graph = _load(args.run_id).get("instruction_provenance_graph", {})
        return _print_json(graph.get("summary", {}) if args.summary else graph)
    if args.command == "explain":
        return _print_json(_load(args.run_id).get("static_chains", []))
    if args.command == "validate-config":
        config = StaticAnalysisConfig.load(args.config)
        errors = config.validate()
        print(json.dumps({"valid": not errors, "errors": errors, "config": config.to_dict()}, ensure_ascii=False, indent=2))
        return 0 if not errors else 1
    if args.command == "export":
        return _export(args.run_id, args.format)
    return 2


def _run(args) -> int:
    config = StaticAnalysisConfig.load(args.config)
    errors = config.validate()
    if errors:
        print(json.dumps({"status": "invalid_config", "errors": errors}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    run_id = args.run_id or f"STATIC-{uuid.uuid4().hex[:12]}"
    result = analyze_static_bundle(args.skill_path, args.skill_file, config=config)
    output_dir = ARTIFACTS_ROOT / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_result(result, output_dir)
    print(
        json.dumps(
            {
                "run_id": run_id,
                "artifacts_dir": str(output_dir),
                "review_priority": result.static_analysis_summary.get("review_priority", "informational"),
                "chain_status_counts": result.static_analysis_summary.get("chain_status_counts", {}),
                "coverage_states": result.static_coverage.states,
                "static_chain_count": len(result.static_chains),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _write_result(result: StaticAnalysisResult, output_dir: Path) -> None:
    payload = result.to_dict()
    (output_dir / "static-analysis.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "static-explanation.md").write_text(result.to_markdown(), encoding="utf-8")
    (output_dir / "instruction-provenance-graph.json").write_text(
        json.dumps(payload["instruction_provenance_graph"], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _load(run_id: str) -> dict[str, Any]:
    path = ARTIFACTS_ROOT / run_id / "static-analysis.json"
    if not path.exists():
        raise SystemExit(f"static analysis artifact not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _export(run_id: str, fmt: str) -> int:
    payload = _load(run_id)
    if fmt == "json":
        return _print_json(payload)
    print((ARTIFACTS_ROOT / run_id / "static-explanation.md").read_text(encoding="utf-8"))
    return 0


def _print_json(payload: Any) -> int:
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
