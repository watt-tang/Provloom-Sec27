from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from app.analyzer.rules import analyze_trace
from app.backend.schemas import LLMConfig
from app.dynamic.analyzer import DynamicRuntimeAnalyzer, persist_dynamic_analysis
from app.dynamic.config import DynamicAnalysisConfig
from app.runner.docker_runner import DockerRunner
from app.telemetry.collector import build_execution_report
from app.telemetry.normalizer import build_normalized_events


ARTIFACTS_ROOT = Path("artifacts/runs")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="provloom dynamic", description="ProvLoom dynamic runtime analysis CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run a skill in the Docker sandbox")
    run_p.add_argument("skill_path")
    run_p.add_argument("--run-id", default="")
    run_p.add_argument("--config", default="")
    run_p.add_argument("--timeout-seconds", type=int, default=30)
    run_p.add_argument("--network-policy", choices=["default", "disabled"], default="default")
    run_p.add_argument("--input", default="{}")

    trace_p = sub.add_parser("trace", help="print canonical runtime events for a run")
    trace_p.add_argument("run_id")

    graph_p = sub.add_parser("graph", help="print runtime provenance graph summary")
    graph_p.add_argument("run_id")

    explain_p = sub.add_parser("explain", help="print recovered runtime chains")
    explain_p.add_argument("run_id")

    validate_p = sub.add_parser("validate-config", help="validate dynamic analysis config")
    validate_p.add_argument("--config", default="")

    export_p = sub.add_parser("export", help="export dynamic report")
    export_p.add_argument("run_id")
    export_p.add_argument("--format", choices=["json", "md"], default="json")

    args = parser.parse_args(argv)
    if args.command == "run":
        return _run(args)
    if args.command == "trace":
        return _print_json(_load_dynamic(args.run_id).get("runtime_events", []))
    if args.command == "graph":
        return _print_json(_load_dynamic(args.run_id).get("runtime_provenance_graph", {}).get("summary", {}))
    if args.command == "explain":
        return _print_json(_load_dynamic(args.run_id).get("runtime_chains", []))
    if args.command == "validate-config":
        config = DynamicAnalysisConfig.load(args.config)
        errors = config.validate()
        print(json.dumps({"valid": not errors, "errors": errors, "config": config.to_dict()}, ensure_ascii=False, indent=2))
        return 0 if not errors else 1
    if args.command == "export":
        return _export(args.run_id, args.format)
    return 2


def _run(args) -> int:
    config = DynamicAnalysisConfig.load(args.config)
    errors = config.validate()
    if errors:
        print(json.dumps({"status": "invalid_config", "errors": errors}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    run_id = args.run_id or f"RUN-{uuid.uuid4().hex[:12]}"
    input_payload = json.loads(args.input) if args.input.strip().startswith(("{", "[")) else json.loads(Path(args.input).read_text(encoding="utf-8"))
    execution = DockerRunner().run(
        execution_id=run_id,
        skill_path=args.skill_path,
        input_payload=input_payload,
        timeout_seconds=args.timeout_seconds,
        network_policy=args.network_policy,
        llm_config=LLMConfig(enabled=False),
    )
    normalized_events = build_normalized_events(execution)
    dynamic_result = DynamicRuntimeAnalyzer(config=config, skill_root=execution.skill_path).analyze_execution(execution, normalized_events)
    persist_dynamic_analysis(dynamic_result, execution.artifacts_dir)
    report = analyze_trace(execution, analysis_mode="rule_plus_epg", normalized_events=normalized_events, dynamic_result=dynamic_result)
    telemetry = build_execution_report(execution, normalized_events=normalized_events, dynamic_result=dynamic_result)
    output = {
        "run_id": run_id,
        "artifacts_dir": execution.artifacts_dir,
        "exit_code": execution.exit_code,
        "timed_out": execution.timed_out,
        "coverage": dynamic_result.coverage.to_dict(),
        "dynamic_summary": dynamic_result.summary(),
        "legacy_review_priority": report.get("final_decision"),
        "trace_summary": report.get("trace_summary"),
        "telemetry_event_count": len(telemetry.get("normalized_events", [])),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def _load_dynamic(run_id: str) -> dict[str, Any]:
    path = ARTIFACTS_ROOT / run_id / "dynamic-analysis.json"
    if not path.exists():
        raise SystemExit(f"dynamic analysis artifact not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _export(run_id: str, fmt: str) -> int:
    payload = _load_dynamic(run_id)
    if fmt == "json":
        return _print_json(payload)
    print(f"# ProvLoom Dynamic Runtime Explanation: {run_id}\n")
    print(f"- Coverage: {payload.get('coverage', {}).get('coverage_state', 'unknown')}")
    print(f"- Runtime chains: {len(payload.get('runtime_chains', []))}")
    for chain in payload.get("runtime_chains", []):
        print(f"- {chain.get('chain_id')}: {chain.get('explanation')}")
    return 0


def _print_json(payload: Any) -> int:
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
