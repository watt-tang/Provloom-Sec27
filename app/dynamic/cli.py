from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from app.analysis.pipeline import ExecutionConfig, analyze_skill_bundle
from app.backend.schemas import LLMConfig
from app.dynamic.analyzer import DynamicRuntimeAnalyzer, persist_dynamic_analysis
from app.dynamic.config import DynamicAnalysisConfig
from app.runner.docker_runner import DEFAULT_SANDBOX_IMAGE, DockerRunner
from app.runner.timeout_config import resolve_total_timeout
from app.static.static_report import analyze_static_bundle
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
    run_p.add_argument("--timeout-seconds", type=int, default=None)
    run_p.add_argument("--network-policy", choices=["default", "disabled"], default="default")
    run_p.add_argument("--image-name", default=DEFAULT_SANDBOX_IMAGE)
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
    timeout_resolution = resolve_total_timeout(args.timeout_seconds)
    analysis = analyze_skill_bundle(
        args.skill_path,
        execution_config=ExecutionConfig(
            input_payload=input_payload,
            timeout_seconds=timeout_resolution.total_timeout_seconds,
            network_policy=args.network_policy,
            analysis_mode="rule_plus_epg",
            llm_config=LLMConfig(enabled=False),
            run_id=run_id,
            timeout_resolution=timeout_resolution.to_dict(),
        ),
        dynamic_config=config,
        runner=DockerRunner(image_name=args.image_name),
    )
    report = analysis.report
    dynamic_result = analysis.dynamic_result
    output = {
        "run_id": run_id,
        "artifacts_dir": analysis.artifacts_dir,
        "exit_code": report.get("exit_code"),
        "timed_out": report.get("timed_out"),
        "sandbox_image": report.get("sandbox_image"),
        "sandbox_image_id": report.get("sandbox_image_id"),
        "source_fingerprint": report.get("source_fingerprint"),
        "coverage": report.get("coverage_certificate", {}),
        "dynamic_summary": dynamic_result.summary() if dynamic_result is not None else {},
        "static_runtime_alignment": report.get("static_runtime_alignment", {}),
        "unified_explanation": report.get("unified_explanation", {}),
        "canonical_decision": report.get("canonical_final_decision"),
        "canonical_risk_score": report.get("canonical_risk_score"),
        "legacy_review_priority": report.get("legacy_final_decision"),
        "trace_summary": report.get("trace_summary"),
        "telemetry_event_count": len(report.get("normalized_events", [])),
        "unified_analysis_path": report.get("unified_analysis_path"),
        "unified_explanation_report_path": report.get("unified_explanation_report_path"),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def _load_dynamic(run_id: str) -> dict[str, Any]:
    path = ARTIFACTS_ROOT / run_id / "dynamic-analysis.json"
    if not path.exists():
        raise SystemExit(f"dynamic analysis artifact not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _export(run_id: str, fmt: str) -> int:
    unified_path = ARTIFACTS_ROOT / run_id / "unified-analysis.json"
    if unified_path.exists():
        if fmt == "json":
            return _print_json(json.loads(unified_path.read_text(encoding="utf-8")))
        md_path = ARTIFACTS_ROOT / run_id / "unified-explanation.md"
        print(md_path.read_text(encoding="utf-8"))
        return 0
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
