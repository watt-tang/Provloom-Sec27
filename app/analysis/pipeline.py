from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

from app.analyzer.rules import analyze_static_skill, analyze_trace
from app.backend.schemas import LLMConfig
from app.dynamic.analyzer import DynamicAnalysisResult, DynamicRuntimeAnalyzer, persist_dynamic_analysis
from app.dynamic.config import DynamicAnalysisConfig
from app.explanation.builder import build_unified_explanation
from app.explanation.models import ALIGNMENT_VERSION, ASSESSMENT_VERSION, DYNAMIC_VERSION, STATIC_VERSION
from app.reporting.risk_mapper import map_risk_profile
from app.reporting.unified_report import write_unified_reports
from app.runtime.skill_parser import load_skill_definition, resolve_skill_target
from app.runner.docker_runner import DockerRunner
from app.runner.models import SandboxExecution
from app.runner.timeout_config import resolve_total_timeout
from app.static.static_config import StaticAnalysisConfig
from app.static.static_report import StaticAnalysisResult, analyze_static_bundle
from app.telemetry.collector import build_execution_report
from app.telemetry.normalizer import NormalizedEvent, build_normalized_events, persist_normalized_events


@dataclass
class ExecutionConfig:
    input_payload: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int | None = None
    network_policy: str = "default"
    analysis_mode: str = "rule_plus_epg"
    llm_config: LLMConfig = field(default_factory=LLMConfig)
    run_id: str = ""
    fixture: dict[str, Any] | None = None
    fixture_path: str | None = None
    timeout_resolution: dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedAnalysisResult:
    execution_id: str
    skill_path: str
    skill_file: str
    static_result: StaticAnalysisResult
    dynamic_result: DynamicAnalysisResult | None
    unified_explanation: dict[str, Any]
    report: dict[str, Any]
    execution: SandboxExecution | None = None
    normalized_events: list[NormalizedEvent] = field(default_factory=list)
    artifacts_dir: str = ""


def analyze_skill_bundle(
    skill_path: str | Path,
    *,
    execution_config: ExecutionConfig | None = None,
    static_config: StaticAnalysisConfig | None = None,
    dynamic_config: DynamicAnalysisConfig | None = None,
    runner: DockerRunner | None = None,
    static_only: bool = False,
) -> UnifiedAnalysisResult:
    config = execution_config or ExecutionConfig()
    if config.timeout_resolution:
        config.timeout_seconds = int(config.timeout_resolution.get("total_timeout_seconds") or config.timeout_seconds or 0) or None
    else:
        timeout_resolution = resolve_total_timeout(config.timeout_seconds, fixture=config.fixture)
        config.timeout_seconds = timeout_resolution.total_timeout_seconds
        config.timeout_resolution = timeout_resolution.to_dict()
    execution_id = config.run_id or uuid.uuid4().hex
    source_dir, skill_file = resolve_skill_target(str(skill_path))
    static_result = analyze_static_bundle(source_dir, skill_file, config=static_config)
    if static_only or config.analysis_mode == "static_only":
        return _analyze_static_only(
            execution_id=execution_id,
            source_dir=source_dir,
            skill_file=skill_file,
            static_result=static_result,
            execution_config=config,
        )
    execution = (runner or DockerRunner()).run(
        execution_id=execution_id,
        skill_path=str(skill_path),
        input_payload=config.input_payload,
        timeout_seconds=config.timeout_seconds,
        network_policy=config.network_policy,
        llm_config=config.llm_config,
        fixture=config.fixture,
        fixture_path=config.fixture_path,
    )
    return analyze_completed_execution(
        execution,
        execution_config=config,
        static_result=static_result,
        static_config=static_config,
        dynamic_config=dynamic_config,
    )


def analyze_completed_execution(
    execution: SandboxExecution,
    *,
    execution_config: ExecutionConfig | None = None,
    static_result: StaticAnalysisResult | None = None,
    static_config: StaticAnalysisConfig | None = None,
    dynamic_config: DynamicAnalysisConfig | None = None,
    normalized_events: list[NormalizedEvent] | None = None,
    dynamic_result: DynamicAnalysisResult | None = None,
) -> UnifiedAnalysisResult:
    config = execution_config or ExecutionConfig(run_id=execution.execution_id)
    if config.timeout_seconds is None:
        timeout_resolution = resolve_total_timeout(None, fixture=config.fixture)
        config.timeout_seconds = timeout_resolution.total_timeout_seconds
        config.timeout_resolution = timeout_resolution.to_dict()
    elif not config.timeout_resolution:
        config.timeout_resolution = resolve_total_timeout(config.timeout_seconds, fixture=config.fixture).to_dict()
    static_result = static_result or analyze_static_bundle(execution.skill_path, execution.skill_file, config=static_config)
    normalized_events = normalized_events if normalized_events is not None else build_normalized_events(execution)
    persist_normalized_events(execution.artifacts_dir, normalized_events)
    if dynamic_result is None:
        dynamic_result = DynamicRuntimeAnalyzer(config=dynamic_config, skill_root=execution.skill_path).analyze_execution(
            execution,
            normalized_events,
            static_result=static_result,
        )
    persist_dynamic_analysis(dynamic_result, execution.artifacts_dir)
    legacy_report = analyze_trace(
        execution,
        analysis_mode=config.analysis_mode,
        normalized_events=normalized_events,
        dynamic_result=dynamic_result,
        static_result=static_result,
    )
    telemetry_report = build_execution_report(
        execution,
        normalized_events=normalized_events,
        dynamic_result=dynamic_result,
        static_result=static_result,
    )
    unified = build_unified_explanation(
        skill_id=Path(execution.skill_path).name,
        static_result=static_result,
        dynamic_result=dynamic_result,
        execution=execution,
        legacy_report=legacy_report,
    )
    report_paths = write_unified_reports(unified, execution.artifacts_dir)
    report = _merge_dynamic_report(
        execution=execution,
        execution_config=config,
        static_result=static_result,
        dynamic_result=dynamic_result,
        legacy_report=legacy_report,
        telemetry_report=telemetry_report,
        unified=unified.to_dict(),
        report_paths=report_paths,
    )
    _write_pipeline_artifact(Path(execution.artifacts_dir), report)
    return UnifiedAnalysisResult(
        execution_id=execution.execution_id,
        skill_path=execution.skill_path,
        skill_file=execution.skill_file,
        static_result=static_result,
        dynamic_result=dynamic_result,
        unified_explanation=unified.to_dict(),
        report=report,
        execution=execution,
        normalized_events=normalized_events,
        artifacts_dir=execution.artifacts_dir,
    )


def _analyze_static_only(
    *,
    execution_id: str,
    source_dir: Path,
    skill_file: str,
    static_result: StaticAnalysisResult,
    execution_config: ExecutionConfig,
) -> UnifiedAnalysisResult:
    artifacts_dir = Path("artifacts/runs") / execution_id
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    definition = load_skill_definition(source_dir, skill_file, allow_empty_actions=True)
    legacy_static = analyze_static_skill(definition, analysis_mode=execution_config.analysis_mode)
    unified = build_unified_explanation(
        skill_id=Path(source_dir).name,
        static_result=static_result,
        dynamic_result=None,
        execution=None,
        legacy_report={"legacy_static_result": legacy_static, "legacy_risk_score": legacy_static.get("risk_score", 0), "legacy_final_decision": legacy_static.get("final_decision", "unknown")},
    )
    report_paths = write_unified_reports(unified, artifacts_dir)
    (artifacts_dir / "normalized-events.jsonl").write_text("", encoding="utf-8")
    (artifacts_dir / "dynamic-analysis.json").write_text(json.dumps({"schema_version": DYNAMIC_VERSION, "runtime_events": [], "runtime_chains": []}, ensure_ascii=False, indent=2), encoding="utf-8")
    report = _merge_static_report(
        execution_id=execution_id,
        source_dir=source_dir,
        skill_file=skill_file,
        static_result=static_result,
        legacy_static=legacy_static,
        execution_config=execution_config,
        unified=unified.to_dict(),
        report_paths=report_paths,
        artifacts_dir=artifacts_dir,
    )
    _write_pipeline_artifact(artifacts_dir, report)
    return UnifiedAnalysisResult(
        execution_id=execution_id,
        skill_path=str(source_dir),
        skill_file=skill_file,
        static_result=static_result,
        dynamic_result=None,
        unified_explanation=unified.to_dict(),
        report=report,
        artifacts_dir=str(artifacts_dir),
    )


def _merge_dynamic_report(
    *,
    execution: SandboxExecution,
    execution_config: ExecutionConfig,
    static_result: StaticAnalysisResult,
    dynamic_result: DynamicAnalysisResult,
    legacy_report: dict[str, Any],
    telemetry_report: dict[str, Any],
    unified: dict[str, Any],
    report_paths: dict[str, Path],
) -> dict[str, Any]:
    report = dict(legacy_report)
    canonical = unified.get("canonical_assessment", {}) or {}
    risk_score = int(canonical.get("canonical_risk_score", report.get("risk_score", 0)) or 0)
    report.update(telemetry_report)
    report.update(_static_payload_fields(static_result))
    report.update(_unified_fields(unified, report_paths))
    report.update(
        {
            "schema_version": "provloom-analysis-result-v1",
            "execution_id": execution.execution_id,
            "status": "completed",
            "skill_path": execution.skill_path,
            "skill_file": execution.skill_file,
            "sandbox_image": execution.sandbox_image,
            "sandbox_image_id": execution.sandbox_image_id,
            "source_fingerprint": execution.source_fingerprint,
            "runtime_build_info": dict(execution.runtime_build_info or {}),
            "runtime_name": execution.runtime_name,
            "network_policy": execution_config.network_policy,
            "analysis_mode": execution_config.analysis_mode,
            "timeout_seconds": execution_config.timeout_seconds,
            "timeout_resolution": execution_config.timeout_resolution,
            "llm_config": execution_config.llm_config.to_public_dict(),
            "llm_model_name": execution.llm_model_name,
            "llm_token_usage": dict(execution.llm_token_usage or {}),
            "exit_code": execution.exit_code,
            "timed_out": execution.timed_out,
            "termination_reason": execution.termination_reason,
            "deadline_reached": execution.deadline_reached,
            "runner_killed_process": execution.runner_killed_process,
            "container_oom_killed": execution.container_oom_killed,
            "agent_step_count": execution.agent_step_count,
            "max_agent_steps": execution.max_agent_steps,
            "max_steps_exhausted": execution.max_steps_exhausted,
            "llm_request_timeout_count": execution.llm_request_timeout_count,
            "provider_retry_count": execution.provider_retry_count,
            "final_response_emitted": execution.final_response_emitted,
            "pending_tool_call": execution.pending_tool_call,
            "pending_obligation_count": execution.pending_obligation_count,
            "stdout": execution.stdout,
            "stderr": execution.stderr,
            "resource_usage": execution.resource_usage.to_dict(),
            "legacy_risk_score": int(legacy_report.get("legacy_risk_score", legacy_report.get("risk_score", 0)) or 0),
            "legacy_final_decision": legacy_report.get("legacy_final_decision", legacy_report.get("final_decision", "unknown")),
            "legacy_static_result": legacy_report.get("legacy_static_result", {}),
            "risk_score": risk_score,
            "final_decision": canonical.get("canonical_final_decision", report.get("final_decision", "unknown")),
            "canonical_risk_score": risk_score,
            "canonical_final_decision": canonical.get("canonical_final_decision", "unknown"),
            "canonical_assessment": canonical,
            "needs_review": bool(canonical.get("needs_review", False)),
            "coverage_state": canonical.get("coverage_state", report.get("coverage_state", "unknown")),
        }
    )
    report.update(_risk_profile(risk_score, report.get("detected_behaviors", [])))
    return report


def _merge_static_report(
    *,
    execution_id: str,
    source_dir: Path,
    skill_file: str,
    static_result: StaticAnalysisResult,
    legacy_static: dict[str, Any],
    execution_config: ExecutionConfig,
    unified: dict[str, Any],
    report_paths: dict[str, Path],
    artifacts_dir: Path,
) -> dict[str, Any]:
    canonical = unified.get("canonical_assessment", {}) or {}
    risk_score = int(canonical.get("canonical_risk_score", 0) or 0)
    report = {
        "schema_version": "provloom-analysis-result-v1",
        "execution_id": execution_id,
        "status": "completed",
        "skill_path": str(source_dir),
        "skill_file": skill_file,
        "sandbox_image": "static-only",
            "runtime_name": "static-analysis",
            "sandbox_image_id": "",
            "source_fingerprint": "",
            "runtime_build_info": {},
        "network_policy": execution_config.network_policy,
        "analysis_mode": execution_config.analysis_mode,
        "timeout_seconds": execution_config.timeout_seconds,
        "timeout_resolution": execution_config.timeout_resolution,
        "llm_config": execution_config.llm_config.to_public_dict(),
        "llm_model_name": "",
        "llm_token_usage": {"model": "", "provider": "", "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "request_count": 0},
        "exit_code": None,
        "timed_out": False,
        "stdout": "",
        "stderr": "",
        "trace_summary": {"file_event_count": 0, "network_event_count": 0, "process_event_count": 0, "tool_call_count": 0, "llm_event_count": 0, "taint_event_count": 0, "stdout_line_count": 0, "stderr_line_count": 0},
        "detected_behaviors": list(legacy_static.get("detected_behaviors", [])),
        "evidence_timeline": legacy_static.get("evidence_timeline", []),
        "file_events": [],
        "network_events": [],
        "process_events": [],
        "tool_calls": [],
        "llm_events": [],
        "data_flows": [],
        "normalized_events": [],
        "runtime_events_v2": [],
        "runtime_provenance_graph": {},
        "runtime_chains": [],
        "runtime_coverage": unified.get("coverage_certificate", {}),
        "runtime_policy_violations": [],
        "dynamic_analysis_summary": {"runtime_event_count": 0, "runtime_chain_count": 0, "coverage_state": unified.get("coverage_certificate", {}).get("coverage_state")},
        "taint_sources": [],
        "resource_usage": {},
        "legacy_static_result": legacy_static,
        "legacy_risk_score": int(legacy_static.get("risk_score", 0) or 0),
        "legacy_final_decision": legacy_static.get("final_decision", "unknown"),
        "risk_score": risk_score,
        "final_decision": canonical.get("canonical_final_decision", "unknown"),
        "canonical_risk_score": risk_score,
        "canonical_final_decision": canonical.get("canonical_final_decision", "unknown"),
        "canonical_assessment": canonical,
        "needs_review": bool(canonical.get("needs_review", False)),
        "coverage_state": canonical.get("coverage_state", "unknown"),
        "artifacts_dir": str(artifacts_dir),
    }
    report.update(_static_payload_fields(static_result))
    report.update(_unified_fields(unified, report_paths))
    report.update(_risk_profile(risk_score, report.get("detected_behaviors", [])))
    return report


def _static_payload_fields(static_result: StaticAnalysisResult) -> dict[str, Any]:
    payload = static_result.to_dict()
    return {
        "static_artifacts_v2": payload.get("static_artifacts_v2", []),
        "static_semantic_units": payload.get("static_semantic_units", []),
        "deterministic_mentions": payload.get("deterministic_mentions", []),
        "extracted_actions": payload.get("extracted_actions", []),
        "grounding_validation": payload.get("grounding_validation", []),
        "resolved_entities": payload.get("resolved_entities", []),
        "entity_resolutions": payload.get("entity_resolutions", []),
        "instruction_provenance_graph": payload.get("instruction_provenance_graph", {}),
        "static_chains": payload.get("static_chains", []),
        "static_coverage": payload.get("static_coverage", {}),
        "static_analysis_summary": payload.get("static_analysis_summary", {}),
        "llm_extraction_metadata": payload.get("llm_extraction_metadata", []),
        "static_schema_version": payload.get("schema_version", STATIC_VERSION),
    }


def _unified_fields(unified: dict[str, Any], report_paths: dict[str, Path]) -> dict[str, Any]:
    versions = unified.get("versions", {}) or {}
    return {
        "unified_analysis": unified,
        "unified_explanation": unified,
        "unified_analysis_path": str(report_paths["json"]),
        "unified_explanation_report_path": str(report_paths["markdown"]),
        "static_runtime_alignment": {
            "schema_version": ALIGNMENT_VERSION,
            "status": _alignment_status(unified),
            "alignment_records": unified.get("alignments", []),
            "contradictions": unified.get("contradictions", []),
            "summary": {
                "aligned_count": sum(1 for item in unified.get("alignments", []) if item.get("status") == "aligned"),
                "partial_count": sum(1 for item in unified.get("alignments", []) if item.get("status") == "partially_aligned"),
                "unresolved_count": sum(1 for item in unified.get("alignments", []) if item.get("status") in {"unresolved", "relevant_unresolved", "internal_unresolved"}),
                "relevant_unresolved_count": len(unified.get("relevant_unresolved", []) or []),
                "internal_unresolved_count": len(unified.get("internal_unresolved", []) or []),
                "contradiction_count": len(unified.get("contradictions", [])),
            },
        },
        "alignments": unified.get("alignments", []),
        "contradictions": unified.get("contradictions", []),
        "aligned_paths": unified.get("aligned_paths", []),
        "instruction_only_paths": unified.get("instruction_only_paths", []),
        "runtime_only_paths": unified.get("runtime_only_paths", []),
        "relevant_unresolved": unified.get("relevant_unresolved", []),
        "internal_unresolved": unified.get("internal_unresolved", []),
        "coverage_certificate": unified.get("coverage_certificate", {}),
        "risk_chain_status": unified.get("risk_chain_status", {}),
        "execution_completion": unified.get("execution_completion", {}),
        "static_path_results": unified.get("static_path_results", []),
        "primary_static_path_id": unified.get("primary_static_path_id", ""),
        "primary_static_path_status": unified.get("primary_static_path_status", "not_applicable"),
        "other_static_path_summary": unified.get("other_static_path_summary", {}),
        "obligation_relevance_summary": unified.get("obligation_relevance_summary", {}),
        "security_resolution": unified.get("security_resolution", {}),
        "security_resolution_status": unified.get("security_resolution_status", "none"),
        "policy_findings": unified.get("policy_findings", []),
        "minimal_witnesses": unified.get("minimal_witnesses", []),
        "limitations": unified.get("limitations", []),
        "static_analysis_version": versions.get("static_analysis_version", STATIC_VERSION),
        "dynamic_analysis_version": versions.get("dynamic_analysis_version", DYNAMIC_VERSION),
        "alignment_version": versions.get("alignment_version", ALIGNMENT_VERSION),
        "assessment_version": versions.get("assessment_version", ASSESSMENT_VERSION),
    }


def _alignment_status(unified: dict[str, Any]) -> str:
    if unified.get("contradictions"):
        return "contradicted"
    records = unified.get("alignments", []) or []
    if records and all(item.get("status") == "aligned" for item in records):
        return "aligned"
    if any(item.get("status") in {"aligned", "partially_aligned"} for item in records):
        return "partially_aligned"
    return "unresolved"


def _risk_profile(risk_score: int, detected_behaviors: list[str]) -> dict[str, Any]:
    profile = map_risk_profile(risk_score=risk_score, detected_behaviors=detected_behaviors)
    return {
        "risk_level": profile["risk_level"],
        "risk_level_name": profile["risk_level_name"],
        "primary_risk": profile["primary_risk"],
        "risk_labels": profile["risk_labels"],
        "risk_summary": profile["risk_summary"],
    }


def _write_pipeline_artifact(root: Path, report: dict[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "canonical-analysis-result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, default=_json_default), encoding="utf-8")


def _json_default(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value):
        return asdict(value)
    return str(value)
