from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.runner.models import DataFlowEvent, FileEvent, LLMEvent, NetworkEvent, ProcessEvent, SandboxExecution, ToolCallEvent
from app.dynamic.assessment import assess_dynamic_result
from app.dynamic.analyzer import DynamicAnalysisResult, DynamicRuntimeAnalyzer, persist_dynamic_analysis
from app.taint.source_registry import SourceRegistry
from app.telemetry.normalizer import build_normalized_events, persist_normalized_events


def load_runtime_events(path: Path) -> list[ToolCallEvent]:
    if not path.exists():
        return []
    tool_calls: list[ToolCallEvent] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        record = json.loads(raw_line)
        if record.get("category") != "tool_call":
            continue
        payload = record.get("payload", {})
        tool_calls.append(
            ToolCallEvent(
                timestamp=record["timestamp"],
                tool_id=payload.get("tool_id", ""),
                tool_name=payload.get("tool_name", ""),
                tool_type=payload.get("tool_type", ""),
                event=record.get("event", ""),
                status=payload.get("status"),
                metadata=payload,
                input_taint_ids=list(payload.get("input_taint_ids", [])),
                output_taint_ids=list(payload.get("output_taint_ids", [])),
                taint_evidence_level=payload.get("taint_evidence_level"),
                taint_propagation_rule=payload.get("taint_propagation_rule"),
                event_id=record.get("event_id"),
                parent_event_id=record.get("parent_event_id"),
                step_id=record.get("step_id"),
                source=record.get("source", "runtime"),
            )
        )
    return tool_calls


def load_llm_events(path: Path) -> list[LLMEvent]:
    if not path.exists():
        return []
    llm_events: list[LLMEvent] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        record = json.loads(raw_line)
        if record.get("category") != "llm":
            continue
        llm_events.append(
            LLMEvent(
                timestamp=record["timestamp"],
                event=record.get("event", ""),
                metadata=record.get("payload", {}),
                event_id=record.get("event_id"),
                parent_event_id=record.get("parent_event_id"),
                step_id=record.get("step_id"),
                source=record.get("source", "runtime"),
            )
        )
    return llm_events


def build_data_flow_hints(
    file_events: list[FileEvent],
    network_events: list[NetworkEvent],
    tool_calls: list[ToolCallEvent],
) -> list[DataFlowEvent]:
    flows: list[DataFlowEvent] = []
    registry = SourceRegistry()
    sensitive_reads = [
        event
        for event in file_events
        if _is_confidential_source_path(registry, event.path)
    ]
    if not sensitive_reads or not network_events:
        return flows

    first_source = sensitive_reads[0]
    first_sink = network_events[0]
    flows.append(
        DataFlowEvent(
            timestamp=first_sink.timestamp,
            source="file_read",
            source_detail=first_source.path,
            sink="network_connect",
            sink_detail=first_sink.address,
            note=(
                "candidate_dependency: sensitive read and network event co-occurred, "
                "but no payload/file/tool taint propagation evidence confirms data flow."
            ),
        )
    )
    return flows


def _is_confidential_source_path(registry: SourceRegistry, path: str) -> bool:
    match = registry.match_path(path)
    return bool(match and str(match.sensitivity).lower() in {"medium", "high", "critical"})


def build_execution_report(
    execution: SandboxExecution,
    *,
    normalized_events: list[Any] | None = None,
    dynamic_result: DynamicAnalysisResult | None = None,
    static_result: Any | None = None,
) -> dict[str, Any]:
    normalized_events = normalized_events if normalized_events is not None else build_normalized_events(execution)
    persist_normalized_events(execution.artifacts_dir, normalized_events)
    if dynamic_result is None:
        dynamic_result = DynamicRuntimeAnalyzer(skill_root=execution.skill_path).analyze_execution(
            execution,
            normalized_events,
            static_result=static_result,
        )
        persist_dynamic_analysis(dynamic_result, execution.artifacts_dir)
    canonical = assess_dynamic_result(dynamic_result)
    return {
        "file_events": [event.to_dict() for event in execution.file_events],
        "network_events": [event.to_dict() for event in execution.network_events],
        "process_events": [event.to_dict() for event in execution.process_events],
        "tool_calls": [event.to_dict() for event in execution.tool_calls],
        "llm_events": [event.to_dict() for event in execution.llm_events],
        "llm_model_name": execution.llm_model_name,
        "llm_token_usage": dict(execution.llm_token_usage or {}),
        "llm_request_retry_count": int(execution.llm_request_retry_count or 0),
        "llm_request_retry_reasons": list(execution.llm_request_retry_reasons or []),
        "data_flows": [event.to_dict() for event in execution.data_flows],
        "taint_events": [event.to_dict() for event in normalized_events if event.event_type.startswith("taint_") or event.event_type == "candidate_dependency"],
        "normalized_events": [event.to_dict() for event in normalized_events],
        "runtime_events_v2": [event.to_dict() for event in dynamic_result.runtime_events],
        "runtime_provenance_graph": dynamic_result.graph.to_dict(),
        "runtime_chains": [chain.to_dict() for chain in dynamic_result.chains],
        "runtime_coverage": dynamic_result.coverage.to_dict(),
        "runtime_policy_violations": [violation.to_dict() for violation in dynamic_result.policy_violations],
        "dynamic_analysis_summary": dynamic_result.summary(),
        "taint_sources": dynamic_result.taint_sources,
        "static_runtime_alignment": dynamic_result.static_runtime_alignment or {},
        "canonical_assessment": canonical.to_dict(),
        "canonical_risk_score": canonical.canonical_risk_score,
        "canonical_final_decision": canonical.canonical_final_decision,
        "needs_review": canonical.needs_review,
        "review_required": canonical.review_required,
        "review_lean": canonical.review_lean,
        "binary_prediction": canonical.binary_prediction,
        "decision_score": canonical.decision_score,
        "review_reason": canonical.review_reason,
        "lean_reason": canonical.lean_reason,
        "lean_score": canonical.lean_score,
        "policy_violation_count": canonical.policy_violation_count,
        "confirmed_chain_count": canonical.confirmed_chain_count,
        "candidate_chain_count": canonical.candidate_chain_count,
        "coverage_state": canonical.coverage_state,
        "instrumentation_gaps": list(canonical.instrumentation_gaps),
    }
