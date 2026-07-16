from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.runner.models import DataFlowEvent, FileEvent, LLMEvent, NetworkEvent, ProcessEvent, SandboxExecution, ToolCallEvent
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
    sensitive_reads = [
        event
        for event in file_events
        if event.path.startswith(("/etc/", "/root/", "/proc/", "/sys/"))
        or ".provloom/adapters/credential_state/" in event.path
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


def build_execution_report(execution: SandboxExecution) -> dict[str, Any]:
    normalized_events = build_normalized_events(execution)
    persist_normalized_events(execution.artifacts_dir, normalized_events)
    return {
        "file_events": [event.to_dict() for event in execution.file_events],
        "network_events": [event.to_dict() for event in execution.network_events],
        "process_events": [event.to_dict() for event in execution.process_events],
        "tool_calls": [event.to_dict() for event in execution.tool_calls],
        "llm_events": [event.to_dict() for event in execution.llm_events],
        "data_flows": [event.to_dict() for event in execution.data_flows],
        "taint_events": [event.to_dict() for event in normalized_events if event.event_type.startswith("taint_") or event.event_type == "candidate_dependency"],
        "normalized_events": [event.to_dict() for event in normalized_events],
    }
