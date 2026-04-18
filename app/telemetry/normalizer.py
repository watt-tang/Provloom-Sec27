from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.runner.models import DataFlowEvent, FileEvent, LLMEvent, NetworkEvent, ProcessEvent, SandboxExecution, ToolCallEvent


@dataclass
class NormalizedEvent:
    """Canonical telemetry event used across runtime, graphing, and benchmarking."""

    event_id: str
    timestamp: str
    execution_id: str
    step_id: str | None
    event_type: str
    source: str
    parent_event_id: str | None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_normalized_events(execution: SandboxExecution) -> list[NormalizedEvent]:
    """Normalize heterogeneous telemetry into a stable event stream."""

    events: list[NormalizedEvent] = []
    llm_events = _normalize_llm_events(execution)
    tool_events = _normalize_tool_events(execution, llm_events)
    process_events = _normalize_process_events(execution, tool_events, llm_events)
    file_events = _normalize_file_events(execution, tool_events, llm_events)
    network_events = _normalize_network_events(execution, tool_events, llm_events)
    data_flow_events = _normalize_data_flow_events(execution, file_events, network_events)

    for group in (llm_events, tool_events, process_events, file_events, network_events, data_flow_events):
        events.extend(group)

    events.sort(key=lambda item: (item.timestamp, item.event_id))
    return events


def persist_normalized_events(artifacts_dir: str | Path, events: list[NormalizedEvent]) -> Path:
    target = Path(artifacts_dir) / "normalized-events.jsonl"
    with target.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
    return target


def load_normalized_events(path: str | Path) -> list[NormalizedEvent]:
    target = Path(path)
    if not target.exists():
        return []
    events: list[NormalizedEvent] = []
    for raw_line in target.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line.strip():
            continue
        events.append(NormalizedEvent(**json.loads(raw_line)))
    return events


def _normalize_llm_events(execution: SandboxExecution) -> list[NormalizedEvent]:
    normalized: list[NormalizedEvent] = []
    previous_event_id: str | None = None
    last_request_event_id_by_step: dict[str, str] = {}
    for event in execution.llm_events:
        step_id = event.step_id or _derive_step_id(event.metadata.get("step"))
        event_id = event.event_id or _event_id("llm")
        parent_event_id = event.parent_event_id
        if parent_event_id is None and event.event == "response" and step_id:
            parent_event_id = last_request_event_id_by_step.get(step_id)
        elif parent_event_id is None:
            parent_event_id = previous_event_id

        normalized_event = NormalizedEvent(
            event_id=event_id,
            timestamp=event.timestamp,
            execution_id=execution.execution_id,
            step_id=step_id,
            event_type="llm_step",
            source=event.source,
            parent_event_id=parent_event_id,
            metadata={
                "event": event.event,
                **event.metadata,
            },
        )
        event.event_id = event_id
        event.parent_event_id = parent_event_id
        event.step_id = step_id
        normalized.append(normalized_event)
        previous_event_id = event_id
        if event.event == "request" and step_id:
            last_request_event_id_by_step[step_id] = event_id
    return normalized


def _normalize_tool_events(
    execution: SandboxExecution,
    llm_events: list[NormalizedEvent],
) -> list[NormalizedEvent]:
    normalized: list[NormalizedEvent] = []
    llm_request_by_step = {
        event.step_id: event.event_id
        for event in llm_events
        if event.metadata.get("event") == "request" and event.step_id
    }
    last_start_by_tool: dict[tuple[str, str | None], str] = {}
    for event in execution.tool_calls:
        step_id = event.step_id or _derive_step_id(event.metadata.get("step"))
        event_id = event.event_id or _event_id("tool")
        parent_event_id = event.parent_event_id
        tool_key = (event.tool_id, step_id)
        if parent_event_id is None and event.event == "finish":
            parent_event_id = last_start_by_tool.get(tool_key)
        if parent_event_id is None and step_id:
            parent_event_id = llm_request_by_step.get(step_id)

        normalized_event = NormalizedEvent(
            event_id=event_id,
            timestamp=event.timestamp,
            execution_id=execution.execution_id,
            step_id=step_id,
            event_type="tool_call",
            source=event.source,
            parent_event_id=parent_event_id,
            metadata={
                "event": event.event,
                "tool_id": event.tool_id,
                "tool_name": event.tool_name,
                "tool_type": event.tool_type,
                "status": event.status,
                **event.metadata,
            },
        )
        event.event_id = event_id
        event.parent_event_id = parent_event_id
        event.step_id = step_id
        normalized.append(normalized_event)
        if event.event == "start":
            last_start_by_tool[tool_key] = event_id
    return normalized


def _normalize_process_events(
    execution: SandboxExecution,
    tool_events: list[NormalizedEvent],
    llm_events: list[NormalizedEvent],
) -> list[NormalizedEvent]:
    return _normalize_trace_events(
        execution=execution,
        raw_events=execution.process_events,
        event_type="process",
        build_metadata=lambda event: {
            "action": event.action,
            "command": event.command,
            "pid": event.pid,
            "raw": event.raw,
        },
        tool_events=tool_events,
        llm_events=llm_events,
    )


def _normalize_file_events(
    execution: SandboxExecution,
    tool_events: list[NormalizedEvent],
    llm_events: list[NormalizedEvent],
) -> list[NormalizedEvent]:
    return _normalize_trace_events(
        execution=execution,
        raw_events=execution.file_events,
        event_type="file",
        build_metadata=lambda event: {
            "action": event.action,
            "path": event.path,
            "pid": event.pid,
            "raw": event.raw,
        },
        tool_events=tool_events,
        llm_events=llm_events,
    )


def _normalize_network_events(
    execution: SandboxExecution,
    tool_events: list[NormalizedEvent],
    llm_events: list[NormalizedEvent],
) -> list[NormalizedEvent]:
    return _normalize_trace_events(
        execution=execution,
        raw_events=execution.network_events,
        event_type="network",
        build_metadata=lambda event: {
            "action": event.action,
            "address": event.address,
            "pid": event.pid,
            "raw": event.raw,
        },
        tool_events=tool_events,
        llm_events=llm_events,
    )


def _normalize_data_flow_events(
    execution: SandboxExecution,
    file_events: list[NormalizedEvent],
    network_events: list[NormalizedEvent],
) -> list[NormalizedEvent]:
    file_read_ids = {event.metadata.get("path"): event.event_id for event in file_events}
    network_ids = {event.metadata.get("address"): event.event_id for event in network_events}
    normalized: list[NormalizedEvent] = []
    for event in execution.data_flows:
        event_id = event.event_id or _event_id("flow")
        parent_event_id = event.parent_event_id
        if parent_event_id is None:
            parent_event_id = (
                file_read_ids.get(event.source_detail)
                or network_ids.get(event.sink_detail)
            )
        normalized_event = NormalizedEvent(
            event_id=event_id,
            timestamp=event.timestamp,
            execution_id=execution.execution_id,
            step_id=event.step_id,
            event_type="data_flow",
            source="analyzer",
            parent_event_id=parent_event_id,
            metadata={
                "source": event.source,
                "source_detail": event.source_detail,
                "sink": event.sink,
                "sink_detail": event.sink_detail,
                "note": event.note,
            },
        )
        event.event_id = event_id
        event.parent_event_id = parent_event_id
        normalized.append(normalized_event)
    return normalized


def _normalize_trace_events(
    execution: SandboxExecution,
    raw_events: list[FileEvent] | list[NetworkEvent] | list[ProcessEvent],
    event_type: str,
    build_metadata,
    tool_events: list[NormalizedEvent],
    llm_events: list[NormalizedEvent],
) -> list[NormalizedEvent]:
    normalized: list[NormalizedEvent] = []
    parent_tool = _last_tool_event(tool_events)
    parent_llm = _last_llm_event(llm_events)
    default_parent_id = parent_tool.event_id if parent_tool is not None else (parent_llm.event_id if parent_llm else None)
    default_step_id = parent_tool.step_id if parent_tool is not None else (parent_llm.step_id if parent_llm else None)

    for event in raw_events:
        event_id = event.event_id or _event_id(event_type)
        parent_event_id = event.parent_event_id or default_parent_id
        step_id = event.step_id or default_step_id
        normalized_event = NormalizedEvent(
            event_id=event_id,
            timestamp=event.timestamp,
            execution_id=execution.execution_id,
            step_id=step_id,
            event_type=event_type,
            source=event.source,
            parent_event_id=parent_event_id,
            metadata=build_metadata(event),
        )
        event.event_id = event_id
        event.parent_event_id = parent_event_id
        event.step_id = step_id
        normalized.append(normalized_event)
    return normalized


def _last_tool_event(events: list[NormalizedEvent]) -> NormalizedEvent | None:
    starts = [event for event in events if event.metadata.get("event") == "start"]
    return starts[-1] if starts else (events[-1] if events else None)


def _last_llm_event(events: list[NormalizedEvent]) -> NormalizedEvent | None:
    requests = [event for event in events if event.metadata.get("event") == "request"]
    return requests[-1] if requests else (events[-1] if events else None)


def _derive_step_id(step: Any) -> str | None:
    if step in (None, ""):
        return None
    return f"step-{step}"


def _event_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"
