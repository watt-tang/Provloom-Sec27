from __future__ import annotations

import hashlib
import json
import posixpath
import re
from pathlib import Path
from typing import Any

from app.dynamic.models import RuntimeEvent
from app.telemetry.normalizer import NormalizedEvent, load_normalized_events
from app.taint.source_registry import normalize_path


PATH_KEYS = {"path", "object_path", "source_object", "upload_file_path"}
URL_RE = re.compile(r"https?://[^\s'\"<>]+")


class RuntimeEventFactory:
    def __init__(self, *, session_id: str, skill_id: str) -> None:
        self.session_id = session_id
        self.skill_id = skill_id
        self._counter = 0

    def next_id(self) -> str:
        self._counter += 1
        return f"EV{self._counter:06d}"

    def create(self, **kwargs: Any) -> RuntimeEvent:
        event_id = str(kwargs.pop("event_id", "") or self.next_id())
        metadata = dict(kwargs.pop("metadata", {}) or {})
        object_path = _normalize_runtime_path(kwargs.pop("object_path", None))
        data_preview = kwargs.pop("data_preview", None)
        data_hash = kwargs.pop("data_hash", None) or (_hash_preview(data_preview) if data_preview is not None else None)
        byte_count = kwargs.pop("byte_count", None)
        if byte_count is None and data_preview is not None:
            byte_count = len(str(data_preview).encode("utf-8"))
        taint_ids = sorted({str(item) for item in kwargs.pop("taint_ids", []) if str(item)})
        evidence_level = str(kwargs.pop("evidence_level", "unknown") or "unknown")
        object_type = str(kwargs.pop("object_type", "value"))
        raw_source = str(kwargs.pop("raw_source", "runtime_wrapper") or "runtime_wrapper")
        raw_reference = str(kwargs.pop("raw_reference", "") or "")
        evidence_strength = str(kwargs.pop("evidence_strength", metadata.get("evidence_strength", "unknown")) or "unknown")
        observation_source = str(kwargs.pop("observation_source", metadata.get("observation_source") or _observation_source(raw_source)) or "runtime_wrapper")
        carrier_type = str(kwargs.pop("carrier_type", metadata.get("carrier_type", "unknown")) or "unknown")
        carrier_location = kwargs.pop("carrier_location", metadata.get("carrier_location"))
        derived_from_hash = bool(kwargs.pop("derived_from_hash", metadata.get("derived_from_hash", False)))
        instrumentation_visibility = str(kwargs.pop("instrumentation_visibility", metadata.get("instrumentation_visibility", "observed")) or "observed")
        raw_event_id = kwargs.pop("raw_event_id", metadata.get("raw_event_id") or raw_reference or None)
        trace_file = kwargs.pop("trace_file", metadata.get("trace_file"))
        trace_line = kwargs.pop("trace_line", metadata.get("trace_line"))
        return RuntimeEvent(
            event_id=event_id,
            timestamp=float(kwargs.pop("timestamp", 0.0) or 0.0),
            event_type=str(kwargs.pop("event_type")),
            process_id=kwargs.pop("process_id", None),
            parent_process_id=kwargs.pop("parent_process_id", None),
            session_id=str(kwargs.pop("session_id", self.session_id) or self.session_id),
            skill_id=str(kwargs.pop("skill_id", self.skill_id) or self.skill_id),
            actor_type=str(kwargs.pop("actor_type", "process")),
            actor_id=str(kwargs.pop("actor_id", "PROC0")),
            object_type=object_type,
            object_id=str(kwargs.pop("object_id", "")) or _object_id(object_type, object_path, data_hash),
            object_path=object_path,
            operation=str(kwargs.pop("operation", "")),
            data_preview=data_preview,
            data_hash=data_hash,
            byte_count=byte_count,
            taint_ids=taint_ids,
            evidence_level=evidence_level,
            raw_source=raw_source,
            raw_reference=raw_reference,
            evidence_strength=evidence_strength,
            observation_source=observation_source,
            carrier_type=carrier_type,
            carrier_location=carrier_location,
            derived_from_hash=derived_from_hash,
            instrumentation_visibility=instrumentation_visibility,
            raw_event_id=raw_event_id,
            trace_file=trace_file,
            trace_line=trace_line,
            metadata={**_normalize_metadata_paths(metadata), **kwargs},
        )


def runtime_events_from_normalized(
    normalized_events: list[NormalizedEvent],
    *,
    session_id: str,
    skill_id: str,
) -> list[RuntimeEvent]:
    factory = RuntimeEventFactory(session_id=session_id, skill_id=skill_id)
    results: list[RuntimeEvent] = []
    for normalized in sorted(normalized_events, key=lambda item: (str(item.timestamp), item.event_id)):
        event = _convert_normalized_event(factory, normalized)
        if event is not None:
            results.append(event)
    return results


def load_runtime_events_v2(path: str | Path, *, session_id: str, skill_id: str) -> list[RuntimeEvent]:
    normalized = load_normalized_events(path)
    return runtime_events_from_normalized(normalized, session_id=session_id, skill_id=skill_id)


def _convert_normalized_event(factory: RuntimeEventFactory, normalized: NormalizedEvent) -> RuntimeEvent | None:
    meta = dict(normalized.metadata)
    timestamp = _timestamp_to_float(normalized.timestamp)
    raw_reference = normalized.event_id
    pid = meta.get("pid") or meta.get("process_id")
    actor_id = _actor_id(normalized, meta)

    if normalized.event_type == "file":
        operation = str(meta.get("action") or "")
        return factory.create(
            timestamp=timestamp,
            event_type=f"file_{operation}",
            process_id=pid,
            actor_type="process",
            actor_id=actor_id,
            object_type="file",
            object_id=f"FILE:{_normalize_runtime_path(meta.get('path'))}",
            object_path=meta.get("path"),
            operation=operation,
            evidence_strength="structured_relation",
            observation_source=_observation_source(normalized.source),
            carrier_type="file_content" if operation in {"read", "write", "create"} else "file_path",
            carrier_location=meta.get("path"),
            raw_source=normalized.source,
            raw_reference=raw_reference,
            metadata=meta,
        )

    if normalized.event_type == "network":
        operation = str(meta.get("action") or "connect")
        evidence_strength, carrier_type, visibility = _network_event_evidence(meta, operation)
        return factory.create(
            timestamp=timestamp,
            event_type=f"network_{operation}",
            process_id=pid,
            actor_type="process",
            actor_id=actor_id,
            object_type="network",
            object_id=f"NET:{meta.get('sink_url') or meta.get('address') or 'unknown'}",
            object_path=None,
            operation=operation,
            evidence_strength=evidence_strength,
            observation_source=_observation_source(normalized.source),
            carrier_type=carrier_type,
            carrier_location=meta.get("carrier_location") or meta.get("sink_url") or meta.get("address"),
            instrumentation_visibility=visibility,
            raw_source=normalized.source,
            raw_reference=raw_reference,
            metadata=meta,
        )

    if normalized.event_type == "process":
        command = str(meta.get("command") or "")
        return factory.create(
            timestamp=timestamp,
            event_type="process_exec",
            process_id=pid,
            actor_type="process",
            actor_id=f"PROC:{pid or 'unknown'}",
            object_type="process",
            object_id=f"PROC:{pid or command or normalized.event_id}",
            operation="exec",
            data_preview=command,
            evidence_strength="structured_relation",
            observation_source=_observation_source(normalized.source),
            carrier_type="process_argv",
            carrier_location="argv",
            raw_source=normalized.source,
            raw_reference=raw_reference,
            metadata=meta,
        )

    if normalized.event_type == "tool_call":
        tool_id = str(meta.get("tool_id") or normalized.event_id)
        event_kind = str(meta.get("event") or "invoke")
        operation = "invoke" if event_kind == "start" else "return"
        taint_ids = list(meta.get("input_taint_ids" if event_kind == "start" else "output_taint_ids", []))
        carrier_type = _tool_carrier_type(meta, operation)
        return factory.create(
            timestamp=timestamp,
            event_type=f"tool_{operation}",
            process_id=pid,
            actor_type="agent" if operation == "invoke" else "tool",
            actor_id="AGENT:runtime" if operation == "invoke" else f"TOOL:{tool_id}",
            object_type="tool" if operation == "invoke" else "value",
            object_id=f"TOOL:{tool_id}" if operation == "invoke" else f"VALUE:{tool_id}:return",
            operation=operation,
            data_preview=json.dumps(meta.get("config", meta), ensure_ascii=False, sort_keys=True)[:4096],
            taint_ids=taint_ids,
            evidence_level=str(meta.get("taint_evidence_level") or "unknown"),
            evidence_strength=str(meta.get("evidence_strength") or ("structured_relation" if taint_ids else "unknown")),
            observation_source=_observation_source(normalized.source),
            carrier_type=carrier_type,
            carrier_location=meta.get("carrier_location") or meta.get("tool_name") or tool_id,
            raw_source=normalized.source,
            raw_reference=raw_reference,
            metadata=meta,
        )

    if normalized.event_type == "llm_step":
        event_kind = str(meta.get("event") or "")
        taint_ids = list(meta.get("taint_ids", []))
        if event_kind != "request" or not taint_ids:
            return None
        base_url = str(meta.get("base_url") or "")
        return factory.create(
            timestamp=timestamp,
            event_type="llm_request",
            process_id=pid,
            actor_type="agent",
            actor_id=actor_id,
            object_type="network",
            object_id=f"NET:{base_url or meta.get('endpoint_host') or 'unknown'}",
            operation="send",
            taint_ids=taint_ids,
            evidence_level=str(meta.get("evidence_level") or "confirmed"),
            evidence_strength=str(meta.get("evidence_strength") or "structured_relation"),
            observation_source="runtime_wrapper",
            carrier_type=str(meta.get("carrier_type") or "llm_context"),
            carrier_location=str(meta.get("carrier_location") or "messages"),
            instrumentation_visibility=str(meta.get("instrumentation_visibility") or "observed"),
            raw_source=normalized.source,
            raw_reference=raw_reference,
            metadata={
                **meta,
                "destination": base_url,
                "network_evidence_level": meta.get("network_evidence_level", "tainted_payload_observed"),
            },
        )

    if normalized.event_type == "taint_source":
        label = meta.get("label", {})
        return factory.create(
            timestamp=timestamp,
            event_type="sensitive_source",
            process_id=pid,
            actor_type="process",
            actor_id=actor_id,
            object_type="file",
            object_id=f"FILE:{meta.get('source_object')}",
            object_path=meta.get("source_object"),
            operation="source",
            taint_ids=list(meta.get("taint_ids", [])),
            evidence_level="confirmed",
            evidence_strength="exact_value",
            observation_source="inferred_relation",
            carrier_type="file_content",
            carrier_location=meta.get("source_object"),
            raw_source="taint",
            raw_reference=raw_reference,
            metadata={**meta, "source_label": label},
        )

    if normalized.event_type == "taint_propagation":
        target = meta.get("target", {})
        return factory.create(
            timestamp=timestamp,
            event_type="taint_propagation",
            process_id=pid,
            actor_type="tool",
            actor_id=f"TOOL:{meta.get('tool_call_id') or target.get('tool_id') or 'unknown'}",
            object_type=str(target.get("type") or "value"),
            object_id=str(target.get("path") or target.get("tool_id") or normalized.event_id),
            object_path=target.get("path"),
            operation="derive",
            taint_ids=list(meta.get("taint_ids", [])),
            evidence_level=str(meta.get("evidence_level") or "conservative"),
            evidence_strength=str(meta.get("evidence_strength") or "structured_relation"),
            observation_source="inferred_relation",
            carrier_type=str(meta.get("carrier_type") or "tool_return"),
            carrier_location=str(meta.get("carrier_location") or target.get("path") or target.get("tool_id") or ""),
            raw_source="taint",
            raw_reference=raw_reference,
            metadata=meta,
        )

    if normalized.event_type == "taint_sink":
        return factory.create(
            timestamp=timestamp,
            event_type="network_send",
            process_id=pid,
            actor_type="tool",
            actor_id=f"TOOL:{meta.get('tool_call_id') or 'unknown'}",
            object_type="network",
            object_id=f"NET:{meta.get('destination') or 'unknown'}",
            operation="send",
            taint_ids=list(meta.get("taint_ids", [])),
            evidence_level=str(meta.get("evidence_level") or "confirmed"),
            evidence_strength=str(meta.get("evidence_strength") or "structured_relation"),
            observation_source="inferred_relation",
            carrier_type=str(meta.get("carrier_type") or "http_body"),
            carrier_location=str(meta.get("carrier_location") or meta.get("destination") or ""),
            raw_source="taint",
            raw_reference=raw_reference,
            metadata=meta,
        )

    if normalized.event_type == "candidate_dependency":
        return factory.create(
            timestamp=timestamp,
            event_type="candidate_dependency",
            process_id=pid,
            actor_type="process",
            actor_id=actor_id,
            object_type="network",
            object_id=f"NET:{meta.get('sink_address') or 'unknown'}",
            operation="connect",
            taint_ids=list(meta.get("taint_ids", [])),
            evidence_level="candidate",
            evidence_strength="temporal_cooccurrence",
            observation_source="inferred_relation",
            carrier_type="unknown",
            instrumentation_visibility="payload_not_observed",
            raw_source="taint",
            raw_reference=raw_reference,
            metadata=meta,
        )
    return None


def _actor_id(normalized: NormalizedEvent, metadata: dict[str, Any]) -> str:
    if metadata.get("tool_id"):
        return f"TOOL:{metadata['tool_id']}"
    if metadata.get("pid"):
        return f"PROC:{metadata['pid']}"
    if normalized.step_id:
        return f"AGENT:{normalized.step_id}"
    return f"EVENT:{normalized.event_id}"


def _timestamp_to_float(value: Any) -> float:
    text = str(value or "")
    if not text:
        return 0.0
    if re.match(r"^\d+(\.\d+)?$", text):
        return float(text)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    return int(digest, 16) / 1_000_000_000


def _normalize_runtime_path(path: Any) -> str | None:
    if path in (None, ""):
        return None
    normalized = normalize_path(str(path))
    if normalized:
        return normalized
    return posixpath.normpath(str(path).replace("\\", "/"))


def _normalize_metadata_paths(metadata: dict[str, Any]) -> dict[str, Any]:
    updated = dict(metadata)
    for key in PATH_KEYS:
        if key in updated and isinstance(updated[key], str):
            updated[key] = _normalize_runtime_path(updated[key])
    return updated


def _hash_preview(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _object_id(object_type: Any, object_path: str | None, data_hash: str | None) -> str:
    if object_path:
        return f"{str(object_type).upper()}:{object_path}"
    return f"{str(object_type).upper()}:{(data_hash or 'unknown')[:16]}"


def _observation_source(raw_source: str) -> str:
    raw = str(raw_source or "")
    if raw.startswith("strace"):
        return "strace_syscall"
    if raw in {"taint", "dynamic_analyzer"}:
        return "inferred_relation"
    if raw.startswith("closure_lift"):
        return "instruction_simulation"
    return "runtime_wrapper"


def _network_event_evidence(metadata: dict[str, Any], operation: str) -> tuple[str, str, str]:
    if metadata.get("encrypted_payload_invisible") or metadata.get("network_evidence_level") == "encrypted_payload_invisible":
        metadata.setdefault("network_evidence_level", "encrypted_payload_invisible")
        return "unknown", "socket_payload", "encrypted_payload_invisible"
    if operation in {"send", "sendto", "sendmsg", "sendmmsg", "write"} and metadata.get("payload_preview"):
        metadata.setdefault("network_evidence_level", "request_observed")
        return "structured_relation", "socket_payload", "payload_preview_observed"
    if operation == "connect":
        metadata.setdefault("network_evidence_level", "endpoint_observed")
        return "candidate", "unknown", "endpoint_only"
    metadata.setdefault("network_evidence_level", "request_observed")
    return "structured_relation", "unknown", "observed"


def _tool_carrier_type(metadata: dict[str, Any], operation: str) -> str:
    tool_type = str(metadata.get("tool_type") or "")
    if tool_type == "http_request":
        return "http_body" if operation == "invoke" else "tool_return"
    if tool_type == "read_file":
        return "file_content" if operation == "return" else "file_path"
    if tool_type == "write_file":
        return "file_content"
    if tool_type == "run_command":
        return "process_argv" if operation == "invoke" else "stdout"
    return "tool_argument" if operation == "invoke" else "tool_return"
