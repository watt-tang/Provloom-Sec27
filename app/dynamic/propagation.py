from __future__ import annotations

import fnmatch
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.dynamic.config import DynamicAnalysisConfig
from app.dynamic.marker_registry import MarkerMatch, TaintRegistry
from app.dynamic.models import RuntimeEvent
from app.taint.source_registry import normalize_path


@dataclass
class FileTaint:
    taint_ids: set[str] = field(default_factory=set)
    evidence_level: str = "confirmed"
    last_event_id: str | None = None


@dataclass
class ProcessInputTaint:
    taint_ids: set[str] = field(default_factory=set)
    evidence_level: str = "conservative"
    last_event_id: str | None = None
    direct_content_observed: bool = False


class RuntimeTaintPropagator:
    def __init__(self, *, registry: TaintRegistry, config: DynamicAnalysisConfig | None = None) -> None:
        self.registry = registry
        self.config = config or DynamicAnalysisConfig()
        self.file_taint: dict[str, FileTaint] = {}
        self.process_inputs: dict[str, ProcessInputTaint] = {}
        self.tool_outputs: dict[str, set[str]] = defaultdict(set)
        self.sensitive_read_events: list[RuntimeEvent] = []

    def propagate(self, events: list[RuntimeEvent]) -> list[RuntimeEvent]:
        enriched: list[RuntimeEvent] = []
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            updated = self._copy_event(event)
            self._enrich_from_markers(updated)
            self._apply_event_rule(updated)
            enriched.append(updated)
        if not any(event.event_type in {"network_send", "file_upload"} and event.taint_ids for event in enriched):
            enriched.extend(self._candidate_dependencies(enriched))
        return sorted(enriched, key=lambda item: (item.timestamp, item.event_id))

    def _apply_event_rule(self, event: RuntimeEvent) -> None:
        if event.event_type == "sensitive_source":
            for taint_id in event.taint_ids:
                if event.object_path:
                    self.file_taint[event.object_path] = FileTaint({taint_id}, "confirmed", event.event_id)
            return

        if event.operation == "read" and event.object_type == "file":
            self._handle_file_read(event)
            return

        if event.operation == "write" and event.object_type == "file":
            self._handle_file_write(event)
            return

        if event.operation in {"rename", "copy", "move", "extract"}:
            self._handle_file_derivation(event)
            return

        if event.operation == "exec" or event.event_type == "process_exec":
            self._handle_process_exec(event)
            return

        if event.operation in {"stdin", "stdout", "stderr", "pipe"} or event.event_type in {"pipe", "stdin", "stdout"}:
            self._handle_ipc(event)
            return

        if event.operation in {"invoke", "return"} and event.object_type in {"tool", "value"}:
            self._handle_tool_event(event)
            return

        if event.event_type in {"network_send", "file_upload"} or event.operation in {"send", "upload"}:
            self._handle_network_send(event)

    def _handle_file_read(self, event: RuntimeEvent) -> None:
        path = event.object_path or ""
        if self._is_sensitive_source_path(path):
            source = self.registry.ensure_source_for_path(path, source_type="secret_file", timestamp=event.timestamp)
            self._merge_taint(event, [source.taint_id], "confirmed", reason="sensitive_source_path")
            self.file_taint[path] = FileTaint({source.taint_id}, "confirmed", event.event_id)
        if path in self.file_taint:
            record = self.file_taint[path]
            self._merge_taint(event, record.taint_ids, record.evidence_level, reason="read_tainted_file")
        if event.taint_ids:
            process = self._process_key(event.actor_id, event.process_id)
            self.process_inputs[process] = ProcessInputTaint(set(event.taint_ids), event.evidence_level, event.event_id, bool(event.data_preview))
            self.sensitive_read_events.append(event)

    def _handle_file_write(self, event: RuntimeEvent) -> None:
        path = event.object_path or ""
        if not path:
            return
        process = self._process_key(event.actor_id, event.process_id)
        process_taint = self.process_inputs.get(process)
        if event.taint_ids:
            self.file_taint[path] = FileTaint(set(event.taint_ids), event.evidence_level, event.event_id)
        elif process_taint and event.metadata.get("output_from_tainted_input"):
            self._merge_taint(event, process_taint.taint_ids, "conservative", reason="opaque_output_from_tainted_input")
            self.file_taint[path] = FileTaint(set(event.taint_ids), "conservative", event.event_id)
        else:
            self.file_taint.pop(path, None)

    def _handle_file_derivation(self, event: RuntimeEvent) -> None:
        source_path = normalize_path(event.metadata.get("source_path", ""))
        dest_path = event.object_path or normalize_path(event.metadata.get("destination_path", ""))
        if not source_path or not dest_path or source_path not in self.file_taint:
            return
        record = self.file_taint[source_path]
        self._merge_taint(event, record.taint_ids, record.evidence_level, reason=f"file_{event.operation}_inherits_taint")
        self.file_taint[dest_path] = FileTaint(set(record.taint_ids), record.evidence_level, event.event_id)

    def _handle_process_exec(self, event: RuntimeEvent) -> None:
        argv_taint = set(event.taint_ids)
        for key in ("argv", "env", "stdin", "command"):
            argv_taint.update(match.taint_id for match in self.registry.detect(event.metadata.get(key)))
        for path in _paths_from_metadata(event.metadata):
            if path in self.file_taint and event.metadata.get("passes_file_content"):
                argv_taint.update(self.file_taint[path].taint_ids)
        if argv_taint:
            self._merge_taint(event, argv_taint, event.evidence_level if event.evidence_level != "unknown" else "confirmed", reason="tainted_process_input")
            process = self._process_key(event.object_id or event.actor_id, event.process_id)
            self.process_inputs[process] = ProcessInputTaint(set(event.taint_ids), event.evidence_level, event.event_id, bool(event.data_preview))

    def _handle_ipc(self, event: RuntimeEvent) -> None:
        if event.operation == "pipe":
            source_process = self._process_key(str(event.metadata.get("source_process") or event.actor_id), event.process_id)
            target_process = self._process_key(str(event.metadata.get("target_process") or event.object_id), event.metadata.get("target_process_id"))
            source = self.process_inputs.get(source_process)
            if source and source.taint_ids:
                level = "confirmed" if event.data_preview and event.taint_ids else "conservative"
                self._merge_taint(event, source.taint_ids, level, reason="pipe_from_tainted_process")
                self.process_inputs[target_process] = ProcessInputTaint(set(event.taint_ids), level, event.event_id, bool(event.data_preview))
            return
        if event.taint_ids:
            process = self._process_key(event.actor_id, event.process_id)
            self.process_inputs[process] = ProcessInputTaint(set(event.taint_ids), event.evidence_level, event.event_id, bool(event.data_preview))

    def _handle_tool_event(self, event: RuntimeEvent) -> None:
        tool_id = str(event.metadata.get("tool_id") or event.actor_id or event.object_id)
        for ref in event.metadata.get("input_taint_ids", []):
            self._merge_taint(event, [str(ref)], "confirmed", reason="declared_tool_input_taint")
        if event.operation == "return":
            if event.taint_ids:
                self.tool_outputs[tool_id].update(event.taint_ids)
            for ref in event.metadata.get("output_taint_ids", []):
                self.tool_outputs[tool_id].add(str(ref))

    def _handle_network_send(self, event: RuntimeEvent) -> None:
        upload_file = normalize_path(event.metadata.get("upload_file_path", ""))
        if upload_file and upload_file in self.file_taint:
            record = self.file_taint[upload_file]
            self._merge_taint(event, record.taint_ids, record.evidence_level, reason="explicit_tainted_file_upload")
        for key in ("body", "headers", "query", "socket_payload", "tool_arguments"):
            matches = self.registry.detect(event.metadata.get(key))
            if matches:
                self._merge_marker_matches(event, matches)
        process = self._process_key(event.actor_id, event.process_id)
        process_taint = self.process_inputs.get(process)
        if not event.taint_ids and process_taint and event.metadata.get("opaque_payload"):
            self._merge_taint(event, process_taint.taint_ids, "conservative", reason="opaque_process_payload_after_tainted_input")

    def _enrich_from_markers(self, event: RuntimeEvent) -> None:
        matches = self.registry.detect(event.data_preview)
        for value in event.metadata.values():
            matches.extend(self.registry.detect(value))
        if matches:
            self._merge_marker_matches(event, matches)

    def _merge_marker_matches(self, event: RuntimeEvent, matches: list[MarkerMatch]) -> None:
        for match in matches:
            event.metadata.setdefault("marker_matches", []).append(
                {"taint_id": match.taint_id, "variant": match.variant_name, "derived": match.derived}
            )
            level = "conservative" if match.derived else "confirmed"
            self._merge_taint(event, [match.taint_id], level, reason=f"marker_variant:{match.variant_name}")

    def _merge_taint(self, event: RuntimeEvent, taint_ids, level: str, *, reason: str) -> None:
        current = set(event.taint_ids)
        current.update(str(item) for item in taint_ids if str(item))
        event.taint_ids = sorted(current)
        event.evidence_level = _strongest_level(event.evidence_level, level)
        event.metadata.setdefault("taint_reasons", [])
        if reason not in event.metadata["taint_reasons"]:
            event.metadata["taint_reasons"].append(reason)

    def _candidate_dependencies(self, events: list[RuntimeEvent]) -> list[RuntimeEvent]:
        if not self.sensitive_read_events:
            return []
        network_events = [event for event in events if event.event_type == "network_connect" or event.operation == "connect"]
        if not network_events:
            return []
        first_read = self.sensitive_read_events[0]
        first_network = sorted(network_events, key=lambda item: (item.timestamp, item.event_id))[0]
        candidate = RuntimeEvent(
            event_id=f"{first_network.event_id}-CANDIDATE",
            timestamp=first_network.timestamp,
            event_type="candidate_dependency",
            process_id=first_network.process_id,
            parent_process_id=first_network.parent_process_id,
            session_id=first_network.session_id,
            skill_id=first_network.skill_id,
            actor_type=first_network.actor_type,
            actor_id=first_network.actor_id,
            object_type=first_network.object_type,
            object_id=first_network.object_id,
            object_path=first_network.object_path,
            operation="connect",
            taint_ids=list(first_read.taint_ids),
            evidence_level="candidate",
            raw_source="dynamic_analyzer",
            raw_reference=f"{first_read.event_id},{first_network.event_id}",
            metadata={
                "reason": "sensitive_read_and_network_connect_without_payload_or_file_upload_evidence",
                "source_event_id": first_read.event_id,
                "network_event_id": first_network.event_id,
            },
        )
        return [candidate]

    def _is_sensitive_source_path(self, path: str) -> bool:
        normalized = normalize_path(path)
        return any(fnmatch.fnmatch(normalized, normalize_path(pattern)) for pattern in self.config.sensitive_source_patterns)

    @staticmethod
    def _process_key(actor_id: str | None, process_id: Any) -> str:
        if process_id not in (None, ""):
            return f"PROC:{process_id}"
        return str(actor_id or "PROC:unknown")

    @staticmethod
    def _copy_event(event: RuntimeEvent) -> RuntimeEvent:
        return RuntimeEvent(**event.to_dict())


def _paths_from_metadata(metadata: dict[str, Any]) -> list[str]:
    paths = []
    for key in ("path", "source_path", "destination_path", "upload_file_path"):
        value = metadata.get(key)
        if isinstance(value, str):
            normalized = normalize_path(value)
            if normalized:
                paths.append(normalized)
    return sorted(set(paths))


def _strongest_level(current: str, incoming: str) -> str:
    order = {"confirmed": 0, "conservative": 1, "candidate": 2, "unknown": 3}
    current = current if current in order else "unknown"
    incoming = incoming if incoming in order else "unknown"
    return current if order[current] <= order[incoming] else incoming
