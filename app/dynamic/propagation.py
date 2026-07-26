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
    evidence_strength: str = "exact_value"
    carrier_type: str = "file_content"


@dataclass
class ProcessInputTaint:
    taint_ids: set[str] = field(default_factory=set)
    evidence_level: str = "conservative"
    last_event_id: str | None = None
    direct_content_observed: bool = False
    context_only: bool = True


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
        if not any(_is_concrete_network_flow(event) for event in enriched):
            enriched.extend(self._candidate_dependencies(enriched))
        return sorted(enriched, key=lambda item: (item.timestamp, item.event_id))

    def _apply_event_rule(self, event: RuntimeEvent) -> None:
        if event.event_type == "sensitive_source":
            for taint_id in event.taint_ids:
                if event.object_path:
                    self.file_taint[event.object_path] = FileTaint({taint_id}, "confirmed", event.event_id, "exact_value")
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
            strength = "exact_value" if event.data_preview else "structured_relation"
            self._merge_taint(event, [source.taint_id], "confirmed", reason="TAINT_SOURCE_PATH_READ", evidence_strength=strength, carrier_type="file_content", carrier_location=path)
            self.file_taint[path] = FileTaint({source.taint_id}, "confirmed", event.event_id, strength)
        if path in self.file_taint:
            record = self.file_taint[path]
            self._merge_taint(event, record.taint_ids, record.evidence_level, reason="TAINT_READ_TAINTED_FILE", evidence_strength=record.evidence_strength, carrier_type=record.carrier_type, carrier_location=path)
        if event.taint_ids:
            process = self._process_key(event.actor_id, event.process_id)
            direct = bool(event.data_preview) or event.evidence_strength in {"exact_value", "encoded_value", "reconstructed_value"}
            self.process_inputs[process] = ProcessInputTaint(set(event.taint_ids), event.evidence_level, event.event_id, direct, context_only=not direct)
            self.sensitive_read_events.append(event)

    def _handle_file_write(self, event: RuntimeEvent) -> None:
        path = event.object_path or ""
        if not path:
            return
        process = self._process_key(event.actor_id, event.process_id)
        process_taint = self.process_inputs.get(process)
        if event.taint_ids:
            self.file_taint[path] = FileTaint(set(event.taint_ids), event.evidence_level, event.event_id, event.evidence_strength, event.carrier_type)
        elif process_taint and event.metadata.get("output_from_tainted_input"):
            self._add_context(event, process_taint.taint_ids, reason="CONTEXT_PROCESS_CONTACT", source_event_id=process_taint.last_event_id)
        else:
            self.file_taint.pop(path, None)

    def _handle_file_derivation(self, event: RuntimeEvent) -> None:
        source_path = normalize_path(event.metadata.get("source_path", ""))
        dest_path = event.object_path or normalize_path(event.metadata.get("destination_path", ""))
        if not source_path or not dest_path or source_path not in self.file_taint:
            return
        record = self.file_taint[source_path]
        self._merge_taint(event, record.taint_ids, record.evidence_level, reason=f"TAINT_FILE_{event.operation.upper()}_INHERITS", evidence_strength=record.evidence_strength, carrier_type="file_content", carrier_location=dest_path)
        self.file_taint[dest_path] = FileTaint(set(record.taint_ids), record.evidence_level, event.event_id, record.evidence_strength)

    def _handle_process_exec(self, event: RuntimeEvent) -> None:
        argv_taint = set(event.taint_ids)
        for key in ("argv", "env", "stdin", "command"):
            argv_taint.update(match.taint_id for match in self.registry.detect(event.metadata.get(key)))
        for path in _paths_from_metadata(event.metadata):
            if path in self.file_taint and event.metadata.get("passes_file_content"):
                record = self.file_taint[path]
                if record.evidence_strength in {"exact_value", "encoded_value", "reconstructed_value"}:
                    argv_taint.update(record.taint_ids)
                else:
                    self._add_context(event, record.taint_ids, reason="CONTEXT_PROCESS_CONTACT", source_event_id=record.last_event_id)
        if argv_taint:
            self._merge_taint(event, argv_taint, event.evidence_level if event.evidence_level != "unknown" else "confirmed", reason="TAINT_PROCESS_INPUT", evidence_strength=event.evidence_strength if event.evidence_strength != "unknown" else "exact_value", carrier_type=event.carrier_type if event.carrier_type != "unknown" else "process_argv", carrier_location=event.carrier_location or "argv/env/stdin")
            process = self._process_key(event.object_id or event.actor_id, event.process_id)
            self.process_inputs[process] = ProcessInputTaint(set(event.taint_ids), event.evidence_level, event.event_id, bool(event.data_preview), context_only=False)

    def _handle_ipc(self, event: RuntimeEvent) -> None:
        if event.operation == "pipe":
            source_process = self._process_key(str(event.metadata.get("source_process") or event.actor_id), event.process_id)
            target_process = self._process_key(str(event.metadata.get("target_process") or event.object_id), event.metadata.get("target_process_id"))
            source = self.process_inputs.get(source_process)
            if source and source.taint_ids:
                if event.taint_ids and event.data_preview:
                    self._merge_taint(event, source.taint_ids, "confirmed", reason="TAINT_PIPE_MARKER", evidence_strength="exact_value", carrier_type="pipe", carrier_location=str(event.object_id))
                    self.process_inputs[target_process] = ProcessInputTaint(set(event.taint_ids), "confirmed", event.event_id, True, context_only=False)
                else:
                    self._add_context(event, source.taint_ids, reason="CONTEXT_PROCESS_CONTACT", source_event_id=source.last_event_id)
                    self.process_inputs[target_process] = ProcessInputTaint(set(source.taint_ids), "candidate", event.event_id, False, context_only=True)
            return
        if event.taint_ids:
            process = self._process_key(event.actor_id, event.process_id)
            self.process_inputs[process] = ProcessInputTaint(set(event.taint_ids), event.evidence_level, event.event_id, bool(event.data_preview), context_only=False)

    def _handle_tool_event(self, event: RuntimeEvent) -> None:
        tool_id = str(event.metadata.get("tool_id") or event.actor_id or event.object_id)
        for ref in event.metadata.get("input_taint_ids", []):
            self._merge_taint(event, [str(ref)], "confirmed", reason="TAINT_TOOL_REFERENCE", evidence_strength="structured_relation", carrier_type="tool_argument", carrier_location=tool_id)
        if event.operation == "return":
            if event.taint_ids:
                self.tool_outputs[tool_id].update(event.taint_ids)
            for ref in event.metadata.get("output_taint_ids", []):
                self.tool_outputs[tool_id].add(str(ref))

    def _handle_network_send(self, event: RuntimeEvent) -> None:
        upload_file = normalize_path(event.metadata.get("upload_file_path", ""))
        if upload_file and upload_file in self.file_taint:
            record = self.file_taint[upload_file]
            self._merge_taint(event, record.taint_ids, record.evidence_level, reason="TAINT_EXPLICIT_FILE_UPLOAD", evidence_strength="explicit_file_identity", carrier_type="upload_file", carrier_location=upload_file)
        for key in ("body", "headers", "query", "socket_payload", "tool_arguments", "json_body", "form", "multipart"):
            matches = self.registry.detect(event.metadata.get(key))
            if matches:
                self._merge_marker_matches(event, matches, carrier_type=_carrier_for_network_key(key), carrier_location=key)
        process = self._process_key(event.actor_id, event.process_id)
        process_taint = self.process_inputs.get(process)
        if not event.taint_ids and process_taint and event.metadata.get("opaque_payload"):
            self._add_context(event, process_taint.taint_ids, reason="CONTEXT_PROCESS_CONTACT", source_event_id=process_taint.last_event_id)

    def _enrich_from_markers(self, event: RuntimeEvent) -> None:
        matches = self.registry.detect(event.data_preview)
        for value in event.metadata.values():
            matches.extend(self.registry.detect(value))
        if matches:
            self._merge_marker_matches(event, matches)

    def _merge_marker_matches(self, event: RuntimeEvent, matches: list[MarkerMatch], *, carrier_type: str | None = None, carrier_location: str | None = None) -> None:
        for match in matches:
            event.metadata.setdefault("marker_matches", []).append(
                {"taint_id": match.taint_id, "variant": match.variant_name, "derived": match.derived, "carrier_type": carrier_type or event.carrier_type}
            )
            level = "conservative" if match.derived else "confirmed"
            strength = "hash_derived" if match.derived else ("exact_value" if match.variant_name == "raw" else "encoded_value")
            rule_id = "TAINT_HASH_DERIVED" if match.derived else ("TAINT_EXACT_MARKER" if match.variant_name == "raw" else f"TAINT_{match.variant_name.upper()}_MARKER")
            self._merge_taint(
                event,
                [match.taint_id],
                level,
                reason=rule_id,
                evidence_strength=strength,
                carrier_type=carrier_type,
                carrier_location=carrier_location,
                derived_from_hash=match.derived,
                transformation=match.variant_name,
            )

    def _merge_taint(
        self,
        event: RuntimeEvent,
        taint_ids,
        level: str,
        *,
        reason: str,
        evidence_strength: str | None = None,
        carrier_type: str | None = None,
        carrier_location: str | None = None,
        derived_from_hash: bool | None = None,
        transformation: str | None = None,
    ) -> None:
        current = set(event.taint_ids)
        current.update(str(item) for item in taint_ids if str(item))
        event.taint_ids = sorted(current)
        event.evidence_level = _strongest_level(event.evidence_level, level)
        if evidence_strength:
            event.evidence_strength = _strongest_strength(event.evidence_strength, evidence_strength)
        if carrier_type:
            event.carrier_type = carrier_type
        if carrier_location:
            event.carrier_location = carrier_location
        if derived_from_hash:
            event.derived_from_hash = True
            event.metadata["derived_from_hash"] = True
        if transformation:
            event.metadata.setdefault("transformations", [])
            if transformation not in event.metadata["transformations"]:
                event.metadata["transformations"].append(transformation)
        event.metadata.setdefault("taint_reasons", [])
        if reason not in event.metadata["taint_reasons"]:
            event.metadata["taint_reasons"].append(reason)

    def _add_context(self, event: RuntimeEvent, taint_ids, *, reason: str, source_event_id: str | None = None) -> None:
        context_ids = sorted({str(item) for item in taint_ids if str(item)})
        if not context_ids:
            return
        existing = set(event.metadata.get("context_taint_ids", []))
        existing.update(context_ids)
        event.metadata["context_taint_ids"] = sorted(existing)
        event.metadata.setdefault("context_reasons", [])
        if reason not in event.metadata["context_reasons"]:
            event.metadata["context_reasons"].append(reason)
        if source_event_id:
            event.metadata.setdefault("context_source_event_ids", [])
            if source_event_id not in event.metadata["context_source_event_ids"]:
                event.metadata["context_source_event_ids"].append(source_event_id)
        event.evidence_strength = _strongest_strength(event.evidence_strength, "process_context")
        event.evidence_level = _strongest_level(event.evidence_level, "candidate")

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
            evidence_strength="temporal_cooccurrence",
            observation_source="inferred_relation",
            carrier_type="unknown",
            instrumentation_visibility="payload_not_observed",
            metadata={
                "reason": "sensitive_read_and_network_connect_without_payload_or_file_upload_evidence",
                "candidate_rule_id": "CANDIDATE_READ_BEFORE_CONNECT",
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
        return RuntimeEvent.from_dict(event.to_dict())


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


def _strongest_strength(current: str, incoming: str) -> str:
    order = {
        "exact_value": 0,
        "encoded_value": 1,
        "reconstructed_value": 2,
        "structured_relation": 3,
        "explicit_file_identity": 4,
        "hash_derived": 5,
        "process_context": 6,
        "temporal_cooccurrence": 7,
        "candidate": 8,
        "unknown": 9,
    }
    current = current if current in order else "unknown"
    incoming = incoming if incoming in order else "unknown"
    return current if order[current] <= order[incoming] else incoming


def _carrier_for_network_key(key: str) -> str:
    return {
        "body": "http_body",
        "json_body": "http_body",
        "headers": "http_header",
        "query": "http_query",
        "form": "http_form",
        "multipart": "multipart_field",
        "socket_payload": "socket_payload",
        "tool_arguments": "tool_argument",
    }.get(key, "unknown")


def _is_concrete_network_flow(event: RuntimeEvent) -> bool:
    if event.event_type not in {"network_send", "file_upload"} and event.operation not in {"send", "upload"}:
        return False
    if not event.taint_ids:
        return False
    if event.derived_from_hash or event.evidence_strength in {"hash_derived", "process_context", "temporal_cooccurrence", "candidate"}:
        return False
    if event.metadata.get("context_taint_ids") and not event.metadata.get("marker_matches") and not event.metadata.get("upload_file_path"):
        return False
    return True
