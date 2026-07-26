from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from app.runtime.skill_parser import SkillDefinition, load_skill_definition
from app.runner.models import SandboxExecution, ToolCallEvent
from app.taint.models import TaintEvidenceLevel, TaintLabel, TaintSet, new_taint_event_id
from app.taint.serialization import taint_event_payload
from app.taint.sink_tracker import classify_http_sink
from app.taint.source_registry import SourceRegistry, normalize_path
from app.taint.state import TaintState

ACTION_STDOUT_RE = re.compile(r"actions\.([A-Za-z0-9_-]+)\.stdout")
PATH_RE = re.compile(r"(/etc/[^\s\"']+|/root/[^\s\"']+|/proc/[^\s\"']+|/sys/[^\s\"']+|/var/run/[^\s\"']+|runtime_output/[^\s\"']+|public/[^\s\"']+|\.provloom/adapters/credential_state/[^\s\"']+)")
REDIRECT_RE = re.compile(r">\s*([^\s\"']+)")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def build_taint_events(
    execution: SandboxExecution,
    *,
    source_registry: SourceRegistry | None = None,
    skill_definition: SkillDefinition | None = None,
) -> list[dict[str, Any]]:
    registry = source_registry or SourceRegistry()
    definition = skill_definition if skill_definition is not None else _load_skill_definition(execution)
    analyzer = TaintPropagationAnalyzer(
        execution=execution,
        registry=registry,
        skill_definition=definition,
    )
    return analyzer.build()


class TaintPropagationAnalyzer:
    def __init__(
        self,
        *,
        execution: SandboxExecution,
        registry: SourceRegistry,
        skill_definition: SkillDefinition | None,
    ) -> None:
        self.execution = execution
        self.registry = registry
        self.skill_definition = skill_definition
        self.state = TaintState()
        self.events: list[dict[str, Any]] = []
        self._source_events_by_path: dict[str, str] = {}
        self._action_config_by_id = {
            action.id: dict(action.config)
            for action in (skill_definition.actions if skill_definition is not None else [])
        }
        self._tool_start_by_id = {
            event.tool_id: event
            for event in execution.tool_calls
            if event.event == "start"
        }

    def build(self) -> list[dict[str, Any]]:
        self._seed_file_sources()
        for event in sorted(self.execution.tool_calls, key=lambda item: (item.timestamp, item.event_id or "")):
            if event.event != "start":
                continue
            self._process_tool_start(event)
        self._emit_candidate_dependencies()
        return sorted(self.events, key=lambda item: (item["timestamp"], item["event_id"]))

    def _seed_file_sources(self) -> None:
        for event in sorted(self.execution.file_events, key=lambda item: (item.timestamp, item.event_id or "")):
            if event.action != "read":
                continue
            match = self.registry.match_path(event.path)
            if match is None:
                continue
            label = self._ensure_source_label(
                path=match.normalized_path,
                source_type=match.source_type,
                sensitivity=match.sensitivity,
                source_event_id=event.event_id or new_taint_event_id("file-source"),
                timestamp=event.timestamp,
                metadata={**match.metadata, "pid": event.pid, "source": event.source},
            )
            self.state.taint_file(match.normalized_path, [label.taint_id])

    def _process_tool_start(self, event: ToolCallEvent) -> None:
        config = self._tool_config(event)
        declared_config = self._action_config_by_id.get(event.tool_id, config)
        input_taint = self._input_taint_from_config(config).union(self._input_taint_from_config(declared_config))

        if event.tool_type == "read_file":
            self._handle_read_file(event, config)
        elif event.tool_type == "write_file":
            self._handle_write_file(event, config, declared_config, input_taint)
        elif event.tool_type == "http_request":
            self._handle_http_request(event, config, declared_config, input_taint)
        elif event.tool_type == "run_command":
            self._handle_run_command(event, config, input_taint)
        elif input_taint.is_empty():
            self.state.set_action_output(event.tool_id, [])
        else:
            self.state.set_action_output(event.tool_id, input_taint)
            self._emit_propagation(
                event=event,
                taint=input_taint,
                rule="opaque_tool_conservative",
                evidence_level=TaintEvidenceLevel.CONSERVATIVE,
                target={"type": "tool_output", "tool_id": event.tool_id},
            )

    def _handle_read_file(self, event: ToolCallEvent, config: dict[str, Any]) -> None:
        path = str(config.get("path", ""))
        match = self.registry.match_path(path)
        file_taint = self.state.taint_for_file(path)
        if match is not None:
            label = self._ensure_source_label(
                path=match.normalized_path,
                source_type=match.source_type,
                sensitivity=match.sensitivity,
                source_event_id=event.event_id or new_taint_event_id("tool-source"),
                timestamp=event.timestamp,
                metadata={**match.metadata, "tool_call_id": event.tool_id},
            )
            file_taint = file_taint.union([label.taint_id])
            self.state.taint_file(path, file_taint)

        self.state.set_action_output(event.tool_id, file_taint)
        if not file_taint.is_empty():
            self._emit_propagation(
                event=event,
                taint=file_taint,
                rule="read_file_rule",
                evidence_level=TaintEvidenceLevel.CONFIRMED,
                source={"type": "file", "path": normalize_path(path)},
                target={"type": "tool_output", "tool_id": event.tool_id},
            )

    def _handle_write_file(
        self,
        event: ToolCallEvent,
        config: dict[str, Any],
        declared_config: dict[str, Any],
        input_taint: TaintSet,
    ) -> None:
        path = str(config.get("path", ""))
        append = bool(config.get("append"))
        content_taint = input_taint.union(self._input_taint_from_value(declared_config.get("content", "")))
        if content_taint.is_empty():
            if not append:
                self.state.clear_file(path)
            self.state.set_action_output(event.tool_id, [])
            return

        self.state.taint_file(path, content_taint, writer_event_id=event.event_id) if append else self.state.set_file_taint(path, content_taint, writer_event_id=event.event_id)
        self.state.set_action_output(event.tool_id, content_taint)
        self._emit_propagation(
            event=event,
            taint=content_taint,
            rule="write_file_rule_append" if append else "write_file_rule",
            evidence_level=TaintEvidenceLevel.CONFIRMED,
            source={"type": "tool_input", "tool_id": event.tool_id},
            target={"type": "file", "path": normalize_path(path)},
        )

    def _handle_http_request(
        self,
        event: ToolCallEvent,
        config: dict[str, Any],
        declared_config: dict[str, Any],
        input_taint: TaintSet,
    ) -> None:
        body_taint = input_taint.union(self._input_taint_from_value(declared_config.get("body", "")))
        header_taint = self._input_taint_from_value(declared_config.get("headers", {}))
        url_taint = self._input_taint_from_value(declared_config.get("url", ""))
        sink_taint = body_taint.union(url_taint).union(header_taint)
        self.state.set_action_output(event.tool_id, [])
        sink_config = {**declared_config, **config}
        sink = classify_http_sink(sink_config, sink_taint)
        if not sink.get("is_sink"):
            return
        self._emit_sink(
            event=event,
            taint=sink_taint,
            rule="network_sink_rule",
            evidence_level=TaintEvidenceLevel.CONFIRMED,
            sink_type=str(sink.get("sink_type", "http_body")),
            destination=str(sink_config.get("url", "")),
            metadata={
                "method": str(sink_config.get("method", "GET")).upper(),
                "payload_size": sink.get("payload_size", 0),
                "payload_hash": sink.get("payload_hash", ""),
                "carrier_type": str(sink.get("sink_type", "http_body")),
                "carrier_location": str(sink.get("carrier_location") or sink.get("sink_type", "")),
                "evidence_strength": "structured_relation",
                "network_evidence_level": "tainted_payload_observed",
                "headers": sink_config.get("headers", {}),
                "query": str(urlparse(str(sink_config.get("url", ""))).query),
                "body": sink_config.get("body", ""),
            },
        )

    def _handle_run_command(self, event: ToolCallEvent, config: dict[str, Any], input_taint: TaintSet) -> None:
        command = str(config.get("command", ""))
        command_taint = input_taint
        for path in _paths_in_value(command):
            match = self.registry.match_path(path)
            if match is not None:
                label = self._ensure_source_label(
                    path=match.normalized_path,
                    source_type=match.source_type,
                    sensitivity=match.sensitivity,
                    source_event_id=event.event_id or new_taint_event_id("command-source"),
                    timestamp=event.timestamp,
                    metadata={**match.metadata, "tool_call_id": event.tool_id, "via": "command_argument"},
                )
                self.state.taint_file(path, [label.taint_id])
            command_taint = command_taint.union(self.state.taint_for_file(path))

        if command_taint.is_empty():
            self.state.set_action_output(event.tool_id, [])
            return

        self.state.set_action_output(event.tool_id, command_taint)
        self._emit_propagation(
            event=event,
            taint=command_taint,
            rule="opaque_command_transform",
            evidence_level=TaintEvidenceLevel.CONSERVATIVE,
            source={"type": "command_input", "command_preview": command[:120]},
            target={"type": "stdout", "tool_id": event.tool_id},
        )

        redirect_target = _redirect_target(command)
        if redirect_target:
            self.state.set_file_taint(redirect_target, command_taint, writer_event_id=event.event_id)
            self._emit_propagation(
                event=event,
                taint=command_taint,
                rule="shell_redirect_file_rule",
                evidence_level=TaintEvidenceLevel.CONSERVATIVE,
                source={"type": "command_output", "tool_id": event.tool_id},
                target={"type": "file", "path": normalize_path(redirect_target)},
            )

        if _command_has_network_body_sink(command):
            network_meta = self._nearest_network_metadata(event)
            destination = _first_url(command) or str(network_meta.get("destination") or "unknown")
            self._emit_sink(
                event=event,
                taint=command_taint,
                rule="opaque_command_network_sink",
                evidence_level=TaintEvidenceLevel.CONSERVATIVE,
                sink_type="command_http_body",
                destination=destination,
                metadata={"command_preview": command[:160], **network_meta},
            )

    def _emit_candidate_dependencies(self) -> None:
        if any(event["event_type"] == "taint_sink" for event in self.events):
            return
        source_events = [event for event in self.events if event["event_type"] == "taint_source"]
        if not source_events or not self.execution.network_events:
            return
        first_source = source_events[0]
        first_network = sorted(self.execution.network_events, key=lambda item: (item.timestamp, item.event_id or ""))[0]
        if first_source["timestamp"] > first_network.timestamp:
            return
        self.events.append(
            taint_event_payload(
                event_type="candidate_dependency",
                event_id=new_taint_event_id("candidate"),
                timestamp=first_network.timestamp,
                run_id=self.execution.execution_id,
                process_id=first_network.pid,
                parent_event_id=first_network.event_id,
                taint_ids=first_source.get("taint_ids", []),
                evidence_level=TaintEvidenceLevel.CANDIDATE.value,
                propagation_rule="read_before_network_no_payload_dependency",
                source_event_ids=[first_source["event_id"]],
                metadata={
                    "relation_type": "candidate_dependency",
                    "source_object": first_source.get("metadata", {}).get("source_object"),
                    "sink_address": first_network.address,
                    "reason": "A sensitive source and network event co-occurred without payload, file, pipe, argument, or tool dependency evidence.",
                },
            )
        )

    def _ensure_source_label(
        self,
        *,
        path: str,
        source_type: str,
        sensitivity: str,
        source_event_id: str,
        timestamp: str,
        metadata: dict[str, Any],
    ) -> TaintLabel:
        normalized = normalize_path(path)
        existing_id = next(
            (
                label.taint_id
                for label in self.state.labels.values()
                if label.source_object == normalized and label.source_type == source_type
            ),
            "",
        )
        if existing_id:
            return self.state.labels[existing_id]

        label = TaintLabel.create(
            run_id=self.execution.execution_id,
            source_type=source_type,
            sensitivity=sensitivity,
            source_object=normalized,
            source_event_id=source_event_id,
            created_at=timestamp,
            metadata=metadata,
        )
        self.state.add_label(label)
        self._source_events_by_path[normalized] = source_event_id
        self.events.append(
            taint_event_payload(
                event_type="taint_source",
                event_id=new_taint_event_id("taint-source"),
                timestamp=timestamp,
                run_id=self.execution.execution_id,
                parent_event_id=source_event_id,
                taint_ids=[label.taint_id],
                evidence_level=TaintEvidenceLevel.CONFIRMED.value,
                propagation_rule="source_registry_path_match",
                source_event_ids=[source_event_id],
                metadata={
                    "label": label.to_dict(),
                    "source_object": normalized,
                    "source_type": source_type,
                    "sensitivity": sensitivity,
                    **metadata,
                },
            )
        )
        return label

    def _emit_propagation(
        self,
        *,
        event: ToolCallEvent,
        taint: TaintSet,
        rule: str,
        evidence_level: TaintEvidenceLevel,
        source: dict[str, Any] | None = None,
        target: dict[str, Any] | None = None,
    ) -> None:
        if taint.is_empty():
            return
        self.events.append(
            taint_event_payload(
                event_type="taint_propagation",
                event_id=new_taint_event_id("taint-prop"),
                timestamp=event.timestamp,
                run_id=self.execution.execution_id,
                tool_call_id=event.tool_id,
                parent_event_id=event.event_id,
                step_id=event.step_id,
                taint_ids=taint.serialize(),
                evidence_level=evidence_level.value,
                propagation_rule=rule,
                source_event_ids=self._source_event_ids(taint),
                metadata={
                    "relation_type": "confirmed_taint_flow",
                    "source": source or {},
                    "target": target or {},
                    "tool_type": event.tool_type,
                },
            )
        )

    def _emit_sink(
        self,
        *,
        event: ToolCallEvent,
        taint: TaintSet,
        rule: str,
        evidence_level: TaintEvidenceLevel,
        sink_type: str,
        destination: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if taint.is_empty():
            return
        self.events.append(
            taint_event_payload(
                event_type="taint_sink",
                event_id=new_taint_event_id("taint-sink"),
                timestamp=event.timestamp,
                run_id=self.execution.execution_id,
                tool_call_id=event.tool_id,
                parent_event_id=event.event_id,
                step_id=event.step_id,
                taint_ids=taint.serialize(),
                evidence_level=evidence_level.value,
                propagation_rule=rule,
                source_event_ids=self._source_event_ids(taint),
                metadata={
                    "relation_type": "confirmed_taint_flow",
                    "sink_type": sink_type,
                    "destination": destination,
                    "tool_type": event.tool_type,
                    **(metadata or {}),
                },
            )
        )

    def _source_event_ids(self, taint: TaintSet) -> list[str]:
        return [
            label.source_event_id
            for label in self.state.labels_for(taint)
            if label.source_event_id
        ]

    def _tool_config(self, event: ToolCallEvent) -> dict[str, Any]:
        return dict(getattr(event, "metadata", {}).get("config", {}) or {})

    def _nearest_network_metadata(self, event: ToolCallEvent) -> dict[str, Any]:
        candidates = [
            item
            for item in self.execution.network_events
            if str(item.timestamp) >= str(event.timestamp)
        ] or list(self.execution.network_events)
        if not candidates:
            return {}
        network = sorted(candidates, key=lambda item: (item.timestamp, item.event_id or ""))[0]
        destination = (
            network.sink_display_label
            or network.display_label
            or network.sink_url
            or network.sink_domain
            or network.address
        )
        return {
            "destination": destination,
            "network_event_id": network.event_id,
            "sink_display_label": network.sink_display_label or network.display_label or destination,
            "sink_raw_ip": network.sink_raw_ip,
            "sink_domain": network.sink_domain,
            "sink_url": network.sink_url,
            "sink_port": network.sink_port,
            "sink_type": network.sink_type,
            "is_controlled_sink": network.is_controlled_sink,
            "sink_resolution_status": network.sink_resolution_status,
            "network_evidence_sources": list(network.network_evidence_sources),
            "original_target_candidates": list(network.original_target_candidates),
            "selected_sink_reason": network.selected_sink_reason,
        }

    def _input_taint_from_config(self, config: dict[str, Any]) -> TaintSet:
        taint = TaintSet()
        for ref in _action_refs(config):
            taint = taint.union(self.state.taint_for_action(ref))
        for path in _paths_in_value(config):
            taint = taint.union(self.state.taint_for_file(path))
        return taint

    def _input_taint_from_value(self, value: Any) -> TaintSet:
        taint = TaintSet()
        for ref in _action_refs(value):
            taint = taint.union(self.state.taint_for_action(ref))
        for path in _paths_in_value(value):
            taint = taint.union(self.state.taint_for_file(path))
        return taint


def _load_skill_definition(execution: SandboxExecution) -> SkillDefinition | None:
    try:
        return load_skill_definition(execution.skill_path, execution.skill_file, allow_empty_actions=True)
    except Exception:
        return None


def _action_refs(value: Any) -> list[str]:
    return sorted(set(ACTION_STDOUT_RE.findall(_serialize(value))))


def _paths_in_value(value: Any) -> list[str]:
    return sorted(set(PATH_RE.findall(_serialize(value))))


def _serialize(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError:
        return str(value)


def _redirect_target(command: str) -> str:
    match = REDIRECT_RE.search(command)
    return match.group(1) if match else ""


def _first_url(command: str) -> str:
    match = URL_RE.search(command)
    return match.group(0) if match else ""


def _command_has_network_body_sink(command: str) -> bool:
    lower = command.lower()
    return any(tool in lower for tool in ("curl ", "wget ")) and any(token in lower for token in ("-d ", "--data", "--upload-file", "-f ", "@-"))


def collect_action_refs(value: Any) -> list[str]:
    return _action_refs(value)
