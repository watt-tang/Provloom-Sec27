from __future__ import annotations

import hashlib
from typing import Any

from app.dynamic.models import RuntimeEdge, RuntimeEvent, RuntimeNode, RuntimeProvenanceGraph, confidence_for_evidence


EDGE_BY_OPERATION = {
    "read": "READ",
    "write": "WRITE",
    "exec": "EXEC",
    "fork": "FORK",
    "pipe": "PIPE",
    "argv": "PASS_AS_ARGUMENT",
    "env": "PASS_AS_ENV",
    "stdin": "PIPE",
    "stdout": "RETURN_TO",
    "stderr": "RETURN_TO",
    "invoke": "CONTROL_TRIGGER",
    "return": "RETURN_TO",
    "send": "SEND",
    "connect": "CONNECT",
    "upload": "UPLOAD_FILE",
    "persist": "PERSIST",
    "materialize_instruction": "MATERIALIZE_INSTRUCTION",
    "source": "DERIVE",
    "derive": "DERIVE",
    "extract": "EXTRACT",
}


class RuntimeGraphBuilder:
    def __init__(self, *, session_id: str) -> None:
        self.session_id = session_id
        self.nodes: dict[str, RuntimeNode] = {}
        self.edges: dict[tuple[str, str, str], RuntimeEdge] = {}

    def build(self, events: list[RuntimeEvent], sources: list[dict[str, Any]] | None = None) -> RuntimeProvenanceGraph:
        for source in sources or []:
            self._node(
                f"source:{source.get('taint_id')}",
                "SensitiveSource",
                str(source.get("source_location") or source.get("taint_id")),
                source,
            )
        for event in events:
            self._ingest(event)
        return RuntimeProvenanceGraph(session_id=self.session_id, nodes=list(self.nodes.values()), edges=list(self.edges.values()))

    def _ingest(self, event: RuntimeEvent) -> None:
        actor = self._actor_node(event)
        obj = self._object_node(event)
        edge_type = EDGE_BY_OPERATION.get(event.operation, event.operation.upper() or "OBSERVE")

        if event.event_type == "taint_propagation":
            source_ref = event.metadata.get("source", {})
            target_ref = event.metadata.get("target", {})
            source_node = self._ref_node(source_ref, fallback=actor)
            target_node = self._ref_node(target_ref, fallback=obj)
            self._edge(source_node, target_node, "DERIVE", event, "taint propagation over structured runtime value")
            return

        if event.event_type == "sensitive_source":
            for taint_id in event.taint_ids:
                source_node = self._node(f"source:{taint_id}", "SensitiveSource", event.object_path or taint_id, {"taint_id": taint_id})
                self._edge(source_node, obj, "DERIVE", event, "synthetic sensitive source registered")
            return

        if event.event_type == "candidate_dependency":
            source_ref = event.metadata.get("source_event_id")
            for taint_id in event.taint_ids:
                source_node = self._node(f"source:{taint_id}", "SensitiveSource", taint_id, {"taint_id": taint_id, "source_event_id": source_ref})
                self._edge(source_node, obj, "CONNECT", event, "candidate read-before-network relation")
            return

        if event.taint_ids and event.operation not in {"read", "send", "upload", "connect"}:
            for taint_id in event.taint_ids:
                source_node = self._node(f"source:{taint_id}", "SensitiveSource", taint_id, {"taint_id": taint_id})
                self._edge(source_node, actor, "DERIVE", event, "marker or structured taint observed at runtime actor")

        if event.object_type == "network":
            if event.metadata.get("marker_matches"):
                for taint_id in event.taint_ids:
                    source_node = self._node(f"source:{taint_id}", "SensitiveSource", taint_id, {"taint_id": taint_id})
                    self._edge(source_node, obj, "SEND", event, "marker variant directly observed in network payload")
            elif event.metadata.get("opaque_payload") and not event.metadata.get("upload_file_path"):
                for taint_id in event.taint_ids:
                    source_node = self._node(f"source:{taint_id}", "SensitiveSource", taint_id, {"taint_id": taint_id})
                    self._edge(source_node, actor, "DERIVE", event, "opaque payload from previously tainted runtime input")
            self._edge(actor, obj, edge_type, event, f"{event.actor_id} {event.operation} network endpoint")
            upload_file = event.metadata.get("upload_file_path")
            if upload_file and event.taint_ids:
                file_node = self._node(f"file:{upload_file}", "File", str(upload_file), {"path": upload_file})
                self._edge(file_node, obj, "UPLOAD_FILE", event, "explicit upload of tainted file")
            return

        if event.operation == "read":
            self._edge(obj, actor, "READ", event, "actor read object")
            for taint_id in event.taint_ids:
                source_node = self._node(f"source:{taint_id}", "SensitiveSource", taint_id, {"taint_id": taint_id})
                self._edge(source_node, obj, "DERIVE", event, "source content represented by file/value")
            return

        if event.operation == "write":
            self._edge(actor, obj, "WRITE", event, "actor wrote object")
            return

        if event.operation == "exec":
            self._edge(actor, obj, "EXEC", event, "process/tool executed child or command")
            if event.taint_ids:
                self._edge(actor, obj, "PASS_AS_ARGUMENT", event, "tainted argv/env/stdin passed into process")
            return

        if event.operation == "pipe":
            source_actor = self._node(str(event.metadata.get("source_process") or event.actor_id), "Process", str(event.metadata.get("source_process") or event.actor_id), {})
            target_actor = self._node(str(event.metadata.get("target_process") or event.object_id), "Process", str(event.metadata.get("target_process") or event.object_id), {})
            self._edge(source_actor, target_actor, "PIPE", event, "stdout/stdin pipe propagation")
            return

        if event.operation == "materialize_instruction":
            self._edge(actor, obj, "MATERIALIZE_INSTRUCTION", event, "runtime generated instruction artifact")
            return

        self._edge(actor, obj, edge_type, event, f"runtime operation {event.operation}")

    def _ref_node(self, ref: dict[str, Any], *, fallback: str) -> str:
        ref_type = ref.get("type")
        if ref_type == "file":
            path = str(ref.get("path") or "unknown")
            return self._node(f"file:{path}", "File", path, {"path": path})
        if ref_type in {"tool_input", "tool_output", "command_output"}:
            tool_id = str(ref.get("tool_id") or "unknown")
            return self._node(f"TOOL:{tool_id}", "ToolInvocation", tool_id, ref)
        if ref_type in {"command_input", "stdout"}:
            label = str(ref.get("tool_id") or ref.get("command_preview") or "process")
            return self._node(f"PROC:{label}", "Process", label, ref)
        return fallback

    def _actor_node(self, event: RuntimeEvent) -> str:
        node_type = {"agent": "AgentSession", "tool": "ToolInvocation", "process": "Process"}.get(event.actor_type, event.actor_type.title())
        return self._node(event.actor_id, node_type, event.actor_id, {"process_id": event.process_id, "parent_process_id": event.parent_process_id})

    def _object_node(self, event: RuntimeEvent) -> str:
        if event.object_type == "file":
            return self._node(f"file:{event.object_path or event.object_id}", "File", event.object_path or event.object_id, {"path": event.object_path})
        if event.object_type == "network":
            return self._node(f"network:{event.object_id}", "NetworkEndpoint", event.metadata.get("url") or event.metadata.get("domain") or event.object_id, event.metadata)
        if event.object_type == "process":
            return self._node(str(event.object_id or event.actor_id), "Process", str(event.object_id or event.actor_id), event.metadata)
        if event.object_type == "instruction":
            return self._node(f"instruction:{event.object_path or event.object_id}", "RuntimeInstruction", event.object_path or event.object_id, event.metadata)
        if event.object_type == "persistence":
            return self._node(f"persistence:{event.object_id}", "PersistenceTarget", event.object_path or event.object_id, event.metadata)
        return self._node(str(event.object_id), "DataObject", str(event.object_id), event.metadata)

    def _node(self, node_id: str, node_type: str, label: str, metadata: dict[str, Any]) -> str:
        if node_id not in self.nodes:
            self.nodes[node_id] = RuntimeNode(node_id=node_id, node_type=node_type, label=label, metadata=dict(metadata))
        else:
            self.nodes[node_id].metadata.update({key: value for key, value in metadata.items() if value not in (None, "", [])})
        return node_id

    def _edge(self, source: str, target: str, edge_type: str, event: RuntimeEvent, reason: str) -> None:
        if not source or not target or source == target:
            return
        key = (source, target, edge_type)
        existing = self.edges.get(key)
        if existing:
            existing.event_ids = sorted(set(existing.event_ids + [event.event_id]))
            existing.taint_ids = sorted(set(existing.taint_ids + event.taint_ids))
            existing.metadata.setdefault("events", []).append(event.to_dict())
            return
        self.edges[key] = RuntimeEdge(
            edge_id=_edge_id(source, target, edge_type),
            source_node=source,
            target_node=target,
            edge_type=edge_type,
            event_ids=[event.event_id],
            taint_ids=list(event.taint_ids),
            evidence_level=event.evidence_level,
            confidence=confidence_for_evidence(event.evidence_level),
            reason=reason,
            metadata={"events": [event.to_dict()], **event.metadata},
        )


def _edge_id(source: str, target: str, edge_type: str) -> str:
    digest = hashlib.sha256(f"{source}|{target}|{edge_type}".encode("utf-8")).hexdigest()[:16]
    return f"E{digest}"
