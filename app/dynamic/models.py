from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any


SCHEMA_VERSION = "runtime-analysis-v3"
EVIDENCE_ORDER = {"confirmed": 0, "conservative": 1, "candidate": 2, "unknown": 3}
EVIDENCE_LEVELS = {"confirmed", "conservative", "candidate", "unknown"}
EVIDENCE_STRENGTHS = {
    "exact_value",
    "encoded_value",
    "reconstructed_value",
    "structured_relation",
    "explicit_file_identity",
    "process_context",
    "temporal_cooccurrence",
    "hash_derived",
    "candidate",
    "unknown",
}
OBSERVATION_SOURCES = {
    "runtime_wrapper",
    "strace_syscall",
    "synthetic_adapter",
    "instruction_simulation",
    "inferred_relation",
    "static_alignment",
}
CARRIER_TYPES = {
    "file_content",
    "file_path",
    "process_argv",
    "process_env",
    "stdin",
    "stdout",
    "stderr",
    "pipe",
    "tool_argument",
    "tool_return",
    "http_header",
    "http_query",
    "http_body",
    "http_form",
    "multipart_field",
    "upload_file",
    "socket_payload",
    "llm_context",
    "instruction_text",
    "unknown",
}
NETWORK_EVIDENCE_LEVELS = {
    "endpoint_observed",
    "request_observed",
    "tainted_payload_observed",
    "tainted_payload_delivered",
    "encrypted_payload_invisible",
}


@dataclass
class RuntimeEvent:
    event_id: str
    timestamp: float
    event_type: str
    process_id: int | str | None
    parent_process_id: int | str | None
    session_id: str
    skill_id: str
    actor_type: str
    actor_id: str
    object_type: str
    object_id: str
    object_path: str | None
    operation: str
    data_preview: str | None = None
    data_hash: str | None = None
    byte_count: int | None = None
    taint_ids: list[str] = field(default_factory=list)
    evidence_level: str = "unknown"
    raw_source: str = "runtime_wrapper"
    raw_reference: str = ""
    evidence_strength: str = "unknown"
    observation_source: str = "runtime_wrapper"
    carrier_type: str = "unknown"
    carrier_location: str | None = None
    derived_from_hash: bool = False
    instrumentation_visibility: str = "observed"
    raw_event_id: str | None = None
    trace_file: str | None = None
    trace_line: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["taint_ids"] = sorted({str(item) for item in self.taint_ids if str(item)})
        if payload["taint_ids"] or _is_network_payload_event(payload):
            payload = _redact_tainted_payload(payload)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RuntimeEvent":
        data = dict(payload or {})
        known = set(cls.__dataclass_fields__)
        metadata = dict(data.get("metadata", {}) or {})
        for key in list(data):
            if key not in known:
                metadata[key] = data.pop(key)
        data["metadata"] = metadata
        data.setdefault("evidence_strength", "unknown")
        data.setdefault("observation_source", _observation_source_from_raw(data.get("raw_source")))
        data.setdefault("carrier_type", "unknown")
        data.setdefault("carrier_location", None)
        data.setdefault("derived_from_hash", bool(metadata.get("derived_from_hash")))
        data.setdefault("instrumentation_visibility", metadata.get("instrumentation_visibility", "observed"))
        data.setdefault("raw_event_id", data.get("raw_reference") or metadata.get("raw_event_id"))
        data.setdefault("trace_file", metadata.get("trace_file"))
        data.setdefault("trace_line", metadata.get("trace_line"))
        return cls(**data)


@dataclass
class TaintSource:
    taint_id: str
    source_type: str
    source_location: str
    marker: str
    created_at: float
    allowed_sinks: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    variants: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeNode:
    node_id: str
    node_type: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["metadata"] = _redact_sensitive_metadata(payload.get("metadata", {}))
        return payload


@dataclass
class RuntimeEdge:
    edge_id: str
    source_node: str
    target_node: str
    edge_type: str
    event_ids: list[str]
    taint_ids: list[str] = field(default_factory=list)
    evidence_level: str = "unknown"
    confidence: float = 0.0
    reason: str = ""
    evidence_strength: str = "unknown"
    carrier_type: str = "unknown"
    carrier_location: str | None = None
    raw_references: list[str] = field(default_factory=list)
    transformation: str | None = None
    timestamp_start: float | None = None
    timestamp_end: float | None = None
    instrumentation_gaps: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["event_ids"] = sorted({item for item in self.event_ids if item})
        payload["taint_ids"] = sorted({item for item in self.taint_ids if item})
        payload["raw_references"] = sorted({item for item in self.raw_references if item})
        payload["instrumentation_gaps"] = sorted({item for item in self.instrumentation_gaps if item})
        payload["metadata"] = _redact_sensitive_metadata(payload.get("metadata", {}))
        return payload


@dataclass
class RuntimeProvenanceGraph:
    session_id: str
    nodes: list[RuntimeNode] = field(default_factory=list)
    edges: list[RuntimeEdge] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def summary(self) -> dict[str, Any]:
        node_types: dict[str, int] = {}
        edge_types: dict[str, int] = {}
        evidence_levels: dict[str, int] = {}
        tainted_edge_count = 0
        for node in self.nodes:
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1
        for edge in self.edges:
            edge_types[edge.edge_type] = edge_types.get(edge.edge_type, 0) + 1
            evidence_levels[edge.evidence_level] = evidence_levels.get(edge.evidence_level, 0) + 1
            if edge.taint_ids:
                tainted_edge_count += 1
        return {
            "summary_scope": "runtime_provenance_graph",
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "tainted_edge_count": tainted_edge_count,
            "node_types": node_types,
            "edge_types": edge_types,
            "evidence_levels": evidence_levels,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "summary": self.summary(),
        }


@dataclass
class RuntimeChain:
    chain_id: str
    chain_type: str
    source: str | None
    sink: str | None
    taint_ids: list[str]
    ordered_nodes: list[str]
    ordered_edges: list[str]
    supporting_event_ids: list[str]
    evidence_level: str
    missing_observation_points: list[str] = field(default_factory=list)
    coverage_status: str = "triggered_and_observed"
    explanation: str = ""
    evidence_strengths: list[str] = field(default_factory=list)
    raw_references: list[str] = field(default_factory=list)
    transformations: list[str] = field(default_factory=list)
    instrumentation_gaps: list[str] = field(default_factory=list)
    confidence: float = 0.0
    minimality_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CoverageReport:
    coverage_state: str
    reasons: list[str] = field(default_factory=list)
    observed_event_count: int = 0
    expected_observations: list[str] = field(default_factory=list)
    missing_observations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeObligation:
    obligation_id: str
    description: str
    skill_activated: bool = False
    target_instruction_loaded: bool = False
    target_action_reached: bool = False
    source_available: bool | None = None
    source_read: bool = False
    intermediate_artifact_created: bool = False
    sink_available: bool | None = None
    request_attempted: bool = False
    instrumentation_complete: bool = True
    network_visibility: str = "unknown"
    external_state_available: bool | None = None
    required_tool_available: bool | None = None
    user_confirmation_available: bool | None = None
    termination_reason: str | None = None
    evidence_event_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyViolation:
    policy_type: str
    violation_id: str
    evidence_level: str
    chain_id: str | None
    taint_ids: list[str]
    reason: str
    event_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def merge_evidence_level(levels: list[str]) -> str:
    if not levels:
        return "unknown"
    return max((level if level in EVIDENCE_ORDER else "unknown" for level in levels), key=lambda item: EVIDENCE_ORDER[item])


def confidence_for_evidence(level: str) -> float:
    return {"confirmed": 1.0, "conservative": 0.72, "candidate": 0.38}.get(level, 0.0)


def _observation_source_from_raw(raw_source: Any) -> str:
    raw = str(raw_source or "")
    if raw.startswith("strace"):
        return "strace_syscall"
    if raw in {"taint", "dynamic_analyzer"}:
        return "inferred_relation"
    if raw.startswith("closure_lift"):
        return "instruction_simulation"
    if raw:
        return "runtime_wrapper"
    return "runtime_wrapper"


def _redact_tainted_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(payload)
    if isinstance(redacted.get("data_preview"), str) and redacted["data_preview"]:
        redacted["data_preview"] = _redacted_text(redacted["data_preview"])
    redacted["metadata"] = _redact_sensitive_metadata(redacted.get("metadata", {}))
    return redacted


def _is_network_payload_event(payload: dict[str, Any]) -> bool:
    metadata = payload.get("metadata", {}) or {}
    return (
        payload.get("object_type") == "network"
        and payload.get("operation") in {"send", "sendto", "upload", "write"}
        and (metadata.get("payload_preview") or metadata.get("raw"))
    )


def _redact_sensitive_metadata(value: Any) -> Any:
    sensitive_keys = {"raw", "payload_preview", "stdout_preview", "content_preview", "body", "authorization", "cookie"}
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, sub_value in value.items():
            lowered = str(key).lower()
            if lowered in {"plaintext_stored", "stdout_plaintext_stored"}:
                result[key] = False
            elif lowered in sensitive_keys and isinstance(sub_value, str) and sub_value:
                result[key] = _redacted_text(sub_value)
                if lowered == "stdout_preview":
                    result["stdout_plaintext_stored"] = False
                else:
                    result["plaintext_stored"] = False
            else:
                result[key] = _redact_sensitive_metadata(sub_value)
        return result
    if isinstance(value, list):
        return [_redact_sensitive_metadata(item) for item in value]
    return value


def _redacted_text(value: str) -> dict[str, Any]:
    return {
        "redacted": "[TAINTED_VALUE]",
        "byte_count": len(value.encode("utf-8")),
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "plaintext_stored": False,
    }
