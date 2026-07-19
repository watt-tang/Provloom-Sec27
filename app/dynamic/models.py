from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SCHEMA_VERSION = "runtime-analysis-v2"
EVIDENCE_ORDER = {"confirmed": 0, "conservative": 1, "candidate": 2, "unknown": 3}
EVIDENCE_LEVELS = {"confirmed", "conservative", "candidate", "unknown"}


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
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["taint_ids"] = sorted({str(item) for item in self.taint_ids if str(item)})
        return payload


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
        return asdict(self)


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
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["event_ids"] = sorted({item for item in self.event_ids if item})
        payload["taint_ids"] = sorted({item for item in self.taint_ids if item})
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
