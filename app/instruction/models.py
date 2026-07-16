from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SCHEMA_VERSION = "instruction-analysis-v1"


@dataclass
class Document:
    document_id: str
    relative_path: str
    file_type: str
    content_hash: str
    size: int
    encoding: str
    parse_status: str
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DocumentSpan:
    span_id: str
    document_id: str
    section_path: list[str]
    start_offset: int
    end_offset: int
    line_start: int
    line_end: int
    content_type: str
    raw_text: str
    normalized_text: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Action:
    action_id: str
    actor: str | None
    operation: str
    object_entity_id: str | None = None
    source_entity_id: str | None = None
    destination_entity_id: str | None = None
    instrument_entity_id: str | None = None
    condition: str | None = None
    modality: str = "uncertain"
    context: str = "unknown"
    privilege: str = "unknown"
    temporal_relation: str | None = None
    evidence_span_ids: list[str] = field(default_factory=list)
    extraction_method: str = "deterministic"
    confidence: float = 0.5
    alignment_keys: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Entity:
    entity_id: str
    entity_type: str
    canonical_name: str
    aliases: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence_span_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EntityLink:
    source_entity_id: str
    target_entity_id: str
    relation: str
    evidence: list[str] = field(default_factory=list)
    method: str = "deterministic"
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InstructionNode:
    node_id: str
    node_type: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InstructionEdge:
    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str
    supporting_span_ids: list[str] = field(default_factory=list)
    extraction_method: str = "deterministic"
    confidence: float = 0.5
    validation_status: str = "candidate"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TypedInstructionGraph:
    nodes: list[InstructionNode] = field(default_factory=list)
    edges: list[InstructionEdge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, Any]:
        node_types: dict[str, int] = {}
        edge_types: dict[str, int] = {}
        validation: dict[str, int] = {}
        for node in self.nodes:
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1
        for edge in self.edges:
            edge_types[edge.edge_type] = edge_types.get(edge.edge_type, 0) + 1
            validation[edge.validation_status] = validation.get(edge.validation_status, 0) + 1
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "node_types": node_types,
            "edge_types": edge_types,
            "edge_validation": validation,
        }


@dataclass
class ValidatedInstructionPath:
    path_id: str
    path_type: str
    node_ids: list[str]
    edge_ids: list[str]
    trust_boundary_node: str | None
    control_transfer_node: str | None
    impact_sink_node: str | None
    evidence_span_ids: list[str]
    confidence: float
    completeness: str
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InstructionAnalysisResult:
    documents: list[Document]
    spans: list[DocumentSpan]
    actions: list[Action]
    entities: list[Entity]
    entity_links: list[EntityLink]
    graph: TypedInstructionGraph
    validated_paths: list[ValidatedInstructionPath]
    partial_paths: list[ValidatedInstructionPath]
    indicators: list[dict[str, Any]]
    summary: dict[str, Any]
    extraction_coverage: dict[str, Any]
    abstention_reasons: list[str]
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "documents": [item.to_dict() for item in self.documents],
            "spans": [item.to_dict() for item in self.spans],
            "actions": [item.to_dict() for item in self.actions],
            "entities": [item.to_dict() for item in self.entities],
            "entity_links": [item.to_dict() for item in self.entity_links],
            "graph": self.graph.to_dict(),
            "validated_paths": [item.to_dict() for item in self.validated_paths],
            "partial_paths": [item.to_dict() for item in self.partial_paths],
            "indicators": list(self.indicators),
            "summary": dict(self.summary),
            "extraction_coverage": dict(self.extraction_coverage),
            "abstention_reasons": list(self.abstention_reasons),
        }
