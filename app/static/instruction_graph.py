from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from app.static.action_schema import StaticAction
from app.static.artifact_schema import LoadedArtifact, SemanticUnit
from app.static.entity_schema import EntityResolution, Mention, StaticEntity


EDGE_FOR_ACTION = {
    "READ": "READS", "ACCESS_CREDENTIAL": "ACCESSES", "WRITE": "WRITES", "COPY": "WRITES", "MOVE": "WRITES",
    "DELETE": "WRITES", "MODIFY": "WRITES", "DOWNLOAD": "DOWNLOADS", "UPLOAD": "UPLOADS", "SEND": "SENDS_TO",
    "EXECUTE": "EXECUTES", "INSTALL": "INSTALLS", "IMPORT": "IMPORTS", "EXTRACT": "EXTRACTS", "PERSIST": "PERSISTS_AS",
    "REGISTER_SERVICE": "PERSISTS_AS", "REQUEST_PERMISSION": "REQUIRES", "CHANGE_PERMISSION": "REQUIRES",
    "INVOKE_TOOL": "INVOKES", "INVOKE_API": "INVOKES", "DECODE": "DERIVES_FROM", "TRANSFORM": "DERIVES_FROM",
}


@dataclass
class StaticGraphNode:
    node_id: str
    node_type: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StaticGraphEdge:
    edge_id: str
    source_node: str
    target_node: str
    edge_type: str
    evidence_unit_ids: list[str]
    action_ids: list[str] = field(default_factory=list)
    resolution_ids: list[str] = field(default_factory=list)
    evidence_level: str = "explicit"
    confidence: float = 1.0
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InstructionProvenanceGraph:
    nodes: list[StaticGraphNode]
    edges: list[StaticGraphEdge]

    def summary(self) -> dict[str, Any]:
        node_types: dict[str, int] = {}
        edge_types: dict[str, int] = {}
        levels: dict[str, int] = {}
        for node in self.nodes:
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1
        for edge in self.edges:
            edge_types[edge.edge_type] = edge_types.get(edge.edge_type, 0) + 1
            levels[edge.evidence_level] = levels.get(edge.evidence_level, 0) + 1
        return {"node_count": len(self.nodes), "edge_count": len(self.edges), "node_types": node_types, "edge_types": edge_types, "evidence_levels": levels}

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": [n.to_dict() for n in self.nodes], "edges": [e.to_dict() for e in self.edges], "summary": self.summary()}


class InstructionGraphBuilderV2:
    def build(
        self,
        *,
        artifacts: list[LoadedArtifact],
        units: list[SemanticUnit],
        mentions: list[Mention],
        actions: list[StaticAction],
        entities: list[StaticEntity],
        resolutions: list[EntityResolution],
    ) -> InstructionProvenanceGraph:
        nodes: dict[str, StaticGraphNode] = {}
        edges: dict[str, StaticGraphEdge] = {}
        mention_to_entity = {mention_id: entity.entity_id for entity in entities for mention_id in entity.mentions}
        for loaded in artifacts:
            art = loaded.artifact
            nodes[art.artifact_id] = StaticGraphNode(art.artifact_id, "DocumentArtifact", art.relative_path, art.to_dict())
        for unit in units:
            nodes[unit.unit_id] = StaticGraphNode(unit.unit_id, "EvidenceSpan", f"{unit.metadata.get('relative_path')}:{unit.start_line}", unit.to_dict())
        for entity in entities:
            nodes[entity.entity_id] = StaticGraphNode(entity.entity_id, "Entity", entity.canonical_value, entity.to_dict())
        for action in actions:
            if action.grounding_status == "unsupported":
                continue
            nodes[action.action_id] = StaticGraphNode(action.action_id, "InstructionAction", action.action_type, action.to_dict())
            unit_id = action.evidence.unit_id if action.evidence else ""
            self._edge(edges, unit_id, action.action_id, "SUPPORTED_BY", [unit_id], [action.action_id], [], "explicit", action.confidence, "Action is grounded in this evidence unit.")
            relation = EDGE_FOR_ACTION.get(action.action_type, "ACTS_ON")
            for mention_id in action.object_mentions:
                ent = mention_to_entity.get(mention_id)
                if ent:
                    self._edge(edges, action.action_id, ent, relation, [unit_id], [action.action_id], [], "explicit" if action.grounding_status == "valid" else "uncertain", action.confidence, f"{action.action_type} acts on mentioned entity.")
            for mention_id in action.source_mentions:
                ent = mention_to_entity.get(mention_id)
                if ent:
                    self._edge(edges, ent, action.action_id, "CONSUMES", [unit_id], [action.action_id], [], "explicit", action.confidence, "Action consumes source entity.")
            for mention_id in action.destination_mentions:
                ent = mention_to_entity.get(mention_id)
                if ent:
                    dtype = "SENDS_TO" if action.action_type in {"SEND", "UPLOAD", "INVOKE_API"} else "PRODUCES"
                    self._edge(edges, action.action_id, ent, dtype, [unit_id], [action.action_id], [], "explicit", action.confidence, "Action references destination entity.")
            if action.condition:
                cid = f"COND:{action.action_id}"
                nodes[cid] = StaticGraphNode(cid, "Condition", action.condition, {"action_id": action.action_id})
                self._edge(edges, action.action_id, cid, "CONDITIONAL_ON", [unit_id], [action.action_id], [], "explicit", action.confidence, "Action condition is explicitly stated.")
        for resolution in resolutions:
            if resolution.status == "rejected":
                continue
            self._edge(
                edges,
                resolution.entity_a,
                resolution.entity_b,
                "SAME_ENTITY_AS" if resolution.relation == "same_entity" else "REFERS_TO" if resolution.relation == "refers_to" else "DERIVES_FROM",
                resolution.evidence_unit_ids,
                [],
                [resolution.resolution_id],
                "resolved" if resolution.status == "confirmed" else "uncertain" if resolution.status == "uncertain" else "inferred",
                resolution.confidence,
                f"Entity resolution {resolution.relation} via {resolution.method}.",
            )
        return InstructionProvenanceGraph(list(nodes.values()), list(edges.values()))

    def _edge(self, edges: dict[str, StaticGraphEdge], source: str, target: str, edge_type: str, units: list[str], actions: list[str], resolutions: list[str], level: str, confidence: float, reason: str) -> None:
        if not source or not target or source == target:
            return
        edge_id = _edge_id(source, target, edge_type, actions, resolutions)
        if edge_id in edges:
            return
        edges[edge_id] = StaticGraphEdge(edge_id, source, target, edge_type, [u for u in units if u], actions, resolutions, level, confidence, reason)


def _edge_id(*parts) -> str:
    digest = hashlib.sha256(repr(parts).encode("utf-8")).hexdigest()[:12]
    return f"SE{digest}"
