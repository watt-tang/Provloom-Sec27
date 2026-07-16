from __future__ import annotations

from app.instruction.models import Action, Entity, EntityLink, InstructionEdge, InstructionNode, TypedInstructionGraph
from app.instruction.serialization import stable_id


EDGE_FOR_OPERATION = {
    "download": "acquires",
    "fetch": "acquires",
    "clone": "acquires",
    "install": "installs",
    "extract": "extracts",
    "execute": "executes",
    "invoke": "invokes",
    "read": "reads",
    "write": "writes",
    "copy": "writes",
    "move": "writes",
    "send": "sends_to",
    "upload": "sends_to",
    "connect": "connects_account",
    "authenticate": "connects_account",
    "grant_permission": "grants_access",
    "modify_environment": "modifies",
    "modify_configuration": "modifies",
    "register_service": "persists_as",
    "register_cron": "schedules",
    "persist": "persists_as",
    "update": "modifies",
    "replace": "modifies",
    "connect_account": "connects_account",
    "access_credential": "reads",
}


class InstructionGraphBuilder:
    def build(self, actions: list[Action], entities: list[Entity], links: list[EntityLink]) -> TypedInstructionGraph:
        nodes: dict[str, InstructionNode] = {}
        edges: list[InstructionEdge] = []

        for entity in entities:
            nodes[entity.entity_id] = InstructionNode(
                node_id=entity.entity_id,
                node_type="Entity",
                label=entity.canonical_name,
                metadata=entity.to_dict(),
            )

        for action in actions:
            nodes[action.action_id] = InstructionNode(
                node_id=action.action_id,
                node_type="Action",
                label=action.operation,
                metadata=action.to_dict(),
            )
            for entity_id, edge_type in self._action_edges(action):
                if entity_id and entity_id in nodes:
                    edges.append(
                        InstructionEdge(
                            edge_id=stable_id("iedge", action.action_id, entity_id, edge_type),
                            source_node_id=action.action_id,
                            target_node_id=entity_id,
                            edge_type=edge_type,
                            supporting_span_ids=list(action.evidence_span_ids),
                            extraction_method=action.extraction_method,
                            confidence=action.confidence,
                            validation_status="validated" if action.modality not in {"prohibited", "example_only", "descriptive"} else "rejected",
                            metadata={"operation": action.operation, "modality": action.modality, "context": action.context},
                        )
                    )
            for span_id in action.evidence_span_ids:
                span_node = f"span:{span_id}"
                nodes.setdefault(span_node, InstructionNode(node_id=span_node, node_type="DocumentSpan", label=span_id, metadata={"span_id": span_id}))
                edges.append(
                    InstructionEdge(
                        edge_id=stable_id("iedge", span_node, action.action_id, "instructs"),
                        source_node_id=span_node,
                        target_node_id=action.action_id,
                        edge_type="instructs",
                        supporting_span_ids=[span_id],
                        extraction_method=action.extraction_method,
                        confidence=action.confidence,
                        validation_status="validated",
                    )
                )

        for index, current in enumerate(actions[:-1]):
            nxt = actions[index + 1]
            same_flow = bool(set(current.evidence_span_ids) & set(nxt.evidence_span_ids)) or current.context == nxt.context
            edges.append(
                InstructionEdge(
                    edge_id=stable_id("iedge", current.action_id, nxt.action_id, "follows"),
                    source_node_id=current.action_id,
                    target_node_id=nxt.action_id,
                    edge_type="follows",
                    supporting_span_ids=list(set(current.evidence_span_ids + nxt.evidence_span_ids)),
                    extraction_method="document_order",
                    confidence=0.7 if same_flow else 0.45,
                    validation_status="validated" if same_flow else "candidate",
                )
            )

        for link in links:
            edges.append(
                InstructionEdge(
                    edge_id=stable_id("iedge", link.source_entity_id, link.target_entity_id, link.relation),
                    source_node_id=link.source_entity_id,
                    target_node_id=link.target_entity_id,
                    edge_type="aliases" if link.relation == "alias" else "candidate_relation",
                    supporting_span_ids=list(link.evidence),
                    extraction_method=link.method,
                    confidence=link.confidence,
                    validation_status="validated" if link.confidence >= 0.75 else "candidate",
                    metadata={"relation": link.relation},
                )
            )

        return TypedInstructionGraph(nodes=list(nodes.values()), edges=edges)

    @staticmethod
    def _action_edges(action: Action) -> list[tuple[str | None, str]]:
        edge = EDGE_FOR_OPERATION.get(action.operation, "acts_on")
        results = [(action.object_entity_id, edge)]
        if action.source_entity_id:
            results.append((action.source_entity_id, "depends_on" if edge != "acquires" else "acquires"))
        if action.destination_entity_id:
            results.append((action.destination_entity_id, "sends_to" if action.operation in {"send", "upload"} else "produces"))
        if action.instrument_entity_id:
            results.append((action.instrument_entity_id, "invokes"))
        return results
