from __future__ import annotations

from app.instruction.models import InstructionEdge, InstructionNode, TypedInstructionGraph


class InstructionGraphIndex:
    def __init__(self, graph: TypedInstructionGraph) -> None:
        self.graph = graph
        self.nodes = {node.node_id: node for node in graph.nodes}
        self.edges = {edge.edge_id: edge for edge in graph.edges}
        self.outgoing: dict[str, list[InstructionEdge]] = {}
        self.incoming: dict[str, list[InstructionEdge]] = {}
        for edge in graph.edges:
            self.outgoing.setdefault(edge.source_node_id, []).append(edge)
            self.incoming.setdefault(edge.target_node_id, []).append(edge)

    def neighbors(self, node_id: str, edge_types: set[str] | None = None) -> list[tuple[InstructionEdge, InstructionNode]]:
        results: list[tuple[InstructionEdge, InstructionNode]] = []
        for edge in self.outgoing.get(node_id, []):
            if edge_types is not None and edge.edge_type not in edge_types:
                continue
            node = self.nodes.get(edge.target_node_id)
            if node is not None:
                results.append((edge, node))
        return results

    def has_cycle(self) -> bool:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> bool:
            if node_id in visiting:
                return True
            if node_id in visited:
                return False
            visiting.add(node_id)
            for edge in self.outgoing.get(node_id, []):
                if visit(edge.target_node_id):
                    return True
            visiting.remove(node_id)
            visited.add(node_id)
            return False

        return any(visit(node.node_id) for node in self.graph.nodes)
