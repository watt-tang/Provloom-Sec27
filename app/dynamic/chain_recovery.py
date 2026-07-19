from __future__ import annotations

import hashlib
from collections import deque
from typing import Any

from app.dynamic.models import RuntimeChain, RuntimeEdge, RuntimeProvenanceGraph, RuntimeNode, merge_evidence_level


CONFIDENTIALITY_TERMINALS = {"SEND", "UPLOAD_FILE"}
EXECUTION_TERMINALS = {"EXEC"}
PERSISTENCE_TERMINALS = {"PERSIST", "MATERIALIZE_INSTRUCTION"}


class ChainRecovery:
    def recover(self, graph: RuntimeProvenanceGraph) -> list[RuntimeChain]:
        node_by_id = {node.node_id: node for node in graph.nodes}
        edges = graph.edges
        chains: list[RuntimeChain] = []
        chains.extend(self._recover_by_terminal(graph, node_by_id, edges, "confidentiality", CONFIDENTIALITY_TERMINALS, {"NetworkEndpoint"}))
        chains.extend(self._recover_by_terminal(graph, node_by_id, edges, "confidentiality_candidate", {"CONNECT"}, {"NetworkEndpoint"}))
        chains.extend(self._recover_execution(graph, node_by_id, edges))
        chains.extend(self._recover_by_terminal(graph, node_by_id, edges, "persistence", PERSISTENCE_TERMINALS, {"PersistenceTarget", "RuntimeInstruction"}))
        return sorted(chains, key=lambda item: (item.evidence_level, item.chain_type, item.chain_id))

    def _recover_by_terminal(
        self,
        graph: RuntimeProvenanceGraph,
        node_by_id: dict[str, RuntimeNode],
        edges: list[RuntimeEdge],
        chain_type: str,
        terminal_edges: set[str],
        terminal_node_types: set[str],
    ) -> list[RuntimeChain]:
        chains: list[RuntimeChain] = []
        adjacency = _adjacency(edges)
        sources = [node for node in graph.nodes if node.node_type == "SensitiveSource"]
        terminals = [
            edge
            for edge in edges
            if edge.edge_type in terminal_edges and node_by_id.get(edge.target_node, RuntimeNode("", "", "")).node_type in terminal_node_types
        ]
        for source in sources:
            for terminal in terminals:
                common_taints = set(source.metadata.get("taint_id", "").split(",")) & set(terminal.taint_ids)
                if not common_taints and terminal.taint_ids:
                    common_taints = set(terminal.taint_ids)
                if terminal.taint_ids and not common_taints:
                    continue
                path_edges = _bfs_edges(source.node_id, terminal.target_node, adjacency, terminal_taint_ids=set(terminal.taint_ids))
                if not path_edges:
                    continue
                chain = _chain_from_edges(chain_type, source.node_id, terminal.target_node, path_edges, node_by_id)
                if chain:
                    chains.append(chain)
        return _dedupe_chains(chains)

    def _recover_execution(
        self,
        graph: RuntimeProvenanceGraph,
        node_by_id: dict[str, RuntimeNode],
        edges: list[RuntimeEdge],
    ) -> list[RuntimeChain]:
        chains: list[RuntimeChain] = []
        download_edges = [edge for edge in edges if edge.edge_type in {"WRITE", "DERIVE", "EXTRACT"} and edge.metadata.get("remote_artifact")]
        exec_edges = [edge for edge in edges if edge.edge_type == "EXEC"]
        adjacency = _adjacency(edges)
        for download in download_edges:
            for execution in exec_edges:
                path_edges = _bfs_edges(download.target_node, execution.target_node, adjacency, terminal_taint_ids=set(execution.taint_ids))
                if path_edges:
                    chain = _chain_from_edges("execution", download.source_node, execution.target_node, path_edges, node_by_id)
                    if chain:
                        chains.append(chain)
        return _dedupe_chains(chains)


def _adjacency(edges: list[RuntimeEdge]) -> dict[str, list[RuntimeEdge]]:
    result: dict[str, list[RuntimeEdge]] = {}
    for edge in edges:
        result.setdefault(edge.source_node, []).append(edge)
    return result


def _bfs_edges(start: str, goal: str, adjacency: dict[str, list[RuntimeEdge]], *, terminal_taint_ids: set[str]) -> list[RuntimeEdge]:
    queue = deque([(start, [])])
    candidates: list[list[RuntimeEdge]] = []
    visited: set[tuple[str, int]] = {(start, 0)}
    while queue:
        node_id, path = queue.popleft()
        if node_id == goal:
            candidates.append(path)
            continue
        if len(path) >= 8:
            continue
        for edge in adjacency.get(node_id, []):
            visit_key = (edge.target_node, len(path) + 1)
            if visit_key in visited:
                continue
            if terminal_taint_ids and edge.taint_ids and not (set(edge.taint_ids) & terminal_taint_ids):
                continue
            visited.add(visit_key)
            queue.append((edge.target_node, path + [edge]))
    if not candidates:
        return []
    return sorted(candidates, key=_path_rank)[0]


def _path_rank(path: list[RuntimeEdge]) -> tuple[int, int, int]:
    edge_types = {edge.edge_type for edge in path}
    has_read = 0 if "READ" in edge_types else 1
    has_relay = 0 if edge_types & {"WRITE", "PIPE", "PASS_AS_ARGUMENT", "PASS_AS_ENV", "UPLOAD_FILE"} else 1
    return (has_read, has_relay, len(path))


def _chain_from_edges(
    chain_type: str,
    source: str,
    sink: str,
    path_edges: list[RuntimeEdge],
    node_by_id: dict[str, RuntimeNode],
) -> RuntimeChain | None:
    if not path_edges:
        return None
    ordered_nodes = [path_edges[0].source_node] + [edge.target_node for edge in path_edges]
    ordered_edges = [edge.edge_id for edge in path_edges]
    event_ids = _dedupe([event_id for edge in path_edges for event_id in edge.event_ids])
    taint_ids = _dedupe([taint_id for edge in path_edges for taint_id in edge.taint_ids])
    evidence_level = merge_evidence_level([edge.evidence_level for edge in path_edges])
    missing = []
    if any(edge.edge_type == "CONNECT" and edge.edge_type not in CONFIDENTIALITY_TERMINALS for edge in path_edges):
        missing.append("payload_or_upload_observation")
    explanation = _explain(chain_type, ordered_nodes, path_edges, node_by_id, evidence_level)
    return RuntimeChain(
        chain_id=f"RC{hashlib.sha256('|'.join(ordered_edges).encode('utf-8')).hexdigest()[:12]}",
        chain_type=chain_type,
        source=source,
        sink=sink,
        taint_ids=taint_ids,
        ordered_nodes=ordered_nodes,
        ordered_edges=ordered_edges,
        supporting_event_ids=event_ids,
        evidence_level=evidence_level,
        missing_observation_points=missing,
        coverage_status="triggered_and_observed" if not missing else "triggered_but_partially_observed",
        explanation=explanation,
    )


def _explain(
    chain_type: str,
    ordered_nodes: list[str],
    path_edges: list[RuntimeEdge],
    node_by_id: dict[str, RuntimeNode],
    evidence_level: str,
) -> str:
    labels = [node_by_id.get(node_id, RuntimeNode(node_id, "Unknown", node_id)).label for node_id in ordered_nodes]
    edge_labels = " -> ".join(edge.edge_type for edge in path_edges)
    return f"{evidence_level} {chain_type} chain: {' -> '.join(labels)} via {edge_labels}."


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _dedupe_chains(chains: list[RuntimeChain]) -> list[RuntimeChain]:
    seen: set[str] = set()
    result: list[RuntimeChain] = []
    for chain in chains:
        key = "|".join(chain.ordered_edges)
        if key in seen:
            continue
        seen.add(key)
        result.append(chain)
    return result
