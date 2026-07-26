from __future__ import annotations

import hashlib
from collections import deque
from typing import Any

from app.dynamic.models import RuntimeChain, RuntimeEdge, RuntimeProvenanceGraph, RuntimeNode, merge_evidence_level


CONFIDENTIALITY_TERMINALS = {"SENDS", "UPLOADS"}
LEGACY_CONFIDENTIALITY_TERMINALS = {"SEND", "UPLOAD_FILE"}
EXECUTION_TERMINALS = {"EXEC"}
PERSISTENCE_TERMINALS = {"PERSIST", "MATERIALIZE_INSTRUCTION"}
WEAK_EDGE_TYPES = {"CONNECT", "CO_OCCURS", "HAS_PROCESS_CONTEXT"}
DISALLOWED_CONFIRMED_STRENGTHS = {"hash_derived", "process_context", "temporal_cooccurrence", "candidate", "unknown"}


class ChainRecovery:
    def recover(self, graph: RuntimeProvenanceGraph) -> list[RuntimeChain]:
        node_by_id = {node.node_id: node for node in graph.nodes}
        edges = graph.edges
        chains: list[RuntimeChain] = []
        chains.extend(self._recover_by_terminal(graph, node_by_id, edges, "confidentiality_confirmed", CONFIDENTIALITY_TERMINALS, {"NetworkEndpoint"}))
        chains.extend(self._recover_by_terminal(graph, node_by_id, edges, "confidentiality_candidate", {"CONNECT", "CO_OCCURS", "HAS_PROCESS_CONTEXT"} | LEGACY_CONFIDENTIALITY_TERMINALS, {"NetworkEndpoint", "Process"}))
        chains.extend(self._recover_execution(graph, node_by_id, edges))
        chains.extend(self._recover_by_terminal(graph, node_by_id, edges, "persistence_confirmed", PERSISTENCE_TERMINALS, {"PersistenceTarget"}))
        chains.extend(self._recover_by_terminal(graph, node_by_id, edges, "instruction_simulated", {"MATERIALIZE_INSTRUCTION"}, {"RuntimeInstruction"}))
        return sorted(chains, key=lambda item: (_chain_rank(item), item.chain_type, item.chain_id))

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
                if chain_type == "confidentiality_confirmed" and not _is_confirmable_confidentiality(path_edges):
                    continue
                if chain_type == "confidentiality_candidate" and _is_confirmable_confidentiality(path_edges):
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
                    chain = _chain_from_edges("execution_confirmed", download.source_node, execution.target_node, path_edges, node_by_id)
                    if chain:
                        chains.append(chain)
        return _dedupe_chains(chains)


def _adjacency(edges: list[RuntimeEdge]) -> dict[str, list[RuntimeEdge]]:
    result: dict[str, list[RuntimeEdge]] = {}
    for edge in edges:
        result.setdefault(edge.source_node, []).append(edge)
    return result


def _bfs_edges(start: str, goal: str, adjacency: dict[str, list[RuntimeEdge]], *, terminal_taint_ids: set[str]) -> list[RuntimeEdge]:
    queue = deque([(start, [], None)])
    candidates: list[list[RuntimeEdge]] = []
    visited: set[tuple[str, int, float | None]] = {(start, 0, None)}
    while queue:
        node_id, path, last_ts = queue.popleft()
        if node_id == goal:
            candidates.append(path)
            continue
        if len(path) >= 8:
            continue
        for edge in adjacency.get(node_id, []):
            edge_ts = edge.timestamp_start
            if last_ts is not None and edge_ts is not None and edge_ts < last_ts:
                continue
            visit_key = (edge.target_node, len(path) + 1, edge_ts)
            if visit_key in visited:
                continue
            if terminal_taint_ids and edge.taint_ids and not (set(edge.taint_ids) & terminal_taint_ids):
                continue
            visited.add(visit_key)
            queue.append((edge.target_node, path + [edge], edge_ts if edge_ts is not None else last_ts))
    if not candidates:
        return []
    return sorted(candidates, key=_path_rank)[0]


def _path_rank(path: list[RuntimeEdge]) -> tuple[int, int, int]:
    edge_types = {edge.edge_type for edge in path}
    has_data = 0 if edge_types & {"SENDS", "UPLOADS", "READS", "PROPAGATES", "DERIVES"} else 1
    weak_edges = sum(1 for edge in path if edge.edge_type in WEAK_EDGE_TYPES)
    strength_penalty = sum(1 for edge in path if edge.evidence_strength in DISALLOWED_CONFIRMED_STRENGTHS)
    return (weak_edges, strength_penalty, has_data, len(path))


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
    if any(edge.edge_type in {"CONNECT", "CO_OCCURS"} for edge in path_edges):
        missing.append("payload_or_upload_observation")
    if any(edge.edge_type == "HAS_PROCESS_CONTEXT" for edge in path_edges):
        missing.append("concrete_data_continuity")
    if any(edge.evidence_strength == "hash_derived" or edge.metadata.get("derived_from_hash") for edge in path_edges):
        missing.append("original_secret_payload")
    instrumentation_gaps = _dedupe([gap for edge in path_edges for gap in edge.instrumentation_gaps])
    missing.extend(gap for gap in instrumentation_gaps if gap not in missing)
    explanation = _explain(chain_type, ordered_nodes, path_edges, node_by_id, evidence_level)
    strengths = _dedupe([edge.evidence_strength for edge in path_edges if edge.evidence_strength])
    raw_refs = _dedupe([ref for edge in path_edges for ref in edge.raw_references])
    transformations = _dedupe([edge.transformation or "" for edge in path_edges if edge.transformation])
    confidence = min([edge.confidence for edge in path_edges] or [0.0])
    coverage_status = "runtime_confirmed" if not missing and chain_type.endswith("_confirmed") else "insufficient_coverage"
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
        coverage_status=coverage_status,
        explanation=explanation,
        evidence_strengths=strengths,
        raw_references=raw_refs,
        transformations=transformations,
        instrumentation_gaps=instrumentation_gaps,
        confidence=confidence,
        minimality_score=1.0 / max(len(path_edges), 1),
        metadata={
            "legacy_chain_type": _legacy_chain_type(chain_type),
            "terminal_edge_type": path_edges[-1].edge_type,
            "carrier_types": _dedupe([edge.carrier_type for edge in path_edges if edge.carrier_type]),
            "minimal_witness": _minimal_witness(path_edges, node_by_id),
        },
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


def _is_confirmable_confidentiality(path_edges: list[RuntimeEdge]) -> bool:
    if not path_edges or path_edges[-1].edge_type not in CONFIDENTIALITY_TERMINALS:
        return False
    if any(edge.edge_type in WEAK_EDGE_TYPES for edge in path_edges):
        return False
    if any(edge.evidence_strength in DISALLOWED_CONFIRMED_STRENGTHS for edge in path_edges):
        return False
    if any(edge.metadata.get("derived_from_hash") for edge in path_edges):
        return False
    if any(edge.instrumentation_gaps for edge in path_edges):
        return False
    if any(event.get("observation_source") == "instruction_simulation" for edge in path_edges for event in edge.metadata.get("events", [])):
        return False
    return any(edge.edge_type in CONFIDENTIALITY_TERMINALS and edge.carrier_type in {"http_header", "http_query", "http_body", "http_form", "multipart_field", "socket_payload", "upload_file"} for edge in path_edges)


def _legacy_chain_type(chain_type: str) -> str:
    return {
        "confidentiality_confirmed": "confidentiality",
        "confidentiality_candidate": "confidentiality_candidate",
        "execution_confirmed": "execution",
        "persistence_confirmed": "persistence",
    }.get(chain_type, chain_type)


def _chain_rank(chain: RuntimeChain) -> tuple[int, int, int]:
    type_rank = {
        "confidentiality_confirmed": 0,
        "execution_confirmed": 1,
        "persistence_confirmed": 2,
        "confidentiality_candidate": 3,
        "instruction_simulated": 4,
        "insufficient_evidence": 5,
    }.get(chain.chain_type, 6)
    evidence_rank = {"confirmed": 0, "conservative": 1, "candidate": 2, "unknown": 3}.get(chain.evidence_level, 3)
    return (type_rank, evidence_rank, len(chain.ordered_edges))


def _minimal_witness(path_edges: list[RuntimeEdge], node_by_id: dict[str, RuntimeNode]) -> list[dict[str, Any]]:
    witness: list[dict[str, Any]] = []
    for edge in path_edges:
        witness.append(
            {
                "from": node_by_id.get(edge.source_node, RuntimeNode(edge.source_node, "Unknown", edge.source_node)).label,
                "edge": edge.edge_type,
                "to": node_by_id.get(edge.target_node, RuntimeNode(edge.target_node, "Unknown", edge.target_node)).label,
                "event_ids": list(edge.event_ids),
                "raw_references": list(edge.raw_references),
                "carrier_type": edge.carrier_type,
                "carrier_location": edge.carrier_location,
                "evidence_strength": edge.evidence_strength,
                "transformation": edge.transformation,
            }
        )
    return witness
