from __future__ import annotations

from collections import deque
from typing import Any

from app.graph.models import ExecutionProvenanceGraph, GraphNode

NOISY_FILE_PREFIXES = (
    "/usr/local/lib/python",
    "/usr/local/bin/../lib",
    "/usr/lib/locale",
    "/usr/share/locale",
    "/usr/lib/x86_64-linux-gnu/gconv",
    "/lib/x86_64-linux-gnu/",
    "/opt/skill_sandbox/",
    "/artifacts/",
    "/workspace/skill/",
)

NOISY_FILE_PATHS = {
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/usr/lib/ssl/cert.pem",
    "/usr/lib/ssl/openssl.cnf",
    "/usr/local/bin/pyvenv.cfg",
    "/usr/local/pyvenv.cfg",
    "/usr/local/bin/pybuilddir.txt",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/resolv.conf",
    "/etc/gai.conf",
    "/proc/self/fd",
}


def extract_primary_attack_chain(
    graph: ExecutionProvenanceGraph,
    detected_behaviors: list[str],
    *,
    filter_noise: bool = False,
) -> list[dict[str, Any]]:
    """Recover a best-effort source-to-sink chain from the EPG."""

    behaviors = set(detected_behaviors)
    if not (
        {"sensitive_file_read", "network_access"} <= behaviors
        or "read_then_exfiltration" in behaviors
        or {"file_write", "network_access"} <= behaviors
    ):
        return []

    node_lookup = {node.node_id: node for node in graph.nodes}
    adjacency = _build_adjacency(graph)
    file_nodes = _candidate_source_nodes(graph, adjacency, filter_noise=filter_noise)
    network_nodes = _candidate_sink_nodes(graph, adjacency)
    if not file_nodes or not network_nodes:
        return []

    best_path: list[tuple[str, str | None]] | None = None
    best_rank: tuple[int, int, int, int, str, str] | None = None
    goal_node_ids = {node.node_id for node in network_nodes}
    for source in file_nodes:
        path = _bfs_path(source.node_id, goal_node_ids, adjacency)
        if path is None:
            continue
        rank = _rank_path(path, node_lookup, adjacency, filter_noise=filter_noise)
        if best_rank is None or rank < best_rank:
            best_path = path
            best_rank = rank

    if best_path is None:
        source = file_nodes[0]
        return [
            {
                "node_id": source.node_id,
                "node_type": source.node_type,
                "label": source.label,
                "edge_type": None,
                "completeness": "partial",
                "role": "source",
            }
        ]

    if filter_noise:
        best_path = _compress_path(best_path, node_lookup)

    chain: list[dict[str, Any]] = []
    terminal_is_network = False
    for node_id, edge_type in best_path:
        node = node_lookup[node_id]
        chain.append(
            {
                "node_id": node.node_id,
                "node_type": node.node_type,
                "label": node.label,
                "edge_type": edge_type,
                "completeness": "complete",
                "role": _node_role(node_id, best_path, node),
            }
        )
        terminal_is_network = node.node_type == "network_endpoint"

    if not terminal_is_network:
        for item in chain:
            item["completeness"] = "partial"
    return chain


def _build_adjacency(graph: ExecutionProvenanceGraph) -> dict[str, list[tuple[str, str]]]:
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.source_node_id, []).append((edge.target_node_id, edge.edge_type))
        if edge.edge_type in {"causes", "flows_to"}:
            adjacency.setdefault(edge.target_node_id, []).append((edge.source_node_id, edge.edge_type))
    return adjacency


def _bfs_path(
    start_node_id: str,
    goal_node_ids: set[str],
    adjacency: dict[str, list[tuple[str, str]]],
) -> list[tuple[str, str | None]] | None:
    queue = deque([(start_node_id, [(start_node_id, None)])])
    visited = {start_node_id}
    while queue:
        node_id, path = queue.popleft()
        if node_id in goal_node_ids:
            return path
        for next_node_id, edge_type in adjacency.get(node_id, []):
            if next_node_id in visited:
                continue
            visited.add(next_node_id)
            queue.append((next_node_id, path + [(next_node_id, edge_type)]))
    return None


def _candidate_source_nodes(
    graph: ExecutionProvenanceGraph,
    adjacency: dict[str, list[tuple[str, str]]],
    *,
    filter_noise: bool,
) -> list[GraphNode]:
    ranked = sorted(
        (node for node in graph.nodes if node.node_type == "file"),
        key=lambda node: (
            _source_priority(node, adjacency),
            1 if filter_noise and _is_noisy_file(node.metadata.get("path", "")) else 0,
            node.label,
        ),
    )
    if filter_noise:
        non_noisy = [node for node in ranked if not _is_noisy_file(node.metadata.get("path", ""))]
        if non_noisy:
            ranked = non_noisy
    return ranked


def _candidate_sink_nodes(
    graph: ExecutionProvenanceGraph,
    adjacency: dict[str, list[tuple[str, str]]],
) -> list[GraphNode]:
    return sorted(
        (node for node in graph.nodes if node.node_type == "network_endpoint"),
        key=lambda node: (
            0 if str(node.label).startswith(("http://", "https://")) else 1,
            0 if _has_tool_predecessor(node.node_id, adjacency) else 1,
            node.label,
        ),
    )


def _source_priority(node: GraphNode, adjacency: dict[str, list[tuple[str, str]]]) -> int:
    path = node.metadata.get("path", "")
    tool_linked = _has_tool_neighbor(node.node_id, adjacency)
    sensitive = _is_sensitive_file(path)
    generated_local = _is_generated_local_file(path)
    public_local = str(path).startswith("public/")

    if tool_linked and sensitive:
        return 0
    if tool_linked and generated_local:
        return 1
    if tool_linked and public_local:
        return 2
    if sensitive:
        return 3
    if generated_local:
        return 4
    if public_local:
        return 5
    return 6


def _rank_path(
    path: list[tuple[str, str | None]],
    node_lookup: dict[str, GraphNode],
    adjacency: dict[str, list[tuple[str, str]]],
    *,
    filter_noise: bool,
) -> tuple[int, int, int, int, str, str]:
    nodes = [node_lookup[node_id] for node_id, _ in path]
    noisy_count = sum(
        1
        for node in nodes
        if node.node_type == "file" and _is_noisy_file(node.metadata.get("path", ""))
    )
    relay_count = sum(1 for node in nodes[1:-1] if node.node_type in {"file", "data", "process", "tool_call"})
    source = nodes[0]
    sink = nodes[-1]
    return (
        len(path),
        noisy_count if filter_noise else 0,
        _source_priority(source, adjacency),
        0 if str(sink.label).startswith(("http://", "https://")) else 1,
        source.label,
        sink.label,
    )


def _compress_path(
    path: list[tuple[str, str | None]],
    node_lookup: dict[str, GraphNode],
) -> list[tuple[str, str | None]]:
    compressed: list[tuple[str, str | None]] = []
    for index, (node_id, edge_type) in enumerate(path):
        node = node_lookup[node_id]
        is_endpoint = index in {0, len(path) - 1}
        if (
            not is_endpoint
            and node.node_type in {"file", "data"}
            and _is_noisy_file(node.metadata.get("path", node.label))
        ):
            continue
        if compressed and compressed[-1][0] == node_id:
            continue
        compressed.append((node_id, edge_type))
    return compressed or path


def _node_role(
    node_id: str,
    path: list[tuple[str, str | None]],
    node: GraphNode,
) -> str:
    if node_id == path[0][0]:
        return "source"
    if node_id == path[-1][0]:
        return "sink"
    if node.node_type in {"file", "data", "process", "tool_call"}:
        return "relay"
    return "context"


def _has_tool_neighbor(node_id: str, adjacency: dict[str, list[tuple[str, str]]]) -> bool:
    for source_id, neighbors in adjacency.items():
        if source_id.startswith("tool:"):
            for target_id, edge_type in neighbors:
                if target_id == node_id and edge_type in {"reads", "writes"}:
                    return True
    return False


def _has_tool_predecessor(node_id: str, adjacency: dict[str, list[tuple[str, str]]]) -> bool:
    for source_id, neighbors in adjacency.items():
        if not source_id.startswith("tool:"):
            continue
        for target_id, edge_type in neighbors:
            if target_id == node_id and edge_type == "connects":
                return True
    return False


def _is_sensitive_file(path: str) -> bool:
    return path.startswith(("/etc/", "/root/", "/proc/", "/sys/", "/var/run/"))


def _is_generated_local_file(path: str) -> bool:
    if not path:
        return False
    return path.startswith("runtime_output/") or (not path.startswith("/") and not path.startswith("public/"))


def _is_noisy_file(path: str) -> bool:
    if not path:
        return False
    if path in NOISY_FILE_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in NOISY_FILE_PREFIXES)
