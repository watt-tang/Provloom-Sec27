from __future__ import annotations

import posixpath
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.dynamic.models import CoverageReport, RuntimeChain, RuntimeProvenanceGraph


@dataclass
class AlignmentRecord:
    alignment_id: str
    status: str
    runtime_id: str | None = None
    static_id: str | None = None
    score: float = 0.0
    reason: str = ""
    supporting_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeContradiction:
    contradiction_type: str
    runtime_edge_id: str | None = None
    static_edge_id: str | None = None
    reason: str = ""
    supporting_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StaticRuntimeAligner:
    def align(
        self,
        *,
        graph: RuntimeProvenanceGraph,
        chains: list[RuntimeChain],
        coverage: CoverageReport,
        static_result: Any | None = None,
    ) -> dict[str, Any]:
        static_items = _extract_static_items(static_result)
        runtime_items = _extract_runtime_items(graph)
        records: list[AlignmentRecord] = []
        contradictions: list[RuntimeContradiction] = []

        if not static_items:
            for item in runtime_items:
                records.append(
                    AlignmentRecord(
                        alignment_id=f"AL-{len(records) + 1:04d}",
                        status="runtime_only",
                        runtime_id=item["id"],
                        score=0.0,
                        reason=f"runtime {item['kind']} has no static input in this analysis invocation",
                        supporting_ids=[item["id"]],
                    )
                )
        else:
            for runtime_item in runtime_items:
                match = _best_match(runtime_item, static_items)
                if match is None:
                    records.append(
                        AlignmentRecord(
                            alignment_id=f"AL-{len(records) + 1:04d}",
                            status="runtime_only",
                            runtime_id=runtime_item["id"],
                            score=0.0,
                            reason="no static entity/action matched normalized runtime key",
                            supporting_ids=[runtime_item["id"]],
                        )
                    )
                    continue
                records.append(
                    AlignmentRecord(
                        alignment_id=f"AL-{len(records) + 1:04d}",
                        status="aligned" if match["score"] >= 0.85 else "partially_aligned",
                        runtime_id=runtime_item["id"],
                        static_id=match["static"]["id"],
                        score=match["score"],
                        reason=match["reason"],
                        supporting_ids=[runtime_item["id"], match["static"]["id"]],
                    )
                )
            contradictions = _contradictions(static_items, runtime_items, chains)

        return {
            "schema_version": "static-runtime-alignment-v1",
            "status": _overall_status(records, contradictions, static_items),
            "alignment_records": [record.to_dict() for record in records],
            "contradictions": [item.to_dict() for item in contradictions],
            "coverage_state": coverage.coverage_state,
            "summary": {
                "runtime_item_count": len(runtime_items),
                "static_item_count": len(static_items),
                "aligned_count": sum(1 for record in records if record.status == "aligned"),
                "partial_count": sum(1 for record in records if record.status == "partially_aligned"),
                "runtime_only_count": sum(1 for record in records if record.status == "runtime_only"),
                "contradiction_count": len(contradictions),
            },
        }


def _extract_runtime_items(graph: RuntimeProvenanceGraph) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for node in graph.nodes:
        if node.node_type == "File":
            key = _norm_path(node.metadata.get("path") or node.label)
            items.append({"id": node.node_id, "kind": "file", "key": key, "label": node.label})
        elif node.node_type == "NetworkEndpoint":
            parsed = urlparse(str(node.label).replace("NET:", ""))
            key = parsed.hostname or str(node.metadata.get("sink_domain") or node.metadata.get("host") or node.label)
            items.append({"id": node.node_id, "kind": "endpoint", "key": key.lower(), "label": node.label})
        elif node.node_type in {"ToolInvocation", "Process"}:
            key = str(node.metadata.get("tool_id") or node.metadata.get("command") or node.label)
            items.append({"id": node.node_id, "kind": "action", "key": posixpath.basename(key), "label": node.label})
        elif node.node_type == "DataObject":
            items.append({"id": node.node_id, "kind": "data", "key": str(node.metadata.get("carrier_location") or node.label), "label": node.label})
    return [item for item in items if item["key"]]


def _extract_static_items(static_result: Any | None) -> list[dict[str, Any]]:
    if static_result is None:
        return []
    payload = static_result.to_dict() if hasattr(static_result, "to_dict") else static_result
    if not isinstance(payload, dict):
        return []
    items: list[dict[str, Any]] = []
    for group, kind in (("entities", "entity"), ("actions", "action")):
        for item in payload.get(group, []) or []:
            if not isinstance(item, dict):
                continue
            alignment_keys = item.get("alignment_keys") or item.get("runtime_alignment_keys") or item.get("attributes", {})
            key = alignment_keys.get("alignment_key") or alignment_keys.get("normalized_path") or alignment_keys.get("domain") or item.get("canonical") or item.get("value") or item.get("name")
            if key:
                items.append({"id": str(item.get("entity_id") or item.get("action_id") or item.get("id") or key), "kind": kind, "key": _normalize_key(str(key)), "raw": item})
    return items


def _best_match(runtime_item: dict[str, Any], static_items: list[dict[str, Any]]) -> dict[str, Any] | None:
    runtime_key = _normalize_key(runtime_item["key"])
    best: dict[str, Any] | None = None
    for static in static_items:
        static_key = _normalize_key(static["key"])
        score = 0.0
        reason = ""
        if runtime_key == static_key:
            score = 1.0
            reason = "exact normalized key match"
        elif runtime_item["kind"] == "endpoint" and _domain_match(runtime_key, static_key):
            score = 0.88
            reason = "domain registrable/suffix match"
        elif runtime_item["kind"] == "file" and _path_suffix_match(runtime_key, static_key):
            score = 0.72
            reason = "normalized path suffix match"
        elif runtime_item["kind"] == "action" and posixpath.basename(runtime_key) == posixpath.basename(static_key):
            score = 0.7
            reason = "command/tool basename match"
        if score and (best is None or score > best["score"]):
            best = {"static": static, "score": score, "reason": reason}
    return best


def _contradictions(static_items: list[dict[str, Any]], runtime_items: list[dict[str, Any]], chains: list[RuntimeChain]) -> list[RuntimeContradiction]:
    contradictions: list[RuntimeContradiction] = []
    static_keys = {item["key"] for item in static_items}
    has_static_network = any(item["kind"] in {"endpoint", "action"} and ("http" in item["key"] or "." in item["key"]) for item in static_items)
    if not has_static_network and any(chain.chain_type == "confidentiality_confirmed" for chain in chains):
        contradictions.append(
            RuntimeContradiction(
                contradiction_type="static_no_network_action_runtime_network_flow",
                reason="static inputs did not declare a network endpoint/action but runtime closed a network data-flow chain",
                supporting_ids=[chain.chain_id for chain in chains if chain.chain_type == "confidentiality_confirmed"],
            )
        )
    runtime_endpoints = [item for item in runtime_items if item["kind"] == "endpoint"]
    for endpoint in runtime_endpoints:
        if static_keys and not _best_match(endpoint, static_items):
            contradictions.append(
                RuntimeContradiction(
                    contradiction_type="declared_official_endpoint_runtime_unrelated_endpoint",
                    runtime_edge_id=endpoint["id"],
                    reason="runtime endpoint did not align with any static endpoint key",
                    supporting_ids=[endpoint["id"]],
                )
            )
    return contradictions


def _overall_status(records: list[AlignmentRecord], contradictions: list[RuntimeContradiction], static_items: list[dict[str, Any]]) -> str:
    if contradictions:
        return "contradicted"
    if not static_items:
        return "runtime_only"
    if records and all(record.status == "aligned" for record in records):
        return "aligned"
    if any(record.status in {"aligned", "partially_aligned"} for record in records):
        return "partially_aligned"
    return "unresolved"


def _normalize_key(value: str) -> str:
    value = value.strip().replace("\\", "/")
    parsed = urlparse(value)
    if parsed.scheme and parsed.hostname:
        return (parsed.hostname + parsed.path).rstrip("/").lower()
    return _norm_path(value).lower()


def _norm_path(value: Any) -> str:
    return posixpath.normpath(str(value or "").replace("\\", "/"))


def _path_suffix_match(left: str, right: str) -> bool:
    return bool(left and right and (left.endswith("/" + right.lstrip("/")) or right.endswith("/" + left.lstrip("/"))))


def _domain_match(left: str, right: str) -> bool:
    left_host = left.split("/", 1)[0]
    right_host = right.split("/", 1)[0]
    return left_host == right_host or left_host.endswith("." + right_host) or right_host.endswith("." + left_host)
