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
    supporting_event_ids: list[str] = field(default_factory=list)

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
            contradictions = _contradictions(static_items, runtime_items, chains, coverage)

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
            host = parsed.hostname or str(node.metadata.get("sink_domain") or node.metadata.get("host") or node.label)
            path = parsed.path if parsed.hostname and parsed.path not in {"", "/"} else ""
            key = f"{host}{path}"
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
    for group, kind in (
        ("entities", "entity"),
        ("resolved_entities", "entity"),
        ("actions", "action"),
        ("extracted_actions", "action"),
    ):
        for item in payload.get(group, []) or []:
            if not isinstance(item, dict):
                continue
            for key in _static_alignment_keys(item, kind):
                items.append(
                    {
                        "id": str(item.get("entity_id") or item.get("action_id") or item.get("id") or key),
                        "kind": kind,
                        "key": _normalize_key(str(key)),
                        "raw": item,
                    }
                )
    for mention in payload.get("deterministic_mentions", []) or []:
        if not isinstance(mention, dict):
            continue
        value = mention.get("normalized_value") or mention.get("raw_value")
        if not value:
            continue
        mention_type = str(mention.get("mention_type") or "mention")
        kind = "endpoint" if mention_type in {"url", "domain"} else "entity"
        items.append(
            {
                "id": str(mention.get("mention_id") or value),
                "kind": kind,
                "key": _normalize_key(str(value)),
                "raw": mention,
            }
        )
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        marker = (item["id"], item["kind"], item["key"])
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(item)
    return deduped


def _static_alignment_keys(item: dict[str, Any], kind: str) -> list[str]:
    keys: list[str] = []
    alignment_keys = item.get("alignment_keys") or item.get("runtime_alignment_keys") or item.get("attributes", {})
    if isinstance(alignment_keys, dict):
        for field in ("alignment_key", "normalized_path", "path", "domain", "url", "endpoint", "command", "tool"):
            value = alignment_keys.get(field)
            if value:
                keys.append(str(value))
    for field in ("canonical", "canonical_value", "value", "name", "raw_verb", "action_type"):
        value = item.get(field)
        if value:
            keys.append(str(value))
    if kind == "action":
        for field in ("object_mentions", "source_mentions", "destination_mentions", "tool_mentions"):
            for value in item.get(field, []) or []:
                if value:
                    keys.append(str(value))
    return keys


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


def _contradictions(
    static_items: list[dict[str, Any]],
    runtime_items: list[dict[str, Any]],
    chains: list[RuntimeChain],
    coverage: CoverageReport,
) -> list[RuntimeContradiction]:
    contradictions: list[RuntimeContradiction] = []
    if coverage.coverage_state in {
        "timeout",
        "execution_failed",
        "path_not_triggered",
        "source_unavailable",
        "sink_unavailable",
        "environment_missing",
        "unsupported_operation",
        "insufficient_coverage",
    }:
        return contradictions
    confirmed_chains = [chain for chain in chains if chain.chain_type.endswith("_confirmed")]
    if not confirmed_chains and coverage.coverage_state != "runtime_confirmed":
        return contradictions
    static_keys = {item["key"] for item in static_items}
    has_static_network = any(item["kind"] in {"endpoint", "action"} and ("http" in item["key"] or "." in item["key"]) for item in static_items)
    if not has_static_network and any(chain.chain_type == "confidentiality_confirmed" for chain in confirmed_chains):
        contradictions.append(
            RuntimeContradiction(
                contradiction_type="static_no_network_action_runtime_network_flow",
                reason="static inputs did not declare a network endpoint/action but runtime closed a network data-flow chain",
                supporting_ids=[chain.chain_id for chain in confirmed_chains if chain.chain_type == "confidentiality_confirmed"],
            )
        )
    runtime_endpoints = [item for item in runtime_items if item["kind"] == "endpoint"]
    static_url_endpoints = [item for item in static_items if item["kind"] == "endpoint" and "/" in item["key"].rstrip("/")]
    confirmed_sink_ids = {chain.sink for chain in confirmed_chains if chain.sink}
    for endpoint in runtime_endpoints:
        if endpoint["id"] not in confirmed_sink_ids:
            continue
        if static_url_endpoints and not any(_endpoint_url_match(endpoint["key"], item["key"]) for item in static_url_endpoints):
            contradictions.append(
                RuntimeContradiction(
                    contradiction_type="declared_official_endpoint_runtime_unrelated_endpoint",
                    runtime_edge_id=endpoint["id"],
                    reason="runtime endpoint path did not align with any statically declared URL endpoint",
                    supporting_ids=[endpoint["id"]] + [item["id"] for item in static_url_endpoints],
                )
            )
            continue
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
    if left_host == right_host:
        left_has_path = "/" in left.rstrip("/")
        right_has_path = "/" in right.rstrip("/")
        if left_has_path or right_has_path:
            return left.rstrip("/") == right.rstrip("/")
        return True
    return left_host.endswith("." + right_host) or right_host.endswith("." + left_host)


def _endpoint_url_match(left: str, right: str) -> bool:
    return left.rstrip("/").lower() == right.rstrip("/").lower()
