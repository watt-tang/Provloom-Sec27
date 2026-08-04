from __future__ import annotations

import difflib
import posixpath
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.dynamic.assessment import assess_dynamic_result
from app.dynamic.review_lean import apply_review_lean
from app.explanation.models import (
    ALIGNMENT_VERSION,
    ASSESSMENT_VERSION,
    DYNAMIC_VERSION,
    STATIC_VERSION,
    CoverageCertificate,
    ExecutionCompletion,
    PathCompletionResult,
    PolicyFinding,
    RiskChainStatus,
    RuntimeObligation,
    SecurityResolutionStatus,
    StaticPathCompletion,
    UnifiedAlignment,
    UnifiedContradiction,
    UnifiedExplanationResult,
)
from app.taint.source_registry import SourceRegistry


ACTION_COMPATIBILITY = {
    "READ": {"file_read", "read", "read_file", "ACCESS_CREDENTIAL"},
    "WRITE": {"file_write", "write", "write_file", "PERSIST"},
    "EXECUTE": {"process_exec", "exec", "run_command", "EXEC"},
    "SEND": {"network_send", "send", "http_request", "llm_request", "INVOKE_API"},
    "UPLOAD": {"file_upload", "upload", "network_send"},
    "DOWNLOAD": {"network_receive", "download", "file_write"},
    "ACCESS_CREDENTIAL": {"file_read", "read", "sensitive_source"},
    "INVOKE_API": {"network_send", "network_connect", "llm_request", "http_request"},
    "PERSIST": {"file_write", "write", "persistence_confirmed"},
}

CONTRADICTION_TYPES = {
    "declared_local_only_but_runtime_network",
    "declared_endpoint_mismatch",
    "declared_auth_but_runtime_body_exposure",
    "declared_artifact_identity_mismatch",
    "required_confirmation_but_runtime_preconfirmation_action",
    "declared_temporary_but_runtime_persistence",
    "declared_read_scope_but_runtime_extra_sensitive_read",
    "declared_tool_but_runtime_different_tool",
    "declared_no_external_side_effect_but_runtime_external_effect",
}


def build_unified_explanation(
    *,
    skill_id: str,
    static_result: Any | None,
    dynamic_result: Any | None,
    execution: Any | None = None,
    legacy_report: dict[str, Any] | None = None,
    analysis_mode: str = "full_system",
) -> UnifiedExplanationResult:
    static_payload = _payload(static_result)
    dynamic_payload = _payload(dynamic_result)
    runtime_events = _runtime_events(dynamic_result, dynamic_payload)
    runtime_chains = _runtime_chains(dynamic_result, dynamic_payload)
    static_items = _static_items(static_payload)
    runtime_items = _runtime_items(runtime_events, dynamic_payload)
    alignments = _build_alignments(static_items, runtime_items, runtime_chains, static_payload)
    contradictions = _build_contradictions(static_payload, runtime_events, runtime_chains, alignments)
    coverage_certificate = _build_coverage_certificate(
        static_payload=static_payload,
        runtime_events=runtime_events,
        runtime_chains=runtime_chains,
        dynamic_payload=dynamic_payload,
        execution=execution,
    )
    policy_findings = _build_policy_findings(static_payload, dynamic_payload, runtime_chains, contradictions, coverage_certificate)
    canonical = _canonical_assessment(dynamic_result, static_payload, dynamic_payload, policy_findings, coverage_certificate, analysis_mode=analysis_mode)
    witnesses = _minimal_witnesses(static_payload, runtime_chains)
    relevant_unresolved = [item.to_dict() for item in alignments if item.status == "relevant_unresolved"]
    internal_unresolved = [item.to_dict() for item in alignments if item.status == "internal_unresolved"]
    aligned_runtime_ids = {rid for item in alignments for rid in item.runtime_ids if item.status in {"aligned", "partially_aligned"}}
    internal_runtime_ids = {rid for item in alignments for rid in item.runtime_ids if item.status == "internal_unresolved"}
    aligned_static_ids = {sid for item in alignments for sid in item.static_ids if item.status in {"aligned", "partially_aligned"}}
    unified = UnifiedExplanationResult(
        skill_id=skill_id,
        static_result=static_payload,
        dynamic_result=dynamic_payload,
        alignments=alignments,
        contradictions=contradictions,
        aligned_paths=[item.to_dict() for item in alignments if item.alignment_type == "path" and item.status in {"aligned", "partially_aligned"}],
        instruction_only_paths=_instruction_only_paths(static_payload, aligned_static_ids),
        runtime_only_paths=_runtime_only_paths(runtime_chains, runtime_events, aligned_runtime_ids, internal_runtime_ids),
        relevant_unresolved=relevant_unresolved,
        internal_unresolved=internal_unresolved,
        coverage_certificate=coverage_certificate,
        policy_violations=list(dynamic_payload.get("policy_violations", dynamic_payload.get("runtime_policy_violations", [])) or []),
        canonical_assessment=canonical,
        minimal_witnesses=witnesses,
        limitations=_limitations(dynamic_payload, coverage_certificate),
        legacy_compatibility={
            "legacy_risk_score": (legacy_report or {}).get("legacy_risk_score", (legacy_report or {}).get("risk_score", 0)),
            "legacy_final_decision": (legacy_report or {}).get("legacy_final_decision", (legacy_report or {}).get("final_decision", "unknown")),
            "legacy_static_result_present": bool((legacy_report or {}).get("legacy_static_result")),
            "deprecated_fields": ["coverage_certificate.path_completion_status"],
            "compatibility_only": True,
        },
        policy_findings=policy_findings,
        risk_chain_status=coverage_certificate.risk_chain_status.to_dict(),
        execution_completion=coverage_certificate.execution_completion.to_dict(),
        static_path_results=[item.to_dict() for item in coverage_certificate.static_path_results],
        primary_static_path_id=coverage_certificate.primary_static_path_id,
        primary_static_path_status=coverage_certificate.primary_static_path_status,
        other_static_path_summary=dict(coverage_certificate.other_static_path_summary),
        obligation_relevance_summary=dict(coverage_certificate.obligation_relevance_summary),
        security_resolution=coverage_certificate.security_resolution.to_dict(),
        security_resolution_status=coverage_certificate.security_resolution.status,
    )
    unified.versions.update(
        {
            "static_analysis_version": STATIC_VERSION,
            "dynamic_analysis_version": DYNAMIC_VERSION,
            "alignment_version": ALIGNMENT_VERSION,
            "assessment_version": ASSESSMENT_VERSION,
        }
    )
    return unified


def _payload(value: Any | None) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return dict(value) if isinstance(value, dict) else {}


def _runtime_events(dynamic_result: Any | None, dynamic_payload: dict[str, Any]) -> list[dict[str, Any]]:
    if dynamic_result is not None and hasattr(dynamic_result, "runtime_events"):
        return [event.to_dict() if hasattr(event, "to_dict") else dict(event) for event in dynamic_result.runtime_events]
    return list(dynamic_payload.get("runtime_events") or dynamic_payload.get("runtime_events_v2") or [])


def _runtime_chains(dynamic_result: Any | None, dynamic_payload: dict[str, Any]) -> list[dict[str, Any]]:
    if dynamic_result is not None and hasattr(dynamic_result, "chains"):
        return [chain.to_dict() if hasattr(chain, "to_dict") else dict(chain) for chain in dynamic_result.chains]
    return list(dynamic_payload.get("runtime_chains") or [])


def _static_items(static_payload: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for entity in static_payload.get("resolved_entities", []) or []:
        sid = _static_id(entity, "entity")
        for key in _entity_keys(entity):
            kind = _entity_kind(entity)
            items.append({"id": sid, "kind": kind, "key": key, "raw": entity})
    for action in static_payload.get("extracted_actions", []) or []:
        sid = _static_id(action, "action")
        action_type = str(action.get("action_type") or action.get("type") or "").upper()
        if action_type:
            items.append({"id": sid, "kind": "action", "key": action_type, "raw": action})
        for key in _action_keys(action):
            items.append({"id": sid, "kind": "action", "key": key, "raw": action})
    for mention in static_payload.get("deterministic_mentions", []) or []:
        value = mention.get("normalized_value") or mention.get("raw_value")
        if not value:
            continue
        kind = "endpoint" if str(mention.get("mention_type")) in {"url", "domain"} else "entity"
        items.append({"id": str(mention.get("mention_id") or value), "kind": kind, "key": str(value), "raw": mention})
    for chain in static_payload.get("static_chains", []) or []:
        cid = str(chain.get("chain_id") or "")
        if cid:
            items.append({"id": cid, "kind": "path", "key": str(chain.get("chain_type") or ""), "raw": chain})
    return _dedupe_items(items)


def _runtime_items(events: list[dict[str, Any]], dynamic_payload: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    graph = dynamic_payload.get("runtime_provenance_graph", {}) or {}
    for node in graph.get("nodes", []) or []:
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("node_type") or "")
        meta = node.get("metadata", {}) or {}
        label = str(node.get("label") or "")
        rid = str(node.get("node_id") or label)
        if node_type == "File":
            items.append({"id": rid, "kind": "file", "key": meta.get("path") or label, "raw": node})
        elif node_type == "NetworkEndpoint":
            items.append({"id": rid, "kind": "endpoint", "key": meta.get("sink_url") or meta.get("sink_domain") or label.replace("NET:", ""), "raw": node})
        elif node_type in {"ToolInvocation", "Process"}:
            items.append({"id": rid, "kind": "tool" if node_type == "ToolInvocation" else "process", "key": meta.get("tool_id") or meta.get("command") or label, "raw": node})
        elif node_type == "DataObject":
            items.append({"id": rid, "kind": "data", "key": meta.get("carrier_location") or label, "raw": node})
    for event in events:
        eid = str(event.get("event_id") or "")
        operation = str(event.get("operation") or event.get("event_type") or "")
        if operation:
            items.append({"id": eid, "kind": "action", "key": operation, "raw": event})
        if event.get("object_path"):
            items.append({"id": eid, "kind": "file", "key": event.get("object_path"), "raw": event})
        if event.get("object_type") == "network":
            items.append({"id": eid, "kind": "endpoint", "key": _event_endpoint(event), "raw": event})
    return _dedupe_items(items)


def _build_alignments(
    static_items: list[dict[str, Any]],
    runtime_items: list[dict[str, Any]],
    runtime_chains: list[dict[str, Any]],
    static_payload: dict[str, Any],
) -> list[UnifiedAlignment]:
    records: list[UnifiedAlignment] = []
    used_runtime: set[str] = set()
    chain_related_runtime_ids = _chain_related_runtime_ids(runtime_chains)
    for ritem in runtime_items:
        match = _best_match(ritem, static_items)
        if match is None:
            internal_scope = _is_runtime_internal_item(ritem) and not _runtime_item_has_taint(ritem) and ritem["id"] not in chain_related_runtime_ids
            status = "internal_unresolved" if internal_scope else "relevant_unresolved"
            reason = (
                "runtime_internal item is outside static entities, taint sources, runtime chains, and target actions"
                if internal_scope
                else "no compatible static entity, action, carrier, or path matched"
            )
            records.append(
                UnifiedAlignment(
                    alignment_id=f"ALN-{len(records) + 1:04d}",
                    status=status,
                    alignment_type=_alignment_type(ritem["kind"]),
                    runtime_ids=[ritem["id"]],
                    reason=reason,
                    supporting_evidence=[_evidence("runtime", ritem["id"], ritem["key"], scope="runtime_internal" if internal_scope else "relevant")],
                )
            )
            continue
        used_runtime.add(ritem["id"])
        records.append(
            UnifiedAlignment(
                alignment_id=f"ALN-{len(records) + 1:04d}",
                status="aligned" if match["score"] >= 0.85 else "partially_aligned",
                alignment_type=_alignment_type(ritem["kind"]),
                static_ids=[match["item"]["id"]],
                runtime_ids=[ritem["id"]],
                score=match["score"],
                reason=match["reason"],
                matched_keys=[match["key"]],
                conflicting_keys=[],
                supporting_evidence=[_evidence("runtime", ritem["id"], ritem["key"]), _evidence("static", match["item"]["id"], match["item"]["key"])],
            )
        )
    static_chain_keys = {_norm_key(item.get("chain_type")) for item in static_payload.get("static_chains", []) or [] if item.get("chain_id")}
    for chain in runtime_chains:
        runtime_type = _runtime_chain_semantic_type(chain)
        if runtime_type and _norm_key(runtime_type) in static_chain_keys:
            static_ids = [str(item.get("chain_id")) for item in static_payload.get("static_chains", []) or [] if _norm_key(item.get("chain_type")) == _norm_key(runtime_type)]
            records.append(
                UnifiedAlignment(
                    alignment_id=f"ALN-{len(records) + 1:04d}",
                    status="partially_aligned",
                    alignment_type="path",
                    static_ids=static_ids,
                    runtime_ids=[str(chain.get("chain_id"))],
                    score=0.72,
                    reason="runtime chain semantic type is compatible with static path type",
                    matched_keys=[runtime_type],
                    supporting_evidence=[_evidence("runtime_chain", str(chain.get("chain_id")), runtime_type)],
                )
            )
        elif str(chain.get("chain_id")) not in used_runtime:
            records.append(
                UnifiedAlignment(
                    alignment_id=f"ALN-{len(records) + 1:04d}",
                    status="relevant_unresolved",
                    alignment_type="path",
                    runtime_ids=[str(chain.get("chain_id"))],
                    score=0.0,
                    reason="runtime chain has no compatible static path",
                    supporting_evidence=[_evidence("runtime_chain", str(chain.get("chain_id")), runtime_type or str(chain.get("chain_type")))],
                )
            )
    return records


def _chain_related_runtime_ids(runtime_chains: list[dict[str, Any]]) -> set[str]:
    related: set[str] = set()
    for chain in runtime_chains:
        for field in ("chain_id", "source_event_id", "sink_event_id"):
            if chain.get(field):
                related.add(str(chain[field]))
        for field in ("supporting_event_ids", "ordered_nodes", "ordered_edges"):
            for value in chain.get(field, []) or []:
                related.add(str(value))
    return related


def _runtime_item_has_taint(runtime_item: dict[str, Any]) -> bool:
    raw = runtime_item.get("raw") or {}
    if raw.get("taint_ids") or raw.get("input_taint_ids") or raw.get("output_taint_ids"):
        return True
    metadata = raw.get("metadata") or {}
    if isinstance(metadata, dict) and (metadata.get("taint_ids") or metadata.get("source_id")):
        return True
    return False


def _is_runtime_internal_item(runtime_item: dict[str, Any]) -> bool:
    if _runtime_item_has_sensitive_source(runtime_item):
        return False
    kind = str(runtime_item.get("kind") or "")
    raw = runtime_item.get("raw") or {}
    keys = [
        runtime_item.get("key"),
        raw.get("label"),
        raw.get("object_path"),
        raw.get("object_id"),
        raw.get("data_preview"),
    ]
    metadata = raw.get("metadata") or {}
    if isinstance(metadata, dict):
        keys.extend(
            metadata.get(field)
            for field in ("path", "command", "executable", "source_path", "destination", "carrier_location")
        )
    text = " ".join(str(key or "") for key in keys).replace("\\", "/").lower()
    if not text:
        return False
    if kind == "endpoint":
        return False
    internal_markers = (
        "/opt/skill_sandbox/",
        "python -m app.runtime.container_runtime",
        "/usr/local/lib/python",
        "/usr/lib/python",
        "/lib/python",
        "/site-packages/",
        "__pycache__",
        ".pyc",
        "/etc/ssl/",
        "/usr/lib/ssl/",
        "/etc/ca-certificates/",
        "/usr/share/ca-certificates/",
        "certifi/cacert.pem",
        "/root/.cache/",
        "/.cache/",
        "/pip/",
        "/.npm/",
        "node_modules/",
        "huggingface/",
        "transformers/",
        "modelscope/",
        "/var/cache/",
        "/var/lib/apt/",
        "/tmp/pip-",
        "/tmp/tmp",
    )
    if any(marker in text for marker in internal_markers):
        return True
    return bool(kind in {"process", "tool"} and "strace" in text and "/artifacts/trace.log" in text)


def _runtime_item_has_sensitive_source(runtime_item: dict[str, Any]) -> bool:
    registry = SourceRegistry()
    raw = runtime_item.get("raw") or {}
    candidates = [runtime_item.get("key"), raw.get("object_path")]
    metadata = raw.get("metadata") or {}
    if isinstance(metadata, dict):
        candidates.extend(metadata.get(field) for field in ("path", "source_path", "source_location"))
    sensitive_levels = {"medium", "high", "critical"}
    for candidate in candidates:
        match = registry.match_path(str(candidate or ""))
        if match and match.sensitivity in sensitive_levels:
            return True
    return False


def _best_match(runtime_item: dict[str, Any], static_items: list[dict[str, Any]]) -> dict[str, Any] | None:
    rkind = runtime_item["kind"]
    rkey = _norm_key(runtime_item["key"])
    best: dict[str, Any] | None = None
    for sitem in static_items:
        skey = _norm_key(sitem["key"])
        score = 0.0
        reason = ""
        matched_key = ""
        if not rkey or not skey:
            continue
        if rkey == skey:
            score, reason, matched_key = 1.0, "exact normalized identity", skey
        elif rkind in {"file", "data"} and sitem["kind"] in {"file", "artifact", "credential", "entity"} and _same_path(rkey, skey):
            score, reason, matched_key = 0.9, "exact normalized path or artifact identity", skey
        elif rkind == "endpoint" and sitem["kind"] in {"endpoint", "entity"} and _same_endpoint(rkey, skey):
            score, reason, matched_key = 0.88, "exact URL/domain endpoint relationship", skey
        elif rkind in {"tool", "process"} and sitem["kind"] in {"tool", "process", "action"} and _same_executable(rkey, skey):
            score, reason, matched_key = 0.86, "normalized command/executable match", skey
        elif rkind == "action" and sitem["kind"] == "action" and _actions_compatible(rkey, skey):
            score, reason, matched_key = 0.8, "structured semantic action compatibility", skey
        else:
            fuzzy = difflib.SequenceMatcher(a=rkey, b=skey).ratio()
            if fuzzy >= 0.82:
                score, reason, matched_key = min(0.69, fuzzy), "fuzzy string similarity weak evidence", skey
        if score and (best is None or score > best["score"]):
            best = {"item": sitem, "score": score, "reason": reason, "key": matched_key}
    return best


def _build_contradictions(
    static_payload: dict[str, Any],
    runtime_events: list[dict[str, Any]],
    runtime_chains: list[dict[str, Any]],
    alignments: list[UnifiedAlignment],
) -> list[UnifiedContradiction]:
    contradictions: list[UnifiedContradiction] = []
    claims = _static_claims(static_payload)
    network_events = [event for event in runtime_events if event.get("object_type") == "network" or str(event.get("event_type", "")).startswith(("network_", "llm_"))]
    tainted_body = [event for event in network_events if event.get("taint_ids") and event.get("carrier_type") in {"http_body", "multipart_field", "http_form", "socket_payload"}]
    persistence = [chain for chain in runtime_chains if chain.get("chain_type") == "persistence_confirmed"]
    sensitive_reads = [event for event in runtime_events if event.get("operation") == "read" and event.get("taint_ids") and event.get("object_type") == "file"]
    external_effects = [event for event in runtime_events if event.get("operation") in {"send", "upload", "write", "connect"} and (event.get("object_type") == "network" or _is_external_write(event))]

    if claims["local_only"] and network_events:
        contradictions.append(_contradiction("declared_local_only_but_runtime_network", "high", claims["local_only"], network_events, "static declares local-only execution but runtime observed network activity", 0.82))
    if claims["endpoints"] and network_events:
        runtime_endpoints = {_norm_endpoint(_event_endpoint(event)) for event in network_events if _event_endpoint(event)}
        static_endpoints = {_norm_endpoint(item["key"]) for item in claims["endpoints"] if item["key"]}
        if runtime_endpoints and static_endpoints and runtime_endpoints.isdisjoint(static_endpoints):
            contradictions.append(_contradiction("declared_endpoint_mismatch", "high", claims["endpoints"], network_events, "runtime endpoint does not match declared static endpoint set", 0.8))
    if claims["auth_only"] and tainted_body:
        contradictions.append(_contradiction("declared_auth_but_runtime_body_exposure", "critical", claims["auth_only"], tainted_body, "static describes credential use as authentication but runtime placed taint in body/form payload", 0.86))
    if claims["artifact_identity"] and _artifact_mismatch(claims["artifact_identity"], runtime_events):
        contradictions.append(_contradiction("declared_artifact_identity_mismatch", "high", claims["artifact_identity"], runtime_events, "runtime artifact path/hash differs from declared artifact identity", 0.72))
    if claims["confirmation_required"] and _preconfirmation_effects(runtime_events):
        contradictions.append(_contradiction("required_confirmation_but_runtime_preconfirmation_action", "high", claims["confirmation_required"], _preconfirmation_effects(runtime_events), "runtime performed side effect before any observed user confirmation", 0.75))
    if claims["temporary_only"] and persistence:
        contradictions.append(_contradiction("declared_temporary_but_runtime_persistence", "high", claims["temporary_only"], persistence, "static declares temporary behavior but runtime persistence chain was recovered", 0.8))
    if claims["read_scope"] and _extra_sensitive_reads(claims["read_scope"], sensitive_reads):
        contradictions.append(_contradiction("declared_read_scope_but_runtime_extra_sensitive_read", "high", claims["read_scope"], _extra_sensitive_reads(claims["read_scope"], sensitive_reads), "runtime read sensitive source outside declared read scope", 0.78))
    if claims["tools"] and _different_runtime_tools(claims["tools"], runtime_events):
        contradictions.append(_contradiction("declared_tool_but_runtime_different_tool", "medium", claims["tools"], _different_runtime_tools(claims["tools"], runtime_events), "runtime invoked a tool/executable not declared statically", 0.68, ["tool equivalence is syntactic"]))
    if claims["no_external_side_effect"] and external_effects:
        contradictions.append(_contradiction("declared_no_external_side_effect_but_runtime_external_effect", "high", claims["no_external_side_effect"], external_effects, "static says no external side effect but runtime observed one", 0.82))

    known = {item.contradiction_type for item in contradictions}
    for missing in sorted(CONTRADICTION_TYPES - known):
        _ = missing
    for item in contradictions:
        item.alignment_id = _alignment_for(item, alignments)
    return contradictions


def _build_coverage_certificate(
    *,
    static_payload: dict[str, Any],
    runtime_events: list[dict[str, Any]],
    runtime_chains: list[dict[str, Any]],
    dynamic_payload: dict[str, Any],
    execution: Any | None,
) -> CoverageCertificate:
    obligations = _runtime_obligations(static_payload, runtime_events, runtime_chains)
    sensitive_artifacts = _sensitive_artifact_findings(runtime_events, execution)
    gaps = sorted(
        {
            str(event.get("instrumentation_visibility"))
            for event in runtime_events
            if str(event.get("instrumentation_visibility") or "") not in {"", "observed", "payload_preview_observed", "endpoint_only"}
        }
        | {str(gap) for chain in runtime_chains for gap in chain.get("instrumentation_gaps", [])}
    )
    if any(event.get("metadata", {}).get("encrypted_payload_invisible") for event in runtime_events):
        gaps.append("encrypted_payload_invisible")
    satisfied = sum(1 for item in obligations if item.status == "satisfied")
    unsatisfied = sum(1 for item in obligations if item.status == "unsatisfied")
    unresolved = sum(1 for item in obligations if item.status in {"unresolved", "unverifiable"})
    dynamic_state = str((dynamic_payload.get("coverage") or dynamic_payload.get("runtime_coverage") or {}).get("coverage_state") or "")
    chain_summary = _chain_evidence_summary(runtime_chains)
    risk_chain_status = _risk_chain_status(dynamic_payload, runtime_chains, runtime_events)
    execution_completion = _execution_completion(execution, dynamic_state, runtime_events, dynamic_payload)
    static_path_results = _static_path_results(static_payload, obligations, runtime_chains, risk_chain_status, execution_completion)
    primary_selection = _primary_risk_path_selection(static_path_results, risk_chain_status)
    path_completion = _path_completion_results(static_payload, obligations, runtime_chains, execution, dynamic_state, static_path_results)
    state = _coverage_state_from_obligations(obligations, runtime_events, runtime_chains, gaps, dynamic_state, execution, sensitive_artifacts, path_completion)
    reasons = _coverage_reasons(state, obligations, gaps, dynamic_state, execution)
    security_resolution = _security_resolution_status(
        obligations=obligations,
        runtime_events=runtime_events,
        runtime_chains=runtime_chains,
        risk_status=risk_chain_status,
        execution_completion=execution_completion,
        static_path_results=static_path_results,
        primary_path_id=str(primary_selection.get("primary_static_path_id") or ""),
        instrumentation_gaps=sorted(set(gaps)),
    )
    obligation_summary = {
        "total": len(obligations),
        "satisfied": satisfied,
        "unsatisfied": unsatisfied,
        "unresolved": unresolved,
        "not_applicable": sum(1 for item in obligations if item.status == "not_applicable"),
        "high_risk_unresolved": sum(1 for item in obligations if item.status in {"unsatisfied", "unresolved", "unverifiable"} and item.risk_relevance in {"high", "critical"} and item.required_for_path_completion),
        "decisive": sum(1 for item in obligations if item.relevance == "decisive"),
        "supporting": sum(1 for item in obligations if item.relevance == "supporting"),
        "auxiliary": sum(1 for item in obligations if item.relevance == "auxiliary"),
        "decisive_unresolved": sum(1 for item in obligations if item.relevance == "decisive" and item.status in {"unsatisfied", "unresolved", "unverifiable"}),
        "supporting_unresolved": sum(1 for item in obligations if item.relevance == "supporting" and item.status in {"unsatisfied", "unresolved", "unverifiable"}),
        "auxiliary_unresolved": sum(1 for item in obligations if item.relevance == "auxiliary" and item.status in {"unsatisfied", "unresolved", "unverifiable"}),
    }
    other_summary = _other_static_path_summary(static_path_results, primary_selection.get("primary_static_path_id", ""))
    return CoverageCertificate(
        coverage_state=state,
        obligations=obligations,
        reasons=reasons,
        instrumentation_gaps=sorted(set(gaps)),
        summary={
            "obligation_count": len(obligations),
            "satisfied": satisfied,
            "unsatisfied": unsatisfied,
            "unverifiable": unresolved,
            "not_applicable": obligation_summary["not_applicable"],
            "dynamic_coverage_state": dynamic_state,
            "chain_evidence": chain_summary,
        },
        execution_status=_execution_status(execution, dynamic_state),
        chain_evidence_status=chain_summary["strongest_evidence_status"],
        path_completion_status=primary_selection.get("primary_static_path_status") or _overall_path_completion(path_completion, obligations, sensitive_artifacts, state),
        termination_reason=_termination_reason(execution, dynamic_state),
        obligation_summary=obligation_summary,
        environment_gaps=_environment_gaps(state, dynamic_state),
        sensitive_artifacts=sensitive_artifacts,
        path_completion=path_completion,
        risk_chain_status=risk_chain_status,
        execution_completion=execution_completion,
        static_path_results=static_path_results,
        primary_static_path_id=str(primary_selection.get("primary_static_path_id") or ""),
        primary_static_path_status=str(primary_selection.get("primary_static_path_status") or "not_applicable"),
        primary_risk_path_selection=primary_selection,
        other_static_path_summary=other_summary,
        obligation_relevance_summary={
            "decisive": obligation_summary["decisive"],
            "supporting": obligation_summary["supporting"],
            "auxiliary": obligation_summary["auxiliary"],
            "decisive_unresolved": obligation_summary["decisive_unresolved"],
            "supporting_unresolved": obligation_summary["supporting_unresolved"],
            "auxiliary_unresolved": obligation_summary["auxiliary_unresolved"],
        },
        security_resolution=security_resolution,
        security_resolution_status=security_resolution.status,
        security_decisive_obligations_resolved=security_resolution.security_decisive_obligations_resolved,
        security_resolution_event_index=security_resolution.resolution_event_index,
        security_resolution_timestamp=security_resolution.resolution_timestamp,
        termination_event_index=security_resolution.termination_event_index,
        termination_timestamp=security_resolution.termination_timestamp,
        termination_after_security_resolution=security_resolution.termination_after_resolution,
        unresolved_decisive_obligations=list(security_resolution.unresolved_decisive_obligation_ids),
        blocking_security_paths=list(security_resolution.blocking_security_paths),
        non_blocking_supporting_gaps=list(security_resolution.non_blocking_supporting_gaps),
        non_blocking_auxiliary_gaps=list(security_resolution.non_blocking_auxiliary_gaps),
    )


def _runtime_obligations(static_payload: dict[str, Any], runtime_events: list[dict[str, Any]], runtime_chains: list[dict[str, Any]]) -> list[RuntimeObligation]:
    obligations: list[RuntimeObligation] = []
    static_chains = list(static_payload.get("static_chains", []) or [])
    if static_payload:
        obligations.append(
            RuntimeObligation(
                obligation_id="OBL-0001",
                origin="trigger_plan",
                static_ids=[],
                expected_runtime_operation="skill_activation",
                static_path_id="execution",
                origin_static_ids=[],
                status="satisfied" if runtime_events else "unsatisfied",
                supporting_runtime_ids=[event.get("event_id", "") for event in runtime_events[:1]],
                reason="runtime emitted at least one event" if runtime_events else "no runtime events were observed",
                obligation_type="execution_started",
                path_role="execution",
                relevance="supporting",
                risk_relevance="low",
                required_for_path_completion=False,
                required_for_risk_closure=False,
                required_for_execution_completion=True,
            )
        )
    for action in static_payload.get("extracted_actions", []) or []:
        if not _action_creates_required_obligation(action):
            continue
        action_id = _static_id(action, "action")
        static_path_id = _static_path_id_for_action(action_id, static_chains)
        for expected, obligation_type, risk in _expected_obligations_for_action(action):
            matches = [event for event in runtime_events if _runtime_matches_expected(event, expected, action)]
            status = "satisfied" if matches else "unsatisfied"
            if expected == "payload_observable" and _tls_payload_gap(runtime_events):
                status = "unresolved"
            path_role, relevance = _obligation_role_and_relevance(action, expected)
            obligations.append(
                RuntimeObligation(
                    obligation_id=f"OBL-{len(obligations) + 1:04d}",
                    origin="declared_action",
                    static_ids=[action_id],
                    expected_runtime_operation=expected,
                    static_path_id=static_path_id,
                    origin_static_ids=[action_id],
                    expected_entity_keys=_action_keys(action),
                    status=status,
                    supporting_runtime_ids=[str(event.get("event_id")) for event in matches],
                    reason="matched runtime operation" if matches else "declared static action was not observed at runtime",
                    obligation_type=obligation_type,
                    path_role=path_role,
                    relevance=relevance,
                    risk_relevance=risk,
                    required_for_path_completion=relevance == "decisive",
                    required_for_risk_closure=relevance == "decisive",
                    required_for_execution_completion=False,
                    conditional=str(action.get("modality") or "").lower() == "conditional",
                    condition_status="unknown" if str(action.get("modality") or "").lower() == "conditional" else "not_applicable",
                    blocking_condition=None if status == "satisfied" else "runtime_operation_missing",
                )
            )
    for action in static_payload.get("extracted_actions", []) or []:
        if not _action_creates_guard_obligation(action, runtime_chains):
            continue
        action_id = _static_id(action, "action")
        static_path_id = _static_path_id_for_action(action_id, static_chains)
        obligations.append(
            RuntimeObligation(
                obligation_id=f"OBL-{len(obligations) + 1:04d}",
                origin="static_guard",
                static_ids=[action_id],
                expected_runtime_operation="untrusted_sink_absence_resolved",
                static_path_id=static_path_id,
                origin_static_ids=[action_id],
                expected_entity_keys=_action_keys(action),
                status="unresolved",
                supporting_runtime_ids=_confirmed_trusted_chain_ids(runtime_chains),
                reason="static instruction prohibits external send/upload/API behavior, while runtime confirmed sensitive data only reached a trusted LLM carrier; no untrusted sink evidence was observed",
                obligation_type="forbidden_external_sink_guard",
                path_role="guard",
                relevance="decisive",
                risk_relevance="high",
                required_for_path_completion=True,
                required_for_risk_closure=True,
                blocking_condition="trusted_llm_boundary_pending" if _trusted_llm_boundary_guard(action) else "trusted_llm_chain_without_untrusted_sink_resolution",
            )
        )
    for chain in static_chains:
        if str(chain.get("alert_status") or chain.get("policy_status") or "") in {"allowed"}:
            continue
        chain_id = str(chain.get("chain_id") or "")
        expected = _expected_chain_obligation(chain)
        matches = [event for event in runtime_events if _runtime_chain_action_match(event, expected)]
        risk = "high" if expected in {"network_send", "process_exec", "file_write"} and str(chain.get("review_priority") or "") != "low" else "medium"
        relevance = _static_chain_obligation_relevance(chain, static_payload)
        obligations.append(
            RuntimeObligation(
                obligation_id=f"OBL-{len(obligations) + 1:04d}",
                origin="static_path",
                static_ids=[chain_id],
                expected_runtime_operation=expected,
                static_path_id=chain_id or "aggregate-static-actions",
                origin_static_ids=[chain_id] if chain_id else [],
                expected_entity_keys=[str(chain.get("source_entity") or ""), str(chain.get("sink_entity") or "")],
                status="satisfied" if matches else "unsatisfied",
                supporting_runtime_ids=[str(event.get("event_id")) for event in matches],
                reason="static risk path target operation reached" if matches else "static risk path target operation not observed",
                obligation_type=_obligation_type_for_expected(expected),
                path_role=_path_role_for_expected(expected),
                relevance=relevance,
                risk_relevance=risk,
                required_for_path_completion=relevance == "decisive" and risk in {"high", "critical"},
                required_for_risk_closure=relevance == "decisive" and risk in {"high", "critical"},
                blocking_condition=None if matches else "static_path_target_missing",
            )
        )
    if not obligations:
        obligations.append(
            RuntimeObligation(
                obligation_id="OBL-0001",
                origin="trigger_plan",
                static_ids=[],
                expected_runtime_operation="skill_activation",
                static_path_id="runtime-only",
                origin_static_ids=[],
                status="satisfied" if runtime_events else "unsatisfied",
                supporting_runtime_ids=[event.get("event_id", "") for event in runtime_events[:1]],
                reason="runtime-only analysis" if runtime_events else "no static or runtime evidence",
                obligation_type="execution_started",
                path_role="execution",
                relevance="supporting",
                risk_relevance="low",
                required_for_path_completion=False,
                required_for_risk_closure=False,
                required_for_execution_completion=True,
            )
        )
    return obligations


def _coverage_state_from_obligations(
    obligations: list[RuntimeObligation],
    runtime_events: list[dict[str, Any]],
    runtime_chains: list[dict[str, Any]],
    gaps: list[str],
    dynamic_state: str,
    execution: Any | None,
    sensitive_artifacts: list[dict[str, Any]] | None = None,
    path_completion: list[PathCompletionResult] | None = None,
) -> str:
    if execution is not None and getattr(execution, "timed_out", False):
        return "timeout"
    if dynamic_state in {"timeout", "max_steps_exhausted", "execution_failed", "environment_missing", "unsupported_operation", "source_unavailable", "sink_unavailable"}:
        return dynamic_state
    if gaps or any(item.status == "unverifiable" for item in obligations):
        return "instrumentation_gap"
    if not runtime_events:
        return "path_not_triggered"
    if any(chain.get("chain_type") == "confidentiality_candidate" for chain in runtime_chains):
        return "insufficient_coverage"
    if any(item.status in {"unsatisfied", "unresolved", "unverifiable"} and item.required_for_path_completion and item.risk_relevance in {"high", "critical"} for item in obligations):
        return "path_incomplete"
    if any(item.get("status") == "review" for item in sensitive_artifacts or []):
        return "path_incomplete"
    if path_completion and any(item.status in {"partial", "unresolved"} for item in path_completion):
        return "path_incomplete"
    if dynamic_state == "runtime_confirmed" or any(chain.get("chain_type", "").endswith("_confirmed") for chain in runtime_chains):
        return "complete" if not gaps else "instrumentation_gap"
    if execution is not None and getattr(execution, "exit_code", 0) not in (0, None):
        return "execution_failed"
    if _strict_target_reached_no_flow(obligations, runtime_events, runtime_chains):
        return "target_reached_no_flow"
    if any(item.status == "unsatisfied" for item in obligations):
        return "path_not_triggered"
    return dynamic_state or "insufficient_coverage"


def _strict_target_reached_no_flow(
    obligations: list[RuntimeObligation],
    runtime_events: list[dict[str, Any]],
    runtime_chains: list[dict[str, Any]],
) -> bool:
    if any(chain.get("chain_type") in {"confidentiality_confirmed", "confidentiality_candidate"} for chain in runtime_chains):
        return False
    if _tls_payload_gap(runtime_events):
        return False
    action_reached = any(item.status == "satisfied" and item.expected_runtime_operation in {"file_read", "network_send", "network_connect", "process_exec", "tool_invoke"} for item in obligations)
    source_ok = all(item.status in {"satisfied", "not_applicable"} for item in obligations if item.expected_runtime_operation in {"source_available", "source_read", "file_read"})
    sink_ok = all(item.status in {"satisfied", "not_applicable"} for item in obligations if item.expected_runtime_operation in {"sink_available", "request_attempted", "network_send", "network_connect", "payload_observable"})
    carriers_observable = all(str(event.get("instrumentation_visibility") or "observed") in {"observed", "payload_preview_observed", "endpoint_only"} for event in runtime_events)
    return action_reached and source_ok and sink_ok and carriers_observable


def _build_policy_findings(
    static_payload: dict[str, Any],
    dynamic_payload: dict[str, Any],
    runtime_chains: list[dict[str, Any]],
    contradictions: list[UnifiedContradiction],
    coverage: CoverageCertificate,
) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    for chain in static_payload.get("static_chains", []) or []:
        alert = str(chain.get("alert_status") or chain.get("policy_status") or "capability_only")
        status = "capability" if alert in {"capability_only", "allowed"} else "review"
        findings.append(
            PolicyFinding(
                finding_id=f"PF-{len(findings) + 1:04d}",
                origin="static",
                policy_domain=_policy_domain(chain),
                status=status,
                evidence_status="instruction_supported",
                supporting_ids=[str(chain.get("chain_id") or "")],
                reason=str(chain.get("explanation") or chain.get("policy_status") or "static instruction finding"),
            )
        )
    for violation in dynamic_payload.get("policy_violations", dynamic_payload.get("runtime_policy_violations", [])) or []:
        findings.append(
            PolicyFinding(
                finding_id=f"PF-{len(findings) + 1:04d}",
                origin="runtime",
                policy_domain=str(violation.get("policy_type") or "confidentiality"),
                status="violation",
                evidence_status="runtime_confirmed",
                supporting_ids=[str(violation.get("violation_id") or violation.get("chain_id") or "")],
                reason=str(violation.get("reason") or "runtime policy violation"),
            )
        )
    for chain in runtime_chains:
        if str(chain.get("chain_type")) == "confidentiality_candidate":
            findings.append(
                PolicyFinding(
                    finding_id=f"PF-{len(findings) + 1:04d}",
                    origin="runtime",
                    policy_domain="confidentiality",
                    status="review",
                    evidence_status="insufficient",
                    supporting_ids=[str(chain.get("chain_id") or "")],
                    reason="candidate runtime flow requires review and is not benign",
                )
            )
    for contradiction in contradictions:
        findings.append(
            PolicyFinding(
                finding_id=f"PF-{len(findings) + 1:04d}",
                origin="reconciliation",
                policy_domain="confidentiality" if "endpoint" in contradiction.contradiction_type or "auth" in contradiction.contradiction_type else "integrity",
                status="review",
                evidence_status="contradicted",
                supporting_ids=list(contradiction.static_claim.get("ids", [])) + list(contradiction.runtime_observation.get("ids", [])),
                reason=contradiction.reason,
            )
        )
    for artifact in coverage.sensitive_artifacts:
        if artifact.get("status") not in {"review", "violation"}:
            continue
        findings.append(
            PolicyFinding(
                finding_id=f"PF-{len(findings) + 1:04d}",
                origin="runtime",
                policy_domain="confidentiality",
                status=str(artifact.get("status")),
                evidence_status="runtime_confirmed",
                supporting_ids=[str(item) for item in artifact.get("supporting_ids", [])],
                reason=str(artifact.get("reason") or "sensitive tainted artifact requires review"),
            )
        )
    if coverage.coverage_state in {
        "instrumentation_gap",
        "insufficient_coverage",
        "path_not_triggered",
        "execution_failed",
        "timeout",
        "max_steps_exhausted",
        "path_incomplete",
        "partially_complete",
        "sink_unavailable",
        "environment_missing",
        "missing_required_command",
        "mock_service_unavailable",
    }:
        findings.append(
            PolicyFinding(
                finding_id=f"PF-{len(findings) + 1:04d}",
                origin="reconciliation",
                policy_domain="confidentiality",
                status="review",
                evidence_status="insufficient",
                supporting_ids=[],
                reason=f"coverage state is {coverage.coverage_state}",
            )
        )
    return findings


def _canonical_assessment(
    dynamic_result: Any | None,
    static_payload: dict[str, Any],
    dynamic_payload: dict[str, Any],
    findings: list[PolicyFinding],
    coverage: CoverageCertificate,
    *,
    analysis_mode: str = "full_system",
) -> dict[str, Any]:
    risk_status = coverage.risk_chain_status.status
    execution_status = coverage.execution_completion.status
    primary_status = coverage.primary_static_path_status
    security_status = coverage.security_resolution.status
    if dynamic_result is not None:
        assessment = assess_dynamic_result(dynamic_result).to_dict()
    else:
        assessment = dict(dynamic_payload.get("canonical_assessment") or {})
    if not assessment:
        review_findings = [item for item in findings if item.status in {"review", "violation"}]
        status = "review_required" if review_findings else "no_violation_observed"
        assessment = {
            "status": status,
            "canonical_final_decision": "needs_review" if review_findings else "benign",
            "canonical_risk_score": 30 if review_findings else 0,
            "needs_review": bool(review_findings),
            "reason_codes": ["static_instruction_supported_review"] if review_findings else [],
        }
    if risk_status == "confirmed_violation" or any(item.status == "violation" and item.evidence_status == "runtime_confirmed" for item in findings):
        assessment.update({"status": "violation_confirmed", "canonical_final_decision": "malicious", "canonical_risk_score": max(80, int(assessment.get("canonical_risk_score", 0) or 0)), "needs_review": False})
    elif risk_status in {"candidate_violation", "candidate_flow"}:
        assessment.update({"status": "review_required", "canonical_final_decision": "needs_review", "canonical_risk_score": max(30, int(assessment.get("canonical_risk_score", 0) or 0)), "needs_review": True})
    elif security_status in {"resolved_allowed", "resolved_no_flow"}:
        assessment.update({"status": "no_violation_observed", "canonical_final_decision": "benign", "canonical_risk_score": min(assessment.get("canonical_risk_score", 0) or 0, 10), "needs_review": False})
    elif security_status.startswith("unresolved_"):
        assessment.update({"status": "review_required", "canonical_final_decision": "needs_review", "canonical_risk_score": max(30, int(assessment.get("canonical_risk_score", 0) or 0)), "needs_review": True})
    elif _has_unresolved_decisive_obligation(coverage):
        assessment.update({"status": "review_required", "canonical_final_decision": "needs_review", "canonical_risk_score": max(30, int(assessment.get("canonical_risk_score", 0) or 0)), "needs_review": True})
    elif risk_status == "confirmed_allowed" and primary_status in {"partial", "unresolved"}:
        assessment.update({"status": "review_required", "canonical_final_decision": "needs_review", "canonical_risk_score": max(30, int(assessment.get("canonical_risk_score", 0) or 0)), "needs_review": True})
    elif execution_status in {"timeout", "llm_request_timeout", "max_steps_exhausted", "provider_failure", "unknown"} and primary_status in {"partial", "unresolved", "not_applicable"} and assessment.get("status") == "no_violation_observed":
        assessment.update({"status": "review_required", "canonical_final_decision": "needs_review", "canonical_risk_score": max(30, int(assessment.get("canonical_risk_score", 0) or 0)), "needs_review": True})
    elif any(item.status == "review" for item in findings) and assessment.get("status") == "no_violation_observed" and _review_finding_is_security_relevant(findings):
        assessment.update({"status": "review_required", "canonical_final_decision": "needs_review", "canonical_risk_score": max(30, int(assessment.get("canonical_risk_score", 0) or 0)), "needs_review": True})
    elif coverage.coverage_state in {
        "instrumentation_gap",
        "insufficient_coverage",
        "path_not_triggered",
        "execution_failed",
        "timeout",
        "max_steps_exhausted",
        "path_incomplete",
        "partially_complete",
        "sink_unavailable",
        "environment_missing",
        "missing_required_command",
        "mock_service_unavailable",
    } and assessment.get("status") == "no_violation_observed":
        assessment.update({"status": "review_required", "canonical_final_decision": "needs_review", "canonical_risk_score": max(30, int(assessment.get("canonical_risk_score", 0) or 0)), "needs_review": True})
    elif (
        assessment.get("status") == "no_violation_observed"
        and (
            coverage.obligation_summary.get("high_risk_unresolved", 0)
            or any(item.get("status") == "review" for item in coverage.sensitive_artifacts)
            or coverage.path_completion_status in {"partial", "unresolved"}
        )
    ):
        assessment.update({"status": "review_required", "canonical_final_decision": "needs_review", "canonical_risk_score": max(30, int(assessment.get("canonical_risk_score", 0) or 0)), "needs_review": True})
    assessment["coverage_state"] = coverage.coverage_state
    assessment["risk_chain_status"] = risk_status
    assessment["execution_completion_status"] = execution_status
    assessment["primary_static_path_status"] = primary_status
    assessment["primary_static_path_id"] = coverage.primary_static_path_id
    assessment["security_resolution_status"] = security_status
    assessment["termination_after_security_resolution"] = coverage.security_resolution.termination_after_resolution
    assessment["assessment_version"] = ASSESSMENT_VERSION
    return apply_review_lean(
        assessment,
        runtime_chains=_runtime_chains(dynamic_result, dynamic_payload),
        runtime_events=_runtime_events(dynamic_result, dynamic_payload),
        policy_findings=[item.to_dict() if hasattr(item, "to_dict") else item for item in findings],
        coverage_certificate=coverage.to_dict(),
        dynamic_payload=dynamic_payload,
        static_payload=static_payload,
        analysis_mode=analysis_mode,
    )


def _has_unresolved_decisive_obligation(coverage: CoverageCertificate) -> bool:
    if coverage.risk_chain_status.status == "confirmed_violation":
        return False
    if coverage.security_resolution.status in {"resolved_allowed", "resolved_no_flow"}:
        return False
    for result in coverage.static_path_results:
        if result.status in {"partial", "unresolved"} and result.unresolved_obligation_ids:
            return True
    return False


def _review_finding_is_security_relevant(findings: list[PolicyFinding]) -> bool:
    for item in findings:
        if item.status != "review":
            continue
        if item.evidence_status in {"contradicted", "insufficient"}:
            return True
        if item.policy_domain in {"confidentiality", "integrity", "execution", "persistence", "permission"}:
            return True
    return False


def _static_claims(static_payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    claims = {key: [] for key in ("local_only", "endpoints", "auth_only", "artifact_identity", "confirmation_required", "temporary_only", "read_scope", "tools", "no_external_side_effect")}
    for unit in static_payload.get("static_semantic_units", []) or []:
        text = _unit_text(unit)
        sid = str(unit.get("unit_id") or unit.get("semantic_unit_id") or unit.get("id") or "")
        _claim_from_text(claims, sid, text, unit)
    for action in static_payload.get("extracted_actions", []) or []:
        sid = _static_id(action, "action")
        text = _action_text(action)
        _claim_from_text(claims, sid, text, action)
        if str(action.get("action_type", "")).upper() in {"SEND", "UPLOAD", "INVOKE_API"}:
            for key in _action_keys(action):
                if "." in key or key.startswith("http"):
                    claims["endpoints"].append({"id": sid, "key": key, "evidence": action})
        if str(action.get("action_type", "")).upper() == "READ":
            for key in _action_keys(action):
                if "/" in key or key.startswith("~"):
                    claims["read_scope"].append({"id": sid, "key": _norm_path(key), "evidence": action})
        for key in action.get("tool_mentions", []) or []:
            claims["tools"].append({"id": sid, "key": str(key), "evidence": action})
    for entity in static_payload.get("resolved_entities", []) or []:
        sid = _static_id(entity, "entity")
        kind = _entity_kind(entity)
        for key in _entity_keys(entity):
            if kind == "endpoint":
                claims["endpoints"].append({"id": sid, "key": key, "evidence": entity})
            if kind in {"file", "artifact"}:
                claims["artifact_identity"].append({"id": sid, "key": key, "evidence": entity})
    return {key: _dedupe_claims(value) for key, value in claims.items()}


def _claim_from_text(claims: dict[str, list[dict[str, Any]]], sid: str, text: str, evidence: dict[str, Any]) -> None:
    low = text.lower()
    if re.search(r"\b(local[- ]only|offline only|no network|without network|never connect|do not connect)\b", low):
        claims["local_only"].append({"id": sid, "key": "local_only", "evidence": evidence})
    if re.search(r"\b(no external side effects?|no outbound|no uploads?|will not upload|never send)\b", low):
        claims["no_external_side_effect"].append({"id": sid, "key": "no_external_side_effect", "evidence": evidence})
    if "authorization" in low or "bearer" in low or "authenticate" in low or "oauth" in low:
        claims["auth_only"].append({"id": sid, "key": "authentication", "evidence": evidence})
    if "confirm" in low or "approval" in low or "permission" in low:
        claims["confirmation_required"].append({"id": sid, "key": "confirmation_required", "evidence": evidence})
    if "temporary" in low or "temp file" in low or "delete after" in low:
        claims["temporary_only"].append({"id": sid, "key": "temporary", "evidence": evidence})
    for url in re.findall(r"https?://[^\s'\"<>]+", text):
        claims["endpoints"].append({"id": sid, "key": url.rstrip(".,)"), "evidence": evidence})
    for path in re.findall(r"(?:~|/|\.)[\w./-]+", text):
        if path:
            claims["read_scope"].append({"id": sid, "key": _norm_path(path), "evidence": evidence})
    for command in re.findall(r"\b(?:curl|wget|python3?|bash|sh|node|npm|pip)\b", low):
        claims["tools"].append({"id": sid, "key": command, "evidence": evidence})


def _contradiction(
    ctype: str,
    severity: str,
    static_claims: list[dict[str, Any]],
    runtime_observations: list[dict[str, Any]],
    reason: str,
    confidence: float,
    limitations: list[str] | None = None,
) -> UnifiedContradiction:
    return UnifiedContradiction(
        contradiction_type=ctype,
        severity=severity,
        static_claim={
            "ids": [str(item.get("id")) for item in static_claims if item.get("id")],
            "evidence_span": [{"key": item.get("key"), "source": item.get("evidence", {}).get("source_artifact_id") or item.get("evidence", {}).get("artifact_id")} for item in static_claims],
        },
        runtime_observation={
            "ids": [str(item.get("event_id") or item.get("chain_id") or item.get("edge_id") or "") for item in runtime_observations],
            "raw_references": [str(item.get("raw_reference") or "") for item in runtime_observations if item.get("raw_reference")],
        },
        reason=reason,
        confidence=confidence,
        limitations=list(limitations or []),
    )


def _instruction_only_paths(static_payload: dict[str, Any], aligned_static_ids: set[str]) -> list[dict[str, Any]]:
    paths = []
    for chain in static_payload.get("static_chains", []) or []:
        cid = str(chain.get("chain_id") or "")
        if cid and cid not in aligned_static_ids:
            paths.append({"static_ids": [cid], "chain_type": chain.get("chain_type"), "status": chain.get("status"), "reason": "static path has no aligned runtime chain"})
    return paths


def _runtime_only_paths(
    runtime_chains: list[dict[str, Any]],
    runtime_events: list[dict[str, Any]],
    aligned_runtime_ids: set[str],
    internal_runtime_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    internal_runtime_ids = internal_runtime_ids or set()
    paths = []
    for chain in runtime_chains:
        cid = str(chain.get("chain_id") or "")
        if cid and cid not in aligned_runtime_ids and cid not in internal_runtime_ids:
            paths.append({"runtime_ids": [cid], "chain_type": chain.get("chain_type"), "evidence_level": chain.get("evidence_level"), "reason": "runtime chain has no aligned static path"})
    if not paths:
        for event in runtime_events:
            eid = str(event.get("event_id") or "")
            if eid and eid not in aligned_runtime_ids and eid not in internal_runtime_ids and event.get("object_type") == "network":
                paths.append({"runtime_ids": [eid], "operation": event.get("operation"), "reason": "runtime network action has no aligned static declaration"})
    return paths


def _minimal_witnesses(static_payload: dict[str, Any], runtime_chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    witnesses = []
    for chain in runtime_chains:
        witnesses.append(
            {
                "witness_id": f"W-{len(witnesses) + 1:04d}",
                "source": "runtime",
                "supporting_ids": [chain.get("chain_id")] + list(chain.get("ordered_edges", []) or []) + list(chain.get("supporting_event_ids", []) or []),
                "confidence": chain.get("confidence", 0.0),
                "limitations": list(chain.get("instrumentation_gaps", []) or []),
            }
        )
    for chain in static_payload.get("static_chains", []) or []:
        if str(chain.get("alert_status")) in {"review", "violation"}:
            witnesses.append(
                {
                    "witness_id": f"W-{len(witnesses) + 1:04d}",
                    "source": "static",
                    "supporting_ids": [chain.get("chain_id")] + list(chain.get("ordered_edges", []) or []) + list(chain.get("evidence_unit_ids", []) or []),
                    "confidence": 0.7 if chain.get("status") == "closed" else 0.45,
                    "limitations": list(chain.get("limitations", []) or []),
                }
            )
    return witnesses


def _limitations(dynamic_payload: dict[str, Any], coverage: CoverageCertificate) -> list[str]:
    limits = []
    if coverage.coverage_state != "runtime_confirmed":
        limits.append(f"coverage_state={coverage.coverage_state}")
    for gap in coverage.instrumentation_gaps:
        limits.append(f"instrumentation_gap:{gap}")
    if not dynamic_payload:
        limits.append("no runtime execution was performed")
    return sorted(set(limits))


def _coverage_reasons(state: str, obligations: list[RuntimeObligation], gaps: list[str], dynamic_state: str, execution: Any | None) -> list[str]:
    reasons = [f"coverage certificate resolved state={state}"]
    if dynamic_state:
        reasons.append(f"dynamic_v3_state={dynamic_state}")
    if gaps:
        reasons.append("instrumentation gaps prevent no-flow certification")
    if any(item.status == "unsatisfied" for item in obligations):
        reasons.append("one or more runtime obligations were unsatisfied")
    if execution is not None and getattr(execution, "timed_out", False):
        reasons.append("execution timed out")
    return reasons


def _chain_evidence_summary(runtime_chains: list[dict[str, Any]]) -> dict[str, Any]:
    confirmed = [
        chain
        for chain in runtime_chains
        if str(chain.get("chain_type", "")).endswith("_confirmed")
        and str(chain.get("evidence_level") or "") in {"", "confirmed", "conservative"}
    ]
    candidates = [chain for chain in runtime_chains if "candidate" in str(chain.get("chain_type") or "")]
    simulated = [chain for chain in runtime_chains if str(chain.get("chain_type") or "") == "instruction_simulated"]
    strongest = "confirmed" if confirmed else "candidate" if candidates else "simulated" if simulated else "none"
    return {
        "strongest_evidence_status": strongest,
        "confirmed_chain_count": len(confirmed),
        "candidate_chain_count": len(candidates),
        "simulated_chain_count": len(simulated),
        "confirmed_chain_ids": [str(chain.get("chain_id") or "") for chain in confirmed],
        "candidate_chain_ids": [str(chain.get("chain_id") or "") for chain in candidates],
    }


def _risk_chain_status(dynamic_payload: dict[str, Any], runtime_chains: list[dict[str, Any]], runtime_events: list[dict[str, Any]]) -> RiskChainStatus:
    violations = list(dynamic_payload.get("policy_violations", dynamic_payload.get("runtime_policy_violations", [])) or [])
    violation_chain_ids = _dedupe_strings([str(item.get("chain_id") or "") for item in violations if item.get("chain_id")])
    confirmed = [chain for chain in runtime_chains if _is_confirmed_confidentiality_chain(chain)]
    candidates = [chain for chain in runtime_chains if "candidate" in str(chain.get("chain_type") or "")]
    if violation_chain_ids:
        return RiskChainStatus(
            status="confirmed_violation",
            confirmed_violation_chain_ids=violation_chain_ids,
            confirmed_allowed_chain_ids=[str(chain.get("chain_id") or "") for chain in confirmed if str(chain.get("chain_id") or "") not in set(violation_chain_ids)],
            candidate_chain_ids=[str(chain.get("chain_id") or "") for chain in candidates],
            decisive_chain_ids=violation_chain_ids,
            reason="runtime policy violation chain has concrete evidence",
        )
    if confirmed:
        confirmed_ids = [str(chain.get("chain_id") or "") for chain in confirmed if chain.get("chain_id")]
        return RiskChainStatus(
            status="confirmed_allowed",
            confirmed_allowed_chain_ids=confirmed_ids,
            decisive_chain_ids=confirmed_ids,
            reason="runtime confirmed sensitive flow but policy did not classify it as a violation",
        )
    if candidates:
        candidate_ids = [str(chain.get("chain_id") or "") for chain in candidates if chain.get("chain_id")]
        return RiskChainStatus(
            status="candidate_flow",
            candidate_chain_ids=candidate_ids,
            decisive_chain_ids=candidate_ids,
            reason="candidate runtime flow requires review",
        )
    if runtime_events and any(str(event.get("object_type") or "") in {"file", "network", "process"} for event in runtime_events):
        return RiskChainStatus(status="no_sensitive_flow_observed", reason="runtime executed observable operations without a sensitive flow chain")
    return RiskChainStatus(status="none", reason="no sufficient runtime chain evidence")


def _execution_completion(execution: Any | None, dynamic_state: str, runtime_events: list[dict[str, Any]], dynamic_payload: dict[str, Any]) -> ExecutionCompletion:
    termination = _termination_reason(execution, dynamic_state)
    status = _execution_completion_status(execution, dynamic_state, runtime_events, termination)
    timeout_resolution = dynamic_payload.get("timeout_resolution") or dynamic_payload.get("execution", {}).get("timeout_resolution") or {}
    return ExecutionCompletion(
        status=status,
        termination_reason=termination,
        agent_step_count=int(getattr(execution, "agent_step_count", 0) or 0),
        max_agent_steps=int(getattr(execution, "max_agent_steps", 0) or 0),
        total_timeout_seconds=timeout_resolution.get("total_timeout_seconds") if isinstance(timeout_resolution, dict) else None,
        llm_request_timeout_seconds=timeout_resolution.get("llm_request_timeout_seconds", 120) if isinstance(timeout_resolution, dict) else 120,
        provider_retry_count=int(getattr(execution, "provider_retry_count", 0) or 0),
        final_response_emitted=bool(getattr(execution, "final_response_emitted", False)),
        pending_tool_call=bool(getattr(execution, "pending_tool_call", None)),
        reason=_execution_completion_reason(status, termination),
    )


def _execution_completion_status(execution: Any | None, dynamic_state: str, runtime_events: list[dict[str, Any]], termination: str) -> str:
    if execution is not None and getattr(execution, "timed_out", False):
        return "timeout"
    if execution is not None and getattr(execution, "max_steps_exhausted", False):
        return "max_steps_exhausted"
    if termination == "llm_request_timeout" or any((event.get("metadata", {}) or {}).get("error_type") == "llm_request_timeout" for event in runtime_events):
        return "llm_request_timeout"
    if termination in {"environment_missing", "missing_required_command", "sink_unavailable"}:
        return termination
    if dynamic_state == "timeout":
        return "timeout"
    if dynamic_state == "max_steps_exhausted":
        return "max_steps_exhausted"
    if dynamic_state in {"runtime_confirmed", "target_reached_no_flow", "complete"}:
        return "complete"
    if dynamic_state in {"environment_missing", "missing_required_command", "execution_failed"}:
        return dynamic_state
    if termination == "process_exit":
        code = getattr(execution, "exit_code", 0) if execution is not None else 0
        return "complete" if code in (0, None) else "execution_failed"
    if termination in {"completed", ""}:
        return "complete"
    return termination or "unknown"


def _execution_completion_reason(status: str, termination: str) -> str:
    if status == "complete":
        return "agent execution completed normally"
    if status in {"timeout", "llm_request_timeout", "max_steps_exhausted"}:
        return f"execution incomplete due to {status}; confirmed risk-chain evidence remains valid"
    if status in {"environment_missing", "missing_required_command", "sink_unavailable", "execution_failed"}:
        return f"execution ended before all runtime work completed: {termination or status}"
    return "execution completion could not be fully determined"


def _security_resolution_status(
    *,
    obligations: list[RuntimeObligation],
    runtime_events: list[dict[str, Any]],
    runtime_chains: list[dict[str, Any]],
    risk_status: RiskChainStatus,
    execution_completion: ExecutionCompletion,
    static_path_results: list[StaticPathCompletion],
    primary_path_id: str,
    instrumentation_gaps: list[str],
) -> SecurityResolutionStatus:
    event_indexes = {str(event.get("event_id") or ""): index for index, event in enumerate(runtime_events) if event.get("event_id")}
    event_timestamps = {str(event.get("event_id") or ""): _float_or_none(event.get("timestamp")) for event in runtime_events if event.get("event_id")}
    termination_index = len(runtime_events) if execution_completion.status in {"timeout", "llm_request_timeout", "max_steps_exhausted", "provider_failure", "execution_failed", "unknown"} else (len(runtime_events) - 1 if runtime_events else None)
    termination_timestamp = _float_or_none(runtime_events[-1].get("timestamp")) if runtime_events else None
    support_ids = _security_supporting_event_ids(runtime_chains, obligations, risk_status)
    resolution_index = _max_event_index(support_ids, event_indexes)
    resolution_timestamp = _max_event_timestamp(support_ids, event_timestamps)
    supporting_gaps = [
        item.obligation_id
        for item in obligations
        if item.relevance == "supporting" and item.status in {"unsatisfied", "unresolved", "unverifiable"}
    ]
    auxiliary_gaps = [
        item.obligation_id
        for item in obligations
        if item.relevance == "auxiliary" and item.status in {"unsatisfied", "unresolved", "unverifiable"}
    ]
    security_decisive = [item for item in obligations if _is_security_decisive_obligation(item)]
    unresolved = [
        item
        for item in security_decisive
        if item.status in {"unsatisfied", "unresolved", "unverifiable"}
        and not _decisive_obligation_resolved_by_security_evidence(item, risk_status, execution_completion, runtime_chains)
    ]
    blocking_paths = _blocking_security_paths(static_path_results, primary_path_id, unresolved)
    termination_after = bool(
        resolution_index is not None
        and termination_index is not None
        and termination_index >= resolution_index
        and execution_completion.status in {"complete", "timeout", "llm_request_timeout", "max_steps_exhausted", "provider_failure", "execution_failed"}
    )
    if risk_status.status == "confirmed_violation":
        ids = risk_status.confirmed_violation_chain_ids
        resolution_index = _max_event_index(_chain_event_ids(runtime_chains, ids), event_indexes)
        resolution_timestamp = _max_event_timestamp(_chain_event_ids(runtime_chains, ids), event_timestamps)
        return SecurityResolutionStatus(
            status="resolved_violation",
            security_decisive_obligations_resolved=True,
            resolved_path_ids=[primary_path_id] if primary_path_id else [],
            resolution_event_index=resolution_index,
            resolution_timestamp=resolution_timestamp,
            termination_event_index=termination_index,
            termination_timestamp=termination_timestamp,
            termination_after_resolution=termination_after,
            non_blocking_supporting_gaps=supporting_gaps,
            non_blocking_auxiliary_gaps=auxiliary_gaps,
            reason="confirmed policy violation chain resolves the security verdict",
        )
    if risk_status.candidate_chain_ids:
        return SecurityResolutionStatus(
            status="unresolved_candidate_flow",
            security_decisive_obligations_resolved=False,
            unresolved_decisive_obligation_ids=[item.obligation_id for item in unresolved],
            blocking_security_paths=blocking_paths,
            non_blocking_supporting_gaps=supporting_gaps,
            non_blocking_auxiliary_gaps=auxiliary_gaps,
            termination_event_index=termination_index,
            termination_timestamp=termination_timestamp,
            unresolved_decisive_at_termination=[item.obligation_id for item in unresolved],
            reason="candidate runtime flow cannot be accepted as benign",
        )
    if instrumentation_gaps:
        return SecurityResolutionStatus(
            status="unresolved_instrumentation",
            security_decisive_obligations_resolved=False,
            unresolved_decisive_obligation_ids=[item.obligation_id for item in unresolved],
            blocking_instrumentation_gaps=list(instrumentation_gaps),
            blocking_security_paths=blocking_paths,
            non_blocking_supporting_gaps=supporting_gaps,
            non_blocking_auxiliary_gaps=auxiliary_gaps,
            termination_event_index=termination_index,
            termination_timestamp=termination_timestamp,
            unresolved_decisive_at_termination=[item.obligation_id for item in unresolved],
            reason="key runtime carrier or payload visibility is incomplete",
        )
    if unresolved:
        status = _unresolved_security_status(unresolved)
        return SecurityResolutionStatus(
            status=status,
            security_decisive_obligations_resolved=False,
            unresolved_decisive_obligation_ids=[item.obligation_id for item in unresolved],
            blocking_security_paths=blocking_paths,
            non_blocking_supporting_gaps=supporting_gaps,
            non_blocking_auxiliary_gaps=auxiliary_gaps,
            resolution_event_index=resolution_index,
            resolution_timestamp=resolution_timestamp,
            termination_event_index=termination_index,
            termination_timestamp=termination_timestamp,
            termination_after_resolution=False,
            unresolved_decisive_at_termination=[item.obligation_id for item in unresolved],
            reason="one or more security-decisive obligations remain unresolved",
        )
    if risk_status.status == "confirmed_allowed":
        return SecurityResolutionStatus(
            status="resolved_allowed",
            security_decisive_obligations_resolved=True,
            resolved_path_ids=_resolved_path_ids(static_path_results, primary_path_id),
            non_blocking_supporting_gaps=supporting_gaps,
            non_blocking_auxiliary_gaps=auxiliary_gaps,
            resolution_event_index=resolution_index,
            resolution_timestamp=resolution_timestamp,
            termination_event_index=termination_index,
            termination_timestamp=termination_timestamp,
            termination_after_resolution=termination_after,
            reason="confirmed flow is policy-allowed and all security-decisive obligations are resolved",
        )
    if risk_status.status == "no_sensitive_flow_observed":
        if resolution_index is None and runtime_events:
            resolution_index = len(runtime_events) - 1
            resolution_timestamp = _float_or_none(runtime_events[-1].get("timestamp"))
            termination_after = bool(termination_index is not None and termination_index >= resolution_index)
        return SecurityResolutionStatus(
            status="resolved_no_flow",
            security_decisive_obligations_resolved=True,
            resolved_path_ids=_resolved_path_ids(static_path_results, primary_path_id),
            non_blocking_supporting_gaps=supporting_gaps,
            non_blocking_auxiliary_gaps=auxiliary_gaps,
            resolution_event_index=resolution_index,
            resolution_timestamp=resolution_timestamp,
            termination_event_index=termination_index,
            termination_timestamp=termination_timestamp,
            termination_after_resolution=termination_after,
            reason="runtime reached observable operations with no confirmed or candidate sensitive flow",
        )
    return SecurityResolutionStatus(
        status="none",
        security_decisive_obligations_resolved=not unresolved,
        unresolved_decisive_obligation_ids=[item.obligation_id for item in unresolved],
        blocking_security_paths=blocking_paths,
        non_blocking_supporting_gaps=supporting_gaps,
        non_blocking_auxiliary_gaps=auxiliary_gaps,
        termination_event_index=termination_index,
        termination_timestamp=termination_timestamp,
        unresolved_decisive_at_termination=[item.obligation_id for item in unresolved],
        reason="no confirmed allowed, confirmed violation, candidate, or no-flow security resolution was available",
    )


def _is_security_decisive_obligation(obligation: RuntimeObligation) -> bool:
    if obligation.relevance != "decisive":
        return False
    if obligation.required_for_risk_closure:
        return True
    return obligation.path_role in {"source", "sink", "carrier", "guard", "persistence", "execution"}


def _decisive_obligation_resolved_by_security_evidence(
    obligation: RuntimeObligation,
    risk_status: RiskChainStatus,
    execution_completion: ExecutionCompletion,
    runtime_chains: list[dict[str, Any]],
) -> bool:
    if obligation.status in {"satisfied", "not_applicable"}:
        return True
    if obligation.expected_runtime_operation == "untrusted_sink_absence_resolved":
        return (
            risk_status.status == "confirmed_allowed"
            and execution_completion.status == "complete"
            and not _has_untrusted_confirmed_confidentiality_sink(runtime_chains)
            and obligation.blocking_condition == "trusted_llm_boundary_pending"
        )
    if obligation.path_role in {"persistence", "execution"} and obligation.status == "unsatisfied":
        return execution_completion.status == "complete" and not _has_runtime_effect_for_obligation(obligation, runtime_chains)
    return False


def _has_runtime_effect_for_obligation(obligation: RuntimeObligation, runtime_chains: list[dict[str, Any]]) -> bool:
    if obligation.path_role == "persistence":
        return any(str(chain.get("chain_type") or "") == "persistence_confirmed" for chain in runtime_chains)
    if obligation.path_role == "execution":
        return any(str(chain.get("chain_type") or "") in {"execution_confirmed", "integrity_confirmed"} for chain in runtime_chains)
    return False


def _unresolved_security_status(unresolved: list[RuntimeObligation]) -> str:
    roles = {item.path_role for item in unresolved}
    operations = {item.expected_runtime_operation for item in unresolved}
    if "source" in roles or "file_read" in operations:
        return "unresolved_before_source"
    if "guard" in roles:
        return "unresolved_before_guard"
    if roles & {"sink", "carrier"} or operations & {"network_send", "sink_reached", "payload_observable"}:
        return "unresolved_before_sink"
    return "unresolved_execution"


def _blocking_security_paths(static_path_results: list[StaticPathCompletion], primary_path_id: str, unresolved: list[RuntimeObligation]) -> list[str]:
    unresolved_ids = {item.obligation_id for item in unresolved}
    paths = []
    for result in static_path_results:
        if set(result.unresolved_obligation_ids) & unresolved_ids:
            paths.append(result.static_path_id)
    if primary_path_id and unresolved_ids and primary_path_id not in paths:
        paths.append(primary_path_id)
    return _dedupe_strings(paths)


def _resolved_path_ids(static_path_results: list[StaticPathCompletion], primary_path_id: str) -> list[str]:
    ids = [item.static_path_id for item in static_path_results if item.status in {"complete", "not_applicable", "not_triggered"}]
    if primary_path_id and primary_path_id not in ids:
        ids.append(primary_path_id)
    return _dedupe_strings(ids)


def _security_supporting_event_ids(runtime_chains: list[dict[str, Any]], obligations: list[RuntimeObligation], risk_status: RiskChainStatus) -> list[str]:
    ids = _chain_event_ids(runtime_chains, risk_status.decisive_chain_ids)
    for obligation in obligations:
        if obligation.status == "satisfied" and _is_security_decisive_obligation(obligation):
            ids.extend([str(item) for item in obligation.supporting_runtime_ids if item])
    return _dedupe_strings(ids)


def _chain_event_ids(runtime_chains: list[dict[str, Any]], chain_ids: list[str]) -> list[str]:
    wanted = set(chain_ids)
    ids: list[str] = []
    for chain in runtime_chains:
        if str(chain.get("chain_id") or "") not in wanted:
            continue
        ids.extend([str(item) for item in chain.get("supporting_event_ids", []) or [] if item])
        ids.extend([str(item) for item in chain.get("ordered_events", []) or [] if item])
    return _dedupe_strings(ids)


def _max_event_index(ids: list[str], event_indexes: dict[str, int]) -> int | None:
    values = [event_indexes[item] for item in ids if item in event_indexes]
    return max(values) if values else None


def _max_event_timestamp(ids: list[str], event_timestamps: dict[str, float | None]) -> float | None:
    values = [event_timestamps[item] for item in ids if event_timestamps.get(item) is not None]
    return max(values) if values else None


def _float_or_none(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _static_path_results(
    static_payload: dict[str, Any],
    obligations: list[RuntimeObligation],
    runtime_chains: list[dict[str, Any]],
    risk_status: RiskChainStatus,
    execution_completion: ExecutionCompletion,
) -> list[StaticPathCompletion]:
    path_ids = _static_path_ids(static_payload, obligations, runtime_chains)
    primary_candidate = _best_static_path_for_risk_chain(static_payload, obligations, runtime_chains, risk_status)
    results: list[StaticPathCompletion] = []
    violation_chain_ids = set(risk_status.confirmed_violation_chain_ids)
    for path_id in path_ids:
        path_obligations = [item for item in obligations if item.static_path_id == path_id]
        matched = _matched_runtime_chains_for_path(path_id, runtime_chains, risk_status, primary_candidate)
        decisive = [item for item in path_obligations if item.relevance == "decisive"]
        supporting = [item for item in path_obligations if item.relevance == "supporting"]
        auxiliary = [item for item in path_obligations if item.relevance == "auxiliary"]
        satisfied_ids = [item.obligation_id for item in path_obligations if item.status == "satisfied"]
        unresolved_ids = [
            item.obligation_id
            for item in decisive
            if item.status in {"unsatisfied", "unresolved", "unverifiable"}
            and not _decisive_obligation_resolved_by_security_evidence(item, risk_status, execution_completion, runtime_chains)
        ]
        all_decisive = [item.obligation_id for item in decisive]
        resolved_decisive = [
            item
            for item in decisive
            if item.status == "satisfied" or _decisive_obligation_resolved_by_security_evidence(item, risk_status, execution_completion, runtime_chains)
        ]
        completion_ratio = (len(resolved_decisive) / len(decisive)) if decisive else (1.0 if matched else 0.0)
        if violation_chain_ids and path_id == primary_candidate:
            status = "complete"
            reason = "primary static path is covered by a confirmed runtime policy-violation chain"
            unresolved_ids = []
            completion_ratio = 1.0
        elif matched and risk_status.status == "confirmed_allowed" and unresolved_ids:
            status = "partial"
            reason = "trusted/allowed runtime chain is observed, but decisive external-risk guard remains unresolved"
        elif matched:
            status = "complete" if not unresolved_ids else "partial"
            reason = "runtime chain matched this static path"
        elif unresolved_ids:
            status = "unresolved" if execution_completion.status in {"timeout", "llm_request_timeout", "max_steps_exhausted", "unknown"} else "partial"
            reason = "decisive path obligations were not fully covered by runtime evidence"
        elif decisive and len(resolved_decisive) == len(decisive):
            status = "complete"
            reason = "all decisive obligations for this path were satisfied"
        elif path_obligations:
            status = "complete" if satisfied_ids or matched else "not_triggered"
            reason = "only supporting or auxiliary obligations were present for this path"
        else:
            status = "not_applicable"
            reason = "no security-relevant path-local obligations"
        results.append(
            StaticPathCompletion(
                static_path_id=path_id,
                risk_relevance=_path_risk_relevance(static_payload, path_id, path_obligations),
                status=status,
                matched_runtime_chain_ids=matched,
                decisive_obligations=all_decisive,
                supporting_obligations=[item.obligation_id for item in supporting],
                auxiliary_obligations=[item.obligation_id for item in auxiliary],
                satisfied_obligation_ids=satisfied_ids,
                unresolved_obligation_ids=unresolved_ids,
                completion_ratio=round(completion_ratio, 3),
                reason=reason,
            )
        )
    return results


def _primary_risk_path_selection(static_path_results: list[StaticPathCompletion], risk_status: RiskChainStatus) -> dict[str, Any]:
    if not static_path_results:
        return {"primary_static_path_id": "", "selection_reason": "no_static_risk_path", "primary_static_path_status": "not_applicable"}
    if risk_status.confirmed_violation_chain_ids:
        matched = [item for item in static_path_results if set(item.matched_runtime_chain_ids) & set(risk_status.confirmed_violation_chain_ids)]
        if matched:
            chosen = matched[0]
            return {"primary_static_path_id": chosen.static_path_id, "selection_reason": "matched_confirmed_violation_chain", "primary_static_path_status": chosen.status}
    if risk_status.candidate_chain_ids:
        matched = [item for item in static_path_results if set(item.matched_runtime_chain_ids) & set(risk_status.candidate_chain_ids)]
        if matched:
            chosen = matched[0]
            return {"primary_static_path_id": chosen.static_path_id, "selection_reason": "matched_candidate_chain", "primary_static_path_status": chosen.status}
    ranked = sorted(static_path_results, key=lambda item: (_risk_rank(item.risk_relevance), item.completion_ratio), reverse=True)
    chosen = ranked[0]
    return {"primary_static_path_id": chosen.static_path_id, "selection_reason": "highest_risk_relevance", "primary_static_path_status": chosen.status}


def _other_static_path_summary(static_path_results: list[StaticPathCompletion], primary_path_id: str) -> dict[str, Any]:
    others = [item for item in static_path_results if item.static_path_id != primary_path_id]
    return {
        "total_other_paths": len(others),
        "complete_path_count": sum(1 for item in others if item.status == "complete"),
        "partial_path_count": sum(1 for item in others if item.status == "partial"),
        "unresolved_path_count": sum(1 for item in others if item.status == "unresolved"),
        "not_triggered_path_count": sum(1 for item in others if item.status == "not_triggered"),
        "not_applicable_path_count": sum(1 for item in others if item.status == "not_applicable"),
    }


def _path_completion_results(
    static_payload: dict[str, Any],
    obligations: list[RuntimeObligation],
    runtime_chains: list[dict[str, Any]],
    execution: Any | None,
    dynamic_state: str,
    static_path_results: list[StaticPathCompletion] | None = None,
) -> list[PathCompletionResult]:
    if static_path_results is not None:
        return [
            PathCompletionResult(
                static_path_id=item.static_path_id,
                status=item.status,
                satisfied_obligations=list(item.satisfied_obligation_ids),
                unsatisfied_obligations=[oid for oid in item.decisive_obligations + item.supporting_obligations + item.auxiliary_obligations if oid not in item.satisfied_obligation_ids and oid not in item.unresolved_obligation_ids],
                unresolved_obligations=list(item.unresolved_obligation_ids),
                observed_runtime_chains=list(item.matched_runtime_chain_ids),
                completion_ratio=item.completion_ratio,
                termination_effect=_termination_reason(execution, dynamic_state),
                reason=item.reason,
            )
            for item in static_path_results
        ]
    required = [item for item in obligations if item.required_for_path_completion and item.origin != "trigger_plan"]
    if not required:
        return []
    termination = _termination_reason(execution, dynamic_state)
    chain_ids = [str(chain.get("chain_id") or "") for chain in runtime_chains if chain.get("chain_id")]
    static_chains = static_payload.get("static_chains", []) or []
    path_ids = [str(chain.get("chain_id") or "") for chain in static_chains if chain.get("chain_id")] or ["aggregate-static-actions"]
    results: list[PathCompletionResult] = []
    for path_id in path_ids:
        if path_id == "aggregate-static-actions":
            path_obligations = required
        else:
            path_obligations = [item for item in required if path_id in item.static_ids or item.origin == "declared_action"] or required
        satisfied = [item.obligation_id for item in path_obligations if item.status == "satisfied"]
        unsatisfied = [item.obligation_id for item in path_obligations if item.status == "unsatisfied"]
        unresolved = [item.obligation_id for item in path_obligations if item.status in {"unresolved", "unverifiable"}]
        total = len(path_obligations)
        ratio = len(satisfied) / total if total else 1.0
        if termination in {"timeout", "max_steps_exhausted", "llm_request_timeout", "environment_missing", "sink_unavailable"} and (unsatisfied or unresolved):
            status = "unresolved"
            reason = f"execution ended with {termination} before required runtime obligations were completed"
        elif unresolved:
            status = "unresolved"
            reason = "one or more required runtime obligations are unverifiable"
        elif unsatisfied and satisfied:
            status = "partial"
            reason = "some required runtime obligations were observed, but the path did not complete"
        elif unsatisfied:
            status = "not_triggered"
            reason = "required runtime obligations were not observed"
        else:
            status = "complete"
            reason = "all required runtime obligations were observed"
        results.append(
            PathCompletionResult(
                static_path_id=path_id,
                status=status,
                satisfied_obligations=satisfied,
                unsatisfied_obligations=unsatisfied,
                unresolved_obligations=unresolved,
                observed_runtime_chains=chain_ids,
                completion_ratio=round(ratio, 3),
                termination_effect=termination,
                reason=reason,
            )
        )
    return results


def _overall_path_completion(
    path_completion: list[PathCompletionResult],
    obligations: list[RuntimeObligation],
    sensitive_artifacts: list[dict[str, Any]],
    state: str,
) -> str:
    if state in {"timeout", "max_steps_exhausted", "execution_failed", "instrumentation_gap"}:
        return "unresolved"
    if any(item.get("status") == "review" for item in sensitive_artifacts):
        return "partial"
    high_risk_unresolved = [
        item
        for item in obligations
        if item.required_for_path_completion
        and item.risk_relevance in {"high", "critical"}
        and item.status in {"unsatisfied", "unresolved", "unverifiable"}
    ]
    if high_risk_unresolved:
        return "unresolved" if any(item.status in {"unresolved", "unverifiable"} for item in high_risk_unresolved) else "partial"
    if path_completion:
        statuses = {item.status for item in path_completion}
        if "unresolved" in statuses:
            return "unresolved"
        if "partial" in statuses:
            return "partial"
        if statuses == {"complete"}:
            return "complete"
        if "not_triggered" in statuses:
            return "not_triggered"
    required = [item for item in obligations if item.required_for_path_completion and item.origin != "trigger_plan"]
    if required and all(item.status == "satisfied" for item in required):
        return "complete"
    if required:
        return "partial"
    return "not_applicable"


def _execution_status(execution: Any | None, dynamic_state: str) -> str:
    if execution is None:
        return "not_executed" if not dynamic_state else dynamic_state
    if getattr(execution, "timed_out", False):
        return "timeout"
    if getattr(execution, "max_steps_exhausted", False):
        return "max_steps_exhausted"
    reason = str(getattr(execution, "termination_reason", "") or "")
    if reason and reason != "completed":
        return reason
    code = getattr(execution, "exit_code", 0)
    return "completed" if code in (0, None) else "execution_failed"


def _termination_reason(execution: Any | None, dynamic_state: str) -> str:
    if execution is not None:
        if getattr(execution, "timed_out", False):
            return "timeout"
        if getattr(execution, "max_steps_exhausted", False):
            return "max_steps_exhausted"
        reason = str(getattr(execution, "termination_reason", "") or "")
        if reason:
            return reason
        code = getattr(execution, "exit_code", 0)
        if code not in (0, None):
            return "process_exit"
    return dynamic_state or "unknown"


def _environment_gaps(state: str, dynamic_state: str) -> list[str]:
    gaps = []
    if state in {"environment_missing", "missing_required_command", "mock_service_unavailable", "sink_unavailable"}:
        gaps.append(state)
    if dynamic_state and dynamic_state != state and dynamic_state in {"environment_missing", "missing_required_command", "mock_service_unavailable", "sink_unavailable"}:
        gaps.append(dynamic_state)
    return sorted(set(gaps))


def _sensitive_artifact_findings(runtime_events: list[dict[str, Any]], execution: Any | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    deleted_paths = _deleted_paths(runtime_events, execution)
    for event in runtime_events:
        if event.get("operation") != "write" or event.get("object_type") != "file":
            continue
        taint_ids = [str(item) for item in event.get("taint_ids", []) or [] if item]
        if not taint_ids:
            continue
        path = str(event.get("object_path") or event.get("object_id", "").replace("FILE:", ""))
        if not path:
            continue
        lifecycle = "deleted" if path in deleted_paths else "retained"
        location_class = _artifact_location_class(path)
        status = "allowed" if lifecycle == "deleted" and location_class == "isolated_workspace" else "review"
        reason = (
            "tainted intermediate artifact was removed before completion"
            if status == "allowed"
            else "tainted sensitive data was materialized into a local artifact without a completed approved sink path"
        )
        findings.append(
            {
                "finding_type": "sensitive_tainted_artifact",
                "source_ids": taint_ids,
                "artifact_path": path,
                "sensitivity": _event_sensitivity(event),
                "location_class": location_class,
                "permissions": "unknown",
                "lifecycle": lifecycle,
                "declared_by_static": "unknown",
                "used_by_later_action": "unknown",
                "status": status,
                "supporting_ids": [str(event.get("event_id") or "")],
                "reason": reason,
            }
        )
    return findings


def _deleted_paths(runtime_events: list[dict[str, Any]], execution: Any | None) -> set[str]:
    deleted: set[str] = set()
    for event in runtime_events:
        operation = str(event.get("operation") or event.get("event_type") or "")
        if operation in {"delete", "unlink", "remove", "rename"}:
            path = str(event.get("object_path") or event.get("object_id", "").replace("FILE:", ""))
            if path:
                deleted.add(path)
    if execution is not None:
        for mutation in getattr(execution, "fixture_mutations", []) or []:
            action = str(mutation.get("action") or mutation.get("mutation_type") or "")
            path = str(mutation.get("path") or mutation.get("relative_path") or "")
            if action in {"delete", "deleted", "removed", "unlink"} and path:
                deleted.add(path)
                deleted.add(f"/workspace/skill/{path.lstrip('/')}")
    return deleted


def _artifact_location_class(path: str) -> str:
    normalized = _norm_path(path)
    if normalized.startswith("/workspace/skill/") or not normalized.startswith("/"):
        return "isolated_workspace"
    if normalized.startswith("/tmp/") or normalized.startswith("/var/tmp/"):
        return "temporary"
    if normalized.startswith("/root/") or normalized.startswith("/home/"):
        return "user_home"
    if normalized.startswith("/etc/") or normalized.startswith("/usr/") or normalized.startswith("/bin/"):
        return "system"
    return "shared_or_unknown"


def _event_sensitivity(event: dict[str, Any]) -> str:
    meta = event.get("metadata", {}) or {}
    for key in ("source_sensitivity", "sensitivity"):
        if meta.get(key):
            return str(meta[key])
    return "high"


def _static_path_ids(static_payload: dict[str, Any], obligations: list[RuntimeObligation], runtime_chains: list[dict[str, Any]]) -> list[str]:
    ids = [str(chain.get("chain_id") or "") for chain in static_payload.get("static_chains", []) or [] if chain.get("chain_id")]
    ids.extend([item.static_path_id for item in obligations if item.static_path_id and item.static_path_id not in {"execution", "runtime-only"}])
    if not ids and runtime_chains:
        ids.extend([f"runtime-chain:{chain.get('chain_id')}" for chain in runtime_chains if chain.get("chain_id")])
    if not ids:
        ids.append("aggregate-static-actions")
    return _dedupe_strings([item for item in ids if item])


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _static_path_id_for_action(action_id: str, static_chains: list[dict[str, Any]]) -> str:
    for chain in static_chains:
        nodes = {str(item) for item in chain.get("ordered_nodes", []) or []}
        if action_id in nodes and chain.get("chain_id"):
            return str(chain["chain_id"])
    return "aggregate-static-actions"


def _best_static_path_for_risk_chain(
    static_payload: dict[str, Any],
    obligations: list[RuntimeObligation],
    runtime_chains: list[dict[str, Any]],
    risk_status: RiskChainStatus,
) -> str:
    target_chain_ids = set(risk_status.confirmed_violation_chain_ids or risk_status.candidate_chain_ids or risk_status.confirmed_allowed_chain_ids)
    if not target_chain_ids:
        return ""
    path_scores: dict[str, float] = {}
    for obligation in obligations:
        if not obligation.static_path_id or obligation.static_path_id == "execution":
            continue
        score = 0.0
        if obligation.relevance == "decisive":
            score += 2.0
        if obligation.status == "satisfied":
            score += 1.0
        if obligation.expected_runtime_operation in {"network_send", "sink_reached", "payload_observable", "untrusted_sink_absence_resolved"}:
            score += 1.0
        path_scores[obligation.static_path_id] = path_scores.get(obligation.static_path_id, 0.0) + score
    for chain in static_payload.get("static_chains", []) or []:
        cid = str(chain.get("chain_id") or "")
        if cid:
            path_scores.setdefault(cid, 0.0)
            path_scores[cid] += _risk_rank(_chain_risk_relevance(chain))
    if not path_scores:
        first_chain = next(iter(target_chain_ids), "")
        return f"runtime-chain:{first_chain}" if first_chain else ""
    return sorted(path_scores.items(), key=lambda item: (item[1], item[0]), reverse=True)[0][0]


def _matched_runtime_chains_for_path(
    path_id: str,
    runtime_chains: list[dict[str, Any]],
    risk_status: RiskChainStatus,
    primary_candidate: str,
) -> list[str]:
    decisive = set(risk_status.decisive_chain_ids)
    if path_id == primary_candidate:
        return [str(chain.get("chain_id") or "") for chain in runtime_chains if str(chain.get("chain_id") or "") in decisive]
    return []


def _path_risk_relevance(static_payload: dict[str, Any], path_id: str, obligations: list[RuntimeObligation]) -> str:
    for chain in static_payload.get("static_chains", []) or []:
        if str(chain.get("chain_id") or "") == path_id:
            return _chain_risk_relevance(chain)
    if any(item.risk_relevance == "critical" for item in obligations):
        return "critical"
    if any(item.risk_relevance == "high" for item in obligations):
        return "high"
    if any(item.risk_relevance == "medium" for item in obligations):
        return "medium"
    return "low"


def _chain_risk_relevance(chain: dict[str, Any]) -> str:
    priority = str(chain.get("review_priority") or "").lower()
    alert = str(chain.get("alert_status") or chain.get("policy_status") or "").lower()
    if alert == "violation":
        return "critical"
    if priority in {"critical", "high", "medium", "low"}:
        return priority
    if alert == "review":
        return "high"
    return "low"


def _static_chain_obligation_relevance(chain: dict[str, Any], static_payload: dict[str, Any]) -> str:
    alert = str(chain.get("alert_status") or chain.get("policy_status") or "").lower()
    if alert in {"capability_only", "allowed", "expected_declared_behavior"}:
        return "supporting"
    actions = {str(action.get("action_id") or action.get("id") or ""): action for action in static_payload.get("extracted_actions", []) or []}
    node_actions = [actions[node] for node in (str(item) for item in chain.get("ordered_nodes", []) or []) if node in actions]
    if node_actions and all(_action_semantic_class(action) in {"optional", "descriptive", "quoted_untrusted", "capability_boundary"} for action in node_actions):
        return "supporting"
    if node_actions and all(str(action.get("modality") or "").lower() == "conditional" for action in node_actions):
        return "supporting"
    return "decisive"


def _risk_rank(risk: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(risk or "").lower(), 0)


def _obligation_role_and_relevance(action: dict[str, Any], expected: str) -> tuple[str, str]:
    atype = str(action.get("action_type") or action.get("type") or "").upper()
    semantic_class = _action_semantic_class(action)
    if semantic_class in {"optional", "descriptive", "quoted_untrusted"}:
        return "auxiliary", "auxiliary"
    if semantic_class == "capability_boundary":
        return "auxiliary", "supporting"
    if expected in {"network_send", "sink_reached"}:
        return "sink", "decisive"
    if expected == "payload_observable":
        return "carrier", "decisive"
    if expected == "file_read" and atype in {"READ", "ACCESS_CREDENTIAL"}:
        return "source", "decisive" if semantic_class in {"mandatory_security", "guard"} else "supporting"
    if expected == "process_exec" and atype in {"EXECUTE", "RUN_COMMAND"}:
        return "execution", "supporting"
    if expected == "file_write":
        if atype == "PERSIST":
            return "persistence", "decisive"
        return "artifact", "auxiliary" if semantic_class in {"mandatory_business", "auxiliary"} else "supporting"
    return "auxiliary", "auxiliary"


def _path_role_for_expected(expected: str) -> str:
    return {
        "file_read": "source",
        "file_write": "artifact",
        "process_exec": "execution",
        "network_send": "sink",
        "sink_reached": "sink",
        "payload_observable": "carrier",
        "tool_invoke": "auxiliary",
    }.get(expected, "auxiliary")


def _action_semantic_class(action: dict[str, Any]) -> str:
    modality = str(action.get("modality") or "").lower()
    atype = str(action.get("action_type") or action.get("type") or "").upper()
    text = _action_text(action).lower()
    if modality == "prohibited":
        return "prohibited"
    if modality in {"optional", "example_only", "hypothetical"}:
        return "optional"
    if modality in {"quoted_untrusted"}:
        return "quoted_untrusted"
    if modality == "descriptive":
        return "descriptive"
    if modality == "conditional":
        return "conditional"
    stripped = text.strip()
    if stripped.startswith("name:") or stripped.startswith("description:") or stripped.startswith("# "):
        return "descriptive"
    if (
        any(token in text for token in ("permits only", "may use", "may only use", "outside scope", "inside sandbox", "sandbox files", "synthetic files", "localhost mock"))
        and any(token in text for token in ("sandbox", "synthetic", "localhost", "outside scope", "reference is tested documentation"))
    ):
        return "capability_boundary"
    if any(token in text for token in ("activity", "log", "report", "receipt", "note", "documentation", "closeout")) and atype in {"WRITE", "DELETE"}:
        return "auxiliary"
    if atype in {"SEND", "UPLOAD", "INVOKE_API", "ACCESS_CREDENTIAL", "PERSIST"}:
        return "mandatory_security"
    if atype in {"READ"} and any(token in text for token in ("secret", "credential", "protected", "restricted", "private", "token", "key", "current record")):
        return "mandatory_security"
    return "mandatory_business"


def _action_creates_required_obligation(action: dict[str, Any]) -> bool:
    modality = str(action.get("modality") or "").lower()
    semantic_class = _action_semantic_class(action)
    if modality in {"optional", "example_only", "prohibited", "hypothetical", "quoted_untrusted", "descriptive"}:
        return False
    if semantic_class in {"optional", "descriptive", "quoted_untrusted", "capability_boundary"}:
        return False
    if modality == "conditional" and not _condition_currently_required(action):
        return False
    return True


def _action_creates_guard_obligation(action: dict[str, Any], runtime_chains: list[dict[str, Any]]) -> bool:
    modality = str(action.get("modality") or "").lower()
    atype = str(action.get("action_type") or action.get("type") or "").upper()
    if modality != "prohibited" or atype not in {"SEND", "UPLOAD", "INVOKE_API"}:
        return False
    return bool(_confirmed_trusted_chain_ids(runtime_chains)) and not _has_untrusted_confirmed_confidentiality_sink(runtime_chains)


def _trusted_llm_boundary_guard(action: dict[str, Any]) -> bool:
    text = _action_text(action).lower()
    if "local model" in text or "model summary" in text or "trusted model" in text:
        return True
    boundary_tokens = (
        "live services",
        "production accounts",
        "public webhooks",
        "real third-party",
        "uncontrolled network",
        "outside scope",
        "localhost mock",
        "sandbox files",
        "synthetic files",
    )
    return any(token in text for token in boundary_tokens)


def _confirmed_trusted_chain_ids(runtime_chains: list[dict[str, Any]]) -> list[str]:
    chain_ids: list[str] = []
    for chain in runtime_chains:
        if not _is_confirmed_confidentiality_chain(chain):
            continue
        if _is_trusted_llm_sink(chain):
            chain_ids.append(str(chain.get("chain_id") or ""))
    return [item for item in chain_ids if item]


def _has_untrusted_confirmed_confidentiality_sink(runtime_chains: list[dict[str, Any]]) -> bool:
    for chain in runtime_chains:
        if not _is_confirmed_confidentiality_chain(chain):
            continue
        if not _is_trusted_llm_sink(chain):
            return True
    return False


def _is_confirmed_confidentiality_chain(chain: dict[str, Any]) -> bool:
    return (
        str(chain.get("chain_type") or "") == "confidentiality_confirmed"
        and str(chain.get("evidence_level") or "") in {"", "confirmed", "conservative"}
    )


def _is_trusted_llm_sink(chain: dict[str, Any]) -> bool:
    sink = str(chain.get("sink") or "").lower()
    metadata = chain.get("metadata", {}) or {}
    carrier_types = {str(item).lower() for item in metadata.get("carrier_types", []) or []}
    if "llm_context" in carrier_types and ("api.siliconflow.cn" in sink or "api.deepseek.com" in sink or "api.openai.com" in sink):
        return True
    if "llm_context" in carrier_types and ("llm" in sink or "provider" in sink):
        return True
    return False


def _condition_currently_required(action: dict[str, Any]) -> bool:
    # Static v2 does not yet expose evaluated runtime condition truth. Treat unresolved
    # conditionals as non-required to avoid fabricating obligations.
    return False


def _expected_obligations_for_action(action: dict[str, Any]) -> list[tuple[str, str, str]]:
    atype = str(action.get("action_type") or action.get("type") or "").upper()
    if atype in {"SEND", "UPLOAD", "INVOKE_API"}:
        return [
            ("network_send", "external_action_attempted", "high"),
            ("sink_reached", "sink_reached", "high"),
            ("payload_observable", "payload_observed", "critical"),
        ]
    if atype in {"READ", "ACCESS_CREDENTIAL"}:
        return [("file_read", "source_read", "medium")]
    if atype in {"WRITE", "COPY", "MOVE", "TRANSFORM"}:
        return [("file_write", "intermediate_artifact_created", "medium")]
    if atype in {"EXECUTE", "RUN_COMMAND"}:
        return [("process_exec", "execution_started", "high")]
    if atype == "PERSIST":
        return [("file_write", "persistence_target_reached", "high")]
    if atype == "DOWNLOAD":
        return [("file_write", "downloaded_artifact_created", "high")]
    return [(_expected_operation(action), _obligation_type_for_expected(_expected_operation(action)), "low")]


def _obligation_type_for_expected(expected: str) -> str:
    return {
        "file_read": "source_read",
        "file_write": "intermediate_artifact_created",
        "process_exec": "downloaded_artifact_executed",
        "network_send": "external_action_attempted",
        "sink_reached": "sink_reached",
        "payload_observable": "payload_observed",
        "tool_invoke": "action_reached",
    }.get(expected, expected)


def _expected_operation(action: dict[str, Any]) -> str:
    atype = str(action.get("action_type") or action.get("type") or "").upper()
    return {
        "READ": "file_read",
        "WRITE": "file_write",
        "EXECUTE": "process_exec",
        "RUN_COMMAND": "process_exec",
        "SEND": "network_send",
        "UPLOAD": "network_send",
        "INVOKE_API": "network_send",
        "ACCESS_CREDENTIAL": "file_read",
        "PERSIST": "file_write",
    }.get(atype, "tool_invoke")


def _expected_chain_obligation(chain: dict[str, Any]) -> str:
    ctype = str(chain.get("chain_type") or "")
    if "exfiltration" in ctype or "network" in ctype:
        return "network_send"
    if "download" in ctype:
        return "process_exec"
    if "persistence" in ctype:
        return "file_write"
    return "tool_invoke"


def _runtime_matches_expected(event: dict[str, Any], expected: str, action: dict[str, Any]) -> bool:
    if expected == "file_read":
        return event.get("operation") == "read" and event.get("object_type") == "file"
    if expected == "file_write":
        return event.get("operation") == "write" and event.get("object_type") == "file"
    if expected == "process_exec":
        return event.get("operation") == "exec" or event.get("event_type") == "process_exec"
    if expected == "network_send":
        return event.get("object_type") == "network" and event.get("operation") in {"send", "upload"} and _network_event_matches_action_target(event, action)
    if expected == "sink_reached":
        return event.get("object_type") == "network" and event.get("operation") in {"send", "upload"} and _network_event_matches_action_target(event, action)
    if expected == "payload_observable":
        meta = event.get("metadata", {}) or {}
        return (
            event.get("object_type") == "network"
            and event.get("operation") in {"send", "upload"}
            and _network_event_matches_action_target(event, action)
            and (
                event.get("instrumentation_visibility") in {"observed", "payload_preview_observed"}
                or meta.get("network_evidence_level") in {"tainted_payload_observed", "tainted_payload_delivered"}
                or event.get("network_evidence_level") in {"tainted_payload_observed", "tainted_payload_delivered"}
            )
        )
    return event.get("event_type", "").startswith("tool_")


def _runtime_chain_action_match(event: dict[str, Any], expected: str) -> bool:
    return _runtime_matches_expected(event, expected, {})


def _network_event_matches_action_target(event: dict[str, Any], action: dict[str, Any]) -> bool:
    targets = _action_network_targets(action)
    if not targets:
        return True
    endpoint = _event_endpoint(event)
    endpoint_keys = _endpoint_match_keys(endpoint)
    event_object = str(event.get("object_id") or "").replace("NET:", "")
    endpoint_keys.update(_endpoint_match_keys(event_object))
    return bool(endpoint_keys & targets)


def _action_network_targets(action: dict[str, Any]) -> set[str]:
    targets: set[str] = set()
    for key in _action_keys(action):
        if not _looks_like_endpoint(key):
            continue
        targets.update(_endpoint_match_keys(key))
    return targets


def _looks_like_endpoint(value: str) -> bool:
    value = str(value or "").strip().lower()
    return value.startswith(("http://", "https://")) or value.startswith("localhost") or bool(re.search(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", value))


def _endpoint_match_keys(value: str) -> set[str]:
    value = str(value or "").strip()
    if not value:
        return set()
    keys = {_norm_key(value)}
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.netloc:
        keys.add(_norm_key(parsed.netloc))
        if parsed.hostname:
            keys.add(_norm_key(parsed.hostname))
        if parsed.path and parsed.path != "/":
            keys.add(_norm_key(f"{parsed.netloc}{parsed.path}"))
            if parsed.hostname:
                keys.add(_norm_key(f"{parsed.hostname}{parsed.path}"))
    elif "." in value:
        keys.add(_norm_key(value.split("/", 1)[0]))
    return {key for key in keys if key}


def _event_endpoint(event: dict[str, Any]) -> str:
    meta = event.get("metadata", {}) or {}
    return str(meta.get("destination") or meta.get("sink_url") or meta.get("url") or event.get("object_id", "").replace("NET:", ""))


def _entity_keys(entity: dict[str, Any]) -> list[str]:
    keys = []
    for field in ("canonical_value", "canonical", "value", "name", "path", "url", "domain"):
        if entity.get(field):
            keys.append(str(entity[field]))
    attrs = entity.get("attributes") or entity.get("alignment_keys") or {}
    if isinstance(attrs, dict):
        for field in ("normalized_path", "path", "url", "domain", "artifact_hash", "command", "tool"):
            if attrs.get(field):
                keys.append(str(attrs[field]))
    return sorted(set(keys))


def _action_keys(action: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    for field in ("object_mentions", "source_mentions", "destination_mentions", "tool_mentions"):
        for value in action.get(field, []) or []:
            keys.append(str(value))
    for field in ("raw_verb", "action_type", "tool", "command"):
        if action.get(field):
            keys.append(str(action[field]))
    return sorted(set(keys))


def _entity_kind(entity: dict[str, Any]) -> str:
    etype = str(entity.get("entity_type") or entity.get("type") or "").lower()
    if "network" in etype or "endpoint" in etype or "url" in etype or "domain" in etype:
        return "endpoint"
    if "artifact" in etype:
        return "artifact"
    if "credential" in etype or "secret" in etype:
        return "credential"
    if "file" in etype or "path" in etype:
        return "file"
    return "entity"


def _static_id(item: dict[str, Any], default: str) -> str:
    return str(item.get(f"{default}_id") or item.get("action_id") or item.get("entity_id") or item.get("unit_id") or item.get("id") or "")


def _unit_text(unit: dict[str, Any]) -> str:
    for key in ("text", "content", "raw_text", "normalized_text"):
        if unit.get(key):
            return str(unit[key])
    return str(unit)


def _action_text(action: dict[str, Any]) -> str:
    evidence = action.get("evidence") or {}
    if isinstance(evidence, dict):
        for key in ("text", "exact_text", "snippet"):
            if evidence.get(key):
                return str(evidence[key])
    return " ".join(str(value) for value in [action.get("raw_verb"), action.get("action_type"), *(_action_keys(action))] if value)


def _dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for item in items:
        marker = (item.get("id"), item.get("kind"), _norm_key(item.get("key")))
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out


def _dedupe_claims(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for item in items:
        marker = (item.get("id"), _norm_key(item.get("key")))
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out


def _norm_key(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    parsed = urlparse(text)
    if parsed.scheme and parsed.hostname:
        return f"{parsed.hostname}{parsed.path}".rstrip("/").lower()
    return posixpath.normpath(text).lower()


def _norm_path(value: Any) -> str:
    return posixpath.normpath(str(value or "").replace("\\", "/")).lower()


def _norm_endpoint(value: Any) -> str:
    text = str(value or "").replace("network:", "").replace("NET:", "")
    parsed = urlparse(text)
    if parsed.hostname:
        return f"{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}{parsed.path}".rstrip("/").lower()
    return text.rstrip("/").lower()


def _same_path(left: str, right: str) -> bool:
    return _norm_path(left) == _norm_path(right)


def _same_endpoint(left: str, right: str) -> bool:
    return _norm_endpoint(left) == _norm_endpoint(right) or _norm_endpoint(left).split(":", 1)[0] == _norm_endpoint(right).split(":", 1)[0]


def _same_executable(left: str, right: str) -> bool:
    return posixpath.basename(_norm_path(left)) == posixpath.basename(_norm_path(right))


def _actions_compatible(left: str, right: str) -> bool:
    left_u = str(left).upper()
    right_u = str(right).upper()
    if left_u == right_u:
        return True
    for static_action, runtime_ops in ACTION_COMPATIBILITY.items():
        if right_u == static_action and left.lower() in {item.lower() for item in runtime_ops}:
            return True
        if left_u == static_action and right.lower() in {item.lower() for item in runtime_ops}:
            return True
    return False


def _alignment_type(kind: str) -> str:
    if kind in {"file", "artifact", "endpoint", "tool", "process", "data", "credential", "entity"}:
        return "entity"
    if kind == "action":
        return "action"
    return "path"


def _runtime_chain_semantic_type(chain: dict[str, Any]) -> str:
    ctype = str(chain.get("chain_type") or "")
    if ctype.startswith("confidentiality_"):
        return "credential_exfiltration"
    if ctype.startswith("persistence_"):
        return "persistence"
    return ctype


def _evidence(source: str, item_id: str, key: Any, **extra: Any) -> dict[str, Any]:
    payload = {"source": source, "id": item_id, "key": str(key)}
    payload.update(extra)
    return payload


def _artifact_mismatch(static_artifacts: list[dict[str, Any]], events: list[dict[str, Any]]) -> bool:
    declared = {_norm_path(item["key"]) for item in static_artifacts if item.get("key") and "/" in str(item["key"])}
    runtime_files = {_norm_path(event.get("object_path")) for event in events if event.get("object_type") == "file" and event.get("operation") in {"write", "exec"}}
    return bool(declared and runtime_files and declared.isdisjoint(runtime_files))


def _preconfirmation_effects(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    confirmation_times = [float(event.get("timestamp") or 0) for event in events if str(event.get("event_type")) in {"user_confirmation", "confirmation"}]
    first_confirmation = min(confirmation_times) if confirmation_times else None
    effects = [event for event in events if event.get("operation") in {"send", "upload", "write", "exec"}]
    if first_confirmation is None:
        return effects
    return [event for event in effects if float(event.get("timestamp") or 0) < first_confirmation]


def _extra_sensitive_reads(read_scope: list[dict[str, Any]], reads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    allowed = {_norm_path(item["key"]) for item in read_scope if item.get("key")}
    return [event for event in reads if _norm_path(event.get("object_path")) not in allowed]


def _different_runtime_tools(tools: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    allowed = {posixpath.basename(_norm_path(item["key"])) for item in tools if item.get("key")}
    different = []
    for event in events:
        if event.get("operation") != "exec":
            continue
        command = str(event.get("data_preview") or event.get("metadata", {}).get("command") or "")
        exe = posixpath.basename(command.split()[0]) if command.split() else ""
        if exe and allowed and exe not in allowed:
            different.append(event)
    return different


def _is_external_write(event: dict[str, Any]) -> bool:
    path = _norm_path(event.get("object_path"))
    return bool(path.startswith("/etc/") or path.startswith("/root/") or "/.config/systemd/" in path or "crontab" in path)


def _tls_payload_gap(events: list[dict[str, Any]]) -> bool:
    return any(
        event.get("instrumentation_visibility") == "encrypted_payload_invisible"
        or event.get("metadata", {}).get("encrypted_payload_invisible")
        or event.get("metadata", {}).get("network_evidence_level") == "encrypted_payload_invisible"
        for event in events
    )


def _policy_domain(chain: dict[str, Any]) -> str:
    ctype = str(chain.get("chain_type") or chain.get("capability_type") or "")
    if "credential" in ctype or "exfil" in ctype:
        return "confidentiality"
    if "persist" in ctype:
        return "persistence"
    if "execute" in ctype or "download" in ctype:
        return "execution"
    return "permission"


def _alignment_for(contradiction: UnifiedContradiction, alignments: list[UnifiedAlignment]) -> str:
    ids = set(contradiction.static_claim.get("ids", [])) | set(contradiction.runtime_observation.get("ids", []))
    for alignment in alignments:
        if ids.intersection(alignment.static_ids) or ids.intersection(alignment.runtime_ids):
            return alignment.alignment_id
    return ""
