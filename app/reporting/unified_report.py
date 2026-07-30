from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.explanation.models import UnifiedExplanationResult
from app.explanation.serializer import to_json_dict


def write_unified_reports(result: UnifiedExplanationResult | dict[str, Any], output_dir: str | Path) -> dict[str, Path]:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    payload = to_json_dict(result)
    json_path = root / "unified-analysis.json"
    md_path = root / "unified-explanation.md"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(generate_unified_markdown(payload), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def generate_unified_markdown(result: UnifiedExplanationResult | dict[str, Any]) -> str:
    payload = to_json_dict(result)
    assessment = payload.get("canonical_assessment", {}) or {}
    title = _title_for(assessment)
    lines = [
        f"# {title}",
        "",
        "## Canonical Assessment",
        f"- Status: {assessment.get('status', 'unknown')}",
        f"- Decision: {assessment.get('canonical_final_decision', assessment.get('final_decision', 'unknown'))}",
        f"- Risk score: {assessment.get('canonical_risk_score', assessment.get('risk_score', 0))}",
        f"- Coverage: {assessment.get('coverage_state', payload.get('coverage_certificate', {}).get('coverage_state', 'unknown'))}",
        "",
        "## Executive Explanation",
        _executive(payload),
        "",
        "## Confirmed Violations",
        *_finding_lines(payload, status="violation"),
        "",
        "## Needs Review",
        *_finding_lines(payload, status="review"),
        "",
        "## Static Instruction Evidence",
        *_static_lines(payload),
        "",
        "## Runtime Evidence",
        *_runtime_lines(payload),
        "",
        "## Aligned Risk Paths",
        *_short_records(payload.get("aligned_paths", []), "alignment_id"),
        "",
        "## Static-Runtime Contradictions",
        *_short_records(payload.get("contradictions", []), "contradiction_type"),
        "",
        "## Instruction-Only Paths",
        *_short_records(payload.get("instruction_only_paths", []), "chain_type"),
        "",
        "## Runtime-Only Paths",
        *_short_records(payload.get("runtime_only_paths", []), "chain_type"),
        "",
        "## Coverage Certificate",
        *_coverage_lines(payload),
        "",
        "## Instrumentation Gaps",
        *_list_or_none(payload.get("coverage_certificate", {}).get("instrumentation_gaps", [])),
        "",
        "## Minimal Witnesses",
        *_short_records(payload.get("minimal_witnesses", []), "witness_id"),
        "",
        "## Policy Decisions",
        *_short_records(payload.get("policy_findings", []), "finding_id"),
        "",
        "## Legacy Compatibility",
        *_dict_lines(payload.get("legacy_compatibility", {})),
        "",
        "## Reproduction Metadata",
        *_dict_lines(payload.get("versions", {})),
    ]
    return "\n".join(lines).rstrip() + "\n"


def _title_for(assessment: dict[str, Any]) -> str:
    status = str(assessment.get("status") or "")
    decision = str(assessment.get("canonical_final_decision") or assessment.get("final_decision") or "")
    coverage = str(assessment.get("coverage_state") or "")
    if status == "violation_confirmed" or decision == "malicious":
        return "Violation Confirmed"
    if coverage in {"timeout", "execution_failed", "path_not_triggered", "max_steps_exhausted", "path_incomplete", "partially_complete"}:
        return "Execution Incomplete"
    if status == "review_required" or decision == "needs_review":
        return "Review Required"
    return "No Violation Observed"


def _executive(payload: dict[str, Any]) -> str:
    counts = {
        "alignments": len(payload.get("alignments", []) or []),
        "relevant_unresolved": len(payload.get("relevant_unresolved", []) or []),
        "internal_unresolved": len(payload.get("internal_unresolved", []) or []),
        "contradictions": len(payload.get("contradictions", []) or []),
        "policy_findings": len(payload.get("policy_findings", []) or []),
        "minimal_witnesses": len(payload.get("minimal_witnesses", []) or []),
    }
    return "- " + "; ".join(f"{key}: {value}" for key, value in counts.items())


def _finding_lines(payload: dict[str, Any], *, status: str) -> list[str]:
    findings = [item for item in payload.get("policy_findings", []) or [] if item.get("status") == status]
    if not findings:
        return ["- None"]
    return [f"- {item.get('finding_id')}: {item.get('policy_domain')} / {item.get('evidence_status')} - {item.get('reason')}" for item in findings]


def _static_lines(payload: dict[str, Any]) -> list[str]:
    static = payload.get("static_result", {}) or {}
    summary = static.get("static_analysis_summary", {}) or {}
    return [
        f"- Static chains: {len(static.get('static_chains', []) or [])}",
        f"- Review priority: {summary.get('review_priority', 'unknown')}",
        f"- Schema: {static.get('schema_version', '')}",
    ]


def _runtime_lines(payload: dict[str, Any]) -> list[str]:
    dynamic = payload.get("dynamic_result", {}) or {}
    summary = dynamic.get("summary", {}) or dynamic.get("dynamic_analysis_summary", {}) or {}
    return [
        f"- Runtime events: {summary.get('runtime_event_count', len(dynamic.get('runtime_events', []) or []))}",
        f"- Runtime chains: {summary.get('runtime_chain_count', len(dynamic.get('runtime_chains', []) or []))}",
        f"- Policy violations: {summary.get('policy_violation_count', len(dynamic.get('policy_violations', []) or []))}",
    ]


def _coverage_lines(payload: dict[str, Any]) -> list[str]:
    coverage = payload.get("coverage_certificate", {}) or {}
    summary = coverage.get("summary", {}) or {}
    lines = [f"- State: {coverage.get('coverage_state', 'unknown')}"]
    if coverage.get("path_completion_status"):
        lines.append(f"- Path completion: {coverage.get('path_completion_status')}")
    if coverage.get("termination_reason"):
        lines.append(f"- Termination: {coverage.get('termination_reason')}")
    if coverage.get("chain_evidence_status"):
        lines.append(f"- Chain evidence: {coverage.get('chain_evidence_status')}")
    for key, value in (coverage.get("obligation_summary", {}) or {}).items():
        lines.append(f"- obligations.{key}: {value}")
    lines.extend(f"- {key}: {value}" for key, value in summary.items())
    for obligation in coverage.get("obligations", []) or []:
        lines.append(
            f"- {obligation.get('obligation_id')}: {obligation.get('expected_runtime_operation')} "
            f"({obligation.get('risk_relevance', 'low')}) -> {obligation.get('status')}"
        )
    for path in coverage.get("path_completion", []) or []:
        lines.append(f"- path {path.get('static_path_id')}: {path.get('status')} ({path.get('completion_ratio')}) - {path.get('reason')}")
    for artifact in coverage.get("sensitive_artifacts", []) or []:
        lines.append(f"- artifact {artifact.get('artifact_path')}: {artifact.get('status')} - {artifact.get('reason')}")
    return lines


def _short_records(records: list[dict[str, Any]], key: str) -> list[str]:
    if not records:
        return ["- None"]
    lines = []
    for item in records:
        label = item.get(key) or item.get("id") or "record"
        reason = item.get("reason") or item.get("status") or item.get("evidence_status") or ""
        lines.append(f"- {label}: {reason}")
    return lines


def _list_or_none(items: list[Any]) -> list[str]:
    return [f"- {item}" for item in items] if items else ["- None"]


def _dict_lines(payload: dict[str, Any]) -> list[str]:
    return [f"- {key}: {value}" for key, value in payload.items()] if payload else ["- None"]
