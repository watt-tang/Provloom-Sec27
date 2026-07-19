from __future__ import annotations

from pathlib import Path
from typing import Any

from app.instruction.models import InstructionAnalysisResult, ValidatedInstructionPath
from app.instruction.orchestrator import analyze_instruction_bundle
from app.static.static_report import StaticAnalysisResult, analyze_static_bundle


MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 1024 * 1024


def analyze_instruction_chain(skill_root: str | Path, skill_file: str = "SKILL.md") -> dict[str, Any]:
    analysis = analyze_instruction_bundle(skill_root, skill_file)
    result = _compat_result(analysis)
    static_v2 = analyze_static_bundle(skill_root, skill_file)
    result.update(_static_v2_fields(static_v2))
    return result


def apply_instruction_chain_decision(
    report: dict[str, Any],
    skill_root: str | Path | None,
    skill_file: str = "SKILL.md",
    *,
    dynamic_chain_observed: bool | None = None,
) -> dict[str, Any]:
    if not skill_root:
        instruction = _empty_instruction_result()
    else:
        try:
            instruction = analyze_instruction_chain(skill_root, skill_file)
        except Exception as exc:
            instruction = _empty_instruction_result()
            instruction["static_supply_chain_risk"]["reason"] = f"instruction scan unavailable: {exc}"

    observed_dynamic_chain = bool(report.get("primary_chain")) if dynamic_chain_observed is None else bool(dynamic_chain_observed)
    report.update(
        {
            "dynamic_chain_observed": observed_dynamic_chain,
            "instruction_chain_recovered": bool(instruction.get("instruction_chain_recovered")),
            "instruction_chain": instruction.get("instruction_chain", []),
            "instruction_indicators": instruction.get("instruction_indicators", []),
            "static_supply_chain_risk": instruction.get("static_supply_chain_risk", _none_risk()),
            "instruction_document_scan": instruction.get("document_scan_summary", {}),
            "instruction_actions": instruction.get("instruction_actions", []),
            "instruction_entities": instruction.get("instruction_entities", []),
            "instruction_graph": instruction.get("instruction_graph", {}),
            "validated_instruction_paths": instruction.get("validated_instruction_paths", []),
            "partial_instruction_paths": instruction.get("partial_instruction_paths", []),
            "instruction_analysis_summary": instruction.get("instruction_analysis_summary", {}),
            "extraction_coverage": instruction.get("extraction_coverage", {}),
            "abstention_reasons": instruction.get("abstention_reasons", []),
            "schema_version": instruction.get("schema_version", ""),
        }
    )

    report["chain_evidence_type"] = _chain_evidence_type(
        dynamic_observed=bool(report["dynamic_chain_observed"]),
        instruction_recovered=bool(report["instruction_chain_recovered"]),
    )
    report["final_risk_level"] = _aggregate_final_risk_level(report)
    report["final_label_reason"] = _final_label_reason(report)
    return report


def _compat_result(analysis: InstructionAnalysisResult) -> dict[str, Any]:
    data = analysis.to_dict()
    validated = analysis.validated_paths
    partial = analysis.partial_paths
    instruction_chain = _legacy_chain_from_paths(validated or partial, analysis.indicators)
    risk = _risk_from_paths(validated, partial, analysis.summary, analysis.indicators)
    return {
        "instruction_chain_recovered": bool(validated),
        "instruction_chain": instruction_chain if validated else [],
        "instruction_indicators": analysis.indicators,
        "static_supply_chain_risk": risk,
        "document_scan_summary": {
            "files_scanned": [document.relative_path for document in analysis.documents],
            "bytes_scanned": sum(document.size for document in analysis.documents),
            "file_limit_bytes": MAX_FILE_BYTES,
            "total_budget_bytes": MAX_TOTAL_BYTES,
            "schema_version": analysis.schema_version,
        },
        "instruction_actions": data["actions"],
        "instruction_entities": data["entities"],
        "instruction_graph": data["graph"],
        "validated_instruction_paths": data["validated_paths"],
        "partial_instruction_paths": data["partial_paths"],
        "instruction_analysis_summary": data["summary"],
        "extraction_coverage": data["extraction_coverage"],
        "abstention_reasons": data["abstention_reasons"],
        "schema_version": analysis.schema_version,
    }


def _static_v2_fields(analysis: StaticAnalysisResult) -> dict[str, Any]:
    data = analysis.to_dict()
    return {
        "static_artifacts_v2": data["static_artifacts_v2"],
        "static_semantic_units": data["static_semantic_units"],
        "deterministic_mentions": data["deterministic_mentions"],
        "extracted_actions": data["extracted_actions"],
        "grounding_validation": data["grounding_validation"],
        "resolved_entities": data["resolved_entities"],
        "entity_resolutions": data["entity_resolutions"],
        "instruction_provenance_graph": data["instruction_provenance_graph"],
        "static_chains": data["static_chains"],
        "static_coverage": data["static_coverage"],
        "static_analysis_summary": data["static_analysis_summary"],
        "llm_extraction_metadata": data["llm_extraction_metadata"],
        "static_schema_version": data["schema_version"],
    }


def _legacy_chain_from_paths(paths: list[ValidatedInstructionPath], indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not paths:
        return []
    path = paths[0]
    chain: list[dict[str, Any]] = []
    previous = "instruction_document"
    projected = _project_legacy_steps(indicators, path)
    for index, item in enumerate(projected):
        action = item["action"]
        target = item["target"]
        chain.append(
            {
                "source": previous,
                "action": action,
                "target": target,
                "evidence_source": item.get("evidence_source", ",".join(path.evidence_span_ids)),
                "evidence_type": item.get("evidence_type", "legacy_heuristic_chain"),
                "observed_at_runtime": False,
                "confidence": _confidence_label(path.confidence),
                "raw_snippet": item.get("raw_snippet", ""),
                "path_id": path.path_id,
                "path_type": path.path_type,
                "completeness": path.completeness,
            }
        )
        previous = target
    return chain


def _risk_from_paths(
    validated: list[ValidatedInstructionPath],
    partial: list[ValidatedInstructionPath],
    summary: dict[str, Any],
    indicators: list[dict[str, Any]],
) -> dict[str, Any]:
    categories = {str(item.get("category", "")) for item in indicators}
    if validated:
        strongest = validated[0]
        level = summary.get("risk_level", "high")
        reason = (
            f"Validated latent instruction risk path `{strongest.path_type}` with deterministic graph evidence. "
            f"Confidence={strongest.confidence:.2f}; evidence spans={len(strongest.evidence_span_ids)}."
        )
        if {"remote_acquisition", "fixed_password_archive", "bulk_update"} <= categories:
            level = "critical"
            reason = (
                "Validated instruction graph evidence connects remote acquisition to bulk skill update authority; "
                "fixed-password archive evidence increases supply-chain setup risk."
            )
        elif {"external_agent", "sensitive_context"} <= categories and strongest.path_type == "remote_fetch_execute":
            level = "medium"
            reason = (
                "External agent setup appears in sensitive capability context. The graph validates setup/control-transfer "
                "instructions but no persistence, bulk update, or global environment impact sink was validated."
            )
        return {
            "level": level,
            "reason": reason,
            "closed_risk_path": True,
            "path_id": strongest.path_id,
            "path_type": strongest.path_type,
            "path_evidence_type": "validated_instruction_graph_path",
            "limitations": list(strongest.limitations),
        }
    if partial:
        strongest = partial[0]
        level = summary.get("risk_level", "medium")
        if categories <= {"instruction_action", "remote_acquisition"} or not (categories & {"persistence", "bulk_update", "environment_modification", "sensitive_context", "fixed_password_archive", "external_agent"}):
            level = "low"
        return {
            "level": level,
            "reason": (
                f"Partial or candidate instruction path `{strongest.path_type}` requires review; "
                f"limitations: {', '.join(strongest.limitations) or 'none'}."
            ),
            "closed_risk_path": False,
            "path_id": strongest.path_id,
            "path_type": strongest.path_type,
            "path_evidence_type": strongest.completeness,
            "limitations": list(strongest.limitations),
        }
    return _none_risk()


def _project_legacy_steps(indicators: list[dict[str, Any]], path: ValidatedInstructionPath) -> list[dict[str, Any]]:
    order = [
        "external_agent_install",
        "remote_script_or_binary_acquisition",
        "fixed_password_archive",
        "global_environment_modification",
        "persistence_setup",
        "bulk_skill_update",
        "sensitive_capability_context",
    ]
    by_action: dict[str, dict[str, Any]] = {}
    for item in indicators:
        action = str(item.get("action", ""))
        if action in order:
            by_action.setdefault(action, item)
    projected = []
    for action in order:
        item = by_action.get(action)
        if item is None:
            continue
        projected.append(
            {
                "action": action,
                "target": item.get("target") or action,
                "evidence_source": item.get("evidence_source", ""),
                "evidence_type": "legacy_heuristic_chain",
                "raw_snippet": item.get("raw_snippet", ""),
            }
        )
    if projected:
        return projected
    return [
        {
            "action": _legacy_action_name(op, path.path_type),
            "target": node_id,
            "evidence_source": ",".join(path.evidence_span_ids),
            "evidence_type": "validated_instruction_graph_path" if path.completeness == "closed" else "candidate_instruction_graph_path",
            "raw_snippet": "",
        }
        for op, node_id in zip(path.metadata.get("action_operations", []), path.node_ids)
    ]


def _aggregate_final_risk_level(report: dict[str, Any]) -> str:
    dynamic = _dynamic_level(report)
    static_level = str((report.get("static_supply_chain_risk") or {}).get("level", "none"))
    if _risk_rank(dynamic) >= _risk_rank("high"):
        return dynamic
    if bool((report.get("static_supply_chain_risk") or {}).get("closed_risk_path")) and _risk_rank(static_level) >= _risk_rank("high"):
        return static_level
    if _risk_rank(static_level) > _risk_rank(dynamic):
        return static_level
    return dynamic


def _dynamic_level(report: dict[str, Any]) -> str:
    score = int(report.get("risk_score", 0) or 0)
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _risk_rank(level: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(level, 0)


def _final_label_reason(report: dict[str, Any]) -> str:
    static_risk = report.get("static_supply_chain_risk") or {}
    static_level = str(static_risk.get("level", "none"))
    dynamic_observed = bool(report.get("dynamic_chain_observed"))
    instruction_recovered = bool(report.get("instruction_chain_recovered"))
    final_level = str(report.get("final_risk_level", "low"))
    if instruction_recovered and _risk_rank(static_level) >= _risk_rank("medium"):
        runtime_note = (
            "Runtime telemetry also contains a primary chain."
            if dynamic_observed
            else "Runtime telemetry did not observe this execution chain; it was not observed at runtime."
        )
        return (
            f"{runtime_note} Final risk is {final_level} because a validated instruction graph path "
            f"was recovered from local bundle documents. {static_risk.get('reason', '')}"
        ).strip()
    if static_level == "medium":
        return (
            "Runtime telemetry did not observe a closed execution chain. Static instruction analysis found "
            f"a partial or candidate path requiring review. {static_risk.get('reason', '')}"
        ).strip()
    return "Final risk follows runtime/dynamic evidence; no validated instruction graph path was recovered."


def _chain_evidence_type(*, dynamic_observed: bool, instruction_recovered: bool) -> str:
    if dynamic_observed and instruction_recovered:
        return "hybrid"
    if dynamic_observed:
        return "observed_runtime"
    if instruction_recovered:
        return "instruction_derived"
    return "none"


def _legacy_action_name(operation: str, path_type: str) -> str:
    if path_type == "bulk_update_authority" and operation in {"update", "replace"}:
        return "bulk_skill_update"
    if operation in {"register_cron", "register_service", "persist"}:
        return "persistence_setup"
    if operation in {"modify_environment", "modify_configuration"}:
        return "global_environment_modification"
    if operation in {"download", "fetch", "install"}:
        return "remote_script_or_binary_acquisition"
    if operation in {"authenticate", "grant_permission", "connect_account", "access_credential"}:
        return "sensitive_capability_context"
    return operation


def _confidence_label(value: float) -> str:
    if value >= 0.85:
        return "high"
    if value >= 0.6:
        return "medium"
    return "low"


def _none_risk() -> dict[str, Any]:
    return {
        "level": "none",
        "reason": "No validated instruction graph path was found.",
        "closed_risk_path": False,
        "path_evidence_type": "no_supported_instruction_path",
    }


def _empty_instruction_result() -> dict[str, Any]:
    return {
        "instruction_chain_recovered": False,
        "instruction_chain": [],
        "instruction_indicators": [],
        "static_supply_chain_risk": _none_risk(),
        "document_scan_summary": {
            "files_scanned": [],
            "bytes_scanned": 0,
            "file_limit_bytes": MAX_FILE_BYTES,
            "total_budget_bytes": MAX_TOTAL_BYTES,
        },
        "instruction_actions": [],
        "instruction_entities": [],
        "instruction_graph": {},
        "validated_instruction_paths": [],
        "partial_instruction_paths": [],
        "instruction_analysis_summary": {},
        "extraction_coverage": {},
        "abstention_reasons": [],
        "schema_version": "",
    }
