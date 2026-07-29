from __future__ import annotations

from typing import Any


def validate_unified_explanation(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if payload.get("schema_version") != "provloom-unified-v1":
        errors.append("schema_version must be provloom-unified-v1")
    for key in ("static_result", "dynamic_result", "canonical_assessment", "coverage_certificate"):
        if key not in payload:
            errors.append(f"missing {key}")
    for alignment in payload.get("alignments", []) or []:
        if not alignment.get("alignment_id"):
            errors.append("alignment missing alignment_id")
        if alignment.get("status") not in {"aligned", "partially_aligned", "unresolved", "relevant_unresolved", "internal_unresolved"}:
            errors.append(f"unsupported alignment status: {alignment.get('status')}")
    return errors
