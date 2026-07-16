from __future__ import annotations

import hashlib
from typing import Any


def sanitized_preview(value: Any, *, limit: int = 32) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def value_hash(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def taint_event_payload(
    *,
    event_type: str,
    event_id: str,
    timestamp: str,
    run_id: str,
    tool_call_id: str | None = None,
    process_id: str | None = None,
    parent_event_id: str | None = None,
    step_id: str | None = None,
    taint_ids: list[str] | None = None,
    evidence_level: str = "unknown",
    propagation_rule: str = "",
    source_event_ids: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "event_id": event_id,
        "timestamp": timestamp,
        "run_id": run_id,
        "tool_call_id": tool_call_id,
        "process_id": process_id,
        "parent_event_id": parent_event_id,
        "step_id": step_id,
        "taint_ids": sorted(set(taint_ids or [])),
        "evidence_level": evidence_level,
        "propagation_rule": propagation_rule,
        "source_event_ids": list(source_event_ids or []),
        "metadata": dict(metadata or {}),
    }
