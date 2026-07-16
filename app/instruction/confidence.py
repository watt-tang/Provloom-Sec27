from __future__ import annotations

from app.instruction.models import ValidatedInstructionPath


def path_confidence(paths: list[ValidatedInstructionPath]) -> float:
    if not paths:
        return 0.0
    return max(path.confidence for path in paths)


def confidence_label(value: float) -> str:
    if value >= 0.85:
        return "high"
    if value >= 0.6:
        return "medium"
    return "low"
