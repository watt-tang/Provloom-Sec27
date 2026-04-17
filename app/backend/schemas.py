from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AnalyzeSkillRequest:
    skill_path: str
    command: list[str] = field(default_factory=lambda: ["python", "skill.py"])
    timeout_seconds: int = 20

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AnalyzeSkillRequest":
        skill_path = payload.get("skill_path")
        command = payload.get("command", ["python", "skill.py"])
        timeout_seconds = payload.get("timeout_seconds", 20)

        if not isinstance(skill_path, str) or not skill_path.strip():
            raise ValueError("`skill_path` must be a non-empty string.")
        if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
            raise ValueError("`command` must be a non-empty string array.")
        if not isinstance(timeout_seconds, int) or not (1 <= timeout_seconds <= 300):
            raise ValueError("`timeout_seconds` must be an integer between 1 and 300.")

        return cls(skill_path=skill_path, command=command, timeout_seconds=timeout_seconds)


@dataclass
class EvidenceEvent:
    timestamp: str
    category: str
    action: str
    detail: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalyzeSkillResponse:
    skill_path: str
    sandbox_image: str
    command: list[str]
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    trace_summary: dict[str, Any]
    risk_score: int
    detected_behaviors: list[str]
    evidence_timeline: list[EvidenceEvent]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
