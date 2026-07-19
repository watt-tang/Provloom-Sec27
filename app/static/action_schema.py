from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


ACTION_TYPES = {
    "READ", "WRITE", "COPY", "MOVE", "DELETE", "DOWNLOAD", "UPLOAD", "SEND", "EXECUTE", "INSTALL", "IMPORT",
    "DECODE", "EXTRACT", "MODIFY", "PERSIST", "REQUEST_PERMISSION", "ACCESS_CREDENTIAL", "INVOKE_TOOL",
    "INVOKE_API", "REGISTER_SERVICE", "CHANGE_PERMISSION", "COLLECT", "TRANSFORM", "UNKNOWN_SECURITY_ACTION",
}

MODALITIES = {"required", "recommended", "optional", "conditional", "prohibited", "example_only", "descriptive", "hypothetical", "quoted_untrusted", "unknown"}


@dataclass
class EvidenceSpan:
    artifact_id: str
    unit_id: str
    start_line: int
    end_line: int
    exact_text: str
    start_offset: int = 0
    end_offset: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StaticAction:
    action_id: str
    actor: dict[str, Any]
    action_type: str
    object_mentions: list[str] = field(default_factory=list)
    source_mentions: list[str] = field(default_factory=list)
    destination_mentions: list[str] = field(default_factory=list)
    tool_mentions: list[str] = field(default_factory=list)
    result_mentions: list[str] = field(default_factory=list)
    condition: str | None = None
    modality: str = "unknown"
    purpose: str | None = None
    evidence: EvidenceSpan | None = None
    extractor: str = "deterministic"
    grounding_status: str = "valid"
    confidence: float = 0.5
    validation_notes: list[str] = field(default_factory=list)
    raw_verb: str = ""
    normalization_method: str = "deterministic"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return payload
