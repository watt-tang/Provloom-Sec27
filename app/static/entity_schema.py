from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


ENTITY_TYPES = {
    "Artifact", "File", "Directory", "Archive", "Executable", "Script", "Package", "SensitiveResource",
    "Credential", "EnvironmentVariable", "DataObject", "NetworkEndpoint", "APIEndpoint", "Tool", "Principal",
    "Permission", "PersistenceTarget", "Trigger", "RuntimeAlignableObject", "UnknownEntity",
}


@dataclass
class Mention:
    mention_id: str
    mention_type: str
    raw_value: str
    normalized_value: str
    artifact_id: str
    unit_id: str
    start_offset_in_unit: int
    end_offset_in_unit: int
    extractor: str
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StaticEntity:
    entity_id: str
    entity_type: str
    canonical_value: str
    aliases: list[str] = field(default_factory=list)
    mentions: list[str] = field(default_factory=list)
    resolution_status: str = "resolved"
    resolution_method: list[str] = field(default_factory=list)
    confidence: float = 0.9
    runtime_alignment_keys: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EntityResolution:
    resolution_id: str
    entity_a: str
    entity_b: str
    relation: str
    method: str
    evidence_unit_ids: list[str]
    confidence: float
    status: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
