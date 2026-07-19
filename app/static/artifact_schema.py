from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


STATIC_SCHEMA_VERSION = "provloom-static-v2"


@dataclass
class StaticArtifact:
    artifact_id: str
    relative_path: str
    artifact_type: str
    sha256: str
    size_bytes: int
    encoding: str
    load_status: str
    load_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LoadedArtifact:
    artifact: StaticArtifact
    text: str


@dataclass
class SemanticUnit:
    unit_id: str
    artifact_id: str
    unit_type: str
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int
    text: str
    parent_section: str
    language: str = "en"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StaticCoverage:
    states: list[str]
    total_files: int
    loaded_files: int
    ignored_files: int
    unsupported_files: int
    semantic_unit_count: int
    llm_success_count: int
    grounding_failure_count: int
    unresolved_entity_count: int
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
