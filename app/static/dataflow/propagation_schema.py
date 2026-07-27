from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.static.action_schema import EvidenceSpan, StaticAction
from app.static.artifact_schema import SemanticUnit
from app.static.entity_schema import Mention


@dataclass
class FlowExtractionResult:
    mentions: list[Mention] = field(default_factory=list)
    actions: list[StaticAction] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


class FlowBuilder:
    def __init__(self, mention_base: int, action_base: int) -> None:
        self.mentions: list[Mention] = []
        self.actions: list[StaticAction] = []
        self.limitations: list[str] = []
        self._mention_base = mention_base
        self._action_base = action_base

    def mention(self, unit: SemanticUnit, mention_type: str, raw: str, *, extractor: str, confidence: float = 0.96) -> str:
        normalized = _normalize(mention_type, raw)
        mention = Mention(
            mention_id=f"M{self._mention_base + len(self.mentions) + 1:04d}",
            mention_type=mention_type,
            raw_value=raw,
            normalized_value=normalized,
            artifact_id=unit.artifact_id,
            unit_id=unit.unit_id,
            start_offset_in_unit=max(unit.text.find(raw), 0),
            end_offset_in_unit=max(unit.text.find(raw), 0) + len(raw),
            extractor=extractor,
            confidence=confidence,
            metadata={"flow_extracted": True},
        )
        self.mentions.append(mention)
        return mention.mention_id

    def action(
        self,
        unit: SemanticUnit,
        action_type: str,
        *,
        object_mentions: list[str] | None = None,
        source_mentions: list[str] | None = None,
        destination_mentions: list[str] | None = None,
        raw_verb: str = "",
        confidence: float = 0.96,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        evidence = EvidenceSpan(unit.artifact_id, unit.unit_id, unit.start_line, unit.end_line, unit.text, unit.start_offset, unit.end_offset)
        self.actions.append(
            StaticAction(
                action_id=f"A{self._action_base + len(self.actions) + 1:04d}",
                actor={"type": "script", "mention": "script"},
                action_type=action_type,
                object_mentions=object_mentions or [],
                source_mentions=source_mentions or [],
                destination_mentions=destination_mentions or [],
                evidence=evidence,
                extractor="deterministic_flow",
                grounding_status="valid",
                confidence=confidence,
                raw_verb=raw_verb or action_type.lower(),
                normalization_method="bounded_dataflow",
                metadata={"unit_type": unit.unit_type, "parent_section": unit.parent_section, **(metadata or {})},
            )
        )

    def add_limitation(self, reason: str) -> None:
        if reason not in self.limitations:
            self.limitations.append(reason)

    def result(self) -> FlowExtractionResult:
        return FlowExtractionResult(self.mentions, self.actions, self.limitations)


def _normalize(mention_type: str, raw: str) -> str:
    if mention_type == "environment_variable":
        return raw.strip("${}").lstrip("$")
    if mention_type == "url":
        return urlparse(raw).geturl()
    return raw.strip("\"'")
