from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable


class TaintEvidenceLevel(str, Enum):
    CONFIRMED = "confirmed"
    CONSERVATIVE = "conservative"
    CANDIDATE = "candidate"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TaintLabel:
    taint_id: str
    source_type: str
    sensitivity: str
    source_object: str
    source_event_id: str
    created_at: float | int | str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        source_type: str,
        sensitivity: str,
        source_object: str,
        source_event_id: str,
        created_at: float | int | str,
        metadata: dict[str, Any] | None = None,
    ) -> "TaintLabel":
        seed = json.dumps(
            {
                "run_id": run_id,
                "source_type": source_type,
                "source_object": source_object,
                "source_event_id": source_event_id,
            },
            sort_keys=True,
        )
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return cls(
            taint_id=f"T-{digest}",
            source_type=source_type,
            sensitivity=sensitivity,
            source_object=source_object,
            source_event_id=source_event_id,
            created_at=created_at,
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TaintSet:
    taint_ids: set[str] = field(default_factory=set)

    @classmethod
    def from_iterable(cls, values: Iterable[str] | None) -> "TaintSet":
        return cls({str(value) for value in values or [] if str(value)})

    def add(self, taint_id: str) -> None:
        if taint_id:
            self.taint_ids.add(taint_id)

    def remove(self, taint_id: str) -> None:
        self.taint_ids.discard(taint_id)

    def union(self, other: "TaintSet" | Iterable[str]) -> "TaintSet":
        if isinstance(other, TaintSet):
            return TaintSet(set(self.taint_ids) | set(other.taint_ids))
        return TaintSet(set(self.taint_ids) | {str(item) for item in other if str(item)})

    def copy(self) -> "TaintSet":
        return TaintSet(set(self.taint_ids))

    def is_empty(self) -> bool:
        return not self.taint_ids

    def serialize(self) -> list[str]:
        return sorted(self.taint_ids)

    @classmethod
    def deserialize(cls, value: Any) -> "TaintSet":
        if isinstance(value, TaintSet):
            return value.copy()
        if isinstance(value, list | tuple | set):
            return cls.from_iterable(value)
        if isinstance(value, str) and value:
            return cls({value})
        return cls()


def new_taint_event_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"
