from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.taint.models import TaintLabel, TaintSet
from app.taint.source_registry import normalize_path


@dataclass
class FileTaintRecord:
    path: str
    taint_ids: TaintSet = field(default_factory=TaintSet)
    inode: str | None = None
    content_hash: str | None = None
    size: int | None = None
    last_writer_event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "taint_ids": self.taint_ids.serialize(),
            "inode": self.inode,
            "content_hash": self.content_hash,
            "size": self.size,
            "last_writer_event_id": self.last_writer_event_id,
        }


class TaintState:
    """Per-run taint side table. Never persists across sandbox executions."""

    def __init__(self) -> None:
        self.labels: dict[str, TaintLabel] = {}
        self.file_taint_map: dict[str, FileTaintRecord] = {}
        self.action_output_taint: dict[str, TaintSet] = {}
        self.process_taint: dict[str, TaintSet] = {}

    def add_label(self, label: TaintLabel) -> TaintLabel:
        self.labels[label.taint_id] = label
        return label

    def taint_file(self, path: str, taint_ids: TaintSet | list[str] | set[str], *, writer_event_id: str | None = None) -> TaintSet:
        normalized = normalize_path(path)
        if not normalized:
            return TaintSet()
        incoming = TaintSet.deserialize(taint_ids)
        record = self.file_taint_map.get(normalized)
        if record is None:
            record = FileTaintRecord(path=normalized)
            self.file_taint_map[normalized] = record
        record.taint_ids = record.taint_ids.union(incoming)
        if writer_event_id:
            record.last_writer_event_id = writer_event_id
        return record.taint_ids.copy()

    def set_file_taint(self, path: str, taint_ids: TaintSet | list[str] | set[str], *, writer_event_id: str | None = None) -> TaintSet:
        normalized = normalize_path(path)
        if not normalized:
            return TaintSet()
        record = FileTaintRecord(
            path=normalized,
            taint_ids=TaintSet.deserialize(taint_ids),
            last_writer_event_id=writer_event_id,
        )
        self.file_taint_map[normalized] = record
        return record.taint_ids.copy()

    def clear_file(self, path: str) -> None:
        normalized = normalize_path(path)
        if normalized:
            self.file_taint_map.pop(normalized, None)

    def rename_file(self, old_path: str, new_path: str, *, writer_event_id: str | None = None) -> None:
        old = normalize_path(old_path)
        new = normalize_path(new_path)
        if not old or not new:
            return
        record = self.file_taint_map.pop(old, None)
        if record is None:
            return
        record.path = new
        if writer_event_id:
            record.last_writer_event_id = writer_event_id
        self.file_taint_map[new] = record

    def taint_for_file(self, path: str) -> TaintSet:
        record = self.file_taint_map.get(normalize_path(path))
        return record.taint_ids.copy() if record else TaintSet()

    def set_action_output(self, action_id: str, taint_ids: TaintSet | list[str] | set[str]) -> TaintSet:
        taint = TaintSet.deserialize(taint_ids)
        if action_id:
            self.action_output_taint[action_id] = taint.copy()
        return taint

    def taint_for_action(self, action_id: str) -> TaintSet:
        return self.action_output_taint.get(action_id, TaintSet()).copy()

    def labels_for(self, taint_ids: TaintSet | list[str] | set[str]) -> list[TaintLabel]:
        return [self.labels[item] for item in TaintSet.deserialize(taint_ids).serialize() if item in self.labels]
