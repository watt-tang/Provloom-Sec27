from __future__ import annotations

from app.taint.state import TaintState


class FileTaintTracker:
    def __init__(self, state: TaintState) -> None:
        self.state = state

    def read(self, path: str):
        return self.state.taint_for_file(path)

    def write(self, path: str, taint_ids, *, append: bool = False, event_id: str | None = None):
        if append:
            return self.state.taint_file(path, taint_ids, writer_event_id=event_id)
        return self.state.set_file_taint(path, taint_ids, writer_event_id=event_id)

    def overwrite_clean(self, path: str) -> None:
        self.state.clear_file(path)

    def delete(self, path: str) -> None:
        self.state.clear_file(path)

    def rename(self, old_path: str, new_path: str, *, event_id: str | None = None) -> None:
        self.state.rename_file(old_path, new_path, writer_event_id=event_id)
