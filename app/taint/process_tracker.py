from __future__ import annotations

from app.taint.models import TaintSet
from app.taint.state import TaintState


class ProcessTaintTracker:
    def __init__(self, state: TaintState) -> None:
        self.state = state

    def set_process_taint(self, pid: str | None, taint_ids) -> TaintSet:
        if not pid:
            return TaintSet()
        taint = TaintSet.deserialize(taint_ids)
        self.state.process_taint[pid] = taint
        return taint.copy()

    def inherit(self, parent_pid: str | None, child_pid: str | None) -> TaintSet:
        if not parent_pid or not child_pid:
            return TaintSet()
        taint = self.state.process_taint.get(parent_pid, TaintSet()).copy()
        self.state.process_taint[child_pid] = taint
        return taint

    def get(self, pid: str | None) -> TaintSet:
        if not pid:
            return TaintSet()
        return self.state.process_taint.get(pid, TaintSet()).copy()
