from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from app.dynamic.config import ClosureLiftConfig
from app.dynamic.event_schema import RuntimeEventFactory
from app.dynamic.models import RuntimeEvent


HTTP_POST_RE = re.compile(r"\bPOST\s+(?P<url>https?://\S+)", re.I)
READ_RE = re.compile(r"\bread\s+(?P<path>[/A-Za-z0-9_.-][^\s]*)", re.I)


class RuntimeInstructionLift:
    def __init__(self, *, skill_root: str | Path, config: ClosureLiftConfig | None = None) -> None:
        self.skill_root = Path(skill_root).resolve()
        self.config = config or ClosureLiftConfig()
        self._processed_hashes: set[str] = set()
        self._processed_count = 0

    def discover(self, events: list[RuntimeEvent], *, depth: int = 0) -> list[RuntimeEvent]:
        if not self.config.enabled or depth > self.config.max_depth or self._processed_count >= self.config.max_files_per_session:
            return []
        generated = [
            event
            for event in events
            if event.operation in {"write", "materialize_instruction"} and event.object_path and Path(event.object_path).suffix in self.config.extensions
        ]
        lifted: list[RuntimeEvent] = []
        factory = RuntimeEventFactory(session_id=events[0].session_id if events else "RUN", skill_id=events[0].skill_id if events else "SKILL")
        for event in generated:
            target = self._resolve(event.object_path)
            if target is None or not target.exists() or target.stat().st_size > self.config.max_file_bytes:
                continue
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if digest in self._processed_hashes:
                continue
            self._processed_hashes.add(digest)
            self._processed_count += 1
            instruction_event = factory.create(
                timestamp=event.timestamp + 0.0001,
                event_type="runtime_instruction_seen",
                process_id=event.process_id,
                parent_process_id=event.parent_process_id,
                actor_type="agent",
                actor_id="AGENT:runtime",
                object_type="instruction",
                object_id=f"INSTR:{digest[:16]}",
                object_path=str(target.relative_to(self.skill_root)),
                operation="materialize_instruction",
                raw_source="closure_lift",
                raw_reference=event.event_id,
                metadata={"file_hash": digest, "lift_depth": depth, "runtime_materialized": True},
            )
            lifted.append(instruction_event)
            lifted.extend(RuntimeInstructionAdapter(factory=factory).execute(target, parent_event=instruction_event))
            if self._processed_count >= self.config.max_files_per_session:
                break
        return lifted

    def _resolve(self, object_path: str) -> Path | None:
        candidate = Path(object_path)
        if not candidate.is_absolute():
            candidate = self.skill_root / candidate
        try:
            resolved = candidate.resolve()
            resolved.relative_to(self.skill_root)
        except Exception:
            return None
        return resolved


class RuntimeInstructionAdapter:
    """Small real adapter for untrusted runtime materialized instruction text."""

    def __init__(self, *, factory: RuntimeEventFactory) -> None:
        self.factory = factory

    def execute(self, path: Path, *, parent_event: RuntimeEvent) -> list[RuntimeEvent]:
        text = path.read_text(encoding="utf-8", errors="replace")
        events: list[RuntimeEvent] = []
        for match in READ_RE.finditer(text):
            target = match.group("path").strip().rstrip(".,")
            events.append(
                self.factory.create(
                    timestamp=parent_event.timestamp + 0.001 + len(events) * 0.001,
                    event_type="file_read",
                    process_id=parent_event.process_id,
                    actor_type="tool",
                    actor_id="TOOL:runtime_instruction_read_file",
                    object_type="file",
                    object_id=f"FILE:{target}",
                    object_path=target,
                    operation="read",
                    raw_source="closure_lift_adapter",
                    raw_reference=parent_event.event_id,
                    metadata={"runtime_materialized_instruction": str(path), "adapter": "read_file"},
                )
            )
        for match in HTTP_POST_RE.finditer(text):
            url = match.group("url").strip().rstrip(".,")
            events.append(
                self.factory.create(
                    timestamp=parent_event.timestamp + 0.002 + len(events) * 0.001,
                    event_type="network_send",
                    process_id=parent_event.process_id,
                    actor_type="tool",
                    actor_id="TOOL:runtime_instruction_http_request",
                    object_type="network",
                    object_id=f"NET:{url}",
                    operation="send",
                    raw_source="closure_lift_adapter",
                    raw_reference=parent_event.event_id,
                    metadata={"url": url, "method": "POST", "runtime_materialized_instruction": str(path), "adapter": "http_request"},
                    opaque_payload=True,
                )
            )
        return events
