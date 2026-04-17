from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FileEvent:
    timestamp: str
    path: str
    action: str
    raw: str
    pid: str | None = None


@dataclass
class NetworkEvent:
    timestamp: str
    address: str
    action: str
    raw: str
    pid: str | None = None


@dataclass
class ProcessEvent:
    timestamp: str
    action: str
    command: str
    raw: str
    pid: str | None = None


@dataclass
class TraceArtifacts:
    files: list[FileEvent] = field(default_factory=list)
    network: list[NetworkEvent] = field(default_factory=list)
    processes: list[ProcessEvent] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SandboxExecution:
    skill_path: str
    sandbox_image: str
    command: list[str]
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    trace_artifacts: TraceArtifacts
    artifacts_dir: str
