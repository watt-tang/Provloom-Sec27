from __future__ import annotations

import re
from pathlib import Path

from app.runner.models import FileEvent, NetworkEvent, ProcessEvent, TraceArtifacts

TRACE_RE = re.compile(r"^(?P<ts>\d{2}:\d{2}:\d{2}\.\d{6}) (?P<body>.*)$")
STRING_RE = re.compile(r'"([^"]+)"')
CONNECT_RE = re.compile(r'connect\([^)]*sin_port=htons\((?P<port>\d+)\), sin_addr=inet_addr\("(?P<host>[^"]+)"\)')


def parse_trace_dir(trace_dir: Path) -> TraceArtifacts:
    artifacts = TraceArtifacts()
    for trace_file in sorted(trace_dir.glob("trace.log*")):
        pid = trace_file.name.split(".")[-1] if "." in trace_file.name else None
        for line in trace_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = _parse_line(line=line, pid=pid)
            if not parsed:
                continue
            category, event = parsed
            if category == "file":
                artifacts.files.append(event)
            elif category == "network":
                artifacts.network.append(event)
            elif category == "process":
                artifacts.processes.append(event)
            artifacts.timeline.append(_to_timeline_item(category, event))
    artifacts.timeline.sort(key=lambda item: item["timestamp"])
    return artifacts


def _parse_line(line: str, pid: str | None):
    match = TRACE_RE.match(line.strip())
    if not match:
        return None
    timestamp = match.group("ts")
    body = match.group("body")

    if body.startswith(("open(", "openat(", "openat2(")):
        return "file", _parse_file_open(timestamp, body, pid)
    if body.startswith(("unlink(", "unlinkat(", "rename(", "renameat(")):
        return "file", FileEvent(timestamp=timestamp, path=_extract_first_string(body), action="delete_or_rename", raw=body, pid=pid)
    if body.startswith(("execve(", "clone(", "clone3(", "vfork(", "fork(")):
        return "process", _parse_process(timestamp, body, pid)
    if body.startswith("connect("):
        return "network", _parse_network(timestamp, body, pid)
    return None


def _parse_file_open(timestamp: str, body: str, pid: str | None) -> FileEvent:
    path = _extract_first_string(body)
    action = "read"
    if "O_WRONLY" in body or "O_RDWR" in body:
        action = "write"
    if "O_CREAT" in body:
        action = "create"
    return FileEvent(timestamp=timestamp, path=path, action=action, raw=body, pid=pid)


def _parse_process(timestamp: str, body: str, pid: str | None) -> ProcessEvent:
    if "= -1 ENOENT" in body:
        return ProcessEvent(timestamp=timestamp, action="skip", command="skip", raw=body, pid=pid)
    command = _extract_first_string(body)
    action = body.split("(", 1)[0]
    return ProcessEvent(timestamp=timestamp, action=action, command=command, raw=body, pid=pid)


def _parse_network(timestamp: str, body: str, pid: str | None) -> NetworkEvent:
    match = CONNECT_RE.search(body)
    if match:
        address = f"{match.group('host')}:{match.group('port')}"
    else:
        address = "unknown"
    return NetworkEvent(timestamp=timestamp, address=address, action="connect", raw=body, pid=pid)


def _extract_first_string(text: str) -> str:
    match = STRING_RE.search(text)
    return match.group(1) if match else "unknown"


def _to_timeline_item(category: str, event):
    if category == "file":
        detail = f"{event.action} {event.path}"
        metadata = {"path": event.path, "pid": event.pid}
        action = event.action
    elif category == "network":
        detail = f"{event.action} {event.address}"
        metadata = {"address": event.address, "pid": event.pid}
        action = event.action
    else:
        detail = f"{event.action} {event.command}"
        metadata = {"command": event.command, "pid": event.pid}
        action = event.action

    return {
        "timestamp": event.timestamp,
        "category": category,
        "action": action,
        "detail": detail,
        "metadata": metadata,
    }
