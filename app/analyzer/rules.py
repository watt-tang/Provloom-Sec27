from __future__ import annotations

from app.backend.schemas import EvidenceEvent
from app.runner.models import SandboxExecution


SENSITIVE_PATH_PREFIXES = [
    "/etc/",
    "/root/",
    "/proc/",
    "/sys/",
    "/var/run/",
]

NOISY_FILE_PREFIXES = [
    "/usr/local/lib/python",
    "/usr/local/bin/../lib",
    "/usr/lib/locale",
    "/usr/share/locale",
    "/usr/lib/x86_64-linux-gnu/gconv",
    "/lib/x86_64-linux-gnu/",
]

NOISY_FILE_PATHS = {
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/usr/lib/ssl/cert.pem",
    "/usr/lib/ssl/openssl.cnf",
    "/usr/local/bin/pyvenv.cfg",
    "/usr/local/pyvenv.cfg",
    "/usr/local/bin/pybuilddir.txt",
}

NETWORK_UNKNOWN = "unknown"


def analyze_trace(execution: SandboxExecution) -> dict:
    artifacts = execution.trace_artifacts
    interesting_files = _interesting_file_events(artifacts.files)
    interesting_network = _interesting_network_events(artifacts.network)
    interesting_processes = _interesting_process_events(artifacts.processes)

    score = 0
    detected: set[str] = set()

    if interesting_network:
        score += 30
        detected.add("network_activity")

    if any(event.command in {"/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash"} for event in interesting_processes):
        score += 25
        detected.add("shell_spawn")

    if interesting_processes:
        score += min(20, len(interesting_processes) * 5)
        detected.add("child_process_execution")

    write_events = [event for event in interesting_files if event.action in {"write", "create", "delete_or_rename"}]
    if write_events:
        score += min(20, len(write_events) * 4)
        detected.add("file_write_activity")

    if any(_is_sensitive_path(event.path) for event in interesting_files):
        score += 25
        detected.add("sensitive_file_access")

    if execution.timed_out:
        score += 15
        detected.add("execution_timeout")

    score = min(score, 100)

    return {
        "risk_score": score,
        "detected_behaviors": sorted(detected),
        "trace_summary": {
            "file_event_count": len(interesting_files),
            "network_event_count": len(interesting_network),
            "process_event_count": len(interesting_processes),
            "stdout_line_count": len([line for line in execution.stdout.splitlines() if line.strip()]),
            "stderr_line_count": len([line for line in execution.stderr.splitlines() if line.strip()]),
        },
        "evidence_timeline": [
            EvidenceEvent(**item)
            for item in _filtered_timeline(artifacts.timeline)
        ],
    }


def _is_sensitive_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in SENSITIVE_PATH_PREFIXES)


def _interesting_file_events(events):
    filtered = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        if _is_noisy_file_event(event.path):
            continue
        key = (event.action, event.path)
        if key in seen:
            continue
        seen.add(key)
        filtered.append(event)
    return filtered


def _interesting_network_events(events):
    filtered = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        if event.address == NETWORK_UNKNOWN:
            continue
        key = (event.action, event.address)
        if key in seen:
            continue
        seen.add(key)
        filtered.append(event)
    return filtered


def _interesting_process_events(events):
    filtered = []
    seen_commands: set[str] = set()
    for event in events:
        if event.action != "execve":
            continue
        if event.command in {"/usr/local/bin/python", "python", "python3"}:
            continue
        if event.command == "unknown":
            continue
        if event.command in seen_commands:
            continue
        seen_commands.add(event.command)
        filtered.append(event)
    return filtered


def _filtered_timeline(timeline_items):
    filtered = []
    seen: set[tuple[str, str, str]] = set()
    for item in timeline_items:
        category = item["category"]
        detail = item["detail"]
        action = item["action"]

        if category == "file":
            path = item["metadata"].get("path", "")
            if _is_noisy_file_event(path):
                continue
        elif category == "network":
            if item["metadata"].get("address") == NETWORK_UNKNOWN:
                continue
        elif category == "process":
            command = item["metadata"].get("command")
            if action != "execve" or command in {"unknown", "/usr/local/bin/python", "python", "python3"}:
                continue

        dedupe_key = (category, action, detail)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        filtered.append(item)

    return filtered


def _is_noisy_file_event(path: str) -> bool:
    if not path:
        return True
    if path in NOISY_FILE_PATHS:
        return True
    if any(path.startswith(prefix) for prefix in NOISY_FILE_PREFIXES):
        return True
    return False
