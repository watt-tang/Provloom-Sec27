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
    interesting_files = _interesting_file_events(execution.file_events)
    interesting_network = _interesting_network_events(execution.network_events)
    interesting_processes = _interesting_process_events(execution.process_events)

    score = 0
    detected: set[str] = set()

    if interesting_network:
        score += 30
        detected.add("network_access")

    if any(event.command in {"/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash"} for event in interesting_processes):
        score += 25
        detected.add("shell_execution")

    if interesting_processes:
        score += min(20, len(interesting_processes) * 5)
        detected.add("process_spawn")

    write_events = [event for event in interesting_files if event.action in {"write", "create", "delete_or_rename"}]
    if write_events:
        score += min(20, len(write_events) * 4)
        detected.add("file_write")

    if any(_is_sensitive_path(event.path) for event in interesting_files):
        score += 25
        detected.add("sensitive_file_read")

    if _has_read_then_exfiltration(interesting_files, interesting_network):
        score += 20
        detected.add("read_then_exfiltration")

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
            "tool_call_count": len(execution.tool_calls),
            "llm_event_count": len(execution.llm_events),
            "stdout_line_count": len([line for line in execution.stdout.splitlines() if line.strip()]),
            "stderr_line_count": len([line for line in execution.stderr.splitlines() if line.strip()]),
        },
        "evidence_timeline": [
            EvidenceEvent(**item)
            for item in _filtered_timeline(execution, interesting_files, interesting_network, interesting_processes)
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


def _filtered_timeline(execution: SandboxExecution, files, network, processes):
    timeline = []
    for event in files:
        timeline.append(
            {
                "timestamp": event.timestamp,
                "category": "file",
                "action": event.action,
                "detail": f"{event.action} {event.path}",
                "metadata": {"path": event.path, "pid": event.pid},
            }
        )
    for event in network:
        timeline.append(
            {
                "timestamp": event.timestamp,
                "category": "network",
                "action": event.action,
                "detail": f"{event.action} {event.address}",
                "metadata": {"address": event.address, "pid": event.pid},
            }
        )
    for event in processes:
        timeline.append(
            {
                "timestamp": event.timestamp,
                "category": "process",
                "action": event.action,
                "detail": f"{event.action} {event.command}",
                "metadata": {"command": event.command, "pid": event.pid},
            }
        )
    for event in execution.tool_calls:
        timeline.append(
            {
                "timestamp": event.timestamp,
                "category": "tool_call",
                "action": event.event,
                "detail": f"{event.event} {event.tool_name} ({event.tool_type})",
                "metadata": {
                    "tool_id": event.tool_id,
                    "tool_name": event.tool_name,
                    "tool_type": event.tool_type,
                    "status": event.status,
                },
            }
        )
    for event in execution.llm_events:
        timeline.append(
            {
                "timestamp": event.timestamp,
                "category": "llm",
                "action": event.event,
                "detail": f"{event.event} llm",
                "metadata": event.metadata,
            }
        )
    for event in execution.data_flows:
        timeline.append(
            {
                "timestamp": event.timestamp,
                "category": "data_flow",
                "action": "source_to_sink",
                "detail": f"{event.source_detail} -> {event.sink_detail}",
                "metadata": event.to_dict(),
            }
        )
    timeline.sort(key=lambda item: item["timestamp"])
    return timeline


def _is_noisy_file_event(path: str) -> bool:
    if not path:
        return True
    if path in NOISY_FILE_PATHS:
        return True
    if any(path.startswith(prefix) for prefix in NOISY_FILE_PREFIXES):
        return True
    return False


def _has_read_then_exfiltration(files, network) -> bool:
    sensitive_reads = [event for event in files if _is_sensitive_path(event.path)]
    if not sensitive_reads or not network:
        return False
    first_read = min(event.timestamp for event in sensitive_reads)
    first_network = min(event.timestamp for event in network)
    return first_read <= first_network
