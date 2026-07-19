from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


COVERAGE_STATES = {
    "triggered_and_observed",
    "triggered_but_partially_observed",
    "instruction_seen_but_not_executed",
    "not_triggered",
    "unsupported_tool",
    "unsupported_environment",
    "external_state_missing",
    "user_confirmation_missing",
    "endpoint_unavailable",
    "execution_failed",
    "timeout",
    "analysis_error",
}


@dataclass
class MarkerConfig:
    prefix: str = "PROVLOOM_SECRET"
    bytes_of_entropy: int = 8
    include_hash_derivatives: bool = True


@dataclass
class ClosureLiftConfig:
    enabled: bool = True
    max_depth: int = 1
    max_files_per_session: int = 4
    max_file_bytes: int = 64 * 1024
    extensions: list[str] = field(default_factory=lambda: [".md", ".txt", ".yaml", ".yml", ".json"])


@dataclass
class DynamicAnalysisConfig:
    sensitive_source_patterns: list[str] = field(
        default_factory=lambda: [
            "/etc/passwd",
            "/etc/shadow",
            "/root/**",
            "/workspace/skill/.provloom/private/**",
            ".provloom/adapters/credential_state/**",
        ]
    )
    trusted_egress_allowlist: list[str] = field(default_factory=list)
    trusted_domains: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    allowed_tool_destinations: dict[str, list[str]] = field(default_factory=dict)
    permitted_source_to_sink_pairs: list[dict[str, str]] = field(default_factory=list)
    writable_directory_allowlist: list[str] = field(default_factory=lambda: ["runtime_output", "/tmp", "/workspace/skill"])
    executable_allowlist: list[str] = field(default_factory=lambda: ["/bin/sh", "/bin/bash", "python", "python3"])
    trusted_download_domains: list[str] = field(default_factory=list)
    persistence_targets: list[str] = field(default_factory=lambda: ["/etc/cron*", "~/.config/systemd/**", "crontab"])
    protected_files: list[str] = field(default_factory=lambda: ["/etc/**", "/root/**", "~/.ssh/**"])
    permitted_installation_paths: list[str] = field(default_factory=lambda: ["/workspace/skill", "runtime_output"])
    maximum_runtime_seconds: int = 30
    closure_lift: ClosureLiftConfig = field(default_factory=ClosureLiftConfig)
    marker: MarkerConfig = field(default_factory=MarkerConfig)
    evidence_thresholds: dict[str, float] = field(default_factory=lambda: {"confirmed": 1.0, "conservative": 0.7, "candidate": 0.3})
    network_capture_options: dict[str, Any] = field(default_factory=lambda: {"capture_payload_preview": True, "max_preview_bytes": 4096})
    mock_service_endpoints: list[str] = field(default_factory=lambda: ["http://127.0.0.1:18080/collect"])

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "DynamicAnalysisConfig":
        payload = dict(payload or {})
        marker_payload = payload.pop("marker", None)
        lift_payload = payload.pop("closure_lift", None)
        config = cls(**payload)
        if marker_payload:
            config.marker = MarkerConfig(**marker_payload)
        if lift_payload:
            config.closure_lift = ClosureLiftConfig(**lift_payload)
        return config

    @classmethod
    def load(cls, path: str | Path | None) -> "DynamicAnalysisConfig":
        if not path:
            return cls()
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.maximum_runtime_seconds <= 0:
            errors.append("maximum_runtime_seconds must be positive")
        if self.closure_lift.max_depth < 0:
            errors.append("closure_lift.max_depth must be non-negative")
        if self.closure_lift.max_files_per_session < 0:
            errors.append("closure_lift.max_files_per_session must be non-negative")
        if self.marker.bytes_of_entropy < 4:
            errors.append("marker.bytes_of_entropy must be >= 4")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
