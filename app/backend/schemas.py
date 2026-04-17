from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class LLMConfig:
    enabled: bool = False
    provider: str = "deepseek"
    base_url: str = "https://api.deepseek.com"
    api_key: str = ""
    model: str = "deepseek-chat"
    temperature: float = 0.0
    max_steps: int = 8

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LLMConfig":
        enabled = bool(payload.get("enabled", False))
        provider = payload.get("provider", "deepseek")
        base_url = payload.get("base_url", "https://api.deepseek.com")
        api_key = payload.get("api_key", "")
        model = payload.get("model", "deepseek-chat")
        temperature = float(payload.get("temperature", 0.0))
        max_steps = int(payload.get("max_steps", 8))
        if enabled and not api_key:
            raise ValueError("`llm_config.api_key` is required when llm_config.enabled=true.")
        return cls(
            enabled=enabled,
            provider=provider,
            base_url=base_url,
            api_key=api_key,
            model=model,
            temperature=temperature,
            max_steps=max_steps,
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "temperature": self.temperature,
            "max_steps": self.max_steps,
        }


@dataclass
class AnalyzeSkillRequest:
    skill_path: str
    input_payload: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 30
    network_policy: str = "default"
    llm_config: LLMConfig = field(default_factory=LLMConfig)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AnalyzeSkillRequest":
        skill_path = payload.get("skill_path")
        input_payload = payload.get("input_payload", {})
        timeout_seconds = payload.get("timeout_seconds", 30)
        network_policy = payload.get("network_policy", "default")
        llm_config = LLMConfig.from_dict(payload.get("llm_config", {}))

        if not isinstance(skill_path, str) or not skill_path.strip():
            raise ValueError("`skill_path` must be a non-empty string.")
        if not isinstance(input_payload, dict):
            raise ValueError("`input_payload` must be a JSON object.")
        if not isinstance(timeout_seconds, int) or not (1 <= timeout_seconds <= 300):
            raise ValueError("`timeout_seconds` must be an integer between 1 and 300.")
        if network_policy not in {"default", "disabled"}:
            raise ValueError("`network_policy` must be one of: default, disabled.")

        return cls(
            skill_path=skill_path,
            input_payload=input_payload,
            timeout_seconds=timeout_seconds,
            network_policy=network_policy,
            llm_config=llm_config,
        )


@dataclass
class EvidenceEvent:
    timestamp: str
    category: str
    action: str
    detail: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalyzeSkillResponse:
    execution_id: str
    status: str
    skill_path: str
    skill_file: str
    sandbox_image: str
    runtime_name: str
    network_policy: str
    llm_config: dict[str, Any]
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    trace_summary: dict[str, Any]
    risk_score: int
    risk_level: str
    risk_level_name: str
    primary_risk: dict[str, Any]
    risk_labels: list[dict[str, Any]]
    risk_summary: str
    detected_behaviors: list[str]
    evidence_timeline: list[EvidenceEvent]
    file_events: list[dict[str, Any]]
    network_events: list[dict[str, Any]]
    process_events: list[dict[str, Any]]
    tool_calls: list[dict[str, Any]]
    llm_events: list[dict[str, Any]]
    data_flows: list[dict[str, Any]]
    resource_usage: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TaskResponse:
    execution_id: str
    status: str
    created_at: str
    updated_at: str
    request: dict[str, Any]
    result: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
