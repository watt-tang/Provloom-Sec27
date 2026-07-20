from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class StaticAnalysisConfig:
    max_file_size: int = 256 * 1024
    max_total_size: int = 2 * 1024 * 1024
    max_depth: int = 5
    max_files: int = 160
    ignore_patterns: list[str] = field(default_factory=lambda: [".git/**", "node_modules/**", "dist/**", "build/**", "vendor/**", "__pycache__/**", "artifacts/**", "skillscan/**", "skillscan_results/**"])
    allowed_extensions: list[str] = field(default_factory=lambda: [".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".ps1"])
    allowed_filenames: list[str] = field(default_factory=lambda: ["SKILL.md", "README", "README.md", "Dockerfile", "Makefile", "package.json", "manifest.json", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg"])
    trusted_domains: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    protected_resource_patterns: list[str] = field(default_factory=lambda: ["~/.ssh/**", "~/.aws/**", ".env", "/etc/**", "/root/**"])
    prompt_version: str = "provloom-static-action-extraction-v2"
    llm_enabled: bool = True
    llm_base_url: str = "https://api.siliconflow.com/v1"
    llm_api_key: str = field(default_factory=lambda: os.environ.get("PROVLOOM_STATIC_LLM_API_KEY", ""))
    llm_model: str = "deepseek-ai/DeepSeek-V4-Pro"
    llm_temperature: float = 0.0
    llm_request_timeout_seconds: int = 45
    llm_max_candidate_actions: int = 16
    llm_candidate_batch_size: int = 4
    llm_filter_deterministic_actions: bool = True

    @classmethod
    def load(cls, path: str | Path | None = None) -> "StaticAnalysisConfig":
        if not path:
            return cls()
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "StaticAnalysisConfig":
        return cls(**dict(payload or {}))

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.max_file_size <= 0:
            errors.append("max_file_size must be positive")
        if self.max_total_size <= 0:
            errors.append("max_total_size must be positive")
        if self.max_files <= 0:
            errors.append("max_files must be positive")
        if self.llm_temperature != 0.0:
            errors.append("llm_temperature must remain 0.0 for reproducibility")
        if self.llm_enabled and not self.llm_base_url:
            errors.append("llm_base_url is required when llm_enabled=true")
        if self.llm_request_timeout_seconds <= 0:
            errors.append("llm_request_timeout_seconds must be positive")
        return errors

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if payload.get("llm_api_key"):
            payload["llm_api_key"] = "***"
        return payload
