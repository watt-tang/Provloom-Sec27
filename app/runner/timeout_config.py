from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any


DEFAULT_TOTAL_TIMEOUT_SECONDS = 600
DEFAULT_LLM_REQUEST_TIMEOUT_SECONDS = 120
DEFAULT_LLM_MAX_RETRIES = 2


@dataclass(frozen=True)
class TimeoutResolution:
    total_timeout_seconds: int
    llm_request_timeout_seconds: int = DEFAULT_LLM_REQUEST_TIMEOUT_SECONDS
    llm_max_retries: int = DEFAULT_LLM_MAX_RETRIES
    source: str = "default"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def resolve_total_timeout(
    explicit: int | None = None,
    *,
    fixture: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
    default: int = DEFAULT_TOTAL_TIMEOUT_SECONDS,
) -> TimeoutResolution:
    env = env if env is not None else os.environ
    if explicit is not None:
        return TimeoutResolution(_clamp_timeout(explicit), source="explicit")

    fixture_value = _fixture_timeout(fixture or {})
    if fixture_value is not None:
        return TimeoutResolution(_clamp_timeout(fixture_value), source="fixture")

    env_value = env.get("PROVLOOM_TIMEOUT_SECONDS") or env.get("PROVLOOM_TOTAL_TIMEOUT_SECONDS")
    if env_value:
        return TimeoutResolution(_clamp_timeout(env_value), source="environment")

    return TimeoutResolution(_clamp_timeout(default), source="default")


def _fixture_timeout(fixture: dict[str, Any]) -> int | None:
    for key in ("timeout_seconds", "total_timeout_seconds"):
        if fixture.get(key) is not None:
            return int(fixture[key])
    runtime = fixture.get("runtime") if isinstance(fixture.get("runtime"), dict) else {}
    for key in ("timeout_seconds", "total_timeout_seconds"):
        if runtime.get(key) is not None:
            return int(runtime[key])
    return None


def _clamp_timeout(value: int | str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise ValueError("timeout must be >= 1 second")
    return parsed

