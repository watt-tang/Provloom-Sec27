from __future__ import annotations

import fnmatch
import os
import posixpath
from dataclasses import dataclass
from typing import Any


DEFAULT_SOURCE_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/root/**",
    "/proc/**",
    "/sys/**",
    "/var/run/**",
    ".provloom/private/**",
    "/workspace/skill/.provloom/private/**",
    "/workspace/.provloom/private/**",
    ".provloom/adapters/credential_state/**",
    "/workspace/skill/.provloom/adapters/credential_state/**",
    "/workspace/.provloom/adapters/credential_state/**",
)

SYNTHETIC_CREDENTIAL_NAMES = {
    "fake.env",
    "fake_token.json",
    "fake_account_profile.json",
    "fake_scopes.txt",
}


@dataclass(frozen=True)
class SourceMatch:
    source_type: str
    sensitivity: str
    normalized_path: str
    metadata: dict[str, Any]


class SourceRegistry:
    """Centralized source classification for dynamic taint analysis."""

    def __init__(
        self,
        *,
        source_paths: list[str] | None = None,
        source_types: dict[str, str] | None = None,
    ) -> None:
        self.source_paths = tuple(source_paths or self._paths_from_env() or DEFAULT_SOURCE_PATHS)
        self.source_types = {
            "public": "public",
            "public_system_configuration": "public",
            "low": "low",
            "medium": "medium",
            "credential": "critical",
            "private_input": "high",
            "sensitive_file": "high",
            **(source_types or {}),
        }

    def match_path(self, path: str) -> SourceMatch | None:
        normalized = normalize_path(path)
        if not normalized:
            return None

        basename = posixpath.basename(normalized)
        if "credential_state/" in normalized or basename in SYNTHETIC_CREDENTIAL_NAMES:
            return SourceMatch(
                source_type="synthetic_credential",
                sensitivity=self.source_types.get("credential", "critical"),
                normalized_path=normalized,
                metadata={"matcher": "synthetic_credential"},
            )

        if ".provloom/private/" in normalized or normalized.startswith(".provloom/private/"):
            return SourceMatch(
                source_type="private_input",
                sensitivity=self.source_types.get("private_input", "high"),
                normalized_path=normalized,
                metadata={"matcher": "private_input"},
            )

        if any(_glob_match(normalized, pattern) for pattern in self.source_paths):
            return SourceMatch(
                source_type="sensitive_file",
                sensitivity=self.source_types.get("sensitive_file", "high"),
                normalized_path=normalized,
                metadata={"matcher": "source_paths"},
            )
        return None

    @staticmethod
    def _paths_from_env() -> list[str]:
        raw = os.environ.get("PROVLOOM_TAINT_SOURCE_PATHS", "")
        return [item.strip() for item in raw.split(os.pathsep) if item.strip()]


def normalize_path(path: str) -> str:
    text = str(path or "").replace("\\", "/").strip()
    if not text or text == "unknown":
        return ""
    if text.startswith("/workspace/skill/"):
        text = text[len("/workspace/skill/") :]
    return posixpath.normpath(text)


def _glob_match(path: str, pattern: str) -> bool:
    normalized_pattern = normalize_path(pattern)
    if fnmatch.fnmatch(path, normalized_pattern):
        return True
    if not path.startswith("/") and fnmatch.fnmatch(f"/workspace/skill/{path}", pattern):
        return True
    return False
