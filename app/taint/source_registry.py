from __future__ import annotations

import fnmatch
import os
import posixpath
from dataclasses import dataclass
from typing import Any


DEFAULT_SOURCE_PATHS = (
    "/etc/shadow",
    "/root/.ssh/id_*",
    "/root/.aws/credentials",
    "/root/.config/gcloud/**",
    "/root/.azure/**",
    "/root/.docker/config.json",
    "**/.env",
    "**/.env.*",
    ".provloom/private/**",
    "/workspace/skill/.provloom/private/**",
    "/workspace/.provloom/private/**",
    ".provloom/adapters/credential_state/**",
    "/workspace/skill/.provloom/adapters/credential_state/**",
    "/workspace/.provloom/adapters/credential_state/**",
)

SYSTEM_SOURCE_RULES: tuple[dict[str, str], ...] = (
    {"pattern": "/etc/hosts", "source_type": "public_system_configuration", "sensitivity": "public", "category": "public_system_configuration"},
    {"pattern": "/etc/passwd", "source_type": "account_metadata", "sensitivity": "low", "category": "account_metadata"},
    {"pattern": "/etc/shadow", "source_type": "system_secret", "sensitivity": "critical", "category": "system_secret"},
    {"pattern": "/root/.ssh/id_*", "source_type": "credential_secret", "sensitivity": "critical", "category": "credential_secret"},
    {"pattern": "**/.ssh/id_*", "source_type": "credential_secret", "sensitivity": "critical", "category": "credential_secret"},
    {"pattern": "**/.env", "source_type": "credential_secret", "sensitivity": "high", "category": "credential_secret"},
    {"pattern": "**/.env.*", "source_type": "credential_secret", "sensitivity": "high", "category": "credential_secret"},
    {"pattern": "/root/.aws/credentials", "source_type": "credential_secret", "sensitivity": "critical", "category": "credential_secret"},
    {"pattern": "**/.aws/credentials", "source_type": "credential_secret", "sensitivity": "critical", "category": "credential_secret"},
    {"pattern": "/root/.config/gcloud/**", "source_type": "credential_secret", "sensitivity": "critical", "category": "credential_secret"},
    {"pattern": "/root/.azure/**", "source_type": "credential_secret", "sensitivity": "critical", "category": "credential_secret"},
    {"pattern": "/root/.docker/config.json", "source_type": "credential_secret", "sensitivity": "critical", "category": "credential_secret"},
    {"pattern": "/root/.cache/**", "source_type": "runtime_internal", "sensitivity": "public", "category": "package_cache"},
    {"pattern": "**/.cache/**", "source_type": "runtime_internal", "sensitivity": "public", "category": "package_cache"},
    {"pattern": "**/pip/**", "source_type": "runtime_internal", "sensitivity": "public", "category": "package_cache"},
    {"pattern": "**/node_modules/**", "source_type": "runtime_internal", "sensitivity": "public", "category": "package_cache"},
    {"pattern": "**/.npm/**", "source_type": "runtime_internal", "sensitivity": "public", "category": "package_cache"},
    {"pattern": "**/.provloom/private/**", "source_type": "private_input", "sensitivity": "high", "category": "private_user_data"},
    {"pattern": "**/.provloom/adapters/credential_state/**", "source_type": "synthetic_credential", "sensitivity": "critical", "category": "credential_secret"},
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

    @property
    def category(self) -> str:
        return str(self.metadata.get("category") or self.source_type)


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
        self.system_rules = SYSTEM_SOURCE_RULES

    def match_path(self, path: str) -> SourceMatch | None:
        normalized = normalize_path(path)
        if not normalized:
            return None

        for rule in self.system_rules:
            pattern = rule["pattern"]
            if _glob_match(normalized, pattern):
                return SourceMatch(
                    source_type=rule["source_type"],
                    sensitivity=self.source_types.get(rule["source_type"], rule["sensitivity"]),
                    normalized_path=normalized,
                    metadata={
                        "matcher": "source_policy_rule",
                        "rule_pattern": pattern,
                        "category": rule["category"],
                    },
                )

        basename = posixpath.basename(normalized)
        if "credential_state/" in normalized or basename in SYNTHETIC_CREDENTIAL_NAMES:
            return SourceMatch(
                source_type="synthetic_credential",
                sensitivity=self.source_types.get("credential", "critical"),
                normalized_path=normalized,
                metadata={"matcher": "synthetic_credential", "category": "credential_secret"},
            )

        if ".provloom/private/" in normalized or normalized.startswith(".provloom/private/"):
            return SourceMatch(
                source_type="private_input",
                sensitivity=self.source_types.get("private_input", "high"),
                normalized_path=normalized,
                metadata={"matcher": "private_input", "category": "private_user_data"},
            )

        if any(_glob_match(normalized, pattern) for pattern in self.source_paths):
            return SourceMatch(
                source_type="sensitive_file",
                sensitivity=self.source_types.get("sensitive_file", "high"),
                normalized_path=normalized,
                metadata={"matcher": "source_paths", "category": "policy_defined"},
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
