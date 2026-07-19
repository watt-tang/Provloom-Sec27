from __future__ import annotations

import fnmatch
import hashlib
from pathlib import Path

from app.static.artifact_schema import LoadedArtifact, StaticArtifact
from app.static.static_config import StaticAnalysisConfig


class ArtifactLoader:
    def __init__(self, config: StaticAnalysisConfig | None = None) -> None:
        self.config = config or StaticAnalysisConfig()
        self.artifacts: list[StaticArtifact] = []

    def load(self, root: str | Path, skill_file: str = "SKILL.md") -> tuple[list[LoadedArtifact], list[StaticArtifact]]:
        base = Path(root).resolve()
        loaded: list[LoadedArtifact] = []
        total = 0
        candidates = self._candidate_files(base, skill_file)
        for path in candidates:
            rel = _safe_relative(base, path)
            if rel is None:
                self._record(path.name, "unknown", "", 0, "ignored", "path_escape")
                continue
            if len(loaded) >= self.config.max_files:
                self._record(rel, _artifact_type(path), "", 0, "ignored", "max_files_exceeded")
                continue
            if _ignored(rel, self.config.ignore_patterns):
                self._record(rel, _artifact_type(path), "", _size(path), "ignored", "ignore_pattern")
                continue
            if not path.is_file():
                continue
            if not self._supported(path):
                self._record(rel, _artifact_type(path), "", _size(path), "unsupported", "unsupported_extension_or_binary")
                continue
            size = _size(path)
            if size > self.config.max_file_size:
                self._record(rel, _artifact_type(path), "", size, "ignored", "oversized_artifact")
                continue
            if total + size > self.config.max_total_size:
                self._record(rel, _artifact_type(path), "", size, "ignored", "total_size_budget_exceeded")
                continue
            try:
                raw = path.read_bytes()
                text = raw.decode("utf-8", errors="replace")
            except Exception as exc:
                self._record(rel, _artifact_type(path), "", size, "failed", f"read_failure:{exc}")
                continue
            artifact = self._record(rel, _artifact_type(path), hashlib.sha256(raw).hexdigest(), size, "loaded", None)
            loaded.append(LoadedArtifact(artifact=artifact, text=text))
            total += size
        return loaded, list(self.artifacts)

    def _candidate_files(self, base: Path, skill_file: str) -> list[Path]:
        preferred = [base / skill_file, base / "README.md", base / "package.json", base / "manifest.json", base / "pyproject.toml"]
        rest = [path for path in sorted(base.rglob("*")) if path.is_file() and len(path.resolve().relative_to(base).parts) <= self.config.max_depth + 1]
        ordered: list[Path] = []
        seen: set[Path] = set()
        for path in preferred + rest:
            try:
                resolved = path.resolve()
                resolved.relative_to(base)
            except Exception:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            ordered.append(resolved)
        return ordered

    def _supported(self, path: Path) -> bool:
        if path.name in self.config.allowed_filenames or path.name.startswith("README"):
            return True
        if path.suffix.lower() not in self.config.allowed_extensions:
            return False
        try:
            return b"\0" not in path.read_bytes()[:4096]
        except OSError:
            return False

    def _record(self, rel: str, artifact_type: str, sha256: str, size: int, status: str, reason: str | None) -> StaticArtifact:
        artifact = StaticArtifact(
            artifact_id=f"ART{len(self.artifacts) + 1:03d}",
            relative_path=rel,
            artifact_type=artifact_type,
            sha256=sha256,
            size_bytes=size,
            encoding="utf-8" if status == "loaded" else "",
            load_status=status,
            load_reason=reason,
        )
        self.artifacts.append(artifact)
        return artifact


def _safe_relative(base: Path, path: Path) -> str | None:
    try:
        return str(path.resolve().relative_to(base)).replace("\\", "/")
    except Exception:
        return None


def _ignored(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(f"{rel}/", pattern) for pattern in patterns)


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _artifact_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".md", ".txt"}:
        return "markdown" if suffix == ".md" else "text"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".json":
        return "json"
    if suffix == ".toml":
        return "toml"
    if suffix in {".sh", ".bash", ".zsh", ".ps1"}:
        return "shell"
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".ts"}:
        return "javascript"
    if path.name == "Dockerfile":
        return "dockerfile"
    if path.name == "Makefile":
        return "makefile"
    return suffix.lstrip(".") or "unknown"
