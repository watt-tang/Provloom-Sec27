from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from app.instruction.models import Document


IGNORE_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "__pycache__",
    "build",
    "dist",
    ".venv",
    "venv",
    "env",
    ".env",
    "artifacts",
    "runtime_output",
    "generated",
}

ALLOWED_SUFFIXES = {
    ".md",
    ".json",
    ".toml",
    ".txt",
    ".cfg",
    ".ini",
    ".yaml",
    ".yml",
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".ts",
    ".ps1",
    ".dockerfile",
    ".makefile",
}

SPECIAL_FILENAMES = {
    "SKILL.md",
    "README",
    "README.md",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "Dockerfile",
    "Makefile",
}


@dataclass
class DocumentLoaderConfig:
    max_file_size: int = 256 * 1024
    max_total_size: int = 1024 * 1024
    max_depth: int = 4
    max_files: int = 80
    allowed_suffixes: set[str] = field(default_factory=lambda: set(ALLOWED_SUFFIXES))
    ignore_dirs: set[str] = field(default_factory=lambda: set(IGNORE_DIRS))


@dataclass
class LoadedDocument:
    document: Document
    text: str


class DocumentLoader:
    def __init__(self, config: DocumentLoaderConfig | None = None) -> None:
        self.config = config or DocumentLoaderConfig()

    def load(self, root: str | Path, skill_file: str = "SKILL.md") -> list[LoadedDocument]:
        base = Path(root).resolve()
        candidates = self._candidate_files(base, skill_file)
        loaded: list[LoadedDocument] = []
        total = 0
        for path in candidates:
            if len(loaded) >= self.config.max_files or total >= self.config.max_total_size:
                break
            try:
                resolved = path.resolve()
                resolved.relative_to(base)
            except Exception:
                continue
            if not resolved.is_file() or self._is_binaryish(resolved):
                continue
            try:
                size = resolved.stat().st_size
            except OSError:
                continue
            if size <= 0:
                continue
            read_size = min(size, self.config.max_file_size, self.config.max_total_size - total)
            try:
                raw = resolved.read_bytes()[:read_size]
            except OSError:
                continue
            text = raw.decode("utf-8", errors="replace")
            rel = str(resolved.relative_to(base)).replace("\\", "/")
            document = Document(
                document_id=_doc_id(rel),
                relative_path=rel,
                file_type=_file_type(resolved),
                content_hash=hashlib.sha256(raw).hexdigest(),
                size=size,
                encoding="utf-8",
                parse_status="parsed",
                truncated=read_size < size,
            )
            loaded.append(LoadedDocument(document=document, text=text))
            total += len(raw)
        return loaded

    def _candidate_files(self, base: Path, skill_file: str) -> list[Path]:
        preferred = [(base / skill_file), base / "README.md", base / "package.json", base / "pyproject.toml"]
        rest: list[Path] = []
        for path in sorted(base.rglob("*")):
            if not self._allowed_path(base, path):
                continue
            rest.append(path)
        ordered: list[Path] = []
        seen: set[Path] = set()
        for path in preferred + rest:
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            ordered.append(path)
        return ordered

    def _allowed_path(self, base: Path, path: Path) -> bool:
        try:
            rel = path.resolve().relative_to(base)
        except Exception:
            return False
        if len(rel.parts) > self.config.max_depth + 1:
            return False
        if rel.parts[:2] == (".provloom", "private"):
            return False
        if any(part in self.config.ignore_dirs for part in rel.parts[:-1]):
            return False
        name = path.name
        if name in SPECIAL_FILENAMES or name.startswith("README-"):
            return True
        suffix = path.suffix.lower()
        if suffix in self.config.allowed_suffixes:
            return True
        return name.lower() in {"dockerfile", "makefile"}

    @staticmethod
    def _is_binaryish(path: Path) -> bool:
        try:
            sample = path.read_bytes()[:2048]
        except OSError:
            return True
        return b"\x00" in sample


def _doc_id(relative_path: str) -> str:
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:12]
    return f"doc-{digest}"


def _file_type(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix == ".md":
        return "markdown"
    if suffix == ".json":
        return "json"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".toml":
        return "toml"
    if suffix in {".sh", ".bash", ".zsh", ".ps1"}:
        return "shell"
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".ts"}:
        return "javascript"
    if name in {"dockerfile", "makefile"}:
        return name
    return "text"
