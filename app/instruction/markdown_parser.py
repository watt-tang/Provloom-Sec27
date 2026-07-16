from __future__ import annotations

import re
from typing import Iterable

from app.instruction.document_loader import LoadedDocument
from app.instruction.models import DocumentSpan


FENCE_START_RE = re.compile(r"^\s*```(?P<info>.*)$")
HEADING_RE = re.compile(r"^(?P<marks>#{1,6})\s+(?P<title>.+?)\s*$")
WARNING_RE = re.compile(r"\b(warning|caution|security notice|do not|never|avoid)\b", re.I)
EXAMPLE_RE = re.compile(r"\b(for example|attacker might|attacker may|such as)\b|(?:^|\s)examples?\s*:", re.I)
OPTIONAL_RE = re.compile(r"\b(optional|optionally|you may|if you want)\b", re.I)
CONDITIONAL_RE = re.compile(r"\b(if|when|unless|provided that)\b", re.I)
DEFENSIVE_RE = re.compile(r"\b(detects?|scanner|prevents?|protects?|defensive|security notice)\b", re.I)
PROHIBITION_RE = re.compile(r"\b(do not|don't|never|must not|should not|avoid)\b", re.I)


class MarkdownParser:
    def parse_many(self, documents: Iterable[LoadedDocument]) -> list[DocumentSpan]:
        spans: list[DocumentSpan] = []
        for loaded in documents:
            spans.extend(self.parse(loaded))
        return spans

    def parse(self, loaded: LoadedDocument) -> list[DocumentSpan]:
        if loaded.document.file_type != "markdown":
            return self._parse_plain_document(loaded)

        text = loaded.text
        lines = text.splitlines(keepends=True)
        offsets = _line_offsets(lines)
        spans: list[DocumentSpan] = []
        section_stack: list[tuple[int, str]] = []
        index = 0
        span_index = 0
        in_frontmatter = False
        if lines and lines[0].strip() == "---":
            in_frontmatter = True

        while index < len(lines):
            raw = lines[index]
            stripped = raw.strip()
            line_no = index + 1

            if in_frontmatter:
                start = index
                index += 1
                while index < len(lines) and lines[index].strip() != "---":
                    index += 1
                if index < len(lines):
                    index += 1
                spans.append(self._span(loaded, span_index, section_stack, lines, offsets, start, index - 1, "metadata"))
                span_index += 1
                in_frontmatter = False
                continue

            fence = FENCE_START_RE.match(raw)
            if fence:
                start = index
                info = fence.group("info").strip().lower()
                index += 1
                while index < len(lines) and not lines[index].strip().startswith("```"):
                    index += 1
                if index < len(lines):
                    index += 1
                content_type = _code_content_type(info, loaded.document.relative_path)
                spans.append(self._span(loaded, span_index, section_stack, lines, offsets, start, index - 1, content_type, {"fence_info": info}))
                span_index += 1
                continue

            heading = HEADING_RE.match(raw)
            if heading:
                level = len(heading.group("marks"))
                title = heading.group("title").strip()
                section_stack = [(lvl, name) for lvl, name in section_stack if lvl < level]
                section_stack.append((level, title))
                spans.append(self._span(loaded, span_index, section_stack, lines, offsets, index, index, "title"))
                span_index += 1
                index += 1
                continue

            if not stripped:
                index += 1
                continue

            start = index
            index += 1
            while index < len(lines):
                nxt = lines[index]
                if not nxt.strip() or HEADING_RE.match(nxt) or FENCE_START_RE.match(nxt):
                    break
                index += 1
            content_type = _prose_content_type("".join(lines[start:index]), section_stack)
            spans.append(self._span(loaded, span_index, section_stack, lines, offsets, start, index - 1, content_type))
            span_index += 1

        return spans

    def _parse_plain_document(self, loaded: LoadedDocument) -> list[DocumentSpan]:
        lines = loaded.text.splitlines(keepends=True)
        if not lines:
            return []
        offsets = _line_offsets(lines)
        content_type = _plain_content_type(loaded.document.file_type, loaded.document.relative_path)
        return [self._span(loaded, 0, [], lines, offsets, 0, len(lines) - 1, content_type)]

    @staticmethod
    def _span(
        loaded: LoadedDocument,
        index: int,
        section_stack: list[tuple[int, str]],
        lines: list[str],
        offsets: list[int],
        start: int,
        end: int,
        content_type: str,
        metadata: dict | None = None,
    ) -> DocumentSpan:
        raw_text = "".join(lines[start:end + 1])
        section_path = [name for _, name in section_stack]
        return DocumentSpan(
            span_id=f"{loaded.document.document_id}:span-{index}",
            document_id=loaded.document.document_id,
            section_path=section_path,
            start_offset=offsets[start],
            end_offset=offsets[end] + len(lines[end]),
            line_start=start + 1,
            line_end=end + 1,
            content_type=content_type,
            raw_text=raw_text,
            normalized_text=" ".join(raw_text.split()),
            metadata={
                "relative_path": loaded.document.relative_path,
                "modality_hint": _modality_hint(raw_text),
                "context_hint": _context_hint(section_path, raw_text),
                **(metadata or {}),
            },
        )


def _line_offsets(lines: list[str]) -> list[int]:
    offsets: list[int] = []
    current = 0
    for line in lines:
        offsets.append(current)
        current += len(line)
    return offsets


def _code_content_type(info: str, relative_path: str) -> str:
    if any(token in info for token in {"bash", "sh", "shell", "zsh", "powershell", "ps1"}):
        return "shell_command"
    if any(token in info for token in {"json", "yaml", "yml", "toml", "ini", "cfg"}):
        return "configuration"
    if any(token in info for token in {"python", "py", "javascript", "js", "typescript", "ts"}):
        return "code_block"
    if relative_path.lower().endswith((".sh", ".bash", ".ps1")):
        return "shell_command"
    return "code_block"


def _plain_content_type(file_type: str, relative_path: str) -> str:
    if file_type in {"shell", "makefile", "dockerfile"}:
        return "shell_command"
    if file_type in {"json", "yaml", "toml"}:
        return "configuration"
    if file_type in {"python", "javascript"}:
        return "code_block"
    return "prose_instruction"


def _prose_content_type(text: str, section_stack: list[tuple[int, str]]) -> str:
    section = " / ".join(name for _, name in section_stack).lower()
    lowered = text.lower()
    if text.lstrip().startswith(">"):
        return "quote"
    if PROHIBITION_RE.search(text):
        return "prohibition"
    if EXAMPLE_RE.search(text) or "example" in section:
        return "example"
    if WARNING_RE.search(text):
        return "warning"
    if DEFENSIVE_RE.search(text) or any(token in section for token in {"security", "detect", "defense"}):
        return "warning"
    if any(token in section for token in {"description", "overview", "about"}):
        return "prose_description"
    return "prose_instruction"


def _modality_hint(text: str) -> str:
    if PROHIBITION_RE.search(text):
        return "prohibited"
    if EXAMPLE_RE.search(text):
        return "example_only"
    if OPTIONAL_RE.search(text):
        return "optional"
    if CONDITIONAL_RE.search(text):
        return "conditional"
    return "required"


def _context_hint(section_path: list[str], text: str) -> str:
    joined = " ".join(section_path).lower()
    lowered = text.lower()
    candidates = [
        ("installation", {"install", "installation", "bootstrap"}),
        ("setup", {"setup", "configure", "configuration", "connect"}),
        ("maintenance", {"maintenance", "schedule", "cron"}),
        ("update", {"update", "upgrade", "sync"}),
        ("troubleshooting", {"troubleshoot", "debug", "diagnostic"}),
        ("defensive", {"security", "scanner", "detect", "defense"}),
    ]
    for context, tokens in candidates:
        if any(token in joined or token in lowered for token in tokens):
            return context
    return "documentation"
