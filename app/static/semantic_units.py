from __future__ import annotations

import json
import re
from typing import Any

from app.static.artifact_schema import LoadedArtifact, SemanticUnit


HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")
FENCE_RE = re.compile(r"^\s*```(?P<info>.*)$")


class SemanticUnitParser:
    def parse(self, artifacts: list[LoadedArtifact]) -> list[SemanticUnit]:
        units: list[SemanticUnit] = []
        for loaded in artifacts:
            if loaded.artifact.artifact_type == "markdown":
                units.extend(self._parse_markdown(loaded, len(units)))
            elif loaded.artifact.artifact_type in {"json", "yaml", "toml"}:
                units.extend(self._parse_config(loaded, len(units)))
            else:
                units.extend(self._parse_code_or_text(loaded, len(units)))
        return units

    def _parse_markdown(self, loaded: LoadedArtifact, base_index: int) -> list[SemanticUnit]:
        lines = loaded.text.splitlines(keepends=True)
        offsets = _line_offsets(lines)
        section = ""
        units: list[SemanticUnit] = []
        index = 0
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            if not stripped:
                index += 1
                continue
            heading = HEADING_RE.match(stripped)
            if heading:
                section = heading.group(2).strip()
                units.append(_unit(loaded, len(units) + base_index, "heading", index, index, lines, offsets, section))
                index += 1
                continue
            fence = FENCE_RE.match(line)
            if fence:
                start = index
                info = fence.group("info").strip().lower()
                index += 1
                while index < len(lines) and not lines[index].strip().startswith("```"):
                    index += 1
                if index < len(lines):
                    index += 1
                units.append(_unit(loaded, len(units) + base_index, "code_block", start, index - 1, lines, offsets, section, {"language": info}))
                for line_no in range(start + 1, max(start + 1, index - 1)):
                    if lines[line_no].strip():
                        units.append(_unit(loaded, len(units) + base_index, "command_line", line_no, line_no, lines, offsets, section, {"language": info}))
                continue
            start = index
            unit_type = "list_item" if stripped.startswith(("-", "*", "1.", "2.", "3.")) else "paragraph"
            index += 1
            while index < len(lines) and lines[index].strip() and not HEADING_RE.match(lines[index].strip()) and not FENCE_RE.match(lines[index]):
                if unit_type == "list_item" and not lines[index].lstrip().startswith(("-", "*")):
                    break
                index += 1
            units.append(_unit(loaded, len(units) + base_index, unit_type, start, index - 1, lines, offsets, section))
        return units

    def _parse_config(self, loaded: LoadedArtifact, base_index: int) -> list[SemanticUnit]:
        lines = loaded.text.splitlines(keepends=True)
        offsets = _line_offsets(lines)
        units: list[SemanticUnit] = []
        for idx, line in enumerate(lines):
            if not line.strip():
                continue
            unit_type = "json_field" if loaded.artifact.artifact_type == "json" else "yaml_field" if loaded.artifact.artifact_type == "yaml" else "config_entry"
            units.append(_unit(loaded, len(units) + base_index, unit_type, idx, idx, lines, offsets, "", {"artifact_type": loaded.artifact.artifact_type}))
        if loaded.artifact.artifact_type == "json":
            try:
                json.loads(loaded.text)
            except json.JSONDecodeError as exc:
                units.append(_synthetic_unit(loaded, len(units) + base_index, "comment", f"JSON parse failure: {exc}", {"parse_error": str(exc)}))
        return units

    def _parse_code_or_text(self, loaded: LoadedArtifact, base_index: int) -> list[SemanticUnit]:
        lines = loaded.text.splitlines(keepends=True)
        offsets = _line_offsets(lines)
        units: list[SemanticUnit] = []
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith(("#", "//")):
                unit_type = "comment"
            elif stripped.startswith(("import ", "from ", "const ", "let ", "var ")) or "=" in stripped:
                unit_type = "assignment"
            elif "(" in stripped and ")" in stripped:
                unit_type = "function_call"
            else:
                unit_type = "command_line" if loaded.artifact.artifact_type in {"shell", "makefile", "dockerfile"} else "paragraph"
            units.append(_unit(loaded, len(units) + base_index, unit_type, idx, idx, lines, offsets, "", {"language": loaded.artifact.artifact_type}))
        return units


def _unit(loaded: LoadedArtifact, index: int, unit_type: str, start: int, end: int, lines: list[str], offsets: list[int], section: str, metadata: dict[str, Any] | None = None) -> SemanticUnit:
    text = "".join(lines[start:end + 1])
    return SemanticUnit(
        unit_id=f"U{index + 1:04d}",
        artifact_id=loaded.artifact.artifact_id,
        unit_type=unit_type,
        start_line=start + 1,
        end_line=end + 1,
        start_offset=offsets[start],
        end_offset=offsets[end] + len(lines[end]),
        text=text,
        parent_section=section,
        language=(metadata or {}).get("language", "en") or "en",
        metadata={"relative_path": loaded.artifact.relative_path, **(metadata or {})},
    )


def _synthetic_unit(loaded: LoadedArtifact, index: int, unit_type: str, text: str, metadata: dict[str, Any]) -> SemanticUnit:
    return SemanticUnit(f"U{index + 1:04d}", loaded.artifact.artifact_id, unit_type, 1, 1, 0, 0, text, "", metadata=metadata)


def _line_offsets(lines: list[str]) -> list[int]:
    offsets: list[int] = []
    current = 0
    for line in lines:
        offsets.append(current)
        current += len(line)
    return offsets or [0]
