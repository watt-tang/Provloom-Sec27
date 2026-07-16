from __future__ import annotations

from dataclasses import dataclass, field

from app.instruction.command_parser import CommandFact, CommandParser


@dataclass
class CodeFact:
    language: str
    commands: list[CommandFact] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


class CodeParser:
    """Extract conservative facts from code blocks and script files."""

    def __init__(self, command_parser: CommandParser | None = None) -> None:
        self._command_parser = command_parser or CommandParser()

    def parse(self, text: str, *, language: str = "unknown") -> CodeFact:
        commands: list[CommandFact] = []
        imports: list[str] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("import ", "from ")):
                imports.append(line)
                continue
            parsed = self._command_parser.parse(line)
            if parsed.operations or parsed.urls or parsed.local_paths:
                commands.append(parsed)
        return CodeFact(language=language, commands=commands, imports=imports)
