from __future__ import annotations

from dataclasses import dataclass, field

from app.instruction.deterministic_extractor import URL_RE, _local_paths, _operations_for_command


@dataclass
class CommandFact:
    command: str
    operations: list[str]
    urls: list[str] = field(default_factory=list)
    local_paths: list[str] = field(default_factory=list)


class CommandParser:
    """Parse shell-like command text into deterministic instruction facts."""

    def parse(self, command: str) -> CommandFact:
        normalized = command.strip()
        return CommandFact(
            command=normalized,
            operations=_operations_for_command(normalized),
            urls=[url.rstrip(".,") for url in URL_RE.findall(normalized)],
            local_paths=_local_paths(normalized),
        )
