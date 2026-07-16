from __future__ import annotations

from collections.abc import Iterable

from app.instruction.document_loader import LoadedDocument
from app.instruction.markdown_parser import MarkdownParser
from app.instruction.models import DocumentSpan


class InstructionSegmenter:
    """Stable entry point for turning loaded documents into evidence spans."""

    def __init__(self, parser: MarkdownParser | None = None) -> None:
        self._parser = parser or MarkdownParser()

    def segment(self, documents: Iterable[LoadedDocument]) -> list[DocumentSpan]:
        return self._parser.parse_many(documents)
