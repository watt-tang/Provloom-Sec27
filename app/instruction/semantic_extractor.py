from __future__ import annotations

from dataclasses import dataclass

from app.instruction.deterministic_extractor import DeterministicExtractor, ExtractionResult
from app.instruction.models import Document, DocumentSpan


@dataclass
class SemanticExtractorConfig:
    backend: str = "hybrid"
    model: str = ""
    temperature: float = 0.0
    timeout_seconds: int = 30
    max_tokens: int = 2048
    cache_enabled: bool = True
    schema_version: str = "instruction-action-extraction-v1"


class SemanticExtractor:
    """Interface-compatible extractor. Offline builds use deterministic extraction only."""

    def __init__(self, config: SemanticExtractorConfig | None = None) -> None:
        self.config = config or SemanticExtractorConfig()
        self._deterministic = DeterministicExtractor()

    def extract(self, documents: list[Document], spans: list[DocumentSpan], contents_by_document: dict[str, str]) -> ExtractionResult:
        # LLM extraction is intentionally not invoked by default; untrusted skill
        # text must never be allowed to decide final risk labels.
        return self._deterministic.extract(documents, spans, contents_by_document)
