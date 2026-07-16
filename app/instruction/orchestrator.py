from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from app.instruction.confidence import confidence_label, path_confidence
from app.instruction.document_loader import DocumentLoader, DocumentLoaderConfig
from app.instruction.entity_linker import EntityLinker
from app.instruction.graph_builder import InstructionGraphBuilder
from app.instruction.models import InstructionAnalysisResult, SCHEMA_VERSION, ValidatedInstructionPath
from app.instruction.path_validator import PathValidator
from app.instruction.segmenter import InstructionSegmenter
from app.instruction.semantic_extractor import SemanticExtractor, SemanticExtractorConfig


def analyze_instruction_bundle(
    skill_root: str | Path,
    skill_file: str = "SKILL.md",
    *,
    mode: str | None = None,
    loader_config: DocumentLoaderConfig | None = None,
) -> InstructionAnalysisResult:
    selected_mode = mode or os.environ.get("INSTRUCTION_ANALYSIS_MODE", "hybrid")
    root = Path(skill_root).resolve()
    loader = DocumentLoader(loader_config)
    loaded = loader.load(root, skill_file)
    documents = [item.document for item in loaded]
    contents_by_document = {item.document.document_id: item.text for item in loaded}

    spans = InstructionSegmenter().segment(loaded)

    extractor = SemanticExtractor(SemanticExtractorConfig(backend=selected_mode))
    extracted = extractor.extract(documents, spans, contents_by_document)
    actions, links = EntityLinker().link(extracted.actions, extracted.entities)
    graph = InstructionGraphBuilder().build(actions, extracted.entities, links)
    validated_paths, partial_paths, abstentions = PathValidator().validate(actions=actions, entities=extracted.entities, graph=graph)
    suppressed_indicators = [item for item in extracted.indicators if item.get("category") == "suppressed_instruction_text"]
    if suppressed_indicators:
        abstentions.append(f"suppressed_{len(suppressed_indicators)}_prohibited_example_or_defensive_spans")
    validated_paths = sorted(validated_paths, key=_path_sort_key)
    partial_paths = sorted(partial_paths, key=_path_sort_key)

    summary = _summary(
        mode=selected_mode,
        documents=documents,
        spans=spans,
        actions=actions,
        entities=extracted.entities,
        validated_paths=validated_paths,
        partial_paths=partial_paths,
        abstentions=abstentions,
    )
    coverage = {
        "files_scanned": [document.relative_path for document in documents],
        "bytes_scanned": sum(document.size for document in documents),
        "span_count": len(spans),
        "action_count": len(actions),
        "entity_count": len(extracted.entities),
        "entity_link_count": len(links),
        "mode": selected_mode,
    }
    return InstructionAnalysisResult(
        documents=documents,
        spans=spans,
        actions=actions,
        entities=extracted.entities,
        entity_links=links,
        graph=graph,
        validated_paths=validated_paths,
        partial_paths=partial_paths,
        indicators=extracted.indicators,
        summary=summary,
        extraction_coverage=coverage,
        abstention_reasons=abstentions,
        schema_version=SCHEMA_VERSION,
    )


def _summary(
    *,
    mode: str,
    documents,
    spans,
    actions,
    entities,
    validated_paths: list[ValidatedInstructionPath],
    partial_paths: list[ValidatedInstructionPath],
    abstentions: list[str],
) -> dict[str, Any]:
    static_level = _risk_level(validated_paths, partial_paths)
    confidence = path_confidence(validated_paths or partial_paths)
    return {
        "mode": mode,
        "risk_level": static_level,
        "risk_status": _risk_status(validated_paths, partial_paths),
        "validated_path_count": len(validated_paths),
        "partial_path_count": len(partial_paths),
        "document_count": len(documents),
        "span_count": len(spans),
        "action_count": len(actions),
        "entity_count": len(entities),
        "confidence": confidence,
        "confidence_label": confidence_label(confidence),
        "abstention_reasons": list(abstentions),
        "hybrid_alignment_status": "coexisting_evidence",
        "aligned_entities": [],
        "aligned_operations": [],
        "alignment_confidence": 0.0,
    }


def _risk_status(validated_paths: list[ValidatedInstructionPath], partial_paths: list[ValidatedInstructionPath]) -> str:
    if validated_paths:
        return "validated_latent_risk_path"
    if partial_paths:
        if any(path.completeness == "candidate" for path in partial_paths):
            return "candidate_path"
        return "partial_latent_risk_path"
    return "no_supported_instruction_path"


def _risk_level(validated_paths: list[ValidatedInstructionPath], partial_paths: list[ValidatedInstructionPath]) -> str:
    if any(path.path_type in {"supply_chain_persistence", "bulk_update_authority"} for path in validated_paths):
        return "critical"
    if any(path.path_type in {"global_environment_modification", "credential_or_account_risk"} for path in validated_paths):
        return "high"
    if any(path.path_type == "remote_fetch_execute" for path in validated_paths):
        return "medium"
    if validated_paths:
        return "medium"
    if any(path.completeness == "partial" for path in partial_paths):
        return "medium"
    if partial_paths:
        return "low"
    return "none"


def _path_sort_key(path: ValidatedInstructionPath) -> tuple[int, int, str]:
    severity = {
        "supply_chain_persistence": 0,
        "bulk_update_authority": 1,
        "global_environment_modification": 2,
        "credential_or_account_risk": 3,
        "remote_fetch_execute": 4,
        "instruction_candidate_exfiltration": 5,
    }.get(path.path_type, 9)
    completeness = {"closed": 0, "candidate": 1, "partial": 2, "insufficient": 3}.get(path.completeness, 9)
    return (severity, completeness, path.path_id)
