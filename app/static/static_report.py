from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.static.action_normalizer import ActionNormalizer
from app.static.action_schema import StaticAction
from app.static.artifact_loader import ArtifactLoader
from app.static.artifact_schema import STATIC_SCHEMA_VERSION, LoadedArtifact, SemanticUnit, StaticArtifact, StaticCoverage
from app.static.deterministic_extractor import DeterministicStaticExtractor
from app.static.entity_resolver import EntityResolver
from app.static.entity_schema import EntityResolution, Mention, StaticEntity
from app.static.grounding_validator import GroundingValidator
from app.static.instruction_graph import InstructionGraphBuilderV2, InstructionProvenanceGraph
from app.static.llm_action_extractor import SpanGroundedLLMActionExtractor
from app.static.path_validator import StaticChain, StaticPathValidator
from app.static.semantic_units import SemanticUnitParser
from app.static.static_config import StaticAnalysisConfig


@dataclass
class StaticAnalysisResult:
    schema_version: str
    skill_root: str
    static_artifacts_v2: list[StaticArtifact]
    static_semantic_units: list[SemanticUnit]
    deterministic_mentions: list[Mention]
    extracted_actions: list[StaticAction]
    grounding_validation: list[dict[str, Any]]
    resolved_entities: list[StaticEntity]
    entity_resolutions: list[EntityResolution]
    instruction_provenance_graph: InstructionProvenanceGraph
    static_chains: list[StaticChain]
    static_coverage: StaticCoverage
    static_analysis_summary: dict[str, Any]
    llm_extraction_metadata: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "skill_root": self.skill_root,
            "static_artifacts_v2": [artifact.to_dict() for artifact in self.static_artifacts_v2],
            "static_semantic_units": [unit.to_dict() for unit in self.static_semantic_units],
            "deterministic_mentions": [mention.to_dict() for mention in self.deterministic_mentions],
            "extracted_actions": [action.to_dict() for action in self.extracted_actions],
            "grounding_validation": self.grounding_validation,
            "resolved_entities": [entity.to_dict() for entity in self.resolved_entities],
            "entity_resolutions": [resolution.to_dict() for resolution in self.entity_resolutions],
            "instruction_provenance_graph": self.instruction_provenance_graph.to_dict(),
            "static_chains": [chain.to_dict() for chain in self.static_chains],
            "static_coverage": self.static_coverage.to_dict(),
            "static_analysis_summary": self.static_analysis_summary,
            "llm_extraction_metadata": self.llm_extraction_metadata,
        }

    def to_markdown(self) -> str:
        lines = [
            "# ProvLoom Static Instruction Analysis",
            "",
            f"- Schema: `{self.schema_version}`",
            f"- Skill root: `{self.skill_root}`",
            f"- Review priority: `{self.static_analysis_summary.get('review_priority', 'informational')}`",
            f"- Coverage states: `{', '.join(self.static_coverage.states)}`",
            "",
            "## Static Chains",
        ]
        if not self.static_chains:
            lines.append("- No instruction-derived path was validated. This is not a safety verdict.")
        for chain in self.static_chains:
            lines.extend(
                [
                    f"- `{chain.chain_id}` `{chain.chain_type}` status=`{chain.status}` priority=`{chain.review_priority}`",
                    f"  Evidence units: {', '.join(chain.evidence_unit_ids) or 'none'}",
                    f"  Explanation: {chain.explanation}",
                ]
            )
            if chain.limitations:
                lines.append(f"  Limitations: {', '.join(chain.limitations)}")
        lines.extend(["", "## Coverage", "```json", json.dumps(self.static_coverage.to_dict(), ensure_ascii=False, indent=2), "```"])
        return "\n".join(lines) + "\n"


def analyze_static_bundle(
    skill_root: str | Path,
    skill_file: str = "SKILL.md",
    *,
    config: StaticAnalysisConfig | None = None,
) -> StaticAnalysisResult:
    cfg = config or StaticAnalysisConfig()
    root = Path(skill_root).resolve()
    started = time.perf_counter()
    artifacts: list[StaticArtifact] = []
    loaded: list[LoadedArtifact] = []
    units: list[SemanticUnit] = []
    mentions: list[Mention] = []
    actions: list[StaticAction] = []
    validation: list[dict[str, Any]] = []
    entities: list[StaticEntity] = []
    resolutions: list[EntityResolution] = []
    graph = InstructionProvenanceGraph([], [])
    chains: list[StaticChain] = []
    llm_metadata: list[dict[str, Any]] = []
    coverage_states: list[str] = []
    limitations: list[str] = []

    try:
        loaded, artifacts = ArtifactLoader(cfg).load(root, skill_file)
        units = SemanticUnitParser().parse(loaded)
        mentions, deterministic_actions = DeterministicStaticExtractor().extract(units)
        llm_actions, llm_metadata = SpanGroundedLLMActionExtractor(cfg).extract(units, mentions)
        deterministic_actions = _apply_llm_action_decisions(deterministic_actions, llm_metadata, cfg)
        actions = ActionNormalizer().normalize(_dedupe_actions(deterministic_actions + llm_actions))
        actions, validation = GroundingValidator().validate(actions, artifacts=loaded, units=units, mentions=mentions)
        entities, resolutions = EntityResolver().resolve(mentions, actions)
        graph = InstructionGraphBuilderV2().build(
            artifacts=loaded,
            units=units,
            mentions=mentions,
            actions=actions,
            entities=entities,
            resolutions=resolutions,
        )
        chains = StaticPathValidator(cfg).validate(actions=actions, entities=entities, graph=graph)
        coverage_states.append("path_validation_complete")
    except Exception as exc:  # pragma: no cover - defensive conversion into coverage
        coverage_states.append("analysis_error")
        limitations.append(f"analysis_error:{exc}")

    coverage_states.extend(_coverage_states(artifacts, units, validation, entities, llm_metadata))
    coverage = StaticCoverage(
        states=_stable_states(coverage_states),
        total_files=len(artifacts),
        loaded_files=sum(1 for artifact in artifacts if artifact.load_status == "loaded"),
        ignored_files=sum(1 for artifact in artifacts if artifact.load_status == "ignored"),
        unsupported_files=sum(1 for artifact in artifacts if artifact.load_status == "unsupported"),
        semantic_unit_count=len(units),
        llm_success_count=sum(1 for meta in llm_metadata if meta.get("status") not in {"llm_extraction_failure"}),
        grounding_failure_count=sum(1 for item in validation if item.get("grounding_status") != "valid"),
        unresolved_entity_count=sum(1 for entity in entities if entity.resolution_status in {"ambiguous", "unresolved"}),
        limitations=sorted(set(limitations + _coverage_limitations(artifacts, entities))),
    )
    summary = _summary(actions, entities, chains, graph, coverage, time.perf_counter() - started)
    return StaticAnalysisResult(
        schema_version=STATIC_SCHEMA_VERSION,
        skill_root=str(root),
        static_artifacts_v2=artifacts,
        static_semantic_units=units,
        deterministic_mentions=mentions,
        extracted_actions=actions,
        grounding_validation=validation,
        resolved_entities=entities,
        entity_resolutions=resolutions,
        instruction_provenance_graph=graph,
        static_chains=chains,
        static_coverage=coverage,
        static_analysis_summary=summary,
        llm_extraction_metadata=llm_metadata,
    )


def _dedupe_actions(actions: list[StaticAction]) -> list[StaticAction]:
    seen: set[tuple[str, str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = set()
    result: list[StaticAction] = []
    for action in actions:
        evidence_key = action.evidence.unit_id if action.evidence else ""
        key = (
            action.action_type,
            evidence_key,
            action.modality,
            tuple(action.object_mentions),
            tuple(action.source_mentions),
            tuple(action.destination_mentions),
        )
        if key in seen:
            continue
        seen.add(key)
        action.action_id = f"A{len(result) + 1:04d}"
        result.append(action)
    return result


def _apply_llm_action_decisions(
    actions: list[StaticAction],
    llm_metadata: list[dict[str, Any]],
    config: StaticAnalysisConfig,
) -> list[StaticAction]:
    if not config.llm_enabled or not config.llm_filter_deterministic_actions:
        return actions
    decisions: dict[str, dict[str, Any]] = {}
    for meta in llm_metadata:
        if not str(meta.get("status", "")).startswith("llm_semantic_filter"):
            continue
        for decision in meta.get("action_decisions", []):
            if isinstance(decision, dict) and decision.get("action_id"):
                decisions[str(decision["action_id"])] = decision
    if not decisions:
        return actions
    filtered: list[StaticAction] = []
    for action in actions:
        decision = decisions.get(action.action_id)
        if decision is None:
            filtered.append(action)
            continue
        action.metadata["llm_semantic_filter"] = {
            "keep": bool(decision.get("keep", False)),
            "reason": decision.get("reason", ""),
        }
        if not decision.get("keep", False):
            continue
        action.action_type = str(decision.get("action_type", action.action_type))
        action.modality = str(decision.get("modality", action.modality))
        action.extractor = "hybrid"
        action.confidence = max(action.confidence, 0.9)
        filtered.append(action)
    return filtered


def _coverage_states(
    artifacts: list[StaticArtifact],
    units: list[SemanticUnit],
    validation: list[dict[str, Any]],
    entities: list[StaticEntity],
    llm_metadata: list[dict[str, Any]],
) -> list[str]:
    states: list[str] = []
    if artifacts and all(artifact.load_status == "loaded" for artifact in artifacts):
        states.append("fully_loaded")
    else:
        states.append("partially_loaded")
    if any(artifact.load_status == "unsupported" for artifact in artifacts):
        states.append("unsupported_artifact")
    if any(artifact.load_reason == "oversized_artifact" for artifact in artifacts):
        states.append("oversized_artifact")
    if any(unit.metadata.get("parse_error") for unit in units):
        states.append("parse_failure")
    if any(meta.get("status") == "llm_extraction_failure" for meta in llm_metadata):
        states.append("llm_extraction_failure")
    if any(item.get("grounding_status") != "valid" for item in validation):
        states.append("grounding_failure")
    if any(entity.resolution_status in {"ambiguous", "unresolved"} for entity in entities):
        states.append("unresolved_entities")
    return states


def _coverage_limitations(artifacts: list[StaticArtifact], entities: list[StaticEntity]) -> list[str]:
    limitations = [f"{artifact.relative_path}:{artifact.load_reason}" for artifact in artifacts if artifact.load_status != "loaded" and artifact.load_reason]
    limitations.extend(f"ambiguous_entity:{entity.entity_id}:{entity.canonical_value}" for entity in entities if entity.resolution_status == "ambiguous")
    return limitations


def _summary(
    actions: list[StaticAction],
    entities: list[StaticEntity],
    chains: list[StaticChain],
    graph: InstructionProvenanceGraph,
    coverage: StaticCoverage,
    latency_seconds: float,
) -> dict[str, Any]:
    priority_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
    strongest = max(chains, key=lambda chain: priority_order.get(chain.review_priority, 0), default=None)
    statuses: dict[str, int] = {}
    priorities: dict[str, int] = {}
    for chain in chains:
        statuses[chain.status] = statuses.get(chain.status, 0) + 1
        priorities[chain.review_priority] = priorities.get(chain.review_priority, 0) + 1
    return {
        "schema_version": STATIC_SCHEMA_VERSION,
        "review_priority": strongest.review_priority if strongest else "informational",
        "priority_reasons": strongest.priority_reasons if strongest else ["No validated static chain was formed; this is not a safety verdict."],
        "closed_static_chain_count": statuses.get("closed", 0),
        "chain_status_counts": statuses,
        "review_priority_counts": priorities,
        "action_count": len(actions),
        "entity_count": len(entities),
        "graph_summary": graph.summary(),
        "coverage_states": coverage.states,
        "latency_seconds": round(latency_seconds, 6),
        "output_semantics": "instruction_derived_potential_path_not_runtime_confirmation",
    }


def _stable_states(states: list[str]) -> list[str]:
    order = [
        "fully_loaded",
        "partially_loaded",
        "unsupported_artifact",
        "oversized_artifact",
        "parse_failure",
        "llm_extraction_failure",
        "grounding_failure",
        "unresolved_entities",
        "path_validation_complete",
        "analysis_error",
    ]
    present = set(states)
    return [state for state in order if state in present]
