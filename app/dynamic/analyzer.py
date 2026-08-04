from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.dynamic.alignment import StaticRuntimeAligner
from app.dynamic.assessment import assess_dynamic_result
from app.dynamic.chain_recovery import ChainRecovery
from app.dynamic.closure_lift import RuntimeInstructionLift
from app.dynamic.config import DynamicAnalysisConfig
from app.dynamic.coverage import CoverageAnalyzer
from app.dynamic.event_schema import runtime_events_from_normalized
from app.dynamic.graph import RuntimeGraphBuilder
from app.dynamic.marker_registry import TaintRegistry
from app.dynamic.models import CoverageReport, PolicyViolation, RuntimeChain, RuntimeEvent, RuntimeProvenanceGraph, SCHEMA_VERSION
from app.dynamic.policy import PolicyEngine
from app.dynamic.propagation import RuntimeTaintPropagator
from app.runner.models import SandboxExecution
from app.telemetry.normalizer import build_normalized_events
from app.telemetry.normalizer import NormalizedEvent


@dataclass
class DynamicAnalysisResult:
    runtime_events: list[RuntimeEvent]
    graph: RuntimeProvenanceGraph
    chains: list[RuntimeChain]
    coverage: CoverageReport
    policy_violations: list[PolicyViolation]
    taint_sources: list[dict[str, Any]]
    static_runtime_alignment: dict[str, Any] | None = None
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        assessment = assess_dynamic_result(self)
        return {
            "schema_version": self.schema_version,
            "runtime_events": [event.to_dict() for event in self.runtime_events],
            "runtime_provenance_graph": self.graph.to_dict(),
            "runtime_chains": [chain.to_dict() for chain in self.chains],
            "coverage": self.coverage.to_dict(),
            "policy_violations": [violation.to_dict() for violation in self.policy_violations],
            "taint_sources": list(self.taint_sources),
            "static_runtime_alignment": self.static_runtime_alignment or {},
            "canonical_assessment": assessment.to_dict(),
            "canonical_risk_score": assessment.canonical_risk_score,
            "canonical_final_decision": assessment.canonical_final_decision,
            "needs_review": assessment.needs_review,
            "review_required": assessment.review_required,
            "review_lean": assessment.review_lean,
            "binary_prediction": assessment.binary_prediction,
            "decision_score": assessment.decision_score,
            "review_reason": assessment.review_reason,
            "lean_reason": assessment.lean_reason,
            "lean_score": assessment.lean_score,
            "policy_violation_count": assessment.policy_violation_count,
            "confirmed_chain_count": assessment.confirmed_chain_count,
            "candidate_chain_count": assessment.candidate_chain_count,
            "coverage_state": assessment.coverage_state,
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, Any]:
        by_level: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for chain in self.chains:
            by_level[chain.evidence_level] = by_level.get(chain.evidence_level, 0) + 1
            by_type[chain.chain_type] = by_type.get(chain.chain_type, 0) + 1
        return {
            "runtime_event_count": len(self.runtime_events),
            "runtime_chain_count": len(self.chains),
            "chain_count_by_evidence": by_level,
            "chain_count_by_type": by_type,
            "coverage_state": self.coverage.coverage_state,
            "policy_violation_count": len(self.policy_violations),
            "confirmed_confidentiality_flow_count": sum(1 for chain in self.chains if chain.chain_type == "confidentiality_confirmed" and chain.evidence_level == "confirmed"),
            "conservative_confidentiality_flow_count": sum(1 for chain in self.chains if chain.chain_type == "confidentiality_confirmed" and chain.evidence_level == "conservative"),
            "candidate_confidentiality_flow_count": sum(1 for chain in self.chains if chain.chain_type == "confidentiality_candidate"),
            "canonical_chain_schema": "v3",
            "static_runtime_alignment_status": (self.static_runtime_alignment or {}).get("status", "unknown"),
        }


class DynamicRuntimeAnalyzer:
    def __init__(
        self,
        *,
        config: DynamicAnalysisConfig | None = None,
        registry: TaintRegistry | None = None,
        skill_root: str | Path | None = None,
    ) -> None:
        self.config = config or DynamicAnalysisConfig()
        self.registry = registry
        self.skill_root = Path(skill_root) if skill_root is not None else None

    def analyze(
        self,
        events: list[RuntimeEvent],
        *,
        session_id: str | None = None,
        skill_id: str | None = None,
        timed_out: bool = False,
        exit_code: int | None = 0,
        static_result: Any | None = None,
    ) -> DynamicAnalysisResult:
        if not events:
            registry = self.registry or TaintRegistry(run_id=session_id or "RUN", config=self.config.marker)
            graph = RuntimeGraphBuilder(session_id=session_id or "RUN").build([], registry.source_dicts())
            coverage = CoverageAnalyzer().analyze(events=[], chains=[], timed_out=timed_out, exit_code=exit_code)
            alignment = StaticRuntimeAligner().align(graph=graph, chains=[], coverage=coverage, static_result=static_result)
            return DynamicAnalysisResult([], graph, [], coverage, [], registry.source_dicts(), alignment)

        session = session_id or events[0].session_id
        skill = skill_id or events[0].skill_id
        registry = self.registry or TaintRegistry(run_id=session, config=self.config.marker)
        all_events = list(events)
        if self.skill_root is not None:
            all_events.extend(RuntimeInstructionLift(skill_root=self.skill_root, config=self.config.closure_lift).discover(all_events))
        propagated = RuntimeTaintPropagator(registry=registry, config=self.config).propagate(all_events)
        taint_sources = _merged_taint_sources(registry.source_dicts(), propagated)
        graph = RuntimeGraphBuilder(session_id=session).build(propagated, taint_sources)
        chains = ChainRecovery().recover(graph)
        coverage = CoverageAnalyzer().analyze(events=propagated, chains=chains, timed_out=timed_out, exit_code=exit_code)
        violations = PolicyEngine(self.config).evaluate(chains=chains, events=propagated)
        alignment = StaticRuntimeAligner().align(graph=graph, chains=chains, coverage=coverage, static_result=static_result)
        return DynamicAnalysisResult(propagated, graph, chains, coverage, violations, taint_sources, alignment, schema_version=SCHEMA_VERSION)

    def analyze_execution(
        self,
        execution: SandboxExecution,
        normalized: list[NormalizedEvent] | None = None,
        *,
        static_result: Any | None = None,
    ) -> DynamicAnalysisResult:
        normalized = normalized if normalized is not None else build_normalized_events(execution)
        return self.analyze_normalized_execution(execution, normalized, static_result=static_result)

    def analyze_normalized_execution(
        self,
        execution: SandboxExecution,
        normalized: list[NormalizedEvent],
        *,
        static_result: Any | None = None,
    ) -> DynamicAnalysisResult:
        runtime_events = runtime_events_from_normalized(
            normalized,
            session_id=execution.execution_id,
            skill_id=Path(execution.skill_path).name,
        )
        return self.analyze(
            runtime_events,
            session_id=execution.execution_id,
            skill_id=Path(execution.skill_path).name,
            timed_out=execution.timed_out,
            exit_code=execution.exit_code,
            static_result=static_result,
        )


def analyze_runtime_events(
    events: list[RuntimeEvent],
    *,
    config: DynamicAnalysisConfig | None = None,
    registry: TaintRegistry | None = None,
    skill_root: str | Path | None = None,
    static_result: Any | None = None,
) -> DynamicAnalysisResult:
    return DynamicRuntimeAnalyzer(config=config, registry=registry, skill_root=skill_root).analyze(events, static_result=static_result)


def _merged_taint_sources(existing: list[dict[str, Any]], events: list[RuntimeEvent]) -> list[dict[str, Any]]:
    by_id = {str(item.get("taint_id")): dict(item) for item in existing if item.get("taint_id")}
    for event in events:
        if event.event_type != "sensitive_source":
            continue
        for taint_id in event.taint_ids:
            by_id.setdefault(
                str(taint_id),
                {
                    "taint_id": str(taint_id),
                    "source_type": str(event.metadata.get("source_type") or event.metadata.get("source_label", {}).get("source_type") or "runtime_sensitive_source"),
                    "source_location": event.object_path or event.carrier_location or str(taint_id),
                    "marker": "",
                    "created_at": event.timestamp,
                    "allowed_sinks": [],
                    "metadata": dict(event.metadata),
                    "variants": {},
                },
            )
    return list(by_id.values())


def persist_dynamic_analysis(result: DynamicAnalysisResult, artifacts_dir: str | Path) -> dict[str, Path]:
    root = Path(artifacts_dir)
    root.mkdir(parents=True, exist_ok=True)
    paths = {
        "runtime_events": root / "runtime-events-v2.jsonl",
        "runtime_graph": root / "runtime-provenance-graph.json",
        "runtime_chains": root / "runtime-chains.json",
        "dynamic_analysis": root / "dynamic-analysis.json",
    }
    with paths["runtime_events"].open("w", encoding="utf-8") as handle:
        for event in result.runtime_events:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
    paths["runtime_graph"].write_text(json.dumps(result.graph.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    paths["runtime_chains"].write_text(json.dumps([chain.to_dict() for chain in result.chains], ensure_ascii=False, indent=2), encoding="utf-8")
    paths["dynamic_analysis"].write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return paths
