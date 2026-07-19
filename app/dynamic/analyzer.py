from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "runtime_events": [event.to_dict() for event in self.runtime_events],
            "runtime_provenance_graph": self.graph.to_dict(),
            "runtime_chains": [chain.to_dict() for chain in self.chains],
            "coverage": self.coverage.to_dict(),
            "policy_violations": [violation.to_dict() for violation in self.policy_violations],
            "taint_sources": list(self.taint_sources),
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
            "confirmed_confidentiality_flow_count": sum(1 for chain in self.chains if chain.chain_type == "confidentiality" and chain.evidence_level == "confirmed"),
            "conservative_confidentiality_flow_count": sum(1 for chain in self.chains if chain.chain_type == "confidentiality" and chain.evidence_level == "conservative"),
            "candidate_confidentiality_flow_count": sum(1 for chain in self.chains if chain.chain_type == "confidentiality_candidate"),
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
    ) -> DynamicAnalysisResult:
        if not events:
            registry = self.registry or TaintRegistry(run_id=session_id or "RUN", config=self.config.marker)
            graph = RuntimeGraphBuilder(session_id=session_id or "RUN").build([], registry.source_dicts())
            coverage = CoverageAnalyzer().analyze(events=[], chains=[], timed_out=timed_out, exit_code=exit_code)
            return DynamicAnalysisResult([], graph, [], coverage, [], registry.source_dicts())

        session = session_id or events[0].session_id
        skill = skill_id or events[0].skill_id
        registry = self.registry or TaintRegistry(run_id=session, config=self.config.marker)
        all_events = list(events)
        if self.skill_root is not None:
            all_events.extend(RuntimeInstructionLift(skill_root=self.skill_root, config=self.config.closure_lift).discover(all_events))
        propagated = RuntimeTaintPropagator(registry=registry, config=self.config).propagate(all_events)
        graph = RuntimeGraphBuilder(session_id=session).build(propagated, registry.source_dicts())
        chains = ChainRecovery().recover(graph)
        coverage = CoverageAnalyzer().analyze(events=propagated, chains=chains, timed_out=timed_out, exit_code=exit_code)
        violations = PolicyEngine(self.config).evaluate(chains=chains, events=propagated)
        return DynamicAnalysisResult(propagated, graph, chains, coverage, violations, registry.source_dicts(), schema_version=SCHEMA_VERSION)

    def analyze_execution(self, execution: SandboxExecution) -> DynamicAnalysisResult:
        normalized = build_normalized_events(execution)
        return self.analyze_normalized_execution(execution, normalized)

    def analyze_normalized_execution(
        self,
        execution: SandboxExecution,
        normalized: list[NormalizedEvent],
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
        )


def analyze_runtime_events(
    events: list[RuntimeEvent],
    *,
    config: DynamicAnalysisConfig | None = None,
    registry: TaintRegistry | None = None,
    skill_root: str | Path | None = None,
) -> DynamicAnalysisResult:
    return DynamicRuntimeAnalyzer(config=config, registry=registry, skill_root=skill_root).analyze(events)


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
