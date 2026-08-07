#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.dynamic.assessment import assess_dynamic_result
from app.dynamic.coverage import CoverageAnalyzer
from app.dynamic.analyzer import DynamicAnalysisResult
from app.dynamic.models import CoverageReport, PolicyViolation, RuntimeChain, RuntimeEvent, RuntimeProvenanceGraph
from app.dynamic.review_lean import apply_review_lean
from app.telemetry.collector import build_data_flow_hints, load_llm_events, load_runtime_events
from app.telemetry.normalizer import NormalizedEvent, build_normalized_events
from app.dynamic.event_schema import runtime_events_from_normalized
from app.runner.models import NetworkEvent, ResourceUsage, SandboxExecution
from app.runner.trace_parser import parse_trace_dir
from app.taint.source_registry import SourceRegistry


SCHEMA_VERSION = "provloom-bv3-ablation-replay-v1"
FULL_ROOT_DEFAULT = "artifacts/benchmark_v3_full_glm52_steps16_0001_0800"
VARIANTS = {"full", "static_only", "event_only", "no_alignment", "no_policy"}
SMOKE_IDS = [f"BV3-{index:04d}" for index in range(1, 11)]
CONSISTENCY_FIELDS = [
    "binary_prediction",
    "final_decision",
    "review_required",
    "decision_score",
    "risk_chain_status",
    "security_resolution_status",
    "confirmed_chain_count",
    "complete_chain_count",
]
TAINT_FORBIDDEN_KEYS = {
    "taint_id",
    "taint_ids",
    "input_taint_ids",
    "output_taint_ids",
    "context_taint_ids",
    "marker_matches",
    "taint_propagation_rule",
    "derived_from_hash",
}
NO_ALIGNMENT_FORBIDDEN_KEYS = {
    "static_path_id",
    "alignment_score",
    "aligned_paths",
    "contradictions",
    "static_path_results",
    "runtime_obligations",
    "obligations",
}
NO_POLICY_FORBIDDEN_TOKENS = {
    "confirmed_allowed",
    "resolved_allowed",
    "trusted_sink",
    "trusted_llm_context",
    "trusted_authentication",
    "permitted_source_to_sink_pair",
    "consent",
    "authorization",
    "guard-condition suppression",
}


@dataclass(frozen=True)
class WorkerConfig:
    variant: str
    full_root: str
    benchmark_root: str
    output_root: str
    force: bool


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).resolve()
    if args.evaluate_only:
        return evaluate_only(args, output_root)

    sample_ids = select_sample_ids(args)
    if not sample_ids:
        raise SystemExit("No samples selected.")

    started = time.perf_counter()
    cfg = WorkerConfig(
        variant=args.variant,
        full_root=str(Path(args.full_root).resolve()),
        benchmark_root=str(Path(args.benchmark_root).resolve()),
        output_root=str(output_root),
        force=bool(args.force),
    )
    rows = run_samples(cfg, sample_ids, workers=args.workers)
    payload = write_variant_outputs(
        output_root=output_root,
        variant=args.variant,
        rows=rows,
        started=started,
        args=args,
    )
    print(
        f"[DONE] variant={args.variant} completed={payload['completed_count']} "
        f"failed={payload['failed_count']} output={output_root / args.variant}",
        flush=True,
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay Benchmark v3 frozen Full-System artifacts under ablated analyzers.")
    parser.add_argument("--variant", required=True, choices=sorted(VARIANTS))
    parser.add_argument("--benchmark-root", default="benchmark_v3")
    parser.add_argument("--full-root", default=FULL_ROOT_DEFAULT)
    parser.add_argument("--output-root", default="artifacts/benchmark_v3_ablation")
    parser.add_argument("--start", default="")
    parser.add_argument("--end", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--sample-ids", default="")
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--evaluate-only", action="store_true")
    args = parser.parse_args()
    args.workers = max(1, int(args.workers))
    if not args.resume:
        args.force = True
    return args


def select_sample_ids(args: argparse.Namespace) -> list[str]:
    ids: list[str] = []
    if args.sample_ids.strip():
        ids.extend(normalize_sample_id(item) for item in args.sample_ids.split(",") if item.strip())
    elif args.start or args.end:
        start = int(str(args.start or "1").replace("BV3-", ""))
        end = int(str(args.end or args.start or start).replace("BV3-", ""))
        ids.extend(f"BV3-{index:04d}" for index in range(start, end + 1))
    else:
        summary = load_json(Path(args.full_root) / "summary.json")
        ids.extend(str(row["sample_id"]) for row in summary.get("samples", []) if row.get("sample_id"))
    ids = sorted(dict.fromkeys(ids))
    if args.limit:
        ids = ids[: args.limit]
    return ids


def normalize_sample_id(value: str) -> str:
    text = str(value).strip().upper()
    if text.startswith("BV3-"):
        return text
    return f"BV3-{int(text):04d}"


def run_samples(cfg: WorkerConfig, sample_ids: list[str], *, workers: int) -> list[dict[str, Any]]:
    if workers <= 1:
        return sorted([process_one_sample(cfg, sample_id) for sample_id in sample_ids], key=lambda row: row["sample_id"])

    executor_cls = ProcessPoolExecutor
    try:
        rows: list[dict[str, Any]] = []
        with executor_cls(max_workers=workers) as pool:
            futures = {pool.submit(process_one_sample, cfg, sample_id): sample_id for sample_id in sample_ids}
            for future in as_completed(futures):
                rows.append(future.result())
        return sorted(rows, key=lambda row: row["sample_id"])
    except Exception as exc:
        rows = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(process_one_sample, cfg, sample_id): sample_id for sample_id in sample_ids}
            for future in as_completed(futures):
                sample_id = futures[future]
                try:
                    rows.append(future.result())
                except Exception as inner:
                    rows.append(failed_payload(sample_id, cfg.variant, cfg.full_root, inner, "threadpool_fallback"))
        rows = sorted(rows, key=lambda row: row["sample_id"])
        for row in rows:
            row.setdefault("executor_fallback_reason", f"ProcessPoolExecutor failed: {type(exc).__name__}: {exc}")
        return rows


def process_one_sample(cfg: WorkerConfig, sample_id: str) -> dict[str, Any]:
    started = time.perf_counter()
    sample_path = Path(cfg.output_root) / cfg.variant / "samples" / f"{sample_id}.json"
    if not cfg.force:
        existing = load_existing_sample(sample_path, cfg.variant)
        if existing:
            existing["resumed"] = True
            return existing
    try:
        full = FullArtifact(Path(cfg.full_root), sample_id)
        if cfg.variant == "full":
            row = replay_full(full)
        elif cfg.variant == "static_only":
            row = replay_static_only(full)
        elif cfg.variant == "event_only":
            row = replay_event_only(full)
        elif cfg.variant == "no_alignment":
            row = replay_no_alignment(full)
        elif cfg.variant == "no_policy":
            row = replay_no_policy(full)
        else:
            raise ValueError(f"Unsupported variant: {cfg.variant}")
        row["runtime_seconds"] = round(time.perf_counter() - started, 4)
        atomic_write_json(sample_path, row)
        return row
    except Exception as exc:
        row = failed_payload(sample_id, cfg.variant, cfg.full_root, exc, "worker")
        row["runtime_seconds"] = round(time.perf_counter() - started, 4)
        atomic_write_json(sample_path, row)
        return row


class FullArtifact:
    def __init__(self, full_root: Path, sample_id: str) -> None:
        self.full_root = full_root
        self.sample_id = sample_id
        self.summary = load_json(full_root / "summary.json")
        self.row = next((row for row in self.summary.get("samples", []) if row.get("sample_id") == sample_id), None)
        if not self.row:
            raise FileNotFoundError(f"Sample {sample_id} not found in frozen summary.")
        self.artifacts_dir = Path(str(self.row.get("artifacts_dir") or ""))
        if not self.artifacts_dir.exists():
            raise FileNotFoundError(f"Frozen artifacts dir missing: {self.artifacts_dir}")
        self.canonical = load_json(self.artifacts_dir / "canonical-analysis-result.json")

    @property
    def source(self) -> str:
        return str(self.artifacts_dir)

    @property
    def static_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.canonical.get("static_schema_version", ""),
            "skill_root": self.canonical.get("skill_path", ""),
            "static_artifacts_v2": self.canonical.get("static_artifacts_v2", []),
            "static_semantic_units": self.canonical.get("static_semantic_units", []),
            "deterministic_mentions": self.canonical.get("deterministic_mentions", []),
            "extracted_actions": self.canonical.get("extracted_actions", []),
            "grounding_validation": self.canonical.get("grounding_validation", []),
            "resolved_entities": self.canonical.get("resolved_entities", []),
            "entity_resolutions": self.canonical.get("entity_resolutions", []),
            "instruction_provenance_graph": self.canonical.get("instruction_provenance_graph", {}),
            "static_chains": self.canonical.get("static_chains", []),
            "static_coverage": self.canonical.get("static_coverage", {}),
            "static_analysis_summary": self.canonical.get("static_analysis_summary", {}),
            "llm_extraction_metadata": self.canonical.get("llm_extraction_metadata", []),
        }


def replay_full(full: FullArtifact) -> dict[str, Any]:
    return base_completed(
        full,
        "full",
        binary_prediction=full.row.get("binary_prediction") or full.canonical.get("binary_prediction"),
        final_decision=full.row.get("final_decision") or full.canonical.get("final_decision"),
        review_required=bool(full.row.get("review_required", full.canonical.get("review_required", False))),
        decision_score=full.row.get("decision_score", full.canonical.get("decision_score")),
        risk_chain_status=full.row.get("risk_chain_status") or full.canonical.get("risk_chain_status"),
        security_resolution_status=full.row.get("security_resolution_status") or full.canonical.get("security_resolution_status"),
        confirmed_chain_count=int(full.canonical.get("canonical_assessment", {}).get("confirmed_chain_count") or 0),
        complete_chain_count=count_complete_chains(full.canonical.get("runtime_chains", [])),
        extra={
            "replay_only": True,
            "ablation_scope": "frozen_full_result_read",
            "full_consistency": full_consistency(full),
        },
    )


def replay_static_only(full: FullArtifact) -> dict[str, Any]:
    static_payload = full.static_payload
    static_findings = static_policy_findings(static_payload)
    assessment = apply_review_lean(
        {"status": "static_only_replay", "canonical_final_decision": "benign", "canonical_risk_score": 0},
        policy_findings=static_findings,
        static_payload=static_payload,
        analysis_mode="static_only",
    )
    return base_completed(
        full,
        "static_only",
        binary_prediction=assessment.get("binary_prediction"),
        final_decision=assessment.get("canonical_final_decision"),
        review_required=bool(assessment.get("review_required", False)),
        decision_score=assessment.get("decision_score"),
        risk_chain_status="static_only_no_runtime",
        security_resolution_status="static_only_no_runtime",
        confirmed_chain_count=0,
        complete_chain_count=0,
        extra={
            "ablation_scope": "static_pre_runtime_artifact_only",
            "static_only_mapping": static_mapping_manifest(),
            "dynamic_artifact_used": False,
            "static_chain_count": len(static_payload.get("static_chains", []) or []),
            "decision_input_audit": {
                "runtime_events_used": False,
                "strace_used": False,
                "dynamic_taint_used": False,
                "runtime_provenance_used": False,
                "static_runtime_alignment_used": False,
                "full_final_decision_used": False,
            },
        },
    )


def replay_event_only(full: FullArtifact) -> dict[str, Any]:
    execution = load_frozen_execution(full)
    normalized = sanitize_normalized_events(build_normalized_events(execution), remove_taint_events=True)
    runtime_events = sanitize_runtime_events(runtime_events_from_normalized(normalized, session_id=execution.execution_id, skill_id=full.sample_id))
    graph, chains = build_event_only_graph_and_chains(runtime_events, execution.execution_id)
    coverage = CoverageAnalyzer().analyze(events=runtime_events, chains=chains, timed_out=execution.timed_out, exit_code=execution.exit_code)
    dynamic = DynamicAnalysisResult(runtime_events, graph, chains, coverage, [], [], None)
    assessment = assess_dynamic_result(dynamic).to_dict()
    clean_intermediate = strip_forbidden_keys(
        {
            "runtime_events": [event.to_dict() for event in runtime_events],
            "runtime_provenance_graph": graph.to_dict(),
            "runtime_chains": [chain.to_dict() for chain in chains],
        },
        TAINT_FORBIDDEN_KEYS,
    )
    contamination = forbidden_key_hits(clean_intermediate, TAINT_FORBIDDEN_KEYS)
    return base_completed(
        full,
        "event_only",
        binary_prediction=assessment.get("binary_prediction"),
        final_decision=assessment.get("canonical_final_decision"),
        review_required=bool(assessment.get("review_required", False)),
        decision_score=assessment.get("decision_score"),
        risk_chain_status=event_only_risk_status(chains, coverage),
        security_resolution_status="event_only_no_taint_flow_identity",
        confirmed_chain_count=len([chain for chain in chains if chain.chain_type.endswith("_confirmed")]),
        complete_chain_count=count_complete_chains([chain.to_dict() for chain in chains]),
        extra={
            "ablation_scope": "analysis_stage",
            "execution_trace": "frozen_taint_instrumented_execution",
            "event_only_name": "Event-only Provenance",
            "intermediate_audit": {
                "source_inputs": ["runtime-events.jsonl", "trace.log.*", "mock-service-records.json"],
                "reused_taint_aware_graph": False,
                "reused_taint_aware_chains": False,
                "reused_dynamic_analysis": False,
                "forbidden_key_hits": contamination,
                "passed": not contamination,
            },
            "event_only_intermediate": clean_intermediate,
        },
    )


def replay_no_alignment(full: FullArtifact) -> dict[str, Any]:
    dynamic = dynamic_from_full_without_alignment(full)
    assessment = assess_dynamic_result(dynamic).to_dict()
    static_findings = static_policy_findings(full.static_payload)
    policy_findings = static_findings + runtime_policy_findings([item.to_dict() for item in dynamic.policy_violations])
    final = apply_review_lean(
        assessment,
        runtime_chains=dynamic.chains,
        runtime_events=dynamic.runtime_events,
        policy_findings=policy_findings,
        static_payload=full.static_payload,
        analysis_mode="full_system",
    )
    decision_input = {
        "independent_static_evidence": {
            "static_chain_count": len(full.static_payload.get("static_chains", []) or []),
            "static_policy_findings": policy_findings[: len(static_findings)],
        },
        "independent_runtime_evidence": {
            "runtime_chain_count": len(dynamic.chains),
            "policy_violation_count": len(dynamic.policy_violations),
            "coverage_state": dynamic.coverage.coverage_state,
        },
        "cross_layer_alignment_used": False,
    }
    purity_hits = forbidden_key_hits(decision_input, NO_ALIGNMENT_FORBIDDEN_KEYS)
    return base_completed(
        full,
        "no_alignment",
        binary_prediction=final.get("binary_prediction"),
        final_decision=final.get("canonical_final_decision"),
        review_required=bool(final.get("review_required", False)),
        decision_score=final.get("decision_score"),
        risk_chain_status=no_alignment_risk_status(dynamic),
        security_resolution_status="no_alignment_security_resolution_not_computed",
        confirmed_chain_count=len([chain for chain in dynamic.chains if chain.chain_type.endswith("_confirmed")]),
        complete_chain_count=count_complete_chains([chain.to_dict() for chain in dynamic.chains]),
        extra={
            "ablation_scope": "analysis_stage",
            "pure_no_alignment": not purity_hits,
            "unimplementable_as_pure_ablation": False,
            "decision_input_audit": decision_input,
            "forbidden_key_hits": purity_hits,
        },
    )


def replay_no_policy(full: FullArtifact) -> dict[str, Any]:
    runtime_events = [RuntimeEvent.from_dict(strip_forbidden_keys(item, {"policy_violations"})) for item in full.canonical.get("runtime_events_v2", []) or []]
    chains = [runtime_chain_from_dict(item) for item in full.canonical.get("runtime_chains", []) or []]
    coverage = coverage_from_dict(full.canonical.get("runtime_coverage", {}) or {})
    dynamic = DynamicAnalysisResult(runtime_events, graph_from_full(full), chains, coverage, [], full.canonical.get("taint_sources", []), full.canonical.get("static_runtime_alignment", {}))
    final = policy_disabled_decision(dynamic, full.static_payload)
    decision_input = {
        "runtime_chain_count": len(chains),
        "confirmed_chain_count": len([chain for chain in chains if chain.chain_type.endswith("_confirmed")]),
        "candidate_chain_count": len([chain for chain in chains if "candidate" in chain.chain_type]),
        "static_chain_count": len(full.static_payload.get("static_chains", []) or []),
        "alignment_retained": bool(full.canonical.get("static_runtime_alignment")),
        "policy_reasoning_used": False,
    }
    policy_hits = forbidden_token_hits(decision_input, NO_POLICY_FORBIDDEN_TOKENS)
    return base_completed(
        full,
        "no_policy",
        binary_prediction=final["binary_prediction"],
        final_decision=final["final_decision"],
        review_required=final["review_required"],
        decision_score=final["decision_score"],
        risk_chain_status=final["risk_chain_status"],
        security_resolution_status="policy_disabled_no_allowed_suppression",
        confirmed_chain_count=final["confirmed_chain_count"],
        complete_chain_count=count_complete_chains([chain.to_dict() for chain in chains]),
        extra={
            "ablation_scope": "analysis_stage",
            "runtime_sandbox_policy_changed": False,
            "decision_input_audit": decision_input,
            "forbidden_token_hits": policy_hits,
        },
    )


def base_completed(
    full: FullArtifact,
    variant: str,
    *,
    binary_prediction: Any,
    final_decision: Any,
    review_required: bool,
    decision_score: Any,
    risk_chain_status: Any,
    security_resolution_status: Any,
    confirmed_chain_count: int,
    complete_chain_count: int,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "sample_id": full.sample_id,
        "variant": variant,
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "binary_prediction": str(binary_prediction or "unknown"),
        "final_decision": str(final_decision or binary_prediction or "unknown"),
        "review_required": bool(review_required),
        "decision_score": normalize_score(decision_score),
        "risk_chain_status": str(risk_chain_status or "unknown"),
        "security_resolution_status": str(security_resolution_status or "unknown"),
        "confirmed_chain_count": int(confirmed_chain_count or 0),
        "complete_chain_count": int(complete_chain_count or 0),
        "source_full_artifact": full.source,
        "replay_only": True,
        "ablation_scope": "analysis_stage",
        "runtime_seconds": 0.0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "worker_pid": os.getpid(),
    }
    payload.update(extra or {})
    return payload


def failed_payload(sample_id: str, variant: str, full_root: str, exc: BaseException, phase: str) -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "variant": variant,
        "schema_version": SCHEMA_VERSION,
        "status": "failed",
        "binary_prediction": "unknown",
        "final_decision": "unknown",
        "review_required": True,
        "decision_score": None,
        "risk_chain_status": "failed",
        "security_resolution_status": "failed",
        "confirmed_chain_count": 0,
        "complete_chain_count": 0,
        "source_full_artifact": str(Path(full_root) / "summary.json"),
        "replay_only": True,
        "ablation_scope": "analysis_stage",
        "runtime_seconds": 0.0,
        "exception_phase": phase,
        "exception_type": type(exc).__name__,
        "exception_message": sanitize(str(exc))[:1000],
        "traceback_tail": sanitize("\n".join(traceback.format_exc().splitlines()[-12:])),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "worker_pid": os.getpid(),
    }


def load_existing_sample(path: Path, variant: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = load_json(path)
    except Exception:
        return None
    if payload.get("status") != "completed":
        return None
    if payload.get("variant") != variant:
        return None
    if payload.get("schema_version") != SCHEMA_VERSION:
        return None
    return payload


def load_frozen_execution(full: FullArtifact) -> SandboxExecution:
    artifacts_dir = full.artifacts_dir
    trace = parse_trace_dir(artifacts_dir)
    tool_calls = strip_tool_taint(load_runtime_events(artifacts_dir / "runtime-events.jsonl"))
    llm_events = strip_llm_taint(load_llm_events(artifacts_dir / "runtime-events.jsonl"))
    mock_records = load_json(artifacts_dir / "mock-service-records.json").get("records", []) if (artifacts_dir / "mock-service-records.json").exists() else []
    network_events = trace.network + network_events_from_mock_records(mock_records)
    file_events = trace.files
    process_events = [event for event in trace.processes if event.action != "skip"]
    data_flows = build_data_flow_hints(file_events, network_events, tool_calls)
    meta = load_json(artifacts_dir / "meta.json") if (artifacts_dir / "meta.json").exists() else {}
    return SandboxExecution(
        execution_id=str(full.canonical.get("execution_id") or full.row.get("run_id") or f"ABLAT-{full.sample_id}"),
        skill_path=str(full.canonical.get("skill_path") or ""),
        skill_file=str(full.canonical.get("skill_file") or "SKILL.md"),
        sandbox_image=str(full.canonical.get("sandbox_image") or "frozen"),
        runtime_name=str(full.canonical.get("runtime_name") or ""),
        command=["frozen-replay"],
        exit_code=meta.get("exit_code", full.canonical.get("exit_code")),
        timed_out=bool(meta.get("timed_out", full.canonical.get("timed_out", False))),
        stdout=read_text(artifacts_dir / "stdout.log"),
        stderr=read_text(artifacts_dir / "stderr.log"),
        trace_artifacts=trace,
        file_events=file_events,
        network_events=network_events,
        process_events=process_events,
        tool_calls=tool_calls,
        llm_events=llm_events,
        data_flows=data_flows,
        resource_usage=ResourceUsage(),
        artifacts_dir=str(artifacts_dir),
        sandbox_image_id=str(full.canonical.get("sandbox_image_id") or ""),
        source_fingerprint=str(full.canonical.get("source_fingerprint") or ""),
        runtime_build_info=dict(full.canonical.get("runtime_build_info") or {}),
        termination_reason=full.canonical.get("termination_reason"),
        agent_step_count=int(full.canonical.get("agent_step_count") or 0),
        max_agent_steps=int(full.canonical.get("max_agent_steps") or 0),
        max_steps_exhausted=bool(full.canonical.get("max_steps_exhausted", False)),
        llm_request_retry_count=int(full.canonical.get("llm_request_retry_count") or 0),
        llm_request_retry_reasons=list(full.canonical.get("llm_request_retry_reasons") or []),
        llm_token_usage=dict(full.canonical.get("llm_token_usage") or {}),
        llm_model_name=str(full.canonical.get("llm_model_name") or ""),
        provider_retry_count=int(full.canonical.get("provider_retry_count") or 0),
        final_response_emitted=bool(full.canonical.get("final_response_emitted", False)),
        pending_tool_call=full.canonical.get("pending_tool_call"),
        pending_obligation_count=int(full.canonical.get("pending_obligation_count") or 0),
    )


def strip_tool_taint(events: list[Any]) -> list[Any]:
    for event in events:
        event.input_taint_ids = []
        event.output_taint_ids = []
        event.taint_evidence_level = None
        event.taint_propagation_rule = None
        event.metadata = strip_forbidden_keys(event.metadata, TAINT_FORBIDDEN_KEYS)
    return events


def strip_llm_taint(events: list[Any]) -> list[Any]:
    for event in events:
        event.metadata = strip_forbidden_keys(event.metadata, TAINT_FORBIDDEN_KEYS)
    return events


def sanitize_normalized_events(events: list[NormalizedEvent], *, remove_taint_events: bool) -> list[NormalizedEvent]:
    sanitized: list[NormalizedEvent] = []
    for event in events:
        if remove_taint_events and (event.event_type.startswith("taint_") or event.event_type == "candidate_dependency"):
            continue
        sanitized.append(
            NormalizedEvent(
                event_id=event.event_id,
                timestamp=event.timestamp,
                execution_id=event.execution_id,
                step_id=event.step_id,
                event_type=event.event_type,
                source=event.source,
                parent_event_id=event.parent_event_id,
                metadata=strip_forbidden_keys(event.metadata, TAINT_FORBIDDEN_KEYS),
            )
        )
    return sanitized


def sanitize_runtime_events(events: list[RuntimeEvent]) -> list[RuntimeEvent]:
    sanitized = []
    for event in events:
        event.taint_ids = []
        event.derived_from_hash = False
        event.evidence_level = "confirmed" if event.evidence_level != "unknown" else "unknown"
        if event.evidence_strength in {"exact_value", "encoded_value", "reconstructed_value", "hash_derived"}:
            event.evidence_strength = "structured_relation"
        event.metadata = strip_forbidden_keys(event.metadata, TAINT_FORBIDDEN_KEYS)
        sanitized.append(event)
    return sanitized


def build_event_only_graph_and_chains(events: list[RuntimeEvent], session_id: str) -> tuple[RuntimeProvenanceGraph, list[RuntimeChain]]:
    from app.dynamic.models import RuntimeEdge, RuntimeNode

    registry = SourceRegistry()
    nodes: dict[str, RuntimeNode] = {}
    edges: list[RuntimeEdge] = []
    sensitive_reads: list[RuntimeEvent] = []
    network_events: list[RuntimeEvent] = []

    def node(node_id: str, node_type: str, label: str, metadata: dict[str, Any] | None = None) -> str:
        if node_id not in nodes:
            nodes[node_id] = RuntimeNode(node_id=node_id, node_type=node_type, label=label, metadata=metadata or {})
        return node_id

    def edge(source: str, target: str, edge_type: str, event: RuntimeEvent, reason: str) -> str:
        edge_id = f"EOE{len(edges) + 1:06d}"
        edges.append(
            RuntimeEdge(
                edge_id=edge_id,
                source_node=source,
                target_node=target,
                edge_type=edge_type,
                event_ids=[event.event_id],
                taint_ids=[],
                evidence_level="confirmed" if event.operation != "connect" else "candidate",
                confidence=0.6 if event.operation != "connect" else 0.35,
                reason=reason,
                evidence_strength="structured_relation" if event.operation != "connect" else "temporal_cooccurrence",
                carrier_type="unknown",
                carrier_location=None,
                raw_references=[event.raw_reference] if event.raw_reference else [],
                timestamp_start=event.timestamp,
                timestamp_end=event.timestamp,
                metadata={"event_type": event.event_type, "operation": event.operation},
            )
        )
        return edge_id

    for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
        actor = node(event.actor_id, event.actor_type.title(), event.actor_id, {"process_id": event.process_id})
        if event.object_type == "file":
            path = event.object_path or event.object_id
            obj = node(f"file:{path}", "File", str(path), {"path": path})
            if event.operation == "read":
                edge(obj, actor, "READ", event, "event-only file read")
                match = registry.match_path(str(path))
                if match and str(match.sensitivity).lower() in {"medium", "high", "critical"}:
                    source = node(f"source:{path}", "SensitiveSource", str(path), {"source_type": match.source_type, "sensitivity": match.sensitivity})
                    edge(source, obj, "SOURCE_OBJECT", event, "sensitive source semantics without taint identity")
                    sensitive_reads.append(event)
            elif event.operation == "write":
                edge(actor, obj, "WRITE", event, "event-only file write")
        elif event.object_type == "network":
            endpoint = str(event.metadata.get("sink_url") or event.metadata.get("url") or event.object_id)
            obj = node(f"network:{endpoint}", "NetworkEndpoint", endpoint, {"endpoint": endpoint})
            edge(actor, obj, "SEND" if event.operation in {"send", "upload", "write"} else "CONNECT", event, "event-only network observation")
            network_events.append(event)
        elif event.object_type == "process":
            obj = node(str(event.object_id or event.actor_id), "Process", str(event.object_id or event.actor_id), {})
            edge(actor, obj, "EXEC", event, "event-only process observation")

    chains: list[RuntimeChain] = []
    for read_event in sensitive_reads:
        later_networks = [event for event in network_events if event.timestamp >= read_event.timestamp]
        if not later_networks:
            continue
        sink_event = later_networks[0]
        read_path = read_event.object_path or read_event.object_id
        endpoint = str(sink_event.metadata.get("sink_url") or sink_event.metadata.get("url") or sink_event.object_id)
        source_node = f"source:{read_path}"
        sink_node = f"network:{endpoint}"
        supporting = [read_event.event_id, sink_event.event_id]
        chains.append(
            RuntimeChain(
                chain_id=f"EOC{len(chains) + 1:06d}",
                chain_type="confidentiality_candidate",
                source=source_node,
                sink=sink_node,
                taint_ids=[],
                ordered_nodes=[source_node, f"file:{read_path}", read_event.actor_id, sink_node],
                ordered_edges=[edge.edge_id for edge in edges if set(edge.event_ids) & set(supporting)],
                supporting_event_ids=supporting,
                evidence_level="candidate",
                missing_observation_points=["taint_flow_identity", "payload_or_carrier_continuity"],
                coverage_status="insufficient_coverage",
                explanation="Event-only temporal source-to-network candidate without taint-aware flow identity.",
                evidence_strengths=["temporal_cooccurrence"],
                confidence=0.35,
                metadata={"ablation": "event_only", "chain_validation": "actor_object_temporal_only"},
            )
        )
    return RuntimeProvenanceGraph(session_id=session_id, nodes=list(nodes.values()), edges=edges), chains


def dynamic_from_full_without_alignment(full: FullArtifact) -> DynamicAnalysisResult:
    runtime_events = [RuntimeEvent.from_dict(item) for item in full.canonical.get("runtime_events_v2", []) or []]
    chains = [runtime_chain_from_dict(item) for item in full.canonical.get("runtime_chains", []) or []]
    violations = [PolicyViolation(**item) for item in full.canonical.get("runtime_policy_violations", []) or []]
    coverage = coverage_from_dict(full.canonical.get("runtime_coverage", {}) or {})
    return DynamicAnalysisResult(runtime_events, graph_from_full(full), chains, coverage, violations, full.canonical.get("taint_sources", []), None)


def graph_from_full(full: FullArtifact) -> RuntimeProvenanceGraph:
    from app.dynamic.models import RuntimeEdge, RuntimeNode

    payload = full.canonical.get("runtime_provenance_graph", {}) or {}
    nodes = [RuntimeNode(**item) for item in payload.get("nodes", []) or []]
    edges = [RuntimeEdge(**item) for item in payload.get("edges", []) or []]
    return RuntimeProvenanceGraph(session_id=str(payload.get("session_id") or full.sample_id), nodes=nodes, edges=edges, schema_version=str(payload.get("schema_version") or "runtime-analysis-v3"))


def runtime_chain_from_dict(item: dict[str, Any]) -> RuntimeChain:
    allowed = set(RuntimeChain.__dataclass_fields__)
    data = {key: value for key, value in item.items() if key in allowed}
    return RuntimeChain(**data)


def coverage_from_dict(item: dict[str, Any]) -> CoverageReport:
    return CoverageReport(
        coverage_state=str(item.get("coverage_state") or "unknown"),
        reasons=list(item.get("reasons") or []),
        observed_event_count=int(item.get("observed_event_count") or 0),
        expected_observations=list(item.get("expected_observations") or []),
        missing_observations=list(item.get("missing_observations") or []),
        metadata=dict(item.get("metadata") or {}),
    )


def policy_disabled_decision(dynamic: DynamicAnalysisResult, static_payload: dict[str, Any]) -> dict[str, Any]:
    confirmed = [chain for chain in dynamic.chains if chain.chain_type.endswith("_confirmed")]
    candidates = [chain for chain in dynamic.chains if "candidate" in chain.chain_type]
    static_violations = [
        chain for chain in static_payload.get("static_chains", []) or []
        if str(chain.get("alert_status") or chain.get("policy_status") or "").lower() in {"violation", "review"}
    ]
    if confirmed:
        return {
            "binary_prediction": "malicious",
            "final_decision": "malicious",
            "review_required": False,
            "decision_score": 0.95,
            "risk_chain_status": "policy_disabled_confirmed_flow",
            "confirmed_chain_count": len(confirmed),
        }
    if candidates or static_violations:
        return {
            "binary_prediction": "malicious",
            "final_decision": "malicious",
            "review_required": True,
            "decision_score": 0.74,
            "risk_chain_status": "policy_disabled_candidate_or_static_flow",
            "confirmed_chain_count": 0,
        }
    return {
        "binary_prediction": "benign",
        "final_decision": "benign",
        "review_required": False,
        "decision_score": 0.12,
        "risk_chain_status": "policy_disabled_no_flow_observed",
        "confirmed_chain_count": 0,
    }


def static_policy_findings(static_payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for chain in static_payload.get("static_chains", []) or []:
        alert = str(chain.get("alert_status") or chain.get("policy_status") or "capability_only").lower()
        status = "violation" if alert == "violation" else "review" if alert == "review" else "capability"
        findings.append(
            {
                "origin": "static",
                "policy_domain": str(chain.get("capability_type") or chain.get("chain_type") or "static"),
                "status": status,
                "evidence_status": "instruction_supported",
                "supporting_ids": [str(chain.get("chain_id") or "")],
                "reason": str(chain.get("explanation") or chain.get("policy_status") or "static instruction finding"),
            }
        )
    return findings


def runtime_policy_findings(violations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "origin": "runtime",
            "policy_domain": str(item.get("policy_type") or "confidentiality"),
            "status": "violation",
            "evidence_status": "runtime_confirmed",
            "supporting_ids": [str(item.get("violation_id") or item.get("chain_id") or "")],
            "reason": str(item.get("reason") or "runtime policy violation"),
        }
        for item in violations
    ]


def static_mapping_manifest() -> dict[str, Any]:
    return {
        "frozen_before_smoke": True,
        "ground_truth_independent": True,
        "rule": "Use existing static_chains alert_status/policy_status through app.dynamic.review_lean static_only scoring.",
        "violation_semantics": "alert_status=violation or policy_status=untrusted_external_flow is high-confidence static risk.",
        "review_semantics": "alert_status=review or ambiguous/high-risk static action enters review band.",
        "no_runtime_semantics": "No runtime event, trace, taint, provenance, alignment, or Full final decision is used.",
    }


def full_consistency(full: FullArtifact) -> dict[str, Any]:
    fields = ["binary_prediction", "final_decision", "review_required", "decision_score", "security_resolution_status"]
    mismatches = {}
    for field in fields:
        row_value = full.row.get(field)
        canonical_value = full.canonical.get(field)
        if row_value is not None and canonical_value is not None and row_value != canonical_value:
            mismatches[field] = {"summary": row_value, "canonical": canonical_value}
    risk_status = full.canonical.get("risk_chain_status")
    if isinstance(risk_status, dict):
        canonical_status = risk_status.get("status")
        if full.row.get("risk_chain_status") != canonical_status:
            mismatches["risk_chain_status"] = {"summary": full.row.get("risk_chain_status"), "canonical_status": canonical_status}
    elif risk_status is not None and full.row.get("risk_chain_status") != risk_status:
        mismatches["risk_chain_status"] = {"summary": full.row.get("risk_chain_status"), "canonical": risk_status}
    return {
        "matches_frozen_summary": not mismatches,
        "mismatches": mismatches,
        "comparison_basis": "runner output copies frozen summary.json fields; canonical nested risk_chain_status is compared by status only",
    }


def event_only_risk_status(chains: list[RuntimeChain], coverage: CoverageReport) -> str:
    if chains:
        return "event_only_candidate_flow"
    return f"event_only_{coverage.coverage_state}"


def no_alignment_risk_status(dynamic: DynamicAnalysisResult) -> str:
    if dynamic.policy_violations:
        return "confirmed_violation"
    if any(chain.chain_type.endswith("_confirmed") for chain in dynamic.chains):
        return "confirmed_flow_policy_allowed_or_unclassified"
    if any("candidate" in chain.chain_type for chain in dynamic.chains):
        return "candidate_flow"
    return "no_sensitive_flow_observed"


def count_complete_chains(chains: list[Any]) -> int:
    count = 0
    for chain in chains:
        payload = chain.to_dict() if hasattr(chain, "to_dict") else chain
        if str(payload.get("coverage_status") or "") == "runtime_confirmed" or str(payload.get("chain_type") or "").endswith("_confirmed"):
            count += 1
    return count


def network_events_from_mock_records(records: list[dict[str, Any]]) -> list[NetworkEvent]:
    events: list[NetworkEvent] = []
    for index, record in enumerate(records, start=1):
        port = int(record.get("port") or 0)
        path = str(record.get("path") or "/")
        address = f"http://localhost:{port}{path}" if port else f"http://localhost{path}"
        events.append(
            NetworkEvent(
                timestamp=str(record.get("timestamp") or ""),
                address=address,
                action="send",
                raw=f"mock service received {record.get('method')} {path}",
                host="localhost",
                port=port or None,
                display_label=address,
                endpoint_kind="http",
                endpoint_source="fixture_mock_service",
                endpoint_role="mock_sink",
                sink_resolution_status="controlled_mock",
                original_url=address,
                sink_url=address,
                sink_port=port or None,
                sink_type="mock_http",
                is_controlled_sink=True,
                network_evidence_sources=["fixture_mock_receipt"],
                byte_count=int(record.get("body_length") or 0),
                encrypted_payload_invisible=False,
                network_evidence_level="request_observed",
                carrier_type="http_body" if int(record.get("body_length") or 0) else "http_query",
                carrier_location="body" if int(record.get("body_length") or 0) else "query",
                event_id=f"event-only-mock-network-{index:04d}",
                source="fixture_mock",
            )
        )
    return events


def write_variant_outputs(
    *,
    output_root: Path,
    variant: str,
    rows: list[dict[str, Any]],
    started: float,
    args: argparse.Namespace,
) -> dict[str, Any]:
    variant_root = output_root / variant
    elapsed = round(time.perf_counter() - started, 4)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "variant": variant,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "full_root": str(Path(args.full_root).resolve()),
        "benchmark_root": str(Path(args.benchmark_root).resolve()),
        "workers": args.workers,
        "executor": "ProcessPoolExecutor" if args.workers > 1 else "serial",
        "sample_count": len(rows),
        "completed_count": sum(1 for row in rows if row.get("status") == "completed"),
        "failed_count": sum(1 for row in rows if row.get("status") == "failed"),
        "elapsed_seconds": elapsed,
        "samples": sorted(rows, key=lambda row: row["sample_id"]),
    }
    atomic_write_json(variant_root / "summary.json", payload)
    write_csv(variant_root / "summary.csv", payload["samples"])
    write_markdown(variant_root / "summary.md", payload)
    return payload


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "sample_id", "variant", "status", "binary_prediction", "final_decision", "review_required",
        "decision_score", "risk_chain_status", "security_resolution_status", "confirmed_chain_count",
        "complete_chain_count", "runtime_seconds", "source_full_artifact",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        f"# Benchmark v3 Ablation Replay: {payload['variant']}",
        "",
        f"- Schema: `{payload['schema_version']}`",
        f"- Workers: `{payload['workers']}`",
        f"- Executor: `{payload['executor']}`",
        f"- Samples: `{payload['sample_count']}`",
        f"- Completed: `{payload['completed_count']}`",
        f"- Failed: `{payload['failed_count']}`",
        f"- Runtime seconds: `{payload['elapsed_seconds']}`",
        "",
        "| Sample | Status | Prediction | Review | Score | Risk | Security |",
        "|---|---|---|---:|---:|---|---|",
    ]
    for row in payload["samples"]:
        lines.append(
            f"| {row['sample_id']} | {row.get('status')} | {row.get('binary_prediction')} | "
            f"{row.get('review_required')} | {row.get('decision_score')} | {row.get('risk_chain_status')} | {row.get('security_resolution_status')} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def evaluate_only(args: argparse.Namespace, output_root: Path) -> int:
    variant_root = output_root / args.variant
    summary = load_json(variant_root / "summary.json")
    print(json.dumps({"variant": args.variant, "sample_count": summary.get("sample_count"), "completed_count": summary.get("completed_count"), "failed_count": summary.get("failed_count")}, ensure_ascii=False, indent=2))
    return 0


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(path.parent), delete=False) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, default=str)
        handle.write("\n")
        tmp = Path(handle.name)
    tmp.replace(path)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def normalize_score(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return round(float(value), 4)
    except (TypeError, ValueError):
        return None


def strip_forbidden_keys(value: Any, forbidden: set[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: strip_forbidden_keys(sub_value, forbidden)
            for key, sub_value in value.items()
            if key not in forbidden and not any(token in key for token in forbidden)
        }
    if isinstance(value, list):
        return [strip_forbidden_keys(item, forbidden) for item in value]
    return value


def forbidden_key_hits(value: Any, forbidden: set[str], path: str = "$") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, sub_value in value.items():
            if key in forbidden or any(token == key for token in forbidden):
                hits.append(f"{path}.{key}")
            hits.extend(forbidden_key_hits(sub_value, forbidden, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            hits.extend(forbidden_key_hits(item, forbidden, f"{path}[{index}]"))
    return hits


def forbidden_token_hits(value: Any, tokens: set[str]) -> list[str]:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
    return sorted(token for token in tokens if token.lower() in text)


def sanitize(text: str) -> str:
    redacted = text
    for key in (os.environ.get("PROVLOOM_SCAN_API_KEY"), os.environ.get("PROVLOOM_LLM_API_KEY"), os.environ.get("OPENAI_API_KEY")):
        if key:
            redacted = redacted.replace(key, "[REDACTED_API_KEY]")
    return redacted


if __name__ == "__main__":
    raise SystemExit(main())
