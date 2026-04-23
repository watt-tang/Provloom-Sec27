from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import uuid
from dataclasses import asdict, is_dataclass
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.analyzer.rules import analyze_static_skill, analyze_trace
from app.backend.schemas import LLMConfig
from app.runner.docker_runner import DockerRunner
from app.runtime.skill_parser import load_skill_definition, resolve_skill_target
from app.telemetry.collector import build_execution_report

BASELINES = ["static_only", "rule_only", "rule_plus_epg", "epg_with_filtering"]
HIGH_RISK_BEHAVIORS = {"sensitive_file_read", "read_then_exfiltration"}


@dataclass
class BenchmarkCase:
    case_id: str
    skill_path: str
    is_malicious: bool
    expected_behaviors: list[str]
    expected_source_nodes: list[dict[str, Any]]
    expected_sink_nodes: list[dict[str, Any]]
    expected_primary_chain: list[dict[str, Any]]
    expected_root_cause: str
    dynamic_runnable: bool
    family: str
    notes: str = ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ACSAC-style benchmark over Skill sandbox baselines.")
    parser.add_argument("--datasets-root", default="datasets")
    parser.add_argument("--analysis-mode", choices=BASELINES + ["all"], default="all")
    parser.add_argument("--timeout-seconds", default=30, type=int)
    parser.add_argument("--network-policy", default="default", choices=["default", "disabled"])
    args = parser.parse_args()

    datasets_root = Path(args.datasets_root).resolve()
    benchmark_root = Path("artifacts/benchmark")
    benchmark_root.mkdir(parents=True, exist_ok=True)
    cases = discover_cases(datasets_root)
    modes = BASELINES if args.analysis_mode == "all" else [args.analysis_mode]

    runner = DockerRunner()
    baseline_results: dict[str, dict[str, Any]] = {}
    csv_rows: list[dict[str, Any]] = []

    for mode in modes:
        case_rows: list[dict[str, Any]] = []
        for case in cases:
            evaluation = run_and_evaluate_case(
                case=case,
                analysis_mode=mode,
                timeout_seconds=args.timeout_seconds,
                network_policy=args.network_policy,
                runner=runner,
                benchmark_root=benchmark_root,
            )
            case_rows.append(evaluation)
        summary = aggregate_rows(case_rows)
        summary["analysis_mode"] = mode
        baseline_results[mode] = {
            "summary": summary,
            "cases": case_rows,
        }
        csv_rows.append(_flatten_summary_row(summary, mode))

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "datasets_root": str(datasets_root),
        "baseline_order": modes,
        "ground_truth_schema_version": "v1",
        "baseline_results": baseline_results,
        "comparison_table": csv_rows,
    }
    write_summary_files(benchmark_root, csv_rows, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def discover_cases(datasets_root: Path) -> list[BenchmarkCase]:
    skills_root = datasets_root / "skills"
    truth_root = datasets_root / "ground_truth"
    cases: list[BenchmarkCase] = []
    for family in ("benign", "malicious"):
        family_root = skills_root / family
        if not family_root.exists():
            continue
        for candidate in sorted(family_root.iterdir()):
            if not candidate.is_dir():
                continue
            source_dir, _ = resolve_skill_target(str(candidate))
            case_id = candidate.name
            ground_truth = load_ground_truth(truth_root / f"{case_id}.json")
            cases.append(
                BenchmarkCase(
                    case_id=ground_truth["case_id"],
                    skill_path=str(source_dir),
                    is_malicious=bool(ground_truth["is_malicious"]),
                    expected_behaviors=list(ground_truth.get("expected_behaviors", [])),
                    expected_source_nodes=list(ground_truth.get("expected_source_nodes", [])),
                    expected_sink_nodes=list(ground_truth.get("expected_sink_nodes", [])),
                    expected_primary_chain=list(ground_truth.get("expected_primary_chain", [])),
                    expected_root_cause=ground_truth.get("expected_root_cause", "unknown"),
                    dynamic_runnable=bool(ground_truth.get("dynamic_runnable", True)),
                    family=family,
                    notes=ground_truth.get("notes", ""),
                )
            )
    return cases


def load_ground_truth(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing ground truth file: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "case_id",
        "is_malicious",
        "expected_behaviors",
        "expected_source_nodes",
        "expected_sink_nodes",
        "expected_primary_chain",
        "expected_root_cause",
        "dynamic_runnable",
    }
    missing = sorted(required - payload.keys())
    if missing:
        raise ValueError(f"Ground truth file {path} is missing fields: {', '.join(missing)}")
    return payload


def run_and_evaluate_case(
    case: BenchmarkCase,
    analysis_mode: str,
    timeout_seconds: int,
    network_policy: str,
    runner: DockerRunner,
    benchmark_root: Path,
) -> dict[str, Any]:
    if analysis_mode != "static_only" and not case.dynamic_runnable:
        return _skipped_case_result(case, analysis_mode)

    started = time.perf_counter()
    try:
        prediction = run_case(
            case=case,
            analysis_mode=analysis_mode,
            timeout_seconds=timeout_seconds,
            network_policy=network_policy,
            runner=runner,
            benchmark_root=benchmark_root,
        )
        prediction["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    except Exception as exc:  # pragma: no cover - benchmark resilience path
        prediction = {
            "status": "failed",
            "analysis_mode": analysis_mode,
            "detected_behaviors": [],
            "primary_chain": [],
            "root_cause": "unknown",
            "root_cause_detail": "unknown",
            "root_cause_evidence": {},
            "graph_summary": {},
            "artifact_dir": None,
            "benchmark_case_dir": None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": str(exc),
        }
    return evaluate_case(case, prediction)


def run_case(
    case: BenchmarkCase,
    analysis_mode: str,
    timeout_seconds: int,
    network_policy: str,
    runner: DockerRunner,
    benchmark_root: Path,
) -> dict[str, Any]:
    execution_id = uuid.uuid4().hex
    source_dir, skill_file = resolve_skill_target(case.skill_path)

    if analysis_mode == "static_only":
        definition = load_skill_definition(source_dir, skill_file, allow_empty_actions=True)
        analysis = analyze_static_skill(definition, analysis_mode=analysis_mode)
        artifact_dir = benchmark_root / "cases" / analysis_mode / case.case_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "result.json").write_text(
            json.dumps(analysis, ensure_ascii=False, indent=2, default=_json_default),
            encoding="utf-8",
        )
        return {
            "status": "completed",
            "analysis_mode": analysis_mode,
            "detected_behaviors": analysis.get("detected_behaviors", []),
            "primary_chain": analysis.get("primary_chain", []),
            "root_cause": analysis.get("root_cause", "unknown"),
            "root_cause_detail": analysis.get("root_cause_detail", analysis.get("root_cause", "unknown")),
            "root_cause_evidence": analysis.get("root_cause_evidence", {}),
            "graph_summary": analysis.get("graph_summary", {}),
            "final_decision": analysis.get("final_decision", "unknown"),
            "triggered_factors": analysis.get("triggered_factors", []),
            "suppression_factors": analysis.get("suppression_factors", []),
            "decision_evidence": analysis.get("decision_evidence", {}),
            "artifact_dir": str(artifact_dir),
        }

    execution = runner.run(
        execution_id=execution_id,
        skill_path=str(source_dir),
        input_payload={},
        timeout_seconds=timeout_seconds,
        network_policy=network_policy,
        llm_config=LLMConfig(),
    )
    analysis = analyze_trace(execution, analysis_mode=analysis_mode)
    telemetry = build_execution_report(execution)
    artifact_dir = Path(execution.artifacts_dir)
    benchmark_case_dir = benchmark_root / "cases" / analysis_mode / case.case_id
    benchmark_case_dir.mkdir(parents=True, exist_ok=True)
    (benchmark_case_dir / "result.json").write_text(
        json.dumps(
            {
                "analysis": analysis,
                "telemetry_summary": {
                    "file_event_count": len(telemetry.get("file_events", [])),
                    "network_event_count": len(telemetry.get("network_events", [])),
                    "process_event_count": len(telemetry.get("process_events", [])),
                    "normalized_event_count": len(telemetry.get("normalized_events", [])),
                },
                "execution_artifact_dir": str(artifact_dir),
            },
            ensure_ascii=False,
            indent=2,
            default=_json_default,
        ),
        encoding="utf-8",
    )
    return {
        "status": "completed",
        "analysis_mode": analysis_mode,
        "detected_behaviors": analysis.get("detected_behaviors", []),
        "primary_chain": analysis.get("primary_chain", []),
        "root_cause": analysis.get("root_cause", "unknown"),
        "root_cause_detail": analysis.get("root_cause_detail", analysis.get("root_cause", "unknown")),
        "root_cause_evidence": analysis.get("root_cause_evidence", {}),
        "graph_summary": analysis.get("graph_summary", {}),
        "final_decision": analysis.get("final_decision", "unknown"),
        "triggered_factors": analysis.get("triggered_factors", []),
        "suppression_factors": analysis.get("suppression_factors", []),
        "decision_evidence": analysis.get("decision_evidence", {}),
        "artifact_dir": str(artifact_dir),
        "benchmark_case_dir": str(benchmark_case_dir),
    }


def evaluate_case(case: BenchmarkCase, prediction: dict[str, Any]) -> dict[str, Any]:
    detected_behaviors = set(prediction.get("detected_behaviors", []))
    expected_behaviors = set(case.expected_behaviors)
    behaviors_match = expected_behaviors.issubset(detected_behaviors)
    predicted_malicious = _is_alerting_prediction(
        prediction=prediction,
        is_malicious_case=case.is_malicious,
        detected_behaviors=detected_behaviors,
        expected_behaviors=expected_behaviors,
    )
    endpoint_accuracy = compute_endpoint_accuracy(case, prediction.get("primary_chain", []))
    edge_level_f1 = compute_edge_level_f1(case.expected_primary_chain, prediction.get("primary_chain", []))
    complete_chain_rate = compute_complete_chain_rate(case.expected_primary_chain, prediction.get("primary_chain", []))
    partial_chain_usefulness = compute_partial_chain_usefulness(
        case.expected_source_nodes,
        case.expected_sink_nodes,
        prediction.get("primary_chain", []),
    )
    root_cause_detail = prediction.get("root_cause_detail", prediction.get("root_cause", "unknown"))
    root_cause_accuracy = (
        1.0 if root_cause_detail == case.expected_root_cause else 0.0
    ) if case.is_malicious else None

    return {
        "case_id": case.case_id,
        "family": case.family,
        "analysis_mode": prediction["analysis_mode"],
        "status": prediction.get("status", "completed"),
        "is_malicious": case.is_malicious,
        "dynamic_runnable": case.dynamic_runnable,
        "predicted_malicious": predicted_malicious,
        "behaviors_match": behaviors_match,
        "expected_behaviors": sorted(expected_behaviors),
        "detected_behaviors": sorted(detected_behaviors),
        "endpoint_accuracy": endpoint_accuracy,
        "edge_level_f1": edge_level_f1,
        "complete_chain_rate": complete_chain_rate,
        "partial_chain_usefulness": partial_chain_usefulness,
        "expected_root_cause": case.expected_root_cause,
        "predicted_root_cause": prediction.get("root_cause", "unknown"),
        "predicted_root_cause_detail": root_cause_detail,
        "root_cause_evidence": prediction.get("root_cause_evidence", {}),
        "final_decision": prediction.get("final_decision", "unknown"),
        "triggered_factors": prediction.get("triggered_factors", []),
        "suppression_factors": prediction.get("suppression_factors", []),
        "decision_evidence": prediction.get("decision_evidence", {}),
        "root_cause_accuracy": root_cause_accuracy,
        "latency_ms": prediction.get("latency_ms"),
        "artifact_dir": prediction.get("artifact_dir"),
        "benchmark_case_dir": prediction.get("benchmark_case_dir"),
        "graph_summary": prediction.get("graph_summary", {}),
        "primary_chain": prediction.get("primary_chain", []),
        "notes": case.notes,
        "skip_reason": prediction.get("skip_reason"),
        "error": prediction.get("error"),
    }


def compute_endpoint_accuracy(case: BenchmarkCase, predicted_chain: list[dict[str, Any]]) -> float | None:
    """Endpoint accuracy: source and sink node signatures must match GT endpoints."""

    if not case.expected_source_nodes and not case.expected_sink_nodes:
        return None
    predicted_sources = _predicted_source_nodes(predicted_chain)
    predicted_sinks = _predicted_sink_nodes(predicted_chain)
    source_hit = _node_set_matches(case.expected_source_nodes, predicted_sources)
    sink_hit = _node_set_matches(case.expected_sink_nodes, predicted_sinks)
    return round((float(source_hit) + float(sink_hit)) / 2.0, 4)


def compute_edge_level_f1(expected_chain: list[dict[str, Any]], predicted_chain: list[dict[str, Any]]) -> float | None:
    """
    Edge-level F1 over semantic chain edges.

    We intentionally score the projected attack-chain skeleton rather than exact
    node-label matches. This avoids under-scoring cases where the system inserts
    relay nodes such as tool calls, or recovers the correct source-to-sink
    structure with different concrete internal labels.
    """

    expected_edges = _semantic_chain_edges(expected_chain)
    predicted_edges = _semantic_chain_edges(predicted_chain)
    if not expected_edges and not predicted_edges:
        return None
    if not expected_edges or not predicted_edges:
        return 0.0
    intersection = len(expected_edges & predicted_edges)
    precision = intersection / len(predicted_edges)
    recall = intersection / len(expected_edges)
    if precision + recall == 0:
        return 0.0
    return round((2 * precision * recall) / (precision + recall), 4)


def compute_complete_chain_rate(expected_chain: list[dict[str, Any]], predicted_chain: list[dict[str, Any]]) -> float | None:
    """
    Complete-chain rate over the semantic chain skeleton.

    A prediction is counted as complete when its projected attack-chain roles
    cover the GT chain roles in order. Exact node labels are handled separately
    by endpoint accuracy and are not required here.
    """

    if not expected_chain:
        return None
    expected_signature = _semantic_chain_signature(expected_chain)
    predicted_signature = _semantic_chain_signature(predicted_chain)
    if not predicted_signature:
        return 0.0
    return 1.0 if _is_subsequence(expected_signature, predicted_signature) else 0.0


def compute_partial_chain_usefulness(
    expected_sources: list[dict[str, Any]],
    expected_sinks: list[dict[str, Any]],
    predicted_chain: list[dict[str, Any]],
) -> float | None:
    """Partial usefulness: the predicted chain preserves the GT source-to-sink direction."""

    if not expected_sources and not expected_sinks:
        return None
    chain_signatures = [_node_signature(node) for node in predicted_chain]
    source_signatures = {_node_signature(node) for node in expected_sources}
    sink_signatures = {_node_signature(node) for node in expected_sinks}

    source_index = next((index for index, sig in enumerate(chain_signatures) if sig in source_signatures), None)
    sink_index = next((index for index, sig in enumerate(chain_signatures) if sig in sink_signatures), None)
    if source_index is None or sink_index is None:
        return 0.0
    return 1.0 if source_index < sink_index else 0.0


def aggregate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [row for row in rows if row["status"] == "completed"]
    skipped = [row for row in rows if row["status"] == "skipped"]
    failed = [row for row in rows if row["status"] == "failed"]
    malicious = [row for row in completed if row["is_malicious"]]
    benign = [row for row in completed if not row["is_malicious"]]
    detection_hits = [row for row in malicious if row["behaviors_match"]]
    false_positives = [row for row in benign if row["predicted_malicious"]]

    def avg_metric(name: str, subset: list[dict[str, Any]]) -> float:
        values = [float(row[name]) for row in subset if row.get(name) is not None]
        if not values:
            return 0.0
        return round(sum(values) / len(values), 4)

    return {
        "case_count": len(rows),
        "completed_case_count": len(completed),
        "skipped_case_count": len(skipped),
        "failed_case_count": len(failed),
        "malicious_case_count": len(malicious),
        "benign_case_count": len(benign),
        "detection_rate": round(len(detection_hits) / len(malicious), 4) if malicious else 0.0,
        "false_positive_rate": round(len(false_positives) / len(benign), 4) if benign else 0.0,
        "endpoint_accuracy": avg_metric("endpoint_accuracy", malicious),
        "edge_level_f1": avg_metric("edge_level_f1", malicious),
        "complete_chain_rate": avg_metric("complete_chain_rate", malicious),
        "partial_chain_usefulness": avg_metric("partial_chain_usefulness", malicious),
        "root_cause_accuracy": avg_metric("root_cause_accuracy", malicious),
        "avg_latency_ms": avg_metric("latency_ms", completed),
    }


def write_summary_files(benchmark_root: Path, csv_rows: list[dict[str, Any]], payload: dict[str, Any]) -> None:
    (benchmark_root / "benchmark-summary.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    with (benchmark_root / "benchmark-summary.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "analysis_mode",
                "case_count",
                "completed_case_count",
                "skipped_case_count",
                "failed_case_count",
                "malicious_case_count",
                "benign_case_count",
                "detection_rate",
                "false_positive_rate",
                "endpoint_accuracy",
                "edge_level_f1",
                "complete_chain_rate",
                "partial_chain_usefulness",
                "root_cause_accuracy",
                "avg_latency_ms",
            ],
        )
        writer.writeheader()
        for row in csv_rows:
            writer.writerow(row)


def _flatten_summary_row(summary: dict[str, Any], analysis_mode: str) -> dict[str, Any]:
    return {
        "analysis_mode": analysis_mode,
        "case_count": summary["case_count"],
        "completed_case_count": summary["completed_case_count"],
        "skipped_case_count": summary["skipped_case_count"],
        "failed_case_count": summary["failed_case_count"],
        "malicious_case_count": summary["malicious_case_count"],
        "benign_case_count": summary["benign_case_count"],
        "detection_rate": summary["detection_rate"],
        "false_positive_rate": summary["false_positive_rate"],
        "endpoint_accuracy": summary["endpoint_accuracy"],
        "edge_level_f1": summary["edge_level_f1"],
        "complete_chain_rate": summary["complete_chain_rate"],
        "partial_chain_usefulness": summary["partial_chain_usefulness"],
        "root_cause_accuracy": summary["root_cause_accuracy"],
        "avg_latency_ms": summary["avg_latency_ms"],
    }


def _skipped_case_result(case: BenchmarkCase, analysis_mode: str) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "family": case.family,
        "analysis_mode": analysis_mode,
        "status": "skipped",
        "is_malicious": case.is_malicious,
        "dynamic_runnable": case.dynamic_runnable,
        "predicted_malicious": False,
        "behaviors_match": False,
        "expected_behaviors": case.expected_behaviors,
        "detected_behaviors": [],
        "endpoint_accuracy": None,
        "edge_level_f1": None,
        "complete_chain_rate": None,
        "partial_chain_usefulness": None,
        "expected_root_cause": case.expected_root_cause,
        "predicted_root_cause": "unknown",
        "predicted_root_cause_detail": "unknown",
        "root_cause_evidence": {},
        "root_cause_accuracy": None,
        "latency_ms": None,
        "artifact_dir": None,
        "benchmark_case_dir": None,
        "graph_summary": {},
        "primary_chain": [],
        "notes": case.notes,
        "skip_reason": "dynamic_runnable=false",
    }


def _predicted_source_nodes(chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return chain[:1]


def _predicted_sink_nodes(chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return chain[-1:] if chain else []


def _is_alerting_prediction(
    prediction: dict[str, Any],
    is_malicious_case: bool,
    detected_behaviors: set[str],
    expected_behaviors: set[str],
) -> bool:
    final_decision = prediction.get("final_decision")
    if final_decision in {"malicious", "needs_review", "benign"}:
        return final_decision in {"malicious", "needs_review"}
    return _is_predicted_malicious(
        is_malicious_case=is_malicious_case,
        detected_behaviors=detected_behaviors,
        expected_behaviors=expected_behaviors,
    )


def _is_predicted_malicious(
    is_malicious_case: bool,
    detected_behaviors: set[str],
    expected_behaviors: set[str],
) -> bool:
    """For benign cases, only unexpected high-risk behaviors count as false-positive alerts."""

    if is_malicious_case:
        return bool(detected_behaviors)
    unexpected_behaviors = detected_behaviors - expected_behaviors
    return bool(unexpected_behaviors & HIGH_RISK_BEHAVIORS)


def _node_set_matches(expected_nodes: list[dict[str, Any]], predicted_nodes: list[dict[str, Any]]) -> bool:
    if not expected_nodes:
        return not predicted_nodes
    expected_signatures = {_node_signature(node) for node in expected_nodes}
    predicted_signatures = {_node_signature(node) for node in predicted_nodes}
    return expected_signatures.issubset(predicted_signatures)


def _node_signature(node: dict[str, Any]) -> tuple[str | None, str | None]:
    return node.get("node_type"), str(node.get("label", "")).strip()


def _chain_signature(chain: list[dict[str, Any]]) -> list[tuple[str | None, str | None]]:
    return [_node_signature(node) for node in chain]


def _chain_edges(chain: list[dict[str, Any]]) -> set[tuple[tuple[str | None, str | None], tuple[str | None, str | None]]]:
    signatures = _chain_signature(chain)
    return {
        (signatures[index], signatures[index + 1])
        for index in range(len(signatures) - 1)
    }


def _semantic_chain_signature(chain: list[dict[str, Any]]) -> list[str]:
    """
    Project a concrete chain to its attack-chain skeleton.

    This keeps only salient source/sink/data-bearing roles and removes relay-only
    nodes such as tool calls, which makes benchmark scoring reflect chain
    semantics instead of exact graph rendering choices.
    """

    projected: list[str] = []
    for node in chain:
        role = _semantic_node_role(node)
        if role is None:
            continue
        if not projected or projected[-1] != role:
            projected.append(role)
    return projected


def _semantic_chain_edges(chain: list[dict[str, Any]]) -> set[tuple[str, str]]:
    signature = _semantic_chain_signature(chain)
    return {
        (signature[index], signature[index + 1])
        for index in range(len(signature) - 1)
    }


def _semantic_node_role(node: dict[str, Any]) -> str | None:
    node_type = node.get("node_type")
    if node_type == "network_endpoint":
        if node.get("endpoint_role") == "relay":
            return "relay:network"
        return "sink:network"
    if node_type == "file":
        return "artifact:file"
    if node_type == "data":
        return "artifact:data"
    if node_type == "process":
        return "relay:process"
    if node_type == "tool_call":
        return None
    return node_type or None


def _is_subsequence(expected: list[str], predicted: list[str]) -> bool:
    if not expected:
        return True
    expected_index = 0
    for item in predicted:
        if item == expected[expected_index]:
            expected_index += 1
            if expected_index == len(expected):
                return True
    return False


def _json_default(value: Any):
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


if __name__ == "__main__":
    raise SystemExit(main())
