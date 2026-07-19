from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate ProvLoom dynamic runtime taint/provenance outputs.")
    parser.add_argument("--predictions", required=True, help="JSONL rows with case_id and dynamic-analysis payload or artifact path.")
    parser.add_argument("--ground-truth", required=True, help="JSON mapping case_id to expected sources/sinks/edges/chains.")
    args = parser.parse_args()

    truth = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))
    rows = [_load_row(json.loads(line)) for line in Path(args.predictions).read_text(encoding="utf-8").splitlines() if line.strip()]
    metrics = evaluate(rows, truth)
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


def evaluate(rows: list[dict[str, Any]], truth: dict[str, Any]) -> dict[str, Any]:
    source_scores = []
    sink_scores = []
    edge_scores = []
    complete_chain_hits = 0
    false_closures = 0
    confirmed_true = 0
    confirmed_total = 0
    overheads = []
    event_loss = []
    coverage_states: dict[str, int] = {}
    trigger_hits = 0
    for row in rows:
        case_id = row["case_id"]
        expected = truth.get(case_id, {})
        predicted = row["analysis"]
        source_scores.append(_prf(_sources(predicted), set(expected.get("sources", []))))
        sink_scores.append(_prf(_sinks(predicted), set(expected.get("sinks", []))))
        edge_scores.append(_prf(_taint_edges(predicted), set(expected.get("taint_edges", []))))
        chains = predicted.get("runtime_chains", [])
        expected_chain = bool(expected.get("complete_chain", False))
        has_complete = any(chain.get("chain_type") == "confidentiality" for chain in chains)
        complete_chain_hits += int(expected_chain and has_complete)
        false_closures += int((not expected_chain) and has_complete)
        confirmed = [chain for chain in chains if chain.get("evidence_level") == "confirmed"]
        confirmed_total += len(confirmed)
        confirmed_true += sum(1 for chain in confirmed if expected_chain and chain.get("chain_type") == "confidentiality")
        coverage = predicted.get("coverage", {}).get("coverage_state", "unknown")
        coverage_states[coverage] = coverage_states.get(coverage, 0) + 1
        trigger_hits += int(coverage in {"triggered_and_observed", "triggered_but_partially_observed"})
        if "runtime_overhead_ms" in row:
            overheads.append(float(row["runtime_overhead_ms"]))
        if "event_loss_rate" in row:
            event_loss.append(float(row["event_loss_rate"]))

    count = max(1, len(rows))
    return {
        "source_identification": _avg_prf(source_scores),
        "sink_identification": _avg_prf(sink_scores),
        "taint_edge": _avg_prf(edge_scores),
        "complete_chain_recall": complete_chain_hits / max(1, sum(1 for value in truth.values() if value.get("complete_chain"))),
        "false_closure_rate": false_closures / count,
        "confirmed_flow_precision": confirmed_true / max(1, confirmed_total),
        "coverage": coverage_states,
        "trigger_rate": trigger_hits / count,
        "conditional_chain_recovery": _chain_recall(rows, truth, "conditional_chain"),
        "end_to_end_chain_recovery": _chain_recall(rows, truth, "complete_chain"),
        "benign_lookalike_false_positive_rate": _benign_fp_rate(rows, truth),
        "runtime_overhead_ms_avg": sum(overheads) / max(1, len(overheads)),
        "event_loss_rate_avg": sum(event_loss) / max(1, len(event_loss)),
        "by_evidence_level": _by_evidence(rows),
    }


def _load_row(row: dict[str, Any]) -> dict[str, Any]:
    analysis = row.get("analysis")
    if analysis is None and row.get("artifact"):
        analysis = json.loads(Path(row["artifact"]).read_text(encoding="utf-8"))
    return {**row, "analysis": analysis or {}}


def _sources(analysis: dict[str, Any]) -> set[str]:
    return {str(source.get("source_location")) for source in analysis.get("taint_sources", [])}


def _sinks(analysis: dict[str, Any]) -> set[str]:
    graph = analysis.get("runtime_provenance_graph", {})
    return {str(node.get("label")) for node in graph.get("nodes", []) if node.get("node_type") == "NetworkEndpoint"}


def _taint_edges(analysis: dict[str, Any]) -> set[str]:
    graph = analysis.get("runtime_provenance_graph", {})
    return {
        f"{edge.get('source_node')}->{edge.get('edge_type')}->{edge.get('target_node')}"
        for edge in graph.get("edges", [])
        if edge.get("taint_ids")
    }


def _prf(predicted: set[str], expected: set[str]) -> dict[str, float]:
    tp = len(predicted & expected)
    precision = tp / max(1, len(predicted))
    recall = tp / max(1, len(expected))
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def _avg_prf(scores: list[dict[str, float]]) -> dict[str, float]:
    return {key: sum(score[key] for score in scores) / max(1, len(scores)) for key in ["precision", "recall", "f1"]}


def _chain_recall(rows: list[dict[str, Any]], truth: dict[str, Any], key: str) -> float:
    expected = [case for case, value in truth.items() if value.get(key)]
    if not expected:
        return 0.0
    hits = 0
    by_case = {row["case_id"]: row["analysis"] for row in rows}
    for case_id in expected:
        if by_case.get(case_id, {}).get("runtime_chains"):
            hits += 1
    return hits / len(expected)


def _benign_fp_rate(rows: list[dict[str, Any]], truth: dict[str, Any]) -> float:
    benign = [row for row in rows if truth.get(row["case_id"], {}).get("benign_lookalike")]
    if not benign:
        return 0.0
    false_positive = sum(1 for row in benign if any(chain.get("evidence_level") == "confirmed" for chain in row["analysis"].get("runtime_chains", [])))
    return false_positive / len(benign)


def _by_evidence(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {"confirmed": 0, "conservative": 0, "candidate": 0}
    for row in rows:
        for chain in row["analysis"].get("runtime_chains", []):
            level = chain.get("evidence_level")
            if level in counts:
                counts[level] += 1
    return counts


if __name__ == "__main__":
    raise SystemExit(main())
