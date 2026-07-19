from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.static.static_config import StaticAnalysisConfig
from app.static.static_report import analyze_static_bundle


ABLATIONS = {
    "deterministic-only",
    "llm-only-direct-judge",
    "llm-action-without-grounding",
    "without-entity-linking",
    "without-modality",
    "without-cross-artifact-loading",
    "full",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate ProvLoom Static v2 against a JSON gold set.")
    parser.add_argument("--dataset", required=True, help="JSON file containing sample records with skill_path and optional gold labels.")
    parser.add_argument("--config", default="")
    parser.add_argument("--ablation", choices=sorted(ABLATIONS), default="full")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    samples = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    config = StaticAnalysisConfig.load(args.config)
    rows = [_evaluate_sample(sample, config, args.ablation) for sample in samples]
    report = _aggregate(rows, args.ablation)
    if args.output:
        Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def _evaluate_sample(sample: dict[str, Any], config: StaticAnalysisConfig, ablation: str) -> dict[str, Any]:
    start = time.perf_counter()
    result = analyze_static_bundle(sample["skill_path"], sample.get("skill_file", "SKILL.md"), config=_config_for_ablation(config, ablation))
    payload = _apply_ablation(result.to_dict(), ablation)
    latency = time.perf_counter() - start
    gold_actions = {item["action_type"] for item in sample.get("expected_actions", [])}
    pred_actions = {item["action_type"] for item in payload.get("extracted_actions", [])}
    gold_modalities = {(item["action_type"], item.get("modality", "unknown")) for item in sample.get("expected_actions", [])}
    pred_modalities = {(item["action_type"], item.get("modality", "unknown")) for item in payload.get("extracted_actions", [])}
    gold_entities = {str(item).lower() for item in sample.get("expected_entities", [])}
    pred_entities = {entity.get("canonical_value", "").lower() for entity in payload.get("resolved_entities", [])}
    gold_sources = {str(item).lower() for item in sample.get("expected_sources", [])}
    gold_sinks = {str(item).lower() for item in sample.get("expected_sinks", [])}
    pred_sources = _pred_entities(payload, {"Credential", "SensitiveResource", "EnvironmentVariable"})
    pred_sinks = _pred_entities(payload, {"NetworkEndpoint", "APIEndpoint", "PersistenceTarget", "Permission"})
    gold_edges = {tuple(item) for item in sample.get("expected_edges", [])}
    pred_edges = {(edge.get("source_node"), edge.get("edge_type"), edge.get("target_node")) for edge in payload.get("instruction_provenance_graph", {}).get("edges", [])}
    gold_chains = {(item["chain_type"], item["status"]) for item in sample.get("expected_chains", [])}
    pred_chains = {(chain.get("chain_type"), chain.get("status")) for chain in payload.get("static_chains", [])}
    closed_expected = any(status == "closed" for _, status in gold_chains)
    closed_predicted = any(chain.get("status") == "closed" for chain in payload.get("static_chains", []))
    return {
        "sample_id": sample.get("sample_id", sample["skill_path"]),
        "action_prf": _prf(pred_actions, gold_actions),
        "action_type_accuracy": _accuracy(pred_actions, gold_actions),
        "modality_accuracy": _accuracy(pred_modalities, gold_modalities),
        "condition_f1": _condition_f1(payload, sample),
        "entity_prf": _prf(pred_entities, gold_entities),
        "entity_linking_prf": _linking_prf(payload, sample),
        "source_prf": _prf(pred_sources, gold_sources),
        "sink_prf": _prf(pred_sinks, gold_sinks),
        "edge_prf": _prf(pred_edges, gold_edges),
        "complete_chain_recall": 1.0 if gold_chains and gold_chains <= pred_chains else 0.0 if gold_chains else None,
        "chain_precision": _chain_precision(pred_chains, gold_chains),
        "false_closure": 1.0 if closed_predicted and not closed_expected else 0.0,
        "evidence_span_accuracy": _evidence_span_accuracy(payload),
        "exact_span_grounding_rate": _grounding_rate(payload),
        "unresolved_entity_rate": _unresolved_rate(payload),
        "prompt_injection_robustness": _prompt_robustness(payload, sample),
        "paraphrase_group": sample.get("paraphrase_group"),
        "coverage": _coverage_score(payload),
        "llm_cost": 0.0,
        "analysis_latency": latency,
        "predicted_chain_signature": sorted(f"{chain_type}:{status}" for chain_type, status in pred_chains),
    }


def _config_for_ablation(config: StaticAnalysisConfig, ablation: str) -> StaticAnalysisConfig:
    payload = config.to_dict()
    if ablation in {"deterministic-only", "full", "without-entity-linking", "without-modality", "without-cross-artifact-loading"}:
        payload["llm_enabled"] = False
    if ablation == "without-cross-artifact-loading":
        payload["max_files"] = 1
        payload["max_depth"] = 0
    return StaticAnalysisConfig.from_dict(payload)


def _apply_ablation(payload: dict[str, Any], ablation: str) -> dict[str, Any]:
    if ablation == "llm-only-direct-judge":
        text = "\n".join(unit.get("text", "") for unit in payload.get("static_semantic_units", []))
        closed = all(token in text.lower() for token in ["credential", "upload", "http"])
        payload["static_chains"] = [{"chain_type": "direct_judge", "status": "closed"}] if closed else []
        payload["instruction_provenance_graph"] = {"nodes": [], "edges": [], "summary": {}}
    if ablation == "llm-action-without-grounding":
        for action in payload.get("extracted_actions", []):
            action["grounding_status"] = "not_checked"
    if ablation == "without-entity-linking":
        payload["entity_resolutions"] = []
        payload["static_chains"] = [chain for chain in payload.get("static_chains", []) if chain.get("status") != "closed"]
    if ablation == "without-modality":
        for action in payload.get("extracted_actions", []):
            action["modality"] = "required"
    return payload


def _aggregate(rows: list[dict[str, Any]], ablation: str) -> dict[str, Any]:
    return {
        "ablation": ablation,
        "sample_count": len(rows),
        "action_extraction": _mean_prf(rows, "action_prf"),
        "action_type_accuracy": _mean(rows, "action_type_accuracy"),
        "modality_accuracy": _mean(rows, "modality_accuracy"),
        "condition_extraction_f1": _mean(rows, "condition_f1"),
        "entity_identification": _mean_prf(rows, "entity_prf"),
        "entity_linking": _mean_prf(rows, "entity_linking_prf"),
        "source_identification": _mean_prf(rows, "source_prf"),
        "sink_identification": _mean_prf(rows, "sink_prf"),
        "edge": _mean_prf(rows, "edge_prf"),
        "complete_chain_recall": _mean(rows, "complete_chain_recall"),
        "chain_precision": _mean(rows, "chain_precision"),
        "false_closure_rate": _mean(rows, "false_closure"),
        "evidence_span_accuracy": _mean(rows, "evidence_span_accuracy"),
        "exact_span_grounding_rate": _mean(rows, "exact_span_grounding_rate"),
        "unresolved_entity_rate": _mean(rows, "unresolved_entity_rate"),
        "prompt_injection_robustness": _mean(rows, "prompt_injection_robustness"),
        "paraphrase_consistency": _paraphrase_consistency(rows),
        "static_coverage": _mean(rows, "coverage"),
        "llm_cost": sum(row["llm_cost"] for row in rows),
        "analysis_latency": {"mean": _mean(rows, "analysis_latency"), "p95": _p95([row["analysis_latency"] for row in rows])},
        "per_sample": rows,
    }


def _pred_entities(payload: dict[str, Any], types: set[str]) -> set[str]:
    return {entity.get("canonical_value", "").lower() for entity in payload.get("resolved_entities", []) if entity.get("entity_type") in types}


def _prf(pred: set[Any], gold: set[Any]) -> dict[str, float]:
    if not pred and not gold:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    tp = len(pred & gold)
    precision = tp / len(pred) if pred else 0.0
    recall = tp / len(gold) if gold else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def _accuracy(pred: set[Any], gold: set[Any]) -> float:
    if not pred and not gold:
        return 1.0
    return len(pred & gold) / len(gold) if gold else 0.0


def _condition_f1(payload: dict[str, Any], sample: dict[str, Any]) -> float:
    pred = {action.get("condition") for action in payload.get("extracted_actions", []) if action.get("condition")}
    gold = {item["condition"] for item in sample.get("expected_actions", []) if item.get("condition")}
    return _prf(pred, gold)["f1"]


def _linking_prf(payload: dict[str, Any], sample: dict[str, Any]) -> dict[str, float]:
    pred = {(item.get("entity_a"), item.get("relation"), item.get("entity_b")) for item in payload.get("entity_resolutions", []) if item.get("status") != "rejected"}
    gold = {tuple(item) for item in sample.get("expected_entity_links", [])}
    return _prf(pred, gold)


def _chain_precision(pred: set[tuple[str, str]], gold: set[tuple[str, str]]) -> float:
    if not pred:
        return 1.0 if not gold else 0.0
    return len(pred & gold) / len(pred)


def _evidence_span_accuracy(payload: dict[str, Any]) -> float:
    actions = payload.get("extracted_actions", [])
    if not actions:
        return 1.0
    valid = sum(1 for action in actions if action.get("evidence", {}).get("unit_id") and action.get("evidence", {}).get("exact_text"))
    return valid / len(actions)


def _grounding_rate(payload: dict[str, Any]) -> float:
    reports = payload.get("grounding_validation", [])
    if not reports:
        return 1.0
    return sum(1 for item in reports if item.get("grounding_status") == "valid") / len(reports)


def _unresolved_rate(payload: dict[str, Any]) -> float:
    entities = payload.get("resolved_entities", [])
    if not entities:
        return 0.0
    return sum(1 for entity in entities if entity.get("resolution_status") in {"ambiguous", "unresolved"}) / len(entities)


def _prompt_robustness(payload: dict[str, Any], sample: dict[str, Any]) -> float | None:
    if not sample.get("prompt_injection"):
        return None
    states = set(payload.get("static_coverage", {}).get("states", []))
    return 0.0 if "analysis_error" in states else 1.0


def _coverage_score(payload: dict[str, Any]) -> float:
    coverage = payload.get("static_coverage", {})
    total = coverage.get("total_files", 0)
    return coverage.get("loaded_files", 0) / total if total else 0.0


def _mean(rows: list[dict[str, Any]], key: str) -> float:
    values = [row[key] for row in rows if row.get(key) is not None]
    return statistics.fmean(values) if values else 0.0


def _mean_prf(rows: list[dict[str, Any]], key: str) -> dict[str, float]:
    return {
        "precision": _mean([{"v": row[key]["precision"]} for row in rows], "v"),
        "recall": _mean([{"v": row[key]["recall"]} for row in rows], "v"),
        "f1": _mean([{"v": row[key]["f1"]} for row in rows], "v"),
    }


def _paraphrase_consistency(rows: list[dict[str, Any]]) -> float:
    groups: dict[str, list[set[tuple[str, str]]]] = {}
    for row in rows:
        group = row.get("paraphrase_group")
        if not group:
            continue
        chains = set(row.get("predicted_chain_signature", []))
        groups.setdefault(group, []).append(chains)
    if not groups:
        return 0.0
    scores = []
    for signatures in groups.values():
        if len(signatures) <= 1:
            continue
        baseline = signatures[0]
        scores.append(sum(1 for signature in signatures[1:] if signature == baseline) / (len(signatures) - 1))
    return statistics.fmean(scores) if scores else 0.0


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    return sorted(values)[int((len(values) - 1) * 0.95)]


if __name__ == "__main__":
    raise SystemExit(main())
