from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.static.static_config import StaticAnalysisConfig
from app.static.static_report import analyze_static_bundle
from app.static.failure_attribution import BEHAVIOR_NAMES, CHAIN_COMPATIBLE_BEHAVIORS, PI_BEHAVIORS, infer_attack_labels


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate ProvLoom Static v2 deterministic policy alerts on a labeled path split.")
    parser.add_argument("--malicious-paths", required=True, help="Text file with one malicious skill path per line.")
    parser.add_argument("--benign-paths", required=True, help="Text file with one benign skill path per line.")
    parser.add_argument("--config", default="")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--output-md", default="")
    args = parser.parse_args()

    config = StaticAnalysisConfig.load(args.config)
    config.llm_enabled = False
    rows = []
    for label, path_file in [("malicious", args.malicious_paths), ("benign", args.benign_paths)]:
        for path in _read_paths(path_file):
            rows.append(_evaluate(path, label, config))
    report = _aggregate(rows)
    if args.output_json:
        Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_json).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.output_md:
        Path(args.output_md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_md).write_text(_markdown(report), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    return 0


def _evaluate(path: str, label: str, config: StaticAnalysisConfig) -> dict[str, Any]:
    start = time.perf_counter()
    path_exists = Path(path).exists()
    try:
        result = analyze_static_bundle(path, config=config)
        payload = result.to_dict()
        chains = payload.get("static_chains", [])
        states = payload.get("static_coverage", {}).get("states", [])
        error = None
    except Exception as exc:  # pragma: no cover - CLI safety net
        payload = {"static_chains": [], "static_analysis_summary": {}, "static_coverage": {"states": ["analysis_error"]}}
        chains = []
        states = ["analysis_error"]
        error = str(exc)
    alerts = Counter(chain.get("alert_status", "none") for chain in chains)
    capabilities = Counter(chain.get("capability_type", "unknown_security_capability") for chain in chains)
    policies = Counter(chain.get("policy_status", "not_applicable") for chain in chains)
    statuses = Counter(chain.get("status", "none") for chain in chains)
    review_reasons = Counter(chain.get("review_reason", "not_applicable") for chain in chains if chain.get("review_reason") not in {None, "not_applicable"})
    vector, behavior = infer_attack_labels(path)
    violation = alerts.get("violation", 0) > 0
    review = alerts.get("review", 0) > 0
    closed = statuses.get("closed", 0) > 0
    primary = _primary_chain(chains)
    return {
        "skill_path": path,
        "path_exists": path_exists,
        "label": label,
        "attack_vector": vector,
        "behavior_id": behavior,
        "chain_compatible": behavior in CHAIN_COMPATIBLE_BEHAVIORS or (vector == "MIXED" and behavior in CHAIN_COMPATIBLE_BEHAVIORS),
        "instruction_policy_behavior": behavior in PI_BEHAVIORS,
        "predicted_violation": violation,
        "predicted_review": review,
        "predicted_closed_capability": closed,
        "latency_seconds": round(time.perf_counter() - start, 6),
        "coverage_states": states,
        "analysis_error": error,
        "closed_chain_count": statuses.get("closed", 0),
        "violation_chain_count": alerts.get("violation", 0),
        "review_chain_count": alerts.get("review", 0),
        "raw_candidate_chain_count": payload.get("static_analysis_summary", {}).get("raw_candidate_chain_count", 0),
        "canonical_chain_count": payload.get("static_analysis_summary", {}).get("canonical_chain_count", len(chains)),
        "duplicate_suppressed_count": payload.get("static_analysis_summary", {}).get("duplicate_suppressed_count", 0),
        "capability_counts": dict(capabilities),
        "policy_counts": dict(policies),
        "alert_counts": dict(alerts),
        "review_reason_counts": dict(review_reasons),
        "primary_chain": primary,
        "false_positive_root_cause": _false_positive_cause(primary) if label == "benign" and violation else "",
    }


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(1 for row in rows if row["label"] == "malicious" and row["predicted_violation"])
    fn = sum(1 for row in rows if row["label"] == "malicious" and not row["predicted_violation"])
    fp = sum(1 for row in rows if row["label"] == "benign" and row["predicted_violation"])
    tn = sum(1 for row in rows if row["label"] == "benign" and not row["predicted_violation"])
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    malicious = [row for row in rows if row["label"] == "malicious"]
    benign = [row for row in rows if row["label"] == "benign"]
    caps = Counter()
    policies = Counter()
    alerts = Counter()
    review_reasons = Counter()
    for row in rows:
        caps.update(row["capability_counts"])
        policies.update(row["policy_counts"])
        alerts.update(row["alert_counts"])
        review_reasons.update(row["review_reason_counts"])
    vector_breakdown = _vector_breakdown(malicious)
    behavior_breakdown = _behavior_breakdown(malicious)
    chain_compatible = [row for row in malicious if row.get("chain_compatible")]
    pi_rows = [row for row in malicious if row.get("instruction_policy_behavior")]
    summary = {
        "sample_count": len(rows),
        "malicious_count": len(malicious),
        "benign_count": len(benign),
        "missing_path_count": sum(1 for row in rows if not row.get("path_exists", True)),
        "missing_malicious_path_count": sum(1 for row in malicious if not row.get("path_exists", True)),
        "missing_benign_path_count": sum(1 for row in benign if not row.get("path_exists", True)),
        "malicious_closed_capability_rate": _rate(malicious, "predicted_closed_capability"),
        "malicious_violation_detection_rate": _rate(malicious, "predicted_violation"),
        "benign_closed_capability_rate": _rate(benign, "predicted_closed_capability"),
        "benign_violation_false_positive_rate": _rate(benign, "predicted_violation"),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "fpr": fpr,
        "abstention_review_rate": _rate(rows, "predicted_review"),
        "chain_compatible_violation_recall": _rate(chain_compatible, "predicted_violation"),
        "ci_violation_recall": vector_breakdown.get("CI", {}).get("recall", 0.0),
        "pi_instruction_policy_recall": _rate(pi_rows, "predicted_violation"),
        "mixed_violation_recall": vector_breakdown.get("MIXED", {}).get("recall", 0.0),
        "raw_chain_count": sum(row["raw_candidate_chain_count"] for row in rows),
        "canonical_chain_count": sum(row["canonical_chain_count"] for row in rows),
        "duplicate_suppressed_count": sum(row["duplicate_suppressed_count"] for row in rows),
        "duplicate_suppression_rate": _safe_div(sum(row["duplicate_suppressed_count"] for row in rows), sum(row["raw_candidate_chain_count"] for row in rows)),
        "credential_authentication_count": caps.get("credential_authentication", 0),
        "credential_exfiltration_count": caps.get("credential_exfiltration", 0),
        "trusted_service_flow_count": policies.get("trusted_service_flow", 0),
        "untrusted_external_flow_count": policies.get("untrusted_external_flow", 0),
        "capability_type_counts": dict(caps),
        "policy_status_counts": dict(policies),
        "alert_status_counts": dict(alerts),
        "review_reason_counts": dict(review_reasons),
        "attack_vector_breakdown": vector_breakdown,
        "behavior_breakdown": behavior_breakdown,
        "latency_seconds": {"mean": statistics.fmean([row["latency_seconds"] for row in rows]) if rows else 0.0, "p95": _p95([row["latency_seconds"] for row in rows])},
    }
    return {
        "summary": summary,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "false_positive_error_analysis": [row for row in rows if row["label"] == "benign" and row["predicted_violation"]],
        "false_negative_error_analysis": [row for row in rows if row["label"] == "malicious" and not row["predicted_violation"]],
        "per_sample": rows,
    }


def _primary_chain(chains: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not chains:
        return None
    order = {"violation": 0, "review": 1, "capability_only": 2, "unresolved": 3, "none": 4}
    priorities = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    chain = sorted(chains, key=lambda item: (order.get(item.get("alert_status", "none"), 4), priorities.get(item.get("review_priority", "informational"), 4)))[0]
    return {
        "chain_id": chain.get("chain_id"),
        "status": chain.get("status"),
        "capability_type": chain.get("capability_type"),
        "policy_status": chain.get("policy_status"),
        "alert_status": chain.get("alert_status"),
        "source_entity": chain.get("source_entity"),
        "sink_entity": chain.get("sink_entity"),
        "evidence_unit_ids": chain.get("evidence_unit_ids", []),
        "policy_reasons": chain.get("policy_reasons", []),
        "limitations": chain.get("limitations", []),
        "data_continuity": chain.get("data_continuity", {}),
    }


def _false_positive_cause(chain: dict[str, Any] | None) -> str:
    if not chain:
        return "no_primary_chain"
    if chain.get("capability_type") == "untrusted_download_execute":
        return "download_execute_policy_context"
    if chain.get("capability_type") == "credential_exfiltration":
        return "credential_payload_or_trust_context"
    if chain.get("capability_type") == "privilege_escalation":
        return "permission_boundary_context"
    return str(chain.get("capability_type", "unknown"))


def _vector_breakdown(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for vector in ["CI", "PI", "MIXED", "unknown"]:
        group = [row for row in rows if row.get("attack_vector") == vector]
        result[vector] = {
            "malicious_count": len(group),
            "violation_tp": sum(1 for row in group if row.get("predicted_violation")),
            "recall": _rate(group, "predicted_violation"),
            "review_rate": _rate(group, "predicted_review"),
            "miss_rate": 1.0 - _rate(group, "predicted_violation") if group else 0.0,
        }
    return result


def _behavior_breakdown(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for behavior, name in BEHAVIOR_NAMES.items():
        group = [row for row in rows if row.get("behavior_id") == behavior]
        result[behavior] = {
            "behavior_name": name,
            "count": len(group),
            "violation_recall": _rate(group, "predicted_violation"),
            "review_rate": _rate(group, "predicted_review"),
            "unsupported_rate": sum(1 for row in group if row.get("analysis_error") or not row.get("predicted_closed_capability") and not row.get("predicted_review")) / len(group) if group else 0.0,
        }
    return result


def _markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = ["# Static Deterministic Development Split", "", "## Summary", ""]
    for key, value in summary.items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## False Positives", ""])
    for row in report["false_positive_error_analysis"][:50]:
        chain = row.get("primary_chain") or {}
        lines.append(f"- `{row['skill_path']}` capability=`{chain.get('capability_type')}` policy=`{chain.get('policy_status')}` cause=`{row.get('false_positive_root_cause')}`")
    lines.extend(["", "## False Negatives", ""])
    for row in report["false_negative_error_analysis"][:50]:
        lines.append(f"- `{row['skill_path']}` closed=`{row['predicted_closed_capability']}` review=`{row['predicted_review']}`")
    return "\n".join(lines) + "\n"


def _read_paths(path_file: str) -> list[str]:
    return [line.strip() for line in Path(path_file).read_text(encoding="utf-8").splitlines() if line.strip()]


def _rate(rows: list[dict[str, Any]], key: str) -> float:
    return sum(1 for row in rows if row.get(key)) / len(rows) if rows else 0.0


def _safe_div(a: int, b: int) -> float:
    return a / b if b else 0.0


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    return sorted(values)[int((len(values) - 1) * 0.95)]


if __name__ == "__main__":
    raise SystemExit(main())
