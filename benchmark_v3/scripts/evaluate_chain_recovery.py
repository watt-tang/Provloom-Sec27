#!/usr/bin/env python3
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

def f1(p, r):
    return 0.0 if p + r == 0 else 2 * p * r / (p + r)

def prf(gold, pred):
    g, p = set(gold), set(pred)
    tp = len(g & p)
    prec = 1.0 if not p else tp / len(p)
    rec = 1.0 if not g else tp / len(g)
    return {"precision": prec, "recall": rec, "f1": f1(prec, rec), "gold_n": len(g), "pred_n": len(p)}

def wilson(k, n, z=1.959963984540054):
    if n == 0:
        return [None, None]
    phat = k / n
    denom = 1 + z * z / n
    center = (phat + z * z / (2 * n)) / denom
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n) / denom
    return [max(0.0, center - margin), min(1.0, center + margin)]

def flatten(values):
    out = []
    for value in values:
        if isinstance(value, dict):
            out.append(json.dumps(value, sort_keys=True))
        elif isinstance(value, list):
            out.append(">".join(map(str, value)))
        else:
            out.append(str(value))
    return out

def load_predictions(path):
    preds = {}
    if not path:
        return preds
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            preds[row["sample_id"]] = row
    return preds

def eval_one(gt, pred):
    pred = pred or {}
    metrics = {
        "source": prf(flatten(gt.get("sources", [])), flatten(pred.get("sources", []))),
        "sink": prf(flatten(gt.get("destinations", [])), flatten(pred.get("destinations", []))),
        "operation": prf(flatten(gt.get("operations", [])), flatten(pred.get("operations", []))),
        "ordered_edge": prf(flatten(gt.get("ordered_relations", [])), flatten(pred.get("ordered_relations", []))),
        "intermediate_object": prf(flatten(gt.get("intermediate_objects", [])), flatten(pred.get("intermediate_objects", []))),
        "carrier": prf(flatten(gt.get("transport_carriers", [])), flatten(pred.get("transport_carriers", []))),
        "minimal_witness": prf(flatten(gt.get("minimal_evidence_sets", [])), flatten(pred.get("minimal_evidence_sets", []))),
        "contradiction": prf(flatten(gt.get("expected_contradictions", [])), flatten(pred.get("expected_contradictions", []))),
    }
    gold_chains = set(flatten(gt.get("expected_complete_chains", [])))
    pred_chains = set(flatten(pred.get("complete_chains", [])))
    metrics["complete_chain_recall"] = 1.0 if not gold_chains else len(gold_chains & pred_chains) / len(gold_chains)
    metrics["exact_chain_match"] = 1.0 if gold_chains == pred_chains else 0.0
    forbidden = set(flatten(gt.get("forbidden_false_chains", [])))
    metrics["false_closure"] = 1.0 if forbidden & pred_chains else 0.0
    metrics["coverage_state_accuracy"] = 1.0 if gt.get("expected_coverage_condition") == pred.get("coverage_condition") else 0.0
    metrics["alignment_accuracy"] = 1.0 if set(flatten(gt.get("expected_alignment_relations", []))) == set(flatten(pred.get("alignment_relations", []))) else 0.0
    metrics["trusted_flow_distinction"] = 1.0 if gt.get("expected_policy_outcome") == pred.get("policy_outcome") else 0.0
    metrics["partial_chain_score"] = sum(m["f1"] for k, m in metrics.items() if isinstance(m, dict)) / 8
    return metrics

def bootstrap_ci(values, rounds=1000):
    if not values:
        return [None, None]
    rng = random.Random(17)
    means = []
    for _ in range(rounds):
        sample = [rng.choice(values) for _ in values]
        means.append(sum(sample) / len(sample))
    means.sort()
    return [means[int(0.025 * rounds)], means[int(0.975 * rounds)]]

def summarize(sample_metrics, rows):
    scalar_keys = ["complete_chain_recall", "exact_chain_match", "false_closure", "coverage_state_accuracy", "alignment_accuracy", "trusted_flow_distinction", "partial_chain_score"]
    summary = {"sample_count": len(sample_metrics), "overall": {}, "by_outcome": {}, "by_risk_family": {}}
    for key in scalar_keys:
        vals = [m[key] for m in sample_metrics.values()]
        successes = sum(1 for v in vals if v == 1.0)
        summary["overall"][key] = {"mean": sum(vals) / len(vals) if vals else None, "wilson_ci": wilson(successes, len(vals)), "bootstrap_ci": bootstrap_ci(vals), "n": len(vals)}
    lookup = {r["sample_id"]: r for r in rows}
    for field, out_key in [("expected_policy_outcome", "by_outcome"), ("risk_family", "by_risk_family")]:
        groups = defaultdict(list)
        for sid, metrics in sample_metrics.items():
            groups[lookup[sid][field]].append(metrics)
        for name, vals in groups.items():
            summary[out_key][name] = {"n": len(vals), "partial_chain_score_mean": sum(v["partial_chain_score"] for v in vals) / len(vals)}
    return summary

def main():
    if len(sys.argv) not in {2, 3}:
        print("usage: evaluate_chain_recovery.py <benchmark_v3> [predictions.jsonl]", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    rows = [json.loads(line) for line in (root / "manifest.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    preds = load_predictions(sys.argv[2] if len(sys.argv) == 3 else None)
    sample_metrics = {}
    for row in rows:
        gt = json.loads((root / row["ground_truth_path"]).read_text(encoding="utf-8"))
        sample_metrics[row["sample_id"]] = eval_one(gt, preds.get(row["sample_id"], {}))
    report = summarize(sample_metrics, rows)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
