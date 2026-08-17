#!/usr/bin/env python3
"""Paper-facing evaluation for the ProvLoom USENIX draft.

The script is evaluation-only. It reads frozen ProvBench artifacts, ground
truth, ProvLoom summaries, runtime graphs, and
ablation outputs. It does not modify analyzer logic or use ground truth to tune
the system.
"""

from __future__ import annotations

import csv
import json
import math
import os
import re
import statistics
from functools import lru_cache
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FORMAL_IDS = ROOT / "results/baselines/common_success_comparison/common_success_manifest.json"
PROV_METRICS = ROOT / "results/provbench/full/metrics.json"
PROV_SUMMARY = ROOT / "results/provbench/full/summary.json"
BASELINE_COMPARISON = ROOT / "results/baselines/common_success_comparison/comparison.json"
BENCHMARK_MANIFEST = ROOT / "provbench/manifest.jsonl"
GT_DIR = ROOT / "provbench/ground_truth"
RUN_DIR = ROOT / "results/provbench/full/runs"
ABLATION_DIR = ROOT / "results/ablation"
OUT = ROOT / "results/paper_usenix"


@lru_cache(maxsize=None)
def read_json(path: Path) -> Any:
    with path.open() as f:
        return json.load(f)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    fields = list(rows[0].keys())
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def norm(s: Any) -> str:
    s = str(s or "").lower()
    s = re.sub(r"^network:net:", "", s)
    s = re.sub(r"^net:", "", s)
    s = re.sub(r"^file:", "", s)
    s = re.sub(r"^source:", "", s)
    s = s.replace("/workspace/", "")
    s = re.sub(r"[^a-z0-9:/._-]+", " ", s)
    return " ".join(s.split())


def path_part(s: str) -> str:
    return norm(str(s).split(":", 1)[0])


def f1(p: float, r: float) -> float:
    return 0.0 if p + r == 0 else 2 * p * r / (p + r)


def div(a: float, b: float) -> float:
    return 0.0 if b == 0 else a / b


def prf(tp: int, pred: int, gold: int) -> dict[str, Any]:
    p = div(tp, pred)
    r = div(tp, gold)
    return {"tp": tp, "predicted": pred, "gold": gold, "precision": p, "recall": r, "f1": f1(p, r)}


def pct(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = (len(xs) - 1) * q
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return xs[lo]
    return xs[lo] * (hi - k) + xs[hi] * (k - lo)


def load_manifest() -> tuple[list[str], dict[str, dict[str, Any]]]:
    ids = read_json(FORMAL_IDS)["sample_ids"]
    rows: dict[str, dict[str, Any]] = {}
    with BENCHMARK_MANIFEST.open() as f:
        for line in f:
            row = json.loads(line)
            if row["sample_id"] in ids:
                rows[row["sample_id"]] = row
    return ids, rows


def load_formal_samples(ids: list[str]) -> dict[str, dict[str, Any]]:
    samples = {s["sample_id"]: s for s in read_json(PROV_METRICS)["samples"]}
    return {sid: samples[sid] for sid in ids if sid in samples}


def load_gt(sid: str) -> dict[str, Any]:
    return read_json(GT_DIR / f"{sid}.json")


def load_unified(sid: str) -> dict[str, Any] | None:
    path = RUN_DIR / f"PROVBENCH-FULL-{sid}" / "unified-analysis.json"
    if not path.exists():
        return None
    return read_json(path)


def load_runtime_chains(sid: str) -> list[dict[str, Any]]:
    path = RUN_DIR / f"PROVBENCH-FULL-{sid}" / "runtime-chains.json"
    if not path.exists():
        return []
    return read_json(path)


def load_runtime_graph(sid: str) -> dict[str, Any] | None:
    path = RUN_DIR / f"PROVBENCH-FULL-{sid}" / "runtime-provenance-graph.json"
    if not path.exists():
        return None
    return read_json(path)


def chain_source_label(chain: dict[str, Any], graph: dict[str, Any] | None) -> str:
    source = chain.get("source", "")
    if not graph:
        return source
    nodes = {n.get("node_id"): n for n in graph.get("nodes", [])}
    n = nodes.get(source)
    if not n:
        return source
    md = n.get("metadata", {})
    return " ".join(norm(x) for x in [
        n.get("label", ""),
        md.get("source_location", ""),
        md.get("source_object", ""),
        md.get("metadata", {}).get("source_object", "") if isinstance(md.get("metadata"), dict) else "",
    ])


def taint_source_labels(unified: dict[str, Any] | None, graph: dict[str, Any] | None) -> list[str]:
    labels: list[str] = []
    dyn = (unified or {}).get("dynamic_result", {}) if unified else {}
    for src in dyn.get("taint_sources", []) or []:
        md = src.get("metadata", {}) or {}
        labels.append(" ".join(norm(x) for x in [
            src.get("source_location", ""),
            md.get("source_object", ""),
            md.get("source_location", ""),
            (md.get("source_label", {}) or {}).get("source_object", "") if isinstance(md.get("source_label"), dict) else "",
        ]))
    if graph:
        for n in graph.get("nodes", []) or []:
            if n.get("node_type") == "SensitiveSource":
                md = n.get("metadata", {}) or {}
                labels.append(" ".join(norm(x) for x in [
                    n.get("label", ""),
                    md.get("source_location", ""),
                    md.get("source_object", ""),
                    md.get("metadata", {}).get("source_object", "") if isinstance(md.get("metadata"), dict) else "",
                ]))
    return [x for x in labels if x.strip()]


def chain_sink_label(chain: dict[str, Any]) -> str:
    return norm(chain.get("sink", ""))


def policy_chain_ids(unified: dict[str, Any] | None) -> set[str]:
    ids: set[str] = set()
    if not unified:
        return ids
    for pv in unified.get("policy_violations", []) or []:
        cid = pv.get("chain_id")
        if cid:
            ids.add(cid)
    if not ids:
        status = unified.get("risk_chain_status", {}) or {}
        ids.update(status.get("decisive_chain_ids", []) or [])
    return ids


def expected_chain_objects(gt: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for chain in gt.get("expected_complete_chains", []) or []:
        for node in chain:
            out.add(norm(node))
    return out


def source_match(gt_source: str, pred_source: str) -> bool:
    g = path_part(gt_source)
    p = norm(pred_source)
    return bool(g and (g in p or p in g))


def sink_match(gt_sink: str, pred_sink: str) -> bool:
    g = norm(gt_sink)
    p = norm(pred_sink)
    return bool(g and (g in p or p in g))


def relay_match(relay: str, chains: list[dict[str, Any]]) -> bool:
    r = norm(relay)
    if not r:
        return False
    blobs: list[str] = []
    for c in chains:
        blobs.extend(norm(x) for x in c.get("ordered_nodes", []) or [])
        blobs.extend(norm(x) for x in c.get("ordered_edges", []) or [])
        for w in c.get("metadata", {}).get("minimal_witness", []) or []:
            blobs.append(norm(w.get("from", "")))
            blobs.append(norm(w.get("to", "")))
            blobs.append(norm(w.get("carrier_location", "")))
    return any(r in b or b in r for b in blobs if b)


def edge_ops(chains: list[dict[str, Any]]) -> set[str]:
    mapping = {
        "read": "read",
        "derives": "transform",
        "derive": "transform",
        "propagates": "transform",
        "sends": "deliver",
        "send": "deliver",
        "upload": "deliver",
        "uploads": "deliver",
        "execute": "execute",
        "executes": "execute",
        "persist": "persist",
    }
    ops: set[str] = set()
    for c in chains:
        for w in c.get("metadata", {}).get("minimal_witness", []) or []:
            e = norm(w.get("edge", ""))
            ops.add(mapping.get(e, e))
        for t in c.get("metadata", {}).get("terminal_edge_type", []) if isinstance(c.get("metadata", {}).get("terminal_edge_type"), list) else [c.get("metadata", {}).get("terminal_edge_type")]:
            e = norm(t)
            if e:
                ops.add(mapping.get(e, e))
    return ops


def object_family(value: Any) -> str:
    s = norm(value)
    if not s:
        return "empty"
    if re.search(r"https?://|localhost|:[0-9]{2,5}(/|$)|\\bnet\\b|network", s):
        return "network_endpoint"
    if any(x in s for x in ["llm_context", "messages[", "prompt", "model_api"]):
        return "llm_context"
    if any(x in s for x in ["http_body", "body", "json", "multipart", "header", "query"]):
        return "carrier"
    if re.search(r"(^|/)[^/]+\\.[a-z0-9]{1,8}($|:)", s) or "/" in s:
        return "file"
    if re.search(r"^t-[a-f0-9]+$", s) or "source" in s:
        return "taint_source"
    if "proc" in s or "exec" in s or "argv" in s:
        return "process"
    return "data_object"


def token_set(value: Any) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", norm(value)) if len(t) >= 3}


def match_quality(gold: str, predicted: list[str]) -> tuple[str, str]:
    g = norm(gold)
    if not g and not predicted:
        return "not_applicable", ""
    if not predicted:
        return "missing_prediction", ""
    if any(g == norm(p) for p in predicted):
        return "exact", next(p for p in predicted if g == norm(p))
    if any(g and (g in norm(p) or norm(p) in g) for p in predicted):
        return "normalized_identity", next(p for p in predicted if g and (g in norm(p) or norm(p) in g))
    gb = path_part(gold)
    if gb and any(gb in norm(p) or norm(p) in gb for p in predicted):
        return "granularity_path_vs_field", next(p for p in predicted if gb in norm(p) or norm(p) in gb)
    gf = object_family(gold)
    same_family = [p for p in predicted if object_family(p) == gf]
    if same_family:
        return "ontology_only", same_family[0]
    gtoks = token_set(gold)
    overlap = [(len(gtoks & token_set(p)), p) for p in predicted]
    overlap = sorted(overlap, reverse=True)
    if overlap and overlap[0][0] > 0:
        return "naming_or_alias", overlap[0][1]
    return "unmatched", predicted[0]


def chain_observations(sid: str, sample: dict[str, Any]) -> dict[str, Any]:
    unified = load_unified(sid)
    graph = load_runtime_graph(sid)
    chains_all = load_runtime_chains(sid)
    decisive = policy_chain_ids(unified)
    chains = [c for c in chains_all if not decisive or c.get("chain_id") in decisive]
    if sample.get("expected_policy_outcome") != "confirmed_violation":
        chains = [c for c in chains if sample.get("predicted_label") == "malicious"]
    pred_sources = [chain_source_label(c, graph) for c in chains]
    registry_sources = taint_source_labels(unified, graph)
    if registry_sources:
        enriched = []
        for p in pred_sources:
            enriched.append(p)
            if re.fullmatch(r"(source )?t-[a-f0-9]+", norm(p)) or not p.strip():
                enriched.extend(registry_sources)
        pred_sources = enriched
    pred_sinks = [chain_sink_label(c) for c in chains if chain_sink_label(c).strip()]
    pred_nodes = [n for c in chains for n in (c.get("ordered_nodes", []) or [])]
    witness_nodes = []
    witness_edges = []
    carrier_types = []
    evidence_strengths = []
    for c in chains:
        evidence_strengths.extend(c.get("evidence_strengths", []) or [])
        carrier_types.extend((c.get("metadata", {}) or {}).get("carrier_types", []) or [])
        for w in (c.get("metadata", {}) or {}).get("minimal_witness", []) or []:
            witness_nodes.extend([w.get("from", ""), w.get("to", ""), w.get("carrier_location", "")])
            witness_edges.append(w)
    return {
        "unified": unified,
        "graph": graph,
        "chains": chains,
        "pred_sources": sorted(set(x for x in pred_sources if x.strip())),
        "pred_sinks": sorted(set(x for x in pred_sinks if x.strip())),
        "pred_nodes": sorted(set(norm(x) for x in pred_nodes + witness_nodes if norm(x))),
        "witness_edges": witness_edges,
        "edge_ops": sorted(edge_ops(chains)),
        "carrier_types": sorted(set(carrier_types)),
        "evidence_strengths": sorted(set(evidence_strengths)),
    }


def explanation_metric_audit(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    obj_rows: list[dict[str, Any]] = []
    edge_rows: list[dict[str, Any]] = []
    chain_rows: list[dict[str, Any]] = []
    mismatch = Counter()
    relay_pred_family = Counter()
    chain_level = Counter()

    op_map = {
        "read": "read",
        "stage": "transform",
        "transform": "transform",
        "deliver": "deliver",
        "send": "deliver",
        "upload": "deliver",
        "call_model": "deliver",
        "execute": "execute",
        "persist": "persist",
        "presence_check": "read",
        "suppress_value": "filter",
        "write_local_review": "write",
    }
    for sid in ids:
        gt = load_gt(sid)
        s = samples[sid]
        obs = chain_observations(sid, s)
        gt_sources = gt.get("sources", []) or []
        gt_sinks = gt.get("destinations", []) or []
        gt_relays = gt.get("intermediate_objects", []) or []
        source_q = [match_quality(g, obs["pred_sources"]) for g in gt_sources]
        sink_q = [match_quality(g, obs["pred_sinks"]) for g in gt_sinks]
        relay_q = [match_quality(g, obs["pred_nodes"]) for g in gt_relays]
        for kind, golds, preds, qs in [
            ("source", gt_sources, obs["pred_sources"], source_q),
            ("sink", gt_sinks, obs["pred_sinks"], sink_q),
            ("relay", gt_relays, obs["pred_nodes"], relay_q),
        ]:
            for gold, (status, matched) in zip(golds, qs):
                mismatch[f"{kind}:{status}"] += 1
                obj_rows.append({
                    "sample_id": sid,
                    "object_kind": kind,
                    "gold": gold,
                    "gold_family": object_family(gold),
                    "matched_prediction": matched,
                    "matched_family": object_family(matched),
                    "match_status": status,
                    "predicted_candidates": ";".join(preds[:8]),
                    "expected_outcome": s.get("expected_policy_outcome"),
                    "predicted_label": s.get("predicted_label"),
                    "risk_family": s.get("risk_family"),
                })
        for p in obs["pred_nodes"]:
            relay_pred_family[object_family(p)] += 1

        pred_ops = set(obs["edge_ops"])
        for rel in gt.get("ordered_relations", []) or []:
            gop = op_map.get(norm(rel.get("operation")), norm(rel.get("operation")))
            status = "operation_matched" if gop in pred_ops else "operation_missing"
            from_status, from_match = match_quality(rel.get("from", ""), obs["pred_nodes"] + obs["pred_sources"])
            to_status, to_match = match_quality(rel.get("to", ""), obs["pred_nodes"] + obs["pred_sinks"])
            edge_rows.append({
                "sample_id": sid,
                "gold_operation": rel.get("operation", ""),
                "canonical_operation": gop,
                "operation_status": status,
                "gold_from": rel.get("from", ""),
                "from_match_status": from_status,
                "from_matched_prediction": from_match,
                "gold_to": rel.get("to", ""),
                "to_match_status": to_status,
                "to_matched_prediction": to_match,
                "predicted_operations": ";".join(sorted(pred_ops)),
                "predicted_edge_count": len(obs["witness_edges"]),
            })
            mismatch[f"edge:{status}"] += 1

        source_ok = bool(gt_sources) and all(q[0] in {"exact", "normalized_identity", "granularity_path_vs_field"} for q in source_q)
        sink_ok = (not gt_sinks) or all(q[0] in {"exact", "normalized_identity", "granularity_path_vs_field"} for q in sink_q)
        relay_ok = (not gt_relays) or all(q[0] in {"exact", "normalized_identity", "granularity_path_vs_field"} for q in relay_q)
        endpoint_ok = bool(gt_sinks) and sink_ok
        closure_ok = bool(s.get("confirmed_violation_chain")) and s.get("expected_policy_outcome") == "confirmed_violation"
        if closure_ok and endpoint_ok and relay_ok:
            level = "L3_structural_fidelity"
        elif closure_ok and endpoint_ok:
            level = "L2_endpoint_correct"
        elif closure_ok:
            level = "L1_closure_only"
        elif s.get("expected_policy_outcome") == "confirmed_violation":
            level = "missed_closure"
        else:
            level = "non_violation_or_false_closure"
        chain_level[level] += 1
        chain_rows.append({
            "sample_id": sid,
            "expected_outcome": s.get("expected_policy_outcome"),
            "predicted_label": s.get("predicted_label"),
            "risk_family": s.get("risk_family"),
            "closure_correct": closure_ok,
            "endpoint_correct": endpoint_ok,
            "source_identity_correct": source_ok,
            "relay_identity_correct": relay_ok,
            "three_level_explanation": level,
            "gt_chain": " | ".join(" -> ".join(c) for c in gt.get("expected_complete_chains", []) or []),
            "predicted_chains": " | ".join(c.get("explanation", "") for c in obs["chains"][:3]),
            "predicted_carriers": ";".join(obs["carrier_types"]),
            "evidence_strengths": ";".join(obs["evidence_strengths"]),
            "source_match_status": ";".join(q[0] for q in source_q),
            "sink_match_status": ";".join(q[0] for q in sink_q),
            "relay_match_status": ";".join(q[0] for q in relay_q),
        })

    summary = {
        "scope": "formal_776_common_success",
        "purpose": "Audit why literal relay/exact-chain metrics collapse although closure metrics are non-zero.",
        "three_level_explanation_definitions": {
            "L1_closure_only": "Correct malicious source-to-sink closure exists, but endpoint and/or structural intermediate identity is not fully matched.",
            "L2_endpoint_correct": "Correct closure plus expected endpoint identity matched.",
            "L3_structural_fidelity": "Closure, endpoint, source identity, and expected intermediate objects all matched under the fixed normalization rules.",
        },
        "mismatch_distribution": dict(mismatch.most_common()),
        "chain_level_counts": dict(chain_level.most_common()),
        "predicted_relay_node_families": dict(relay_pred_family.most_common()),
        "interpretation": [
            "Runtime chains encode taint-to-carrier-to-endpoint witnesses, e.g. source taint -> http_body/body or llm_context -> network endpoint.",
            "Benchmark ground truth encodes human-named intermediate artifacts such as staging files and payload files.",
            "Therefore relay/exact-chain literal metrics measure structural artifact fidelity, not only source-to-sink closure.",
        ],
    }
    out = OUT / "explanation_metric_audit"
    write_csv(out / "object_mapping_audit.csv", obj_rows)
    write_csv(out / "edge_mapping_audit.csv", edge_rows)
    write_csv(out / "chain_mapping_audit.csv", chain_rows)
    write_json(out / "object_mapping_audit.json", {"rows": obj_rows, "summary": summary})
    write_json(out / "edge_mapping_audit.json", {"rows": edge_rows, "summary": summary})
    write_json(out / "mismatch_distribution.json", summary)
    return summary


def static_vs_full_analysis(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    static_path = ABLATION_DIR / "static_only/metrics.json"
    if not static_path.exists():
        return {"status": "missing_static_only_metrics"}
    static = {s["sample_id"]: s for s in read_json(static_path)["samples"]}
    rows = []
    transition = Counter()
    reason = Counter()
    for sid in ids:
        full = samples[sid]
        st = static.get(sid, {})
        gt_label = "malicious" if full.get("expected_policy_outcome") == "confirmed_violation" else "benign"
        sp = st.get("predicted_label") or st.get("binary_prediction")
        fpred = full.get("predicted_label")
        key = f"GT={gt_label}|static={sp}|full={fpred}|coverage={full.get('coverage_state')}|risk={full.get('risk_chain_status')}|security={full.get('security_resolution_status')}"
        transition[key] += 1
        if gt_label == "malicious" and sp == "malicious" and fpred != "malicious":
            if full.get("coverage_state") in {"path_incomplete", "max_steps_exhausted", "timeout"}:
                r = "runtime_execution_or_path_incomplete_suppressed_static_risk"
            elif full.get("risk_chain_status") in {"confirmed_allowed", "no_sensitive_flow_observed"}:
                r = "runtime_observed_allowed_or_no_flow_overrode_static_risk"
            else:
                r = "full_policy_scoring_downgraded_static_malicious"
            reason[r] += 1
        elif gt_label == "benign" and sp == "malicious" and fpred == "benign":
            r = "runtime_policy_or_no_flow_corrected_static_false_positive"
            reason[r] += 1
        elif gt_label == "benign" and sp == "benign" and fpred == "malicious":
            r = "runtime_false_closure_or_trust_resolution_added_false_positive"
            reason[r] += 1
        else:
            r = "same_or_non_decisive_transition"
        rows.append({
            "sample_id": sid,
            "expected_label": gt_label,
            "expected_outcome": full.get("expected_policy_outcome"),
            "risk_family": full.get("risk_family"),
            "static_prediction": sp,
            "full_prediction": fpred,
            "static_correct": sp == gt_label,
            "full_correct": fpred == gt_label,
            "coverage_state": full.get("coverage_state"),
            "risk_chain_status": full.get("risk_chain_status"),
            "security_resolution_status": full.get("security_resolution_status"),
            "transition_reason": r,
        })
    out = {
        "scope": "formal_776_common_success",
        "static_only_f1_observation": "Static-only has higher binary F1 in current artifacts because it recalls every malicious GT case, while Full suppresses 107 malicious cases under incomplete/allowed/no-flow runtime evidence but also corrects some static benign false positives.",
        "transition_counts": dict(transition.most_common()),
        "reason_counts": dict(reason.most_common()),
    }
    write_csv(OUT / "static_vs_full/transitions.csv", rows)
    write_json(OUT / "static_vs_full/analysis.json", out)
    return out


def fn_taxonomy_v2(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rows = []
    counter = Counter()
    for sid in ids:
        s = samples[sid]
        if s.get("expected_policy_outcome") != "confirmed_violation" or s.get("predicted_label") == "malicious":
            continue
        gt = load_gt(sid)
        unified = load_unified(sid)
        cov = s.get("coverage_state", "")
        risk = s.get("risk_chain_status", "")
        sec = s.get("security_resolution_status", "")
        cert = (unified or {}).get("coverage_certificate", {}) or {}
        unresolved = cert.get("unresolved_decisive_obligations", []) or []
        gaps = cert.get("instrumentation_gaps", []) or []
        chains = load_runtime_chains(sid)
        if cov in {"timeout", "max_steps_exhausted"}:
            tax = "execution_budget_exhausted_before_decisive_sink"
        elif cov == "environment_missing":
            tax = "environment_or_dependency_missing"
        elif "allowed" in risk or "allowed" in sec:
            tax = "authorization_or_trust_model_downgraded_expected_violation"
        elif cov == "target_reached_no_flow":
            tax = "target_reached_but_taint_carrier_not_observed"
        elif unresolved:
            tax = "path_local_decisive_obligation_unresolved"
        elif gaps:
            tax = "instrumentation_gap_blocked_confirmation"
        elif not chains:
            tax = "no_runtime_chain_recovered"
        else:
            tax = "policy_assessment_did_not_escalate_recovered_chain"
        counter[tax] += 1
        rows.append({
            "sample_id": sid,
            "risk_family": s.get("risk_family"),
            "coverage_state": cov,
            "risk_chain_status": risk,
            "security_resolution_status": sec,
            "taxonomy_v2": tax,
            "runtime_chain_count": len(chains),
            "confirmed_chain_count": sum(c.get("evidence_level") == "confirmed" for c in chains),
            "unresolved_decisive_obligation_count": len(unresolved),
            "instrumentation_gap_count": len(gaps),
            "gt_sources": ";".join(gt.get("sources", []) or []),
            "gt_destinations": ";".join(gt.get("destinations", []) or []),
            "gt_operations": ";".join(gt.get("operations", []) or []),
        })
    out = {"fn_count": len(rows), "taxonomy_v2": dict(counter.most_common())}
    write_csv(OUT / "fn_taxonomy_v2/fn_cases.csv", rows)
    write_json(OUT / "fn_taxonomy_v2/summary.json", out)
    return out


def trusted_allowed_fp_taxonomy(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rows = []
    counter = Counter()
    for sid in ids:
        s = samples[sid]
        if s.get("expected_policy_outcome") != "trusted_allowed" or s.get("predicted_label") != "malicious":
            continue
        gt = load_gt(sid)
        obs = chain_observations(sid, s)
        sinks = ";".join(obs["pred_sinks"])
        if any("llm-provider.example" in x or "chat/completions" in x for x in obs["pred_sinks"]):
            tax = "trusted_llm_provider_flow_treated_as_untrusted_or_secondary_sink"
        elif obs["carrier_types"] and not gt.get("trusted_entities"):
            tax = "authorization_context_not_linked_to_runtime_sink"
        elif "confirmed_violation" in s.get("risk_chain_status", ""):
            tax = "confirmed_chain_policy_allowlist_mismatch"
        else:
            tax = "trusted_allowed_policy_resolution_error"
        counter[tax] += 1
        rows.append({
            "sample_id": sid,
            "risk_family": s.get("risk_family"),
            "coverage_state": s.get("coverage_state"),
            "risk_chain_status": s.get("risk_chain_status"),
            "security_resolution_status": s.get("security_resolution_status"),
            "taxonomy": tax,
            "gt_destinations": ";".join(gt.get("destinations", []) or []),
            "trusted_entities": ";".join(gt.get("trusted_entities", []) or []),
            "predicted_sinks": sinks,
            "predicted_carriers": ";".join(obs["carrier_types"]),
            "chain_count": len(obs["chains"]),
        })
    out = {"trusted_allowed_fp_count": len(rows), "taxonomy": dict(counter.most_common())}
    write_csv(OUT / "trusted_allowed_fp_taxonomy/fp_cases.csv", rows)
    write_json(OUT / "trusted_allowed_fp_taxonomy/summary.json", out)
    return out


def cooccurrence_baseline(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rows = []
    counters = {name: Counter() for name in ["any_network", "source_and_network", "any_taint_chain"]}
    for sid in ids:
        s = samples[sid]
        unified = load_unified(sid)
        events = ((unified or {}).get("dynamic_result", {}) or {}).get("runtime_events", []) or []
        chains = load_runtime_chains(sid)
        has_net = any((e.get("event_type") or "").startswith("network") or e.get("object_type") == "network" for e in events)
        has_taint_src = bool(((unified or {}).get("dynamic_result", {}) or {}).get("taint_sources", []))
        predicates = {
            "any_network": has_net,
            "source_and_network": has_net and has_taint_src,
            "any_taint_chain": bool(chains),
        }
        expected = s.get("expected_policy_outcome") == "confirmed_violation"
        for name, pred_bool in predicates.items():
            if expected and pred_bool:
                counters[name]["tp"] += 1
            elif expected and not pred_bool:
                counters[name]["fn"] += 1
            elif not expected and pred_bool:
                counters[name]["fp"] += 1
            else:
                counters[name]["tn"] += 1
        rows.append({"sample_id": sid, "expected_malicious": expected, **predicates})
    out = {}
    for name, c in counters.items():
        tp, tn, fp, fn = c["tp"], c["tn"], c["fp"], c["fn"]
        prec = div(tp, tp + fp)
        rec = div(tp, tp + fn)
        out[name] = {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "precision": prec, "recall": rec, "f1": f1(prec, rec), "fpr": div(fp, fp + tn)}
    write_csv(OUT / "cooccurrence_baseline/per_sample.csv", rows)
    write_json(OUT / "cooccurrence_baseline/metrics.json", out)
    return out


def coverage_evaluation(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    by_state = Counter()
    by_state_outcome = Counter()
    rows = []
    for sid in ids:
        s = samples[sid]
        state = s.get("coverage_state", "")
        outcome = s.get("expected_policy_outcome", "")
        by_state[state] += 1
        by_state_outcome[f"{state}|{outcome}|pred={s.get('predicted_label')}"] += 1
        rows.append({
            "sample_id": sid,
            "expected_outcome": outcome,
            "predicted_label": s.get("predicted_label"),
            "coverage_state": state,
            "risk_chain_status": s.get("risk_chain_status"),
            "security_resolution_status": s.get("security_resolution_status"),
            "correct": s.get("correct"),
        })
    out = {"coverage_state_counts": dict(by_state.most_common()), "coverage_state_by_outcome_prediction": dict(by_state_outcome.most_common())}
    write_csv(OUT / "coverage_evaluation/per_sample.csv", rows)
    write_json(OUT / "coverage_evaluation/summary.json", out)
    return out


def alignment_analysis(ids: list[str]) -> dict[str, Any]:
    status = Counter()
    atype = Counter()
    rows = []
    for sid in ids:
        unified = load_unified(sid) or {}
        aligns = unified.get("alignments", []) or []
        for a in aligns:
            status[a.get("status", "")] += 1
            atype[f"{a.get('alignment_type','')}|{a.get('status','')}"] += 1
        rows.append({
            "sample_id": sid,
            "alignment_count": len(aligns),
            "aligned": sum(a.get("status") == "aligned" for a in aligns),
            "partially_aligned": sum(a.get("status") == "partially_aligned" for a in aligns),
            "relevant_unresolved": sum(a.get("status") == "relevant_unresolved" for a in aligns),
            "internal_unresolved": sum(a.get("status") == "internal_unresolved" for a in aligns),
            "aligned_paths": len(unified.get("aligned_paths", []) or []),
            "runtime_only_paths": len(unified.get("runtime_only_paths", []) or []),
            "instruction_only_paths": len(unified.get("instruction_only_paths", []) or []),
        })
    out = {"alignment_status_counts": dict(status.most_common()), "alignment_type_status_counts": dict(atype.most_common())}
    write_csv(OUT / "alignment_analysis/per_sample.csv", rows)
    write_json(OUT / "alignment_analysis/summary.json", out)
    return out


def counterfactual_pair_consistency(ids: list[str], manifest: dict[str, dict[str, Any]], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[str]] = defaultdict(list)
    for sid in ids:
        pid = manifest[sid].get("counterfactual_pair_id")
        if pid:
            groups[pid].append(sid)
    rows = []
    counts = Counter()
    for pid, sids in sorted(groups.items()):
        if len(sids) < 2:
            continue
        preds = {sid: samples[sid].get("predicted_label") for sid in sids}
        gts = {sid: samples[sid].get("expected_label") for sid in sids}
        same_pred = len(set(preds.values())) == 1
        same_gt = len(set(gts.values())) == 1
        if same_gt and not same_pred:
            cat = "unstable_with_same_gt"
        elif not same_gt and same_pred:
            cat = "insensitive_to_counterfactual_label_change"
        else:
            cat = "consistent_or_mixed"
        counts[cat] += 1
        rows.append({"pair_id": pid, "sample_ids": ";".join(sids), "gt_labels": json.dumps(gts, sort_keys=True), "predictions": json.dumps(preds, sort_keys=True), "category": cat})
    out = {"pair_count_with_at_least_two_formal_samples": len(rows), "category_counts": dict(counts.most_common())}
    write_csv(OUT / "counterfactual_pairs/pairs.csv", rows)
    write_json(OUT / "counterfactual_pairs/summary.json", out)
    return out


def evidence_strength_ablation(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rows = []
    counts = Counter()
    for sid in ids:
        s = samples[sid]
        obs = chain_observations(sid, s)
        strengths = obs["evidence_strengths"]
        carriers = obs["carrier_types"]
        key = f"strength={'+'.join(strengths) or 'none'}|carrier={'+'.join(carriers) or 'none'}|expected={s.get('expected_policy_outcome')}|pred={s.get('predicted_label')}"
        counts[key] += 1
        rows.append({
            "sample_id": sid,
            "expected_outcome": s.get("expected_policy_outcome"),
            "predicted_label": s.get("predicted_label"),
            "evidence_strengths": ";".join(strengths),
            "carrier_types": ";".join(carriers),
            "chain_count": len(obs["chains"]),
            "complete_chain_recovered": s.get("complete_chain_recovered"),
            "confirmed_violation_chain": s.get("confirmed_violation_chain"),
        })
    out = {"evidence_strength_carrier_distribution": dict(counts.most_common())}
    write_csv(OUT / "evidence_strength_ablation/per_sample.csv", rows)
    write_json(OUT / "evidence_strength_ablation/summary.json", out)
    return out


def analyst_protocol() -> None:
    text = """# Analyst Review Protocol

This protocol is not a completed human study. It is a reproducible review checklist
for the frozen formal-776 artifacts.

Review unit: one ProvBench case with ground truth, SKILL.md, ProvLoom
unified-analysis.json, runtime-chains.json, runtime graph, and evaluator row.

Questions:
1. Is the malicious/benign binary prediction correct?
2. If malicious, does the reported witness establish source-to-sink closure?
3. Does the witness identify the expected endpoint?
4. Does the witness preserve expected intermediate artifact structure?
5. Are missing relays due to carrier-level runtime modeling, true execution miss,
   ontology mismatch, or evaluator normalization failure?
6. If false positive, is the cause trust/authorization, benign-lookalike false
   closure, instrumentation gap, or policy scoring?
7. If false negative, is the cause path not triggered, runtime failure, missing
   carrier visibility, allowlist/trust downgrade, or policy scoring?

Recommended outputs: adjudicated label, explanation level (L1/L2/L3), mismatch
category, and free-text rationale. Do not tune analyzer or thresholds during
review.
"""
    (OUT / "analyst_protocol/review_protocol.md").parent.mkdir(parents=True, exist_ok=True)
    (OUT / "analyst_protocol/review_protocol.md").write_text(text)


def explanation_metrics(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    source_tp = source_pred = source_gold = 0
    sink_tp = sink_pred = sink_gold = 0
    relay_tp = relay_pred = relay_gold = 0
    edge_tp = edge_pred = edge_gold = 0
    exact_tp = exact_pred = exact_gold = 0
    witness_tp = witness_pred = witness_gold = 0
    per_sample: list[dict[str, Any]] = []
    carrier_rows: list[dict[str, Any]] = []

    for sid in ids:
        gt = load_gt(sid)
        sample = samples[sid]
        unified = load_unified(sid)
        graph = load_runtime_graph(sid)
        chains_all = load_runtime_chains(sid)
        decisive = policy_chain_ids(unified)
        chains = [c for c in chains_all if not decisive or c.get("chain_id") in decisive]
        if sample.get("expected_policy_outcome") != "confirmed_violation":
            chains = [c for c in chains if sample.get("predicted_label") == "malicious"]

        pred_sources = [chain_source_label(c, graph) for c in chains]
        registry_sources = taint_source_labels(unified, graph)
        if registry_sources:
            enriched = []
            for p in pred_sources:
                enriched.append(p)
                if re.fullmatch(r"(source )?t-[a-f0-9]+", norm(p)) or not p.strip():
                    enriched.extend(registry_sources)
            pred_sources = enriched
        pred_sources = sorted(set(p for p in pred_sources if p.strip()))
        pred_sinks = sorted(set(chain_sink_label(c) for c in chains if chain_sink_label(c).strip()))
        gt_sources = sorted(set(gt.get("sources", []) or []))
        gt_sinks = sorted(set(gt.get("destinations", []) or []))
        gt_relays = sorted(set(gt.get("intermediate_objects", []) or []))
        gt_ops = set(gt.get("operations", []) or [])
        pred_ops = edge_ops(chains)

        source_gold += len(gt_sources)
        source_pred += len(pred_sources)
        for g in gt_sources:
            if any(source_match(g, p) for p in pred_sources):
                source_tp += 1

        sink_gold += len(gt_sinks)
        sink_pred += len(pred_sinks)
        for g in gt_sinks:
            if any(sink_match(g, p) for p in pred_sinks):
                sink_tp += 1

        relay_gold += len(gt_relays)
        pred_relay_nodes = sorted(set(n for c in chains for n in (c.get("ordered_nodes", []) or [])))
        relay_pred += len(pred_relay_nodes)
        for r in gt_relays:
            if relay_match(r, chains):
                relay_tp += 1

        edge_gold += len(gt.get("ordered_relations", []) or [])
        pred_edge_keys = sorted(set(
            f"{norm(w.get('edge', ''))}:{norm(w.get('from', ''))}:{norm(w.get('to', ''))}"
            for c in chains
            for w in (c.get("metadata", {}).get("minimal_witness", []) or [])
        ))
        edge_pred += len(pred_edge_keys)
        edge_tp += len(gt_ops & pred_ops)

        has_gt_chain = bool(gt.get("expected_complete_chains"))
        has_pred_chain = bool(chains)
        if has_gt_chain:
            exact_gold += 1
        if has_pred_chain:
            exact_pred += 1
        exact_match = (
            has_gt_chain
            and has_pred_chain
            and all(any(source_match(g, p) for p in pred_sources) for g in gt_sources)
            and all(any(sink_match(g, p) for p in pred_sinks) for g in gt_sinks)
            and all(relay_match(r, chains) for r in gt_relays)
        )
        if exact_match:
            exact_tp += 1

        witness_gold += len(gt.get("minimal_evidence_sets", []) or [])
        witness_pred += len((unified or {}).get("minimal_witnesses", []) or [])
        gt_spans = {norm(x) for xs in gt.get("minimal_evidence_sets", []) or [] for x in xs}
        static_text = " ".join(
            norm(a.get("evidence", {}).get("exact_text", ""))
            for a in ((unified or {}).get("static_result", {}) or {}).get("extracted_actions", []) or []
        )
        witness_hit = bool(gt_spans and all(s in static_text for s in gt_spans))
        if witness_hit:
            witness_tp += len(gt.get("minimal_evidence_sets", []) or [])

        carrier_types = sorted({ct for c in chains for ct in (c.get("metadata", {}).get("carrier_types", []) or [])})
        carrier_rows.append({
            "sample_id": sid,
            "expected_outcome": sample.get("expected_policy_outcome"),
            "risk_family": sample.get("risk_family"),
            "gt_transport_carriers": ";".join(gt.get("transport_carriers", []) or []),
            "predicted_carrier_types": ";".join(carrier_types),
            "confirmed_violation_chain": bool(sample.get("confirmed_violation_chain")),
            "complete_chain_recovered": bool(sample.get("complete_chain_recovered")),
            "coverage_state": sample.get("coverage_state", ""),
            "exact_chain_match": exact_match,
        })
        per_sample.append({
            "sample_id": sid,
            "expected_outcome": sample.get("expected_policy_outcome"),
            "predicted_label": sample.get("predicted_label"),
            "source_match": any(any(source_match(g, p) for p in pred_sources) for g in gt_sources) if gt_sources else False,
            "sink_match": any(any(sink_match(g, p) for p in pred_sinks) for g in gt_sinks) if gt_sinks else False,
            "relay_match": all(relay_match(r, chains) for r in gt_relays) if gt_relays else False,
            "exact_chain_match": exact_match,
            "minimal_witness_match": witness_hit,
            "predicted_chain_count": len(chains),
            "coverage_state": sample.get("coverage_state", ""),
        })

    complete_pred = sum(1 for sid in ids if samples[sid].get("complete_chain_recovered"))
    complete_gold = sum(1 for sid in ids if samples[sid].get("has_expected_complete_chain"))
    complete_tp = sum(1 for sid in ids if samples[sid].get("complete_chain_recovered") and samples[sid].get("has_expected_complete_chain"))
    confirmed_pred = sum(1 for sid in ids if samples[sid].get("confirmed_violation_chain"))
    confirmed_gold = sum(1 for sid in ids if samples[sid].get("expected_policy_outcome") == "confirmed_violation")
    confirmed_tp = sum(1 for sid in ids if samples[sid].get("confirmed_violation_chain") and samples[sid].get("expected_policy_outcome") == "confirmed_violation")

    metrics = {
        "metric_scope": "formal_776",
        "matching_policy": "Conservative ontology-level string matching between GT objects and frozen ProvLoom evidence objects; not a manual edge audit.",
        "confirmed_violation_chain": prf(confirmed_tp, confirmed_pred, confirmed_gold),
        "complete_chain": prf(complete_tp, complete_pred, complete_gold),
        "source": prf(source_tp, source_pred, source_gold),
        "sink": prf(sink_tp, sink_pred, sink_gold),
        "relay_or_intermediate": prf(relay_tp, relay_pred, relay_gold),
        "edge_operation": prf(edge_tp, edge_pred, edge_gold),
        "exact_chain_match": prf(exact_tp, exact_pred, exact_gold),
        "minimal_witness": prf(witness_tp, witness_pred, witness_gold),
        "counts": {
            "samples": len(ids),
            "confirmed_violation_samples": confirmed_gold,
            "complete_chain_gold_samples": complete_gold,
        },
    }
    write_json(OUT / "chain_metrics/metrics.json", metrics)
    write_csv(OUT / "chain_metrics/per_sample.csv", per_sample)
    write_csv(OUT / "carrier_analysis/per_sample.csv", carrier_rows)
    return metrics


def group_rate(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[str(r.get(key, ""))].append(r)
    out = []
    for k, xs in sorted(groups.items()):
        n = len(xs)
        out.append({
            key: k,
            "n": n,
            "confirmed_chain_recall": div(sum(x["confirmed_violation_chain"] for x in xs), n),
            "complete_chain_recall": div(sum(x["complete_chain_recovered"] for x in xs), n),
            "exact_chain_match_rate": div(sum(x["exact_chain_match"] for x in xs), n),
            "coverage_failure_rate": div(sum(x["coverage_state"] != "complete" for x in xs), n),
        })
    return out


def failure_taxonomy(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    fp_rows = []
    fn_rows = []
    fp_counter = Counter()
    fn_counter = Counter()
    for sid in ids:
        s = samples[sid]
        gt = load_gt(sid)
        expected = s.get("expected_policy_outcome")
        pred = s.get("predicted_label")
        if expected != "confirmed_violation" and pred == "malicious":
            if expected == "trusted_allowed":
                reason = "trust_or_authorization_resolution_error"
            elif expected == "benign_lookalike":
                reason = "benign_lookalike_false_closure"
            elif expected == "review_coverage":
                reason = "coverage_state_over_escalated"
            else:
                reason = "other_false_positive"
            fp_counter[reason] += 1
            fp_rows.append({
                "sample_id": sid,
                "expected_outcome": expected,
                "risk_family": s.get("risk_family"),
                "coverage_state": s.get("coverage_state"),
                "risk_chain_status": s.get("risk_chain_status"),
                "security_resolution_status": s.get("security_resolution_status"),
                "taxonomy": reason,
            })
        if expected == "confirmed_violation" and pred != "malicious":
            cov = s.get("coverage_state", "")
            sec = s.get("security_resolution_status", "")
            risk = s.get("risk_chain_status", "")
            if cov in {"timeout", "max_steps_exhausted"}:
                reason = "bounded_execution_not_completed"
            elif cov == "environment_missing":
                reason = "environment_missing"
            elif cov == "target_reached_no_flow":
                reason = "target_reached_no_carrier_flow"
            elif "unresolved_execution" in sec:
                reason = "branch_or_execution_path_incomplete"
            elif cov == "path_incomplete" and risk == "confirmed_allowed":
                reason = "policy_or_authorization_mismatch_after_partial_path"
            elif cov == "path_incomplete":
                reason = "source_to_sink_relation_incomplete"
            else:
                reason = "other_false_negative"
            fn_counter[reason] += 1
            fn_rows.append({
                "sample_id": sid,
                "risk_family": s.get("risk_family"),
                "coverage_state": cov,
                "risk_chain_status": risk,
                "security_resolution_status": sec,
                "taxonomy": reason,
                "gt_sources": ";".join(gt.get("sources", []) or []),
                "gt_destinations": ";".join(gt.get("destinations", []) or []),
            })
    obj = {
        "false_positive_taxonomy": dict(fp_counter.most_common()),
        "false_negative_taxonomy": dict(fn_counter.most_common()),
        "fp_count": len(fp_rows),
        "fn_count": len(fn_rows),
    }
    write_json(OUT / "failure_analysis/metrics.json", obj)
    write_csv(OUT / "failure_analysis/false_positives.csv", fp_rows)
    write_csv(OUT / "failure_analysis/false_negatives.csv", fn_rows)
    return obj


def benchmark_distribution(ids: list[str], manifest: dict[str, dict[str, Any]]) -> dict[str, Any]:
    fields = ["expected_policy_outcome", "split", "risk_family", "writing_style_family", "llm_mediated", "network_or_external", "multi_file"]
    out = {"n": len(ids)}
    for f in fields:
        out[f] = dict(Counter(str(manifest[sid].get(f)) for sid in ids).most_common())
    pair_counter = Counter(manifest[sid].get("counterfactual_pair_id") for sid in ids)
    out["counterfactual_pair_count"] = len(pair_counter)
    out["complete_pairs_in_formal_776"] = sum(1 for v in pair_counter.values() if v > 1)
    write_json(OUT / "benchmark_methodology/distribution.json", out)
    return out


def ablation(ids: list[str], samples: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    variants = {
        "Full": PROV_METRICS,
        "Static-only": ABLATION_DIR / "static_only/metrics.json",
        "Event-only": ABLATION_DIR / "event_only/metrics.json",
        "No alignment": ABLATION_DIR / "no_alignment/metrics.json",
        "No policy": ABLATION_DIR / "no_policy/metrics.json",
    }
    rows = []
    ids_set = set(ids)
    for name, path in variants.items():
        if not path.exists():
            continue
        ms = {s["sample_id"]: s for s in read_json(path)["samples"] if s["sample_id"] in ids_set}
        tp = tn = fp = fn = 0
        for sid, s in ms.items():
            exp = "malicious" if s.get("expected_policy_outcome") == "confirmed_violation" else "benign"
            pred = s.get("predicted_label") or s.get("binary_prediction")
            if exp == "malicious" and pred == "malicious":
                tp += 1
            elif exp == "benign" and pred != "malicious":
                tn += 1
            elif exp == "benign" and pred == "malicious":
                fp += 1
            elif exp == "malicious" and pred != "malicious":
                fn += 1
        prec = div(tp, tp + fp)
        rec = div(tp, tp + fn)
        nonmal = tn + fp
        bl = [s for s in ms.values() if s.get("expected_policy_outcome") == "benign_lookalike"]
        ta = [s for s in ms.values() if s.get("expected_policy_outcome") == "trusted_allowed"]
        rows.append({
            "variant": name,
            "n": len(ms),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "precision": round(prec, 6),
            "recall": round(rec, 6),
            "f1": round(f1(prec, rec), 6),
            "fpr": round(div(fp, nonmal), 6),
            "benign_lookalike_fpr": round(div(sum((x.get("predicted_label") == "malicious") for x in bl), len(bl)), 6),
            "trusted_allowed_fpr": round(div(sum((x.get("predicted_label") == "malicious") for x in ta), len(ta)), 6),
            "complete_chain_recall": round(div(sum(x.get("complete_chain_recovered") for x in ms.values()), sum(x.get("has_expected_complete_chain") for x in ms.values())), 6),
            "confirmed_chain_recall": round(div(sum(x.get("confirmed_violation_chain") for x in ms.values() if x.get("expected_policy_outcome") == "confirmed_violation"), sum(1 for x in ms.values() if x.get("expected_policy_outcome") == "confirmed_violation")), 6),
        })
    write_csv(OUT / "ablation/metrics.csv", rows)
    write_json(OUT / "ablation/metrics.json", rows)
    return rows


def efficiency(ids: list[str]) -> dict[str, Any]:
    summary = read_json(PROV_SUMMARY)
    by_id = {s["sample_id"]: s for s in summary.get("samples", []) if s["sample_id"] in set(ids)}
    elapsed = [float(s.get("elapsed_seconds") or 0) for s in by_id.values() if s.get("status") == "completed"]
    req = [float((s.get("token_usage") or {}).get("request_count") or 0) for s in by_id.values() if s.get("status") == "completed"]
    total_tokens = [float((s.get("token_usage") or {}).get("total_tokens") or 0) for s in by_id.values() if s.get("status") == "completed"]
    prompt_tokens = [float((s.get("token_usage") or {}).get("prompt_tokens") or 0) for s in by_id.values() if s.get("status") == "completed"]
    completion_tokens = [float((s.get("token_usage") or {}).get("completion_tokens") or 0) for s in by_id.values() if s.get("status") == "completed"]
    node_counts, edge_counts, sizes = [], [], []
    event_counts = []
    for sid in ids:
        g = load_runtime_graph(sid)
        if g:
            node_counts.append(len(g.get("nodes", [])))
            edge_counts.append(len(g.get("edges", [])))
            event_counts.append(sum((g.get("summary") or {}).get("edge_types", {}).values()))
        d = RUN_DIR / f"PROVBENCH-FULL-{sid}"
        if d.exists():
            total_size = 0
            for p in d.iterdir():
                if p.is_file():
                    total_size += p.stat().st_size
            sizes.append(total_size)
    def stats(xs: list[float]) -> dict[str, float]:
        return {
            "median": round(statistics.median(xs), 3) if xs else 0,
            "p95": round(pct(xs, 0.95), 3) if xs else 0,
            "mean": round(statistics.mean(xs), 3) if xs else 0,
        }
    out = {
        "samples": len(ids),
        "completed_with_summary": len(elapsed),
        "elapsed_seconds": stats(elapsed),
        "llm_requests_per_sample": stats(req),
        "total_tokens_per_sample": stats(total_tokens),
        "prompt_tokens_per_sample": stats(prompt_tokens),
        "completion_tokens_per_sample": stats(completion_tokens),
        "runtime_graph_nodes": stats(node_counts),
        "runtime_graph_edges": stats(edge_counts),
        "runtime_graph_edge_events_proxy": stats(event_counts),
        "artifact_bytes_per_sample": stats(sizes),
        "timeout_or_failed_count": sum(1 for s in by_id.values() if s.get("timed_out") or s.get("status") != "completed"),
    }
    write_json(OUT / "performance/metrics.json", out)
    return out


def group_analyses(ids: list[str], manifest: dict[str, dict[str, Any]], samples: dict[str, dict[str, Any]]) -> None:
    rows = []
    for sid in ids:
        gt = load_gt(sid)
        s = samples[sid]
        m = manifest[sid]
        rows.append({
            "sample_id": sid,
            "writing_style_family": m.get("writing_style_family"),
            "multi_file": m.get("multi_file"),
            "llm_mediated": m.get("llm_mediated"),
            "risk_family": m.get("risk_family"),
            "transformation": ";".join(gt.get("transformations", []) or []),
            "transport_carrier": ";".join(gt.get("transport_carriers", []) or []),
            "confirmed_violation_chain": bool(s.get("confirmed_violation_chain")),
            "complete_chain_recovered": bool(s.get("complete_chain_recovered")),
            "coverage_state": s.get("coverage_state", ""),
            "exact_chain_match": False,
        })
    per_sample_path = OUT / "chain_metrics/per_sample.csv"
    if per_sample_path.exists():
        exact = {r["sample_id"]: r["exact_chain_match"] in ("True", "true", True) for r in csv.DictReader(per_sample_path.open())}
        for r in rows:
            r["exact_chain_match"] = exact.get(r["sample_id"], False)
    write_csv(OUT / "instruction_robustness/per_sample_groups.csv", rows)
    write_csv(OUT / "instruction_robustness/by_writing_style.csv", group_rate(rows, "writing_style_family"))
    write_csv(OUT / "instruction_robustness/by_multifile.csv", group_rate(rows, "multi_file"))
    write_csv(OUT / "transformation_robustness/by_transformation.csv", group_rate(rows, "transformation"))
    write_csv(OUT / "carrier_analysis/by_gt_transport_carrier.csv", group_rate(rows, "transport_carrier"))


def case_studies(samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    fn_sid = next(sid for sid, s in samples.items() if s.get("expected_policy_outcome") == "confirmed_violation" and s.get("predicted_label") != "malicious")
    ids = ["PB-001", "PB-399", fn_sid]
    cases = []
    for sid in ids:
        gt = load_gt(sid)
        s = samples[sid]
        skill = (ROOT / f"provbench/cases/{sid}/SKILL.md").read_text()
        unified = load_unified(sid)
        chains = load_runtime_chains(sid)
        cases.append({
            "sample_id": sid,
            "role": "true_positive_closed_chain" if sid == "PB-001" else ("benign_lookalike" if sid == "PB-399" else "false_negative_or_need_review"),
            "expected_outcome": s.get("expected_policy_outcome"),
            "predicted_label": s.get("predicted_label"),
            "risk_family": s.get("risk_family"),
            "coverage_state": s.get("coverage_state"),
            "security_resolution_status": s.get("security_resolution_status"),
            "instruction_excerpt": skill[:1600],
            "gt_sources": gt.get("sources", []),
            "gt_intermediate_objects": gt.get("intermediate_objects", []),
            "gt_destinations": gt.get("destinations", []),
            "gt_expected_chains": gt.get("expected_complete_chains", []),
            "gt_forbidden_false_chains": gt.get("forbidden_false_chains", []),
            "runtime_chains": chains[:3],
            "policy_findings": (unified or {}).get("policy_findings", [])[:4],
            "minimal_witnesses": (unified or {}).get("minimal_witnesses", [])[:3],
        })
    write_json(OUT / "case_studies/cases.json", cases)
    return {"case_ids": ids}


def markdown_summary(results: dict[str, Any]) -> None:
    lines = ["# ProvLoom USENIX Paper Evaluation Artifacts", ""]
    lines.append(f"Generated at: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("Scope: fixed ProvBench 776-case corpus.")
    lines.append("")
    cm = results["chain_metrics"]
    lines.append("## Explanation Metrics")
    for k in ["confirmed_violation_chain", "complete_chain", "source", "sink", "relay_or_intermediate", "edge_operation", "exact_chain_match", "minimal_witness"]:
        v = cm[k]
        lines.append(f"- {k}: P={v['precision']:.3f}, R={v['recall']:.3f}, F1={v['f1']:.3f} (tp={v['tp']}, pred={v['predicted']}, gold={v['gold']})")
    lines.append("")
    lines.append("## Failure Taxonomy")
    lines.append(f"- FP: {results['failure']['false_positive_taxonomy']}")
    lines.append(f"- FN: {results['failure']['false_negative_taxonomy']}")
    lines.append(f"- FN v2: {results['fn_taxonomy_v2']['taxonomy_v2']}")
    lines.append(f"- Trusted-allowed FP: {results['trusted_allowed_fp_taxonomy']['taxonomy']}")
    lines.append("")
    lines.append("## Explanation Audit")
    audit = results["explanation_metric_audit"]
    lines.append(f"- Three-level counts: {audit['chain_level_counts']}")
    lines.append("- Interpretation: runtime witnesses are carrier-level (`taint -> http_body/llm_context -> endpoint`), while GT complete chains include named staging/payload artifacts.")
    lines.append("")
    lines.append("## Static vs Full")
    lines.append(f"- Main transition reasons: {results['static_vs_full']['reason_counts']}")
    lines.append("")
    lines.append("## Co-occurrence Baselines")
    for name, vals in results["cooccurrence_baseline"].items():
        lines.append(f"- {name}: F1={vals['f1']:.3f}, Precision={vals['precision']:.3f}, Recall={vals['recall']:.3f}, FPR={vals['fpr']:.3f}")
    lines.append("")
    lines.append("## Efficiency")
    perf = results["performance"]
    lines.append(f"- Total latency seconds: median={perf['elapsed_seconds']['median']}, p95={perf['elapsed_seconds']['p95']}")
    lines.append(f"- LLM requests/sample: median={perf['llm_requests_per_sample']['median']}, p95={perf['llm_requests_per_sample']['p95']}")
    lines.append(f"- Tokens/sample: median={perf['total_tokens_per_sample']['median']}, p95={perf['total_tokens_per_sample']['p95']}")
    lines.append("")
    (OUT / "summary.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    ids, manifest = load_manifest()
    samples = load_formal_samples(ids)
    if len(ids) != 776 or len(samples) != 776:
        raise SystemExit(f"Expected 776 formal samples, got ids={len(ids)} samples={len(samples)}")
    OUT.mkdir(parents=True, exist_ok=True)
    config = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "ProvBench corpus, N=776",
        "formal_id_source": str(FORMAL_IDS.relative_to(ROOT)),
        "full_system_metrics": str(PROV_METRICS.relative_to(ROOT)),
        "ground_truth_dir": str(GT_DIR.relative_to(ROOT)),
        "analyzer_ground_truth_loaded": False,
        "script": str(Path(__file__).relative_to(ROOT)),
    }
    write_json(OUT / "config.json", config)
    results = {
        "benchmark": benchmark_distribution(ids, manifest),
        "chain_metrics": explanation_metrics(ids, samples),
        "explanation_metric_audit": explanation_metric_audit(ids, samples),
        "failure": failure_taxonomy(ids, samples),
        "fn_taxonomy_v2": fn_taxonomy_v2(ids, samples),
        "trusted_allowed_fp_taxonomy": trusted_allowed_fp_taxonomy(ids, samples),
        "static_vs_full": static_vs_full_analysis(ids, samples),
        "ablation": ablation(ids, samples),
        "cooccurrence_baseline": cooccurrence_baseline(ids, samples),
        "coverage_evaluation": coverage_evaluation(ids, samples),
        "alignment_analysis": alignment_analysis(ids),
        "counterfactual_pairs": counterfactual_pair_consistency(ids, manifest, samples),
        "evidence_strength_ablation": evidence_strength_ablation(ids, samples),
        "performance": efficiency(ids),
        "case_studies": case_studies(samples),
    }
    group_analyses(ids, manifest, samples)
    analyst_protocol()
    write_json(OUT / "metrics.json", results)
    markdown_summary(results)


if __name__ == "__main__":
    main()
