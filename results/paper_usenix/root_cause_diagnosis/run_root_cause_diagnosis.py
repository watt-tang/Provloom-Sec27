#!/usr/bin/env python3
"""Evaluation-only root-cause diagnosis for frozen ProvLoom artifacts.

This script does not invoke the analyzer, Docker, LLMs, or benchmark runners.
It reads the fixed common-success 776 sample IDs, frozen ProvLoom predictions,
ProvBench ground truth, and existing runtime/static artifacts.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import statistics
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "artifacts/paper_usenix/root_cause_diagnosis"
STRUCT = OUT / "structural_explanation"
ORACLE = OUT / "oracle_policy"
COMMON = ROOT / "artifacts/baseline_provbench/common_success_comparison/common_success_manifest.json"
PROV_METRICS = ROOT / "artifacts/provbench_full_glm52_steps16_0001_0800/metrics.json"
PROV_SUMMARY = ROOT / "artifacts/provbench_full_glm52_steps16_0001_0800/summary.json"
GT_DIR = ROOT / "provbench/ground_truth_private"
RUN_DIR = ROOT / "artifacts/runs"
PREV_EVAL = ROOT / "scripts/paper_usenix_eval.py"


@lru_cache(maxsize=None)
def read_json(path: Path) -> Any:
    with path.open() as f:
        return json.load(f)


def sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0].keys()) if rows else []
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    except Exception as exc:  # pragma: no cover - diagnostic metadata only
        return f"unavailable: {exc}"


@lru_cache(maxsize=None)
def norm_text(s: Any) -> str:
    s = str(s or "").strip().lower()
    s = s.replace("\\", "/")
    s = re.sub(r"/+", "/", s)
    s = re.sub(r"^(file|source|network|net):", "", s)
    s = s.replace("/workspace/skill/", "").replace("/workspace/", "")
    s = re.sub(r"[^a-z0-9:/._?=&-]+", " ", s)
    return " ".join(s.split())


@lru_cache(maxsize=None)
def is_url(s: Any) -> bool:
    return bool(re.match(r"^[a-z][a-z0-9+.-]*://", str(s or "").strip(), re.I))


@lru_cache(maxsize=None)
def canon_url(s: Any) -> str:
    raw = str(s or "").strip()
    if not is_url(raw):
        return ""
    p = urlparse(raw)
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port else ""
    path = re.sub(r"/+", "/", p.path or "/")
    query = p.query
    return urlunparse((scheme, host + port, path, "", query, ""))


@lru_cache(maxsize=None)
def strip_source_field(s: Any) -> str:
    raw = str(s or "").strip()
    if is_url(raw):
        return canon_url(raw)
    if ":" in raw and not raw.lower().startswith(("t-", "source:")):
        left, right = raw.rsplit(":", 1)
        if "/" in left or "." in left:
            return left
    return raw


@lru_cache(maxsize=None)
def canon_path(s: Any) -> str:
    raw = strip_source_field(s)
    if is_url(raw):
        return canon_url(raw)
    x = norm_text(raw)
    for prefix in ("/workspace/skill/", "/workspace/", "file:"):
        if x.startswith(prefix):
            x = x[len(prefix):]
    return x.strip("/")


@lru_cache(maxsize=None)
def basename(s: Any) -> str:
    c = canon_path(s)
    return c.rsplit("/", 1)[-1] if c else ""


@lru_cache(maxsize=None)
def object_family(value: Any) -> str:
    s = str(value or "")
    n = norm_text(s)
    if not n:
        return "empty"
    if is_url(s) or n.startswith("net:") or "network:" in n:
        return "network_endpoint"
    if "llm_context" in n or "messages[" in n or "prompt" in n:
        return "llm_context"
    if "http_body" in n or n in {"body", "header", "query"} or "multipart" in n:
        return "generic_carrier"
    if re.search(r"(^|/)[^/]+\\.[a-z0-9]{1,8}($|:)", n) or "/" in n:
        return "file"
    if re.fullmatch(r"t-[a-f0-9]+", n) or n.startswith("source:"):
        return "taint_source"
    if "proc" in n or "exec" in n or "argv" in n:
        return "process"
    return "data_object"


def literal_match(gold: Any, pred: Any) -> bool:
    return str(gold or "").strip() == str(pred or "").strip()


def canonical_match(gold: Any, pred: Any) -> bool:
    if is_url(gold) or is_url(pred):
        return bool(canon_url(gold) and canon_url(gold) == canon_url(pred))
    gp = canon_path(gold)
    pp = canon_path(pred)
    if not gp or not pp:
        return False
    if gp == pp:
        return True
    gb, pb = basename(gp), basename(pp)
    return bool(gb and pb and gb == pb)


def semantic_specific_match(gold: Any, pred: Any) -> bool:
    """Ontology-aware but does not map generic carrier to a specific relay."""
    gf = object_family(gold)
    pf = object_family(pred)
    if canonical_match(gold, pred):
        return True
    if gf == "file" and pf == "file":
        return basename(gold) == basename(pred)
    if gf == "network_endpoint" and pf == "network_endpoint":
        return canonical_match(gold, pred)
    if gf in {"file", "network_endpoint"} and pf in {"generic_carrier", "llm_context", "data_object"}:
        return False
    return False


OP_ALIASES = {
    "read": "read",
    "access": "read",
    "stage": "write",
    "write": "write",
    "create": "write",
    "transform": "transform",
    "derive": "transform",
    "derives": "transform",
    "propagate": "transform",
    "propagates": "transform",
    "deliver": "send",
    "send": "send",
    "sends": "send",
    "upload": "send",
    "call_model": "send",
    "execute": "execute",
    "exec": "execute",
    "persist": "persist",
    "presence_check": "read",
    "suppress_value": "filter",
    "write_local_review": "write",
}


RULES_TEXT = """schema_version: provloom-root-cause-normalization-v1
scope: evaluation-only fixed formal_776
object_canonicalization:
  paths:
    - lower-case and slash-normalize
    - remove /workspace/skill and /workspace prefixes
    - allow basename/full-path equivalence for file-like objects
    - strip source field suffix such as path:FIELD only for file-like source objects
  endpoints:
    - normalize scheme, host case, explicit port, repeated slashes, path, and query
    - never split URL strings on the first colon
  taint_sources:
    - allow taint id to source path only when runtime source registry metadata contains source_object/source_location
operation_equivalence:
  read: [read, access, presence_check]
  write: [stage, write, create, write_local_review]
  transform: [transform, derive, derives, propagate, propagates]
  send: [deliver, send, sends, upload, call_model]
  execute: [execute, exec]
carrier_equivalence:
  generic_carrier_types: [http_body, llm_context, tool_argument, socket_payload, generic payload]
  rule: generic carriers may support closure but must not be counted as specific relay identity
artifact_identity_rules:
  specific relay match requires file/path/object identity evidence, not only a generic DataObject hash or carrier label
  semantic match is global and deterministic; no sample-specific mapping is allowed
contracts:
  literal: exact raw string equality
  canonical: deterministic path/URI/operation normalization only
  semantic: schema-level equivalence with specific object identity; generic carriers do not match named relays
"""


def load_ids() -> list[str]:
    ids = read_json(COMMON)["sample_ids"]
    if len(ids) != 776:
        raise SystemExit(f"Expected fixed N=776, got {len(ids)}")
    return ids


def load_samples(ids: list[str]) -> dict[str, dict[str, Any]]:
    all_samples = {s["sample_id"]: s for s in read_json(PROV_METRICS)["samples"]}
    return {sid: all_samples[sid] for sid in ids}


def gt(sid: str) -> dict[str, Any]:
    return read_json(GT_DIR / f"{sid}.json")


def unified(sid: str) -> dict[str, Any]:
    p = RUN_DIR / f"PROVBENCH-FULL-{sid}" / "unified-analysis.json"
    return read_json(p) if p.exists() else {}


def graph(sid: str) -> dict[str, Any]:
    p = RUN_DIR / f"PROVBENCH-FULL-{sid}" / "runtime-provenance-graph.json"
    return read_json(p) if p.exists() else {"nodes": [], "edges": []}


def chains(sid: str) -> list[dict[str, Any]]:
    p = RUN_DIR / f"PROVBENCH-FULL-{sid}" / "runtime-chains.json"
    return read_json(p) if p.exists() else []


def source_labels(sid: str, chs: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    u = unified(sid)
    g = graph(sid)
    node_by_id = {n.get("node_id"): n for n in g.get("nodes", [])}
    for c in chs:
        out.append(c.get("source", ""))
        n = node_by_id.get(c.get("source"))
        if n:
            out.extend([n.get("label", ""), (n.get("metadata", {}) or {}).get("source_location", ""), (n.get("metadata", {}) or {}).get("source_object", "")])
    for src in ((u.get("dynamic_result", {}) or {}).get("taint_sources", []) or []):
        md = src.get("metadata", {}) or {}
        label = md.get("label", {}) if isinstance(md.get("label"), dict) else {}
        out.extend([
            src.get("source_location", ""),
            md.get("source_object", ""),
            md.get("source_location", ""),
            label.get("source_object", ""),
        ])
    for n in g.get("nodes", []):
        if n.get("node_type") == "SensitiveSource":
            md = n.get("metadata", {}) or {}
            out.extend([n.get("label", ""), md.get("source_location", ""), md.get("source_object", "")])
    return sorted({x for x in out if str(x).strip()})


def sink_labels(chs: list[dict[str, Any]]) -> list[str]:
    return sorted({str(c.get("sink", "")).replace("network:NET:", "").replace("NET:", "") for c in chs if c.get("sink")})


def chain_relay_labels(chs: list[dict[str, Any]]) -> list[str]:
    out = []
    for c in chs:
        nodes = c.get("ordered_nodes", []) or []
        for n in nodes[1:-1]:
            out.append(str(n).replace("file:", "").replace("network:NET:", "").replace("NET:", ""))
        for w in (c.get("metadata", {}) or {}).get("minimal_witness", []) or []:
            out.extend([w.get("to", ""), w.get("carrier_location", "")])
    return sorted({norm_text(x) for x in out if norm_text(x)})


def all_object_candidates(sid: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    u = unified(sid)
    g = graph(sid)
    for n in g.get("nodes", []):
        md = n.get("metadata", {}) or {}
        values = [n.get("node_id", ""), n.get("label", ""), md.get("path", ""), md.get("source_location", ""), md.get("source_object", ""), md.get("carrier_location", "")]
        for v in values:
            if v:
                out.append({"source": "runtime_graph_node", "type": n.get("node_type", ""), "value": str(v), "id": n.get("node_id", "")})
    for e in g.get("edges", []):
        values = [e.get("source_node", ""), e.get("target_node", ""), e.get("carrier_location", "")]
        for v in values:
            if v:
                out.append({"source": "runtime_graph_edge", "type": e.get("edge_type", ""), "value": str(v), "id": e.get("edge_id", "")})
    sr = u.get("static_result", {}) or {}
    for ent in sr.get("resolved_entities", []) or []:
        for k in ("name", "value", "canonical", "entity_id", "text"):
            if ent.get(k):
                out.append({"source": "static_entity", "type": ent.get("entity_type", ""), "value": str(ent.get(k)), "id": ent.get("entity_id", "")})
    for act in sr.get("extracted_actions", []) or []:
        for k in ("object", "target", "source", "sink", "tool_name", "action_id"):
            if act.get(k):
                out.append({"source": "static_action", "type": act.get("action_type", ""), "value": str(act.get(k)), "id": act.get("action_id", "")})
    return out


def graph_edges_for(sid: str) -> list[dict[str, Any]]:
    return graph(sid).get("edges", []) or []


def chain_edge_ops(chs: list[dict[str, Any]]) -> list[str]:
    ops = []
    for c in chs:
        for w in (c.get("metadata", {}) or {}).get("minimal_witness", []) or []:
            op = OP_ALIASES.get(norm_text(w.get("edge", "")), norm_text(w.get("edge", "")))
            if op:
                ops.append(op)
    return sorted(set(ops))


def any_match(golds: list[str], preds: list[str], contract: str) -> tuple[int, list[str]]:
    matcher = {"literal": literal_match, "canonical": canonical_match, "semantic": semantic_specific_match}[contract]
    hits = []
    for g in golds:
        if any(matcher(g, p) for p in preds):
            hits.append(g)
    return len(hits), hits


def metric_counts(tp: int, pred: int, gold: int) -> dict[str, Any]:
    p = 0.0 if pred == 0 else tp / pred
    r = 0.0 if gold == 0 else tp / gold
    f1 = 0.0 if p + r == 0 else 2 * p * r / (p + r)
    return {"tp": tp, "predicted": pred, "gold": gold, "precision": p, "recall": r, "f1": f1}


def classify_relay(
    gold: str,
    chain_relays: list[str],
    candidate_canons: set[str],
    candidate_basenames: set[str],
    candidate_families: set[str],
    edge_present: bool,
) -> tuple[str, str]:
    if any(literal_match(gold, p) for p in chain_relays):
        return "EXACT_MATCH", "exact relay appears in recovered chain"
    if any(canonical_match(gold, p) for p in chain_relays):
        return "NORMALIZATION_MATCH", "canonical relay appears in recovered chain"
    if any(semantic_specific_match(gold, p) for p in chain_relays):
        return "ONTOLOGY_MATCH", "specific semantic relay appears in recovered chain"
    gold_canon = canon_path(gold)
    gold_base = basename(gold)
    specific_candidate_exists = bool(
        (gold_canon and gold_canon in candidate_canons)
        or (gold_base and gold_base in candidate_basenames)
    )
    if specific_candidate_exists:
        if edge_present:
            return "RELATION_PRESENT_OBJECT_MISSING", "specific relay object and related evidence exist outside recovered chain"
        return "GRANULARITY_COLLAPSE", "specific relay object exists in runtime/static evidence but not in recovered chain"
    if any(object_family(p) in {"generic_carrier", "llm_context", "data_object"} for p in chain_relays):
        return "GENERIC_CARRIER_ONLY", "recovered chain contains only generic carrier/data object for this relay"
    if object_family(gold) in candidate_families:
        return "WRONG_OBJECT", "same-family candidates exist but none match"
    return "MISSING_OBJECT", "no specific matching relay candidate found"


def relation_edge_status(
    rel: dict[str, Any],
    chs: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    candidate_canons: set[str],
    candidate_basenames: set[str],
    edge_blob: str,
) -> tuple[str, str]:
    g_from, g_to = rel.get("from", ""), rel.get("to", "")
    gop = OP_ALIASES.get(norm_text(rel.get("operation", "")), norm_text(rel.get("operation", "")))
    pred_ops = set(chain_edge_ops(chs))
    from_ok = bool(canon_path(g_from) in candidate_canons or basename(g_from) in candidate_basenames)
    to_ok = bool(canon_path(g_to) in candidate_canons or basename(g_to) in candidate_basenames)
    op_ok = gop in pred_ops or any(OP_ALIASES.get(norm_text(e.get("edge_type", "")), norm_text(e.get("edge_type", ""))) == gop for e in edges)
    if from_ok and to_ok and op_ok:
        # Check if the exact directed relation is materialized as one edge.
        gf = canon_path(g_from)
        gt = canon_path(g_to)
        if (gf and gf in edge_blob) and (gt and gt in edge_blob):
            return "SEMANTICALLY_EQUIVALENT_EDGE", "source, target, and operation evidence exist"
        return "COLLAPSED_MULTI_EDGE", "objects and operation exist but direct ordered edge is collapsed through tool/agent/carrier nodes"
    if from_ok and to_ok and not op_ok:
        return "OPERATION_MISMATCH", "source and target exist but expected operation is absent"
    if (from_ok or to_ok) and op_ok:
        return "MISSING_EDGE", "operation and one endpoint exist but full relation is absent"
    if not to_ok and is_url(g_to):
        return "ENDPOINT_MISMATCH", "expected endpoint not recovered"
    return "MISSING_EDGE", "relation not materialized"


def compute_structural(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    STRUCT.mkdir(parents=True, exist_ok=True)
    rules_path = STRUCT / "normalization_rules.yaml"
    rules_path.write_text(RULES_TEXT)
    rules_hash = sha256(rules_path)

    per_rows = []
    human_rows = []
    relay_tax = Counter()
    edge_tax = Counter()
    exact_failure = Counter()
    metrics = {
        c: defaultdict(int)
        for c in ("literal", "canonical", "semantic")
    }

    for sid in ids:
        s = samples[sid]
        gtruth = gt(sid)
        chs = chains(sid)
        src_preds = source_labels(sid, chs)
        sink_preds = sink_labels(chs)
        chain_relays = chain_relay_labels(chs)
        candidates = all_object_candidates(sid)
        cand_values = [c["value"] for c in candidates]
        candidate_canons = {canon_path(v) for v in cand_values if object_family(v) in {"file", "network_endpoint"}}
        candidate_basenames = {basename(v) for v in cand_values if object_family(v) in {"file", "network_endpoint"}}
        candidate_families = {object_family(v) for v in cand_values}
        edges = graph_edges_for(sid)
        edge_blob = norm_text(" ".join(
            " ".join(str(e.get(k, "")) for k in ("source_node", "target_node", "edge_type", "carrier_location"))
            for e in edges
        ))

        gt_sources = gtruth.get("sources", []) or []
        gt_sinks = gtruth.get("destinations", []) or []
        gt_relays = gtruth.get("intermediate_objects", []) or []
        gt_edges = gtruth.get("ordered_relations", []) or []

        specific_relay_candidates = [v for v in cand_values if object_family(v) in {"file", "network_endpoint"}]

        relay_details = []
        for r in gt_relays:
            rc = canon_path(r)
            rb = basename(r)
            edge_present = bool((rc and rc in edge_blob) or (rb and rb in edge_blob))
            primary, reason = classify_relay(r, chain_relays, candidate_canons, candidate_basenames, candidate_families, edge_present)
            relay_tax[primary] += 1
            relay_details.append(f"{r}=>{primary}")

        edge_details = []
        edge_statuses = []
        for rel in gt_edges:
            status, reason = relation_edge_status(rel, chs, edges, candidate_canons, candidate_basenames, edge_blob)
            edge_statuses.append(status)
            edge_tax[status] += 1
            edge_details.append(f"{rel.get('from')}--{rel.get('operation')}-->{rel.get('to')}=>{status}")

        row: dict[str, Any] = {
            "sample_id": sid,
            "gt_source": ";".join(gt_sources),
            "pred_source": ";".join(src_preds[:8]),
            "gt_relays": ";".join(gt_relays),
            "pred_relays": ";".join(chain_relays[:12]),
            "gt_sink": ";".join(gt_sinks),
            "pred_sink": ";".join(sink_preds[:8]),
            "gt_edges": " | ".join(f"{r.get('from')}--{r.get('operation')}-->{r.get('to')}" for r in gt_edges),
            "pred_edges": ";".join(chain_edge_ops(chs)),
            "gt_relay_count": len(gt_relays),
            "closure_correct": bool(s.get("confirmed_violation_chain") and s.get("expected_policy_outcome") == "confirmed_violation"),
            "primary_structural_failure": "",
            "secondary_structural_failure": ";".join(relay_details + edge_details),
        }
        for contract in ("literal", "canonical", "semantic"):
            relay_pred_basis = chain_relays if contract != "semantic" else specific_relay_candidates
            src_hit, _ = any_match(gt_sources, src_preds, contract)
            sink_hit, _ = any_match(gt_sinks, sink_preds, contract)
            if contract == "semantic":
                relay_hit = sum(
                    1 for r in gt_relays
                    if (canon_path(r) and canon_path(r) in candidate_canons)
                    or (basename(r) and basename(r) in candidate_basenames)
                )
            else:
                relay_hit, _ = any_match(gt_relays, relay_pred_basis, contract)
            edge_hit = sum(1 for st in edge_statuses if st == "SEMANTICALLY_EQUIVALENT_EDGE") if contract == "semantic" else sum(1 for rel in gt_edges if OP_ALIASES.get(norm_text(rel.get("operation", "")), norm_text(rel.get("operation", ""))) in chain_edge_ops(chs))

            metrics[contract]["source_tp"] += src_hit
            metrics[contract]["source_pred"] += len(set(src_preds))
            metrics[contract]["source_gold"] += len(gt_sources)
            metrics[contract]["sink_tp"] += sink_hit
            metrics[contract]["sink_pred"] += len(set(sink_preds))
            metrics[contract]["sink_gold"] += len(gt_sinks)
            metrics[contract]["relay_tp"] += relay_hit
            metrics[contract]["relay_pred"] += len(set(relay_pred_basis))
            metrics[contract]["relay_gold"] += len(gt_relays)
            metrics[contract]["edge_tp"] += min(edge_hit, len(gt_edges))
            metrics[contract]["edge_pred"] += len(chain_edge_ops(chs))
            metrics[contract]["edge_gold"] += len(gt_edges)

            exact = bool(gt_edges or gt_relays) and src_hit == len(gt_sources) and sink_hit == len(gt_sinks) and relay_hit == len(gt_relays) and min(edge_hit, len(gt_edges)) == len(gt_edges)
            if exact:
                metrics[contract]["exact_tp"] += 1
            if gt_edges or gt_relays:
                metrics[contract]["exact_gold"] += 1
            if chs:
                metrics[contract]["exact_pred"] += 1
            row[f"{contract}_source_match"] = src_hit == len(gt_sources) if gt_sources else False
            row[f"{contract}_sink_match"] = sink_hit == len(gt_sinks) if gt_sinks else False
            row[f"{contract}_relay_match_count"] = relay_hit
            row[f"{contract}_edge_match_count"] = min(edge_hit, len(gt_edges))
            row[f"exact_{contract}_chain"] = exact

        failures = [x.split("=>", 1)[1] for x in relay_details if "=>" in x and not x.endswith("EXACT_MATCH")]
        failures += [x.rsplit("=>", 1)[1] for x in edge_details if "=>" in x and not x.endswith("SEMANTICALLY_EQUIVALENT_EDGE")]
        row["primary_structural_failure"] = failures[0] if failures else "NONE"
        if not row["exact_semantic_chain"]:
            exact_failure[row["primary_structural_failure"]] += 1
        per_rows.append(row)

        if len(human_rows) < 100 and (
            row["closure_correct"]
            or row["gt_relay_count"] > 0
            or "http_body" in row["pred_relays"]
            or "llm_context" in row["pred_relays"]
            or s.get("risk_family") in {"Persistence", "Multi-stage compositional behavior", "LLM-mediated disclosure"}
        ):
            human_rows.append({
                "sample_id": sid,
                "GT chain": " | ".join(" -> ".join(c) for c in gtruth.get("expected_complete_chains", []) or []),
                "ProvLoom chain": " | ".join(c.get("explanation", "") for c in chs[:4]),
                "GT evidence": ";".join(gtruth.get("instruction_evidence_spans", []) or []),
                "ProvLoom evidence": ";".join(row["pred_edges"].split(";")),
                "runtime events": ";".join(str(e.get("event_ids", "")) for e in edges[:8]),
                "static spans": ";".join(gtruth.get("minimal_evidence_sets", [[]])[0] if gtruth.get("minimal_evidence_sets") else []),
                "literal evaluator result": row["exact_literal_chain"],
                "canonical evaluator result": row["exact_canonical_chain"],
                "semantic evaluator result": row["exact_semantic_chain"],
                "human_source_correct": "",
                "human_sink_correct": "",
                "human_relay_correct": "",
                "human_edge_correct": "",
                "human_chain_semantically_correct": "",
                "human_comments": "",
            })

    metric_objs = {}
    for contract, c in metrics.items():
        obj = {
            "scope": "formal_776",
            "normalization_rules_sha256": rules_hash,
            "contract": contract,
            "closure": metric_counts(
                sum(1 for sid in ids if samples[sid].get("confirmed_violation_chain") and samples[sid].get("expected_policy_outcome") == "confirmed_violation"),
                sum(1 for sid in ids if samples[sid].get("confirmed_violation_chain")),
                sum(1 for sid in ids if samples[sid].get("expected_policy_outcome") == "confirmed_violation"),
            ),
            "source": metric_counts(c["source_tp"], c["source_pred"], c["source_gold"]),
            "sink": metric_counts(c["sink_tp"], c["sink_pred"], c["sink_gold"]),
            "relay": metric_counts(c["relay_tp"], c["relay_pred"], c["relay_gold"]),
            "edge": metric_counts(c["edge_tp"], c["edge_pred"], c["edge_gold"]),
            "exact_structural_chain": metric_counts(c["exact_tp"], c["exact_pred"], c["exact_gold"]),
        }
        metric_objs[contract] = obj
        write_json(STRUCT / f"metrics_{contract}.json", obj)

    write_csv(STRUCT / "per_sample_chain_audit.csv", per_rows)
    write_json(STRUCT / "relay_mismatch_taxonomy.json", dict(relay_tax.most_common()))
    write_json(STRUCT / "edge_mismatch_taxonomy.json", dict(edge_tax.most_common()))
    write_json(STRUCT / "exact_chain_failure_decomposition.json", dict(exact_failure.most_common()))
    write_csv(STRUCT / "human_audit_packet.csv", human_rows)
    return {
        "normalization_rules_sha256": rules_hash,
        "metrics": metric_objs,
        "relay_taxonomy": dict(relay_tax.most_common()),
        "edge_taxonomy": dict(edge_tax.most_common()),
        "exact_failure": dict(exact_failure.most_common()),
        "human_packet_count": len(human_rows),
    }


def current_confusion(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, int]:
    tp = tn = fp = fn = 0
    for sid in ids:
        s = samples[sid]
        gt_label = "malicious" if s.get("expected_policy_outcome") == "confirmed_violation" else "benign"
        pred = s.get("predicted_label")
        if gt_label == "malicious" and pred == "malicious":
            tp += 1
        elif gt_label == "malicious":
            fn += 1
        elif pred == "malicious":
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def metrics_from_cm(cm: dict[str, int]) -> dict[str, Any]:
    tp, tn, fp, fn = cm["tp"], cm["tn"], cm["fp"], cm["fn"]
    precision = 0.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 0.0 if tp + fn == 0 else tp / (tp + fn)
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    fpr = 0.0 if fp + tn == 0 else fp / (fp + tn)
    return {**cm, "precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def source_sink_correct(sid: str, sample: dict[str, Any]) -> tuple[bool, bool, bool, str, str]:
    gtruth = gt(sid)
    chs = chains(sid)
    src_preds = source_labels(sid, chs)
    sink_preds = sink_labels(chs)
    src_ok = bool(gtruth.get("sources")) and all(any(canonical_match(gs, ps) for ps in src_preds) for gs in gtruth.get("sources", []))
    sink_ok = bool(gtruth.get("destinations")) and all(any(canonical_match(gs, ps) for ps in sink_preds) for gs in gtruth.get("destinations", []))
    closure = bool(chs)
    return src_ok, sink_ok, closure, ";".join(src_preds[:5]), ";".join(sink_preds[:5])


def oracle_policy(ids: list[str], samples: dict[str, dict[str, Any]]) -> dict[str, Any]:
    ORACLE.mkdir(parents=True, exist_ok=True)
    cases = []
    fn_decomp = Counter()
    fp_decomp = Counter()
    matrix = Counter()
    oracle_preds = {}
    policy_fixable = 0
    fp_eliminated = 0

    for sid in ids:
        s = samples[sid]
        expected_mal = s.get("expected_policy_outcome") == "confirmed_violation"
        pred = s.get("predicted_label")
        src_ok, sink_ok, closure, cur_src, cur_sink = source_sink_correct(sid, s)
        cov = s.get("coverage_state", "")
        risk = s.get("risk_chain_status", "")
        policy_correct = pred == ("malicious" if expected_mal else "benign") if src_ok and sink_ok else False
        prov_correct = src_ok and sink_ok and closure
        matrix[f"prov={'correct' if prov_correct else 'wrong'}|policy={'correct' if policy_correct else 'wrong'}|gt={'mal' if expected_mal else 'ben'}"] += 1

        oracle_verdict = pred
        error_type = "not_error"
        oracle_policy_status = "not_applied"
        if expected_mal and pred != "malicious":
            if prov_correct:
                error_type = "POLICY_FIXABLE"
                oracle_verdict = "malicious"
                oracle_policy_status = "gt_prohibited_on_existing_correct_closure"
                policy_fixable += 1
            elif cov in {"timeout", "max_steps_exhausted", "execution_failed"}:
                error_type = "EXECUTION_NOT_FIXABLE"
                oracle_policy_status = "no_correct_existing_closure_execution_limited"
            elif cov in {"path_incomplete", "path_not_triggered", "target_reached_no_flow", "environment_missing"}:
                error_type = "COVERAGE_NOT_FIXABLE"
                oracle_policy_status = "no_correct_existing_closure_coverage_limited"
            elif closure:
                error_type = "PROVENANCE_NOT_FIXABLE"
                oracle_policy_status = "closure_exists_but_wrong_sink_or_source"
            else:
                error_type = "PROVENANCE_NOT_FIXABLE"
                oracle_policy_status = "no_existing_closure"
            fn_decomp[error_type.lower()] += 1
        elif not expected_mal and pred == "malicious":
            if prov_correct:
                error_type = "PURE_POLICY_FP"
                oracle_verdict = "benign"
                oracle_policy_status = "gt_allowed_on_existing_correct_flow"
                fp_eliminated += 1
            elif closure:
                error_type = "PROVENANCE_FP"
                oracle_policy_status = "malicious_verdict_depends_on_wrong_existing_flow"
            else:
                error_type = "MIXED_FP"
                oracle_policy_status = "no_clear_existing_closure"
            fp_decomp[error_type.lower()] += 1

        oracle_preds[sid] = oracle_verdict
        cases.append({
            "sample_id": sid,
            "GT outcome": s.get("expected_policy_outcome"),
            "current verdict": pred,
            "current source": cur_src,
            "current sink": cur_sink,
            "current closure": closure,
            "current coverage": cov,
            "current policy status": risk,
            "oracle policy status": oracle_policy_status,
            "oracle verdict": oracle_verdict,
            "changed?": oracle_verdict != pred,
            "correct_after_oracle?": oracle_verdict == ("malicious" if expected_mal else "benign"),
            "error_type": error_type,
            "source_correct": src_ok,
            "sink_correct": sink_ok,
            "provenance_correct": prov_correct,
        })

    oracle_cm = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    for sid in ids:
        expected_mal = samples[sid].get("expected_policy_outcome") == "confirmed_violation"
        pred = oracle_preds[sid]
        if expected_mal and pred == "malicious":
            oracle_cm["tp"] += 1
        elif expected_mal:
            oracle_cm["fn"] += 1
        elif pred == "malicious":
            oracle_cm["fp"] += 1
        else:
            oracle_cm["tn"] += 1

    current = metrics_from_cm(current_confusion(ids, samples))
    oracle = metrics_from_cm(oracle_cm)
    write_csv(ORACLE / "oracle_policy_cases.csv", cases)
    write_json(ORACLE / "fn_policy_decomposition.json", dict(fn_decomp.most_common()))
    write_json(ORACLE / "fp_policy_decomposition.json", dict(fp_decomp.most_common()))
    write_json(ORACLE / "oracle_metrics.json", {
        "scope": "formal_776",
        "warning": "NOT A SYSTEM RESULT. DIAGNOSTIC UPPER BOUND ONLY.",
        "current_full": current,
        "full_plus_oracle_policy_diagnostic": oracle,
        "policy_fixable_fn_count": policy_fixable,
        "fp_eliminated_by_oracle_count": fp_eliminated,
    })
    rows = [{"bucket": k, "count": v} for k, v in matrix.most_common()]
    write_csv(ORACLE / "provenance_policy_matrix.csv", rows, ["bucket", "count"])
    return {
        "current": current,
        "oracle": oracle,
        "fn_decomposition": dict(fn_decomp.most_common()),
        "fp_decomposition": dict(fp_decomp.most_common()),
        "policy_fixable_fn_count": policy_fixable,
        "fp_eliminated_by_oracle_count": fp_eliminated,
        "matrix": dict(matrix.most_common()),
    }


def freeze_inputs(ids: list[str]) -> None:
    runtime_paths = []
    static_paths = []
    for sid in ids:
        base = RUN_DIR / f"PROVBENCH-FULL-{sid}"
        runtime_paths.extend(str((base / name).relative_to(ROOT)) for name in ["runtime-chains.json", "runtime-provenance-graph.json", "unified-analysis.json"] if (base / name).exists())
        if (base / "unified-analysis.json").exists():
            static_paths.append(str((base / "unified-analysis.json").relative_to(ROOT)))
    obj = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "benchmark_population_n": len(ids),
        "benchmark_sample_ids": ids,
        "prediction_artifact_paths": [str(PROV_METRICS.relative_to(ROOT)), str(PROV_SUMMARY.relative_to(ROOT))],
        "prediction_artifact_sha256": {str(p.relative_to(ROOT)): sha256(p) for p in [PROV_METRICS, PROV_SUMMARY]},
        "ground_truth_dir": str(GT_DIR.relative_to(ROOT)),
        "ground_truth_paths": [str((GT_DIR / f"{sid}.json").relative_to(ROOT)) for sid in ids],
        "relevant_runtime_artifact_paths": runtime_paths,
        "relevant_static_artifact_paths": static_paths,
        "existing_evaluator_path": str(PREV_EVAL.relative_to(ROOT)),
        "existing_evaluator_sha256": sha256(PREV_EVAL),
        "current_git_commit": git("rev-parse", "HEAD"),
        "git_status_short": git("status", "--short"),
        "untracked_scripts_paper_usenix_eval_sha256": sha256(PREV_EVAL) if PREV_EVAL.exists() and "?? scripts/paper_usenix_eval.py" in git("status", "--short") else None,
    }
    write_json(OUT / "frozen_inputs.json", obj)


def evaluation_bug_report() -> None:
    text = """# Evaluation Bug Report

Bug description: the previous exploratory evaluator used a helper equivalent to
`str(value).split(':', 1)[0]` for path-like comparison. That is safe for
file-field labels such as `path:FIELD`, but unsafe for URL endpoints because
`http://localhost:20001/path` collapses to `http`.

Affected metrics: prior endpoint and chain-level exploratory diagnostics in
`artifacts/paper_usenix/explanation_metric_audit/` may over-count endpoint
matches whenever URL strings were compared through that helper.

Expected impact: previous `L2_endpoint_correct` and some sink granularity
matches should be treated as provisional. This root-cause diagnosis preserves
those old artifacts and writes corrected contract-specific metrics under
`root_cause_diagnosis/structural_explanation/`.

Scope: evaluation-only bug. It does not touch ProvLoom analyzer, runtime,
ground truth, predictions, or benchmark samples.

Corrected evaluator version: `provloom-root-cause-normalization-v1` in
`structural_explanation/normalization_rules.yaml`.
"""
    (OUT / "evaluation_bug_report.md").write_text(text)


def summary(structural: dict[str, Any], oracle: dict[str, Any]) -> None:
    lit = structural["metrics"]["literal"]
    can = structural["metrics"]["canonical"]
    sem = structural["metrics"]["semantic"]
    relay_tax = structural["relay_taxonomy"]
    exact_fail = structural["exact_failure"]
    cur = oracle["current"]
    ora = oracle["oracle"]
    lines = [
        "# Root-Cause Diagnosis Summary",
        "",
        "Scope: evaluation-only diagnosis over the fixed formal ProvBench common-success population, N=776.",
        "",
        "## Direct Answers",
        "",
        f"1. The previously reported 61.6% complete-chain recall is closure-level correctness: it reflects source-to-sink/security closure recovery, not full structural relay reconstruction.",
        "2. It is not structural chain reconstruction. The decisive runtime chains are carrier-level witnesses, while GT complete chains include named staging/payload/state artifacts.",
        f"3. Relay literal F1: {lit['relay']['f1']:.6f}.",
        f"4. Relay canonical F1: {can['relay']['f1']:.6f}.",
        f"5. Relay semantic F1: {sem['relay']['f1']:.6f}.",
        f"6. Exact literal structural chain F1: {lit['exact_structural_chain']['f1']:.6f}.",
        f"7. Exact canonical structural chain F1: {can['exact_structural_chain']['f1']:.6f}.",
        f"8. Exact semantic structural chain F1: {sem['exact_structural_chain']['f1']:.6f}.",
        f"9. Relay mismatch taxonomy: {relay_tax}.",
        f"10. Exact-chain failure decomposition: {exact_fail}.",
        f"11. Canonical Source/Sink/Edge F1: source={can['source']['f1']:.6f}, sink={can['sink']['f1']:.6f}, edge={can['edge']['f1']:.6f}.",
        f"12. Semantic Source/Sink/Edge F1: source={sem['source']['f1']:.6f}, sink={sem['sink']['f1']:.6f}, edge={sem['edge']['f1']:.6f}.",
        "13. Generic carriers were not counted as specific relay identities.",
        "14. The accurate scientific claim is: source-to-sink closure with carrier-level witness, plus partial artifact evidence in the runtime graph; not reliable ordered structural provenance reconstruction.",
        f"15. 107 FN decomposition: {oracle['fn_decomposition']}.",
        f"16. 39 trusted/allowed FP decomposition: {oracle['fp_decomposition']}.",
        f"17. Current Full metrics: TP={cur['tp']} TN={cur['tn']} FP={cur['fp']} FN={cur['fn']} Precision={cur['precision']:.6f} Recall={cur['recall']:.6f} F1={cur['f1']:.6f} FPR={cur['fpr']:.6f}.",
        f"18. Oracle-policy diagnostic metrics: TP={ora['tp']} TN={ora['tn']} FP={ora['fp']} FN={ora['fn']} Precision={ora['precision']:.6f} Recall={ora['recall']:.6f} F1={ora['f1']:.6f} FPR={ora['fpr']:.6f}.",
        f"19. Oracle policy restores {ora['recall'] - cur['recall']:.6f} recall and eliminates {oracle['fp_eliminated_by_oracle_count']} FP. This is a diagnostic upper bound, not a system result.",
        "20. The primary bottleneck is both relay representation and policy adjudication, but for different metrics: structural explanation is limited by carrier-level/partially connected provenance; trusted-allowed false positives are pure policy adjudication errors when the recovered flow is otherwise correct.",
        "21. Evaluation bug found: previous URL matching could collapse endpoints by splitting on the first colon; see evaluation_bug_report.md.",
        "",
        "## Decision",
        "",
        "D. relay + policy both need work if the paper wants to claim explanation-level structural provenance and reduce trusted-allowed errors. If the claim is narrowed to source-to-sink closure with carrier-level witnesses, analyzer changes are not required for that narrower claim.",
        "",
        "## Integrity Audit",
        "",
        "- GT was loaded only by this offline evaluator after frozen predictions were read.",
        "- Oracle policy only changes evaluation-time final adjudication over existing evidence; it does not create sources, sinks, edges, closures, coverage, or runtime events.",
        "- Normalization rules are global and deterministic; their SHA256 is recorded in the metrics.",
        "- Generic carriers are explicitly forbidden from matching named GT relays.",
        "- Literal metrics are preserved separately from canonical and semantic metrics.",
        "- N is fixed at 776; no samples are silently excluded.",
        "- Oracle metrics are labeled NOT A SYSTEM RESULT / DIAGNOSTIC UPPER BOUND ONLY.",
    ]
    (OUT / "summary.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    ids = load_ids()
    samples = load_samples(ids)
    freeze_inputs(ids)
    structural = compute_structural(ids, samples)
    oracle = oracle_policy(ids, samples)
    evaluation_bug_report()
    summary(structural, oracle)
    write_json(OUT / "diagnosis_index.json", {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope_n": len(ids),
        "structural": structural,
        "oracle_policy": oracle,
    })


if __name__ == "__main__":
    main()
